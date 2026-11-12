package ech

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Classes of an ECH config found in DNS, relative to the keys Zoraxy holds
const (
	ClassOursActive  = "ours-active"  // Byte-identical to an active key's config: Zoraxy decrypts it
	ClassOursRetired = "ours-retired" // A retired key: still decrypts until it is purged
	ClassOursPurged  = "ours-purged"  // Our public name but no key matches (rotation purged it, or the key store was reset): ECH will be rejected
	ClassForeign     = "foreign"      // Another party's config (for example a CDN's public_name): Zoraxy cannot decrypt it
	ClassNone        = "none"         // No HTTPS record, or no ech= parameter
	ClassUnparsable  = "unparsable"
)

// ParsedConfig is one ECHConfig out of an ECHConfigList
type ParsedConfig struct {
	ConfigID   uint8
	PublicName string
	Class      string `json:",omitempty"`
	raw        []byte
}

// ParseConfigList splits an ECHConfigList (RFC 9849 section 4) and reads config_id and public_name of each version 0xfe0d entry.
// Entries of other versions are skipped.
func ParseConfigList(list []byte) ([]ParsedConfig, error) {
	if len(list) < 2 {
		return nil, errors.New("config list too short")
	}
	total := int(binary.BigEndian.Uint16(list))
	body := list[2:]
	if total != len(body) {
		return nil, errors.New("config list length mismatch")
	}
	var out []ParsedConfig
	for len(body) > 0 {
		if len(body) < 4 {
			return nil, errors.New("truncated config header")
		}
		ver, n := binary.BigEndian.Uint16(body), int(binary.BigEndian.Uint16(body[2:]))
		if len(body) < 4+n {
			return nil, errors.New("truncated config")
		}
		raw := body[:4+n]
		cont := body[4 : 4+n]
		body = body[4+n:]
		if ver != echVersion {
			continue
		}
		// config_id(1) kem(2) public_key<2> cipher_suites<2> max_name_length(1) public_name<1>
		if len(cont) < 3 {
			return nil, errors.New("truncated config")
		}
		id := cont[0]
		p := 3
		for _, w := range []int{2, 2} {
			if len(cont) < p+w {
				return nil, errors.New("truncated config")
			}
			l := int(binary.BigEndian.Uint16(cont[p:]))
			p += w + l
		}
		if len(cont) < p+2 {
			return nil, errors.New("truncated config")
		}
		nl := int(cont[p+1])
		if len(cont) < p+2+nl {
			return nil, errors.New("truncated public name")
		}
		out = append(out, ParsedConfig{ConfigID: id, PublicName: string(cont[p+2 : p+2+nl]), raw: raw})
	}
	return out, nil
}

// Classify decides, for every config of a base64 list, how it relates to keys
func Classify(listB64 string, keys []KeyInfo, ourPublicName string) ([]ParsedConfig, error) {
	list, err := base64.StdEncoding.DecodeString(listB64)
	if err != nil {
		return nil, err
	}
	cfgs, err := ParseConfigList(list)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	if ourPublicName != "" {
		names[strings.ToLower(ourPublicName)] = true
	}
	for _, k := range keys {
		names[strings.ToLower(k.PublicName)] = true
	}
	for i := range cfgs {
		cfgs[i].Class = ClassForeign
		if names[strings.ToLower(cfgs[i].PublicName)] {
			cfgs[i].Class = ClassOursPurged
		}
		for _, k := range keys {
			kb, err := base64.StdEncoding.DecodeString(k.Config)
			if err != nil || !bytes.Equal(kb, cfgs[i].raw) {
				continue
			}
			if k.State == StateActive {
				cfgs[i].Class = ClassOursActive
			} else {
				cfgs[i].Class = ClassOursRetired
			}
			break
		}
	}
	return cfgs, nil
}

// DomainView is what one resolver returns for one host
type DomainView struct {
	Resolver string
	Error    string `json:",omitempty"`
	HasHTTPS bool
	Status   string // One of the Class* values (the first ECH config decides), or an error
	Configs  []ParsedConfig
	Advice   string
}

// DomainCheck compares the HTTPS records seen by the system resolver and by a public resolver
type DomainCheck struct {
	Host   string
	System DomainView
	Public DomainView
}

// PublicResolver is the public DNS used to see what the internet (and a browser using DNS-over-HTTPS) would be told
const PublicResolver = "1.1.1.1:53"

func (m *Manager) domainView(ctx context.Context, host, resolver string) DomainView {
	rrs, used, err := lookupHTTPS(ctx, host, resolver)
	v := DomainView{Resolver: used}
	if err != nil {
		v.Status, v.Error = "error", err.Error()
		v.Advice = "The lookup failed: " + err.Error()
		return v
	}
	return m.viewFromRecords(v, rrs)
}

func (m *Manager) viewFromRecords(v DomainView, rrs []*dns.HTTPS) DomainView {
	s := m.Settings()
	keys := m.Keys()
	v.Status = ClassNone
	for _, rr := range rrs {
		v.HasHTTPS = true
		if rr.Priority == 0 {
			continue
		}
		for _, kv := range rr.Value {
			e, ok := kv.(*dns.SVCBECHConfig)
			if !ok {
				continue
			}
			cfgs, err := Classify(base64.StdEncoding.EncodeToString(e.ECH), keys, s.PublicName)
			if err != nil {
				cfgs = []ParsedConfig{{Class: ClassUnparsable}}
			}
			v.Configs = append(v.Configs, cfgs...)
		}
	}
	if len(v.Configs) > 0 {
		v.Status = v.Configs[0].Class
	}
	v.Advice = domainAdvice(v)
	return v
}

func domainAdvice(v DomainView) string {
	name := ""
	if len(v.Configs) > 0 {
		name = v.Configs[0].PublicName
	}
	switch v.Status {
	case ClassOursActive:
		return "This resolver advertises Zoraxy's current ECH config."
	case ClassOursRetired:
		return "This resolver advertises a retired Zoraxy key. It still decrypts until it is purged: publish the current record soon."
	case ClassOursPurged:
		return "This resolver advertises an ECH config with Zoraxy's public name that no stored key matches. Browsers will have ECH rejected: publish the current record."
	case ClassForeign:
		return "This resolver advertises an ECH config from another party (public name " + name + "). Zoraxy cannot decrypt it, so a browser that uses it gets ECH rejected and, when this host resolves to this proxy, the certificate error ERR_ECH_FALLBACK_CERTIFICATE_INVALID."
	case ClassUnparsable:
		return "The ech= parameter could not be parsed."
	}
	if v.HasHTTPS {
		return "An HTTPS record exists but carries no ech= parameter, so browsers will not use ECH for this name."
	}
	return "No HTTPS record: browsers will not use ECH for this name."
}

// CheckDomains looks up every host with the system resolver and the public resolver (a few at a time)
func (m *Manager) CheckDomains(ctx context.Context, hosts []string) []DomainCheck {
	out := make([]DomainCheck, len(hosts))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = DomainCheck{Host: h, System: m.domainView(ctx, h, ""), Public: m.domainView(ctx, h, PublicResolver)}
		}(i, h)
	}
	wg.Wait()
	return out
}
