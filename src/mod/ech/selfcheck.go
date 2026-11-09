package ech

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
)

// SelfCheckResult is the outcome of a local ECH handshake against Zoraxy's own listener.
// It proves that the server decrypts the advertised config. It does NOT prove that any browser or resolver
// will use ECH: that depends on the published DNS record and on the client.
type SelfCheckResult struct {
	Addr        string
	Attempted   bool   // A handshake was tried (false when there is no listener, key or config)
	Accepted    bool   // The server decrypted the inner ClientHello (ConnectionState.ECHAccepted)
	TLSVersion  string // Negotiated version, ECH only exists in TLS 1.3
	Error       string `json:",omitempty"`
	Advice      string
	Rejected    bool `json:",omitempty"` // The server answered with retry configs instead of accepting
	InnerName   string
	ElapsedMs   int64
	ConfigBytes int
}

// SelfCheck dials addr over TCP with ECH enabled (inner name innerName, certificate verification disabled
// because only the ECH outcome is under test) using the given base64 ECHConfigList.
func SelfCheck(ctx context.Context, addr, innerName, configList string) *SelfCheckResult {
	res := &SelfCheckResult{Addr: addr, InnerName: innerName}
	raw, err := base64.StdEncoding.DecodeString(configList)
	if err != nil || len(raw) == 0 {
		res.Advice = "There is no active ECH key to test. Enable ECH with a public name first."
		return res
	}
	res.ConfigBytes = len(raw)
	if addr == "" {
		res.Advice = "The HTTPS listener address is unknown."
		return res
	}
	res.Attempted = true
	start := time.Now()
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := (&tls.Dialer{NetDialer: d, Config: &tls.Config{
		ServerName: innerName, MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, //nolint:gosec // only the ECH outcome is checked
		EncryptedClientHelloConfigList: raw,
	}}).DialContext(ctx, "tcp", addr)
	res.ElapsedMs = time.Since(start).Milliseconds()
	if err != nil {
		var rej *tls.ECHRejectionError
		if asRej(err, &rej) {
			res.Rejected = true
			res.Error = "The server did not accept the ECH extension and sent retry configs."
			res.Advice = "The listener answered but did not decrypt the config. Check that ECH is enabled and the key is active, then try again; a different key may be live than the one advertised."
			return res
		}
		res.Error = err.Error()
		res.Advice = "Could not complete a TLS 1.3 handshake with the listener: " + err.Error()
		return res
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	res.TLSVersion = tlsVersionName(st.Version)
	res.Accepted = st.ECHAccepted
	if st.ECHAccepted {
		res.Advice = "The listener decrypted a real ECH ClientHello made with the advertised config. A browser still needs the DNS record below and must have DNS-over-HTTPS or an ECH aware resolver."
	} else {
		res.Advice = "The handshake worked but ECH was not used. Check that ECH is enabled and the listener runs in TLS mode."
	}
	return res
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return "unknown"
}

// HostRecord is a copy-ready HTTPS record for one host name
type HostRecord struct {
	Host   string
	Record string
}

// RecordsFor builds one HTTPS record per host (lower-cased, de-duplicated, sorted). Wildcard names, IP literals and
// single label names cannot carry the record and are skipped.
func RecordsFor(hosts []string, configList string, h3 bool) []HostRecord {
	seen := map[string]bool{}
	out := []HostRecord{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(h), ".")))
		if h == "" || seen[h] || strings.ContainsAny(h, "*/: ") || !strings.Contains(h, ".") || net.ParseIP(h) != nil {
			continue
		}
		seen[h] = true
		out = append(out, HostRecord{Host: h, Record: SVCBExample(h, configList, h3)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func asRej(err error, target **tls.ECHRejectionError) bool {
	return errors.As(err, target)
}
