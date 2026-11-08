package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/selfhostde"
)

/*
	Map typed DNS provider credentials (upstream #1067 selfhost.de, #410 Hurricane Electric)

	A few lego providers take a map instead of flat fields: Hurricane Electric, dns.home.de and
	myaddr.tools take Credentials (map[string]string, "name:token" pairs) and selfhost.de takes
	RecordsMapping (domain -> record IDs). The ACME form renders such a field as a text area and
	sends the text as a string. Accepted text formats:

	  * a JSON object:  {"example.org": "token1", "demo.example.org": "token2"}
	  * lego's pair list, separated by commas or new lines:  example.org:token1,demo.example.org:token2

	selfhost.de record IDs are a list of one or two IDs per domain:
	  {"example.org": ["id1", "id2"]}  or  example.org:id1:id2,other.org:id3
	API clients may also send the JSON object directly instead of a string.
*/

// splitMapEntries splits "a:b,c:d" (commas and/or new lines) into entries
func splitMapEntries(raw string) []string {
	entries := []string{}
	for _, e := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if e = strings.TrimSpace(e); e != "" {
			entries = append(entries, e)
		}
	}
	return entries
}

// parseStringMapCredential decodes the value of a map[string]string provider field
func parseStringMapCredential(raw any) (map[string]string, error) {
	switch v := raw.(type) {
	case map[string]any:
		out := map[string]string{}
		for k, val := range v {
			str, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("value of %q must be a string", k)
			}
			out[k] = str
		}
		return out, nil
	case string:
		text := strings.TrimSpace(v)
		if strings.HasPrefix(text, "{") {
			out := map[string]string{}
			if err := json.Unmarshal([]byte(text), &out); err != nil {
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
			return out, nil
		}
		out := map[string]string{}
		for _, entry := range splitMapEntries(text) {
			name, value, ok := strings.Cut(entry, ":")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if !ok || name == "" || value == "" {
				return nil, fmt.Errorf("incorrect pair %q, expected name:value", entry)
			}
			out[name] = value
		}
		return out, nil
	}
	return nil, errors.New("expected a JSON object or a name:value list")
}

// parseRecordIDs decodes the value of the selfhost.de RecordsMapping field into record ID lists
func parseRecordIDs(raw any) (map[string][]string, error) {
	out := map[string][]string{}
	switch v := raw.(type) {
	case map[string]any:
		for domain, val := range v {
			switch ids := val.(type) {
			case string:
				out[domain] = []string{ids}
			case []any:
				for _, id := range ids {
					str, ok := id.(string)
					if !ok {
						return nil, fmt.Errorf("record IDs of %q must be strings", domain)
					}
					out[domain] = append(out[domain], str)
				}
			default:
				return nil, fmt.Errorf("record IDs of %q must be a string or a list of strings", domain)
			}
		}
	case string:
		text := strings.TrimSpace(v)
		if strings.HasPrefix(text, "{") {
			var generic map[string]any
			if err := json.Unmarshal([]byte(text), &generic); err != nil {
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
			return parseRecordIDs(generic)
		}
		for _, entry := range splitMapEntries(strings.ReplaceAll(text, " ", "")) {
			parts := strings.Split(entry, ":")
			if len(parts) < 2 {
				return nil, fmt.Errorf("incorrect entry %q, expected domain:id[:id]", entry)
			}
			out[parts[0]] = parts[1:]
		}
	default:
		return nil, errors.New("expected a JSON object or a domain:id list")
	}

	if len(out) == 0 {
		return nil, errors.New("empty mapping")
	}
	for domain, ids := range out {
		if domain == "" || len(ids) == 0 || len(ids) > 2 {
			return nil, fmt.Errorf("%q needs one or two record IDs", domain)
		}
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return nil, fmt.Errorf("empty record ID for %q", domain)
			}
		}
	}
	return out, nil
}

// normaliseMapCredentials converts the text of every map[string]string field of the provider
// into a real map so the generic JSON based provider factory can decode it.
func normaliseMapCredentials(structure map[string]string, credentials map[string]any) error {
	for field, datatype := range structure {
		if datatype != "map[string]string" {
			continue
		}
		raw, ok := credentials[field]
		if !ok || raw == nil {
			continue
		}
		parsed, err := parseStringMapCredential(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		credentials[field] = parsed
	}
	return nil
}

// newSelfhostdeProvider builds the selfhost.de provider. lego's record sequence type has no
// exported fields, so RecordsMapping cannot go through the generic JSON decoder.
func newSelfhostdeProvider(credentials map[string]any, propagationTimeout int, pollingInterval int) (challenge.Provider, error) {
	cfg := selfhostde.NewDefaultConfig()
	if v, ok := credentials["Username"].(string); ok {
		cfg.Username = strings.TrimSpace(v)
	}
	if v, ok := credentials["Password"].(string); ok {
		cfg.Password = v
	}
	cfg.PropagationTimeout = time.Duration(propagationTimeout) * time.Second
	cfg.PollingInterval = time.Duration(pollingInterval) * time.Second

	rawMapping, ok := credentials["RecordsMapping"]
	if !ok || rawMapping == nil || strings.TrimSpace(fmt.Sprint(rawMapping)) == "" {
		return nil, errors.New("selfhostde: RecordsMapping is required, use domain:recordID[:recordID] entries")
	}
	ids, err := parseRecordIDs(rawMapping)
	if err != nil {
		return nil, fmt.Errorf("selfhostde: RecordsMapping: %w", err)
	}
	cfg.RecordsMapping = map[string]*selfhostde.Seq{}
	for domain, list := range ids {
		cfg.RecordsMapping[domain] = selfhostde.NewSeq(list...)
	}
	return selfhostde.NewDNSProviderConfig(cfg)
}
