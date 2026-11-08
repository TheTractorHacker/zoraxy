package acme

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

/*
	profiles.go

	Named, reusable ACME configuration stored in the system database (table "acmepref"):

	* CA profiles: a custom ACME directory URL with an optional External Account Binding
	  (key id + HMAC) for CAs such as ZeroSSL or Google. Several can exist side by side; the
	  ACME account of each is stored separately (keyed by directory URL + email, see account.go).
	* DNS credential profiles: provider + credentials, selected by name when obtaining or
	  renewing a certificate instead of retyping them. Secrets are stored exactly like the
	  per certificate DNS credentials were before (plain values in the database) and are never
	  returned by the API: they are masked.
*/

// SecretMask replaces secret values in API responses. Sending it back on save keeps the stored value.
const SecretMask = "********"

var profileMu sync.Mutex

// CAProfile is a saved ACME CA definition.
type CAProfile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directoryURL"`
	SkipTLS      bool   `json:"skipTLS"`
	EABKid       string `json:"eabKid"`
	EABHmac      string `json:"eabHmac"` // base64url HMAC key as issued by the CA; secret
	Profile      string `json:"profile"` // default ACME profile to request, optional
}

// DNSProfile is a saved DNS-01 credential set.
type DNSProfile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Credentials string `json:"credentials"` // JSON object, same format as the per certificate credentials; secret
	DNSServers  string `json:"dnsServers"`
}

func newProfileID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func validateDirectoryURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("invalid ACME directory URL")
	}
	return nil
}

func (a *ACMEHandler) loadProfiles(key string, out any) {
	if a.Database == nil || !a.Database.TableExists(prefTableName) || !a.Database.KeyExists(prefTableName, key) {
		return
	}
	a.Database.Read(prefTableName, key, out)
}

func (a *ACMEHandler) saveProfiles(key string, v any) error {
	if a.Database == nil {
		return errors.New("database not available")
	}
	if !a.Database.TableExists(prefTableName) {
		if err := a.Database.NewTable(prefTableName); err != nil {
			return err
		}
	}
	return a.Database.Write(prefTableName, key, v)
}

/* ---------- CA profiles ---------- */

// ListCAProfiles returns all saved CA profiles sorted by name.
func (a *ACMEHandler) ListCAProfiles() []CAProfile {
	profileMu.Lock()
	defer profileMu.Unlock()
	return a.listCAProfilesLocked()
}

func (a *ACMEHandler) listCAProfilesLocked() []CAProfile {
	list := []CAProfile{}
	a.loadProfiles(prefCAProfiles, &list)
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	return list
}

// GetCAProfile finds a CA profile by ID.
func (a *ACMEHandler) GetCAProfile(id string) (*CAProfile, error) {
	for _, p := range a.ListCAProfiles() {
		if p.ID == id {
			cp := p
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("CA profile %q not found", id)
}

// SaveCAProfile creates (empty ID) or updates a CA profile and returns its ID. An EABHmac equal
// to SecretMask keeps the stored secret.
func (a *ACMEHandler) SaveCAProfile(p CAProfile) (string, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.DirectoryURL = strings.TrimSpace(p.DirectoryURL)
	if p.Name == "" {
		return "", errors.New("profile name is required")
	}
	if err := validateDirectoryURL(p.DirectoryURL); err != nil {
		return "", err
	}
	if (p.EABKid == "") != (p.EABHmac == "") {
		return "", errors.New("EAB needs both the key id and the HMAC key")
	}
	profileMu.Lock()
	defer profileMu.Unlock()
	list := a.listCAProfilesLocked()
	found := false
	for i := range list {
		if list[i].ID != p.ID && strings.EqualFold(list[i].Name, p.Name) {
			return "", errors.New("a CA profile with this name already exists")
		}
		if p.ID != "" && list[i].ID == p.ID {
			if p.EABHmac == SecretMask {
				p.EABHmac = list[i].EABHmac
			}
			list[i] = p
			found = true
		}
	}
	if p.EABHmac == SecretMask {
		return "", errors.New("no stored secret to keep")
	}
	if !found {
		if p.ID != "" {
			return "", errors.New("CA profile not found")
		}
		p.ID = newProfileID()
		list = append(list, p)
	}
	return p.ID, a.saveProfiles(prefCAProfiles, list)
}

// DeleteCAProfile removes a CA profile. Certificates that reference it fail to renew until reassigned.
func (a *ACMEHandler) DeleteCAProfile(id string) error {
	profileMu.Lock()
	defer profileMu.Unlock()
	list := a.listCAProfilesLocked()
	out := make([]CAProfile, 0, len(list))
	for _, p := range list {
		if p.ID != id {
			out = append(out, p)
		}
	}
	if len(out) == len(list) {
		return errors.New("CA profile not found")
	}
	return a.saveProfiles(prefCAProfiles, out)
}

// Masked returns a copy that is safe to send to the browser.
func (p CAProfile) Masked() CAProfile {
	if p.EABHmac != "" {
		p.EABHmac = SecretMask
	}
	return p
}

/* ---------- DNS profiles ---------- */

// ListDNSProfiles returns all saved DNS credential profiles sorted by name.
func (a *ACMEHandler) ListDNSProfiles() []DNSProfile {
	profileMu.Lock()
	defer profileMu.Unlock()
	return a.listDNSProfilesLocked()
}

func (a *ACMEHandler) listDNSProfilesLocked() []DNSProfile {
	list := []DNSProfile{}
	a.loadProfiles(prefDNSProfiles, &list)
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	return list
}

// GetDNSProfile finds a DNS credential profile by ID.
func (a *ACMEHandler) GetDNSProfile(id string) (*DNSProfile, error) {
	for _, p := range a.ListDNSProfiles() {
		if p.ID == id {
			cp := p
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("DNS profile %q not found", id)
}

// mergeCredentials fills fields that the client sent back as SecretMask with the stored value.
func mergeCredentials(oldJSON, newJSON string) (string, error) {
	var newMap, oldMap map[string]any
	if err := json.Unmarshal([]byte(newJSON), &newMap); err != nil {
		return "", errors.New("credentials must be a JSON object")
	}
	json.Unmarshal([]byte(oldJSON), &oldMap)
	for k, v := range newMap {
		if s, ok := v.(string); ok && s == SecretMask {
			if ov, has := oldMap[k]; has {
				newMap[k] = ov
			} else {
				delete(newMap, k)
			}
		}
	}
	out, err := json.Marshal(newMap)
	return string(out), err
}

// SaveDNSProfile creates (empty ID) or updates a DNS profile and returns its ID.
func (a *ACMEHandler) SaveDNSProfile(p DNSProfile) (string, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.Provider = strings.TrimSpace(p.Provider)
	if p.Name == "" || p.Provider == "" {
		return "", errors.New("profile name and DNS provider are required")
	}
	profileMu.Lock()
	defer profileMu.Unlock()
	list := a.listDNSProfilesLocked()
	found := false
	for i := range list {
		if list[i].ID != p.ID && strings.EqualFold(list[i].Name, p.Name) {
			return "", errors.New("a DNS profile with this name already exists")
		}
		if p.ID != "" && list[i].ID == p.ID {
			merged, err := mergeCredentials(list[i].Credentials, p.Credentials)
			if err != nil {
				return "", err
			}
			p.Credentials = merged
			list[i] = p
			found = true
		}
	}
	if !found {
		if p.ID != "" {
			return "", errors.New("DNS profile not found")
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(p.Credentials), &m); err != nil {
			return "", errors.New("credentials must be a JSON object")
		}
		p.ID = newProfileID()
		list = append(list, p)
	}
	return p.ID, a.saveProfiles(prefDNSProfiles, list)
}

// DeleteDNSProfile removes a DNS profile (and clears the default if it pointed at it).
func (a *ACMEHandler) DeleteDNSProfile(id string) error {
	profileMu.Lock()
	defer profileMu.Unlock()
	list := a.listDNSProfilesLocked()
	out := make([]DNSProfile, 0, len(list))
	for _, p := range list {
		if p.ID != id {
			out = append(out, p)
		}
	}
	if len(out) == len(list) {
		return errors.New("DNS profile not found")
	}
	if a.prefGet(prefDefaultDNS) == id {
		a.prefSet(prefDefaultDNS, "")
	}
	return a.saveProfiles(prefDNSProfiles, out)
}

// DefaultDNSProfileID is the DNS profile pre-selected in the UI ("" = none).
func (a *ACMEHandler) DefaultDNSProfileID() string {
	id := a.prefGet(prefDefaultDNS)
	if id == "" {
		return ""
	}
	if _, err := a.GetDNSProfile(id); err != nil {
		return ""
	}
	return id
}

// SetDefaultDNSProfile selects the default DNS profile ("" clears it).
func (a *ACMEHandler) SetDefaultDNSProfile(id string) error {
	if id != "" {
		if _, err := a.GetDNSProfile(id); err != nil {
			return err
		}
	}
	return a.prefSet(prefDefaultDNS, id)
}

// Masked returns a copy safe for the browser: every credential value except the polling settings is replaced by SecretMask.
func (p DNSProfile) Masked() DNSProfile {
	var m map[string]any
	if json.Unmarshal([]byte(p.Credentials), &m) == nil {
		for k, v := range m {
			if k == "PollingInterval" || k == "PropagationTimeout" {
				continue
			}
			if s, ok := v.(string); ok && s == "" {
				continue
			}
			m[k] = SecretMask
		}
		b, _ := json.Marshal(m)
		p.Credentials = string(b)
	} else {
		p.Credentials = "{}"
	}
	return p
}
