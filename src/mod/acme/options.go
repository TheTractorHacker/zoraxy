package acme

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

/*
	options.go

	Per request / per certificate issuance options that go beyond the long positional
	argument list of ObtainCert, plus the small preference store (table "acmepref")
	used for the defaults (key type, default DNS credential profile).
*/

// ObtainOptions are optional extras for ObtainCertWithOptions. The zero value reproduces
// the behaviour of ObtainCert exactly.
type ObtainOptions struct {
	KeyType      string // RSA2048, RSA3072, RSA4096, EC256, EC384. Empty = stored value / default preference / RSA2048
	Profile      string // ACME profile (RFC draft "profile" extension, e.g. "shortlived"). Empty = CA default
	CAProfileID  string // ID of a saved CA profile (custom directory URL, EAB). Empty = use caName / caUrl arguments
	DNSProfileID string // ID of a saved DNS credential profile. Empty = per certificate credentials
}

// CertEvent describes the outcome of an issuance, passed to ACMEHandler.OnEvent.
type CertEvent struct {
	Type     string // EventCertIssued or EventCertFailed
	CertName string
	Domains  []string
	Expiry   time.Time // zero when unknown (failures)
	CA       string
	Error    string
}

// Event types emitted by the ACME handler
const (
	EventCertIssued = "certificate.issued"
	EventCertFailed = "certificate.renewal_failed"
)

const (
	prefKeyType     = "keytype"
	prefDefaultDNS  = "default_dns_profile"
	prefCAProfiles  = "ca_profiles"
	prefDNSProfiles = "dns_profiles"
	prefTableName   = acmeAccountTable
)

// prefGet reads a string preference; missing / no database yields "".
func (a *ACMEHandler) prefGet(key string) string {
	if a.Database == nil || !a.Database.TableExists(prefTableName) || !a.Database.KeyExists(prefTableName, key) {
		return ""
	}
	var v string
	if err := a.Database.Read(prefTableName, key, &v); err != nil {
		return ""
	}
	return v
}

func (a *ACMEHandler) prefSet(key string, value string) error {
	if a.Database == nil {
		return errors.New("database not available")
	}
	if !a.Database.TableExists(prefTableName) {
		if err := a.Database.NewTable(prefTableName); err != nil {
			return err
		}
	}
	return a.Database.Write(prefTableName, key, value)
}

// resolveKeyType picks the key type for an issuance: explicit request, then the value stored in
// the certificate's metadata (renewal keeps the key type), then the ACME default preference,
// then RSA2048.
func (a *ACMEHandler) resolveKeyType(requested string, stored string) string {
	for _, c := range []string{requested, stored, a.prefGet(prefKeyType)} {
		if n, err := NormalizeKeyType(c); err == nil && n != "" {
			return n
		}
	}
	return DefaultKeyType
}

// DefaultKeyType returns the configured default key type for new certificates.
func (a *ACMEHandler) DefaultKeyTypePref() string {
	return a.resolveKeyType("", "")
}

// SetDefaultKeyType stores the default key type for new certificates ("" resets).
func (a *ACMEHandler) SetDefaultKeyType(name string) error {
	n, err := NormalizeKeyType(name)
	if err != nil {
		return err
	}
	return a.prefSet(prefKeyType, n)
}

// IsExternallyManaged reports whether the certificate metadata says the certificate is not issued by
// this ACME handler (uploaded / mapped directory / CSR), so it must never be auto renewed.
func (c *CertificateInfoJSON) IsExternallyManaged() bool {
	switch strings.ToLower(c.ManagedBy) {
	case "", "acme":
		return false
	}
	return true
}

var (
	errNoDomains         = errors.New("could not read the domains of this certificate")
	errExternallyManaged = errors.New("this certificate is managed externally (uploaded, mapped directory or CSR) and cannot be renewed by ACME")
)

// SaveCertInfoJSON writes certificate metadata (the <name>.json next to <name>.pem).
func SaveCertInfoJSON(filename string, info *CertificateInfoJSON, mode os.FileMode) error {
	js, err := json.Marshal(info)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filename, js, mode); err != nil {
		return err
	}
	return os.Chmod(filename, mode)
}
