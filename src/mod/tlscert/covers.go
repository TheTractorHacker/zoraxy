package tlscert

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CertCoversHost reports whether the stored certificate (by store name, without extension) is valid
// for the host. A wildcard rule host ("*.example.com") is covered only by a certificate listing that
// exact name.
func (m *Manager) CertCoversHost(certName, host string) (bool, error) {
	if certName == "" || strings.ContainsAny(certName, "/\\") || strings.Contains(certName, "..") {
		return false, errors.New("invalid certificate name")
	}
	b, err := os.ReadFile(filepath.Join(m.CertStore, certName+".pem"))
	if err != nil {
		return false, errors.New("certificate not found: " + certName)
	}
	cert := firstCertificate(b)
	if cert == nil {
		return false, errors.New("certificate unreadable: " + certName)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(host, "*") {
		for _, n := range cert.DNSNames {
			if strings.EqualFold(n, host) {
				return true, nil
			}
		}
		return false, nil
	}
	return cert.VerifyHostname(host) == nil, nil
}
