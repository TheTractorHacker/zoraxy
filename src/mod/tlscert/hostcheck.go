package tlscert

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

// Certificate check states reported by CheckHostCertificate
const (
	CertOK         = "ok"         // Covers the name, in date, not self-signed
	CertSelfSigned = "selfsigned" // Covers the name and is in date, but is self-signed: browsers will not trust it unless installed by hand
	CertFallback   = "fallback"   // Nothing matches: the built-in self-signed localhost certificate would be served
	CertMissing    = "missing"    // No certificate could be loaded
	CertExpired    = "expired"    // Covers the name but is expired or not yet valid
	CertMismatch   = "mismatch"   // The certificate that would be served does not cover the name
)

// HostCertCheck says whether the certificate Zoraxy serves for a host name is really valid for it.
// GetCertificateByHostname never fails (it returns the built-in localhost certificate when nothing matches),
// so "a certificate was found" proves nothing.
type HostCertCheck struct {
	Host     string
	State    string
	Valid    bool // true for ok only; selfsigned is a warning
	Reason   string
	Source   string    `json:",omitempty"` // File name the certificate comes from
	Subject  string    `json:",omitempty"`
	Issuer   string    `json:",omitempty"`
	NotAfter time.Time `json:",omitzero"`
}

// EvaluateCertificate judges a loaded certificate for host at time now. fallback marks the built-in localhost certificate.
func EvaluateCertificate(cert *tls.Certificate, host string, fallback bool, now time.Time) HostCertCheck {
	res := HostCertCheck{Host: host}
	if cert == nil || len(cert.Certificate) == 0 {
		res.State, res.Reason = CertMissing, "No certificate is available for "+host+"."
		return res
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		res.State, res.Reason = CertMissing, "The certificate for "+host+" cannot be parsed: "+err.Error()
		return res
	}
	res.Subject, res.Issuer, res.NotAfter = leaf.Subject.String(), leaf.Issuer.String(), leaf.NotAfter
	if fallback {
		res.State = CertFallback
		res.Reason = "No certificate matches " + host + ", so Zoraxy would present its built-in self-signed localhost certificate."
		return res
	}
	if err := leaf.VerifyHostname(host); err != nil {
		res.State = CertMismatch
		res.Reason = "The certificate that would be served for " + host + " does not cover that name."
		return res
	}
	if now.Before(leaf.NotBefore) {
		res.State, res.Reason = CertExpired, "The certificate for "+host+" is not valid before "+leaf.NotBefore.Format("2006-01-02")+"."
		return res
	}
	if now.After(leaf.NotAfter) {
		res.State, res.Reason = CertExpired, "The certificate for "+host+" expired on "+leaf.NotAfter.Format("2006-01-02")+"."
		return res
	}
	if len(cert.Certificate) == 1 && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		res.State = CertSelfSigned
		res.Reason = "The certificate for " + host + " is self-signed. It covers the name but browsers will not trust it."
		return res
	}
	res.State, res.Valid = CertOK, true
	res.Reason = "A valid certificate covers " + host + " (expires " + leaf.NotAfter.Format("2006-01-02") + ")."
	return res
}

// CheckHostCertificate resolves the certificate Zoraxy would serve for host and evaluates it
func (m *Manager) CheckHostCertificate(host string, now time.Time) HostCertCheck {
	host = utils.NormalizeHostname(host)
	pubKey, priKey, err := m.GetCertificateByHostname(host)
	if err != nil {
		return HostCertCheck{Host: host, State: CertMissing, Reason: "No certificate is available for " + host + ": " + err.Error()}
	}
	fallback := pubKey == filepath.Join(m.tmpFolder(), "localhost.pem")
	cert, err := tls.LoadX509KeyPair(pubKey, priKey)
	if err != nil {
		return HostCertCheck{Host: host, State: CertMissing, Reason: "The certificate for " + host + " cannot be loaded: " + err.Error()}
	}
	res := EvaluateCertificate(&cert, host, fallback, now)
	res.Source = filepath.Base(pubKey)
	return res
}
