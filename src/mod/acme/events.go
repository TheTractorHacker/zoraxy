package acme

import (
	"errors"
	"os"
	"strings"
	"time"
)

// obtainAndNotify runs an issuance (issueMu is held by the caller) and reports the outcome to OnEvent.
func (a *ACMEHandler) obtainAndNotify(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool, opts ObtainOptions) (bool, error) {
	ok, err := a.obtainCertLocked(domains, certificateName, email, caName, caUrl, skipTLS, useDNS, propagationTimeout, dnsServers, disableRecursiveNssCheck, disableAuthoritativeNssCheck, opts)
	if a.OnEvent != nil {
		ev := CertEvent{CertName: certificateName, Domains: domains, CA: caName}
		if err != nil || !ok {
			ev.Type = EventCertFailed
			if err != nil {
				ev.Error = err.Error()
			}
		} else {
			ev.Type = EventCertIssued
			if info, ierr := LoadCertInfoJSON(a.certPath(certificateName + ".json")); ierr == nil && info.AcmeName != "" {
				ev.CA = info.AcmeName
			}
			if b, rerr := os.ReadFile(a.certPath(certificateName + ".pem")); rerr == nil {
				if exp, eerr := CertExpiry(b); eerr == nil {
					ev.Expiry = exp
				}
			}
		}
		func() {
			defer func() { recover() }() // a misbehaving subscriber must not break issuance
			a.OnEvent(ev)
		}()
	}
	return ok, err
}

// ObtainCertCapture is ObtainCertWithOptions that also returns the log lines produced by this operation
// (used by the "renew now" button to show progress to the admin).
func (a *ACMEHandler) ObtainCertCapture(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool, opts ObtainOptions) (bool, []string, error) {
	a.issueMu.Lock()
	defer a.issueMu.Unlock()
	var lines []string
	a.logSink = func(s string) { lines = append(lines, redactLogLine(s)) }
	defer func() { a.logSink = nil }()
	if a.beforeIssue != nil {
		if err := a.beforeIssue(); err != nil {
			return false, lines, err
		}
	}
	ok, err := a.obtainAndNotify(domains, certificateName, email, caName, caUrl, skipTLS, useDNS, propagationTimeout, dnsServers, disableRecursiveNssCheck, disableAuthoritativeNssCheck, opts)
	return ok, lines, err
}

// redactLogLine withholds any line that mentions a secret-ish word before it is shown in the UI.
func redactLogLine(s string) string {
	l := strings.ToLower(s)
	for _, w := range []string{"hmac", "password", "secret", "token"} {
		if strings.Contains(l, w) {
			return "[line withheld: may contain a secret]"
		}
	}
	return s
}

// CertExpiry returns the NotAfter of the first certificate in a PEM bundle.
func CertExpiry(certBytes []byte) (time.Time, error) {
	cert, err := firstCert(certBytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

var errNoCert = errors.New("no certificate found")
