package acme

import (
	"errors"
	"strings"
)

// hintedError keeps the original CA error and appends a plain language hint for the most common causes.
type hintedError struct {
	err  error
	hint string
}

func (h *hintedError) Error() string { return h.err.Error() + "\n\nHint: " + h.hint }
func (h *hintedError) Unwrap() error { return h.err }

// explainACMEError appends an actionable hint to well known Let's Encrypt / ACME failures, e.g. the
// "400 urn:ietf:params:acme:error:connection ... Error getting validation data" reported in upstream #537.
// The original message is preserved; errors without a known pattern are returned unchanged.
func explainACMEError(err error, useDNS bool) error {
	if err == nil {
		return nil
	}
	var h *hintedError
	if errors.As(err, &h) {
		return err
	}
	msg := strings.ToLower(err.Error())
	hint := ""
	switch {
	case strings.Contains(msg, "error getting validation data") || strings.Contains(msg, "acme:error:connection"):
		if useDNS {
			hint = "the CA could not reach the validation host. DNS-01 normally does not need inbound access; check that the DNS records are published and propagated."
		} else {
			hint = "the CA could not fetch http://<domain>/.well-known/acme-challenge/<token> from this server. Check that the domain's public DNS (A/AAAA/CNAME, including IPv6 and any dynamic DNS name) points to this Zoraxy, that port 80 is forwarded to it from the internet, and that no firewall, CDN proxy or other web server answers on port 80. Use the DNS challenge for wildcard or internal-only hosts."
		}
	case strings.Contains(msg, "acme:error:unauthorized") || strings.Contains(msg, "invalid response from"):
		hint = "the CA reached a server but received the wrong challenge answer. Another web server or a redirect on port 80 is probably answering for this domain."
	case strings.Contains(msg, "acme:error:dns") || strings.Contains(msg, "no valid a or aaaa") || strings.Contains(msg, "nxdomain"):
		hint = "the domain has no public DNS record the CA can resolve. Create the A/AAAA record first."
	case strings.Contains(msg, "acme:error:ratelimited") || strings.Contains(msg, "too many"):
		hint = "the CA rate limit was hit. Wait before retrying, or switch to the staging CA while testing."
	case strings.Contains(msg, "acme:error:invalidcontact") || strings.Contains(msg, "contact email"):
		hint = "the ACME account email was rejected. Set a real email address (not example.com or a non-existent domain) in the ACME settings."
	case strings.Contains(msg, "acme:error:rejectedidentifier") || strings.Contains(msg, "policy forbids"):
		hint = "the CA refuses this domain name (invalid suffix, IP address or blocked name)."
	}
	if hint == "" {
		return err
	}
	return &hintedError{err: err, hint: hint}
}
