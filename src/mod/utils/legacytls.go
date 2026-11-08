package utils

import "crypto/tls"

// InsecureUpstreamTLSConfig returns the TLS client configuration for upstreams on which the administrator
// switched certificate verification off ("Skip Verification"). Such upstreams are typically appliances
// (IPMI/BMC, printers, old NAS firmware) with a self-signed certificate that only speak TLS 1.0/1.1 or
// legacy RSA key exchange cipher suites, which Go's client does not offer by default and which
// show up as "remote error: tls: handshake failure" (upstream #971). Verification is already
// off for these upstreams, so also accepting the legacy suites does not weaken anything further.
func InsecureUpstreamTLSConfig(serverName string) *tls.Config {
	suites := []uint16{}
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       suites,
	}
}
