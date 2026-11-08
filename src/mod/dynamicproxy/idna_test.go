package dynamicproxy

import (
	"testing"
)

// Upstream #458: a rule typed with the Unicode spelling must match requests carrying the punycode Host
// (that is what every browser sends), and vice versa; aliases and wildcards too.
func TestProxyRuleMatchesUnicodeAndPunycodeHost(t *testing.T) {
	router, _, _ := newNonTLSTestRouter(t)

	uni := &ProxyEndpoint{RootOrMatchingDomain: "Bücher.Example", parent: router, MatchingDomainAlias: []string{"café.example"}}
	pun := &ProxyEndpoint{RootOrMatchingDomain: "xn--mnchen-3ya.de", parent: router}
	wild := &ProxyEndpoint{RootOrMatchingDomain: "*.bücher.example", parent: router}
	for _, e := range []*ProxyEndpoint{uni, pun, wild} {
		if err := router.AddProxyRouteToRuntime(e); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		host string
		want *ProxyEndpoint
	}{
		{"xn--bcher-kva.example", uni},
		{"bücher.example", uni},
		{"XN--BCHER-KVA.EXAMPLE", uni},
		{"xn--caf-dma.example", uni}, // alias typed as unicode
		{"münchen.de", pun},
		{"xn--mnchen-3ya.de", pun},
		{"shop.xn--bcher-kva.example", wild},
		{"shop.bücher.example", wild},
		{"other.example", nil},
	}
	for _, c := range cases {
		if got := router.GetProxyEndpointFromHostname(c.host); got != c.want {
			t.Errorf("host %q matched %v, want %v", c.host, got, c.want)
		}
	}
}
