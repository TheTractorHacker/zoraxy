package aiassist

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

func testRedactor(p Policy) *Redactor {
	return &Redactor{P: p, Pseudo: func(k, v string) string { return k + "-" + hex.EncodeToString([]byte(v))[:6] }}
}

func randHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }
func randB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", 11+mrand.Intn(200), mrand.Intn(256), mrand.Intn(256), 1+mrand.Intn(254))
}

// Property: random secrets planted in every attacker or user controlled field never appear in the payload.
func TestRedactionProperty(t *testing.T) {
	r := testRedactor(Policy{SendPaths: true})
	for i := 0; i < 300; i++ {
		cookie, token, ip, qv, body, jwt, pass := randHex(16), randB64(24), randIP(), randHex(8)+"Zq", randB64(40), "eyJ"+randB64(12)+"."+randB64(20)+"."+randB64(16), "pw"+randHex(5)
		secrets := []string{cookie, token, ip, qv, body, jwt, pass}
		ev := &waf.Event{Time: time.Now(), Endpoint: "ep", ClientIP: ip, Method: "POST", Host: "h.example",
			Path: "/a/" + token + "/b", URI: "/a/" + token + "/b?id=" + qv + "&session=" + cookie + "&x=" + body,
			Rules: []waf.RuleHit{{ID: 942100, Message: "msg", Variable: "ARGS:q", Data: "body=" + body + " cookie=" + cookie}}}
		be := &blocklog.Entry{Seq: 1, Time: time.Now().Unix(), IP: ip, Host: "h.example", Method: "GET", Path: "/p?token=" + token + "&k=" + qv,
			Reason: "waf", Detail: "Authorization: Bearer " + token + " from " + ip,
			UA: "Mozilla/5.0 Cookie: sid=" + cookie + "; other=" + qv + " jwt " + jwt + " password=" + pass + " " + ip}
		for _, in := range []EventInput{{WAF: ev}, {Block: be}} {
			p, err := r.explainPayload(in)
			if err != nil {
				t.Fatal(err)
			}
			o, err := r.Seal(FeatureExplain, "task", p, "t", "d", explainSchema(), 100)
			if err != nil {
				t.Fatal(err)
			}
			all := o.System + o.User
			for _, sct := range secrets {
				// the cookie value planted in the event is only guaranteed absent when it was attacker text (everything above is)
				if strings.Contains(all, sct) {
					t.Fatalf("iteration %d: %q leaked into %s", i, sct, all)
				}
			}
		}
		tp := r.trafficPayload(RawTraffic{Top404Paths: map[string]int{"/x?pass=" + pass + "&id=" + qv: 3, "/t/" + token: 2}, UserAgents: map[string]int{"ua Cookie: a=" + cookie + " " + ip: 4},
			WAFRules: map[string]int{"942100 " + token: 1}, TopIPs: map[string]int{ip: 9}})
		o, err := r.Seal(FeatureSuggest, "task", tp, "t", "d", proposalsSchema(), 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, sct := range []string{cookie, token, ip, qv, pass} {
			if strings.Contains(o.User, sct) {
				t.Fatalf("traffic leak %q in %s", sct, o.User)
			}
		}
	}
}

func TestRedactionRealIPsOnlyWhenAllowed(t *testing.T) {
	on := testRedactor(Policy{SendIPs: true, SendPaths: true})
	if on.IP("203.0.113.5") != "203.0.113.5" {
		t.Fatal("allowed IP changed")
	}
	off := testRedactor(Policy{SendPaths: true})
	if off.IP("203.0.113.5") == "203.0.113.5" || !strings.HasPrefix(off.IP("203.0.113.5"), "ip-") {
		t.Fatal("pseudonym expected")
	}
	if got := off.Text("from 203.0.113.5 and 2001:db8::1 via Chrome/120.0.0.0", 100); strings.Contains(got, "203.0.113.5") || strings.Contains(got, "2001:db8") || !strings.Contains(got, "Chrome/120.0.0.0") {
		t.Fatalf("text: %q", got)
	}
	// everything in a payload is checked once more: a planted raw IP makes Seal fail closed
	if _, err := off.Seal("x", "task 10.1.2.3", map[string]string{"a": "b"}, "t", "d", nil, 10); err == nil {
		t.Fatal("raw IP in the task text was not caught by the final check")
	}
}

func TestRedactionPoliciesAndFormats(t *testing.T) {
	r := testRedactor(Policy{})
	if r.Path("/secret/path?a=1") != "[hidden by data policy]" {
		t.Fatal("paths must be hidden when the policy says so")
	}
	r = testRedactor(Policy{SendPaths: true})
	got := r.Path("/search?q=hello&user=alice&token=abc#frag")
	if got != "/search?q=[v]&user=[v]&token=[v]" {
		t.Fatalf("path: %q", got)
	}
	if h := testRedactor(Policy{MaskHosts: true}).Host("intranet.corp.example"); !strings.HasPrefix(h, "host-") {
		t.Fatalf("host: %q", h)
	}
	if got := r.Text("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----", 200); strings.Contains(got, "MIIB") {
		t.Fatalf("pem: %q", got)
	}
	if got := r.Text(strings.Repeat("a b ", 500), 100); len([]rune(got)) > 101 {
		t.Fatalf("cap: %d", len(got))
	}
	if got := r.Text("mail me at bob@example.com", 100); strings.Contains(got, "bob@") {
		t.Fatalf("email: %q", got)
	}
	if got := r.Text("a\x00b​c<d>", 100); strings.ContainsAny(got, "\x00<>​") {
		t.Fatalf("control/delimiters: %q", got)
	}
	// a slug is not a token, a hex string is
	if got := r.Text("/blog/my-very-long-article-slug-2024-edition", 100); strings.Contains(got, "[token]") {
		t.Fatalf("slug masked: %q", got)
	}
	if r.Country("de") != "DE" || r.Country("Germany") != "" {
		t.Fatal("country")
	}
	// IP literal parse
	if _, err := netip.ParseAddr(r.IP("not-an-ip")); err == nil {
		t.Fatal("invalid ip passed")
	}
}

func TestPayloadTypesHaveNoBodyOrHeaderFields(t *testing.T) {
	// the structure itself guarantees that bodies, header values and WAF match data cannot be sent
	r := testRedactor(Policy{SendPaths: true, SendIPs: true})
	p, _ := r.explainPayload(EventInput{WAF: wafEvent()})
	o, _ := r.Seal(FeatureExplain, "t", p, "t", "d", nil, 1)
	if strings.Contains(o.User, "OR 1=1") || strings.Contains(o.User, "Matched Data") {
		t.Fatalf("WAF match data was sent: %s", o.User)
	}
}
