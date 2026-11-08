package cluster

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestKeyMaterialUnsetIsUnchanged(t *testing.T) {
	for _, purpose := range []string{PurposeCaptchaSession, PurposeStickySession} {
		if got := KeyMaterial("", "node-uuid-1", purpose); got != "node-uuid-1" {
			t.Fatalf("without a cluster secret the key input must stay the node UUID, got %q", got)
		}
	}
	var m *Manager
	if got := m.KeyMaterial("abc", PurposeCaptchaSession); got != "abc" {
		t.Fatalf("nil manager must pass the uuid through, got %q", got)
	}
}

func TestKeyMaterialSharedAcrossNodesAndSeparatedByPurpose(t *testing.T) {
	a := KeyMaterial(testSecret, "uuid-A", PurposeCaptchaSession)
	b := KeyMaterial(testSecret, "uuid-B", PurposeCaptchaSession)
	if a != b {
		t.Fatal("nodes with the same secret must derive the same key regardless of UUID")
	}
	if a == KeyMaterial(testSecret, "uuid-A", PurposeStickySession) {
		t.Fatal("different purposes must derive different keys")
	}
	if a == KeyMaterial(testSecret+"x", "uuid-A", PurposeCaptchaSession) {
		t.Fatal("different secrets must derive different keys")
	}
	if strings.Contains(a, testSecret) || strings.Contains(a, "uuid-A") {
		t.Fatal("derived key must not contain its inputs")
	}
	if string(DeriveKey(testSecret, PurposeSyncSign, 32)) == string(DeriveKey(testSecret, PurposeSyncEncrypt, 32)) {
		t.Fatal("signing and encryption keys must differ")
	}
}

func TestCaptchaSessionAcceptedAcrossNodes(t *testing.T) {
	nodeA := captcha.NewSessionStoreWithSecret(KeyMaterial(testSecret, "uuid-A", PurposeCaptchaSession))
	nodeB := captcha.NewSessionStoreWithSecret(KeyMaterial(testSecret, "uuid-B", PurposeCaptchaSession))
	tok, _ := nodeA.Issue("app.example.com", 600)
	if ok, reason := nodeB.Validate("app.example.com", tok); !ok {
		t.Fatalf("node B rejected node A's CAPTCHA session: %s", reason)
	}
	other := captcha.NewSessionStoreWithSecret(KeyMaterial(testSecret+"different", "uuid-B", PurposeCaptchaSession))
	if ok, _ := other.Validate("app.example.com", tok); ok {
		t.Fatal("a node with another secret accepted the session")
	}
	// A cluster session is not valid for a node without the secret
	legacy := captcha.NewSessionStoreWithSecret("uuid-B")
	if ok, _ := legacy.Validate("app.example.com", tok); ok {
		t.Fatal("a standalone node accepted a cluster session")
	}
}

func TestCaptchaUnsetBehaviourUnchanged(t *testing.T) {
	// Without a cluster secret the store is built exactly as before
	before := captcha.NewSessionStoreWithSecret("uuid-A")
	after := captcha.NewSessionStoreWithSecret(KeyMaterial("", "uuid-A", PurposeCaptchaSession))
	tok, _ := before.Issue("h.example.com", 600)
	if ok, _ := after.Validate("h.example.com", tok); !ok {
		t.Fatal("unset cluster secret changed the CAPTCHA key derivation")
	}
	otherNode := captcha.NewSessionStoreWithSecret(KeyMaterial("", "uuid-B", PurposeCaptchaSession))
	if ok, _ := otherNode.Validate("h.example.com", tok); ok {
		t.Fatal("per node isolation must stay without a cluster secret")
	}
}

func newLB(key string) *loadbalance.RouteManager {
	m := &loadbalance.RouteManager{Options: loadbalance.Options{SystemUUID: key}}
	m.ResetSessions()
	return m
}

func TestStickyCookieAcceptedAcrossNodes(t *testing.T) {
	a := newLB(KeyMaterial(testSecret, "uuid-A", PurposeStickySession))
	b := newLB(KeyMaterial(testSecret, "uuid-B", PurposeStickySession))

	req := httptest.NewRequest("GET", "http://x/", nil)
	rec := httptest.NewRecorder()
	sess, _ := a.SessionStore.Get(req, loadbalance.STICKY_SESSION_NAME)
	sess.Values["zr_sid_origin"] = "10.0.0.5:80"
	if err := sess.Save(req, rec); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie issued")
	}

	req2 := httptest.NewRequest("GET", "http://x/", nil)
	req2.AddCookie(cookies[0])
	got, err := b.SessionStore.Get(req2, loadbalance.STICKY_SESSION_NAME)
	if err != nil || got.Values["zr_sid_origin"] != "10.0.0.5:80" {
		t.Fatalf("node B did not accept node A's sticky cookie: %v %v", err, got.Values)
	}

	// Different purpose key (captcha) must not decode the sticky cookie
	wrong := sessions.NewCookieStore([]byte(KeyMaterial(testSecret, "uuid-A", PurposeCaptchaSession)))
	req2b := httptest.NewRequest("GET", "http://x/", nil)
	req2b.AddCookie(cookies[0])
	if g, _ := wrong.Get(req2b, loadbalance.STICKY_SESSION_NAME); g.Values["zr_sid_origin"] != nil {
		t.Fatal("sticky cookie decoded with the captcha purpose key")
	}

	// Unset: per node keys, cookies not shared (unchanged behaviour)
	c := newLB(KeyMaterial("", "uuid-A", PurposeStickySession))
	d := newLB(KeyMaterial("", "uuid-B", PurposeStickySession))
	rec2 := httptest.NewRecorder()
	reqC := httptest.NewRequest("GET", "http://x/", nil)
	s2, _ := c.SessionStore.Get(reqC, loadbalance.STICKY_SESSION_NAME)
	s2.Values["zr_sid_origin"] = "10.0.0.5:80"
	s2.Save(reqC, rec2)
	req3 := httptest.NewRequest("GET", "http://x/", nil)
	req3.AddCookie(rec2.Result().Cookies()[0])
	if g, _ := d.SessionStore.Get(req3, loadbalance.STICKY_SESSION_NAME); g.Values["zr_sid_origin"] != nil {
		t.Fatal("standalone nodes must not share sticky cookies")
	}
	_ = http.StatusOK
}

func TestValidateSecret(t *testing.T) {
	if ValidateSecret("short") == nil {
		t.Fatal("short secret accepted")
	}
	s, err := GenerateSecret()
	if err != nil || len(s) != 64 || ValidateSecret(s) != nil {
		t.Fatalf("generated secret invalid: %q %v", s, err)
	}
	s2, _ := GenerateSecret()
	if s == s2 {
		t.Fatal("generated secrets repeat")
	}
}
