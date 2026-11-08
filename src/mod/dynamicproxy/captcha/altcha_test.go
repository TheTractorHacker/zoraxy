package captcha

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const altchaTestSecret = "unit-test-secret-key-0123456789"

func solveAltcha(t *testing.T, c *AltchaChallenge) int {
	t.Helper()
	for n := 0; n <= c.MaxNumber; n++ {
		if altchaHash(c.Salt, n) == c.Challenge {
			return n
		}
	}
	t.Fatal("challenge has no solution within maxnumber")
	return -1
}

func payloadFor(c *AltchaChallenge, number int) string {
	b, _ := json.Marshal(map[string]interface{}{"algorithm": c.Algorithm, "challenge": c.Challenge, "number": number, "salt": c.Salt, "signature": c.Signature})
	return base64.StdEncoding.EncodeToString(b)
}

func TestAltchaRoundTrip(t *testing.T) {
	now := time.Now()
	c, err := NewAltchaChallenge(altchaTestSecret, 2000, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxNumber != 2000 || c.Algorithm != "SHA-256" || len(c.Challenge) != 64 {
		t.Fatalf("%+v", c)
	}
	n := solveAltcha(t, c)
	if err := VerifyAltcha(payloadFor(c, n), altchaTestSecret, now); err != nil {
		t.Fatalf("valid solution rejected: %v", err)
	}
	// replay of the same solved payload
	if err := VerifyAltcha(payloadFor(c, n), altchaTestSecret, now); err == nil {
		t.Fatal("a solved challenge can be redeemed twice")
	}
}

func TestAltchaRejections(t *testing.T) {
	now := time.Now()
	fresh := func() (*AltchaChallenge, int) {
		c, _ := NewAltchaChallenge(altchaTestSecret, 1000, now)
		return c, solveAltcha(t, c)
	}
	c, n := fresh()
	if VerifyAltcha(payloadFor(c, n+1), altchaTestSecret, now) == nil {
		t.Error("wrong number accepted")
	}
	if VerifyAltcha(payloadFor(c, n), "other-secret", now) == nil {
		t.Error("signature verified with a different secret")
	}
	c, n = fresh()
	if VerifyAltcha(payloadFor(c, n), altchaTestSecret, now.Add(altchaTTL+time.Second)) == nil {
		t.Error("expired challenge accepted")
	}
	// a client cannot mint its own challenge: signature is an HMAC over the challenge
	own := &AltchaChallenge{Algorithm: "SHA-256", Salt: "mine?expires=" + "9999999999", MaxNumber: 10}
	own.Challenge = altchaHash(own.Salt, 3)
	own.Signature = strings.Repeat("0", 64)
	if VerifyAltcha(payloadFor(own, 3), altchaTestSecret, now) == nil {
		t.Error("self made challenge accepted")
	}
	own.Signature = altchaHMAC("guess", own.Challenge)
	if VerifyAltcha(payloadFor(own, 3), altchaTestSecret, now) == nil {
		t.Error("challenge signed with a guessed secret accepted")
	}
	// tampered salt (extended expiry) breaks the hash
	c, n = fresh()
	c.Salt = strings.Replace(c.Salt, "?expires=", "?expires=9", 1)
	if VerifyAltcha(payloadFor(c, n), altchaTestSecret, now) == nil {
		t.Error("salt with extended expiry accepted")
	}
	// garbage
	for _, p := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("{")), base64.StdEncoding.EncodeToString([]byte(`{"algorithm":"MD5"}`)),
		strings.Repeat("A", altchaMaxPayload+1), base64.StdEncoding.EncodeToString([]byte(`{"algorithm":"SHA-256","number":-1,"challenge":"` + strings.Repeat("a", 64) + `"}`))} {
		if VerifyAltcha(p, altchaTestSecret, now) == nil {
			t.Errorf("garbage %.20q accepted", p)
		}
	}
	if VerifyAltcha(payloadFor(c, n), "", now) == nil {
		t.Error("empty secret accepted")
	}
	if _, err := NewAltchaChallenge("", 100, now); err == nil {
		t.Error("challenge issued without a secret")
	}
}

func TestAltchaWorkFactorClamped(t *testing.T) {
	if clampAltchaMax(0) != DefaultAltchaMaxNumber || clampAltchaMax(5) != MinAltchaMaxNumber || clampAltchaMax(1<<40) != MaxAltchaMaxNumber {
		t.Fatal("work factor not clamped")
	}
}

func TestAltchaReplayCacheIsBounded(t *testing.T) {
	r := &altchaReplay{seen: map[string]time.Time{}}
	now := time.Now()
	for i := 0; i < altchaReplayMax; i++ {
		if !r.markUsed(string(rune(i+1))+"x", now.Add(time.Minute), now) {
			t.Fatal("unexpected duplicate")
		}
	}
	if r.markUsed("overflow", now.Add(time.Minute), now) {
		t.Fatal("cache grew beyond its bound while full of live entries")
	}
	if !r.markUsed("overflow", now.Add(time.Minute), now.Add(2*time.Minute)) {
		t.Fatal("expired entries must be reclaimed")
	}
}

func TestAltchaEndToEndVerificationIssuesSession(t *testing.T) {
	cfg := &Config{Provider: ProviderAltcha, SecretKey: altchaTestSecret, AltchaMaxNumber: 2000}
	if !cfg.IsConfigured() {
		t.Fatal("altcha with a secret must count as configured (no site key)")
	}
	if (&Config{Provider: ProviderAltcha}).IsConfigured() {
		t.Fatal("altcha without a secret configured")
	}
	// challenge endpoint
	w := httptest.NewRecorder()
	HandleAltchaChallenge(w, httptest.NewRequest(http.MethodGet, "https://h.example.com"+AltchaChallengePath, nil), cfg)
	var c AltchaChallenge
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bad challenge response: %v %s", err, w.Body.String())
	}
	// not for other providers, not via POST
	w = httptest.NewRecorder()
	HandleAltchaChallenge(w, httptest.NewRequest(http.MethodGet, "/x", nil), &Config{Provider: ProviderCloudflare, SecretKey: "s", SiteKey: "k"})
	if w.Code != 404 {
		t.Fatal("challenge served for a different provider")
	}
	w = httptest.NewRecorder()
	HandleAltchaChallenge(w, httptest.NewRequest(http.MethodPost, "/x", nil), cfg)
	if w.Code != 404 {
		t.Fatal("challenge served on POST")
	}

	store := NewSessionStore()
	post := func(field, val string) *httptest.ResponseRecorder {
		form := url.Values{field: {val}}
		r := httptest.NewRequest(http.MethodPost, "https://h.example.com"+VerifyPath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		HandleVerification(rec, r, cfg, store, "198.51.100.1")
		return rec
	}
	n := solveAltcha(t, &c)
	// a token in another provider's field is not accepted
	if rec := post("cf-turnstile-response", payloadFor(&c, n)); rec.Code == 200 {
		t.Fatal("payload accepted from the wrong form field")
	}
	rec := post(AltchaField, payloadFor(&c, n))
	if rec.Code != 200 {
		t.Fatalf("valid payload refused: %d %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == CookieName {
			found = true
		}
	}
	if !found {
		t.Fatal("no session cookie issued")
	}
	if rec := post(AltchaField, payloadFor(&c, n)); rec.Code == 200 {
		t.Fatal("replayed payload issued a second session")
	}
	// the page gets the altcha client config and loads no third party script
	var b strings.Builder
	rw := httptest.NewRecorder()
	RenderChallenge(rw, httptest.NewRequest(http.MethodGet, "https://h.example.com/", nil), cfg, "h.example.com", "")
	b.WriteString(rw.Body.String())
	if !strings.Contains(b.String(), `"provider":"altcha"`) || !strings.Contains(b.String(), AltchaChallengePath) {
		t.Fatalf("challenge page does not use the altcha provider: %.300s", b.String())
	}
	if csp := rw.Header().Get("Content-Security-Policy"); strings.Contains(csp, "challenges.cloudflare.com") && strings.Contains(csp, "google") {
		t.Logf("note: CSP allows third party hosts: %s", csp)
	}
}
