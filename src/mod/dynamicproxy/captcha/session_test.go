package captcha

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	s := NewSessionStoreWithSecret("node-a")
	tok, exp := s.Issue("App.Example.com:443", 3600)
	if time.Until(exp) < 59*time.Minute {
		t.Fatalf("expiry too early: %v", exp)
	}
	if ok, why := s.Validate("app.example.com", tok); !ok {
		t.Fatalf("fresh session rejected: %s", why)
	}
}

// The reported bug: sessions were in memory and vanished on restart, so users
// were challenged again. A new store built from the same secret must accept them.
func TestSessionSurvivesRestartAndIsSharedBetweenNodes(t *testing.T) {
	tok, _ := NewSessionStoreWithSecret("shared-secret").Issue("a.example.com", 3600)
	restarted := NewSessionStoreWithSecret("shared-secret")
	if ok, why := restarted.Validate("a.example.com", tok); !ok {
		t.Fatalf("session lost across restart/node: %s", why)
	}
}

func TestSessionRejections(t *testing.T) {
	s := NewSessionStoreWithSecret("secret")
	tok, _ := s.Issue("a.example.com", 3600)

	cases := []struct {
		name, host, token, reason string
	}{
		{"other host", "b.example.com", tok, ReasonHost},
		{"other secret", "a.example.com", func() string { t, _ := NewSessionStoreWithSecret("x").Issue("a.example.com", 3600); return t }(), ReasonInvalid},
		{"random store", "a.example.com", func() string { t, _ := NewSessionStore().Issue("a.example.com", 3600); return t }(), ReasonInvalid},
		{"tampered mac", "a.example.com", tok[:len(tok)-2] + "AA", ReasonInvalid},
		{"tampered payload", "a.example.com", "x" + tok, ReasonInvalid},
		{"garbage", "a.example.com", "not-a-token", ReasonInvalid},
		{"empty", "a.example.com", "", ReasonInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, why := s.Validate(c.host, c.token)
			if ok || why != c.reason {
				t.Fatalf("got ok=%v reason=%q, want rejected with %q", ok, why, c.reason)
			}
		})
	}
}

func TestSessionExpires(t *testing.T) {
	s := NewSessionStoreWithSecret("secret")
	// Build an already-expired but correctly signed token.
	payload := tokenVersion + "|1|a.example.com"
	tok := encodeForTest(s, payload)
	if ok, why := s.Validate("a.example.com", tok); ok || why != ReasonExpired {
		t.Fatalf("expired token: ok=%v reason=%q", ok, why)
	}
}

func encodeForTest(s *SessionStore, payload string) string {
	// reuse Issue's encoding by signing the given payload directly
	return b64(payload) + "." + b64(string(s.sign(payload)))
}

func TestClampSessionDuration(t *testing.T) {
	for in, want := range map[int]int{
		-5: DefaultSessionDuration, 0: DefaultSessionDuration, 1: MinSessionDuration, 30: MinSessionDuration,
		60: 60, 3600: 3600, MaxSessionDuration: MaxSessionDuration, MaxSessionDuration + 1: MaxSessionDuration,
	} {
		if got := ClampSessionDuration(in); got != want {
			t.Errorf("ClampSessionDuration(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestCheckSessionReason(t *testing.T) {
	s := NewSessionStoreWithSecret("secret")
	r := httptest.NewRequest("GET", "http://a.example.com/", nil)
	if ok, why := CheckSessionReason(r, s); ok || why != ReasonMissing {
		t.Fatalf("no cookie: ok=%v reason=%q", ok, why)
	}
	tok, _ := s.Issue("a.example.com", 3600)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	if ok, why := CheckSessionReason(r, s); !ok {
		t.Fatalf("valid cookie rejected: %s", why)
	}
	if !strings.Contains(tok, ".") {
		t.Fatal("token format changed unexpectedly")
	}
}

func b64(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
