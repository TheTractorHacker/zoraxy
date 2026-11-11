package dynamicproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
	waf_challenge.go

	Challenge half of the WAF graduated response (see waf/bands.go).

	A request whose anomaly score is in the challenge band gets the endpoint's CAPTCHA page (the same providers,
	branding and verification as "Require CAPTCHA", HTTP 403 like every CAPTCHA page). When the visitor solves it
	the verification answer carries a second cookie, zoraxy_waf_challenge, that is

	  - signed (HMAC-SHA256) with a random per-install key kept in the conf folder (waf_challenge.key),
	  - bound to the client IP, the User-Agent hash, the endpoint and an expiry (ChallengeTTLMinutes),
	  - HttpOnly, SameSite=Lax, Secure when the connection is TLS.

	While it is valid, requests in the challenge band pass (logged as challenge_passed). It has no effect on the
	block band. Challenged requests are never counted by the automatic abuse ban.

	No CAPTCHA provider configured on the endpoint: the challenge band is a block (fail closed), see bands.go.
*/

const (
	wafChallengeCookie  = "zoraxy_waf_challenge"
	wafChallengeVersion = "w1"
	wafChallengeKeyLen  = 32
)

// wafChallengeSigner signs and verifies challenge cookies
type wafChallengeSigner struct {
	key []byte
}

// loadWAFChallengeKey reads the install key from path, creating it (0600) when missing. With an empty path, or
// when the file cannot be used, a random in-memory key is used: challenge cookies then do not survive a restart.
func loadWAFChallengeKey(path string) []byte {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) >= wafChallengeKeyLen {
				return k
			}
		}
	}
	key := make([]byte, wafChallengeKeyLen)
	if _, err := rand.Read(key); err != nil {
		panic("waf challenge: cannot read system randomness: " + err.Error())
	}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err == nil {
			os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0600)
		}
	}
	return key
}

func (router *Router) wafChallengeSigner() *wafChallengeSigner {
	if s := router.wafChallenge.Load(); s != nil {
		return s
	}
	path := ""
	if router.Option != nil {
		path = router.Option.WAFChallengeKeyFile
	}
	s := &wafChallengeSigner{key: loadWAFChallengeKey(path)}
	if router.wafChallenge.CompareAndSwap(nil, s) {
		return s
	}
	return router.wafChallenge.Load()
}

func (s *wafChallengeSigner) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("zoraxy-waf-challenge|"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// challengeIPKey reduces a client address to the form that is signed (no port, canonical text)
func challengeIPKey(clientIP string) string {
	host := clientIP
	if h, _, err := net.SplitHostPort(clientIP); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func challengeUAKey(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:12])
}

func challengeEndpointKey(endpoint string) string {
	return strings.ToLower(strings.TrimSpace(endpoint))
}

func (s *wafChallengeSigner) payload(expires time.Time, endpoint, clientIP, ua string) string {
	return strings.Join([]string{wafChallengeVersion, strconv.FormatInt(expires.Unix(), 10),
		base64.RawURLEncoding.EncodeToString([]byte(challengeEndpointKey(endpoint))),
		challengeIPKey(clientIP), challengeUAKey(ua)}, "|")
}

// Issue creates a cookie value valid for ttl
func (s *wafChallengeSigner) Issue(endpoint, clientIP, ua string, ttl time.Duration) (value string, expires time.Time) {
	expires = time.Now().Add(ttl)
	p := s.payload(expires, endpoint, clientIP, ua)
	return base64.RawURLEncoding.EncodeToString([]byte(p)) + "." + base64.RawURLEncoding.EncodeToString(s.mac(p)), expires
}

// Validate reports whether value is an unexpired cookie issued for exactly this endpoint, client IP and User-Agent
func (s *wafChallengeSigner) Validate(value, endpoint, clientIP, ua string) bool {
	encP, encM, found := strings.Cut(value, ".")
	if !found || len(value) > 1024 {
		return false
	}
	pb, err1 := base64.RawURLEncoding.DecodeString(encP)
	got, err2 := base64.RawURLEncoding.DecodeString(encM)
	if err1 != nil || err2 != nil {
		return false
	}
	p := string(pb)
	if !hmac.Equal(got, s.mac(p)) {
		return false
	}
	parts := strings.Split(p, "|")
	if len(parts) != 5 || parts[0] != wafChallengeVersion {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	// The binding is recomputed and compared as a whole (constant time) against the signed payload
	want := s.payload(time.Unix(exp, 0), endpoint, clientIP, ua)
	return hmac.Equal([]byte(want), pb)
}

// wafChallengeValid checks the request's challenge cookie
func (router *Router) wafChallengeValid(r *http.Request, sep *ProxyEndpoint, clientIP string) bool {
	c, err := r.Cookie(wafChallengeCookie)
	if err != nil {
		return false
	}
	return router.wafChallengeSigner().Validate(c.Value, sep.RootOrMatchingDomain, clientIP, r.UserAgent())
}

// challengeCookieWriter adds the WAF challenge cookie to a successful CAPTCHA verification answer. The captcha
// package signals success by setting its session cookie before it writes the answer; the cookie is added at that
// moment because headers cannot be changed afterwards.
type challengeCookieWriter struct {
	http.ResponseWriter
	router   *Router
	r        *http.Request
	sep      *ProxyEndpoint
	clientIP string
	ttl      time.Duration
	done     bool
}

func (w *challengeCookieWriter) addCookie() {
	if w.done {
		return
	}
	w.done = true
	if !captchaVerifiedOK(w.ResponseWriter) {
		return
	}
	value, expires := w.router.wafChallengeSigner().Issue(w.sep.RootOrMatchingDomain, w.clientIP, w.r.UserAgent(), w.ttl)
	http.SetCookie(w.ResponseWriter, &http.Cookie{
		Name:     wafChallengeCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int(w.ttl.Seconds()),
		Expires:  expires,
		HttpOnly: true,
		Secure:   w.r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func (w *challengeCookieWriter) WriteHeader(code int) {
	w.addCookie()
	w.ResponseWriter.WriteHeader(code)
}

func (w *challengeCookieWriter) Write(b []byte) (int, error) {
	w.addCookie()
	return w.ResponseWriter.Write(b)
}

func (w *challengeCookieWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// wafChallengeAvailable reports whether the endpoint can serve a challenge (a configured CAPTCHA provider)
func (router *Router) wafChallengeAvailable(sep *ProxyEndpoint) bool {
	return sep != nil && sep.EffectiveCaptchaConfig().IsConfigured() && router.captchaSessionStore != nil
}

// wafChallengeVerify handles the CAPTCHA verification endpoints for the challenge band. It runs before WAF
// inspection (the paths are answered by the captcha package and never forwarded) so that solving a challenge can
// not itself end up in the challenge band. Returns true when the request was answered.
func (router *Router) wafChallengeVerify(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, cfg *waf.Config, clientIP string) bool {
	if !cfg.ChallengeEnabled() || !router.wafChallengeAvailable(sep) {
		return false
	}
	if r.URL.Path == captcha.AltchaChallengePath && sep.EffectiveCaptchaConfig().Provider == captcha.ProviderAltcha {
		captcha.HandleAltchaChallenge(w, r, sep.EffectiveCaptchaConfig())
		return true
	}
	if r.URL.Path != captcha.VerifyPath {
		return false
	}
	cw := &challengeCookieWriter{ResponseWriter: w, router: router, r: r, sep: sep, clientIP: clientIP, ttl: cfg.ChallengeTTL()}
	captcha.HandleVerification(cw, r, sep.EffectiveCaptchaConfig(), router.captchaSessionStore, clientIP)
	router.recordCaptchaVerification(w, sep)
	if !captchaVerifiedOK(w) {
		abuseNoteKind(r, abuse.KindCaptchaFail)
	}
	return true
}

// wafServeChallenge writes the challenge page for a request in the challenge band
func (router *Router) wafServeChallenge(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, detail string) {
	// A challenge is not a block: it must not count towards the automatic ban (the status would otherwise be
	// read as a plain 403). An empty kind is "noted, nothing to report".
	abuseNoteKind(r, "")
	w.Header().Set("X-Zoraxy-Captcha-Reason", "waf-challenge")
	domain := r.Host
	if domain == "" {
		domain = sep.RootOrMatchingDomain
	}
	captcha.RenderChallenge(w, r, sep.EffectiveCaptchaConfig(), domain, router.Option.WebDirectory)
	router.Option.Metrics.Event(metrics.EventCaptchaChallenge, sep.RootOrMatchingDomain, "waf-challenge")
	router.logRequestDetail(r, false, http.StatusForbidden, "waf-challenged", r.Host, "", sep, detail)
}
