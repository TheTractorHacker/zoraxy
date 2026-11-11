package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/gorilla/securecookie"
)

func sessAgent(t *testing.T) (*AuthAgent, *time.Time) {
	t.Helper()
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("admin", "correct-horse-battery", "")
	now := time.Now()
	a.nowFn = func() time.Time { return now }
	return a, &now
}

func loginRemember(t *testing.T, a *AuthAgent, remember bool) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}}
	if remember {
		form.Set("rmbme", "true")
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.1:1234"
	w := httptest.NewRecorder()
	a.HandleLogin(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == a.SessionName && c.Value != "" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestSessionSettingsDefaultsUnchanged(t *testing.T) {
	d := DefaultSessionSettings()
	if d.LifetimeMinutes != 60 || d.RememberDays != 7 || d.SlidingExtend {
		t.Fatalf("defaults changed: %+v", d)
	}
	a, _ := sessAgent(t)
	if a.SessionSettings() != d {
		t.Fatal("fresh agent must use the defaults")
	}
	if c := loginRemember(t, a, false); c.MaxAge != 3600 {
		t.Fatalf("default login Max-Age = %d, want 3600", c.MaxAge)
	}
	if c := loginRemember(t, a, true); c.MaxAge != 7*24*3600 {
		t.Fatalf("default remember Max-Age = %d, want 604800", c.MaxAge)
	}
}

func TestSessionSettingsValidation(t *testing.T) {
	ok := []SessionSettings{{5, 1, false}, {43200, 365, true}, {60, 7, false}}
	bad := []SessionSettings{{4, 7, false}, {43201, 7, false}, {0, 7, false}, {60, 0, false}, {60, 366, false}, {-1, -1, true}}
	for _, s := range ok {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", s, err)
		}
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

func TestSessionSettingsSaveLoadAndApplyWithoutRestart(t *testing.T) {
	a, _ := sessAgent(t)
	if err := a.SetSessionSettings(SessionSettings{LifetimeMinutes: 5, RememberDays: 30, SlidingExtend: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetSessionSettings(SessionSettings{LifetimeMinutes: 1, RememberDays: 7}); err == nil {
		t.Fatal("invalid settings stored")
	}
	if a.SessionSettings().LifetimeMinutes != 5 {
		t.Fatal("a rejected save must keep the previous settings")
	}
	if c := loginRemember(t, a, false); c.MaxAge != 300 {
		t.Fatalf("Max-Age = %d, want 300 right after saving", c.MaxAge)
	}
	if c := loginRemember(t, a, true); c.MaxAge != 30*24*3600 {
		t.Fatalf("remember Max-Age = %d", c.MaxAge)
	}
	//a new agent on the same database (a restart) loads them
	b := NewAuthenticationAgent("test", []byte("0123456789abcdef0123456789abcdef"), a.Database, false, a.Logger, nil)
	if got := b.SessionSettings(); got != (SessionSettings{5, 30, true}) {
		t.Fatalf("after restart: %+v", got)
	}
	//corrupt stored values fall back to the defaults
	a.Database.Write("settings", "adminSession", SessionSettings{LifetimeMinutes: 1, RememberDays: 999})
	c := NewAuthenticationAgent("test", []byte("0123456789abcdef0123456789abcdef"), a.Database, false, a.Logger, nil)
	if c.SessionSettings() != DefaultSessionSettings() {
		t.Fatal("invalid stored settings must fall back to defaults")
	}
}

func TestExistingSessionKeepsOldExpiry(t *testing.T) {
	a, now := sessAgent(t)
	old := loginRemember(t, a, false) //1 hour
	a.SetSessionSettings(SessionSettings{LifetimeMinutes: 5, RememberDays: 7})
	*now = now.Add(30 * time.Minute)
	if !a.CheckAuth(reqWith(old, "GET", "/", nil)) {
		t.Fatal("session issued with the old 1 hour lifetime must still be valid after 30 minutes")
	}
	*now = now.Add(31 * time.Minute)
	if a.CheckAuth(reqWith(old, "GET", "/", nil)) {
		t.Fatal("session must end after its own 1 hour")
	}
}

func TestServerSideExpiry(t *testing.T) {
	a, now := sessAgent(t)
	a.SetSessionSettings(SessionSettings{LifetimeMinutes: 5, RememberDays: 7})
	c := loginRemember(t, a, false)
	*now = now.Add(4 * time.Minute)
	if !a.CheckAuth(reqWith(c, "GET", "/", nil)) {
		t.Fatal("valid before expiry")
	}
	*now = now.Add(2 * time.Minute)
	if a.CheckAuth(reqWith(c, "GET", "/", nil)) {
		t.Fatal("a cookie that a client keeps beyond the lifetime must be refused by the server")
	}
}

// A session from before this feature has no expiry stamp and keeps working
func TestLegacySessionWithoutExpiryStillValid(t *testing.T) {
	a, _ := sessAgent(t)
	s, _ := a.SessionStore.New(httptest.NewRequest("GET", "/", nil), a.SessionName)
	s.Values["authenticated"] = true
	s.Values["username"] = "admin"
	s.Values["sessver"] = a.loadState("admin").ver
	w := httptest.NewRecorder()
	s.Save(httptest.NewRequest("GET", "/", nil), w)
	if !a.CheckAuth(reqWith(w.Result().Cookies()[0], "GET", "/", nil)) {
		t.Fatal("legacy session rejected")
	}
}

// setCodecClock makes a securecookie codec stamp its values with the given clock (the field is unexported)
func setCodecClock(t *testing.T, sc *securecookie.SecureCookie, f func() int64) {
	t.Helper()
	fld := reflect.ValueOf(sc).Elem().FieldByName("timeFunc")
	reflect.NewAt(fld.Type(), unsafe.Pointer(fld.UnsafeAddr())).Elem().Set(reflect.ValueOf(f))
}

// A cookie issued 60 days ago, with a 365 day remember me lifetime, must still validate. securecookie's own
// default (30 days) would reject it, so this fails if the store does not raise MaxAge.
func TestRememberMeSixtyDaysValidates(t *testing.T) {
	a, now := sessAgent(t)
	if err := a.SetSessionSettings(SessionSettings{LifetimeMinutes: 60, RememberDays: 365}); err != nil {
		t.Fatal(err)
	}
	c := loginRemember(t, a, true)
	if c.MaxAge != 365*24*3600 {
		t.Fatalf("Max-Age = %d", c.MaxAge)
	}
	//re-encode the same session as if it was issued 60 days ago, then let 60 days pass
	sc := a.SessionStore.Codecs[0].(*securecookie.SecureCookie)
	var vals map[interface{}]interface{}
	if err := sc.Decode(a.SessionName, c.Value, &vals); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().Add(-60 * 24 * time.Hour).Unix()
	setCodecClock(t, sc, func() int64 { return issued })
	old, err := sc.Encode(a.SessionName, vals)
	setCodecClock(t, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(60 * 24 * time.Hour)
	oldCookie := &http.Cookie{Name: a.SessionName, Value: old}
	if !a.CheckAuth(reqWith(oldCookie, "GET", "/", nil)) {
		t.Fatal("a session cookie that is 60 days old (remember me 365 days) must validate")
	}
	//control: a codec with securecookie's default 30 days refuses the very same value
	def := securecookie.New([]byte("0123456789abcdef0123456789abcdef"), nil)
	var dst map[interface{}]interface{}
	if def.Decode(a.SessionName, old, &dst) == nil {
		t.Fatal("test setup: the default 30 day codec should reject this cookie")
	}
}

// A cookie from before this feature (no "exp") keeps the old 30 day server side limit, although the store
// limit is now a year.
func TestLegacySessionKeepsThirtyDayLimit(t *testing.T) {
	a, _ := sessAgent(t)
	vals := map[interface{}]interface{}{"authenticated": true, "username": "admin", "sessver": a.loadState("admin").ver}
	sc := a.SessionStore.Codecs[0].(*securecookie.SecureCookie)
	mk := func(days int) *http.Cookie {
		issued := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
		setCodecClock(t, sc, func() int64 { return issued })
		v, err := sc.Encode(a.SessionName, vals)
		setCodecClock(t, sc, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: a.SessionName, Value: v}
	}
	if !a.CheckAuth(reqWith(mk(10), "GET", "/", nil)) {
		t.Fatal("a 10 day old legacy cookie must still be valid")
	}
	if a.CheckAuth(reqWith(mk(40), "GET", "/", nil)) {
		t.Fatal("a 40 day old legacy cookie (no exp) must be refused as before")
	}
}

func TestSlidingExtend(t *testing.T) {
	a, now := sessAgent(t)
	a.SetSessionSettings(SessionSettings{LifetimeMinutes: 60, RememberDays: 7, SlidingExtend: true})
	c := loginRemember(t, a, false)
	touch := func() *http.Cookie {
		w := httptest.NewRecorder()
		a.RefreshSession(w, reqWith(c, "POST", "/api/x", nil))
		for _, ck := range w.Result().Cookies() {
			return ck
		}
		return nil
	}
	//within a few minutes nothing is re-issued (not on every request)
	*now = now.Add(2 * time.Minute)
	if touch() != nil {
		t.Fatal("cookie re-issued on every request")
	}
	//after 5 minutes it is, with a fresh 1 hour
	*now = now.Add(4 * time.Minute)
	n := touch()
	if n == nil || n.MaxAge != 3600 {
		t.Fatalf("expected a re-issued cookie with Max-Age 3600, got %+v", n)
	}
	if !a.CheckAuth(reqWith(n, "GET", "/", nil)) {
		t.Fatal("re-issued cookie must be valid")
	}
	//keep being active: still logged in after more than 3 hours in total
	c = n
	for i := 0; i < 36; i++ {
		*now = now.Add(5*time.Minute + time.Second)
		if r := touch(); r != nil {
			c = r
		}
	}
	if !a.CheckAuth(reqWith(c, "GET", "/", nil)) {
		t.Fatal("an active admin must stay signed in")
	}
	//idle logout still works: no request for longer than the lifetime
	*now = now.Add(61 * time.Minute)
	if a.CheckAuth(reqWith(c, "GET", "/", nil)) {
		t.Fatal("idle session must expire")
	}
	//an expired session is never revived
	if touch() != nil {
		t.Fatal("expired session was re-issued")
	}
}

func TestSlidingOffNeverReissues(t *testing.T) {
	a, now := sessAgent(t)
	c := loginRemember(t, a, false)
	*now = now.Add(30 * time.Minute)
	w := httptest.NewRecorder()
	a.RefreshSession(w, reqWith(c, "POST", "/api/x", nil))
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("default (sliding off) must never re-issue")
	}
}

func TestSlidingShortLifetimeStillRefreshesBeforeExpiry(t *testing.T) {
	a, now := sessAgent(t)
	a.SetSessionSettings(SessionSettings{LifetimeMinutes: 5, RememberDays: 7, SlidingExtend: true})
	c := loginRemember(t, a, false)
	*now = now.Add(2 * time.Minute)
	w := httptest.NewRecorder()
	a.RefreshSession(w, reqWith(c, "POST", "/api/x", nil))
	if len(w.Result().Cookies()) != 1 {
		t.Fatal("a 5 minute lifetime must refresh before it ends")
	}
}

func TestRememberFlagSurvivesRefresh(t *testing.T) {
	a, now := sessAgent(t)
	a.SetSessionSettings(SessionSettings{LifetimeMinutes: 60, RememberDays: 7, SlidingExtend: true})
	c := loginRemember(t, a, true)
	*now = now.Add(6 * time.Minute)
	w := httptest.NewRecorder()
	a.RefreshSession(w, reqWith(c, "POST", "/api/x", nil))
	r := w.Result().Cookies()
	if len(r) != 1 || r[0].MaxAge != 7*24*3600 {
		t.Fatalf("remember me session must stay a 7 day session: %+v", r)
	}
}

func TestIsActivityRequest(t *testing.T) {
	for _, c := range []struct {
		m, p string
		want bool
	}{{"GET", "/index.html", true}, {"GET", "/components/security/users.html", true}, {"GET", "/api/stats/summary", false}, {"POST", "/api/proxy/add", true}} {
		if got := IsActivityRequest(httptest.NewRequest(c.m, c.p, nil)); got != c.want {
			t.Errorf("%s %s = %v", c.m, c.p, got)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	for in, want := range map[int]string{5: "5 minutes", 60: "1 hour", 90: "1 hour 30 minutes", 1440: "1 day", 2940: "2 days 1 hour", 43200: "30 days"} {
		if got := HumanDuration(in); got != want {
			t.Errorf("%d = %q, want %q", in, got, want)
		}
	}
}

func TestSettingsAPIAdminOnlyAndRefusesBadInput(t *testing.T) {
	a, _ := sessAgent(t)
	c := loginRemember(t, a, false)
	post := func(ck *http.Cookie, form url.Values) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.HandleSessionSettingsSet(w, reqWith(ck, "POST", "/api/auth/sessionSettings/set", form))
		return w
	}
	if w := post(nil, url.Values{"minutes": {"10"}, "days": {"7"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := post(c, url.Values{"minutes": {"3"}, "days": {"7"}}); !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("out of range must be refused: %s", w.Body.String())
	}
	if a.SessionSettings() != DefaultSessionSettings() {
		t.Fatal("a refused save changed the settings")
	}
	if w := post(c, url.Values{"minutes": {"10"}, "days": {"14"}, "sliding": {"true"}}); strings.Contains(w.Body.String(), "error") {
		t.Fatalf("valid save refused: %s", w.Body.String())
	}
	if got := a.SessionSettings(); got != (SessionSettings{10, 14, true}) {
		t.Fatalf("got %+v", got)
	}
}
