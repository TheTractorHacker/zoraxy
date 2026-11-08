package updater

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func relHits(f *fixture) int { return f.gh.hit("/repos/o/r/releases") }

func TestCheckUsesCacheThenETag(t *testing.T) {
	f := newFixture(t)
	f.gh.useETag = true
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	ctx := context.Background()

	if _, err := f.m.Check(ctx, true); err != nil {
		t.Fatal(err)
	}
	if relHits(f) != 1 {
		t.Fatalf("hits=%d", relHits(f))
	}
	// a fresh manager (restart) reads the on-disk cache: no request at all
	f.build(nil)
	res, err := f.m.Check(ctx, false)
	if err != nil || !res.UpdateAvailable {
		t.Fatalf("cached check: %v %+v", err, res)
	}
	if relHits(f) != 1 {
		t.Fatalf("cached check hit the network: %d", relHits(f))
	}
	// a forced check revalidates with If-None-Match and gets a 304
	res, err = f.m.Check(ctx, true)
	if err != nil || !res.UpdateAvailable {
		t.Fatalf("forced check: %v", err)
	}
	if relHits(f) != 2 || f.gh.notMod != 1 {
		t.Fatalf("hits=%d notModified=%d", relHits(f), f.gh.notMod)
	}
	// content change: the ETag differs, new data is returned
	f.gh.set(f.release("v3.3.7-x.1", false, time.Hour, "NEWER"))
	res, err = f.m.Check(ctx, true)
	if err != nil || res.Latest.Tag != "v3.3.7-x.1" {
		t.Fatalf("after change: %v %+v", err, res)
	}
}

func TestCacheExpires(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.build(func(c *Config) { c.Hooks.Now = func() time.Time { return now } })
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	f.m.Check(context.Background(), true)
	now = now.Add(9 * time.Minute)
	f.m.cacheMu.Lock()
	f.m.cacheRes = nil
	f.m.cacheMu.Unlock()
	f.m.Check(context.Background(), false)
	if relHits(f) != 1 {
		t.Fatalf("within 10 minutes the cache must be used: %d", relHits(f))
	}
	now = now.Add(2 * time.Minute)
	f.m.cacheMu.Lock()
	f.m.cacheRes = nil
	f.m.cacheMu.Unlock()
	f.m.Check(context.Background(), false)
	if relHits(f) != 2 {
		t.Fatalf("after 10 minutes the list must be fetched again: %d", relHits(f))
	}
}

func TestRateLimitFriendlyMessage(t *testing.T) {
	f := newFixture(t)
	reset := time.Now().Add(37 * time.Minute).Truncate(time.Second)
	f.gh.fail = http.StatusForbidden
	f.gh.failHdr = http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {strconv.FormatInt(reset.Unix(), 10)}}

	_, err := f.m.Check(context.Background(), true)
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("want RateLimitError, got %v", err)
	}
	want := "GitHub rate limit reached, try again at " + reset.Local().Format("15:04")
	if !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("message %q", err.Error())
	}
	// through the API: 429, friendly text, retry_at
	rec := call(f.m.HandleCheck, "GET", "/check?force=true", nil)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), want) || !strings.Contains(rec.Body.String(), "retry_at") {
		t.Fatalf("api: %d %s", rec.Code, rec.Body.String())
	}
	// while limited no further request is made
	n := relHits(f)
	f.m.Check(context.Background(), true)
	if relHits(f) != n {
		t.Fatalf("requests continued during the limit: %d -> %d", n, relHits(f))
	}
}

func TestRetryAfterAndPlain403(t *testing.T) {
	f := newFixture(t)
	f.gh.fail = http.StatusTooManyRequests
	f.gh.failHdr = http.Header{"Retry-After": {"120"}}
	_, err := f.m.Check(context.Background(), true)
	var rl *RateLimitError
	if !errors.As(err, &rl) || time.Until(rl.ResetAt) < 100*time.Second || time.Until(rl.ResetAt) > 130*time.Second {
		t.Fatalf("Retry-After not honoured: %v", err)
	}
	// a 403 without rate limit headers is an ordinary error
	f2 := newFixture(t)
	f2.gh.fail = http.StatusForbidden
	_, err = f2.m.Check(context.Background(), true)
	if err == nil || errors.As(err, &rl) {
		t.Fatalf("plain 403 reported as rate limit: %v", err)
	}
}

func TestGitHubTokenStoredPrivatelyAndSent(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	const tok = "ghp_testtoken123"
	rec := call(f.m.HandleSetToken, "POST", "/t", map[string][]string{"token": {tok}})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), tok) || !strings.Contains(rec.Body.String(), `"has_token":true`) {
		t.Fatalf("set token: %d %s", rec.Code, rec.Body.String())
	}
	st, err := os.Stat(filepath.Join(f.conf, "updater", "github_token"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", st, err)
	}
	// never returned by info
	if rec := call(f.m.HandleInfo, "GET", "/info", nil); strings.Contains(rec.Body.String(), tok) {
		t.Fatal("token leaked through /info")
	}
	if _, err := f.m.Check(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if f.gh.lastAuth != "Bearer "+tok {
		t.Fatalf("Authorization = %q", f.gh.lastAuth)
	}
	// survives a restart, and can be removed
	f.build(nil)
	if !f.m.Settings().HasToken {
		t.Fatal("token lost on restart")
	}
	call(f.m.HandleSetToken, "POST", "/t", map[string][]string{"token": {""}})
	if _, err := os.Stat(filepath.Join(f.conf, "updater", "github_token")); err == nil {
		t.Fatal("token file not removed")
	}
	if call(f.m.HandleSetToken, "POST", "/t", map[string][]string{"token": {"bad token"}}).Code != 400 {
		t.Fatal("invalid token accepted")
	}
}

func TestTokenNotSentToAssetHosts(t *testing.T) {
	if sameHost("https://github.com/o/r/releases/download/x/y", "https://api.github.com") {
		t.Fatal("asset host treated as API host")
	}
	if !sameHost("https://api.github.com/repos/o/r/releases", "https://api.github.com") {
		t.Fatal("API host not recognised")
	}
}
