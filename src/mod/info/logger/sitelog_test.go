package logger

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSafeSiteName(t *testing.T) {
	inputs := []string{
		"example.com", "Example.COM", "../../etc/passwd", "a/b", `a\b`, "..", ".", "", "con", "nul.txt",
		"host\x00.com", "ex ample.com", "日本語.jp", strings.Repeat("a", 500), "a..b", ".hidden", "trailing.", "*.example.com",
	}
	seen := map[string]string{}
	for _, in := range inputs {
		out := SafeSiteName(in)
		if out == "" || out == "." || out == ".." {
			t.Errorf("%q -> unusable %q", in, out)
		}
		if strings.ContainsAny(out, "/\\\x00 ") || strings.Contains(out, "..") || strings.HasPrefix(out, ".") || strings.HasSuffix(out, ".") {
			t.Errorf("%q -> unsafe %q", in, out)
		}
		if len(out) > 100 {
			t.Errorf("%q -> too long (%d)", in, len(out))
		}
		if filepath.Base(out) != out {
			t.Errorf("%q -> not a single path component: %q", in, out)
		}
		if prev, dup := seen[out]; dup && strings.ToLower(prev) != strings.ToLower(in) {
			t.Errorf("collision %q and %q -> %q", prev, in, out)
		}
		seen[out] = in
	}
	if SafeSiteName("example.com") != "example.com" {
		t.Error("plain host names must stay readable")
	}
	if SafeSiteName("a/b") == SafeSiteName("a_b") {
		t.Error("changed names must not collide with literal ones")
	}
}

func newSite(t *testing.T, cfg SiteLogConfig) (*SiteLogs, string) {
	dir := t.TempDir()
	s, err := NewSiteLogs(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, dir
}

func TestSiteLogDefaultOffAndModes(t *testing.T) {
	s, dir := newSite(t, DefaultSiteLogConfig())
	if s.ModeFor("a.example") != SiteLogOff {
		t.Fatal("default must be off")
	}
	if err := s.Write("a.example", SiteLine{Time: time.Now(), Status: 200}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sites")); err == nil {
		t.Fatal("nothing may be written while off")
	}
	cfg := s.Config()
	cfg.Rules["a.example"] = SiteLogOnly
	cfg.Mode = SiteLogAlso
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if s.ModeFor("a.example") != SiteLogOnly || s.ModeFor("b.example") != SiteLogAlso || s.ModeFor("") != SiteLogOff {
		t.Fatal("mode resolution")
	}
	bad := cfg
	bad.Rules = map[string]string{"x": "bogus"}
	if s.SetConfig(bad) == nil {
		t.Fatal("bad mode accepted")
	}
}

func TestSiteLogFormatsAndTraversal(t *testing.T) {
	cfg := DefaultSiteLogConfig()
	cfg.Mode = SiteLogAlso
	s, dir := newSite(t, cfg)
	line := SiteLine{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Class: "host-http", Origin: "a.example", Client: "1.2.3.4", Agent: "ua\ninjected", Method: "GET", URI: "/x?y=1", Status: 200}
	if err := s.Write("a.example", line); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("../../escape", line); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "sites", "a.example", "a.example.log"))
	txt := string(b)
	if !strings.Contains(txt, "[router:host-http] [origin:a.example] [client: 1.2.3.4] [useragent: ua injected] GET /x?y=1 200") || strings.Count(txt, "\n") != 1 {
		t.Fatalf("text line: %q", txt)
	}
	// nothing outside <dir>/sites
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if !strings.HasPrefix(p, dir) {
			t.Errorf("escaped: %s", p)
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape")); err == nil {
		t.Fatal("path traversal")
	}

	cfg.Format = SiteLogFormatJSON
	s.SetConfig(cfg)
	s.Write("b.example", line)
	b, _ = os.ReadFile(filepath.Join(dir, "sites", "b.example", "b.example.log"))
	var got SiteLine
	if err := json.Unmarshal(b, &got); err != nil || got.Status != 200 || got.Site != "b.example" || got.Agent != "ua injected" {
		t.Fatalf("json line: %q %v", b, err)
	}
}

func TestSiteLogRotationGzipRetention(t *testing.T) {
	cfg := DefaultSiteLogConfig()
	cfg.Mode = SiteLogAlso
	cfg.MaxSizeMB = 1
	cfg.MaxBackups = 2
	cfg.Compress = true
	s, dir := newSite(t, cfg)
	var clock int64
	s.Now = func() time.Time {
		clock++
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(clock) * time.Second)
	}
	big := SiteLine{Time: time.Now(), Origin: "a", Client: "c", Agent: strings.Repeat("x", 100000), Method: "GET", URI: "/", Status: 200}
	for i := 0; i < 45; i++ { // ~4.5 MB => at least 4 rotations
		if err := s.Write("rot.example", big); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	var rotated []string
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		rotated = nil
		es, _ := os.ReadDir(filepath.Join(dir, "sites", "rot.example"))
		for _, e := range es {
			if e.Name() != "rot.example.log" {
				rotated = append(rotated, e.Name())
			}
		}
		if len(rotated) == 2 && strings.HasSuffix(rotated[0], ".gz") && strings.HasSuffix(rotated[1], ".gz") {
			break
		}
	}
	if len(rotated) != 2 {
		t.Fatalf("retention should keep 2 rotated files, have %v", rotated)
	}
	f, _ := os.Open(filepath.Join(dir, "sites", "rot.example", rotated[0]))
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := io.Copy(io.Discard, zr); n < 500000 {
		t.Fatalf("rotated gzip content too small: %d", n)
	}
}

func TestSiteLogRetentionByAge(t *testing.T) {
	cfg := DefaultSiteLogConfig()
	cfg.Mode = SiteLogAlso
	cfg.MaxAgeDays = 7
	cfg.MaxBackups = 100
	s, dir := newSite(t, cfg)
	d := filepath.Join(dir, "sites", "age.example")
	os.MkdirAll(d, 0o755)
	oldF := filepath.Join(d, "age.example.20250101-000000.000.log.gz")
	newF := filepath.Join(d, "age.example.20260101-000000.000.log")
	os.WriteFile(oldF, []byte("x"), 0o644)
	os.WriteFile(newF, []byte("x"), 0o644)
	old := time.Now().AddDate(0, 0, -30)
	os.Chtimes(oldF, old, old)
	s.Retention()
	if _, err := os.Stat(oldF); err == nil {
		t.Fatal("old file kept")
	}
	if _, err := os.Stat(newF); err != nil {
		t.Fatal("new file removed")
	}
}

func TestLoggerRoutesToSiteLogs(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("zr", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := DefaultSiteLogConfig()
	cfg.Rules["only.example"] = SiteLogOnly
	cfg.Rules["also.example"] = SiteLogAlso
	sites, _ := NewSiteLogs(dir, cfg)
	defer sites.Close()
	l.Sites = sites
	r := httptest.NewRequest("GET", "/p", nil)
	for _, k := range []string{"only.example", "also.example", "none.example", ""} {
		l.LogHTTPRequestSite(k, r, "host-http", 200, k, "up", "1.1.1.1")
	}
	time.Sleep(300 * time.Millisecond)
	global, _ := os.ReadFile(l.CurrentLogFile)
	g := string(global)
	if strings.Contains(g, "origin:only.example") || !strings.Contains(g, "origin:also.example") || !strings.Contains(g, "origin:none.example") {
		t.Fatalf("global log content wrong:\n%s", g)
	}
	for _, k := range []string{"only.example", "also.example"} {
		if _, err := os.Stat(filepath.Join(dir, "sites", k, k+".log")); err != nil {
			t.Errorf("site log for %s missing", k)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sites", "none.example")); err == nil {
		t.Error("site log for unconfigured rule")
	}
}

func TestSiteLogConcurrent(t *testing.T) {
	cfg := DefaultSiteLogConfig()
	cfg.Mode = SiteLogAlso
	cfg.MaxSizeMB = 1
	s, dir := newSite(t, cfg)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				s.Write("h"+string(rune('a'+(i+g)%60)), SiteLine{Time: time.Now(), Agent: strings.Repeat("y", 200), Status: 200})
			}
		}(g)
	}
	wg.Wait()
	s.Retention()
	es, _ := os.ReadDir(filepath.Join(dir, "sites"))
	if len(es) == 0 {
		t.Fatal("no site dirs")
	}
}
