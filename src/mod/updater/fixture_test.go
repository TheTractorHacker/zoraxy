package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRelease describes one release served by the fake GitHub API.
type fakeRelease struct {
	Tag        string
	Prerelease bool
	Published  time.Time
	Binary     []byte
	// fault injection
	TamperBinary bool // serve different bytes than the ones that were signed
	TamperSums   bool // modify SHA256SUMS after signing
	WrongKey     bool // sign with a different key
	NoSig        bool // omit SHA256SUMS.sig asset
	NoBinary     bool // omit the platform asset
	ArchAssets   []string
}

type fakeGitHub struct {
	t        *testing.T
	srv      *httptest.Server
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	other    ed25519.PrivateKey
	mu       sync.Mutex
	releases []fakeRelease
	hits     map[string]int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	g := &fakeGitHub{t: t, priv: priv, pub: pub, other: other, hits: map[string]int{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) hit(k string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[k]
}

func (g *fakeGitHub) set(r ...fakeRelease) {
	g.mu.Lock()
	g.releases = r
	g.mu.Unlock()
}

const testAsset = "zoraxy_linux_amd64"

func sumsFor(name string, bin []byte) []byte {
	h := sha256.Sum256(bin)
	return []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(h[:]), name))
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.hits[r.URL.Path]++
	rels := append([]fakeRelease(nil), g.releases...)
	g.mu.Unlock()
	if r.URL.Path == "/repos/o/r/releases" {
		var out []map[string]any
		for _, fr := range rels {
			var assets []map[string]any
			add := func(n string, size int) {
				assets = append(assets, map[string]any{"name": n, "size": size,
					"browser_download_url": g.srv.URL + "/dl/" + fr.Tag + "/" + n})
			}
			if !fr.NoBinary {
				add(testAsset, len(fr.Binary))
			}
			for _, a := range fr.ArchAssets {
				add(a, 10)
			}
			add(SumsAsset, 100)
			if !fr.NoSig {
				add(SigAsset, 64)
			}
			out = append(out, map[string]any{"tag_name": fr.Tag, "name": fr.Tag, "body": "notes for " + fr.Tag,
				"html_url": "https://example.invalid/" + fr.Tag, "draft": false, "prerelease": fr.Prerelease,
				"published_at": fr.Published.UTC().Format(time.RFC3339), "assets": assets})
		}
		// a draft that must be ignored
		out = append(out, map[string]any{"tag_name": "v9.9.9", "draft": true, "published_at": time.Now().UTC().Format(time.RFC3339)})
		json.NewEncoder(w).Encode(out)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/dl/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	for _, fr := range rels {
		if fr.Tag != parts[0] {
			continue
		}
		sums := sumsFor(testAsset, fr.Binary)
		key := g.priv
		if fr.WrongKey {
			key = g.other
		}
		sig := ed25519.Sign(key, sums)
		switch parts[1] {
		case testAsset:
			b := fr.Binary
			if fr.TamperBinary {
				b = append(append([]byte(nil), b...), []byte("EVIL")...)
			}
			w.Write(b)
		case SumsAsset:
			if fr.TamperSums {
				sums = append(sums, []byte("# tampered\n")...)
			}
			w.Write(sums)
		case SigAsset:
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
		return
	}
	http.NotFound(w, r)
}

// fixture is an install tree plus a Manager wired to fakes.
type fixture struct {
	t        *testing.T
	root     string
	exe      string
	conf     string
	gh       *fakeGitHub
	m        *Manager
	mu       sync.Mutex
	restarts int
	spawned  int
	smoke    func(ctx context.Context, bin string) (string, error)
	free     uint64
	env      map[string]string
	now      time.Time
}

const oldBinary = "OLD-BINARY-3.3.5"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, root: root, gh: newFakeGitHub(t), free: 10 << 30, env: map[string]string{}, now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	f.exe = filepath.Join(root, "bin", "zoraxy")
	f.conf = filepath.Join(root, "conf")
	must(t, os.MkdirAll(filepath.Dir(f.exe), 0o755))
	must(t, os.MkdirAll(filepath.Join(f.conf, "proxy"), 0o755))
	must(t, os.WriteFile(f.exe, []byte(oldBinary), 0o755))
	must(t, os.WriteFile(filepath.Join(f.conf, "proxy", "a.json"), []byte(`{"a":1}`), 0o644))
	must(t, os.WriteFile(filepath.Join(f.conf, "version"), []byte("335"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "sys.db"), []byte("dbdata"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "sys.uuid"), []byte("uuid-1"), 0o644))
	f.build(nil)
	return f
}

func (f *fixture) build(mut func(*Config)) {
	cfg := Config{
		Repo: "o/r", APIBase: f.gh.srv.URL, Client: f.gh.srv.Client(), AllowHTTP: true,
		ConfDir: f.conf, DBPath: filepath.Join(f.root, "sys.db"), UUIDPath: filepath.Join(f.root, "sys.uuid"),
		CurrentVersion: "3.3.5", Executable: f.exe, Args: []string{"-port=:8000", "-noauth"},
		GOOS: "linux", GOARCH: "amd64", PubKey: f.gh.pub, DockerEnvFile: filepath.Join(f.root, "no-dockerenv"),
		Getenv: func(k string) string { f.mu.Lock(); defer f.mu.Unlock(); return f.env[k] },
		Logf:   func(string, ...any) {}, HealthyTimeout: 5 * time.Second,
		Hooks: Hooks{
			Smoke: func(ctx context.Context, bin string) (string, error) {
				if f.smoke != nil {
					return f.smoke(ctx, bin)
				}
				return "Zoraxy - Version " + f.gh.latestBase(), nil
			},
			Restart: func(exe string, args []string) error {
				f.mu.Lock()
				f.restarts++
				f.mu.Unlock()
				return nil
			},
			SpawnWatchdog: func(prev, marker string) error { f.mu.Lock(); f.spawned++; f.mu.Unlock(); return nil },
			FreeSpace:     func(string) (uint64, error) { return f.free, nil },
			Now:           func() time.Time { return time.Now() },
			RestartDelay:  time.Nanosecond,
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	f.m = New(cfg)
}

func (f *fixture) release(tag string, pre bool, age time.Duration, bin string) fakeRelease {
	return fakeRelease{Tag: tag, Prerelease: pre, Published: time.Now().Add(-age), Binary: []byte(bin)}
}

func (f *fixture) readExe() string {
	b, err := os.ReadFile(f.exe)
	must(f.t, err)
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) leftoverTemp() []string {
	var out []string
	ents, _ := os.ReadDir(filepath.Dir(f.exe))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".zoraxy-update-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// latestBase returns the upstream version of the first served release.
func (g *fakeGitHub) latestBase() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.releases) == 0 {
		return "0.0.0"
	}
	t, _ := ParseTag(g.releases[0].Tag)
	return t.BaseVersion()
}

// unbusy simulates the process having been replaced by the restart.
func (f *fixture) unbusy() {
	f.m.mu.Lock()
	f.m.running = false
	f.m.mu.Unlock()
}

func (f *fixture) restartCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.restarts }
