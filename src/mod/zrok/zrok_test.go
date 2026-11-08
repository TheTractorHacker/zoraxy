package zrok

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const fakeScript = `#!/bin/sh
D="$(dirname "$0")"
{ printf 'CMD'; for a in "$@"; do printf '\t%s' "$a"; done; printf '\n'; } >> "$D/calls.log"
env | sort > "$D/env.log"
MODE=$(cat "$D/mode" 2>/dev/null || echo run)
case "$1" in
  version) echo "fake zrok v1.1.11"; exit 0;;
  config) exit 0;;
  disable) exit 0;;
  reserve) echo "reserved share $4"; exit 0;;
  enable)
    if [ "$MODE" = enablefail ]; then echo "the token $2 was rejected"; exit 1; fi
    echo "enabled environment with token $2"; exit 0;;
  share|access)
    case "$MODE" in
      crash) echo "boom"; exit 3;;
      crashlater) sleep 0.3; echo "late crash"; exit 2;;
      ignoreterm) trap '' TERM; echo "https://abc123.share.zrok.io"; while :; do sleep 0.1; done;;
      *) trap 'echo TERM >> "$D/signals.log"; exit 0' TERM
         if [ "$2" = private ]; then echo "allow others to access your share with: zrok access private tok5678"; else echo "access your zrok share at: https://abc123.share.zrok.io"; fi
         while :; do sleep 0.1; done;;
    esac;;
esac
exit 0
`

type fixture struct {
	m   *Manager
	dir string // where the fake binary lives
}

func newFixture(t *testing.T, allowed bool) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake zrok is a shell script")
	}
	d := t.TempDir()
	bin := filepath.Join(d, "bin")
	os.MkdirAll(bin, 0o755)
	if err := os.WriteFile(filepath.Join(bin, "zrok"), []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := Open(filepath.Join(d, "conf"), allowed, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.backoffBase, m.backoffMax, m.termGrace = 20*time.Millisecond, 80*time.Millisecond, 400*time.Millisecond
	if err := m.SetSettings(Settings{BinaryPath: filepath.Join(bin, "zrok")}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return &fixture{m: m, dir: bin}
}

func (f *fixture) mode(s string) { os.WriteFile(filepath.Join(f.dir, "mode"), []byte(s), 0o644) }

func (f *fixture) calls(t *testing.T) [][]string {
	raw, _ := os.ReadFile(filepath.Join(f.dir, "calls.log"))
	var out [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		out = append(out, strings.Split(l, "\t")[1:])
	}
	return out
}

func (f *fixture) enable(t *testing.T) {
	t.Helper()
	if err := f.m.SetToken("SECRETTOKEN1234"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func state(m *Manager, id string) TunnelStatus {
	for _, s := range m.Status() {
		if s.ID == id {
			return s
		}
	}
	return TunnelStatus{}
}

func TestNothingRunsWithoutTheFlag(t *testing.T) {
	f := newFixture(t, false)
	f.m.SetToken("SECRETTOKEN1234")
	if _, err := f.m.Enable(context.Background()); err == nil {
		t.Fatal("enable ran without -allow_external_tools")
	}
	tn, err := f.m.SaveTunnel(Tunnel{Name: "a", Kind: KindSharePrivate, Target: "127.0.0.1:80"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Start(tn.ID); err == nil {
		t.Fatal("start ran without the flag")
	}
	if f.m.Version(context.Background()) != "" {
		t.Fatal("version ran without the flag")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "calls.log")); err == nil {
		t.Fatal("the binary was executed")
	}
}

func TestArgumentConstruction(t *testing.T) {
	cases := []struct {
		flavor string
		t      Tunnel
		want   []string
	}{
		{FlavorV1, Tunnel{Name: "n", Kind: KindSharePublic, Target: "http://127.0.0.1:8080", Frontend: "public", Insecure: true},
			[]string{"share", "public", "--headless", "--backend-mode", "proxy", "--frontend", "public", "--insecure", "--", "http://127.0.0.1:8080"}},
		{FlavorV2, Tunnel{Name: "n", Kind: KindSharePublic, Target: "127.0.0.1:8080", Frontend: "public:myname"},
			[]string{"share", "public", "--headless", "--backend-mode", "proxy", "--name-selection", "public:myname", "--", "127.0.0.1:8080"}},
		{FlavorV1, Tunnel{Name: "n", Kind: KindSharePublic, Target: "127.0.0.1:8080", UniqueName: "my-site"},
			[]string{"share", "reserved", "my-site", "--headless"}},
		{FlavorV1, Tunnel{Name: "n", Kind: KindSharePrivate, Target: "10.0.0.5:22", BackendMode: BackendTCP},
			[]string{"share", "private", "--headless", "--backend-mode", "tcpTunnel", "--", "10.0.0.5:22"}},
		{FlavorV2, Tunnel{Name: "n", Kind: KindAccess, ShareToken: "tok5678"},
			[]string{"access", "private", "tok5678", "--headless", "--bind", "127.0.0.1:9191"}},
		{FlavorV1, Tunnel{Name: "n", Kind: KindAccess, ShareToken: "tok5678", Bind: "0.0.0.1:1"},
			[]string{"access", "private", "tok5678", "--headless", "--bind", "0.0.0.1:1"}},
	}
	for i, c := range cases {
		got, err := buildRunArgs(c.flavor, &c.t)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: got %v (%v), want %v", i, got, err, c.want)
		}
	}
	rv := buildReserveArgs(FlavorV1, &Tunnel{Kind: KindSharePublic, Target: "127.0.0.1:80", UniqueName: "my-site", Frontend: "public"})
	if !reflect.DeepEqual(rv, []string{"reserve", "public", "--unique-name", "my-site", "--backend-mode", "proxy", "--frontend", "public", "--", "127.0.0.1:80"}) {
		t.Errorf("reserve args: %v", rv)
	}
	if buildReserveArgs(FlavorV2, &Tunnel{Kind: KindSharePublic, UniqueName: "x"}) != nil {
		t.Error("v2 has no reserve")
	}
}

func TestArgumentInjectionIsRefused(t *testing.T) {
	good := Tunnel{Name: "ok", Kind: KindSharePublic, Target: "127.0.0.1:80"}
	mut := map[string]func(*Tunnel){
		"target option":       func(x *Tunnel) { x.Target = "--config=/etc/shadow" },
		"target shell":        func(x *Tunnel) { x.Target = "127.0.0.1:80; rm -rf /" },
		"target subshell":     func(x *Tunnel) { x.Target = "$(id):80" },
		"target backtick":     func(x *Tunnel) { x.Target = "`id`:80" },
		"target newline":      func(x *Tunnel) { x.Target = "127.0.0.1:80\n--headless" },
		"target space":        func(x *Tunnel) { x.Target = "127.0.0.1:80 --insecure" },
		"target creds":        func(x *Tunnel) { x.Target = "http://user:pw@127.0.0.1:80" },
		"target file scheme":  func(x *Tunnel) { x.Target = "file:///etc/passwd" },
		"target no port":      func(x *Tunnel) { x.Target = "example.com" },
		"target bad port":     func(x *Tunnel) { x.Target = "127.0.0.1:99999" },
		"target query":        func(x *Tunnel) { x.Target = "http://127.0.0.1:80/?a=b" },
		"target dir (web)":    func(x *Tunnel) { x.Target = "/etc" },
		"mode web":            func(x *Tunnel) { x.BackendMode = "web" },
		"mode drive":          func(x *Tunnel) { x.BackendMode = "drive" },
		"mode injection":      func(x *Tunnel) { x.BackendMode = "proxy --insecure" },
		"public tcp":          func(x *Tunnel) { x.BackendMode = BackendTCP },
		"frontend option":     func(x *Tunnel) { x.Frontend = "--basic-auth=a:b" },
		"frontend space":      func(x *Tunnel) { x.Frontend = "a b" },
		"unique name":         func(x *Tunnel) { x.UniqueName = "Bad_Name;x" },
		"unique name short":   func(x *Tunnel) { x.UniqueName = "ab" },
		"name injection":      func(x *Tunnel) { x.Name = "a;b" },
		"name empty":          func(x *Tunnel) { x.Name = "" },
		"kind":                func(x *Tunnel) { x.Kind = "exec" },
		"token on share":      func(x *Tunnel) { x.ShareToken = "abcd1234" },
		"bind on share":       func(x *Tunnel) { x.Bind = "127.0.0.1:1" },
		"private with front.": func(x *Tunnel) { x.Kind = KindSharePrivate; x.Frontend = "public" },
	}
	for name, f := range mut {
		c := good
		f(&c)
		if _, err := buildRunArgs(FlavorV1, &c); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
	acc := Tunnel{Name: "x", Kind: KindAccess, ShareToken: "tok5678"}
	for name, f := range map[string]func(*Tunnel){
		"token option":    func(x *Tunnel) { x.ShareToken = "--bind" },
		"token shell":     func(x *Tunnel) { x.ShareToken = "tok;id" },
		"token short":     func(x *Tunnel) { x.ShareToken = "ab" },
		"bind no port":    func(x *Tunnel) { x.Bind = "127.0.0.1" },
		"bind option":     func(x *Tunnel) { x.Bind = "--x:80" },
		"access target":   func(x *Tunnel) { x.Target = "127.0.0.1:1" },
		"access frontend": func(x *Tunnel) { x.Frontend = "public" },
	} {
		c := acc
		f(&c)
		if _, err := buildRunArgs(FlavorV1, &c); err == nil {
			t.Errorf("access %s: accepted %+v", name, c)
		}
	}
	if err := (&Tunnel{Name: "x", Kind: KindSharePublic, Target: "127.0.0.1:80", UniqueName: "my-site"}).Validate(FlavorV2); err == nil {
		t.Error("reserved names must be refused on v2")
	}
	for _, bad := range []string{"/bin/sh", "/usr/bin/curl", "zrok;id", "..", "sh", "rm"} {
		if ValidateBinary(bad) == nil {
			t.Errorf("binary %q accepted", bad)
		}
	}
	for _, ok := range []string{"zrok", "zrok2", "/usr/local/bin/zrok", "/opt/zrok_2.0.9/zrok2", "C:/x/zrok.exe"} {
		if p := ok; strings.HasPrefix(p, "C:") {
			continue
		} else if err := ValidateBinary(p); err != nil {
			t.Errorf("binary %q refused: %v", ok, err)
		}
	}
	if ValidateBinary("bin/zrok") == nil {
		t.Error("relative path with a directory accepted")
	}
	for _, bad := range []string{"ftp://x", "https://u:p@host", "https://169.254.169.254", "http://example.com", "https://host/?a=b", "https://ho st", "javascript:1"} {
		if ValidateAPIEndpoint(bad) == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
	for _, ok := range []string{"", "https://api-v1.zrok.io", "https://zrok.example.com:8443", "http://127.0.0.1:18080", "http://10.0.0.2:18080"} {
		if err := ValidateAPIEndpoint(ok); err != nil {
			t.Errorf("endpoint %q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "tok;rm", "-x", "short", "a\nb"} {
		if ValidateAccountToken(bad) == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
	if FlavorFor("", "/x/zrok2") != FlavorV2 || FlavorFor("", "/x/zrok") != FlavorV1 || FlavorFor(FlavorV2, "zrok") != FlavorV2 {
		t.Error("flavor detection")
	}
}

func TestEnableTokenHandling(t *testing.T) {
	f := newFixture(t, true)
	t.Setenv("ZORAXY_TEST_SECRET", "must-not-leak")
	f.enable(t)
	if !f.m.Settings().EnabledEnv {
		t.Fatal("environment not marked enabled")
	}
	//Output returned to the UI is redacted
	f.mode("enablefail")
	f.m.SetSettings(Settings{BinaryPath: f.m.Settings().BinaryPath, ApiEndpoint: "https://zrok.example.com"})
	out, err := f.m.Enable(context.Background())
	if err == nil {
		t.Fatal("enable failure not reported")
	}
	if strings.Contains(out, "SECRETTOKEN1234") || strings.Contains(err.Error(), "SECRETTOKEN1234") || !strings.Contains(out, "***") {
		t.Fatalf("token leaked in output: %q / %v", out, err)
	}
	if f.m.Settings().EnabledEnv {
		t.Fatal("a changed API endpoint must reset the enabled flag")
	}
	//The command line has the token (zrok offers no other way), config set came first
	calls := f.calls(t)
	var sawEnable, sawConfig bool
	for _, c := range calls {
		if c[0] == "enable" {
			sawEnable = c[1] == "SECRETTOKEN1234" && c[2] == "--headless"
		}
		if c[0] == "config" {
			sawConfig = reflect.DeepEqual(c, []string{"config", "set", "apiEndpoint", "https://zrok.example.com"})
		}
	}
	if !sawEnable || !sawConfig {
		t.Fatalf("calls: %v", calls)
	}
	//Child environment: isolated HOME, nothing of ours
	env, _ := os.ReadFile(filepath.Join(f.dir, "env.log"))
	if strings.Contains(string(env), "must-not-leak") || strings.Contains(string(env), "ZORAXY_TEST_SECRET") {
		t.Fatal("parent environment leaked into the zrok process")
	}
	if !strings.Contains(string(env), "HOME="+filepath.Join(filepath.Dir(f.dir), "conf", "home")) {
		t.Fatalf("HOME not isolated:\n%s", env)
	}
	//Files
	for _, p := range []string{"token", "zrok.json"} {
		st, err := os.Stat(filepath.Join(filepath.Dir(f.dir), "conf", p))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s must be 0600: %v %v", p, st, err)
		}
	}
	js, _ := os.ReadFile(filepath.Join(filepath.Dir(f.dir), "conf", "zrok.json"))
	if strings.Contains(string(js), "SECRETTOKEN") {
		t.Fatal("token stored in zrok.json")
	}
	if err := f.m.SetToken("bad token;"); err == nil {
		t.Fatal("malformed token accepted")
	}
	if err := f.m.SetToken(""); err != nil || f.m.TokenSet() {
		t.Fatal("clear failed")
	}
	if _, err := f.m.Enable(context.Background()); err == nil {
		t.Fatal("enable without token")
	}
}

func TestStartRequiresEnabledEnvironment(t *testing.T) {
	f := newFixture(t, true)
	tn, _ := f.m.SaveTunnel(Tunnel{Name: "a", Kind: KindSharePrivate, Target: "127.0.0.1:80"})
	if err := f.m.Start(tn.ID); err == nil || !strings.Contains(err.Error(), "enable") {
		t.Fatalf("got %v", err)
	}
}

func TestShareLifecycleAndGracefulStop(t *testing.T) {
	f := newFixture(t, true)
	f.enable(t)
	tn, err := f.m.SaveTunnel(Tunnel{Name: "pub", Kind: KindSharePublic, Target: "127.0.0.1:8080", Frontend: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Start(tn.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Start(tn.ID); err == nil {
		t.Fatal("double start accepted")
	}
	waitFor(t, "running with URL", func() bool { s := state(f.m, tn.ID); return s.State == StateRunning && s.PublicURL != "" })
	if s := state(f.m, tn.ID); s.PublicURL != "https://abc123.share.zrok.io" {
		t.Fatalf("url %q", s.PublicURL)
	}
	if logs := f.m.Logs(tn.ID); len(logs) == 0 || !strings.Contains(strings.Join(logs, "\n"), "abc123") {
		t.Fatalf("logs: %v", logs)
	}
	f.m.Stop(tn.ID)
	if s := state(f.m, tn.ID); s.State != StateStopped {
		t.Fatalf("state after stop: %s", s.State)
	}
	sig, _ := os.ReadFile(filepath.Join(f.dir, "signals.log"))
	if !strings.Contains(string(sig), "TERM") {
		t.Fatal("the process was not asked to terminate gracefully")
	}
	if len(f.m.Logs(tn.ID)) == 0 {
		t.Fatal("logs lost after stop")
	}
	//private share announces its token
	pv, _ := f.m.SaveTunnel(Tunnel{Name: "priv", Kind: KindSharePrivate, Target: "127.0.0.1:22", BackendMode: BackendTCP})
	f.m.Start(pv.ID)
	waitFor(t, "token", func() bool { return state(f.m, pv.ID).Token == "tok5678" })
}

func TestCrashRestartsWithBackoffAndGivesUp(t *testing.T) {
	f := newFixture(t, true)
	f.enable(t)
	f.mode("crash")
	tn, _ := f.m.SaveTunnel(Tunnel{Name: "bad", Kind: KindSharePrivate, Target: "127.0.0.1:80"})
	f.m.Start(tn.ID)
	waitFor(t, "backoff restarts", func() bool { return state(f.m, tn.ID).Restarts >= 2 })
	waitFor(t, "failed state after repeated immediate failures", func() bool { return state(f.m, tn.ID).State == StateFailed })
	s := state(f.m, tn.ID)
	if !strings.Contains(s.LastExit, "exit code 3") {
		t.Fatalf("last exit %q", s.LastExit)
	}
	n := 0
	for _, c := range f.calls(t) {
		if c[0] == "share" {
			n++
		}
	}
	if n != 8 {
		t.Fatalf("expected 8 attempts before giving up, got %d", n)
	}
	//A manual start works again once the cause is fixed
	f.mode("run")
	waitFor(t, "runner cleanup", func() bool { f.m.mu.Lock(); defer f.m.mu.Unlock(); return f.m.runners[tn.ID] == nil })
	if err := f.m.Start(tn.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", func() bool { return state(f.m, tn.ID).State == StateRunning })
}

func TestBackoffGrowsAndResetsAfterStableRun(t *testing.T) {
	f := newFixture(t, true)
	f.m.stableAfter = 200 * time.Millisecond
	f.enable(t)
	f.mode("crashlater") // runs 0.3 s (> stableAfter), then exits 2
	tn, _ := f.m.SaveTunnel(Tunnel{Name: "flaky", Kind: KindSharePrivate, Target: "127.0.0.1:80"})
	f.m.Start(tn.ID)
	waitFor(t, "several restarts", func() bool { return state(f.m, tn.ID).Restarts >= 3 })
	if s := state(f.m, tn.ID); s.State == StateFailed {
		t.Fatal("a tunnel that runs for a while must keep being restarted")
	}
	f.m.Stop(tn.ID)
}

func TestKillAfterGracePeriod(t *testing.T) {
	f := newFixture(t, true)
	f.enable(t)
	f.mode("ignoreterm")
	tn, _ := f.m.SaveTunnel(Tunnel{Name: "stubborn", Kind: KindSharePrivate, Target: "127.0.0.1:80"})
	f.m.Start(tn.ID)
	waitFor(t, "running", func() bool { return state(f.m, tn.ID).State == StateRunning })
	start := time.Now()
	f.m.Stop(tn.ID)
	if d := time.Since(start); d < 300*time.Millisecond || d > 3*time.Second {
		t.Fatalf("stop took %v, want about the 400 ms grace period", d)
	}
	if !strings.Contains(strings.Join(f.m.Logs(tn.ID), "\n"), "killing") {
		t.Fatal("kill not logged")
	}
}

func TestCloseStopsEverything(t *testing.T) {
	f := newFixture(t, true)
	f.enable(t)
	var ids []string
	for _, n := range []string{"a", "b", "c"} {
		tn, _ := f.m.SaveTunnel(Tunnel{Name: n, Kind: KindSharePrivate, Target: "127.0.0.1:80"})
		f.m.Start(tn.ID)
		ids = append(ids, tn.ID)
	}
	for _, id := range ids {
		id := id
		waitFor(t, "running", func() bool { return state(f.m, id).State == StateRunning })
	}
	f.m.Close()
	for _, id := range ids {
		if s := state(f.m, id); s.State != StateStopped {
			t.Fatalf("%s still %s", id, s.State)
		}
	}
	if err := f.m.Start(ids[0]); err == nil {
		t.Fatal("start after close accepted")
	}
	sig, _ := os.ReadFile(filepath.Join(f.dir, "signals.log"))
	if strings.Count(string(sig), "TERM") != 3 {
		t.Fatalf("signals: %q", sig)
	}
}

func TestReservedShareIsCreatedOnce(t *testing.T) {
	f := newFixture(t, true)
	f.enable(t)
	tn, err := f.m.SaveTunnel(Tunnel{Name: "res", Kind: KindSharePublic, Target: "127.0.0.1:80", UniqueName: "my-site", Frontend: "public"})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Start(tn.ID)
	waitFor(t, "running", func() bool { return state(f.m, tn.ID).State == StateRunning })
	f.m.Stop(tn.ID)
	f.m.Start(tn.ID)
	waitFor(t, "running again", func() bool { return state(f.m, tn.ID).State == StateRunning })
	f.m.Stop(tn.ID)
	reserves, reserved := 0, 0
	for _, c := range f.calls(t) {
		switch {
		case c[0] == "reserve":
			reserves++
		case c[0] == "share" && c[1] == "reserved" && c[2] == "my-site":
			reserved++
		}
	}
	if reserves != 1 || reserved != 2 {
		t.Fatalf("reserve calls %d, share reserved calls %d", reserves, reserved)
	}
}

func TestPersistenceAndAutoStart(t *testing.T) {
	f := newFixture(t, true)
	f.enable(t)
	tn, _ := f.m.SaveTunnel(Tunnel{Name: "auto", Kind: KindSharePrivate, Target: "127.0.0.1:80", AutoStart: true})
	f.m.Close()
	m2, err := Open(filepath.Join(filepath.Dir(f.dir), "conf"), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	if len(m2.Tunnels()) != 1 || m2.Tunnels()[0].ID != tn.ID || !m2.TokenSet() || !m2.Settings().EnabledEnv {
		t.Fatal("state not restored")
	}
	m2.StartAuto()
	waitFor(t, "auto start", func() bool { return state(m2, tn.ID).State == StateRunning })
	//Editing a running tunnel restarts it with the new definition
	if _, err := m2.SaveTunnel(Tunnel{ID: tn.ID, Name: "auto", Kind: KindSharePrivate, Target: "127.0.0.1:81", AutoStart: true}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restarted", func() bool { return state(m2, tn.ID).State == StateRunning })
	var last []string
	for _, c := range f.calls(t) {
		if c[0] == "share" {
			last = c
		}
	}
	if last[len(last)-1] != "127.0.0.1:81" {
		t.Fatalf("edit did not restart with the new target: %v", last)
	}
	if err := m2.DeleteTunnel(tn.ID); err != nil || len(m2.Tunnels()) != 0 {
		t.Fatal("delete failed")
	}
}

func TestBinaryDiscovery(t *testing.T) {
	m, _ := Open(filepath.Join(t.TempDir(), "conf"), true, nil)
	t.Setenv("PATH", t.TempDir())
	if _, err := m.Binary(); err == nil {
		t.Fatal("binary found in an empty PATH")
	}
	if runtime.GOOS == "windows" {
		return
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "zrok2"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	t.Setenv("PATH", d)
	p, err := m.Binary()
	if err != nil || filepath.Base(p) != "zrok2" {
		t.Fatalf("PATH discovery: %v %v", p, err)
	}
	if FlavorFor("", p) != FlavorV2 {
		t.Fatal("zrok2 must select the v2 command line")
	}
}
