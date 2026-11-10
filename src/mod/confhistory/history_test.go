package confhistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	secretHash   = "S3CR3T-HASH-VALUE-0123456789"
	secretBearer = "Bearer SUPER-SECRET-TOKEN-ABCDEF"
	secretCert   = "-----BEGIN PRIVATE KEY-----TESTKEYMATERIAL"
	secretDNS    = "DNS-API-SECRET-XYZ"
)

func secretProxy(domain string) string {
	return fmt.Sprintf(`{"RootOrMatchingDomain":%q,"ActiveOrigins":[{"OriginIpOrDomain":"10.0.0.1:80"}],`+
		`"AuthenticationProvider":{"BasicAuthCredentials":[{"Username":"bob","PasswordHash":%q}]},`+
		`"HeaderRewriteRules":{"UserDefinedHeaders":[{"Key":"Authorization","Value":%q,"IsRemove":false}]}}`, domain, secretHash, secretBearer)
}

func TestHashStabilityAndDedupe(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "10.0.0.1:80"))
	e.write("access/default.json", `{"id":"default"}`)
	v1, created, err := e.m.Capture(CaptureInfo{Actor: "x", Summary: "first"})
	if err != nil || !created {
		t.Fatalf("first capture: %v %v", created, err)
	}
	v2, created, _ := e.m.Capture(CaptureInfo{Actor: "x", Summary: "again"})
	if created || v2.ID != v1.ID || v2.Hash != v1.Hash {
		t.Fatalf("identical state must dedupe: created=%v %d vs %d", created, v2.ID, v1.ID)
	}
	// a second manager (fresh process) computes the same hash
	m2 := e.reopen(nil)
	v3, created, _ := m2.Capture(CaptureInfo{Summary: "restart"})
	if created || v3.Hash != v1.Hash {
		t.Fatalf("hash must be stable across restarts: created=%v", created)
	}
	// files outside the allow-list and hidden files do not influence the hash
	e.write("version", "336")
	e.write("proxy/a.config.bak", "junk")
	e.write("proxy/.hidden.config", "{}")
	e.write("geodb/big.mmdb", "x")
	if _, created, _ := e.m.Capture(CaptureInfo{}); created {
		t.Fatal("non allow-listed files must not create a version")
	}
	e.write("proxy/a.config", proxyJSON("a.example.com", "10.0.0.2:80"))
	v4 := e.capture("edit")
	if v4.ID != v1.ID+1 || len(v4.Changes) != 1 || v4.Changes[0].Kind != "changed" || v4.Changes[0].Label != "Proxy rule a" {
		t.Fatalf("unexpected changes: %+v", v4.Changes)
	}
	// back to the old content: a new version (history is linear), same content hash as v1
	e.write("proxy/a.config", proxyJSON("a.example.com", "10.0.0.1:80"))
	v5 := e.capture("revert by hand")
	if v5.ID == v1.ID || v5.Hash != v1.Hash {
		t.Fatalf("revert must be a new version with the old hash: %+v", v5)
	}
	e.write("proxy/b.config", proxyJSON("b.example.com", "10.0.0.3:80"))
	v6 := e.capture("add")
	if len(v6.Changes) != 1 || v6.Changes[0].Kind != "added" {
		t.Fatalf("add: %+v", v6.Changes)
	}
	os.Remove(filepath.Join(e.conf, "proxy", "b.config"))
	v7 := e.capture("del")
	if len(v7.Changes) != 1 || v7.Changes[0].Kind != "removed" {
		t.Fatalf("remove: %+v", v7.Changes)
	}
}

func TestDebounce(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.m.Start()
	base := len(e.m.IDs())
	for i := 0; i < 5; i++ {
		e.write("proxy/a.config", proxyJSON("a.example.com", fmt.Sprintf("1.1.1.%d:80", i+2)))
		e.m.Notify("alice", fmt.Sprintf("Proxy rule edited: step%d", i))
		time.Sleep(5 * time.Millisecond)
	}
	if len(e.m.IDs()) != base {
		t.Fatal("capture must wait for the debounce window")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(e.m.IDs()) == base && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(120 * time.Millisecond)
	ids := e.m.IDs()
	if len(ids) != base+1 {
		t.Fatalf("a burst must produce one version, got %d new", len(ids)-base)
	}
	v, _ := e.m.Get(ids[len(ids)-1])
	if v.Actor != "alice" || !strings.Contains(v.Summary, "step0") || !strings.Contains(v.Summary, "+4 more") {
		t.Fatalf("summary/actor: %+v", v)
	}
	// a notification without a real change stores nothing
	e.m.Notify("alice", "noop")
	time.Sleep(200 * time.Millisecond)
	if len(e.m.IDs()) != base+1 {
		t.Fatal("no change, no version")
	}
}

func TestMaxWaitBoundsBurst(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Debounce = 200 * time.Millisecond; o.MaxWait = 300 * time.Millisecond })
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.m.Start()
	base := len(e.m.IDs())
	stop := time.Now().Add(900 * time.Millisecond)
	i := 0
	for time.Now().Before(stop) {
		i++
		e.write("proxy/a.config", proxyJSON("a.example.com", fmt.Sprintf("2.2.2.%d:80", i)))
		e.m.Notify("alice", "burst")
		time.Sleep(80 * time.Millisecond)
	}
	if len(e.m.IDs()) <= base {
		t.Fatal("a continuous stream must not postpone the capture forever")
	}
	e.m.Flush()
}

func TestRetention(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.m.SetSettings(Settings{Enabled: true, KeepCount: 5, KeepDays: 1, MaxMiB: 200}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		e.write("proxy/a.config", proxyJSON("a.example.com", fmt.Sprintf("10.0.0.%d:80", i)))
		e.advance(48 * time.Hour) // every version is older than KeepDays by the time the next is taken
		e.capture(fmt.Sprintf("v%d", i))
	}
	ids := e.m.IDs()
	if len(ids) != 5 {
		t.Fatalf("expected the 5 protected newest versions, got %d: %v", len(ids), ids)
	}
	if ids[len(ids)-1] != 20 {
		t.Fatalf("newest must survive: %v", ids)
	}
	// blobs of pruned versions are gone
	ents, _ := os.ReadDir(e.m.dir(blobDir))
	if len(ents) != 5 {
		t.Fatalf("unreferenced blobs must be collected, %d left", len(ents))
	}

	// keepDays keeps young versions even beyond keepCount
	e2 := newEnv(t, nil)
	e2.m.SetSettings(Settings{Enabled: true, KeepCount: 5, KeepDays: 30, MaxMiB: 200})
	for i := 0; i < 20; i++ {
		e2.write("proxy/a.config", proxyJSON("a.example.com", fmt.Sprintf("10.0.0.%d:80", i)))
		e2.advance(time.Hour)
		e2.capture("v")
	}
	if n := len(e2.m.IDs()); n != 20 {
		t.Fatalf("young versions must be kept, got %d", n)
	}
	// ...until they age out
	e2.advance(40 * 24 * time.Hour)
	e2.write("proxy/a.config", proxyJSON("a.example.com", "9.9.9.9:80"))
	e2.capture("new")
	if n := len(e2.m.IDs()); n != 5 {
		t.Fatalf("aged versions must be pruned down to the protected 5, got %d", n)
	}
}

func TestRetentionPendingRestoreAndSizeCap(t *testing.T) {
	e := newEnv(t, nil)
	e.m.SetSettings(Settings{Enabled: true, KeepCount: 5, KeepDays: 1, MaxMiB: 10})
	rnd := rand.New(rand.NewSource(1))
	big := func() string {
		b := make([]byte, 1<<20)
		rnd.Read(b)
		return fmt.Sprintf(`{"x":%q}`, fmt.Sprintf("%x", b[:600000]))
	}
	for i := 0; i < 4; i++ {
		e.write("proxy/a.config", big())
		e.advance(48 * time.Hour)
		e.capture(fmt.Sprintf("v%d", i))
	}
	// version 1 is needed by a pending restore: it must survive any pruning
	e.m.mu.Lock()
	e.m.writePending(&pendingRestore{Phase: "applied", Pre: 1, From: 2, BackupDir: e.m.dir("backup-x")})
	e.m.mu.Unlock()
	for i := 4; i < 12; i++ {
		e.write("proxy/a.config", big())
		e.advance(48 * time.Hour)
		e.capture(fmt.Sprintf("v%d", i))
	}
	ids := e.m.IDs()
	has := func(id int64) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
	if !has(1) || !has(2) {
		t.Fatalf("versions a pending restore depends on must not be pruned: %v", ids)
	}
	for _, id := range []int64{8, 9, 10, 11, 12} {
		if !has(id) {
			t.Fatalf("last 5 are protected: %v", ids)
		}
	}
	if has(3) || has(4) {
		t.Fatalf("old unprotected versions must go (size cap/age): %v", ids)
	}
	if got := e.m.StoreBytes(); got > 25<<20 {
		t.Fatalf("size cap not enforced: %d", got)
	}
}

func TestSettingsValidation(t *testing.T) {
	e := newEnv(t, nil)
	for _, s := range []Settings{{KeepCount: 2, KeepDays: 30, MaxMiB: 200}, {KeepCount: 100, KeepDays: 0, MaxMiB: 200}, {KeepCount: 100, KeepDays: 30, MaxMiB: 1}} {
		if e.m.SetSettings(s) == nil {
			t.Fatalf("settings %+v must be rejected", s)
		}
	}
	if err := e.m.SetSettings(Settings{Enabled: true, KeepCount: 50, KeepDays: 7, MaxMiB: 50}); err != nil {
		t.Fatal(err)
	}
	m2 := e.reopen(nil)
	if m2.Settings().KeepCount != 50 {
		t.Fatal("settings must persist")
	}
}

func allFiles(t *testing.T, dir string) map[string][]byte {
	out := map[string][]byte{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			out[p] = b
		}
		return nil
	})
	return out
}

func TestSealedStoreNoPlaintextAndPerms(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", secretProxy("a.example.com"))
	e.write("certs/a.example.com.key", secretCert)
	e.write("acme_conf.json", fmt.Sprintf(`{"Email":"a@b.c","DNSToken":%q}`, secretDNS))
	e.kv.Write("acme", "x_dns_credentials", map[string]string{"token": secretDNS})
	e.capture("secrets")
	e.write("proxy/a.config", strings.Replace(secretProxy("a.example.com"), "10.0.0.1", "10.0.0.9", 1))
	e.capture("again")
	for p, b := range allFiles(t, e.m.dir()) {
		if filepath.Base(p) == "history.key" {
			continue
		}
		for _, s := range []string{secretHash, secretBearer, secretCert, secretDNS, "bob", "a.example.com", "RootOrMatchingDomain"} {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("%s contains %q in clear", p, s)
			}
		}
	}
	// permissions
	fi, _ := os.Stat(e.m.dir("history.key"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key perm %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(e.m.dir())
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %v", di.Mode().Perm())
	}
	for p := range allFiles(t, e.m.dir()) {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s perm %v", p, fi.Mode().Perm())
		}
	}
	// the key is random per install
	e2 := newEnv(t, nil)
	k1, _ := os.ReadFile(e.m.dir("history.key"))
	k2, _ := os.ReadFile(e2.m.dir("history.key"))
	if bytes.Equal(k1, k2) || len(bytes.TrimSpace(k1)) != 64 {
		t.Fatal("per-install random 32 byte key expected")
	}
}

func TestTamperDetection(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.write("proxy/b.config", proxyJSON("b.example.com", "2.2.2.2:80"))
	v := e.capture("one")
	if _, err := e.m.loadState(v.ID); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	st, _ := e.m.loadState(v.ID)
	if string(st["proxy/a.config"].Data) != proxyJSON("a.example.com", "1.1.1.1:80") {
		t.Fatal("round trip content mismatch")
	}
	mf, _ := e.m.loadManifest(v.ID)
	a, b := mf["proxy/a.config"].Blob, mf["proxy/b.config"].Blob

	// flipped bit
	pa := e.m.blobPath(a)
	orig, _ := os.ReadFile(pa)
	bad := append([]byte(nil), orig...)
	bad[len(bad)-3] ^= 0x01
	os.WriteFile(pa, bad, 0o600)
	if _, err := e.m.loadState(v.ID); !errors.Is(err, ErrTampered) {
		t.Fatalf("bit flip must be detected, got %v", err)
	}
	// swapped blobs (both authentic, wrong place)
	pb := e.m.blobPath(b)
	ob, _ := os.ReadFile(pb)
	os.WriteFile(pa, ob, 0o600)
	if _, err := e.m.loadState(v.ID); !errors.Is(err, ErrTampered) {
		t.Fatalf("swapped blob must be detected, got %v", err)
	}
	os.WriteFile(pa, orig, 0o600)
	if _, err := e.m.loadState(v.ID); err != nil {
		t.Fatal(err)
	}
	// a restore refuses a tampered version and changes nothing
	os.WriteFile(pa, bad, 0o600)
	e.write("proxy/a.config", proxyJSON("a.example.com", "9.9.9.9:80"))
	if _, err := e.m.Restore(RestoreRequest{ID: v.ID, Scope: "proxy", Actor: "t"}); err == nil {
		t.Fatal("tampered version must not restore")
	}
	if !strings.Contains(e.read("proxy/a.config"), "9.9.9.9") {
		t.Fatal("live config must be untouched")
	}
	// tampered manifest and index
	mp := e.m.manifestPath(v.ID)
	raw, _ := os.ReadFile(mp)
	raw[len(raw)-2] ^= 0xff
	os.WriteFile(mp, raw, 0o600)
	if _, err := e.m.loadManifest(v.ID); !errors.Is(err, ErrTampered) {
		t.Fatalf("manifest tamper: %v", err)
	}
	ip := e.m.dir(indexFile)
	raw, _ = os.ReadFile(ip)
	raw[len(raw)-1] ^= 0xff
	os.WriteFile(ip, raw, 0o600)
	m2 := e.reopen(nil)
	if _, err := m2.List(Filter{}); err == nil {
		t.Fatal("tampered index must be rejected")
	}
	// wrong key cannot open the store
	e.m.seal, _ = loadOrCreateKey(filepath.Join(t.TempDir(), "other.key"))
	if _, err := e.m.getBlob(b); err == nil {
		t.Fatal("other key must not open blobs")
	}
}

func TestDiffMasksSecrets(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", secretProxy("a.example.com"))
	e.write("acme_conf.json", fmt.Sprintf(`{"Email":"a@b.c","DNSToken":%q}`, secretDNS))
	e.kv.Write("acme", "x_dns_credentials", map[string]string{"token": secretDNS})
	e.kv.Write("settings", "devMode", true)
	v1 := e.capture("one")
	changed := strings.NewReplacer(secretHash, "ANOTHER-SECRET-HASH-777", "10.0.0.1:80", "10.0.0.2:80").Replace(secretProxy("a.example.com"))
	e.write("proxy/a.config", changed)
	e.write("acme_conf.json", `{"Email":"x@y.z","DNSToken":"NEW-DNS-SECRET-QQQ"}`)
	e.kv.Write("acme", "x_dns_credentials", map[string]string{"token": "NEW-DNS-SECRET-QQQ"})
	e.kv.Write("settings", "devMode", false)
	v2 := e.capture("two")
	files, err := e.m.Diff(v1.ID, v2.ID)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(files)
	for _, s := range []string{secretHash, "ANOTHER-SECRET-HASH-777", secretBearer, secretDNS, "NEW-DNS-SECRET-QQQ", "SUPER-SECRET"} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatalf("diff leaks %q: %s", s, out)
		}
	}
	js := string(out)
	if !strings.Contains(js, MaskText) || !strings.Contains(js, "(changed)") {
		t.Fatalf("masked and changed markers expected: %s", js)
	}
	if !strings.Contains(js, "10.0.0.2:80") || !strings.Contains(js, "10.0.0.1:80") {
		t.Fatalf("non secret values must stay readable: %s", js)
	}
	// the API handler output as well, including the download variant
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/history/diff?from=%d&to=%d&download=1", v1.ID, v2.ID), nil)
	e.m.HandleDiff(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("diff api: %d %v", rec.Code, rec.Header())
	}
	for _, s := range []string{secretHash, secretBearer, secretDNS, "NEW-DNS-SECRET-QQQ"} {
		if strings.Contains(rec.Body.String(), s) {
			t.Fatalf("diff API leaks %q", s)
		}
	}
	// list / get metadata never carry content
	rec = httptest.NewRecorder()
	e.m.HandleList(rec, httptest.NewRequest("GET", "/api/history/list", nil))
	for _, s := range []string{secretHash, secretBearer, secretDNS} {
		if strings.Contains(rec.Body.String(), s) {
			t.Fatalf("list API leaks %q", s)
		}
	}
	// certificate files: never any content
	e.write("certs/a.example.com.key", secretCert)
	v3 := e.capture("cert")
	files, _ = e.m.Diff(v2.ID, v3.ID)
	out, _ = json.Marshal(files)
	if bytes.Contains(out, []byte("TESTKEYMATERIAL")) || len(files) != 1 || !files[0].Hidden {
		t.Fatalf("cert content must be hidden: %s", out)
	}
	// diff against nothing (from=0) works and masks too
	files, _ = e.m.Diff(0, v1.ID)
	out, _ = json.Marshal(files)
	if bytes.Contains(out, []byte(secretHash)) {
		t.Fatal("from-empty diff leaks")
	}
}

func TestHeaderPairMasking(t *testing.T) {
	e := newEnv(t, nil)
	fd := e.m.diffEntry("proxy/a.config", "changed",
		[]byte(`{"H":[{"Key":"X-Api-Key","Value":"one-secret"},{"Key":"X-Frame","Value":"visible"}]}`),
		[]byte(`{"H":[{"Key":"X-Api-Key","Value":"two-secret"},{"Key":"X-Frame","Value":"visible2"}]}`))
	out, _ := json.Marshal(fd)
	if bytes.Contains(out, []byte("one-secret")) || bytes.Contains(out, []byte("two-secret")) {
		t.Fatalf("header secret leaked: %s", out)
	}
	if !bytes.Contains(out, []byte("visible2")) {
		t.Fatalf("plain header must stay visible: %s", out)
	}
}

func TestRestoreRoundTripDryRunAndScope(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.write("redirect/r.json", `{"from":"a","to":"b"}`)
	e.kv.Write("settings", "idleTimeout", 30)
	v1 := e.capture("v1")
	e.write("proxy/a.config", proxyJSON("a.example.com", "2.2.2.2:80"))
	e.write("proxy/new.config", proxyJSON("new.example.com", "3.3.3.3:80"))
	os.Remove(filepath.Join(e.conf, "redirect", "r.json"))
	e.kv.Write("settings", "idleTimeout", 99)
	v2 := e.capture("v2")

	// dry run changes nothing and lists everything
	res, err := e.m.Restore(RestoreRequest{ID: v1.ID, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 4 || !res.DryRun || res.Applied || len(res.Diffs) != 4 || !res.NeedsWord {
		t.Fatalf("dry run: %+v", res)
	}
	if !strings.Contains(e.read("proxy/a.config"), "2.2.2.2") || e.kv.get("settings", "idleTimeout") != "99" {
		t.Fatal("dry run must not change anything")
	}
	if len(e.m.IDs()) != 2 {
		t.Fatal("dry run must not create versions")
	}

	// scope: only proxy rules
	res, err = e.m.Restore(RestoreRequest{ID: v1.ID, Scope: "proxy", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Pre == 0 {
		t.Fatalf("result: %+v", res)
	}
	if !strings.Contains(e.read("proxy/a.config"), "1.1.1.1") || e.read("proxy/new.config") != "<missing>" {
		t.Fatal("proxy area must be restored (changed file back, added file removed)")
	}
	if e.read("redirect/r.json") != "<missing>" || e.kv.get("settings", "idleTimeout") != "99" {
		t.Fatal("other areas must be untouched by a scoped restore")
	}
	// the safety snapshot has the pre-restore state, and a "restore" version follows
	pre, _ := e.m.Get(res.Pre)
	if pre.ID != v2.ID {
		t.Fatalf("pre-restore version (identical state reuses the newest): %+v", pre)
	}
	last, _ := e.m.Get(e.m.Latest())
	if last.Trigger != "restore" || last.Actor != "alice" {
		t.Fatalf("restore version: %+v", last)
	}
	// undo the restore from the pre-restore snapshot
	if _, err := e.m.Restore(RestoreRequest{ID: pre.ID, Scope: "proxy", Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.read("proxy/a.config"), "2.2.2.2") || e.read("proxy/new.config") == "<missing>" {
		t.Fatal("undo of the restore failed")
	}

	// whole configuration needs the confirmation word
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID}); err == nil || !strings.Contains(err.Error(), ConfirmWord) {
		t.Fatalf("confirmation word required: %v", err)
	}
	res, err = e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.read("proxy/a.config"), "1.1.1.1") || e.read("redirect/r.json") == "<missing>" || e.kv.get("settings", "idleTimeout") != "30" {
		t.Fatal("whole restore must bring back files, deleted files and table values")
	}
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord}); !errors.Is(err, ErrNothingToRestore) {
		t.Fatalf("second identical restore: %v", err)
	}
	if _, err := e.m.Restore(RestoreRequest{ID: 9999, Confirm: ConfirmWord}); err == nil {
		t.Fatal("unknown version")
	}
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Scope: "bogus"}); err == nil {
		t.Fatal("unknown scope")
	}
}

func TestCertsOptInScope(t *testing.T) {
	e := newEnv(t, nil)
	e.write("certs/a.pem", "OLD-CERT")
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	v1 := e.capture("v1")
	e.write("certs/a.pem", "RENEWED-CERT")
	e.write("proxy/a.config", proxyJSON("a.example.com", "2.2.2.2:80"))
	e.capture("v2")
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord}); err != nil {
		t.Fatal(err)
	}
	if e.read("certs/a.pem") != "RENEWED-CERT" {
		t.Fatal("whole restore must not replace certificates")
	}
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Scope: "certs"}); err != nil {
		t.Fatal(err)
	}
	if e.read("certs/a.pem") != "OLD-CERT" {
		t.Fatal("explicit certs scope restores certificates")
	}
}

func TestRestoreFleetManagedSkip(t *testing.T) {
	e := newEnv(t, func(o *Options) {
		o.Managed = func(rel string) string {
			if rel == "proxy/hub.config" || strings.HasPrefix(rel, "redirect/") {
				return "managed by the Fleet hub"
			}
			return ""
		}
	})
	e.write("proxy/hub.config", proxyJSON("hub.example.com", "1.1.1.1:80"))
	e.write("proxy/local.config", proxyJSON("local.example.com", "1.1.1.1:80"))
	e.write("redirect/r.json", `{"a":1}`)
	v1 := e.capture("v1")
	e.write("proxy/hub.config", proxyJSON("hub.example.com", "9.9.9.9:80"))
	e.write("proxy/local.config", proxyJSON("local.example.com", "9.9.9.9:80"))
	e.write("redirect/r.json", `{"a":2}`)
	e.capture("v2")
	res, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord, DryRun: true})
	if err != nil || len(res.Skipped) != 2 || len(res.Items) != 1 {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	res, err = e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.read("proxy/hub.config"), "9.9.9.9") || e.read("redirect/r.json") != `{"a":2}` {
		t.Fatal("hub managed files must not be overwritten")
	}
	if !strings.Contains(e.read("proxy/local.config"), "1.1.1.1") {
		t.Fatal("node local file must be restored")
	}
	if len(res.Skipped) != 2 || !strings.Contains(res.Skipped[0].Reason, "Fleet") {
		t.Fatalf("skipped must be reported: %+v", res.Skipped)
	}
	// only managed differences: refuse with a clear message
	e.write("proxy/local.config", proxyJSON("local.example.com", "1.1.1.1:80"))
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord}); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("expected the managed-only refusal, got %v", err)
	}
}

func snapshotFiles(t *testing.T, e *env) map[string]string {
	out := map[string]string{}
	filepath.WalkDir(e.conf, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(e.conf, p)
		if strings.HasPrefix(rel, dirName) {
			return nil
		}
		b, _ := os.ReadFile(p)
		out[rel] = string(b)
		return nil
	})
	return out
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func twoVersionEnv(t *testing.T, mut func(*Options)) (*env, Meta) {
	e := newEnv(t, mut)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.write("proxy/b.config", proxyJSON("b.example.com", "1.1.1.1:80"))
	e.write("redirect/r.json", `{"a":1}`)
	e.kv.Write("settings", "idleTimeout", 30)
	v1 := e.capture("v1")
	e.write("proxy/a.config", proxyJSON("a.example.com", "2.2.2.2:80"))
	os.Remove(filepath.Join(e.conf, "proxy", "b.config"))
	e.write("proxy/c.config", proxyJSON("c.example.com", "2.2.2.2:80"))
	e.write("redirect/r.json", `{"a":2}`)
	e.kv.Write("settings", "idleTimeout", 99)
	e.capture("v2")
	return e, v1
}

func TestRestoreFailureInjectionLeavesConfigIntact(t *testing.T) {
	stages := []string{"validate", "swap:proxy/a.config", "swap:proxy/b.config", "swap:proxy/c.config", "swap:redirect/r.json", "tables", "db:settings/idleTimeout"}
	for _, st := range stages {
		t.Run(st, func(t *testing.T) {
			e, v1 := twoVersionEnv(t, nil)
			before := snapshotFiles(t, e)
			dbBefore := e.kv.get("settings", "idleTimeout")
			e.m.failAt[st] = errors.New("boom at " + st)
			_, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord, Actor: "t"})
			if err == nil {
				t.Fatal("injected failure must fail the restore")
			}
			if !sameMap(before, snapshotFiles(t, e)) {
				t.Fatalf("files changed after failure at %s:\nbefore %v\nafter  %v", st, before, snapshotFiles(t, e))
			}
			if e.kv.get("settings", "idleTimeout") != dbBefore {
				t.Fatal("table changed after failure")
			}
			if e.m.readPending() != nil {
				t.Fatal("a failed restore must not leave a pending marker")
			}
			ents, _ := os.ReadDir(e.m.dir())
			for _, en := range ents {
				if strings.HasPrefix(en.Name(), "staging-") || strings.HasPrefix(en.Name(), "backup-") {
					t.Fatalf("working folder %s left behind", en.Name())
				}
			}
			if lr := e.m.LastRestore(); lr == nil || lr.Result != "failed" {
				t.Fatalf("failure must be recorded: %+v", lr)
			}
			// the restore works afterwards
			delete(e.m.failAt, st)
			if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord, Actor: "t"}); err != nil {
				t.Fatalf("retry: %v", err)
			}
		})
	}
}

func TestRestoreValidationRejectsBadFile(t *testing.T) {
	e, v1 := twoVersionEnv(t, func(o *Options) {
		o.Validate = func(rel string, data []byte) error {
			if rel == "proxy/b.config" {
				return errors.New("loader says no")
			}
			return nil
		}
	})
	before := snapshotFiles(t, e)
	_, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord})
	if err == nil || !strings.Contains(err.Error(), "loader says no") {
		t.Fatalf("validator must veto: %v", err)
	}
	if !sameMap(before, snapshotFiles(t, e)) {
		t.Fatal("validation failure must leave the config untouched")
	}
}

func TestCrashAfterStageLeavesConfigAndBootCleans(t *testing.T) {
	e, v1 := twoVersionEnv(t, nil)
	before := snapshotFiles(t, e)
	e.m.failAt["stage"] = errCrash
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord}); !errors.Is(err, errCrash) {
		t.Fatalf("expected the simulated crash: %v", err)
	}
	if !sameMap(before, snapshotFiles(t, e)) {
		t.Fatal("a crash after staging must leave the live config untouched")
	}
	staged := false
	ents, _ := os.ReadDir(e.m.dir())
	for _, en := range ents {
		staged = staged || strings.HasPrefix(en.Name(), "staging-")
	}
	if !staged {
		t.Fatal("test expects the leftover staging folder")
	}
	m2 := e.reopen(nil)
	m2.BootGuard()
	m2.Start()
	ents, _ = os.ReadDir(m2.dir())
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), "staging-") {
			t.Fatal("boot must clean the stale staging folder")
		}
	}
	if !sameMap(before, snapshotFiles(t, e)) {
		t.Fatal("config changed by boot cleanup")
	}
}

func TestCrashDuringSwapIsRolledBackAtBoot(t *testing.T) {
	e, v1 := twoVersionEnv(t, nil)
	before := snapshotFiles(t, e)
	dbBefore := e.kv.get("settings", "idleTimeout")
	e.m.failAt["swap:proxy/c.config"] = errCrash // after a.config and b.config already moved
	if _, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord}); !errors.Is(err, errCrash) {
		t.Fatalf("crash expected: %v", err)
	}
	if sameMap(before, snapshotFiles(t, e)) {
		t.Fatal("the simulated crash should have left a half applied state")
	}
	m2 := e.reopen(nil)
	m2.BootGuard()
	if !sameMap(before, snapshotFiles(t, e)) {
		t.Fatalf("boot guard must undo the half applied restore:\n%v\n%v", before, snapshotFiles(t, e))
	}
	if e.kv.get("settings", "idleTimeout") != dbBefore {
		t.Fatal("table state")
	}
	if lr := m2.LastRestore(); lr == nil || lr.Result != "rolled_back" {
		t.Fatalf("outcome: %+v", lr)
	}
}

func TestReloadFailureRollsBack(t *testing.T) {
	e, v1 := twoVersionEnv(t, func(o *Options) { o.Reload = func() error { return errors.New("cannot restart") } })
	before := snapshotFiles(t, e)
	dbBefore := e.kv.get("settings", "idleTimeout")
	_, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord})
	if err == nil || !strings.Contains(err.Error(), "cannot restart") {
		t.Fatalf("err: %v", err)
	}
	if !sameMap(before, snapshotFiles(t, e)) || e.kv.get("settings", "idleTimeout") != dbBefore || e.m.readPending() != nil {
		t.Fatal("failed restart must put everything back")
	}
}

func TestBootGuardUnhealthyThenHealthy(t *testing.T) {
	reloads := 0
	e, v1 := twoVersionEnv(t, func(o *Options) { o.Reload = func() error { reloads++; return nil } })
	before := snapshotFiles(t, e)
	dbBefore := e.kv.get("settings", "idleTimeout")
	res, err := e.m.Restore(RestoreRequest{ID: v1.ID, Confirm: ConfirmWord, Actor: "a"})
	if err != nil || !res.Restarting || reloads != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	restored := snapshotFiles(t, e)
	if sameMap(before, restored) {
		t.Fatal("restore did not change anything")
	}
	if lr := e.m.LastRestore(); lr.Result != "pending" {
		t.Fatalf("%+v", lr)
	}
	// start #1 with the restored config: the guard only counts the attempt
	m1 := e.reopen(nil)
	m1.BootGuard()
	if !sameMap(restored, snapshotFiles(t, e)) {
		t.Fatal("first start must keep the restored config")
	}
	// the process dies before MarkHealthy: start #2 rolls back
	m2 := e.reopen(nil)
	m2.BootGuard()
	if !sameMap(before, snapshotFiles(t, e)) || e.kv.get("settings", "idleTimeout") != dbBefore {
		t.Fatalf("second unhealthy start must roll back:\n%v\n%v", before, snapshotFiles(t, e))
	}
	if lr := m2.LastRestore(); lr.Result != "rolled_back" {
		t.Fatalf("%+v", lr)
	}
	if m2.readPending() != nil {
		t.Fatal("pending marker must be gone")
	}

	// healthy path
	e2, v1b := twoVersionEnv(t, func(o *Options) { o.Reload = func() error { return nil } })
	if _, err := e2.m.Restore(RestoreRequest{ID: v1b.ID, Confirm: ConfirmWord}); err != nil {
		t.Fatal(err)
	}
	restored2 := snapshotFiles(t, e2)
	m3 := e2.reopen(nil)
	m3.BootGuard()
	m3.MarkHealthy()
	m4 := e2.reopen(nil)
	m4.BootGuard() // nothing pending any more
	if !sameMap(restored2, snapshotFiles(t, e2)) {
		t.Fatal("confirmed restore must stay")
	}
	if lr := m4.LastRestore(); lr.Result != "confirmed" {
		t.Fatalf("%+v", lr)
	}
	ents, _ := os.ReadDir(m4.dir())
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), "backup-") {
			t.Fatal("confirmed restore must drop its working backup")
		}
	}
}

func TestValidateWritesRejectsBadEntries(t *testing.T) {
	e := newEnv(t, nil)
	long := make([]byte, maxFileBytes+1)
	for i := range long {
		long[i] = ' '
	}
	cases := map[string]Entry{
		"traversal":     {Path: "proxy/../../etc/passwd", Data: []byte("{}")},
		"traversal2":    {Path: "../proxy/a.config", Data: []byte("{}")},
		"absolute":      {Path: "/etc/passwd", Data: []byte("{}")},
		"backslash":     {Path: `proxy\a.config`, Data: []byte("{}")},
		"outside roots": {Path: "evil.json", Data: []byte("{}")},
		"history store": {Path: ".history/history.key", Data: []byte("{}")},
		"hidden":        {Path: "proxy/.x.config", Data: []byte("{}")},
		"too deep":      {Path: "proxy/sub/a.config", Data: []byte("{}")},
		"wrong ext":     {Path: "proxy/a.sh", Data: []byte("{}")},
		"nul":           {Path: "proxy/a\x00.config", Data: []byte("{}")},
		"unknown table": {Path: "db/auth", Data: []byte("{}")},
		"oversized":     {Path: "proxy/a.config", Data: long},
		"invalid json":  {Path: "proxy/a.config", Data: []byte("{nope")},
		"table array":   {Path: "db/settings", Data: []byte("[1]")},
	}
	for name, ent := range cases {
		if err := e.m.validateWrites([]Entry{ent}); err == nil {
			t.Errorf("%s: %q must be rejected", name, ent.Path)
		}
	}
	for _, ok := range []string{"proxy/a.config", "access/default.json", "waf_central.json", "db/settings"} {
		if err := e.m.validateWrites([]Entry{{Path: ok, Data: []byte("{}")}}); err != nil {
			t.Errorf("%s must be accepted: %v", ok, err)
		}
	}
	// the secret tables are never part of the registry
	for _, forbidden := range []string{"db/auth", "db/apitokens", "db/stats", "db/zorxauth_users", "version", "cluster.json", "waf_challenge.key", "webui/cert.pem"} {
		if e.m.reg.ValidEntry(forbidden) {
			t.Errorf("%s must not be in the registry", forbidden)
		}
	}
}

func TestCollectSkipsSymlinksAndHuge(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	os.WriteFile(filepath.Join(t.TempDir(), "outside.config"), []byte(`{"x":"outside"}`), 0o644)
	outside := filepath.Join(t.TempDir(), "o.config")
	os.WriteFile(outside, []byte(`{"secret":"outside"}`), 0o644)
	if err := os.Symlink(outside, filepath.Join(e.conf, "proxy", "link.config")); err != nil {
		t.Skip("no symlinks")
	}
	huge := bytes.Repeat([]byte(" "), maxFileBytes+10)
	os.WriteFile(filepath.Join(e.conf, "proxy", "huge.config"), huge, 0o644)
	st, skipped, err := e.m.collect()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st["proxy/link.config"]; ok {
		t.Fatal("symlinks must be skipped")
	}
	if _, ok := st["proxy/huge.config"]; ok || len(skipped) != 1 {
		t.Fatalf("huge file must be skipped and reported: %v", skipped)
	}
	// a restore never writes through a symlink at the destination
	v := e.capture("v")
	os.Remove(filepath.Join(e.conf, "proxy", "link.config"))
	os.Remove(filepath.Join(e.conf, "proxy", "huge.config"))
	e.write("proxy/a.config", proxyJSON("a.example.com", "5.5.5.5:80"))
	os.Remove(filepath.Join(e.conf, "proxy", "a.config"))
	os.Symlink(outside, filepath.Join(e.conf, "proxy", "a.config"))
	if _, err := e.m.Restore(RestoreRequest{ID: v.ID, Scope: "proxy"}); err == nil {
		// symlink at the destination: collect ignores it, so the file counts as added and the swap must refuse
		t.Fatal("restore must refuse to replace a symlink")
	}
	if b, _ := os.ReadFile(outside); !strings.Contains(string(b), `"secret":"outside"`) {
		t.Fatal("the symlink target must not be written")
	}
}

func TestMiddlewareCapturesOnlyRealChanges(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Debounce = 400 * time.Millisecond; o.MaxWait = 4 * time.Second })
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.m.Start()
	base := len(e.m.IDs())
	mux := http.NewServeMux()
	mux.HandleFunc("/api/proxy/edit", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Anon") != "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.ParseForm()
		e.write("proxy/a.config", proxyJSON("a.example.com", r.FormValue("ep")))
		w.Write([]byte(`"OK"`))
	})
	mux.HandleFunc("/api/proxy/testupstream", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/api/proxy/list", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[]")) })
	mux.HandleFunc("/api/proxy/del", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	})
	mux.HandleFunc("/api/readonlypost", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/api/history/restore", func(w http.ResponseWriter, r *http.Request) {})
	h := e.m.Middleware(func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if r.Header.Get("X-Anon") != "" {
			return "", false
		}
		return "alice", true
	})(mux)
	do := func(method, path string, form string, hdr ...string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	settle := func() { time.Sleep(1200 * time.Millisecond) }

	do("GET", "/api/proxy/list", "")
	do("POST", "/api/readonlypost", "")
	do("POST", "/api/history/restore", "")
	do("POST", "/api/proxy/testupstream", "")
	do("POST", "/api/proxy/edit", "ep=8.8.8.8:80&rootname=a.example.com", "X-Anon", "1")
	do("POST", "/api/proxy/del", "ep=a.example.com") //fails with 500
	settle()
	if n := len(e.m.IDs()); n != base {
		t.Fatalf("read-only, skipped, failed and unauthenticated requests must not create versions (got %d new)", n-base)
	}
	// reset the file changed by the skipped handlers: external drift is captured before the next real change
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	time.Sleep(1100 * time.Millisecond) // PreChange rate limit window
	do("POST", "/api/proxy/edit", "ep=8.8.8.8:80&rootname=a.example.com")
	do("POST", "/api/proxy/edit", "ep=8.8.4.4:80&rootname=a.example.com")
	settle()
	ids := e.m.IDs()
	if len(ids) != base+1 {
		t.Fatalf("one burst, one version, got %d", len(ids)-base)
	}
	v, _ := e.m.Get(ids[len(ids)-1])
	if v.Actor != "alice" || !strings.HasPrefix(v.Summary, "Proxy rule edited: a.example.com") {
		t.Fatalf("summary: %+v", v)
	}
	if len(v.Changes) != 1 || v.Changes[0].Path != "proxy/a.config" {
		t.Fatalf("changes: %+v", v.Changes)
	}
}

func TestPreChangeRecordsExternalDrift(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.m.Start()
	e.write("proxy/a.config", proxyJSON("a.example.com", "6.6.6.6:80")) // edited on disk by hand
	e.m.PreChange()
	ids := e.m.IDs()
	if len(ids) != 2 {
		t.Fatalf("drift must be recorded before the change: %v", ids)
	}
	v, _ := e.m.Get(ids[1])
	if v.Trigger != "external" || v.Actor != "system" {
		t.Fatalf("%+v", v)
	}
	b, _ := e.m.Get(ids[0])
	if b.Trigger != "baseline" {
		t.Fatalf("%+v", b)
	}
}

func TestConcurrentCapturesAndRestores(t *testing.T) {
	e := newEnv(t, nil)
	e.write("proxy/a.config", proxyJSON("a.example.com", "1.1.1.1:80"))
	e.m.Start()
	var wg sync.WaitGroup
	var wmu sync.Mutex
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				wmu.Lock()
				e.write(fmt.Sprintf("proxy/g%d.config", g), proxyJSON(fmt.Sprintf("g%d.example.com", g), fmt.Sprintf("10.%d.0.%d:80", g, i)))
				wmu.Unlock()
				e.m.Notify(fmt.Sprintf("user%d", g), "Proxy rule edited")
				if i%5 == 0 {
					e.m.PreChange()
					e.m.List(Filter{})
					e.m.Diff(0, e.m.Latest())
				}
				if i%7 == 0 {
					e.m.Capture(CaptureInfo{Actor: "x", Trigger: "manual", Summary: "m"})
				}
			}
		}(g)
	}
	wg.Wait()
	e.m.Flush()
	time.Sleep(150 * time.Millisecond)
	ids := e.m.IDs()
	if len(ids) == 0 || len(ids) > 130 {
		t.Fatalf("unexpected count %d", len(ids))
	}
	// every stored version is intact and ids are unique/ascending
	for i, id := range ids {
		if i > 0 && ids[i-1] >= id {
			t.Fatalf("ids not strictly ascending: %v", ids)
		}
		if _, err := e.m.loadState(id); err != nil {
			t.Fatalf("version %d damaged: %v", id, err)
		}
	}
	// the store survives a restart
	m2 := e.reopen(nil)
	if r, err := m2.List(Filter{PageSize: 200}); err != nil || r.Total != len(ids) {
		t.Fatalf("reload: %v %d", err, r.Total)
	}
}

func TestListFilterAndPaging(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 12; i++ {
		e.write("proxy/a.config", proxyJSON("a.example.com", fmt.Sprintf("1.1.1.%d:80", i)))
		if i%2 == 0 {
			e.write("redirect/r.json", fmt.Sprintf(`{"i":%d}`, i))
		}
		e.advance(time.Hour)
		actor := "alice"
		if i%3 == 0 {
			actor = "bob"
		}
		e.m.Capture(CaptureInfo{Actor: actor, Trigger: "api", Summary: fmt.Sprintf("edit %d", i)})
	}
	r, _ := e.m.List(Filter{PageSize: 5, Page: 1})
	if r.Total != 12 || len(r.Items) != 5 || r.Items[0].ID != 12 {
		t.Fatalf("paging: %+v", r)
	}
	r, _ = e.m.List(Filter{PageSize: 5, Page: 3})
	if len(r.Items) != 2 {
		t.Fatalf("last page: %d", len(r.Items))
	}
	r, _ = e.m.List(Filter{Actor: "bob", PageSize: 50})
	if r.Total != 4 {
		t.Fatalf("actor filter: %d", r.Total)
	}
	r, _ = e.m.List(Filter{Object: "redirect", PageSize: 50})
	if r.Total != 6 {
		t.Fatalf("object filter: %d", r.Total)
	}
	from := e.clock().Add(-3 * time.Hour).Unix()
	r, _ = e.m.List(Filter{From: from, PageSize: 50})
	if r.Total != 4 {
		t.Fatalf("date filter: %d", r.Total)
	}
}

func TestRegistryExtensible(t *testing.T) {
	reg := DefaultRegistry()
	reg.RegisterArea(Area{ID: "myplugin", Label: "My plugin"})
	reg.RegisterRoot(Root{Path: "myplugin.json", Area: "myplugin"})
	reg.RegisterTable(Table{Name: "myplugin_tbl", Area: "myplugin"})
	if !reg.ValidFile("myplugin.json") || !reg.ValidTable("db/myplugin_tbl") || reg.AreaOf("myplugin.json") != "myplugin" {
		t.Fatal("registered items must be accepted")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unsafe root must panic")
		}
	}()
	reg.RegisterRoot(Root{Path: "../x", Area: "x"})
}

func TestLastFiveVersionsNeverRemovedEvenWithTinyBudget(t *testing.T) {
	e := newEnv(t, nil)
	e.m.SetSettings(Settings{Enabled: true, KeepCount: 5, KeepDays: 1, MaxMiB: 10})
	rnd := rand.New(rand.NewSource(2))
	for i := 0; i < 10; i++ {
		b := make([]byte, 3<<20)
		rnd.Read(b)
		e.write("proxy/a.config", fmt.Sprintf(`{"x":"%x"}`, b[:1500000]))
		e.advance(72 * time.Hour)
		e.capture("big")
	}
	if n := len(e.m.IDs()); n < 5 {
		t.Fatalf("at least the last 5 must remain, got %d", n)
	}
}
