package cluster

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTree creates a conf folder that contains synced data and, next to it,
// every kind of node specific data that must never be synced.
func writeTree(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"proxy/a.config":           `{"RootOrMatchingDomain":"a.example.com"}`,
		"proxy/b.config":           `{"RootOrMatchingDomain":"b.example.com"}`,
		"proxy/a.config.bak":       `{"old":true}`,
		"redirect/r1.json":         `{"from":"/x"}`,
		"access/default.json":      `{"id":"default"}`,
		"streamproxy/s1.config":    `{"name":"s1"}`,
		"rules/pathrules/p1.json":  `{"path":"/"}`,
		"trusted_proxies.json":     `["10.0.0.0/8"]`,
		"acme_conf.json":           `{"Enabled":true,"Email":"ops@example.com"}`,
		"certs/a.pem":              "CERT-A",
		"certs/a.key":              "KEY-A",
		"webui/webui.key":          "WEBUI-TLS-PRIVATE-KEY",
		"webui/webui.crt":          "WEBUI-TLS-CERT",
		"updater/pending.json":     `{"UPDATER-STATE":true}`,
		"sys.uuid":                 "SYSUUID-MARKER",
		"auth_users.json":          `{"admin":"PASSWORDHASH-SHA512"}`,
		"cluster.json":             `{"secret":"` + testSecret + `"}`,
		"log_conf.json":            `{}`,
		"plugin_groups.json":       `{}`,
		".cluster/follower.json":   `{"appliedVersion":1}`,
		"geodb/GeoLite2.mmdb":      "geo",
		"proxy/subdir/evil.config": `{}`,
	}
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func pathsOf(p *Payload) map[string]string {
	m := map[string]string{}
	for _, f := range p.Files {
		m[f.Path] = string(f.Data)
	}
	return m
}

func TestSnapshotContentsAndExclusions(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir)

	p, err := CollectFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	got := pathsOf(p)
	for _, want := range []string{
		"proxy/a.config", "proxy/b.config", "redirect/r1.json", "access/default.json",
		"streamproxy/s1.config", "rules/pathrules/p1.json", "trusted_proxies.json", "acme_conf.json",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s in snapshot", want)
		}
	}
	for path, content := range got {
		for _, bad := range []string{"certs/", "webui/", "updater/", "sys.uuid", "auth_users", "cluster.json", ".cluster", "geodb", "log_conf", "plugin_groups", ".bak", "subdir"} {
			if strings.Contains(path, bad) {
				t.Errorf("node specific path %q must not be in the snapshot", path)
			}
		}
		for _, bad := range []string{"PASSWORDHASH", "SYSUUID-MARKER", "UPDATER-STATE", "WEBUI-TLS", testSecret, "CERT-A", "KEY-A"} {
			if strings.Contains(content, bad) {
				t.Errorf("%s leaks %q", path, bad)
			}
		}
	}

	withCerts, err := CollectFiles(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	g2 := pathsOf(withCerts)
	if g2["certs/a.pem"] != "CERT-A" || g2["certs/a.key"] != "KEY-A" {
		t.Fatal("certs missing when sync certificates is on")
	}
	for path := range g2 {
		if strings.HasPrefix(path, "webui/") || strings.HasPrefix(path, "updater/") {
			t.Fatalf("%s must never be synced", path)
		}
	}

	// The sealed form must not contain readable config either
	raw, err := Seal(testSecret, 1, 1, "node", withCerts)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"a.example.com", "KEY-A", "ops@example.com", "PASSWORDHASH", "SYSUUID-MARKER", testSecret} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("sealed snapshot contains plaintext %q", s)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir)
	p, _ := CollectFiles(dir, false)
	raw, err := Seal(testSecret, 42, time.Now().Unix(), "node-a", p)
	if err != nil {
		t.Fatal(err)
	}
	env, got, err := Open(testSecret, raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.Version != 42 || env.Node != "node-a" || got.ContentHash != p.ContentHash || len(got.Files) != len(p.Files) {
		t.Fatalf("round trip mismatch: %+v", env)
	}
}

func TestOpenRejectsTamperingWrongSecretAndGarbage(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir)
	p, _ := CollectFiles(dir, false)
	raw, _ := Seal(testSecret, 7, 100, "n", p)

	if _, _, err := Open(testSecret+"x", raw); err != ErrBadSignature {
		t.Fatalf("wrong secret: want ErrBadSignature got %v", err)
	}

	var env Envelope
	json.Unmarshal(raw, &env)

	mutate := func(f func(e *Envelope)) []byte {
		e := env
		f(&e)
		b, _ := json.Marshal(e)
		return b
	}
	cases := map[string][]byte{
		"version bumped": mutate(func(e *Envelope) { e.Version++ }),
		"node changed":   mutate(func(e *Envelope) { e.Node = "evil" }),
		"time changed":   mutate(func(e *Envelope) { e.CreatedAt++ }),
		"nonce changed":  mutate(func(e *Envelope) { e.Nonce = e.Nonce[:len(e.Nonce)-4] + "AAAA" }),
		"data flipped": mutate(func(e *Envelope) {
			b := []byte(e.Data)
			if b[10] == 'A' {
				b[10] = 'B'
			} else {
				b[10] = 'A'
			}
			e.Data = string(b)
		}),
		"sig removed": mutate(func(e *Envelope) { e.Sig = "" }),
	}
	for name, b := range cases {
		if _, _, err := Open(testSecret, b); err == nil {
			t.Errorf("%s: tampered snapshot accepted", name)
		}
	}
	if _, _, err := Open(testSecret, []byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, _, err := Open(testSecret, []byte(`{"format":"other","v":1}`)); err == nil {
		t.Fatal("foreign format accepted")
	}
}

func TestValidatePayloadRejectsBadPaths(t *testing.T) {
	good := func(files ...FileEntry) *Payload {
		return &Payload{Roots: ManagedRoots(true), Files: files, ContentHash: HashFiles(files)}
	}
	for _, path := range []string{
		"../etc/passwd", "/abs/path", "proxy/../../x.config", "proxy//a.config", "proxy/a.json",
		"webui/webui.key", "sys.uuid", "cluster.json", "proxy/sub/a.config", `proxy\a.config`,
		"proxy/a.config\x00", "updater/x.json", "certs", "acme_conf.json/x", "",
	} {
		if err := ValidatePayload(good(FileEntry{Path: path, Data: []byte("{}")})); err == nil {
			t.Errorf("path %q accepted", path)
		}
	}
	if err := ValidatePayload(good(FileEntry{Path: "proxy/a.config", Data: []byte("{not json")})); err == nil {
		t.Error("invalid JSON config accepted")
	}
	dup := good(FileEntry{Path: "proxy/a.config", Data: []byte("{}")}, FileEntry{Path: "proxy/a.config", Data: []byte("{}")})
	if ValidatePayload(dup) == nil {
		t.Error("duplicate path accepted")
	}
	bad := good(FileEntry{Path: "proxy/a.config", Data: []byte("{}")})
	bad.ContentHash = "deadbeef"
	if ValidatePayload(bad) == nil {
		t.Error("hash mismatch accepted")
	}
	if ValidatePayload(good(FileEntry{Path: "proxy/a.config", Data: []byte("{}")})) != nil {
		t.Error("valid payload rejected")
	}
}
