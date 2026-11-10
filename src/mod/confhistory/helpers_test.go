package confhistory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// memKV is an in-memory sys.db.
type memKV struct {
	mu     sync.Mutex
	tables map[string]map[string][]byte
	failOn string // "table/key": Write fails
}

func newMemKV() *memKV { return &memKV{tables: map[string]map[string][]byte{}} }

func (k *memKV) TableExists(t string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.tables[t]
	return ok
}
func (k *memKV) NewTable(t string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.tables[t] == nil {
		k.tables[t] = map[string][]byte{}
	}
	return nil
}
func (k *memKV) Write(t, key string, v interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failOn == t+"/"+key {
		return fmt.Errorf("injected db failure")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if k.tables[t] == nil {
		k.tables[t] = map[string][]byte{}
	}
	k.tables[t][key] = b
	return nil
}
func (k *memKV) Delete(t, key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.tables[t], key)
	return nil
}
func (k *memKV) ListTable(t string) ([][][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var keys []string
	for key := range k.tables[t] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out [][][]byte
	for _, key := range keys {
		out = append(out, [][]byte{[]byte(key), k.tables[t][key]})
	}
	return out, nil
}
func (k *memKV) get(t, key string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return string(k.tables[t][key])
}

type env struct {
	t    *testing.T
	conf string
	kv   *memKV
	m    *Manager
	now  time.Time
	mu   sync.Mutex
}

func (e *env) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func newEnv(t *testing.T, mut func(*Options)) *env {
	t.Helper()
	e := &env{t: t, conf: filepath.Join(t.TempDir(), "conf"), kv: newMemKV(), now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	if err := os.MkdirAll(e.conf, 0o755); err != nil {
		t.Fatal(err)
	}
	opt := Options{ConfDir: e.conf, DB: e.kv, Debounce: 40 * time.Millisecond, MaxWait: 400 * time.Millisecond, Now: e.clock}
	if mut != nil {
		mut(&opt)
	}
	m, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	e.m = m
	return e
}

func (e *env) write(rel, content string) {
	e.t.Helper()
	p := filepath.Join(e.conf, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(e.conf, filepath.FromSlash(rel)))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func (e *env) capture(summary string) Meta {
	e.t.Helper()
	meta, _, err := e.m.Capture(CaptureInfo{Actor: "tester", Trigger: "api", Summary: summary})
	if err != nil {
		e.t.Fatal(err)
	}
	return meta
}

// reopen simulates a process restart on the same folder.
func (e *env) reopen(mut func(*Options)) *Manager {
	opt := Options{ConfDir: e.conf, DB: e.kv, Debounce: 40 * time.Millisecond, Now: e.clock}
	if mut != nil {
		mut(&opt)
	}
	m, err := New(opt)
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

func proxyJSON(domain, target string) string {
	return fmt.Sprintf(`{"RootOrMatchingDomain":%q,"ActiveOrigins":[{"OriginIpOrDomain":%q}],"RequireRateLimit":false}`, domain, target)
}
