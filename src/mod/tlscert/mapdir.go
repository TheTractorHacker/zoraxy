package tlscert

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/acme"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	mapdir.go

	Certificates from a mapped directory (upstream #798), for setups where certbot, acme.sh, cert-manager
	or a secrets mount keeps the files up to date outside Zoraxy.

	The directory is polled every Interval seconds (no new dependency, works on network and
	container mounts where inotify does not). Supported layouts, all relative to the directory:

	  fullchain.pem + privkey.pem                  (the directory itself, name = directory name)
	  <name>/fullchain.pem + <name>/privkey.pem    (also <name>/cert.pem, <name>/tls.crt + tls.key)
	  live/<name>/fullchain.pem + privkey.pem      (certbot; symlinks into archive/ are followed)
	  <name>.crt + <name>.key                      (also <name>.pem + <name>.key)
	  <name>/*.crt + <name>/*.key                  (one pair per folder)

	Files are copied into the certificate store (<name>.pem, <name>.key, <name>.json with
	managed_by=mapdir) after the key was verified to match the certificate. The source files are only
	ever read, never modified or deleted. Certificates of the same name that were not imported from
	the directory are never overwritten. Imported certificates are never auto renewed by ACME.
*/

// MapDirCandidate is a certificate/key pair found in the directory.
type MapDirCandidate struct {
	Name     string
	CertPath string
	KeyPath  string
}

// MapDirStatus is what the UI shows for each pair found in the last scan.
type MapDirStatus struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	Imported  bool   `json:"imported"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checkedAt"`
}

// MapDirWatcher polls a directory and imports changed certificates.
type MapDirWatcher struct {
	Dir      string
	Interval time.Duration
	Manager  *Manager
	// Logf receives progress messages (may be nil)
	Logf func(format string, args ...any)

	mu       sync.Mutex
	seen     map[string]string // candidate key -> fingerprint of the last processed state (error or success)
	status   []MapDirStatus
	stop     chan struct{}
	lastScan time.Time
}

func (w *MapDirWatcher) logf(format string, args ...any) {
	if w.Logf != nil {
		w.Logf(format, args...)
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p) // follows symlinks (certbot live/ links)
	return err == nil && st.Mode().IsRegular()
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// pairInDir finds a certificate/key pair inside one folder.
func pairInDir(dir string) (cert, key string, ok bool) {
	for _, c := range []struct{ cert, key string }{
		{"fullchain.pem", "privkey.pem"},
		{"tls.crt", "tls.key"},
		{"cert.pem", "privkey.pem"},
		{"cert.pem", "key.pem"},
		{"certificate.crt", "private.key"},
	} {
		if fileExists(filepath.Join(dir, c.cert)) && fileExists(filepath.Join(dir, c.key)) {
			return filepath.Join(dir, c.cert), filepath.Join(dir, c.key), true
		}
	}
	// exactly one *.crt/*.pem and one *.key
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", false
	}
	var certs, keys []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if !fileExists(p) {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".crt", ".cer":
			certs = append(certs, p)
		case ".key":
			keys = append(keys, p)
		}
	}
	if len(certs) == 1 && len(keys) == 1 {
		return certs[0], keys[0], true
	}
	return "", "", false
}

// Discover lists the certificate/key pairs in the mapped directory.
func Discover(root string) []MapDirCandidate {
	var out []MapDirCandidate
	seenName := map[string]bool{}
	add := func(name, c, k string) {
		name = StoreNameFromDomain(name)
		if name == "" || !storeNameRegex.MatchString(name) || seenName[name] {
			return
		}
		seenName[name] = true
		out = append(out, MapDirCandidate{Name: name, CertPath: c, KeyPath: k})
	}
	if c, k, ok := pairInDir(root); ok && (filepath.Base(c) == "fullchain.pem" || filepath.Base(c) == "tls.crt") {
		add(filepath.Base(root), c, k)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	// certbot live/<name>/
	if live := filepath.Join(root, "live"); isDir(live) {
		if sub, err := os.ReadDir(live); err == nil {
			for _, e := range sub {
				dir := filepath.Join(live, e.Name())
				if isDir(dir) {
					if c, k, ok := pairInDir(dir); ok {
						add(e.Name(), c, k)
					}
				}
			}
		}
	}
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		switch {
		case isDir(p):
			if e.Name() == "live" || e.Name() == "archive" || e.Name() == "renewal" || e.Name() == "keys" {
				continue
			}
			if c, k, ok := pairInDir(p); ok {
				add(e.Name(), c, k)
			}
		case fileExists(p):
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".crt" || ext == ".cer" || ext == ".pem" {
				base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
				if k := filepath.Join(root, base+".key"); fileExists(k) {
					add(base, p, k)
				}
			}
		}
	}
	return out
}

func sha(b ...[]byte) string {
	h := sha256.New()
	for _, x := range b {
		h.Write(x)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// importCandidate validates and copies one pair. It returns imported=true only if the store changed.
func (w *MapDirWatcher) importCandidate(c MapDirCandidate) (imported bool, err error) {
	m := w.Manager
	certPEM, err := os.ReadFile(c.CertPath)
	if err != nil {
		return false, err
	}
	keyPEM, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return false, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("certificate and key do not match or are unreadable: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, err
	}
	if time.Now().After(leaf.NotAfter) {
		return false, fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}

	pemPath := filepath.Join(m.CertStore, c.Name+".pem")
	keyPath := filepath.Join(m.CertStore, c.Name+".key")
	infoPath := filepath.Join(m.CertStore, c.Name+".json")
	if utils.FileExists(pemPath) || utils.FileExists(keyPath) {
		info, ierr := acme.LoadCertInfoJSON(infoPath)
		if ierr != nil || info.ManagedBy != "mapdir" {
			return false, fmt.Errorf("a certificate named %q exists in the store and is not managed by the mapped directory; it was left alone", c.Name)
		}
		curPEM, _ := os.ReadFile(pemPath)
		curKey, _ := os.ReadFile(keyPath)
		if bytes.Equal(curPEM, certPEM) && bytes.Equal(curKey, keyPEM) {
			return false, nil // already current
		}
	}

	if err := os.MkdirAll(m.CertStore, 0o775); err != nil {
		return false, err
	}
	if err := writeFileWithMode(m.CertStore, c.Name+".key", keyPEM, defaultPrivateKeyFileMode); err != nil {
		return false, err
	}
	if err := writeFileWithMode(m.CertStore, c.Name+".pem", certPEM, defaultPublicCertFileMode); err != nil {
		return false, err
	}
	info := &acme.CertificateInfoJSON{ManagedBy: "mapdir", Source: c.CertPath, AcmeName: leaf.Issuer.CommonName}
	if err := acme.SaveCertInfoJSON(infoPath, info, defaultPublicCertFileMode); err != nil {
		return false, err
	}
	return true, nil
}

// ScanOnce examines the directory once and returns the number of certificates imported or updated.
func (w *MapDirWatcher) ScanOnce() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen == nil {
		w.seen = map[string]string{}
	}
	now := time.Now()
	w.lastScan = now
	stamp := now.Format("2006-01-02 15:04:05")
	status := []MapDirStatus{}
	changed := 0
	for _, c := range Discover(w.Dir) {
		ci, err1 := os.Stat(c.CertPath)
		ki, err2 := os.Stat(c.KeyPath)
		if err1 != nil || err2 != nil {
			continue
		}
		// cheap change detection first (mtime + size), content hash second
		stat := fmt.Sprintf("%d:%d:%d:%d", ci.ModTime().UnixNano(), ci.Size(), ki.ModTime().UnixNano(), ki.Size())
		prev, known := w.seen[c.Name+"|stat"]
		st := MapDirStatus{Name: c.Name, Source: c.CertPath, CheckedAt: stamp}
		if known && prev == stat {
			st.Imported = w.seen[c.Name+"|err"] == ""
			st.Error = w.seen[c.Name+"|err"]
			status = append(status, st)
			continue
		}
		w.seen[c.Name+"|stat"] = stat
		certPEM, _ := os.ReadFile(c.CertPath)
		keyPEM, _ := os.ReadFile(c.KeyPath)
		hash := sha(certPEM, keyPEM)
		if w.seen[c.Name+"|hash"] == hash && w.seen[c.Name+"|err"] == "" {
			st.Imported = true
			status = append(status, st)
			continue
		}
		w.seen[c.Name+"|hash"] = hash
		imported, err := w.importCandidate(c)
		if err != nil {
			w.seen[c.Name+"|err"] = err.Error()
			st.Error = err.Error()
			w.logf("[certs-dir] %s: %v", c.Name, err)
		} else {
			w.seen[c.Name+"|err"] = ""
			st.Imported = true
			if imported {
				changed++
				w.logf("[certs-dir] imported %s from %s", c.Name, c.CertPath)
			}
		}
		status = append(status, st)
	}
	w.status = status
	if changed > 0 {
		w.Manager.UpdateLoadedCertList()
	}
	return changed
}

// Start begins polling; the first scan runs immediately.
func (w *MapDirWatcher) Start() {
	if w.Interval < time.Second {
		w.Interval = 60 * time.Second
	}
	w.stop = make(chan struct{})
	go func(stop chan struct{}) {
		w.ScanOnce()
		t := time.NewTicker(w.Interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				w.ScanOnce()
			}
		}
	}(w.stop)
}

// Stop ends polling.
func (w *MapDirWatcher) Stop() {
	if w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
}

// Status returns the result of the last scan.
func (w *MapDirWatcher) Status() []MapDirStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]MapDirStatus{}, w.status...)
}

// HandleMapDir serves /api/cert/mapdir: GET status; POST op=scan triggers an immediate scan.
// A nil watcher reports enabled=false.
func HandleMapDir(w *MapDirWatcher) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if w == nil {
			utils.SendJSONResponse(rw, `{"enabled":false,"items":[]}`)
			return
		}
		if r.Method == http.MethodPost {
			if op, _ := utils.PostPara(r, "op"); op == "scan" {
				w.ScanOnce()
			}
		}
		js, _ := json.Marshal(map[string]any{"enabled": true, "dir": w.Dir, "intervalSeconds": int(w.Interval.Seconds()), "items": w.Status()})
		utils.SendJSONResponse(rw, string(js))
	}
}
