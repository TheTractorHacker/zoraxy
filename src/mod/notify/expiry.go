package notify

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ExpiryWatcher emits certificate.expiring for certificates in a store directory that expire within
// WarnDays (or already expired). Each certificate is reported at most once per Repeat interval
// (default 24h) while the process runs.
type ExpiryWatcher struct {
	CertDir  string
	WarnDays func() int
	Emit     func(Event)
	Repeat   time.Duration
	Now      func() time.Time

	mu       sync.Mutex
	lastSent map[string]time.Time
	stop     chan struct{}
}

// CheckOnce scans the store and returns the number of events emitted.
func (w *ExpiryWatcher) CheckOnce() int {
	now := time.Now()
	if w.Now != nil {
		now = w.Now()
	}
	repeat := w.Repeat
	if repeat <= 0 {
		repeat = 24 * time.Hour
	}
	warn := DefaultExpiryWarnDays
	if w.WarnDays != nil && w.WarnDays() > 0 {
		warn = w.WarnDays()
	}
	entries, err := os.ReadDir(w.CertDir)
	if err != nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastSent == nil {
		w.lastSent = map[string]time.Time{}
	}
	sent := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pem")
		if _, err := os.Stat(filepath.Join(w.CertDir, name+".key")); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(w.CertDir, e.Name()))
		if err != nil {
			continue
		}
		cert := firstCert(b)
		if cert == nil {
			continue
		}
		left := cert.NotAfter.Sub(now)
		if left > time.Duration(warn)*24*time.Hour {
			continue
		}
		if t, ok := w.lastSent[name]; ok && now.Sub(t) < repeat {
			continue
		}
		w.lastSent[name] = now
		days := int(left.Hours() / 24)
		exp := cert.NotAfter.UTC()
		ca := cert.Issuer.CommonName
		var meta struct {
			AcmeName string `json:"acme_name"`
		}
		if mb, err := os.ReadFile(filepath.Join(w.CertDir, name+".json")); err == nil {
			if json.Unmarshal(mb, &meta) == nil && meta.AcmeName != "" {
				ca = meta.AcmeName
			}
		}
		domains := append([]string{}, cert.DNSNames...)
		if len(domains) == 0 && cert.Subject.CommonName != "" {
			domains = []string{cert.Subject.CommonName}
		}
		w.Emit(Event{Event: EventCertExpiring, Time: now.UTC(), Source: "certificate", Subject: name,
			Domains: domains, Expiry: &exp, DaysLeft: &days, CA: ca})
		sent++
	}
	return sent
}

// Start runs CheckOnce every interval until Stop. The first check runs after 1 minute so start-up stays quiet.
func (w *ExpiryWatcher) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	w.stop = make(chan struct{})
	go func(stop chan struct{}) {
		t := time.NewTimer(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				w.CheckOnce()
				t.Reset(interval)
			}
		}
	}(w.stop)
}

// Stop ends the background loop.
func (w *ExpiryWatcher) Stop() {
	if w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
}

func firstCert(b []byte) *x509.Certificate {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			return c
		}
	}
}
