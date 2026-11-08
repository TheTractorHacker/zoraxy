package notify

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CertExpiry is the expiry of one certificate of the store
type CertExpiry struct {
	Name     string
	NotAfter time.Time
}

// ScanCertExpiry reads the leaf certificate of every <name>.pem (with a matching .key) in dir,
// soonest expiry first. It parses files, so callers should cache the result.
func ScanCertExpiry(dir string) []CertExpiry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []CertExpiry
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pem")
		if _, err := os.Stat(filepath.Join(dir, name+".key")); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if c := firstCert(b); c != nil {
			out = append(out, CertExpiry{Name: name, NotAfter: c.NotAfter})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out
}
