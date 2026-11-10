package aiassist

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	keyFileName    = "ai.key"        // random per-install master key (32 bytes, hex), 0600
	sealedFileName = "apikey.sealed" // base64(nonce || AES-256-GCM(api key)), 0600
	sealAAD        = "zoraxy-aiassist-apikey-v1"
)

// ErrTampered is returned when the sealed key cannot be authenticated (modified file or
// a different install key, for example after restoring a backup on another machine).
var ErrTampered = errors.New("the stored API key cannot be decrypted (file modified or from another install); enter the key again")

// IsSecretFile tells the configuration backup which files under the conf folder must never be
// exported. rel is relative to the conf folder.
func IsSecretFile(rel string) bool {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "./")
	return rel == dirName+"/"+keyFileName || rel == dirName+"/"+sealedFileName
}

// Vault holds the sealed API key. The plain key is never kept in memory between calls.
type Vault struct {
	dir string
	mu  sync.Mutex
}

// NewVault uses dir (created 0700 when missing).
func NewVault(dir string) *Vault { return &Vault{dir: dir} }

func (v *Vault) masterKey(create bool) ([]byte, error) {
	p := filepath.Join(v.dir, keyFileName)
	if b, err := os.ReadFile(p); err == nil {
		k, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr == nil && len(k) == 32 {
			return k, nil
		}
		if !create {
			return nil, ErrTampered
		}
	} else if !create {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(p, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func gcmFor(k []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Set seals and stores the API key.
func (v *Vault) Set(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 512 || strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("invalid API key")
	}
	mk, err := v.masterKey(true)
	if err != nil {
		return err
	}
	g, err := gcmFor(mk)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	blob := g.Seal(nonce, nonce, []byte(key), []byte(sealAAD))
	return writeFileAtomic(filepath.Join(v.dir, sealedFileName), []byte(base64.StdEncoding.EncodeToString(blob)), 0o600)
}

// Clear removes the stored key.
func (v *Vault) Clear() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	err := os.Remove(filepath.Join(v.dir, sealedFileName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Get returns the plain key. ok is false when none is stored. Callers must not log it.
func (v *Vault) Get() (key string, ok bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(v.dir, sealedFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", true, ErrTampered
	}
	mk, err := v.masterKey(false)
	if err != nil {
		return "", true, ErrTampered
	}
	g, err := gcmFor(mk)
	if err != nil || len(blob) < g.NonceSize()+g.Overhead() {
		return "", true, ErrTampered
	}
	pt, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], []byte(sealAAD))
	if err != nil {
		return "", true, ErrTampered
	}
	return string(pt), true, nil
}

// Hint returns only whether a key is set and its last 4 characters.
func (v *Vault) Hint() (set bool, last4 string, err error) {
	k, ok, err := v.Get()
	if err != nil {
		return true, "", err
	}
	if !ok {
		return false, "", nil
	}
	if len(k) <= 8 { // never reveal a large part of a short key
		return true, "", nil
	}
	return true, k[len(k)-4:], nil
}

// Pseudonym returns a stable per-install label such as "ip-7f3a1c" for a value. It is an HMAC
// under the install key, so it cannot be reversed or compared across installs.
func (v *Vault) Pseudonym(kind, value string) string {
	v.mu.Lock()
	mk, err := v.masterKey(true)
	v.mu.Unlock()
	if err != nil {
		mk = []byte("zoraxy-aiassist-fallback")
	}
	m := hmac.New(sha256.New, mk)
	m.Write([]byte("pseudonym:" + kind + ":"))
	m.Write([]byte(strings.ToLower(value)))
	return kind + "-" + hex.EncodeToString(m.Sum(nil))[:6]
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_ = tmp.Chmod(perm) // not supported on every platform
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
