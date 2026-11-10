package confhistory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"imuslab.com/zoraxy/mod/cluster"
)

/*
	Sealing

	Everything in the history store is sealed with AES-256-GCM. The key is a
	random per-install secret in conf/.history/history.key (mode 0600, created on
	first use). Sub keys for encryption and for content addressing are derived
	with the HKDF helper of the cluster package (separate purposes), so the
	blob names (HMAC-SHA256 of the plaintext) reveal nothing about the content.
	The "additional data" of every object binds it to its kind and name, so a
	blob cannot be swapped for another one and a flipped bit is detected.
*/

const (
	purposeEncrypt = "history-encrypt"
	purposeName    = "history-content-name"
	sealMagic      = "ZHS1"
)

// ErrTampered is returned when a sealed object fails authentication.
var ErrTampered = errors.New("history store object failed authentication (corrupted or tampered)")

type sealer struct {
	gcm     cipher.AEAD
	nameKey []byte
}

func loadOrCreateKey(path string) (*sealer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw = []byte(hex.EncodeToString(b))
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil, err
		}
	}
	secret := strings.TrimSpace(string(raw))
	if len(secret) < 32 {
		return nil, errors.New("history.key is too short or damaged")
	}
	block, err := aes.NewCipher(cluster.DeriveKey(secret, purposeEncrypt, 32))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{gcm: gcm, nameKey: cluster.DeriveKey(secret, purposeName, 32)}, nil
}

// name returns the content address of plaintext.
func (s *sealer) name(plain []byte) string {
	m := hmac.New(sha256.New, s.nameKey)
	m.Write(plain)
	return hex.EncodeToString(m.Sum(nil))
}

// nameOf hashes an arbitrary string list (version hashes).
func (s *sealer) nameOf(parts ...string) string {
	m := hmac.New(sha256.New, s.nameKey)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

func (s *sealer) seal(kind, name string, plain []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(sealMagic), nonce...)
	return s.gcm.Seal(out, nonce, plain, []byte(kind+":"+name)), nil
}

func (s *sealer) open(kind, name string, sealed []byte) ([]byte, error) {
	n := s.gcm.NonceSize()
	if len(sealed) < len(sealMagic)+n+s.gcm.Overhead() || string(sealed[:len(sealMagic)]) != sealMagic {
		return nil, ErrTampered
	}
	nonce := sealed[len(sealMagic) : len(sealMagic)+n]
	plain, err := s.gcm.Open(nil, nonce, sealed[len(sealMagic)+n:], []byte(kind+":"+name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTampered, kind)
	}
	return plain, nil
}
