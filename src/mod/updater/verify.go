package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

//go:embed release_pubkey.pem
var embeddedPubKeyPEM []byte

// ParsePublicKeyPEM parses a PEM encoded SPKI ed25519 public key.
func ParsePublicKeyPEM(p []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 public key")
	}
	return pk, nil
}

// EmbeddedPublicKey returns the release public key compiled into the binary.
func EmbeddedPublicKey() (ed25519.PublicKey, error) { return ParsePublicKeyPEM(embeddedPubKeyPEM) }

// VerifySums checks the raw ed25519 signature over the exact bytes of sums.
func VerifySums(pub ed25519.PublicKey, sums, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature has wrong length (%d bytes)", len(sig))
	}
	if !ed25519.Verify(pub, sums, sig) {
		return errors.New("SHA256SUMS signature verification FAILED")
	}
	return nil
}

// SumFor extracts the hex SHA-256 listed for name in a sha256sum formatted
// file. Exactly one matching line must exist.
func SumFor(sums []byte, name string) (string, error) {
	found := ""
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) != 2 || strings.TrimPrefix(f[1], "*") != name {
			continue
		}
		h := strings.ToLower(f[0])
		if _, err := hex.DecodeString(h); err != nil || len(h) != 64 {
			return "", fmt.Errorf("malformed checksum for %s", name)
		}
		if found != "" {
			return "", fmt.Errorf("duplicate checksum entries for %s", name)
		}
		found = h
	}
	if found == "" {
		return "", fmt.Errorf("%s is not listed in SHA256SUMS", name)
	}
	return found, nil
}

// VerifyBinarySum compares the computed hash of a binary to its signed entry.
func VerifyBinarySum(sums []byte, name string, got [sha256.Size]byte) error {
	want, err := SumFor(sums, name)
	if err != nil {
		return err
	}
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return nil
}
