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
	"strconv"
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

// SumsHeader is the signed release identity carried on the first line of
// SHA256SUMS: "# zoraxy-release tag=<tag> build=<n> upstream=<ver>". Because
// the line is inside the signed bytes, an old validly-signed SHA256SUMS cannot
// be replayed as a newer release (the tag must match the fetched release and
// the build number must increase).
type SumsHeader struct {
	Tag      string
	Build    int
	Upstream string
}

const sumsHeaderPrefix = "# zoraxy-release "

// FormatSumsHeader renders the header line (without trailing newline).
func FormatSumsHeader(h SumsHeader) string {
	return fmt.Sprintf("%stag=%s build=%d upstream=%s", sumsHeaderPrefix, h.Tag, h.Build, h.Upstream)
}

// ParseSumsHeader reads the release header from the first line of sums.
func ParseSumsHeader(sums []byte) (SumsHeader, error) {
	line := string(sums)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimRight(line, "\r")
	if !strings.HasPrefix(line, sumsHeaderPrefix) {
		return SumsHeader{}, errors.New("SHA256SUMS has no signed release header (old or unversioned release); refusing")
	}
	var h SumsHeader
	for _, kv := range strings.Fields(strings.TrimPrefix(line, sumsHeaderPrefix)) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "tag":
			h.Tag = v
		case "upstream":
			h.Upstream = v
		case "build":
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return SumsHeader{}, fmt.Errorf("invalid build number %q in the signed release header", v)
			}
			h.Build = n
		}
	}
	if h.Tag == "" || h.Build == 0 {
		return SumsHeader{}, errors.New("incomplete signed release header (need tag and build)")
	}
	return h, nil
}

// CheckSumsHeader verifies the signed header against the release that was
// fetched and the build number of the currently installed release (0 when
// unknown).
func CheckSumsHeader(sums []byte, relTag string, installedBuild int) (SumsHeader, error) {
	h, err := ParseSumsHeader(sums)
	if err != nil {
		return h, err
	}
	if h.Tag != relTag {
		return h, fmt.Errorf("signed release tag %q does not match release tag %q (possible replay of an older release)", h.Tag, relTag)
	}
	if h.Build <= installedBuild {
		return h, fmt.Errorf("signed build %d is not newer than the installed build %d; refusing downgrade", h.Build, installedBuild)
	}
	return h, nil
}
