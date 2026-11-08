// sign_release.go - release signing helper for the in-app updater.
//
// This is a standalone program (stdlib only). It is NOT part of the Zoraxy
// binary and not part of the Go module; run it with `go run tools/sign_release.go`.
//
// Modes:
//
//	sign    (default)  go run tools/sign_release.go -dist DIR -key PRIVATE.pem -tag vX.Y.Z[-topic.N] -build N [-pub PUBLIC.pem]
//	        Writes DIR/SHA256SUMS (sha256sum format, over every zoraxy_* file in DIR,
//	        preceded by the signed header line
//	        "# zoraxy-release tag=<tag> build=<n> upstream=<X.Y.Z>" that binds the
//	        release tag and a monotonically increasing build number so an old signed
//	        release cannot be replayed as a downgrade; `sha256sum -c` ignores it)
//	        and DIR/SHA256SUMS.sig (raw 64 byte ed25519 signature over the exact
//	        bytes of SHA256SUMS), then re-verifies its own output.
//	verify             go run tools/sign_release.go -verify -dist DIR -pub PUBLIC.pem
//	        Checks the signature and every listed file's SHA-256.
//	genkey             go run tools/sign_release.go -genkey PRIVATE.pem PUBLIC.pem
//	        Creates a (throwaway or real) ed25519 key pair; refuses to overwrite.
//
// The private key path may also come from $ZORAXY_RELEASE_KEY. The key is read
// only to sign; its contents are never printed or logged.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	sumsName = "SHA256SUMS"
	sigName  = "SHA256SUMS.sig"
)

func main() {
	dist := flag.String("dist", "", "directory containing the zoraxy_* release binaries")
	keyPath := flag.String("key", os.Getenv("ZORAXY_RELEASE_KEY"), "path to the ed25519 private key (PKCS#8 PEM); default $ZORAXY_RELEASE_KEY")
	pubPath := flag.String("pub", "", "path to the ed25519 public key (SPKI PEM) used to verify")
	tag := flag.String("tag", "", "release tag the signature is bound to, e.g. v3.3.6-topic.1 (must equal the GitHub release tag)")
	build := flag.Int("build", 0, "monotonically increasing build number (must exceed the previous release's)")
	verify := flag.Bool("verify", false, "verify an existing dist directory instead of signing")
	genkey := flag.Bool("genkey", false, "generate a key pair: -genkey PRIVATE.pem PUBLIC.pem")
	flag.Parse()

	var err error
	switch {
	case *genkey:
		if flag.NArg() != 2 {
			err = errors.New("usage: -genkey PRIVATE.pem PUBLIC.pem")
		} else {
			err = generateKey(flag.Arg(0), flag.Arg(1))
		}
	case *verify:
		err = verifyDist(*dist, *pubPath)
	default:
		err = signDist(*dist, *keyPath, *pubPath, *tag, *build)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func generateKey(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if err := writeNew(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}), 0o600); err != nil {
		return err
	}
	return writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadPrivate(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("no private key: pass -key or set ZORAXY_RELEASE_KEY")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("private key is not a valid PKCS#8 key")
	}
	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ed25519")
	}
	return pk, nil
}

func loadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("public key is not PEM encoded")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ed25519")
	}
	return pk, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var upstreamRe = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)

func signDist(dist, keyPath, pubPath, tag string, build int) error {
	m := upstreamRe.FindStringSubmatch(tag)
	if m == nil {
		return errors.New("-tag is required and must look like v3.3.6 or v3.3.6-topic.1")
	}
	if build <= 0 {
		return errors.New("-build is required and must be a positive, increasing number")
	}
	if dist == "" {
		return errors.New("-dist is required")
	}
	priv, err := loadPrivate(keyPath)
	if err != nil {
		return err
	}
	ents, err := os.ReadDir(dist)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "zoraxy_") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no zoraxy_* files found in %s", dist)
	}
	sort.Strings(names)
	var sums strings.Builder
	fmt.Fprintf(&sums, "# zoraxy-release tag=%s build=%d upstream=%s\n", tag, build, m[1])
	for _, n := range names {
		h, err := fileSum(filepath.Join(dist, n))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", h, n)
	}
	sig := ed25519.Sign(priv, []byte(sums.String()))
	if err := os.WriteFile(filepath.Join(dist, sumsName), []byte(sums.String()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dist, sigName), sig, 0o644); err != nil {
		return err
	}
	// Verify our own output against the derived public key (and -pub if given).
	derived := priv.Public().(ed25519.PublicKey)
	if pubPath != "" {
		want, err := loadPublic(pubPath)
		if err != nil {
			return err
		}
		if !derived.Equal(want) {
			return errors.New("the private key does not match the expected public key (-pub); signature files were written but are NOT valid for that key")
		}
	}
	if err := verifyWith(dist, derived); err != nil {
		return fmt.Errorf("self-verification failed: %w", err)
	}
	fmt.Printf("signed %d files; wrote %s and %s\n", len(names), sumsName, sigName)
	return nil
}

func verifyDist(dist, pubPath string) error {
	if dist == "" || pubPath == "" {
		return errors.New("-verify needs -dist and -pub")
	}
	pub, err := loadPublic(pubPath)
	if err != nil {
		return err
	}
	if err := verifyWith(dist, pub); err != nil {
		return err
	}
	fmt.Println("OK: signature and checksums verified")
	return nil
}

func verifyWith(dist string, pub ed25519.PublicKey) error {
	sums, err := os.ReadFile(filepath.Join(dist, sumsName))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(dist, sigName))
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, sig) {
		return errors.New("bad signature over " + sumsName)
	}
	n := 0
	first := true
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if first {
			first = false
			if !strings.HasPrefix(line, "# zoraxy-release tag=") || !strings.Contains(line, " build=") {
				return errors.New(sumsName + " has no signed release header")
			}
			continue
		}
		if len(f) != 2 {
			return fmt.Errorf("malformed line %q", line)
		}
		got, err := fileSum(filepath.Join(dist, f[1]))
		if err != nil {
			return err
		}
		if got != f[0] {
			return fmt.Errorf("checksum mismatch for %s", f[1])
		}
		n++
	}
	if n == 0 {
		return errors.New(sumsName + " is empty")
	}
	return nil
}
