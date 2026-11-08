package main

// Run with:  cd tools && go test sign_release.go sign_release_test.go
// Uses throwaway keys only.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := generateKey(priv, pub); err == nil {
		t.Fatal("genkey must not overwrite")
	}
	dist := filepath.Join(dir, "dist")
	os.MkdirAll(dist, 0o755)
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_amd64"), []byte("bin-a"), 0o755)
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_arm64"), []byte("bin-b"), 0o755)
	os.WriteFile(filepath.Join(dist, "README"), []byte("ignored"), 0o644)

	if err := signDist(dist, priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := verifyDist(dist, pub); err != nil {
		t.Fatal(err)
	}
	// tamper with a binary
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_arm64"), []byte("evil"), 0o755)
	if verifyDist(dist, pub) == nil {
		t.Fatal("tampered binary verified")
	}
	// wrong public key
	priv2, pub2 := filepath.Join(dir, "k2.pem"), filepath.Join(dir, "k2.pub")
	generateKey(priv2, pub2)
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_arm64"), []byte("bin-b"), 0o755)
	if verifyDist(dist, pub2) == nil {
		t.Fatal("wrong key verified")
	}
	if signDist(dist, priv, pub2) == nil {
		t.Fatal("sign must flag a key/pub mismatch")
	}
}
