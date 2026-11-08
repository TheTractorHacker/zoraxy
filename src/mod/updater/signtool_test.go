package updater

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSignToolRoundtrip signs a directory with tools/sign_release.go using a
// throwaway key and checks that the updater's verifier accepts the output.
func TestSignToolRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	tool, _ := filepath.Abs("../../../tools/sign_release.go")
	if _, err := os.Stat(tool); err != nil {
		t.Skip("tools/sign_release.go not found")
	}
	dir := t.TempDir()
	priv, pubPath, dist := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub"), filepath.Join(dir, "dist")
	must(t, os.MkdirAll(dist, 0o755))
	bin := []byte("fake release binary")
	must(t, os.WriteFile(filepath.Join(dist, "zoraxy_linux_amd64"), bin, 0o755))

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(goBin, append([]string{"run", tool}, args...)...)
		cmd.Dir = dir // do not run from inside the module
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sign tool %v: %v\n%s", args, err, out)
		}
	}
	run("-genkey", priv, pubPath)
	run("-dist", dist, "-key", priv, "-pub", pubPath)

	pemBytes, _ := os.ReadFile(pubPath)
	pub, err := ParsePublicKeyPEM(pemBytes)
	must(t, err)
	sums, _ := os.ReadFile(filepath.Join(dist, "SHA256SUMS"))
	sig, _ := os.ReadFile(filepath.Join(dist, "SHA256SUMS.sig"))
	must(t, VerifySums(pub, sums, sig))
	want, err := SumFor(sums, "zoraxy_linux_amd64")
	must(t, err)
	if len(want) != 64 {
		t.Fatal("bad sum")
	}
	// the committed production key must NOT accept a throwaway signature
	prod, _ := EmbeddedPublicKey()
	if VerifySums(prod, sums, sig) == nil {
		t.Fatal("production key accepted a throwaway signature")
	}
}
