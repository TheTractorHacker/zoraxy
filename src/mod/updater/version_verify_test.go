package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestParseTag(t *testing.T) {
	cases := []struct {
		in    string
		want  Tag
		isErr bool
	}{
		{"v3.3.5", Tag{Major: 3, Minor: 3, Patch: 5}, false},
		{"v3.3.5-rc5-grpcfix.1", Tag{Major: 3, Minor: 3, Patch: 5, RC: 5, Topic: "grpcfix", Build: 1}, false},
		{"v3.3.6-rc1.2", Tag{Major: 3, Minor: 3, Patch: 6, RC: 1, Build: 2}, false},
		{"v3.3.5-captcha-stateless.12", Tag{Major: 3, Minor: 3, Patch: 5, Topic: "captcha-stateless", Build: 12}, false},
		{"nightly", Tag{}, true},
		{"v3.3", Tag{}, true},
	}
	for _, c := range cases {
		got, err := ParseTag(c.in)
		if (err != nil) != c.isErr {
			t.Fatalf("%s: err=%v", c.in, err)
		}
		if err == nil {
			got.Raw = ""
			if got != c.want {
				t.Errorf("%s: got %+v want %+v", c.in, got, c.want)
			}
		}
	}
}

func bid(t *testing.T, tag string, age time.Duration) BuildID {
	tg, err := ParseTag(tag)
	if err != nil {
		t.Fatal(err)
	}
	b := BuildID{Tag: tg}
	if age >= 0 {
		b.Published = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Add(-age)
	}
	return b
}

func TestCompareReleases(t *testing.T) {
	day := 24 * time.Hour
	// Same base, different topics: published date decides, not the topic text or build number.
	a := bid(t, "v3.3.5-rc5-zzz.9", 10*day)
	b := bid(t, "v3.3.5-rc5-aaa.1", 1*day)
	if CompareReleases(a, b) != -1 || CompareReleases(b, a) != 1 {
		t.Error("date should dominate within the same base version")
	}
	// Upstream version dominates even against a later date.
	if CompareReleases(bid(t, "v3.3.6-x.1", 100*day), bid(t, "v3.3.5-x.1", 0)) != 1 {
		t.Error("higher upstream version must win")
	}
	// Same date: build number decides.
	if CompareReleases(bid(t, "v3.3.5-x.1", day), bid(t, "v3.3.5-x.2", day)) != -1 {
		t.Error("build number tie-break")
	}
	if CompareReleases(bid(t, "v3.3.5-x.2", day), bid(t, "v3.3.5-x.2", day)) != 0 {
		t.Error("equal")
	}
	// Unknown running date: dated same-base release is newer; undated is not.
	run := BuildID{Tag: Tag{Major: 3, Minor: 3, Patch: 5}}
	if CompareReleases(bid(t, "v3.3.5-rc5-x.1", day), run) != 1 {
		t.Error("dated release should be newer than undated running build")
	}
	if CompareReleases(bid(t, "v3.3.4-x.1", day), run) != -1 {
		t.Error("older upstream version is older")
	}
}

func TestLatestForChannel(t *testing.T) {
	now := time.Now()
	rels := []Release{
		{Tag: "v3.3.5-stable.1", Published: now.Add(-48 * time.Hour)},
		{Tag: "v3.3.5-beta.2", Prerelease: true, Published: now.Add(-1 * time.Hour)},
		{Tag: "garbage", Published: now},
		{Tag: "v3.3.4-old.9", Published: now},
	}
	s, err := LatestForChannel(rels, ChannelStable)
	if err != nil || s.Tag != "v3.3.5-stable.1" {
		t.Fatalf("stable: %v %v", s, err)
	}
	b, err := LatestForChannel(rels, ChannelBeta)
	if err != nil || b.Tag != "v3.3.5-beta.2" {
		t.Fatalf("beta: %v %v", b, err)
	}
	if _, err := LatestForChannel([]Release{{Tag: "v1.0.0-x.1", Prerelease: true}}, ChannelStable); err == nil {
		t.Error("stable with only prereleases must error")
	}
}

func TestAssetName(t *testing.T) {
	for _, c := range [][3]string{
		{"linux", "amd64", "zoraxy_linux_amd64"}, {"linux", "arm64", "zoraxy_linux_arm64"},
		{"linux", "arm", "zoraxy_linux_arm"}, {"linux", "386", "zoraxy_linux_386"},
		{"linux", "riscv64", "zoraxy_linux_riscv64"}, {"linux", "mipsle", "zoraxy_linux_mipsle"},
	} {
		if got := AssetName(c[0], c[1]); got != c[2] {
			t.Errorf("%v -> %s", c, got)
		}
	}
	rel := Release{Assets: []Asset{{Name: "zoraxy_linux_arm64"}, {Name: "zoraxy_linux_amd64"}}}
	if _, ok := FindAsset(rel, AssetName("linux", "amd64")); !ok {
		t.Error("amd64 must be found")
	}
	if _, ok := FindAsset(rel, AssetName("linux", "riscv64")); ok {
		t.Error("riscv64 must be missing")
	}
}

func TestEmbeddedPublicKey(t *testing.T) {
	k, err := EmbeddedPublicKey()
	if err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatalf("embedded key: %v", err)
	}
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("binary-bytes")
	sums := sumsFor("zoraxy_linux_amd64", bin)
	sig := ed25519.Sign(priv, sums)

	if err := VerifySums(pub, sums, sig); err != nil {
		t.Fatalf("good signature rejected: %v", err)
	}
	if VerifySums(otherPub, sums, sig) == nil {
		t.Error("wrong key accepted")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if VerifySums(pub, sums, bad) == nil {
		t.Error("corrupted signature accepted")
	}
	if VerifySums(pub, append(sums, '\n'), sig) == nil {
		t.Error("tampered SHA256SUMS accepted")
	}
	if VerifySums(pub, sums, sig[:10]) == nil || VerifySums(pub, sums, nil) == nil {
		t.Error("short/missing signature accepted")
	}
	if err := VerifyBinarySum(sums, "zoraxy_linux_amd64", sha256.Sum256(bin)); err != nil {
		t.Errorf("good binary rejected: %v", err)
	}
	if VerifyBinarySum(sums, "zoraxy_linux_amd64", sha256.Sum256(append(bin, 'x'))) == nil {
		t.Error("tampered binary accepted")
	}
	if VerifyBinarySum(sums, "zoraxy_linux_arm64", sha256.Sum256(bin)) == nil {
		t.Error("asset missing from SHA256SUMS accepted")
	}
	dup := append(append([]byte(nil), sums...), sums...)
	if _, err := SumFor(dup, "zoraxy_linux_amd64"); err == nil {
		t.Error("duplicate entries accepted")
	}
	if _, err := SumFor([]byte("zz  zoraxy_linux_amd64\n"), "zoraxy_linux_amd64"); err == nil {
		t.Error("malformed hash accepted")
	}
}
