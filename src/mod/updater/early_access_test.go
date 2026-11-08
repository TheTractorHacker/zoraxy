package updater

import "testing"

// Upstream #969: release candidates must be marked as early access in the updater.
func TestMarkEarlyAccess(t *testing.T) {
	cases := []struct {
		tag  string
		pre  bool
		want bool
	}{
		{"v3.3.5-rc5-grpcfix.1", false, true}, // rc tag without the GitHub pre-release flag
		{"v3.3.6-rc1.2", false, true},
		{"v3.3.5-beta.2", true, true}, // GitHub flag
		{"v3.3.5.1", false, false},    // plain stable release
		{"v3.3.6-topic.1", false, false},
	}
	for _, c := range cases {
		r := Release{Tag: c.tag, Prerelease: c.pre}
		r.MarkEarlyAccess()
		if r.EarlyAccess != c.want {
			t.Errorf("%s (prerelease=%v): EarlyAccess=%v, want %v", c.tag, c.pre, r.EarlyAccess, c.want)
		}
	}
}
