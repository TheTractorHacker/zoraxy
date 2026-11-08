package updater

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tag is a parsed fork release tag.
type Tag struct {
	Raw   string
	Major int
	Minor int
	Patch int
	RC    int    // 0 when the tag is not a release candidate
	Topic string // free text between the upstream version and the build number
	Build int    // trailing ".<n>" fork build number, 0 if absent
}

var tagRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?(?:-([A-Za-z0-9_-]+?))?(?:\.(\d+))?$`)

// ParseTag parses tags such as v3.3.5, v3.3.5-rc5-grpcfix.1 or v3.3.6-rc1.2.
func ParseTag(s string) (Tag, error) {
	m := tagRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Tag{}, fmt.Errorf("unrecognised release tag %q", s)
	}
	atoi := func(x string) int { n, _ := strconv.Atoi(x); return n }
	return Tag{Raw: s, Major: atoi(m[1]), Minor: atoi(m[2]), Patch: atoi(m[3]), RC: atoi(m[4]), Topic: m[5], Build: atoi(m[6])}, nil
}

// BaseVersion returns "major.minor.patch".
func (t Tag) BaseVersion() string { return fmt.Sprintf("%d.%d.%d", t.Major, t.Minor, t.Patch) }

// BuildID identifies one build: a tag plus the time it was published.
// A zero Published means "unknown date".
type BuildID struct {
	Tag       Tag
	Published time.Time
}

// CompareReleases orders two builds: -1 if a is older than b, 0 if equal, +1 if newer.
// Order: upstream version triple, then published-at, then fork build number.
// If only one side has a date, the undated side is the running build of
// unknown origin and is treated as older than any dated release of the same
// upstream version.
func CompareReleases(a, b BuildID) int {
	for _, p := range [][2]int{{a.Tag.Major, b.Tag.Major}, {a.Tag.Minor, b.Tag.Minor}, {a.Tag.Patch, b.Tag.Patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case !a.Published.IsZero() && !b.Published.IsZero():
		if a.Published.Before(b.Published) {
			return -1
		}
		if a.Published.After(b.Published) {
			return 1
		}
	case a.Published.IsZero() && !b.Published.IsZero():
		return -1
	case !a.Published.IsZero() && b.Published.IsZero():
		return 1
	}
	if a.Tag.Build != b.Tag.Build {
		if a.Tag.Build < b.Tag.Build {
			return -1
		}
		return 1
	}
	return 0
}

// Release is the subset of a GitHub release the updater needs.
type Release struct {
	Tag        string `json:"tag"`
	Name       string `json:"name"`
	Notes      string `json:"notes"`
	URL        string `json:"url"`
	Prerelease bool   `json:"prerelease"`
	// EarlyAccess marks releases the UI must label as early access: GitHub pre-releases and every
	// release candidate ("-rcN" tags), even when the GitHub pre-release flag was not ticked (upstream #969).
	// It is informational only; channel selection still follows the Prerelease flag.
	EarlyAccess bool      `json:"early_access"`
	Published   time.Time `json:"published"`
	Assets      []Asset   `json:"assets"`
}

// Asset is a release asset.
type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"-"`
}

// MarkEarlyAccess sets EarlyAccess from the GitHub flag and the tag.
func (r *Release) MarkEarlyAccess() {
	r.EarlyAccess = r.Prerelease
	if t, err := ParseTag(r.Tag); err == nil && t.RC > 0 {
		r.EarlyAccess = true
	}
}

// ID returns the ordering identity of the release.
func (r Release) ID() (BuildID, error) {
	t, err := ParseTag(r.Tag)
	return BuildID{Tag: t, Published: r.Published}, err
}

// Update channels.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// ValidChannel reports whether c is a known channel.
func ValidChannel(c string) bool { return c == ChannelStable || c == ChannelBeta }

// LatestForChannel returns the newest release visible on the channel.
// stable: non-prerelease only. beta: everything (prereleases included).
// Releases with unparseable tags are skipped. Drafts must be filtered by the caller.
func LatestForChannel(rels []Release, channel string) (*Release, error) {
	type item struct {
		r  Release
		id BuildID
	}
	var items []item
	for _, r := range rels {
		if channel != ChannelBeta && r.Prerelease {
			continue
		}
		id, err := r.ID()
		if err != nil {
			continue
		}
		items = append(items, item{r, id})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no releases found on the %s channel", channel)
	}
	sort.SliceStable(items, func(i, j int) bool { return CompareReleases(items[i].id, items[j].id) > 0 })
	r := items[0].r
	return &r, nil
}

// AssetName returns the release asset name for a platform.
func AssetName(goos, goarch string) string { return "zoraxy_" + goos + "_" + goarch }

// FindAsset finds a named asset in a release.
func FindAsset(r Release, name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Names of the signing assets attached to every release.
const (
	SumsAsset = "SHA256SUMS"
	SigAsset  = "SHA256SUMS.sig"
)
