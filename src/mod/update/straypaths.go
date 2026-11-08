package update

import (
	"os"
	"path/filepath"
)

// StrayPath describes a configured folder that differs from its relative default
// while the default folder still exists on disk.
type StrayPath struct {
	Flag    string //command line flag, e.g. "conf"
	Default string //the relative default, e.g. "./conf"
	Used    string //the folder in use
}

// FindStrayDefaultPaths reports the flags where a custom folder is in use but the
// relative default folder exists too. Older builds ran the config migrations
// against ./conf even with -conf set, so such a folder may hold stale data that is
// no longer read. folders maps the flag name to {default, configured}.
func FindStrayDefaultPaths(folders map[string][2]string) []StrayPath {
	var found []StrayPath
	for _, flagName := range []string{"conf", "tmp", "log", "plugin", "webroot"} {
		pair, ok := folders[flagName]
		if !ok || pair[0] == pair[1] || pair[1] == "" {
			continue
		}
		a, err1 := filepath.Abs(pair[0])
		b, err2 := filepath.Abs(pair[1])
		if err1 == nil && err2 == nil && a == b {
			continue
		}
		if st, err := os.Stat(pair[0]); err == nil && st.IsDir() {
			found = append(found, StrayPath{Flag: flagName, Default: pair[0], Used: pair[1]})
		}
	}
	return found
}
