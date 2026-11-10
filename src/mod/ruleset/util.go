package ruleset

import (
	"net"
	"path"
	"strings"
)

func netSplit(hostport string) (string, string, error) { return net.SplitHostPort(hostport) }

// cleanPath implements the http.path normalisation (see NormalizePath)
func cleanPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.IndexByte(p, 0); i >= 0 {
		p = p[:i]
	}
	if strings.IndexByte(p, ';') >= 0 {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			if j := strings.IndexByte(s, ';'); j >= 0 {
				segs[i] = s[:j]
			}
		}
		p = strings.Join(segs, "/")
	}
	return path.Clean("/" + p)
}
