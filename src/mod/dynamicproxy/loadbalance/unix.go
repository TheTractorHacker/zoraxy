package loadbalance

import (
	"errors"
	"path/filepath"
	"strings"
)

/*
	Unix domain socket upstreams (upstream issue #663)

	An upstream origin written as "unix:/run/app/app.sock" is reached with HTTP over
	that socket. TLS options do not apply (the transport is local); WebSocket upgrades
	and the passive uptime monitor are not supported for such upstreams.
*/

const unixPrefix = "unix:"

// maxUnixPathLen is the sun_path limit on Linux (108 incl. NUL); keep a margin for other systems
const maxUnixPathLen = 104

// UnixSocketPath returns the socket path if origin uses the unix: scheme
func UnixSocketPath(origin string) (string, bool) {
	if !strings.HasPrefix(origin, unixPrefix) {
		return "", false
	}
	return strings.TrimPrefix(origin, unixPrefix), true
}

// ValidateUnixSocketPath checks a socket path: absolute, already clean (no "..", no "//",
// no trailing slash), no control characters, within the kernel path length limit.
func ValidateUnixSocketPath(p string) error {
	if p == "" {
		return errors.New("unix socket path is empty")
	}
	if len(p) > maxUnixPathLen {
		return errors.New("unix socket path is too long")
	}
	if !strings.HasPrefix(p, "/") {
		return errors.New("unix socket path must be absolute")
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return errors.New("unix socket path contains control characters")
		}
		if c == '?' || c == '#' || c == '\\' {
			return errors.New("unix socket path contains invalid characters")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return errors.New("unix socket path must not contain . or .. segments")
		}
	}
	if p == "/" || filepath.Clean(p) != p {
		return errors.New("unix socket path must name a file and be normalised (no duplicate or trailing slashes)")
	}
	return nil
}

// IsUnix reports whether the upstream is a unix domain socket upstream
func (u *Upstream) IsUnix() bool {
	_, ok := UnixSocketPath(u.OriginIpOrDomain)
	return ok
}

// validateUnix returns the validation error of a unix upstream, nil for other upstreams
func (u *Upstream) validateUnix() error {
	p, ok := UnixSocketPath(u.OriginIpOrDomain)
	if !ok {
		return nil
	}
	if err := ValidateUnixSocketPath(p); err != nil {
		return err
	}
	if u.RequireTLS {
		return errors.New("a unix socket upstream cannot use TLS")
	}
	if u.ProxyProtocol != 0 || u.ClientCertName != "" || u.H2C {
		return errors.New("PROXY protocol, client certificates and H2C are not supported on unix socket upstreams")
	}
	return nil
}
