package zrok

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

/*
	args.go

	Strict argument construction for the zrok CLI. No shell is ever involved (exec with an argument vector), every value that
	ends up in the vector is validated against a whitelist and may never start with "-" so it cannot be read as an option.

	Two CLI generations exist and differ in a few options:
	  v1 (binary "zrok"):  share public <target> --frontend F ; reserve public|private <target> --unique-name N ; share reserved <N>
	  v2 (binary "zrok2"): share public <target> --name-selection S (names replace reserved shares)
	  both:                enable <token> --headless, share private <target>, access private <token> --bind, config set apiEndpoint
	The flags used here were taken from the zrok source (v1.1.11 and v2.0.9); they could not be exercised against a live zrok service.
*/

const (
	FlavorAuto = "auto"
	FlavorV1   = "v1"
	FlavorV2   = "v2"

	KindSharePublic  = "share-public"
	KindSharePrivate = "share-private"
	KindAccess       = "access"

	BackendProxy = "proxy"
	BackendTCP   = "tcpTunnel"
	BackendUDP   = "udpTunnel"
)

var (
	nameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$`)
	uniqueRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{2,30}[a-z0-9]$`)
	frontendRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$`)
	tokenRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\-]{3,63}$`)
	accountRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\-]{5,127}$`)
	hostLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$`)
	binaryRe    = regexp.MustCompile(`^zrok[0-9A-Za-z._\-]*$`)
)

// Tunnel is one managed zrok share or access
type Tunnel struct {
	ID          string
	Name        string
	Kind        string //share-public, share-private, access
	Target      string //share: backend, "host:port" or "http(s)://host:port[/path]"
	BackendMode string //share: proxy (default), tcpTunnel, udpTunnel (private shares only)
	Frontend    string `json:",omitempty"` //public share: v1 --frontend / v2 --name-selection
	UniqueName  string `json:",omitempty"` //v1: reserved share name (reserve + share reserved). v2: ignored (use Frontend "namespace:name")
	Insecure    bool   `json:",omitempty"` //Do not verify the TLS certificate of the backend (self-signed Zoraxy listener)
	ShareToken  string `json:",omitempty"` //access: token of the private share to bind
	Bind        string `json:",omitempty"` //access: local bind address, default 127.0.0.1:9191
	AutoStart   bool
}

func validHost(h string) bool {
	if h == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return !ip.IsMulticast() && !ip.IsUnspecified()
	}
	if len(h) > 253 || h == "" {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

func validHostPort(s string) (string, bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil || !validHost(h) {
		return "", false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return s, true
}

// validateTarget accepts host:port or http(s)://host:port[/path] and returns the normalised target
func validateTarget(kind, mode, target string) (string, error) {
	if target == "" || len(target) > 300 || target[0] == '-' || strings.ContainsAny(target, " \t\r\n\x00\\'\"`$;&|<>()*?!{}") {
		return "", errors.New("invalid target")
	}
	if mode == BackendTCP || mode == BackendUDP {
		if _, ok := validHostPort(target); !ok {
			return "", errors.New("tunnel target must be host:port")
		}
		return target, nil
	}
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("target must be host:port or http(s)://host:port[/path] (no credentials, query or fragment)")
		}
		hp := u.Host
		if u.Port() == "" {
			if !validHost(strings.Trim(hp, "[]")) {
				return "", errors.New("invalid target host")
			}
			return target, nil
		}
		if _, ok := validHostPort(hp); !ok {
			return "", errors.New("invalid target host or port")
		}
		return target, nil
	}
	if _, ok := validHostPort(target); !ok {
		return "", errors.New("target must be host:port or http(s)://host:port[/path]")
	}
	return target, nil
}

// Validate checks a tunnel definition. flavor is the resolved CLI generation.
func (t *Tunnel) Validate(flavor string) error {
	if !nameRe.MatchString(t.Name) {
		return errors.New("name must be 1-64 characters: letters, digits, space, dot, dash, underscore")
	}
	switch t.Kind {
	case KindSharePublic, KindSharePrivate:
		mode := t.BackendMode
		if mode == "" {
			mode = BackendProxy
		}
		switch mode {
		case BackendProxy:
		case BackendTCP, BackendUDP:
			if t.Kind == KindSharePublic {
				return errors.New("tcpTunnel / udpTunnel backends are only available for private shares")
			}
		default:
			return errors.New("backend mode must be proxy, tcpTunnel or udpTunnel (file based backends are not offered)")
		}
		if _, err := validateTarget(t.Kind, mode, t.Target); err != nil {
			return err
		}
		if t.Frontend != "" && (t.Kind != KindSharePublic || !frontendRe.MatchString(t.Frontend)) {
			return errors.New("invalid frontend selection (public shares only)")
		}
		if t.UniqueName != "" {
			if !uniqueRe.MatchString(t.UniqueName) {
				return errors.New("reserved name must be 4-32 characters: lower case letters, digits, dash")
			}
			if flavor == FlavorV2 {
				return errors.New("reserved shares do not exist in zrok v2: select a name through the frontend field (namespace:name)")
			}
		}
		if t.ShareToken != "" || t.Bind != "" {
			return errors.New("share token and bind address only apply to access entries")
		}
	case KindAccess:
		if !tokenRe.MatchString(t.ShareToken) {
			return errors.New("share token must be 4-64 characters: letters, digits, dash, underscore")
		}
		bind := t.Bind
		if bind == "" {
			bind = "127.0.0.1:9191"
		}
		if _, ok := validHostPort(bind); !ok {
			return errors.New("bind must be host:port")
		}
		if t.Target != "" || t.Frontend != "" || t.UniqueName != "" || t.BackendMode != "" {
			return errors.New("target, frontend, reserved name and backend mode only apply to shares")
		}
	default:
		return errors.New("kind must be share-public, share-private or access")
	}
	return nil
}

// buildRunArgs returns the argument vector of the long running process of a tunnel
func buildRunArgs(flavor string, t *Tunnel) ([]string, error) {
	if err := t.Validate(flavor); err != nil {
		return nil, err
	}
	mode := t.BackendMode
	if mode == "" {
		mode = BackendProxy
	}
	switch t.Kind {
	case KindAccess:
		bind := t.Bind
		if bind == "" {
			bind = "127.0.0.1:9191"
		}
		return []string{"access", "private", t.ShareToken, "--headless", "--bind", bind}, nil
	case KindSharePrivate:
		args := []string{"share", "private", "--headless", "--backend-mode", mode}
		if t.Insecure {
			args = append(args, "--insecure")
		}
		if t.UniqueName != "" {
			return []string{"share", "reserved", t.UniqueName, "--headless"}, nil
		}
		return append(args, "--", t.Target), nil
	case KindSharePublic:
		if flavor == FlavorV1 && t.UniqueName != "" {
			return []string{"share", "reserved", t.UniqueName, "--headless"}, nil
		}
		args := []string{"share", "public", "--headless", "--backend-mode", mode}
		if t.Frontend != "" {
			if flavor == FlavorV2 {
				args = append(args, "--name-selection", t.Frontend)
			} else {
				args = append(args, "--frontend", t.Frontend)
			}
		}
		if t.Insecure {
			args = append(args, "--insecure")
		}
		return append(args, "--", t.Target), nil
	}
	return nil, errors.New("unknown kind")
}

// buildReserveArgs returns the one-shot "reserve" command (v1 only, shares with a unique name), or nil
func buildReserveArgs(flavor string, t *Tunnel) []string {
	if flavor != FlavorV1 || t.UniqueName == "" || t.Kind == KindAccess {
		return nil
	}
	mode := t.BackendMode
	if mode == "" {
		mode = BackendProxy
	}
	vis := "private"
	args := []string{"reserve"}
	if t.Kind == KindSharePublic {
		vis = "public"
	}
	args = append(args, vis, "--unique-name", t.UniqueName, "--backend-mode", mode)
	if t.Kind == KindSharePublic && t.Frontend != "" {
		args = append(args, "--frontend", t.Frontend)
	}
	return append(args, "--", t.Target)
}

// ValidateAPIEndpoint checks the zrok API endpoint (https, or http for loopback / private hosts), no credentials
func ValidateAPIEndpoint(ep string) error {
	if ep == "" {
		return nil
	}
	u, err := url.Parse(ep)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("API endpoint must be https://host[:port] (http only for local test instances)")
	}
	if len(ep) > 300 || strings.ContainsAny(ep, " \t\r\n\x00'\"`$;&|<>\\") || ep[0] == '-' {
		return errors.New("invalid API endpoint")
	}
	if !validHost(u.Hostname()) {
		return errors.New("invalid API endpoint host")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return errors.New("API endpoint must not be a link-local / metadata address")
	}
	if u.Scheme == "http" {
		if ip, err := netip.ParseAddr(u.Hostname()); !(u.Hostname() == "localhost" || (err == nil && (ip.IsLoopback() || ip.IsPrivate()))) {
			return errors.New("plain http API endpoints are only accepted for localhost and private addresses")
		}
	}
	return nil
}

// ValidateAccountToken checks the shape of the account token (never echoed back in errors)
func ValidateAccountToken(tok string) error {
	if !accountRe.MatchString(tok) {
		return errors.New("account token has an unexpected format (letters, digits, dash, underscore; 6-128 characters)")
	}
	return nil
}

// ValidateBinary checks a configured binary path: an absolute path or a bare name, whose file name starts with "zrok"
func ValidateBinary(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > 400 || strings.ContainsAny(p, "\x00\r\n") {
		return errors.New("invalid binary path")
	}
	if !binaryRe.MatchString(strings.TrimSuffix(filepath.Base(p), ".exe")) {
		return fmt.Errorf("the binary file name must start with \"zrok\" (for example zrok, zrok2, zrok.exe)")
	}
	if strings.ContainsAny(p, `/\`) && !filepath.IsAbs(p) {
		return errors.New("a binary path must be absolute (or just the file name to search in PATH)")
	}
	return nil
}

// FlavorFor resolves auto detection from the binary name
func FlavorFor(setting, bin string) string {
	switch setting {
	case FlavorV1, FlavorV2:
		return setting
	}
	if strings.HasPrefix(strings.TrimSuffix(filepath.Base(bin), ".exe"), "zrok2") {
		return FlavorV2
	}
	return FlavorV1
}
