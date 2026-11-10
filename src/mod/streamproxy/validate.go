package streamproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

/*
	Validation of the stream proxy form values (admin API). The relay itself accepts anything
	and fails when it starts; the API refuses a config that could never run.
*/

const maxStreamNameLength = 100

var streamHostLabelRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$`)

func validStreamHost(h string) bool {
	if h == "localhost" {
		return true
	}
	if _, err := netip.ParseAddr(strings.Split(h, "%")[0]); err == nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if len(l) > 63 || !streamHostLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidateAddress checks a "host:port" address. The host may be empty (all interfaces) only when allowEmptyHost is set.
func ValidateAddress(addr string, allowEmptyHost bool) (host string, port int, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, errors.New("address cannot be empty")
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return "", 0, fmt.Errorf("%q is not a valid address, use host:port (for example 0.0.0.0:2222)", addr)
	}
	if host == "" && !allowEmptyHost {
		return "", 0, fmt.Errorf("%q needs a host name or IP address before the port", addr)
	}
	if host != "" && !validStreamHost(host) {
		return "", 0, fmt.Errorf("%q is not a valid host name or IP address", host)
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("the port in %q must be a number from 1 to 65535", addr)
	}
	return host, port, nil
}

// validateAddresses checks the listening and the target address of a config
func validateAddresses(listen, target string) (listenPort int, err error) {
	_, listenPort, err = ValidateAddress(listen, true)
	if err != nil {
		return 0, errors.New("listening address: " + err.Error())
	}
	if _, _, err := ValidateAddress(target, false); err != nil {
		return 0, errors.New("target address: " + err.Error())
	}
	return listenPort, nil
}

// portOf returns the port of an address, 0 when it has none
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// validateConfig checks a whole config. selfUUID is the config being edited (excluded from the duplicate checks).
// When editing, an address that was not changed is not checked again (a stored legacy value must not block an unrelated edit).
func (m *Manager) validateConfig(selfUUID, name, listen, target string, useTCP, useUDP bool, keepListen, keepTarget bool) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name cannot be empty")
	}
	if len([]rune(name)) > maxStreamNameLength {
		return fmt.Errorf("name is too long (%d characters at most)", maxStreamNameLength)
	}
	if !useTCP && !useUDP {
		return errors.New("enable TCP, UDP or both")
	}
	listenPort := portOf(listen)
	if !keepListen {
		if _, p, err := ValidateAddress(listen, true); err != nil {
			return errors.New("listening address: " + err.Error())
		} else {
			listenPort = p
		}
	}
	if !keepTarget {
		if _, _, err := ValidateAddress(target, false); err != nil {
			return errors.New("target address: " + err.Error())
		}
	}
	for _, c := range m.Configs {
		if c.UUID == selfUUID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(c.Name), strings.TrimSpace(name)) {
			return errors.New("a config named " + strings.TrimSpace(name) + " already exists")
		}
		_, p, perr := net.SplitHostPort(c.ListeningAddress)
		if perr == nil && p == strconv.Itoa(listenPort) && ((useTCP && c.UseTCP) || (useUDP && c.UseUDP)) {
			return fmt.Errorf("port %d is already used by %q", listenPort, c.Name)
		}
	}
	return nil
}
