package instance

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// Sock is one row of /proc/net/tcp or /proc/net/tcp6.
type Sock struct {
	IP     net.IP
	Port   int
	State  int    // 0x0A = LISTEN
	TxQ    uint64 // for LISTEN sockets: the backlog limit
	RxQ    uint64 // for LISTEN sockets: connections waiting in the accept queue
	Uid    int
	Inode  uint64
	IsIPv6 bool
}

// StateListen is the TCP_LISTEN state number.
const StateListen = 0x0A

// Listening reports a LISTEN socket.
func (s Sock) Listening() bool { return s.State == StateListen }

// QueueFull reports an accept queue that has reached its limit (the kernel then drops or refuses new
// connections). The kernel counts one more than the limit before it refuses, so the comparison is ">=".
func (s Sock) QueueFull() bool { return s.Listening() && s.TxQ > 0 && s.RxQ >= s.TxQ }

// Addr renders "ip:port" ("[::]:443" for IPv6).
func (s Sock) Addr() string { return net.JoinHostPort(s.IP.String(), strconv.Itoa(s.Port)) }

// ParseProcNetTCP parses /proc/net/tcp (ipv6=false) or /proc/net/tcp6 (ipv6=true), skipping bad rows.
func ParseProcNetTCP(text string, ipv6 bool) []Sock {
	var out []Sock
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		ip, port, ok := parseHexAddr(f[1])
		if !ok {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			continue
		}
		q := strings.SplitN(f[4], ":", 2)
		if len(q) != 2 {
			continue
		}
		tx, e1 := strconv.ParseUint(q[0], 16, 64)
		rx, e2 := strconv.ParseUint(q[1], 16, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Sock{IP: ip, Port: port, State: int(st), TxQ: tx, RxQ: rx, Uid: uid, Inode: inode, IsIPv6: ipv6})
	}
	return out
}

// parseHexAddr decodes "0100007F:01BB" (IPv4) or the 32 hex digit IPv6 form. Each 32-bit word is stored
// in host (little endian) byte order.
func parseHexAddr(s string) (net.IP, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return ip, int(port), true
}

// ParseSocketLink extracts the inode from a "/proc/<pid>/fd/N" link target such as "socket:[12345]".
func ParseSocketLink(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	v, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
	return v, err == nil
}

// PortFromListenAddr takes a -port style value (":8000", "127.0.0.1:8000", "8000") and returns the port.
func PortFromListenAddr(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		n, _ := strconv.Atoi(p)
		return n
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(addr, ":"))
	return n
}
