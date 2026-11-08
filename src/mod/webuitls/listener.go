package webuitls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// NewSniffListener wraps ln so that TLS connections (first byte 0x16) are
// terminated with cfg and returned from Accept, while plain HTTP connections are
// answered with a 308 redirect to https://<host> and closed.
func NewSniffListener(ln net.Listener, cfg *tls.Config) net.Listener {
	s := &sniffListener{Listener: ln, cfg: cfg, ch: make(chan net.Conn), done: make(chan struct{})}
	go s.loop()
	return s
}

type sniffListener struct {
	net.Listener
	cfg  *tls.Config
	ch   chan net.Conn
	done chan struct{}
	err  error
}

func (s *sniffListener) loop() {
	for {
		c, err := s.Listener.Accept()
		if err != nil {
			s.err = err
			close(s.done)
			return
		}
		go s.handle(c)
	}
}

func (s *sniffListener) Accept() (net.Conn, error) {
	select {
	case c := <-s.ch:
		return c, nil
	case <-s.done:
		return nil, s.err
	}
}

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (s *sniffListener) handle(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	if b[0] == 0x16 {
		select {
		case s.ch <- tls.Server(&peekConn{Conn: c, r: br}, s.cfg):
		case <-s.done:
			c.Close()
		}
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.ReadRequest(br)
	host := ""
	target := "/"
	if err == nil {
		host = req.Host
		target = req.URL.RequestURI()
	}
	if host == "" {
		host = c.LocalAddr().String()
	}
	if !strings.HasPrefix(target, "/") {
		target = "/"
	}
	host, target = sanitize(host), sanitize(target)
	body := "This port serves HTTPS. Use https://" + host + target + "\n"
	fmt.Fprintf(c, "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://%s%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		host, target, len(body), body)
}

// sanitize strips CR/LF to prevent header injection.
func sanitize(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// ServerTLSConfig builds a tls.Config for the web UI.
func ServerTLSConfig(info *CertInfo) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{info.Certificate},
		NextProtos:   []string{"http/1.1"},
	}
}
