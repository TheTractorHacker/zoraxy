package email

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal port-25 style relay that advertises NO AUTH and no STARTTLS.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	cmds []string
	data string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	w := func(s string) { c.Write([]byte(s + "\r\n")) }
	w("220 relay ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		f.mu.Lock()
		f.cmds = append(f.cmds, line)
		f.mu.Unlock()
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w("250-relay")
			w("250 8BITMIME")
		case strings.HasPrefix(up, "DATA"):
			w("354 go")
			var sb strings.Builder
			for {
				l, _ := r.ReadString('\n')
				if l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			f.mu.Lock()
			f.data = sb.String()
			f.mu.Unlock()
			w("250 queued")
		case strings.HasPrefix(up, "QUIT"):
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

// Upstream #518: sending through an unauthenticated relay (port 25) must work and must never try AUTH.
func TestSendEmailWithoutAuthentication(t *testing.T) {
	f := newFakeSMTP(t)
	addr := f.ln.Addr().(*net.TCPAddr)
	s := NewEmailSender("127.0.0.1", addr.Port, "", "", "zoraxy@example.com")
	if err := s.SendEmail("admin@example.com", "hi", "<p>body</p>"); err != nil {
		t.Fatalf("send without auth failed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.HasPrefix(strings.ToUpper(c), "AUTH") {
			t.Fatalf("client attempted AUTH: %v", f.cmds)
		}
	}
	if !strings.Contains(f.data, "Subject: hi") {
		t.Fatalf("message not delivered: %q", f.data)
	}
}

// A username without a password (relays that identify by source IP) must not trigger AUTH either.
func TestSendEmailUsernameOnlyDoesNotAuth(t *testing.T) {
	f := newFakeSMTP(t)
	addr := f.ln.Addr().(*net.TCPAddr)
	s := NewEmailSender("127.0.0.1", addr.Port, "someone", "", "zoraxy@example.com")
	if err := s.SendEmail("admin@example.com", "hi", "x"); err != nil {
		t.Fatal(err)
	}
}
