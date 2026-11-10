package forwardproxy

import (
	"net"
	"testing"
)

func TestUpdatePortRefusesInvalidAndOccupiedPorts(t *testing.T) {
	h := &Handler{Port: 1}
	for _, p := range []int{0, -1, 99999} {
		if err := h.UpdatePort(p); err == nil {
			t.Fatalf("port %d must be refused", p)
		}
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	if err := h.UpdatePort(busy); err == nil {
		t.Fatalf("occupied port %d must be refused", busy)
	}
	if h.Port != 1 {
		t.Fatalf("a refused port change must keep the old port, got %d", h.Port)
	}
}
