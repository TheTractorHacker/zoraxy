package main

import (
	"net"
	"strings"
	"testing"
)

func TestValidateProxyListenPort(t *testing.T) {
	for _, p := range []int{0, -5, 65536, 99999} {
		if err := validateProxyListenPort(p); err == nil || !strings.Contains(err.Error(), "Invalid incoming port value") {
			t.Fatalf("port %d: want the invalid port error, got %v", p, err)
		}
	}
	old := *webUIPort
	defer func() { *webUIPort = old }()
	*webUIPort = ":29240"
	if err := validateProxyListenPort(29240); err == nil || !strings.Contains(err.Error(), "management interface") {
		t.Fatalf("the management port must be refused, got %v", err)
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	free := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if err := validateProxyListenPort(free); err != nil {
		t.Fatalf("a free port must be accepted: %v", err)
	}
}
