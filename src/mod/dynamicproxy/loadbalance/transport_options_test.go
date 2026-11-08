package loadbalance

import (
	"crypto/tls"
	"errors"
	"testing"
)

func TestUpstreamTransportOptionValidation(t *testing.T) {
	ok := []*Upstream{
		{OriginIpOrDomain: "a:1"},
		{OriginIpOrDomain: "a:1", ProxyProtocol: 1},
		{OriginIpOrDomain: "a:1", ProxyProtocol: 2},
		{OriginIpOrDomain: "a:1", RequireTLS: true, ClientCertName: "backend-client"},
		{OriginIpOrDomain: "a:1", RequireTLS: true, ClientCertName: "my.cert_2"},
	}
	for i, u := range ok {
		if err := u.ValidateTransportOptions(); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := []*Upstream{
		{ProxyProtocol: 3},
		{ProxyProtocol: -1},
		{RequireTLS: true, ClientCertName: "../etc/passwd"},
		{RequireTLS: true, ClientCertName: "a/b"},
		{RequireTLS: true, ClientCertName: ".hidden"},
		{RequireTLS: true, ClientCertName: "a..b"},
		{RequireTLS: true, ClientCertName: "a\\b"},
		{RequireTLS: false, ClientCertName: "plain-upstream"},
	}
	for i, u := range bad {
		if err := u.ValidateTransportOptions(); err == nil {
			t.Errorf("bad[%d] %+v accepted", i, u.ProxyProtocol)
		}
	}
}

func TestUpstreamClientCertCallback(t *testing.T) {
	old := UpstreamClientCertLoader
	defer func() { UpstreamClientCertLoader = old }()

	if (&Upstream{RequireTLS: true}).clientCertCallback() != nil {
		t.Fatal("callback without a configured name")
	}
	if (&Upstream{ClientCertName: "x"}).clientCertCallback() != nil {
		t.Fatal("callback for a non TLS upstream")
	}
	u := &Upstream{RequireTLS: true, ClientCertName: "x"}
	cb := u.clientCertCallback()
	UpstreamClientCertLoader = nil
	if _, err := cb(nil); err == nil {
		t.Fatal("no loader must be an error")
	}
	var asked string
	UpstreamClientCertLoader = func(name string) (*tls.Certificate, error) { asked = name; return nil, errors.New("nope") }
	if _, err := cb(nil); err == nil || asked != "x" {
		t.Fatalf("loader not consulted: %v %q", err, asked)
	}
}
