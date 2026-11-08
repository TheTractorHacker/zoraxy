package ech

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestQUICECHSupport asserts that the pinned quic-go / crypto/tls pair accepts ECH on HTTP/3.
// The result is documented in DEVELOPMENT.md.
func TestQUICECHSupport(t *testing.T) {
	m := newMgr(t, true)
	cert, pool := testCert(t, pubName, innerName)
	cfg := &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }}
	m.Apply(cfg)
	l, err := quic.ListenAddr("127.0.0.1:0", cfg, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			if _, err := l.Accept(context.Background()); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, l.Addr().String(), &tls.Config{ServerName: innerName, RootCAs: pool, NextProtos: []string{"h3"},
		EncryptedClientHelloConfigList: listOf(t, m)}, &quic.Config{})
	if err != nil {
		t.Fatalf("QUIC dial with ECH: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if !conn.ConnectionState().TLS.ECHAccepted {
		t.Fatal("ECH was not accepted over QUIC; the HTTP/3 documentation must be updated")
	}
}
