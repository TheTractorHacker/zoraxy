package dynamicproxy

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

func TestUnixSocketUpstreamServesThroughProxyHandler(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets unavailable: ", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Host", r.Host)
		w.Write([]byte("uds:" + r.URL.Path))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	router, _ := newOpsTestRouter(t, "unix:"+sock)
	w := serveOps(router, "GET", "/hello", nil)
	if w.Code != 200 || w.Body.String() != "uds:/hello" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Host") != "app.example.com" {
		t.Fatalf("original host not preserved: %q", w.Header().Get("X-Host"))
	}
}

func TestUnixSocketPathValidation(t *testing.T) {
	bad := []string{"", "relative.sock", "/run/../etc/x.sock", "/run//x.sock", "/run/x.sock/", "/", "/run/a\x00b", "/run/x?y", "/./x", "/run/x\n"}
	for _, p := range bad {
		if loadbalance.ValidateUnixSocketPath(p) == nil {
			t.Errorf("%q must be rejected", p)
		}
	}
	if err := loadbalance.ValidateUnixSocketPath("/run/app/app.sock"); err != nil {
		t.Error(err)
	}
	u := &loadbalance.Upstream{OriginIpOrDomain: "unix:/run/x.sock", RequireTLS: true}
	if u.ValidateTransportOptions() == nil {
		t.Error("TLS on unix must be rejected")
	}
	u = &loadbalance.Upstream{OriginIpOrDomain: "unix:/run/../x.sock"}
	if u.ValidateTransportOptions() == nil {
		t.Error("traversal must be rejected")
	}
}

func TestUnixSocketUpstreamDownGives521(t *testing.T) {
	router, _ := newOpsTestRouter(t, "unix:"+filepath.Join(t.TempDir(), "missing.sock"))
	if w := serveOps(router, "GET", "/", nil); w.Code != 521 {
		t.Fatalf("got %d", w.Code)
	}
}
