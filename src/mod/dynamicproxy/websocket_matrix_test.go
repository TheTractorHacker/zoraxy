package dynamicproxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

// Upstream #974: WebSocket towards HTTP and HTTPS (self signed) upstreams. "wss to an HTTP upstream" is not a
// thing: the upstream scheme follows the upstream's "Require TLS" option while the client side may be ws or wss.
func TestWebSocketUpstreamMatrix(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, m, err := c.ReadMessage()
			if err != nil {
				return
			}
			c.WriteMessage(mt, m)
		}
	})
	plain := httptest.NewServer(echo)
	defer plain.Close()
	secure := httptest.NewTLSServer(echo) // self signed certificate
	defer secure.Close()

	cases := []struct {
		name     string
		origin   string // upstream address
		tls, skp bool
		wantOK   bool
	}{
		{"http upstream", strings.TrimPrefix(plain.URL, "http://"), false, false, true},
		{"https upstream with skip verify", strings.TrimPrefix(secure.URL, "https://"), true, true, true},
		{"https upstream, self signed, verification on", strings.TrimPrefix(secure.URL, "https://"), true, false, false},
		{"https upstream configured as plain http", strings.TrimPrefix(secure.URL, "https://"), false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			router, sep, _ := newNonTLSTestRouter(t)
			router.pluginRouteHook = nil
			router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: router.Option.Logger})
			sep.ProxyType = ProxyTypeHost
			sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: c.origin, RequireTLS: c.tls, SkipCertValidations: c.skp, Weight: 1}}
			prepared, err := router.PrepareProxyRoute(sep)
			if err != nil {
				t.Fatal(err)
			}
			prepared.parent = router
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				router.handleNonTLSRequest(w, r, prepared)
			}))
			defer proxy.Close()

			d := websocket.Dialer{HandshakeTimeout: 3 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			conn, resp, err := d.Dial("ws"+strings.TrimPrefix(proxy.URL, "http"), http.Header{"Origin": {proxy.URL}})
			if !c.wantOK {
				if err == nil {
					conn.Close()
					t.Fatal("expected the WebSocket upgrade to fail")
				}
				return
			}
			if err != nil {
				code := 0
				if resp != nil {
					code = resp.StatusCode
				}
				t.Fatalf("dial failed (status %d): %v", code, err)
			}
			defer conn.Close()
			conn.UnderlyingConn().SetDeadline(time.Now().Add(3 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
				t.Fatal(err)
			}
			_, m, err := conn.ReadMessage()
			if err != nil || string(m) != "hello" {
				t.Fatalf("echo failed: %q %v", m, err)
			}
		})
	}
}
