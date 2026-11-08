package websocketproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// Skipping certificate verification for one upstream must not switch it off for every other WebSocket upstream:
// the shared websocket.DefaultDialer may not be modified (upstream #974 audit).
func TestSkipTLSValidationDoesNotPoisonDefaultDialer(t *testing.T) {
	up := websocket.Upgrader{}
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err == nil {
			c.Close()
		}
	}))
	defer backend.Close()

	u, _ := url.Parse("wss://" + strings.TrimPrefix(backend.URL, "https://"))
	proxy := httptest.NewServer(NewProxy(u, Options{SkipTLSValidation: true, SkipOriginCheck: true}))
	defer proxy.Close()

	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http"), nil)
	if err != nil {
		t.Fatalf("proxy to self signed upstream with skip verify failed: %v", err)
	}
	c.Close()

	if websocket.DefaultDialer.TLSClientConfig != nil {
		t.Fatal("websocket.DefaultDialer was modified: certificate verification is now off for every upstream")
	}
}
