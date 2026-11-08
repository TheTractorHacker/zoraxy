package websocketproxy

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
)

func TestProxy(t *testing.T) {
	// websocket proxy
	supportedSubProtocols := []string{"test-protocol"}
	upgrader := &websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		Subprotocols: supportedSubProtocols,
	}

	// Both servers listen on ephemeral loopback ports so the test never
	// collides with other processes or parallel test runs.
	frontendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	frontendHost := frontendListener.Addr().String()
	serverURL := "ws://" + frontendHost
	backendURL := "ws://" + backendListener.Addr().String()

	u, _ := url.Parse(backendURL)
	proxy := NewProxy(u, Options{
		SkipTLSValidation: false,
		SkipOriginCheck:   false,
		Logger:            nil,
	})
	proxy.Upgrader = upgrader

	mux := http.NewServeMux()
	mux.Handle("/proxy", proxy)
	frontend := &http.Server{Handler: mux}
	go frontend.Serve(frontendListener)
	defer frontend.Close()

	// backend echo server
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Don't upgrade if original host header isn't preserved
		if r.Host != frontendHost {
			log.Printf("Host header set incorrectly.  Expecting %s got %s", frontendHost, r.Host)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}

		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}

		if err = conn.WriteMessage(messageType, p); err != nil {
			return
		}
	})
	backend := &http.Server{Handler: mux2}
	go backend.Serve(backendListener)
	defer backend.Close()

	// let's us define two subprotocols, only one is supported by the server
	clientSubProtocols := []string{"test-protocol", "test-notsupported"}
	h := http.Header{}
	for _, subprot := range clientSubProtocols {
		h.Add("Sec-WebSocket-Protocol", subprot)
	}

	// frontend server, dial now our proxy, which will reverse proxy our
	// message to the backend websocket server.
	conn, resp, err := websocket.DefaultDialer.Dial(serverURL+"/proxy", h)
	if err != nil {
		t.Fatal(err)
	}

	// check if the server really accepted only the first one
	in := func(desired string) bool {
		for _, prot := range resp.Header[http.CanonicalHeaderKey("Sec-WebSocket-Protocol")] {
			if desired == prot {
				return true
			}
		}
		return false
	}

	if !in("test-protocol") {
		t.Error("test-protocol should be available")
	}

	if in("test-notsupported") {
		t.Error("test-notsupported should be not recevied from the server.")
	}

	// now write a message and send it to the backend server (which goes trough
	// proxy..)
	msg := "hello kite"
	err = conn.WriteMessage(websocket.TextMessage, []byte(msg))
	if err != nil {
		t.Error(err)
	}

	messageType, p, err := conn.ReadMessage()
	if err != nil {
		t.Error(err)
	}

	if messageType != websocket.TextMessage {
		t.Error("incoming message type is not Text")
	}

	if msg != string(p) {
		t.Errorf("expecting: %s, got: %s", msg, string(p))
	}
}
