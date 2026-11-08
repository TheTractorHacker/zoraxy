package cluster

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveHealth(h *HealthEndpoint, method, remote string, running bool, n int) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://any.host"+HealthPath, nil)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	if !h.Serve(w, r, running, n) {
		w.Code = -1
	}
	return w
}

func TestHealthOKAndUnavailable(t *testing.T) {
	h := NewHealthEndpoint("9.9.9")
	w := serveHealth(h, "GET", "203.0.113.9:1234", true, 4)
	if w.Code != 200 {
		t.Fatalf("running proxy: want 200 got %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" || body["version"] != "9.9.9" || body["proxyRunning"] != true || body["activeEndpoints"] != float64(4) {
		t.Fatalf("unexpected body %v", body)
	}
	if _, ok := body["uptimeSeconds"]; !ok {
		t.Fatal("uptimeSeconds missing")
	}
	if len(body) != 5 {
		t.Fatalf("health must expose exactly 5 fields, got %v", body)
	}

	w = serveHealth(h, "GET", "203.0.113.9:1234", false, 0)
	if w.Code != 503 {
		t.Fatalf("stopped proxy: want 503 got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"unavailable"`) {
		t.Fatalf("body %s", w.Body.String())
	}
	if w := serveHealth(h, "HEAD", "1.2.3.4:5", true, 1); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD must return 200 without body")
	}
	if w := serveHealth(h, "POST", "1.2.3.4:5", true, 1); w.Code != 405 {
		t.Fatalf("POST want 405 got %d", w.Code)
	}
}

func TestHealthAllowListAndDisable(t *testing.T) {
	h := NewHealthEndpoint("1")
	if err := h.Configure([]string{"10.0.0.0/8", "192.168.1.5", "fd00::/8"}, false); err != nil {
		t.Fatal(err)
	}
	cases := map[string]int{
		"10.1.2.3:99":      200,
		"192.168.1.5:99":   200,
		"192.168.1.6:99":   403,
		"203.0.113.1:99":   403,
		"[fd00::1]:99":     200,
		"[2001:db8::1]:99": 403,
		"garbage":          403,
	}
	for remote, want := range cases {
		if got := serveHealth(h, "GET", remote, true, 1).Code; got != want {
			t.Errorf("%s: want %d got %d", remote, want, got)
		}
	}
	if err := h.Configure([]string{"not-an-ip"}, false); err == nil {
		t.Fatal("invalid allow-list accepted")
	}
	// the failed Configure must not have changed anything
	if serveHealth(h, "GET", "203.0.113.1:99", true, 1).Code != 403 {
		t.Fatal("allow list changed by a failed Configure")
	}
	h.Configure(nil, true)
	if serveHealth(h, "GET", "10.1.2.3:99", true, 1).Code != -1 {
		t.Fatal("disabled endpoint must fall through to normal routing")
	}
}

func TestIsHealthRequestExactPathOnly(t *testing.T) {
	for path, want := range map[string]bool{
		HealthPath:                      true,
		"/.zoraxy/captcha/verify":       false,
		"/.well-known/acme-challenge/x": false,
		HealthPath + "/":                false,
		HealthPath + "x":                false,
		"/":                             false,
	} {
		r := &http.Request{URL: httptest.NewRequest("GET", "http://h"+path, nil).URL}
		if IsHealthRequest(r) != want {
			t.Errorf("%s: want %v", path, want)
		}
	}
}
