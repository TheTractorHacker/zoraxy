package loadbalance

import (
	"net/http"
	"testing"
)

// Upstream #1343: the per-upstream option reaches the transport, default keeps pooling.
func TestStartProxyDisableKeepAlive(t *testing.T) {
	for _, want := range []bool{false, true} {
		u := &Upstream{OriginIpOrDomain: "127.0.0.1:1", DisableKeepAlive: want}
		if err := u.StartProxy(""); err != nil {
			t.Fatal(err)
		}
		tr := u.proxy.Transport.(*http.Transport)
		if tr.DisableKeepAlives != want {
			t.Errorf("DisableKeepAlive=%v: transport DisableKeepAlives=%v", want, tr.DisableKeepAlives)
		}
	}
}
