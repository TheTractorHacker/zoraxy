package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// runH2C talks prior-knowledge cleartext HTTP/2 to url. It runs a unary call (reads trailers) and a
// full-duplex streaming call (writes a chunk, must read its echo before writing the next).
func runH2C(url, sni string) {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni},
		AllowHTTP:       strings.HasPrefix(url, "http://"),
	}
	if strings.HasPrefix(url, "http://") {
		tr.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	cl := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	out := map[string]any{}

	req, _ := http.NewRequest("POST", url+"/e2e.Svc/Unary", bytes.NewReader([]byte{0, 0, 0, 0, 3, 'a', 'b', 'c'}))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Host = sni
	resp, err := cl.Do(req)
	if err != nil {
		out["error"] = "unary: " + err.Error()
		report(out)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	out["unary_status"] = resp.StatusCode
	out["unary_proto"] = resp.ProtoMajor
	out["unary_body"] = string(body)
	out["trailer_grpc_status"] = resp.Trailer.Get("Grpc-Status")
	out["trailer_grpc_message"] = resp.Trailer.Get("Grpc-Message")

	pr, pw := io.Pipe()
	req2, _ := http.NewRequest("POST", url+"/e2e.Svc/Bidi", pr)
	req2.Header.Set("Content-Type", "application/grpc")
	req2.Host = sni
	resp2, err := cl.Do(req2)
	if err != nil {
		out["error"] = "bidi: " + err.Error()
		report(out)
		return
	}
	var echoes []string
	buf := make([]byte, 256)
	for _, m := range []string{"one", "two", "three"} {
		pw.Write([]byte(m))
		n, err := resp2.Body.Read(buf)
		if err != nil && n == 0 {
			out["bidi_error"] = err.Error()
			break
		}
		echoes = append(echoes, strings.TrimSpace(string(buf[:n])))
	}
	pw.Close()
	io.Copy(io.Discard, resp2.Body)
	out["bidi_echoes"] = echoes
	out["bidi_trailer_grpc_status"] = resp2.Trailer.Get("Grpc-Status")
	report(out)
}
