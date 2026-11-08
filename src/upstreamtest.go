package main

/*
	upstreamtest.go

	Read only connection test used by the "New proxy rule" dialog.

	GET /api/proxy/testupstream?url=HOST[:PORT][/path]   (an http:// or https:// prefix is accepted and used as a hint)
	  -> {"ok":bool,"protocol":"http|https|","status":int,"selfsign":bool,"latencyMs":int,"address":"host:port","error":"..."}

	It dials the address, works out whether the upstream speaks TLS, whether its certificate verifies, and what a plain
	GET answers. Nothing is stored. A unix: socket address is only checked for existence and connectability.
*/

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

type upstreamTestResult struct {
	OK        bool   `json:"ok"`
	Protocol  string `json:"protocol"`
	Status    int    `json:"status"`
	SelfSign  bool   `json:"selfsign"`
	LatencyMs int64  `json:"latencyMs"`
	Address   string `json:"address"`
	Error     string `json:"error,omitempty"`
}

const upstreamTestTimeout = 4 * time.Second

// splitUpstreamTarget splits user input into a dial address (host:port), a request path and a protocol hint
func splitUpstreamTarget(raw string) (addr string, path string, hint string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", errors.New("no address given")
	}
	switch {
	case strings.HasPrefix(strings.ToLower(raw), "https://"):
		hint, raw = "https", raw[len("https://"):]
	case strings.HasPrefix(strings.ToLower(raw), "http://"):
		hint, raw = "http", raw[len("http://"):]
	}
	u, perr := url.Parse("//" + raw)
	if perr != nil || u.Hostname() == "" {
		return "", "", "", errors.New("invalid address")
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		if hint == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path = u.RequestURI()
	if path == "" {
		path = "/"
	}
	return net.JoinHostPort(host, port), path, hint, nil
}

// testUpstream probes one upstream address
func testUpstream(raw string) upstreamTestResult {
	start := time.Now()
	res := upstreamTestResult{}

	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "unix:") {
		sock := strings.TrimSpace(raw)[len("unix:"):]
		res.Address = "unix:" + sock
		c, err := net.DialTimeout("unix", sock, upstreamTestTimeout)
		res.LatencyMs = time.Since(start).Milliseconds()
		if err != nil {
			res.Error = "cannot connect to the socket: " + err.Error()
			return res
		}
		c.Close()
		res.OK, res.Protocol = true, "http"
		return res
	}

	addr, path, hint, err := splitUpstreamTarget(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Address = addr

	// 1. can we connect at all
	c, err := net.DialTimeout("tcp", addr, upstreamTestTimeout)
	if err != nil {
		res.LatencyMs = time.Since(start).Milliseconds()
		res.Error = "cannot connect: " + shortNetErr(err)
		return res
	}
	c.Close()
	res.LatencyMs = time.Since(start).Milliseconds()

	host, _, _ := net.SplitHostPort(addr)
	// 2. does it speak TLS (unless the user said plain http)
	if hint != "http" {
		d := &net.Dialer{Timeout: upstreamTestTimeout}
		tc, terr := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if terr == nil {
			tc.Close()
			res.Protocol = "https"
			// does the certificate verify
			vc, verr := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host})
			if verr != nil {
				res.SelfSign = true
			} else {
				vc.Close()
			}
		}
	}
	if res.Protocol == "" {
		res.Protocol = "http"
	}

	// 3. what does a GET answer (certificate errors are not an issue for a reachability test)
	client := &http.Client{
		Timeout:       upstreamTestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true},
	}
	t0 := time.Now()
	resp, err := client.Get(res.Protocol + "://" + addr + path)
	if err != nil {
		if res.Protocol == "http" {
			res.OK = true // the port accepts connections; it may just not speak HTTP the way a browser does
			res.Error = "connected, but the HTTP request failed: " + shortNetErr(err)
		} else {
			res.Error = "TLS connected, but the HTTPS request failed: " + shortNetErr(err)
		}
		return res
	}
	resp.Body.Close()
	res.OK = true
	res.Status = resp.StatusCode
	res.LatencyMs = time.Since(t0).Milliseconds()
	return res
}

func shortNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func HandleTestUpstream(w http.ResponseWriter, r *http.Request) {
	target, err := utils.GetPara(r, "url")
	if err != nil {
		utils.SendErrorResponse(w, "url is required")
		return
	}
	js, _ := json.Marshal(testUpstream(target))
	utils.SendJSONResponse(w, string(js))
}
