package loadbalance

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

/*
	Active health checks

	One goroutine per checked upstream, grouped by endpoint. A group is owned by
	the RouteManager: Sync starts / replaces it, Stop and StopAll cancel it and
	wait until every goroutine returned, so nothing leaks across a router
	restart or an endpoint removal.
*/

// healthIntervalUnit is the unit of IntervalSeconds, shortened by tests
var healthIntervalUnit = time.Second

type healthGroup struct {
	sig    string
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// healthSignature identifies the exact work a group is doing, if it is the same nothing needs to restart
func healthSignature(cfg *Config, upstreams []*Upstream) string {
	var b strings.Builder
	for _, u := range upstreams {
		hc, ok := cfg.activeFor(u)
		if !ok {
			continue
		}
		js, _ := json.Marshal(hc)
		fmt.Fprintf(&b, "%p|%s|%t|%t|%s|%s;", u, u.OriginIpOrDomain, u.RequireTLS, u.SkipCertValidations, u.tlsServerName, js)
	}
	return b.String()
}

// SyncHealthChecks makes the running active health checks of the endpoint identified by key
// match the config and upstream list. It is safe and cheap to call often
func (m *RouteManager) SyncHealthChecks(key string, cfg *Config, upstreams []*Upstream) {
	sig := healthSignature(cfg, upstreams)

	m.hcMu.Lock()
	defer m.hcMu.Unlock()
	if old, ok := m.hcGroups[key]; ok {
		if old.sig == sig {
			return
		}
		m.stopGroupLocked(key, old)
	}

	//Upstreams without checks must not stay marked unhealthy by an earlier config
	for _, u := range upstreams {
		if _, ok := cfg.activeFor(u); !ok {
			u.resetActive()
		}
	}
	if sig == "" {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &healthGroup{sig: sig, cancel: cancel}
	for _, u := range upstreams {
		hc, ok := cfg.activeFor(u)
		if !ok {
			continue
		}
		g.wg.Add(1)
		go func(u *Upstream, hc ActiveHealthCheck) {
			defer g.wg.Done()
			m.runHealthCheck(ctx, u, hc)
		}(u, hc)
	}
	if m.hcGroups == nil {
		m.hcGroups = map[string]*healthGroup{}
	}
	m.hcGroups[key] = g
}

func (m *RouteManager) stopGroupLocked(key string, g *healthGroup) {
	g.cancel()
	g.wg.Wait()
	delete(m.hcGroups, key)
}

// StopHealthChecks stops the active health checks of one endpoint and waits for them to end
func (m *RouteManager) StopHealthChecks(key string) {
	if m == nil {
		return
	}
	m.hcMu.Lock()
	defer m.hcMu.Unlock()
	if g, ok := m.hcGroups[key]; ok {
		m.stopGroupLocked(key, g)
	}
}

// StopAllHealthChecks stops every active health check and waits for them to end
func (m *RouteManager) StopAllHealthChecks() {
	m.hcMu.Lock()
	defer m.hcMu.Unlock()
	for key, g := range m.hcGroups {
		m.stopGroupLocked(key, g)
	}
}

// HealthCheckGroupCount returns the number of endpoints with running health checks (for tests and diagnostics)
func (m *RouteManager) HealthCheckGroupCount() int {
	m.hcMu.Lock()
	defer m.hcMu.Unlock()
	return len(m.hcGroups)
}

// runHealthCheck probes one upstream until ctx is canceled
func (m *RouteManager) runHealthCheck(ctx context.Context, u *Upstream, hc ActiveHealthCheck) {
	prober := newProber(u, hc)
	defer prober.close()

	interval := time.Duration(hc.IntervalSeconds) * healthIntervalUnit
	timer := time.NewTimer(0) //First probe right away
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		err := prober.probe(ctx)
		if ctx.Err() != nil {
			return //Canceled mid probe, the result is meaningless
		}
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		if u.reportActive(hc, err == nil, errText, m.now()) {
			state := "healthy"
			if err != nil {
				state = "unhealthy (" + errText + ")"
			}
			m.println("Upstream "+u.OriginIpOrDomain+" is now "+state, nil)
		}
		timer.Reset(interval)
	}
}

type prober struct {
	u      *Upstream
	hc     ActiveHealthCheck
	client *http.Client
}

func newProber(u *Upstream, hc ActiveHealthCheck) *prober {
	p := &prober{u: u, hc: hc}
	if hc.Mode != "tcp" {
		//Same TLS rules as the proxied traffic: skip verify flag and SNI override
		tlsCfg := &tls.Config{InsecureSkipVerify: u.SkipCertValidations, ServerName: u.tlsServerName}
		if cb := u.clientCertCallback(); cb != nil {
			tlsCfg.GetClientCertificate = cb //upstream mTLS, same as the proxied traffic
		}
		tr := &http.Transport{
			TLSClientConfig:   tlsCfg,
			DisableKeepAlives: true, //No idle connection goroutines to leak
			Proxy:             nil,
		}
		if u.ProxyProtocol == 1 || u.ProxyProtocol == 2 {
			//Upstreams that require a PROXY header would drop probes without one
			tr.DialContext = dpcore.ProxyProtocolDialer((&net.Dialer{}).DialContext, u.ProxyProtocol)
		}
		p.client = &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return p
}

func (p *prober) close() {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
}

// trimmedOrigin strips scheme and trailing slash from the configured origin
func trimmedOrigin(origin string) string {
	origin = strings.TrimPrefix(origin, "http://")
	origin = strings.TrimPrefix(origin, "https://")
	return strings.TrimRight(origin, "/")
}

// tcpAddress returns host:port of the upstream, adding the scheme default port if missing
func (u *Upstream) tcpAddress() string {
	hostport := trimmedOrigin(u.OriginIpOrDomain)
	if i := strings.Index(hostport, "/"); i >= 0 {
		hostport = hostport[:i]
	}
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	hostport = strings.Trim(hostport, "[]")
	if u.RequireTLS {
		return net.JoinHostPort(hostport, "443")
	}
	return net.JoinHostPort(hostport, "80")
}

// probe runs a single check. nil means healthy
func (p *prober) probe(ctx context.Context) error {
	timeout := time.Duration(p.hc.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if p.hc.Mode == "tcp" {
		dial := (&net.Dialer{}).DialContext
		if p.u.ProxyProtocol == 1 || p.u.ProxyProtocol == 2 {
			dial = dpcore.ProxyProtocolDialer(dial, p.u.ProxyProtocol)
		}
		conn, err := dial(ctx, "tcp", p.u.tcpAddress())
		if err != nil {
			return err
		}
		return conn.Close()
	}

	scheme := "http://"
	if p.u.RequireTLS {
		scheme = "https://"
	}
	req, err := http.NewRequestWithContext(ctx, p.hc.Method, scheme+trimmedOrigin(p.u.OriginIpOrDomain)+p.hc.Path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Zoraxy-HealthCheck")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < p.hc.ExpectedStatusMin || resp.StatusCode > p.hc.ExpectedStatusMax {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if p.hc.BodyContains != "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if !strings.Contains(string(body), p.hc.BodyContains) {
			return errors.New("response body does not contain the expected text")
		}
	}
	return nil
}
