package dynamicproxy

/*
	httplistenaddr.go

	Configurable address for the optional plain-HTTP listener (the one that is
	"port 80" by default). An empty HttpListenAddr keeps the historic ":80".
*/

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultHttpListenAddr is the plain HTTP listener address used when none is configured
const DefaultHttpListenAddr = ":80"

// NormalizeHttpListenAddr returns the effective listen address ("" -> ":80")
func NormalizeHttpListenAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return DefaultHttpListenAddr
	}
	return addr
}

// ParseHttpListenAddr splits and validates a host:port listen address.
// The host may be empty (all interfaces) or an IP literal / "localhost".
func ParseHttpListenAddr(addr string) (host string, port int, err error) {
	addr = NormalizeHttpListenAddr(addr)
	h, p, serr := net.SplitHostPort(addr)
	if serr != nil {
		return "", 0, errors.New("address must be in host:port or :port form")
	}
	port, perr := strconv.Atoi(p)
	if perr != nil || port < 0 || port > 65535 {
		return "", 0, errors.New("port must be a number between 1 and 65535")
	}
	if h != "" && !strings.EqualFold(h, "localhost") {
		ip := net.ParseIP(strings.Split(h, "%")[0])
		if ip == nil {
			return "", 0, errors.New("host must be empty or an IP address")
		}
	}
	return h, port, nil
}

func hostsOverlap(a, b string) bool {
	wild := func(h string) bool {
		if h == "" {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsUnspecified()
	}
	if wild(a) || wild(b) {
		return true
	}
	if strings.EqualFold(a, "localhost") {
		a = "127.0.0.1"
	}
	if strings.EqualFold(b, "localhost") {
		b = "127.0.0.1"
	}
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a == b
	}
	return ia.Equal(ib)
}

// ValidateHttpListenAddr validates a plain HTTP listener address and refuses
// addresses that collide with the admin UI listener (adminAddr, e.g. ":8000",
// may be empty) or the HTTPS proxy port.
func ValidateHttpListenAddr(addr string, adminAddr string, proxyPort int) error {
	host, port, err := ParseHttpListenAddr(addr)
	if err != nil {
		return err
	}
	if port < 1 {
		return errors.New("port must be a number between 1 and 65535")
	}
	if adminAddr != "" {
		if ah, ap, aerr := net.SplitHostPort(adminAddr); aerr == nil {
			if apn, e := strconv.Atoi(ap); e == nil && apn == port && hostsOverlap(host, ah) {
				return errors.New("this address conflicts with the management interface listener")
			}
		}
	}
	if proxyPort == port {
		return errors.New("this port is already used by the proxy listener")
	}
	return nil
}

// HttpListenPort returns the port of the effective plain HTTP listener (80 if invalid)
func (router *Router) HttpListenPort() int {
	_, p, err := ParseHttpListenAddr(router.Option.HttpListenAddr)
	if err != nil {
		return 80
	}
	return p
}

// HttpListenAddr returns the effective plain HTTP listener address
func (router *Router) HttpListenAddr() string {
	if _, _, err := ParseHttpListenAddr(router.Option.HttpListenAddr); err != nil {
		return DefaultHttpListenAddr
	}
	return NormalizeHttpListenAddr(router.Option.HttpListenAddr)
}

// UpdateHttpListenAddr changes the plain HTTP listener address and restarts the proxy service
func (router *Router) UpdateHttpListenAddr(addr string) {
	router.Option.HttpListenAddr = NormalizeHttpListenAddr(addr)
	router.Restart()
}

// BoundHttpAddr returns the actual address the plain HTTP listener is bound to ("" if not running)
func (router *Router) BoundHttpAddr() string {
	if router.httpListenerAddr == nil {
		return ""
	}
	return router.httpListenerAddr.String()
}

// startHttpListener binds the plain HTTP listener (HTTP-to-HTTPS redirector, ACME
// challenges, plain-HTTP-allowed hosts). On failure the listener is disabled
// instead of terminating the process.
func (router *Router) startHttpListener() {
	addr := router.HttpListenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		router.Option.ListenOnPort80 = false
		router.tlsRedirectStop = nil
		router.Option.Logger.PrintAndLog("dprouter", "Could not start HTTP-to-HTTPS redirector ("+addr+"); disabling plain HTTP listener", err)
		return
	}
	httpServer := &http.Server{
		Handler:           http.HandlerFunc(router.handlePort80Request),
		ReadHeaderTimeout: time.Duration(router.Option.ReadHeaderTimeout) * time.Second,
		WriteTimeout:      time.Duration(router.Option.WriteTimeout) * time.Second,
		IdleTimeout:       time.Duration(router.Option.IdleTimeout) * time.Second,
	}
	router.Option.Logger.PrintAndLog("dprouter", "Starting HTTP-to-HTTPS redirector ("+ln.Addr().String()+")", nil)

	stopChan := make(chan bool)
	go func() {
		<-stopChan
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
		router.Option.Logger.PrintAndLog("dprouter", "HTTP to HTTPS redirection listener stopped", nil)
	}()
	go func() {
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			router.Option.Logger.PrintAndLog("dprouter", "HTTP-to-HTTPS redirector stopped unexpectedly", err)
		}
	}()
	router.tlsRedirectStop = stopChan
	router.httpListenerAddr = ln.Addr()
}
