package dnsresponder

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const maxBuckets = 20000

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a per client IP token bucket (IPv6 clients are keyed by /64)
type limiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	m     map[netip.Addr]*bucket
	now   func() time.Time
}

func newLimiter(qps float64, burst int) *limiter {
	return &limiter{rate: qps, burst: float64(burst), m: map[netip.Addr]*bucket{}, now: time.Now}
}

func limiterKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

// Allow consumes one token for the client, reporting whether the query may proceed
func (l *limiter) Allow(ip netip.Addr) bool {
	key := limiterKey(ip)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[key]
	if b == nil {
		if len(l.m) >= maxBuckets {
			l.sweep(now)
			if len(l.m) >= maxBuckets {
				return false //table full of active clients: fail closed
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have fully refilled (idle clients). Caller holds the lock.
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.m {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.m, k)
		}
	}
}

// limitListener caps the number of concurrently open TCP connections
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, max int) *limitListener {
	return &limitListener{Listener: l, sem: make(chan struct{}, max)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
		default:
			c.Close() //over the cap: refuse by closing immediately
		}
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
