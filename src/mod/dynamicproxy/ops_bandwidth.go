package dynamicproxy

import (
	"context"
	"net/http"
	"sync"
	"time"
)

/*
	ops_bandwidth.go

	Response bandwidth limit (upstream #1208): token buckets, one per response and optionally
	one shared by every connection of a client IP. Data is written in small chunks; before
	each chunk the writer waits until the buckets allow it, and flushes after the chunk so the
	server's write buffer does not hide the pacing. The clock and sleep are injectable.
*/

type bwBucket struct {
	mu     sync.Mutex
	rate   float64 //bytes per second
	cap    float64
	tokens float64
	last   time.Time
}

func newBucket(rate int64, chunk int, now time.Time) *bwBucket {
	return &bwBucket{rate: float64(rate), cap: float64(chunk), tokens: float64(chunk), last: now}
}

// reserve takes n tokens and returns how long the caller has to wait before using them
func (b *bwBucket) reserve(now time.Time, n int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * b.rate
		if b.tokens > b.cap {
			b.tokens = b.cap
		}
		b.last = now
	}
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

type bandwidthRuntime struct {
	perConn   int64
	perClient int64
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration)

	mu      sync.Mutex
	clients map[string]*bwBucket
}

const (
	maxBWChunk       = 16 * 1024
	maxTrackedClient = 65536
)

func realSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func newBandwidthRuntime(c *BandwidthConfig) *bandwidthRuntime {
	return &bandwidthRuntime{perConn: c.BytesPerSecond, perClient: c.PerClientBytesPerSecond,
		now: time.Now, sleep: realSleep, clients: map[string]*bwBucket{}}
}

func chunkFor(rate int64) int {
	c := int(rate / 10)
	if c < 1 {
		c = 1
	}
	if c > maxBWChunk {
		c = maxBWChunk
	}
	return c
}

func (b *bandwidthRuntime) clientBucket(ip string, now time.Time) *bwBucket {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bk, ok := b.clients[ip]; ok {
		return bk
	}
	if len(b.clients) > 4096 {
		for k, v := range b.clients { //drop buckets idle for a while
			v.mu.Lock()
			idle := now.Sub(v.last) > 2*time.Minute
			v.mu.Unlock()
			if idle {
				delete(b.clients, k)
			}
		}
	}
	bk := newBucket(b.perClient, chunkFor(b.perClient), now)
	if len(b.clients) < maxTrackedClient {
		b.clients[ip] = bk
	}
	return bk
}

// bwConn is the throttle of one response
type bwConn struct {
	rt     *bandwidthRuntime
	ctx    context.Context
	conn   *bwBucket
	client *bwBucket
	chunk  int
}

func (b *bandwidthRuntime) newConn(ip string, ctx context.Context) *bwConn {
	c := &bwConn{rt: b, ctx: ctx, chunk: maxBWChunk}
	now := b.now()
	if b.perConn > 0 {
		c.conn = newBucket(b.perConn, chunkFor(b.perConn), now)
		c.chunk = chunkFor(b.perConn)
	}
	if b.perClient > 0 {
		c.client = b.clientBucket(ip, now)
		if cc := chunkFor(b.perClient); cc < c.chunk {
			c.chunk = cc
		}
	}
	return c
}

func (c *bwConn) write(w http.ResponseWriter, p []byte) (int, error) {
	written := 0
	fl, _ := w.(http.Flusher)
	for len(p) > 0 {
		n := len(p)
		if n > c.chunk {
			n = c.chunk
		}
		now := c.rt.now()
		var wait time.Duration
		if c.conn != nil {
			wait = c.conn.reserve(now, n)
		}
		if c.client != nil {
			if d := c.client.reserve(now, n); d > wait {
				wait = d
			}
		}
		if wait > 0 {
			c.rt.sleep(c.ctx, wait)
			if c.ctx.Err() != nil {
				return written, c.ctx.Err()
			}
		}
		m, err := w.Write(p[:n])
		written += m
		if err != nil {
			return written, err
		}
		if fl != nil {
			fl.Flush()
		}
		p = p[n:]
	}
	return written, nil
}
