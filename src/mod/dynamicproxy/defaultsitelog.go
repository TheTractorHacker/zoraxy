package dynamicproxy

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

/*
	defaultsitelog.go

	Optional logging of requests that hit the default site without a matching proxy rule (upstream #578).

	Requests answered by the default site 404 page, and requests to an unknown host on a secondary
	listening port, were never logged on purpose: scanners can send thousands of them per second. With
	the switch on (default OFF) they are logged, but through a global token bucket (defaultSiteLogBurst
	lines at once, then defaultSiteLogPerSecond lines per second) so a flood cannot fill the disk. The
	lines that were dropped are counted and reported by one summary line the next time a line is let through.

	Requests the default site proxies or serves from the static web server go through the normal proxy
	logging of the default site rule (its own "disable logging" setting), this switch does not change that.
*/

const (
	defaultSiteLogBurst     = 20
	defaultSiteLogPerSecond = 5.0
)

type defaultSiteLogger struct {
	enabled    atomic.Bool
	suppressed atomic.Int64
	logged     atomic.Int64 //lines written, for tests and the status API

	mu     sync.Mutex
	tokens float64
	last   time.Time
	now    func() time.Time //test seam
}

func (d *defaultSiteLogger) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// allow consumes a token. The second result is the number of lines dropped since the last allowed line.
func (d *defaultSiteLogger) allow() (bool, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock()
	if d.last.IsZero() {
		d.tokens = defaultSiteLogBurst
	} else if el := now.Sub(d.last).Seconds(); el > 0 {
		d.tokens += el * defaultSiteLogPerSecond
		if d.tokens > defaultSiteLogBurst {
			d.tokens = defaultSiteLogBurst
		}
	}
	d.last = now
	if d.tokens < 1 {
		d.suppressed.Add(1)
		return false, 0
	}
	d.tokens--
	return true, d.suppressed.Swap(0)
}

// SetDefaultSiteLogging turns logging of default site requests on or off
func (router *Router) SetDefaultSiteLogging(enabled bool) {
	router.defaultSiteLog.enabled.Store(enabled)
}

// DefaultSiteLogStats returns the number of default site lines written since start
func (router *Router) DefaultSiteLogStats() int64 {
	return router.defaultSiteLog.logged.Load()
}

// DefaultSiteLoggingEnabled reports the switch state
func (router *Router) DefaultSiteLoggingEnabled() bool {
	return router.defaultSiteLog.enabled.Load()
}

// logDefaultSiteRequest records a request handled by the default site when the switch is on
func (router *Router) logDefaultSiteRequest(r *http.Request, statusCode int, forwardType string) {
	if !router.defaultSiteLog.enabled.Load() {
		return
	}
	ok, dropped := router.defaultSiteLog.allow()
	if !ok {
		return
	}
	if dropped > 0 && router.Option != nil && router.Option.Logger != nil {
		router.Option.Logger.PrintAndLog("dprouter", "Default site: "+strconv.FormatInt(dropped, 10)+" request(s) not logged (rate limited)", nil)
	}
	if router.Option == nil || router.Option.Logger == nil {
		return
	}
	router.defaultSiteLog.logged.Add(1)
	//No endpoint: logged even when the default site rule has logging disabled, and no statistics
	router.logRequest(r, false, statusCode, forwardType, r.Host, "", nil)
}
