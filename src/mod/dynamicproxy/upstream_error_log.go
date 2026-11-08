package dynamicproxy

import (
	"fmt"
	"sync"
	"time"
)

/*
	upstream_error_log.go

	A 521 / 404 error page only says that the upstream could not be reached. The reason ("connection refused",
	"i/o timeout", "no such host", "no route to host"...) used to be visible nowhere, which made reports like
	upstream #1102 (Transmission returns 521) impossible to debug. The reason is now written to the system
	log, at most once per upstream and reason every upstreamErrorLogInterval so a dead upstream cannot flood it.
*/

const upstreamErrorLogInterval = 30 * time.Second

var upstreamErrorLogLimiter = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

// shouldLogUpstreamFailure reports whether a failure with this key was not logged within the interval
func shouldLogUpstreamFailure(key string, now time.Time) bool {
	l := &upstreamErrorLogLimiter
	l.Lock()
	defer l.Unlock()
	if len(l.last) > 2048 {
		for k, t := range l.last {
			if now.Sub(t) >= upstreamErrorLogInterval {
				delete(l.last, k)
			}
		}
		if len(l.last) > 2048 {
			l.last = map[string]time.Time{}
		}
	}
	if t, ok := l.last[key]; ok && now.Sub(t) < upstreamErrorLogInterval {
		return false
	}
	l.last[key] = now
	return true
}

// logUpstreamFailure writes why the upstream request failed to the system log (rate limited)
func (router *Router) logUpstreamFailure(requestHost string, upstream string, err error) {
	if err == nil || router == nil || router.Option == nil || router.Option.Logger == nil {
		return
	}
	reason := err.Error()
	if !shouldLogUpstreamFailure(upstream+"|"+reason, time.Now()) {
		return
	}
	router.Option.Logger.PrintAndLog("proxy", fmt.Sprintf("Upstream %s failed for request to %s", upstream, requestHost), err)
}
