package dynamicproxy

import (
	"testing"
	"time"
)

func TestShouldLogUpstreamFailureRateLimit(t *testing.T) {
	now := time.Now()
	key := "10.0.0.1:9091|dial tcp 10.0.0.1:9091: connect: connection refused"
	if !shouldLogUpstreamFailure(key, now) {
		t.Fatal("first failure must be logged")
	}
	if shouldLogUpstreamFailure(key, now.Add(time.Second)) {
		t.Fatal("same failure within the interval must be suppressed")
	}
	if !shouldLogUpstreamFailure(key+" other", now.Add(time.Second)) {
		t.Fatal("a different reason must be logged")
	}
	if !shouldLogUpstreamFailure(key, now.Add(upstreamErrorLogInterval+time.Second)) {
		t.Fatal("the failure must be logged again after the interval")
	}
}

func TestLogUpstreamFailureNilSafe(t *testing.T) {
	var r *Router
	r.logUpstreamFailure("a", "b", nil)
	(&Router{}).logUpstreamFailure("a", "b", errTest("x"))
}

type errTest string

func (e errTest) Error() string { return string(e) }
