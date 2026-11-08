package loadbalance

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

/*
	Load balancing / health check / retry configuration

	Every field here is optional. A nil *Config (the value found in all
	configs written by older versions) means: weighted random selection,
	no active or passive health checks, no retries.
*/

// Algorithm names, stored in Config.Algorithm
const (
	AlgoRandom             = "random" //Weighted random, the historical default (also used when empty)
	AlgoRoundRobin         = "round_robin"
	AlgoWeightedRoundRobin = "weighted_round_robin" //Smooth weighted round robin
	AlgoLeastConnections   = "least_connections"
	AlgoLeastResponseTime  = "least_response_time"
	AlgoIPHash             = "ip_hash"
	AlgoHeaderHash         = "header_hash"
	AlgoCookieHash         = "cookie_hash"
	AlgoPowerOfTwoChoices  = "power_of_two_choices"
)

// AllAlgorithms lists every valid algorithm name (without the empty string)
var AllAlgorithms = []string{
	AlgoRandom, AlgoRoundRobin, AlgoWeightedRoundRobin, AlgoLeastConnections,
	AlgoLeastResponseTime, AlgoIPHash, AlgoHeaderHash, AlgoCookieHash, AlgoPowerOfTwoChoices,
}

// Config is the per-endpoint load balancing configuration
type Config struct {
	Algorithm string //One of the Algo* constants, empty = random
	HashKey   string //Header name (header_hash) or cookie name (cookie_hash)

	ActiveHealthCheck  *ActiveHealthCheck  //Default settings for active health checks of every upstream in this endpoint
	PassiveHealthCheck *PassiveHealthCheck //Passive health check (outlier ejection)
	Retry              *RetryConfig        //Retry on another upstream

	SlowStartSeconds int //Seconds to ramp the weight of a recovered upstream back to 100%, 0 = no slow start

	rtOnce sync.Once
	rt     *algoState
}

// ActiveHealthCheck probes an upstream periodically on its own
type ActiveHealthCheck struct {
	Enabled           bool
	Mode              string //"http" (default) or "tcp"
	Path              string //Request path, default "/"
	Method            string //Request method, default GET
	IntervalSeconds   int    //Default 10
	TimeoutSeconds    int    //Default 5
	ExpectedStatusMin int    //Default 200
	ExpectedStatusMax int    //Default 399
	BodyContains      string //Optional substring the response body must contain
	Rise              int    //Consecutive successes to mark healthy, default 2
	Fall              int    //Consecutive failures to mark unhealthy, default 3
}

// PassiveHealthCheck ejects an upstream that fails real traffic
type PassiveHealthCheck struct {
	Enabled         bool
	FailThreshold   int   //Consecutive failures before ejection, default 3
	CooldownSeconds int   //Ejection time, default 30
	FailureStatuses []int //Response codes counted as failure, default 502, 503, 504. Connection errors and timeouts always count
}

// RetryConfig controls retrying a failed request on another upstream
type RetryConfig struct {
	Enabled       bool
	MaxRetries    int      //Extra attempts after the first one, default 1
	RetryStatuses []int    //Upstream response codes that trigger a retry (only if nothing was sent to the client yet), default none
	ExtraMethods  []string //Non-idempotent methods (e.g. POST) allowed to retry. GET, HEAD and OPTIONS are always allowed
	MaxBodyKB     int      //Largest request body that may be buffered for a retry, default 1024. Bigger or unknown length bodies are never retried
}

// Defaults used when the corresponding field is zero
const (
	DefaultHealthInterval   = 10
	DefaultHealthTimeout    = 5
	DefaultRise             = 2
	DefaultFall             = 3
	DefaultFailThreshold    = 3
	DefaultCooldownSeconds  = 30
	DefaultMaxRetries       = 1
	DefaultMaxRetryBodyKB   = 1024
	maxHealthIntervalSecond = 86400
)

// GetAlgorithm returns the effective algorithm of this config (nil safe)
func (c *Config) GetAlgorithm() string {
	if c == nil || c.Algorithm == "" {
		return AlgoRandom
	}
	return c.Algorithm
}

// Validate checks the config values and returns a descriptive error
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	valid := c.Algorithm == ""
	for _, a := range AllAlgorithms {
		if c.Algorithm == a {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("unknown load balancing algorithm: %q", c.Algorithm)
	}
	if (c.Algorithm == AlgoHeaderHash || c.Algorithm == AlgoCookieHash) && strings.TrimSpace(c.HashKey) == "" {
		return errors.New("a header or cookie name is required for " + c.Algorithm)
	}
	if c.SlowStartSeconds < 0 || c.SlowStartSeconds > 3600 {
		return errors.New("slow start must be between 0 and 3600 seconds")
	}
	if a := c.ActiveHealthCheck; a != nil {
		if err := a.Validate(); err != nil {
			return err
		}
	}
	if p := c.PassiveHealthCheck; p != nil {
		if p.FailThreshold < 0 || p.CooldownSeconds < 0 {
			return errors.New("passive health check values cannot be negative")
		}
		for _, s := range p.FailureStatuses {
			if s < 100 || s > 599 {
				return fmt.Errorf("invalid failure status code %d", s)
			}
		}
	}
	if rc := c.Retry; rc != nil {
		if rc.MaxRetries < 0 || rc.MaxRetries > 10 {
			return errors.New("max retries must be between 0 and 10")
		}
		if rc.MaxBodyKB < 0 {
			return errors.New("max retry body size cannot be negative")
		}
		for _, s := range rc.RetryStatuses {
			if s < 100 || s > 599 {
				return fmt.Errorf("invalid retry status code %d", s)
			}
		}
		for _, m := range rc.ExtraMethods {
			if m == "" || m != strings.ToUpper(strings.TrimSpace(m)) || strings.ContainsAny(m, " \t") {
				return fmt.Errorf("invalid HTTP method %q (use upper case)", m)
			}
			if m == http.MethodConnect {
				return errors.New("CONNECT can never be retried")
			}
		}
	}
	return nil
}

// Validate checks an active health check definition
func (a *ActiveHealthCheck) Validate() error {
	if a == nil {
		return nil
	}
	if a.Mode != "" && a.Mode != "http" && a.Mode != "tcp" {
		return fmt.Errorf("unknown health check mode %q", a.Mode)
	}
	if a.Path != "" && !strings.HasPrefix(a.Path, "/") {
		return errors.New("health check path must start with /")
	}
	if a.IntervalSeconds < 0 || a.IntervalSeconds > maxHealthIntervalSecond || a.TimeoutSeconds < 0 {
		return errors.New("invalid health check interval or timeout")
	}
	if a.Rise < 0 || a.Fall < 0 {
		return errors.New("rise and fall cannot be negative")
	}
	if a.ExpectedStatusMin != 0 || a.ExpectedStatusMax != 0 {
		if a.ExpectedStatusMin < 100 || a.ExpectedStatusMax > 599 || a.ExpectedStatusMin > a.ExpectedStatusMax {
			return errors.New("invalid expected status range")
		}
	}
	if a.Method != "" {
		switch strings.ToUpper(a.Method) {
		case "GET", "HEAD", "OPTIONS", "POST":
		default:
			return fmt.Errorf("unsupported health check method %q", a.Method)
		}
	}
	return nil
}

// Normalized returns a copy with all zero values replaced by the defaults
func (a ActiveHealthCheck) Normalized() ActiveHealthCheck {
	if a.Mode == "" {
		a.Mode = "http"
	}
	if a.Path == "" {
		a.Path = "/"
	}
	a.Method = strings.ToUpper(a.Method)
	if a.Method == "" {
		a.Method = http.MethodGet
	}
	if a.IntervalSeconds <= 0 {
		a.IntervalSeconds = DefaultHealthInterval
	}
	if a.TimeoutSeconds <= 0 {
		a.TimeoutSeconds = DefaultHealthTimeout
	}
	if a.ExpectedStatusMin == 0 && a.ExpectedStatusMax == 0 {
		a.ExpectedStatusMin, a.ExpectedStatusMax = 200, 399
	}
	if a.Rise <= 0 {
		a.Rise = DefaultRise
	}
	if a.Fall <= 0 {
		a.Fall = DefaultFall
	}
	return a
}

// Normalized returns a copy with all zero values replaced by the defaults
func (p PassiveHealthCheck) Normalized() PassiveHealthCheck {
	if p.FailThreshold <= 0 {
		p.FailThreshold = DefaultFailThreshold
	}
	if p.CooldownSeconds <= 0 {
		p.CooldownSeconds = DefaultCooldownSeconds
	}
	if len(p.FailureStatuses) == 0 {
		p.FailureStatuses = []int{502, 503, 504}
	}
	return p
}

// Normalized returns a copy with all zero values replaced by the defaults
func (rc RetryConfig) Normalized() RetryConfig {
	if rc.MaxRetries <= 0 {
		rc.MaxRetries = DefaultMaxRetries
	}
	if rc.MaxBodyKB <= 0 {
		rc.MaxBodyKB = DefaultMaxRetryBodyKB
	}
	return rc
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (c *Config) slowStart() time.Duration {
	if c == nil || c.SlowStartSeconds <= 0 {
		return 0
	}
	return time.Duration(c.SlowStartSeconds) * time.Second
}

func (c *Config) passive() (PassiveHealthCheck, bool) {
	if c == nil || c.PassiveHealthCheck == nil || !c.PassiveHealthCheck.Enabled {
		return PassiveHealthCheck{}, false
	}
	return c.PassiveHealthCheck.Normalized(), true
}

func (c *Config) retry() (RetryConfig, bool) {
	if c == nil || c.Retry == nil || !c.Retry.Enabled {
		return RetryConfig{}, false
	}
	return c.Retry.Normalized(), true
}

// activeFor returns the effective active health check of an upstream, if any
func (c *Config) activeFor(u *Upstream) (ActiveHealthCheck, bool) {
	var hc *ActiveHealthCheck
	if u != nil && u.HealthCheck != nil {
		hc = u.HealthCheck //Per upstream definition overrides the endpoint one completely
	} else if c != nil {
		hc = c.ActiveHealthCheck
	}
	if hc == nil || !hc.Enabled {
		return ActiveHealthCheck{}, false
	}
	return hc.Normalized(), true
}

func (c *Config) state() *algoState {
	c.rtOnce.Do(func() { c.rt = newAlgoState() })
	return c.rt
}
