package waf

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

/*
	bands.go

	Graduated response: the anomaly score of a request decides between three bands.

	  score < ChallengeThreshold                       log only (request passes, rule matches are logged as "detected")
	  ChallengeThreshold <= score < InboundThreshold   challenge: the client gets the CAPTCHA page instead of a 403.
	                                                   A client holding a valid challenge cookie passes ("challenge_passed")
	  score >= InboundThreshold                        block (403), exactly as before. A challenge cookie never helps here

	How the score is obtained: the CRS keeps blocking at tx.inbound_anomaly_score_threshold in REQUEST-949, so the
	block band, detection_only and the existing behaviour are untouched. When the transaction was NOT interrupted the
	final score is read from tx.blocking_inbound_anomaly_score (set by the 949 rules at the end of phase 2, before the
	body is replayed) and compared with ChallengeThreshold in Go. Nothing else about the request is consumed twice.

	Safe fallbacks. A request in the challenge band is blocked (never silently let through) when
	  - no CAPTCHA provider is configured for the endpoint (OnChallenge is nil), or
	  - the client cannot render a challenge page: only GET navigations that accept text/html are challenged
	    (API clients, XHR / fetch, POST bodies, HEAD get the block band logic).
	detection_only never challenges and never blocks.
*/

const (
	DefaultChallengeTTLMinutes = 60
	MaxChallengeTTLMinutes     = 1440

	// Event actions of the graduated response (Event.Action)
	ActionChallenged      = "challenged"
	ActionChallengePassed = "challenge_passed"

	scoreVariable = "blocking_inbound_anomaly_score"
)

func validateBandValues(threshold, ttlMinutes int) error {
	if threshold < 0 {
		return errors.New("challenge threshold must not be negative (0 turns the challenge band off)")
	}
	if threshold > 10000 {
		return errors.New("challenge threshold is too large")
	}
	if ttlMinutes < 0 {
		return errors.New("challenge validity must not be negative")
	}
	if ttlMinutes > MaxChallengeTTLMinutes {
		return fmt.Errorf("challenge validity must not exceed %d minutes", MaxChallengeTTLMinutes)
	}
	return nil
}

// validateBands checks the raw (not yet normalised) challenge settings
func (c *Config) validateBands() error {
	if c == nil {
		return nil
	}
	if err := validateBandValues(c.ChallengeThreshold, c.ChallengeTTLMinutes); err != nil {
		return err
	}
	if c.ChallengeThreshold > 0 {
		n := c.Normalize()
		if c.ChallengeThreshold >= n.InboundThreshold {
			return fmt.Errorf("challenge threshold (%d) must be lower than the block threshold (%d)", c.ChallengeThreshold, n.InboundThreshold)
		}
	}
	return nil
}

// ChallengeEnabled reports whether the challenge band is configured
func (c *Config) ChallengeEnabled() bool {
	return c != nil && c.ChallengeThreshold > 0
}

// ChallengeTTL is the validity of a solved challenge
func (c *Config) ChallengeTTL() time.Duration {
	m := DefaultChallengeTTLMinutes
	if c != nil && c.ChallengeTTLMinutes > 0 {
		m = c.ChallengeTTLMinutes
	}
	if m > MaxChallengeTTLMinutes {
		m = MaxChallengeTTLMinutes
	}
	return time.Duration(m) * time.Minute
}

// applyBands merges the challenge settings of the policy, profile and endpoint override into cfg.
// Same rules as the paranoia level / threshold: 0 inherits, the endpoint override needs AllowEndpointOverride.
// A merged challenge threshold that is not below the block threshold is dropped (band off) with a warning, and
// reported through res.bandErr so that saving such a combination can be refused.
func (s *State) applyBands(cfg *Config, prof *Profile, x *Overrides, res *Resolved) {
	p := s.Policy
	cfg.ChallengeThreshold, cfg.ChallengeTTLMinutes = p.ChallengeThreshold, p.ChallengeTTLMinutes
	if prof != nil {
		if prof.ChallengeThreshold > 0 {
			cfg.ChallengeThreshold = prof.ChallengeThreshold
		}
		if prof.ChallengeTTLMinutes > 0 {
			cfg.ChallengeTTLMinutes = prof.ChallengeTTLMinutes
		}
	}
	if x != nil {
		if p.AllowEndpointOverride {
			if x.ChallengeThreshold > 0 {
				cfg.ChallengeThreshold = x.ChallengeThreshold
			}
			if x.ChallengeTTLMinutes > 0 {
				cfg.ChallengeTTLMinutes = x.ChallengeTTLMinutes
			}
		} else if x.ChallengeThreshold != 0 || x.ChallengeTTLMinutes != 0 {
			res.Warning = strings.TrimSpace(res.Warning + " endpoint challenge override ignored (not allowed by the global policy)")
		}
	}
	if cfg.ChallengeThreshold > 0 {
		block := cfg.InboundThreshold
		if block <= 0 {
			block = DefaultInboundThreshold
		}
		if cfg.ChallengeThreshold >= block {
			res.bandErr = fmt.Sprintf("challenge threshold (%d) must be lower than the block threshold (%d)", cfg.ChallengeThreshold, block)
			res.Warning = strings.TrimSpace(res.Warning + " " + res.bandErr + ": challenge band disabled")
			cfg.ChallengeThreshold, cfg.ChallengeTTLMinutes = 0, 0
		}
	}
}

// anomalyScore returns the final inbound anomaly score of a transaction (0 if unavailable)
func anomalyScore(tx types.Transaction) int {
	ts, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return 0
	}
	vals := ts.Variables().TX().Get(scoreVariable)
	if len(vals) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(vals[0]))
	return n
}

// CanChallenge reports whether the client can be shown a challenge page: a GET navigation that accepts HTML.
func CanChallenge(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" && !strings.EqualFold(m, "navigate") {
		return false // fetch() / XHR / subresource, cannot show a page
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	return true
}
