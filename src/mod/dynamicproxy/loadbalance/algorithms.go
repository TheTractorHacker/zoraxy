package loadbalance

import (
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/*
	Selection algorithms

	All algorithms work on the already filtered list of usable upstreams
	(online, not draining, not at capacity, healthy). The common rules are:
	  - Upstreams with Weight > 0 form the primary group. Upstreams with
	    Weight == 0 are only used when no primary upstream is usable.
	  - The weight of an upstream that is in slow start is scaled down.

	The designs follow the well known public descriptions of these algorithms
	(nginx smooth weighted round robin, HAProxy leastconn, power of two
	choices by Mitzenmacher, ketama consistent hashing). No third party
	code is copied.
*/

type algoState struct {
	rr atomic.Uint64

	mu      sync.Mutex
	wrrCur  map[*Upstream]float64 //Smooth weighted round robin current weights
	ringPri *hashRing
	ringFb  *hashRing
}

func newAlgoState() *algoState {
	return &algoState{wrrCur: map[*Upstream]float64{}}
}

// candidate is an upstream with its effective weight for this pick
type candidate struct {
	u *Upstream
	w float64
}

// buildPool selects the primary group (or the fallback group when no primary is usable)
// and applies the slow start scaling to the weights
func buildPool(cands []*Upstream, now time.Time, slow time.Duration) (pool []candidate, usingFallback bool) {
	for _, u := range cands {
		if u.Weight > 0 {
			pool = append(pool, candidate{u, float64(u.Weight) * u.slowStartFactor(now, slow)})
		}
	}
	if len(pool) > 0 {
		return pool, false
	}
	for _, u := range cands {
		pool = append(pool, candidate{u, u.slowStartFactor(now, slow)})
	}
	return pool, true
}

func weightedRandom(pool []candidate) candidate {
	total := 0.0
	for _, c := range pool {
		total += c.w
	}
	if total <= 0 {
		return pool[rand.Intn(len(pool))]
	}
	x := rand.Float64() * total
	for _, c := range pool {
		if x < c.w {
			return c
		}
		x -= c.w
	}
	return pool[len(pool)-1]
}

// pickRoundRobin walks the pool in order. A slow starting upstream is skipped with probability 1-factor
func pickRoundRobin(st *algoState, pool []candidate, baseWeight func(*Upstream) float64) *Upstream {
	start := int((st.rr.Add(1) - 1) % uint64(len(pool)))
	for i := 0; i < len(pool); i++ {
		c := pool[(start+i)%len(pool)]
		base := baseWeight(c.u)
		if base <= 0 || c.w >= base || rand.Float64() < c.w/base {
			return c.u
		}
	}
	return pool[start].u
}

// pickSmoothWRR is the smooth weighted round robin: every pick adds the weight of each
// candidate to its running score, takes the highest and subtracts the total from it
func pickSmoothWRR(st *algoState, pool []candidate, known []*Upstream) *Upstream {
	st.mu.Lock()
	defer st.mu.Unlock()
	total := 0.0
	var best *Upstream
	bestScore := math.Inf(-1)
	for _, c := range pool {
		st.wrrCur[c.u] += c.w
		total += c.w
		if st.wrrCur[c.u] > bestScore {
			best, bestScore = c.u, st.wrrCur[c.u]
		}
	}
	st.wrrCur[best] -= total
	if len(st.wrrCur) > len(known)+4 {
		//Forget upstream objects that no longer exist in this endpoint
		for u := range st.wrrCur {
			found := false
			for _, k := range known {
				if k == u {
					found = true
					break
				}
			}
			if !found {
				delete(st.wrrCur, u)
			}
		}
	}
	return best
}

// pickMinScore returns the candidate with the lowest score, ties are broken randomly
func pickMinScore(pool []candidate, score func(candidate) float64) *Upstream {
	var best []*Upstream
	bestScore := math.Inf(1)
	for _, c := range pool {
		if c.w <= 0 {
			continue
		}
		s := score(c)
		switch {
		case s < bestScore*(1-1e-9):
			best, bestScore = []*Upstream{c.u}, s
		case s <= bestScore*(1+1e-9):
			best = append(best, c.u)
		}
	}
	if len(best) == 0 {
		return pool[rand.Intn(len(pool))].u
	}
	return best[rand.Intn(len(best))]
}

func leastConnScore(c candidate) float64 {
	return float64(c.u.InFlight()+1) / c.w
}

func leastTimeScore(c candidate) float64 {
	t := c.u.EWMA().Seconds()
	if t < minEWMASeconds {
		t = minEWMASeconds
	}
	return t * float64(c.u.InFlight()+1) / c.w
}

// pickTwoChoices samples two distinct upstreams by weight and returns the less loaded one
func pickTwoChoices(pool []candidate) *Upstream {
	if len(pool) == 1 {
		return pool[0].u
	}
	a := weightedRandom(pool)
	rest := make([]candidate, 0, len(pool)-1)
	for _, c := range pool {
		if c.u != a.u {
			rest = append(rest, c)
		}
	}
	b := weightedRandom(rest)
	if leastConnScore(b) < leastConnScore(a) {
		return b.u
	}
	return a.u
}

// ring returns the cached hash ring for the primary or fallback group of the endpoint
func (st *algoState) ring(origins []*Upstream, fallback bool) *hashRing {
	members := make([]*Upstream, 0, len(origins))
	for _, u := range origins {
		if (u.Weight > 0) != fallback {
			members = append(members, u)
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	cached := &st.ringPri
	if fallback {
		cached = &st.ringFb
	}
	if !(*cached).sameMembers(members) {
		*cached = buildRing(members)
	}
	return *cached
}

// hashKey extracts the hash input for the hash based algorithms. ok is false when the request carries no key
func hashKey(cfg *Config, r *http.Request, clientIP func() string) (key string, ok bool) {
	switch cfg.GetAlgorithm() {
	case AlgoIPHash:
		if clientIP != nil {
			key = clientIP()
		}
		if key == "" {
			key = r.RemoteAddr
			if i := strings.LastIndex(key, ":"); i > 0 {
				key = key[:i]
			}
		}
	case AlgoHeaderHash:
		key = r.Header.Get(cfg.HashKey)
	case AlgoCookieHash:
		if c, err := r.Cookie(cfg.HashKey); err == nil {
			key = c.Value
		}
	}
	return key, key != ""
}

// pickByAlgorithm applies the configured algorithm on cands (never empty). origins is the complete list of the endpoint
func (m *RouteManager) pickByAlgorithm(r *http.Request, origins, cands []*Upstream, opt *SelectOptions) *Upstream {
	cfg := opt.Config
	algo := cfg.GetAlgorithm()
	slow := cfg.slowStart()
	now := m.now()

	if len(cands) == 1 {
		return cands[0]
	}

	if algo == AlgoRandom {
		inSlowStart := false
		if slow > 0 {
			for _, u := range cands {
				if u.slowStartFactor(now, slow) < 1 {
					inSlowStart = true
					break
				}
			}
		}
		if !inSlowStart {
			//Historical behavior, bit for bit
			u, _, err := getRandomUpstreamByWeight(cands)
			if err != nil {
				m.println("Failed to get next origin", err)
				return cands[0]
			}
			return u
		}
	}

	pool, usingFallback := buildPool(cands, now, slow)
	st := cfg.state()

	switch algo {
	case AlgoRoundRobin:
		return pickRoundRobin(st, pool, func(u *Upstream) float64 {
			if usingFallback {
				return 1
			}
			return float64(u.Weight)
		})
	case AlgoWeightedRoundRobin:
		return pickSmoothWRR(st, pool, origins)
	case AlgoLeastConnections:
		return pickMinScore(pool, leastConnScore)
	case AlgoLeastResponseTime:
		return pickMinScore(pool, leastTimeScore)
	case AlgoPowerOfTwoChoices:
		return pickTwoChoices(pool)
	case AlgoIPHash, AlgoHeaderHash, AlgoCookieHash:
		key, ok := hashKey(cfg, r, opt.ClientIP)
		if !ok {
			//Nothing to hash on, spread the request randomly
			return weightedRandom(pool).u
		}
		allowed := func(u *Upstream) bool {
			for _, c := range pool {
				if c.u == u {
					return true
				}
			}
			return false
		}
		if u := st.ring(origins, usingFallback).pick(hashString(key), allowed); u != nil {
			return u
		}
		return weightedRandom(pool).u
	}

	//AlgoRandom with slow start, or an unknown name (treated as random)
	return weightedRandom(pool).u
}
