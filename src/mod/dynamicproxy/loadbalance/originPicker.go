package loadbalance

import (
	"errors"
	"math/rand"
	"net/http"
	"strings"
)

// removeStickyCookieHeaders drops any sticky session Set-Cookie already queued on the response,
// so a re-selection (retry) does not send two competing cookies
func removeStickyCookieHeaders(h http.Header) {
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, c := range cookies {
		if !strings.HasPrefix(c, STICKY_SESSION_NAME+"=") {
			h.Add("Set-Cookie", c)
		}
	}
}

/*
	Origin Picker

	This script contains the code to pick the best origin
	by this request.
*/

const (
	STICKY_SESSION_NAME = "zr_sticky_session"
)

// ErrUpstreamsBusy is returned when every otherwise usable upstream reached its MaxInFlight limit
var ErrUpstreamsBusy = errors.New("all upstreams reached their maximum concurrent requests")

// SelectOptions are the per request inputs of the upstream selection
type SelectOptions struct {
	Config              *Config       //Endpoint load balancing config, nil = weighted random with no extra checks
	UseStickySession    bool          //Sticky sessions take precedence over the algorithm
	DisableAutoFallback bool          //Do not filter out upstreams reported offline by the uptime monitor
	ClientIP            func() string //Resolves the real client IP, used by ip_hash only
	ClientCountry       func() string //Resolves the client's ISO country code (GeoIP), used by client rules only
	Exclude             []*Upstream   //Upstreams that must not be selected (already tried by this request)
}

func (o *SelectOptions) excluded(u *Upstream) bool {
	for _, x := range o.Exclude {
		if x == u {
			return true
		}
	}
	return false
}

// GetRequestUpstreamTarget return the upstream target where this
// request should be routed. Kept for callers that have no load balancing config
func (m *RouteManager) GetRequestUpstreamTarget(w http.ResponseWriter, r *http.Request, origins []*Upstream, useStickySession bool, disableAutoFallback bool) (*Upstream, error) {
	return m.SelectUpstream(w, r, origins, &SelectOptions{
		UseStickySession:    useStickySession,
		DisableAutoFallback: disableAutoFallback,
	})
}

// usable reports whether an upstream may receive a new request right now (ignoring uptime monitor state)
func (m *RouteManager) usable(u *Upstream, opt *SelectOptions) bool {
	return !u.Draining && !u.atCapacity() && !opt.excluded(u)
}

// candidates applies all availability filters, in order: uptime monitor, draining / excluded / full,
// then active and passive health. Health is advisory: if it would remove every upstream the
// previous set is used instead, an endpoint should never go dark just because every check failed
func (m *RouteManager) candidates(r *http.Request, origins []*Upstream, opt *SelectOptions) ([]*Upstream, error) {
	originalCount := len(origins)
	online := m.FilterOfflineOrigins(origins, originalCount, opt.DisableAutoFallback)

	available := make([]*Upstream, 0, len(online))
	busy := false
	for _, u := range online {
		if u.Draining || opt.excluded(u) {
			continue
		}
		if u.atCapacity() {
			busy = true
			continue
		}
		available = append(available, u)
	}
	if len(available) == 0 {
		if busy {
			return nil, ErrUpstreamsBusy
		}
		return nil, errors.New("no online upstream is available for origin: " + r.Host)
	}

	if originalCount > 1 {
		now := m.now()
		healthy := make([]*Upstream, 0, len(available))
		for _, u := range available {
			if u.isHealthy(now) {
				healthy = append(healthy, u)
			}
		}
		if len(healthy) > 0 {
			available = healthy
		}
	}
	return available, nil
}

// HasAlternative reports whether at least one more upstream could be selected with the given options
func (m *RouteManager) HasAlternative(r *http.Request, origins []*Upstream, opt *SelectOptions) bool {
	c, err := m.candidates(r, origins, opt)
	return err == nil && len(c) > 0
}

// SelectUpstream picks the upstream for this request.
// Order of precedence: valid sticky session, then the configured algorithm
func (m *RouteManager) SelectUpstream(w http.ResponseWriter, r *http.Request, origins []*Upstream, opt *SelectOptions) (*Upstream, error) {
	if len(origins) == 0 {
		return nil, errors.New("no upstream is defined for this host")
	}

	rule := opt.Config.matchClientRule(opt)

	if opt.UseStickySession {
		//Use stick session, check which origins this request previously used
		targetOriginId, err := m.getSessionHandler(r, origins)
		if err == nil && m.usable(origins[targetOriginId], opt) &&
			(rule == nil || rule.group[origins[targetOriginId].OriginIpOrDomain]) &&
			(len(origins) == 1 || origins[targetOriginId].isHealthy(m.now())) {
			//Valid session found and origin is usable
			return origins[targetOriginId], nil
		}

		//No valid session found or origin is offline / draining / unhealthy
		cands, err := m.candidates(r, origins, opt)
		if err != nil {
			return nil, err
		}
		if rule != nil {
			if cands, err = opt.Config.restrictToClientGroup(cands, rule); err != nil {
				return nil, err
			}
		}
		targetOrigin := m.pickByAlgorithm(r, origins, cands, opt)
		index := 0
		for i, o := range origins {
			if o == targetOrigin {
				index = i
				break
			}
		}
		m.setSessionHandler(w, r, targetOrigin.OriginIpOrDomain, index)
		return targetOrigin, nil
	}

	cands, err := m.candidates(r, origins, opt)
	if err != nil {
		return nil, err
	}
	if rule != nil {
		if cands, err = opt.Config.restrictToClientGroup(cands, rule); err != nil {
			return nil, err
		}
	}
	return m.pickByAlgorithm(r, origins, cands, opt), nil
}

// GetUsableUpstreamCounts return the number of usable upstreams
func (m *RouteManager) GetUsableUpstreamCounts(origins []*Upstream, disableAutoFallback bool) int {
	originalUpstreamCount := len(origins)
	origins = m.FilterOfflineOrigins(origins, originalUpstreamCount, disableAutoFallback)
	return len(origins)
}

/* Features related to session access */
//Set a new origin for this connection by session
func (m *RouteManager) setSessionHandler(w http.ResponseWriter, r *http.Request, originIpOrDomain string, index int) error {
	session, err := m.SessionStore.Get(r, STICKY_SESSION_NAME)
	if err != nil {
		return err
	}
	session.Values["zr_sid_origin"] = originIpOrDomain
	session.Values["zr_sid_index"] = index
	session.Options.MaxAge = 86400 //1 day
	session.Options.Path = "/"
	removeStickyCookieHeaders(w.Header())
	err = session.Save(r, w)
	if err != nil {
		return err
	}
	return nil
}

// Get the previous connected origin from session
func (m *RouteManager) getSessionHandler(r *http.Request, upstreams []*Upstream) (int, error) {
	// Get existing session
	session, err := m.SessionStore.Get(r, STICKY_SESSION_NAME)
	if err != nil {
		return -1, err
	}

	// Retrieve session values for origin
	originDomainRaw := session.Values["zr_sid_origin"]
	originIDRaw := session.Values["zr_sid_index"]

	if originDomainRaw == nil || originIDRaw == nil || originIDRaw == -1 {
		return -1, errors.New("no session has been set")
	}
	originDomain := originDomainRaw.(string)
	//originID := originIDRaw.(int)

	//Check if the upstream still exists
	for i, upstream := range upstreams {
		if upstream.OriginIpOrDomain == originDomain {
			if !m.IsTargetOnline(originDomain) {
				//Origin is offline
				return -1, errors.New("origin is offline")
			}

			//Ok, the origin is still online
			return i, nil
		}
	}

	return -1, errors.New("origin is no longer exists")
}

/* Functions related to random upstream picking */
// Get a random upstream by the weights defined in Upstream struct, return the upstream, index value and any error
func getRandomUpstreamByWeight(upstreams []*Upstream) (*Upstream, int, error) {
	// If there is only one upstream, return it
	if len(upstreams) == 1 {
		return upstreams[0], 0, nil
	}

	// Preserve the index with upstreams
	type upstreamWithIndex struct {
		Upstream *Upstream
		Index    int
	}

	// Calculate total weight for upstreams with weight > 0
	totalWeight := 0
	fallbackUpstreams := make([]upstreamWithIndex, 0, len(upstreams))

	for index, upstream := range upstreams {
		if upstream.Weight > 0 {
			totalWeight += upstream.Weight
		} else {
			// Collect fallback upstreams
			fallbackUpstreams = append(fallbackUpstreams, upstreamWithIndex{upstream, index})
		}
	}

	// If there are no upstreams with weight > 0, return a fallback upstream if available
	if totalWeight == 0 {
		if len(fallbackUpstreams) > 0 {
			// Randomly select one of the fallback upstreams
			randIndex := rand.Intn(len(fallbackUpstreams))
			return fallbackUpstreams[randIndex].Upstream, fallbackUpstreams[randIndex].Index, nil
		}
		// No upstreams available at all
		return nil, -1, errors.New("no valid upstream servers available")
	}

	// Random weight between 0 and total weight
	randomWeight := rand.Intn(totalWeight)

	// Select an upstream based on the random weight
	for index, upstream := range upstreams {
		if upstream.Weight > 0 { // Only consider upstreams with weight > 0
			if randomWeight < upstream.Weight {
				// Return the selected upstream and its index
				return upstream, index, nil
			}
			randomWeight -= upstream.Weight
		}
	}

	// If we reach here, it means we should return a fallback upstream if available
	if len(fallbackUpstreams) > 0 {
		randIndex := rand.Intn(len(fallbackUpstreams))
		return fallbackUpstreams[randIndex].Upstream, fallbackUpstreams[randIndex].Index, nil
	}

	return nil, -1, errors.New("failed to pick an upstream origin server")
}
