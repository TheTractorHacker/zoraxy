package metrics

// Totals returns the number of requests and of 5xx responses counted since
// the registry started recording (used by the Fleet heartbeat, which ships
// two numbers instead of any per request data).
func (r *Registry) Totals() (requests, errors uint64) {
	if r == nil {
		return 0, 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.endpoints {
		for c := range e.requests {
			for m := range e.requests[c] {
				n := e.requests[c][m].Load()
				requests += n
				if c == 4 { //5xx
					errors += n
				}
			}
		}
	}
	return
}
