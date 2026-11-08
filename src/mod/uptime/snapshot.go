package uptime

import "sort"

// LatestRecords returns the most recent check result of every target (sorted by name).
// It only reads the in-memory log: no checks are run.
func (m *Monitor) LatestRecords() []Record {
	m.logMutex.RLock()
	defer m.logMutex.RUnlock()
	out := make([]Record, 0, len(m.OnlineStatusLog))
	for _, recs := range m.OnlineStatusLog {
		if n := len(recs); n > 0 && recs[n-1] != nil {
			out = append(out, *recs[n-1])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
