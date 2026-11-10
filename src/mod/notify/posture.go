package notify

// EventPosture is raised by the security overview (mod/posture) when the score drops or a check starts failing.
// Off unless the administrator enables "notify me" on the Security overview page.
//
//	security.posture  warning  security  summary line  detail
const EventPosture = "security.posture"

func init() {
	Catalog = append(Catalog, EventInfo{EventPosture, SevWarning, "Security score dropped"})
}

// Summary counts the enabled destinations, for the security overview. No settings or secrets are returned.
func (m *Manager) Summary() (channels, webhooks int, command bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.cfg.Channels {
		if c.Enabled {
			channels++
		}
	}
	for _, w := range m.cfg.Webhooks {
		if w.Enabled {
			webhooks++
		}
	}
	return channels, webhooks, m.cfg.Command.Enabled
}
