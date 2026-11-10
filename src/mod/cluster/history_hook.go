package cluster

// HubManagedReason tells the configuration history whether a conf relative file
// is owned by a hub or a primary, so a history restore does not silently
// overwrite it (the next sync would revert it anyway). It returns "" when the
// file is node local or this node is not managed at all.
//
//   - Fleet node: files of the scopes the hub manages (for the merging proxy
//     scope only the files the hub published), see applyFleet.
//   - Legacy follower: every synced root, unless local edits are allowed.
func (m *Manager) HubManagedReason(rel string) string {
	switch m.Role() {
	case RoleNode:
		m.mu.RLock()
		st := m.status
		m.mu.RUnlock()
		for _, sc := range st.FleetScopes {
			s, ok := GetScope(sc)
			if !ok || !s.OwnsPath(rel) {
				continue
			}
			if sc == "proxy" {
				for _, k := range st.Managed["proxy"] {
					if k == rel {
						return "managed by the Fleet hub"
					}
				}
				continue
			}
			return "managed by the Fleet hub (" + sc + ")"
		}
	case RoleFollower:
		if m.opt.AllowLocalEdits {
			return ""
		}
		m.mu.RLock()
		certs := m.status.CertsSynced
		m.mu.RUnlock()
		if validEntryPath(rel, ManagedRoots(certs)) {
			return "synced from the cluster primary"
		}
	}
	return ""
}
