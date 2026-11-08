package cluster

// NodeState is the id, name and dashboard status of one enrolled fleet node
type NodeState struct {
	ID     string
	Name   string
	Status string
}

// FleetNodeStates lists the nodes enrolled at this hub with their current status
// (empty when this instance is not a hub). Used by the notification centre to
// report nodes going offline.
func (m *Manager) FleetNodeStates() []NodeState {
	if m == nil || m.hub == nil {
		return nil
	}
	nodes, _ := m.hub.Overview()["nodes"].([]NodeView)
	out := make([]NodeState, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, NodeState{ID: n.ID, Name: n.Name, Status: n.Status})
	}
	return out
}

// Status values of FleetNodeStates
const (
	NodeStatusOnline  = StatusOnline
	NodeStatusOffline = StatusOffline
)
