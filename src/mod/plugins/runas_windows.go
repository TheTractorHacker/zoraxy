//go:build windows

package plugins

import "os/exec"

// applyRunAs is not supported on Windows: the setting is ignored and plugins run as the Zoraxy user
func (m *Manager) applyRunAs(cmd *exec.Cmd, binary string) error {
	if m.Options != nil && m.Options.RunAsUser != "" {
		m.Log("Running plugins as another user (-plugin_user) is not supported on Windows, the setting is ignored", nil)
	}
	return nil
}
