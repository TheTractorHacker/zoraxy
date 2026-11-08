//go:build windows

package main

import "os"

// restartSelf exits and relies on the service manager to start Zoraxy again
// (Windows cannot replace the process image in place).
func restartSelf(exe string) {
	os.Exit(0)
}
