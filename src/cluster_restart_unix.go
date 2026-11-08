//go:build !windows

package main

import (
	"os"
	"syscall"
)

// restartSelf replaces the process image with a fresh copy of itself.
func restartSelf(exe string) {
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		SystemWideLogger.PrintAndLog("cluster", "Self restart failed; restart Zoraxy manually", err)
	}
}
