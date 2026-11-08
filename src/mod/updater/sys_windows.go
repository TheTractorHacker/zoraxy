//go:build windows

package updater

import (
	"errors"
	"time"
)

var errUnsupported = errors.New("not supported on this platform")

func execInPlace(exe string, args []string) error { return errUnsupported }

func freeSpace(dir string) (uint64, error) { return 0, errUnsupported }

func spawnDetached(bin string, args []string, logPath string) (int, error) {
	return 0, errUnsupported
}

func terminate(pid int, grace time.Duration) {}

const platformSupported = false
