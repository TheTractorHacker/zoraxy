// Package offline holds the process wide "offline mode" switch (start flag -offline).
//
// When enabled, every outbound request that Zoraxy makes on its own initiative (start-up or
// background) or that is a convenience feature (GeoIP database download, public IP lookup,
// update check, plugin store sync, setup wizard IP lookup) is refused with ErrOffline before any
// socket is opened. Traffic that is the point of the product is NOT affected: proxied requests,
// upstream health checks, and ACME certificate issuance / DNS-01 challenges that an administrator
// explicitly requests.
package offline

import (
	"errors"
	"sync/atomic"
)

// ErrOffline is returned by guarded operations in offline mode.
var ErrOffline = errors.New("offline mode: outbound network access is disabled (-offline)")

var enabled atomic.Bool

// Set switches offline mode on or off (called once from the flag at start-up; tests toggle it).
func Set(v bool) { enabled.Store(v) }

// Enabled reports whether offline mode is on.
func Enabled() bool { return enabled.Load() }

// Check returns ErrOffline in offline mode and nil otherwise. Call it at the top of anything that
// would dial out on its own.
func Check() error {
	if enabled.Load() {
		return ErrOffline
	}
	return nil
}
