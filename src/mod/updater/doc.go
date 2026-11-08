// Package updater implements the in-app "Update" page backend of this Zoraxy
// fork: release discovery on GitHub, ed25519 + SHA-256 verification, backup,
// atomic binary replacement, restart and automatic rollback.
//
// # Security / behaviour contract
//
//   - No network access happens unless an administrator opens the Update page
//     or clicks a button. There is no automatic update (a future "auto update"
//     setting would be off by default and is deliberately not implemented).
//   - A downloaded binary is only installed if SHA256SUMS carries a valid raw
//     ed25519 signature (SHA256SUMS.sig) made with the public key embedded in
//     release_pubkey.pem AND the binary's SHA-256 matches its SHA256SUMS line.
//   - Updates are forward-only (see CompareReleases). Rolling back is a
//     separate, explicit operation that restores the saved previous binary.
//
// # Version ordering rule
//
// Release tags look like v<upstream>[-rc<N>][-<topic>].<build> e.g.
// v3.3.5-rc5-grpcfix.1. Because the topic part is free text, tags are NOT
// ordered as semver. Releases are ordered by (1) the upstream version triple
// major.minor.patch, then (2) the GitHub published-at timestamp, then (3) the
// trailing fork build number. A candidate is an upgrade only if it sorts
// strictly after the running build. The identity of the running build is
// recorded in <conf>/updater/installed.json when the updater installs a binary
// (and is trusted only while the SHA-256 of the running executable still
// matches); otherwise it falls back to SYSTEM_VERSION with an unknown date.
//
// # Restart strategy
//
// After the new binary is renamed over the old one the process runs its normal
// shutdown sequence and then re-executes the new binary in place with
// syscall.Exec (same PID, same arguments and environment). That keeps a
// systemd MainPID valid whatever the Restart= policy of the unit is. If exec
// fails the process exits with status 75 so that a supervisor with
// Restart=on-failure/always brings the new binary up.
//
// # Rollback
//
// A pending-update marker (<conf>/updater/pending.json) is written before the
// restart. The new process must reach "healthy" (management HTTP listener up
// and proxy router initialised) within HealthyTimeout. Two independent layers
// restore the previous binary otherwise: an in-process guard started at the
// very beginning of main (covers hangs and crash loops: the start attempt
// counter in the marker is bumped on every start), and an out-of-process
// watchdog child (the old binary run with -updater_watchdog) which survives
// the in-place exec but is killed by systemd's cgroup cleanup if the unit is
// stopped or restarted.
package updater
