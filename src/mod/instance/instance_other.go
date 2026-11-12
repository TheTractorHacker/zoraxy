//go:build !linux

package instance

import "errors"

// Supported is false: there is no /proc to read on this platform.
const Supported = false

// ErrNoHolder means nobody holds a lock on the file (or it could not be determined).
var ErrNoHolder = errors.New("no process holds a lock on this file")

var errUnsupported = errors.New("process inspection is only available on Linux")

// FindLockHolders is not available off Linux.
func FindLockHolders(path string) (LockMatch, error) { return LockMatch{}, errUnsupported }

// FindLockHolder is not available off Linux.
func FindLockHolder(path string) (int, bool, error) { return 0, false, errUnsupported }

// Describe returns an invisible process off Linux.
func Describe(pid int) ProcInfo {
	return ProcInfo{Pid: pid, Uid: -1, Note: "process inspection is only available on Linux"}
}

// ListZoraxyProcesses finds nothing off Linux.
func ListZoraxyProcesses(exclude int) ([]ProcInfo, int) { return nil, 0 }

// ListenSocket is a LISTEN socket plus its owner pids.
type ListenSocket struct {
	Sock
	Owners []int
}

// ListenSockets is not available off Linux.
func ListenSockets() ([]ListenSocket, int, error) { return nil, 0, errUnsupported }

// UnitStatus is what systemctl reports about a unit.
type UnitStatus struct {
	Available bool
	Exists    bool
	Active    string
	Sub       string
	MainPID   int
	Type      string
	Fragment  string
	TimedOut  bool
}

// QueryUnit reports nothing off Linux.
func QueryUnit(name string) UnitStatus { return UnitStatus{} }

// OpensFile is not available off Linux.
func OpensFile(pid int, path string) (opens, known bool) { return false, false }
