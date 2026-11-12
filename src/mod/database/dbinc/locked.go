package dbinc

import (
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/instance"
)

// HolderSummary names the process holding the lock on a path ("" when unknown). A var so tests can
// replace it; the default reads /proc on Linux and says nothing elsewhere (see mod/instance).
var HolderSummary = instance.LockHolderSummary

/*
LockedError is returned by a backend when the database could not be opened
because another process holds its lock. It carries the full, operator facing
explanation so every caller (startup, -compact-db, -reset-account) shows the
same text.
*/
type LockedError struct {
	Path    string        //database file (BoltDB) or directory (LevelDB)
	Backend string        //BoltDB / LevelDB
	Waited  time.Duration //how long the open waited (0 when the backend fails at once)
	Err     error         //the underlying error
}

// Error is the full text for starting Zoraxy (ends with the stop-then-start advice)
func (e *LockedError) Error() string {
	return e.Describe() + "\n" + "Stop that process (for a service: sudo systemctl stop zoraxy), then start Zoraxy again."
}

// Describe is the explanation without the closing advice, for callers whose next step differs
func (e *LockedError) Describe() string {
	var b strings.Builder
	b.WriteString("the database is locked by another process: " + e.Path + " (" + e.Backend)
	if e.Waited > 0 {
		b.WriteString(", waited " + e.Waited.Round(time.Second).String())
	}
	b.WriteString(")\n")
	if h := HolderSummary(e.Path); h != "" {
		b.WriteString("The lock is " + h + "\n")
	}
	b.WriteString("Another Zoraxy process (or another program) most likely has it open. Only one process can use the database at a time.\n")
	b.WriteString("Find the process holding it:\n")
	b.WriteString("    sudo lsof " + e.Path + "\n")
	b.WriteString("    ps -eo pid,etimes,args | grep [z]oraxy")
	return b.String()
}

func (e *LockedError) Unwrap() error { return e.Err }
