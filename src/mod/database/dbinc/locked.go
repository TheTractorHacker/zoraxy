package dbinc

import (
	"strings"
	"time"
)

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

func (e *LockedError) Error() string {
	var b strings.Builder
	b.WriteString("the database is locked by another process: " + e.Path + " (" + e.Backend)
	if e.Waited > 0 {
		b.WriteString(", waited " + e.Waited.Round(time.Second).String())
	}
	b.WriteString(")\n")
	b.WriteString("Another Zoraxy process (or another program) most likely has it open. Only one process can use the database at a time.\n")
	b.WriteString("Find the process holding it:\n")
	b.WriteString("    sudo lsof " + e.Path + "\n")
	b.WriteString("    ps -eo pid,etimes,args | grep [z]oraxy\n")
	b.WriteString("Stop that process (for a service: sudo systemctl stop zoraxy), then start Zoraxy again.")
	return b.String()
}

func (e *LockedError) Unwrap() error { return e.Err }
