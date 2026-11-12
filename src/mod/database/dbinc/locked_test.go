package dbinc

import (
	"strings"
	"testing"
	"time"
)

func TestLockedErrorNamesTheHolder(t *testing.T) {
	old := HolderSummary
	defer func() { HolderSummary = old }()
	e := &LockedError{Path: "/x/sys.db", Backend: "BoltDB", Waited: 10 * time.Second}

	HolderSummary = func(string) string {
		return "held by PID 3479504 (zoraxy, started 2h ago), state: FROZEN (stopped, probably Ctrl+Z or SIGSTOP). Resume it: kill -CONT 3479504, or stop it: kill -9 3479504"
	}
	for _, s := range []string{e.Describe(), e.Error()} {
		if !strings.Contains(s, "kill -CONT 3479504") || !strings.Contains(s, "FROZEN") {
			t.Fatalf("holder missing:\n%s", s)
		}
	}

	HolderSummary = func(string) string { return "" } //cannot be determined: the generic text only
	d := e.Describe()
	if strings.Contains(d, "The lock is") || !strings.Contains(d, "sudo lsof /x/sys.db") {
		t.Fatalf("generic message changed:\n%s", d)
	}
}
