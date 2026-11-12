package instance

import (
	"strconv"
	"strings"
)

// LockEntry is one granted lock line of /proc/locks.
type LockEntry struct {
	Kind  string // FLOCK, POSIX, OFDLCK, LEASE
	Write bool
	Pid   int // pid of the owner as seen from this pid namespace (0 or -1 when unknown, OFD locks use -1)
	Major uint32
	Minor uint32
	Inode uint64
}

// ParseProcLocks parses the text of /proc/locks. Waiter lines ("->") and anything malformed are skipped.
//
//	1: FLOCK  ADVISORY  WRITE 1234 fd:01:5678 0 EOF
func ParseProcLocks(text string) []LockEntry {
	var out []LockEntry
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		if !strings.HasSuffix(f[0], ":") {
			continue
		}
		if f[1] == "->" { //a waiter, not the holder
			continue
		}
		// f[1]=kind f[2]=ADVISORY|MANDATORY f[3]=READ|WRITE f[4]=pid f[5]=maj:min:inode
		pid, err := strconv.Atoi(f[4])
		if err != nil {
			continue
		}
		dev := strings.Split(f[5], ":")
		if len(dev) != 3 {
			continue
		}
		maj, e1 := strconv.ParseUint(dev[0], 16, 32)
		min, e2 := strconv.ParseUint(dev[1], 16, 32)
		ino, e3 := strconv.ParseUint(dev[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		out = append(out, LockEntry{Kind: f[1], Write: f[3] == "WRITE", Pid: pid, Major: uint32(maj), Minor: uint32(min), Inode: ino})
	}
	return out
}

// DevMajorMinor splits a Linux st_dev into major and minor numbers (glibc encoding).
func DevMajorMinor(dev uint64) (uint32, uint32) {
	major := uint32(((dev >> 8) & 0xfff) | ((dev >> 32) &^ 0xfff))
	minor := uint32((dev & 0xff) | ((dev >> 12) &^ 0xff))
	return major, minor
}

// LockMatch is the result of looking a file up in /proc/locks.
type LockMatch struct {
	Pids        []int // distinct holder pids, may contain 0 / -1 when the kernel could not translate the pid
	Approximate bool  // matched on inode only (device numbers differ, seen on btrfs subvolumes and some overlays)
}

// MatchLocks returns the holders of the file identified by device and inode. An exact device+inode match
// wins; if there is none, an inode-only match is returned flagged Approximate.
func MatchLocks(entries []LockEntry, major, minor uint32, inode uint64) LockMatch {
	var exact, loose []int
	for _, e := range entries {
		if e.Inode != inode {
			continue
		}
		if e.Major == major && e.Minor == minor {
			exact = appendUnique(exact, e.Pid)
		} else {
			loose = appendUnique(loose, e.Pid)
		}
	}
	if len(exact) > 0 {
		return LockMatch{Pids: exact}
	}
	if len(loose) > 0 {
		return LockMatch{Pids: loose, Approximate: true}
	}
	return LockMatch{}
}

func appendUnique(s []int, v int) []int {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
