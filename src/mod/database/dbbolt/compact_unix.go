//go:build linux || darwin

package dbbolt

import (
	"fmt"
	"os"
	"syscall"
)

// copyOwner gives dst the owner and group of ref. Run as root (sudo) the new file would otherwise
// be owned by root and the service user could no longer open it. Best effort: not being allowed is ignored.
func copyOwner(ref, dst string) {
	fi, err := os.Stat(ref)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		os.Chown(dst, int(st.Uid), int(st.Gid))
	}
}

// checkFreeSpace refuses to start when the folder cannot take the backup and the new file
func checkFreeSpace(dir string, need int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil //cannot tell, carry on
	}
	free := int64(uint64(st.Bavail) * uint64(st.Bsize))
	if free < need {
		return fmt.Errorf("not enough free space in %s: the backup and the new file need up to %d MB, %d MB are free", dir, need>>20, free>>20)
	}
	return nil
}
