//go:build linux

package instance

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"
)

func statIDs(t *testing.T, fi os.FileInfo) (uint32, uint32, uint64) {
	t.Helper()
	st := fi.Sys().(*syscall.Stat_t)
	maj, min := DevMajorMinor(uint64(st.Dev))
	return maj, min, uint64(st.Ino)
}

func hex2(v uint32) string { return fmt.Sprintf("%02x", v) }
func itoa(v uint64) string { return strconv.FormatUint(v, 10) }
