//go:build !linux && !darwin

package dbbolt

func copyOwner(ref, dst string)                   {}
func checkFreeSpace(dir string, need int64) error { return nil }
