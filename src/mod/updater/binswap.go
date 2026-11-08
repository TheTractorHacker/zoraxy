package updater

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

// prevSlot returns the path of the n-th saved previous binary:
// <exe>.prev, <exe>.prev.1, <exe>.prev.2 ...
func prevSlot(exe string, n int) string {
	if n == 0 {
		return exe + ".prev"
	}
	return exe + ".prev." + strconv.Itoa(n)
}

// linkOrCopy makes dst another name for src (hard link, else a copy).
func linkOrCopy(src, dst string) error {
	os.Remove(dst)
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

// installBinary keeps the current executable as <exe>.prev (shifting older
// ones, keeping at most keep) and atomically renames newPath over exe.
func installBinary(exe, newPath string, keep int) error {
	if keep < 1 {
		keep = 1
	}
	if _, err := os.Stat(exe); err != nil {
		return err
	}
	os.Remove(prevSlot(exe, keep-1))
	for i := keep - 2; i >= 0; i-- {
		if _, err := os.Stat(prevSlot(exe, i)); err == nil {
			if err := os.Rename(prevSlot(exe, i), prevSlot(exe, i+1)); err != nil {
				return fmt.Errorf("rotating previous binaries: %w", err)
			}
		}
	}
	if err := linkOrCopy(exe, prevSlot(exe, 0)); err != nil {
		return fmt.Errorf("saving previous binary: %w", err)
	}
	if err := os.Chmod(newPath, 0o755); err != nil {
		return err
	}
	// Atomic on POSIX: exe always names either the old or the new file.
	return os.Rename(newPath, exe)
}

// restorePrevious puts <exe>.prev back in place of exe (atomically) and shifts
// older saved binaries down. The displaced binary is kept as <exe>.rolledback.
func restorePrevious(exe string) error {
	prev := prevSlot(exe, 0)
	st, err := os.Stat(prev)
	if err != nil {
		return errors.New("no previous binary is available")
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return errors.New("previous binary is not usable")
	}
	if err := linkOrCopy(exe, exe+".rolledback"); err != nil {
		return fmt.Errorf("keeping displaced binary: %w", err)
	}
	if err := os.Chmod(prev, 0o755); err != nil {
		return err
	}
	if err := os.Rename(prev, exe); err != nil {
		return err
	}
	for i := 1; ; i++ {
		if _, err := os.Stat(prevSlot(exe, i)); err != nil {
			break
		}
		if err := os.Rename(prevSlot(exe, i), prevSlot(exe, i-1)); err != nil {
			break
		}
	}
	return nil
}
