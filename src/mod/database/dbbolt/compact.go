package dbbolt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

/*
	compact.go

	Offline compaction of a BoltDB file. A Bolt file never shrinks by itself:
	deleted keys only leave free pages inside it. Compaction copies every bucket
	into a fresh file (bbolt.Compact), which drops that free space.

	Safety rules, in order:
	  1. open the database with the fail-fast open, so a database that another
	     process holds is refused (never a second writer);
	  2. write a consistent, timestamped backup next to the file;
	  3. compact into a temporary file next to the database;
	  4. verify the new file: it opens, passes bbolt's consistency check and every
	     bucket (including nested ones) has the same key count, sub-bucket count and
	     payload size as the old one;
	  5. swap it in with one atomic rename.
	Any failure before step 5 removes the temporary file and leaves the original
	untouched. The backup is never deleted by this code.
*/

// CompactOptions and CompactResult live in dbinc so platforms without BoltDB can name them
type CompactOptions = dbinc.CompactOptions
type CompactResult = dbinc.CompactResult

// CompactFile compacts the BoltDB file at path in place (see the file comment for the guarantees).
func CompactFile(path string, opt CompactOptions) (res *CompactResult, err error) {
	started := time.Now()
	if opt.TxMaxSize <= 0 {
		opt.TxMaxSize = 16 << 20
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the database file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a database file (BoltDB is a single file; a LevelDB database is a directory and cannot be compacted here)", path)
	}
	if fi.Size() == 0 {
		return nil, fmt.Errorf("%s is empty, nothing to compact", path)
	}

	//Step 0: take the lock. Refuses (LockedError) when another process has it.
	src, err := openBolt(path, OpenOptions{Timeout: opt.OpenTimeout})
	if err != nil {
		return nil, err
	}
	srcClosed := false
	defer func() {
		if !srcClosed {
			src.Close()
		}
	}()

	if err := checkFreeSpace(filepath.Dir(path), 2*fi.Size()); err != nil {
		return nil, err
	}

	dir, base := filepath.Dir(path), filepath.Base(path)
	backupPath := filepath.Join(dir, base+".bak-"+opt.Now().Format("20060102-150405"))
	tmpPath := filepath.Join(dir, base+".compact-tmp")
	os.Remove(tmpPath) //a leftover of an earlier failed run (never the database)
	swapped := false
	defer func() {
		if !swapped {
			os.Remove(tmpPath)
		}
	}()

	//Step 1: backup (a consistent snapshot taken in a read transaction)
	if err := opt.StepHook("backup"); err != nil {
		return nil, err
	}
	if _, serr := os.Stat(backupPath); serr == nil {
		return nil, fmt.Errorf("backup file %s already exists, try again in a second", backupPath)
	}
	opt.Logff("Writing backup %s", backupPath)
	if err := writeSnapshot(src, backupPath, fi.Mode().Perm()); err != nil {
		os.Remove(backupPath)
		return nil, fmt.Errorf("backup failed, the database was not touched: %w", err)
	}
	copyOwner(path, backupPath)

	//Step 2: compact into the temporary file
	if err := opt.StepHook("compact"); err != nil {
		return nil, err
	}
	opt.Logff("Compacting into %s", tmpPath)
	dst, err := bolt.Open(tmpPath, fi.Mode().Perm(), &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("cannot create the new database file: %w", err)
	}
	if err := bolt.Compact(dst, src, opt.TxMaxSize); err != nil {
		dst.Close()
		return nil, fmt.Errorf("compaction failed, the database was not touched: %w", err)
	}
	if err := dst.Close(); err != nil {
		return nil, fmt.Errorf("closing the new database file: %w", err)
	}
	if err := syncFile(tmpPath); err != nil {
		return nil, err
	}

	//Step 3: verify the new file against the old one
	if err := opt.StepHook("verify"); err != nil {
		return nil, err
	}
	opt.Logff("Verifying the new file")
	tables, keys, err := verifyCompacted(src, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("verification failed, the database was not touched: %w", err)
	}
	copyOwner(path, tmpPath)

	//Step 4: swap. The old file is closed first (a rename over an open file is refused on Windows).
	if err := opt.StepHook("swap"); err != nil {
		return nil, err
	}
	src.Close()
	srcClosed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("could not put the new file in place, the database was not touched: %w", err)
	}
	swapped = true
	syncDir(dir)

	after := int64(0)
	if nfi, err := os.Stat(path); err == nil {
		after = nfi.Size()
	}
	return &CompactResult{
		Path: path, BackupPath: backupPath,
		BytesBefore: fi.Size(), BytesAfter: after,
		Tables: tables, Keys: keys, Elapsed: time.Since(started),
	}, nil
}

// writeSnapshot writes a consistent copy of src to dst
func writeSnapshot(src *bolt.DB, dst string, perm os.FileMode) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	err = src.View(func(tx *bolt.Tx) error {
		_, werr := tx.WriteTo(f)
		return werr
	})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// verifyCompacted opens the new file read only, runs bbolt's consistency check and
// compares every top level bucket with the old database.
func verifyCompacted(src *bolt.DB, newPath string) (tables int, keys int64, err error) {
	dst, err := bolt.Open(newPath, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return 0, 0, fmt.Errorf("the new file does not open: %w", err)
	}
	defer dst.Close()

	var oldCounts, newCounts map[string]bucketCount
	if err := src.View(func(tx *bolt.Tx) error { oldCounts = countAll(tx); return nil }); err != nil {
		return 0, 0, err
	}
	var checkErrs []error
	if err := dst.View(func(tx *bolt.Tx) error {
		newCounts = countAll(tx)
		for e := range tx.Check() {
			checkErrs = append(checkErrs, e)
			if len(checkErrs) >= 5 {
				break
			}
		}
		return nil
	}); err != nil {
		return 0, 0, err
	}
	if len(checkErrs) > 0 {
		return 0, 0, fmt.Errorf("the new file is inconsistent: %w", errors.Join(checkErrs...))
	}
	if len(oldCounts) != len(newCounts) {
		return 0, 0, fmt.Errorf("table count differs: %d before, %d after", len(oldCounts), len(newCounts))
	}
	for name, o := range oldCounts {
		n, ok := newCounts[name]
		if !ok {
			return 0, 0, fmt.Errorf("table %q is missing from the new file", name)
		}
		if n != o {
			return 0, 0, fmt.Errorf("table %q differs: %d keys / %d nested / %d bytes before, %d / %d / %d after",
				name, o.keys, o.buckets, o.bytes, n.keys, n.buckets, n.bytes)
		}
		keys += o.keys
	}
	return len(oldCounts), keys, nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync() //best effort, not supported everywhere
		d.Close()
	}
}
