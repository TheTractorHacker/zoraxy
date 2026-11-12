package dbbolt_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"imuslab.com/zoraxy/mod/database/dbbolt"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

// A second open of a locked file must come back with a LockedError after the (short, injected)
// timeout instead of hanging forever.
func TestSecondOpenFailsFastWhenLocked(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sys.db")
	first, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := dbbolt.NewBoltDatabaseWithOptions(file, dbbolt.OpenOptions{Timeout: 300 * time.Millisecond})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the second open of a locked database must fail")
		}
		var locked *dbinc.LockedError
		if !errors.As(err, &locked) {
			t.Fatalf("want *dbinc.LockedError, got %T: %v", err, err)
		}
		if !errors.Is(err, bolt.ErrTimeout) {
			t.Fatalf("the cause should be bolt.ErrTimeout: %v", err)
		}
		for _, want := range []string{file, "sudo lsof " + file, "ps -eo pid,etimes,args | grep [z]oraxy", "another process"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("message lacks %q:\n%s", want, err.Error())
			}
		}
		if el := time.Since(start); el > 3*time.Second {
			t.Fatalf("took %v, should be about the 300ms timeout", el)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second open hangs (no timeout)")
	}

	//the first handle is unaffected
	if err := first.Write("t", "k", "v"); err != nil {
		t.Fatalf("the first handle broke: %v", err)
	}
}

func seed(t *testing.T, file string, tables, keys int) {
	t.Helper()
	db, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	big := strings.Repeat("x", 2048)
	for ti := 0; ti < tables; ti++ {
		name := fmt.Sprintf("table%d", ti)
		for k := 0; k < keys; k++ {
			if err := db.Write(name, fmt.Sprintf("key%05d", k), big+fmt.Sprint(k)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// delete most keys: the file keeps its size (Bolt never shrinks)
func thin(t *testing.T, file string) map[string]string {
	t.Helper()
	db, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	kept := map[string]string{}
	for ti := 0; ti < 3; ti++ {
		name := fmt.Sprintf("table%d", ti)
		for k := 0; k < 400; k++ {
			key := fmt.Sprintf("key%05d", k)
			if k%50 == 0 {
				var v string
				db.Read(name, key, &v)
				kept[name+"/"+key] = v
				continue
			}
			db.Delete(name, key)
		}
	}
	//a nested bucket and a sequence, which Compact has to carry over
	bdb := db.Db.(*bolt.DB)
	if err := bdb.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("table0"))
		n, err := b.CreateBucketIfNotExists([]byte("nested"))
		if err != nil {
			return err
		}
		return n.Put([]byte("a"), []byte("1"))
	}); err != nil {
		t.Fatal(err)
	}
	return kept
}

func dump(t *testing.T, file string) map[string]string {
	t.Helper()
	db, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	out := map[string]string{}
	db.Db.(*bolt.DB).View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return b.ForEach(func(k, v []byte) error {
				out[string(name)+"/"+string(k)] = string(v)
				return nil
			})
		})
	})
	return out
}

func TestCompactShrinksAndKeepsData(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sys.db")
	seed(t, file, 3, 400)
	thin(t, file)
	before := dump(t, file)
	fiBefore, _ := os.Stat(file)

	res, err := dbbolt.CompactFile(file, dbbolt.CompactOptions{Now: func() time.Time { return time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesBefore != fiBefore.Size() || res.BytesAfter >= res.BytesBefore/2 {
		t.Fatalf("expected a big shrink, got %d -> %d", res.BytesBefore, res.BytesAfter)
	}
	if want := filepath.Join(dir, "sys.db.bak-20261112-100000"); res.BackupPath != want {
		t.Fatalf("backup %q want %q", res.BackupPath, want)
	}
	after := dump(t, file)
	if len(after) != len(before) {
		t.Fatalf("keys: %d before, %d after", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("value of %s changed", k)
		}
	}
	//the backup is the old content, byte size of the old file
	bfi, err := os.Stat(res.BackupPath)
	if err != nil || bfi.Size() < fiBefore.Size()/2 {
		t.Fatalf("backup missing or too small: %v", err)
	}
	if got := dump(t, res.BackupPath); len(got) != len(before) {
		t.Fatalf("backup holds %d keys, want %d", len(got), len(before))
	}
	if _, err := os.Stat(file + ".compact-tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	//the compacted file is a normal database: writable
	db, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write("table0", "after", "ok"); err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func TestCompactRefusesLockedDatabase(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sys.db")
	seed(t, file, 1, 5)
	held, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before, _ := os.ReadFile(file)

	start := time.Now()
	_, err = dbbolt.CompactFile(file, dbbolt.CompactOptions{OpenTimeout: 200 * time.Millisecond})
	var locked *dbinc.LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("want LockedError, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not fail fast")
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Fatalf("a locked database must leave no backup or temp file, found %d entries", len(entries))
	}
	after, _ := os.ReadFile(file)
	if string(before) != string(after) {
		t.Fatal("the locked database file was modified")
	}
}

func TestCompactRefusesMissingFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nope.db")
	if _, err := dbbolt.CompactFile(file, dbbolt.CompactOptions{}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("compaction must not create a database file")
	}
}

// Failure injection: whichever step fails, the original database stays valid and complete
// and no temp file is left. The failure in "swap" happens right before the rename.
func TestCompactFailureLeavesOriginalIntact(t *testing.T) {
	for _, failAt := range []string{"backup", "compact", "verify", "swap"} {
		t.Run(failAt, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "sys.db")
			seed(t, file, 2, 100)
			want := dump(t, file)
			orig, _ := os.ReadFile(file)

			boom := errors.New("injected failure")
			_, err := dbbolt.CompactFile(file, dbbolt.CompactOptions{Step: func(s string) error {
				if s == failAt {
					return boom
				}
				return nil
			}})
			if !errors.Is(err, boom) {
				t.Fatalf("want the injected error, got %v", err)
			}
			now, _ := os.ReadFile(file)
			if string(now) != string(orig) {
				t.Fatal("the original file changed")
			}
			got := dump(t, file) //opens, so it is valid and unlocked
			if len(got) != len(want) {
				t.Fatalf("keys %d want %d", len(got), len(want))
			}
			if _, err := os.Stat(file + ".compact-tmp"); !os.IsNotExist(err) {
				t.Fatal("temp file left behind")
			}
		})
	}
}

// A corrupt result must be refused by the verification, not swapped in. Simulated by changing
// the source between the compaction and the verification (the hook runs before "verify").
func TestCompactVerificationCatchesMismatch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sys.db")
	seed(t, file, 2, 50)
	orig, _ := os.ReadFile(file)
	// open the source ourselves is impossible (it is locked by CompactFile), so write a key via a
	// second handle of the same process is not possible either; instead tamper with the new file.
	_, err := dbbolt.CompactFile(file, dbbolt.CompactOptions{Step: func(s string) error {
		if s != "verify" {
			return nil
		}
		db, err := bolt.Open(file+".compact-tmp", 0600, nil)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("table0")).Delete([]byte("key00001")) })
	}})
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("want a verification error, got %v", err)
	}
	now, _ := os.ReadFile(file)
	if string(now) != string(orig) {
		t.Fatal("the original file changed")
	}
}

func TestUsage(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sys.db")
	db, err := dbbolt.NewBoltDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 10; i++ {
		db.Write("small", fmt.Sprint(i), "v")
	}
	for i := 0; i < 100; i++ {
		db.Write("big", fmt.Sprint(i), strings.Repeat("y", 1000))
	}
	db.NewTable("empty")
	db.Db.(*bolt.DB).Update(func(tx *bolt.Tx) error {
		_, err := tx.Bucket([]byte("small")).CreateBucket([]byte("sub"))
		return err
	})

	u, err := db.Usage(0)
	if err != nil {
		t.Fatal(err)
	}
	if u.FileBytes <= 0 || u.TotalTables != 3 || len(u.Tables) != 3 || u.Truncated {
		t.Fatalf("unexpected usage %+v", u)
	}
	if u.Tables[0].Name != "big" || u.Tables[0].Keys != 100 {
		t.Fatalf("biggest table first: %+v", u.Tables)
	}
	// payload = key + JSON encoded value (quotes add 2)
	wantBytes := int64(0)
	for i := 0; i < 100; i++ {
		wantBytes += int64(len(fmt.Sprint(i)) + 1000 + 2)
	}
	if u.Tables[0].Bytes != wantBytes {
		t.Fatalf("bytes %d want %d", u.Tables[0].Bytes, wantBytes)
	}
	if u.Tables[1].Name != "small" || u.Tables[1].Buckets != 1 || u.Tables[2].Name != "empty" || u.Tables[2].Keys != 0 {
		t.Fatalf("tables %+v", u.Tables)
	}

	//a budget that is already spent reports truncation instead of walking everything
	u2, err := db.Usage(time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if u2.TotalTables != 3 || !u2.Truncated || len(u2.Tables) != 3 {
		t.Fatalf("all tables are still listed and the result is flagged truncated: %+v", u2)
	}
}

// A symlinked sys.db: the link must stay a link and the real file be the one compacted.
func TestCompactFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	os.MkdirAll(realDir, 0755)
	target := filepath.Join(realDir, "sys.db")
	seed(t, target, 3, 200)
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	before, _ := os.Stat(target)
	res, err := dbbolt.CompactFile(link, dbbolt.CompactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink must still be a symlink: %v %v", fi, err)
	}
	if filepath.Dir(res.BackupPath) != realDir {
		t.Errorf("backup should sit next to the real file, got %s", res.BackupPath)
	}
	after, _ := os.Stat(target)
	if os.SameFile(before, after) {
		t.Error("the real file was not replaced by the compacted one")
	}
	d, err := dbbolt.NewBoltDatabase(link)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
}

// The compact path must not tell the operator to "start Zoraxy again" as the next step.
func TestLockedErrorDescribeHasNoStartAdvice(t *testing.T) {
	e := &dbinc.LockedError{Path: "/x/sys.db", Backend: "BoltDB"}
	if strings.Contains(e.Describe(), "start Zoraxy") || !strings.Contains(e.Error(), "start Zoraxy again") {
		t.Errorf("Describe=%q Error=%q", e.Describe(), e.Error())
	}
}
