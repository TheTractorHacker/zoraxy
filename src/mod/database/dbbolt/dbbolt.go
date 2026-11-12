package dbbolt

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/instance"
)

/*
	MaxValueSize is the largest serialized value this backend will accept for a
	single key.

	bbolt itself allows values up to 2GiB, but that limit alone is not enough to
	keep a database readable. A leaf page addresses all of its key/value data
	through a single 2GiB (MaxAllocSize) unsafe slice window, the offset of an
	element inside that window accumulates over every element before it, and
	bbolt refuses to split a node holding 4 or fewer keys. A handful of very
	large values sharing one page can therefore push the cumulative offset past
	the window even when every individual value is legal. Once that happens,
	every read and every write that seeks over the element panics, permanently,
	and the only way out is restoring the database file from a backup.

	64MB per value keeps roughly 8x headroom under that ceiling in the
	4-values-per-page worst case.
*/
const MaxValueSize = 64 * 1024 * 1024

type Database struct {
	Db interface{} //This is the bolt database object
}

// DefaultOpenTimeout is how long opening the database waits for the file lock
// held by another process before giving up. Without it bolt waits forever.
const DefaultOpenTimeout = 10 * time.Second

// OpenOptions are the tunables of opening a database. The zero value is the default.
type OpenOptions struct {
	Timeout time.Duration //how long to wait for the file lock, 0 = DefaultOpenTimeout
}

// openBolt opens a bbolt file with the stock options plus a lock timeout. A lock
// that is still held when the timeout passes is reported as *dbinc.LockedError.
func openBolt(dbfile string, opt OpenOptions) (*bolt.DB, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultOpenTimeout
	}
	o := *bolt.DefaultOptions //same as passing nil, except for the timeout
	o.Timeout = opt.Timeout
	stopWatch := instance.WatchLockWait(dbfile) //STATUS= for systemd while waiting (no-op without NOTIFY_SOCKET)
	db, err := bolt.Open(dbfile, 0600, &o)
	stopWatch()
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, &dbinc.LockedError{Path: absPath(dbfile), Backend: "BoltDB", Waited: opt.Timeout, Err: err}
		}
		return nil, err
	}
	return db, nil
}

// absPath makes the path in the error message usable from any folder (lsof, ls)
func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func NewBoltDatabase(dbfile string) (*Database, error) {
	return NewBoltDatabaseWithOptions(dbfile, OpenOptions{})
}

// NewBoltDatabaseWithOptions is NewBoltDatabase with an injectable lock timeout (used by tests)
func NewBoltDatabaseWithOptions(dbfile string, opt OpenOptions) (*Database, error) {
	db, err := openBolt(dbfile, opt)
	if err != nil {
		return nil, err
	}

	return &Database{
		Db: db,
	}, err
}

// Create a new table
func (d *Database) NewTable(tableName string) error {
	err := d.Db.(*bolt.DB).Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(tableName))
		if err != nil {
			return err
		}
		return nil
	})

	return err
}

// Check is table exists
func (d *Database) TableExists(tableName string) bool {
	return d.Db.(*bolt.DB).View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tableName))
		if b == nil {
			return errors.New("table not exists")
		}
		return nil
	}) == nil
}

// Drop the given table
func (d *Database) DropTable(tableName string) error {
	err := d.Db.(*bolt.DB).Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(tableName))
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// Write to table
func (d *Database) Write(tableName string, key string, value interface{}) error {
	jsonString, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(jsonString) > MaxValueSize {
		//Refuse the write instead of storing a value that might make the
		//containing page unreadable. See MaxValueSize for the details.
		return fmt.Errorf("value too large for key %s in table %s: %d bytes exceeds the limit of %d bytes", key, tableName, len(jsonString), MaxValueSize)
	}
	err = d.Db.(*bolt.DB).Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(tableName))
		if err != nil {
			return err
		}
		b := tx.Bucket([]byte(tableName))
		err = b.Put([]byte(key), jsonString)
		return err
	})
	return err
}

func (d *Database) Read(tableName string, key string, assignee interface{}) error {
	err := d.Db.(*bolt.DB).View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tableName))
		v := b.Get([]byte(key))
		json.Unmarshal(v, &assignee)
		return nil
	})
	return err
}

func (d *Database) KeyExists(tableName string, key string) bool {
	resultIsNil := false
	if !d.TableExists(tableName) {
		//Table not exists. Do not proceed accessing key
		//log.Println("[DB] ERROR: Requesting key from table that didn't exist!!!")
		return false
	}
	err := d.Db.(*bolt.DB).View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tableName))
		v := b.Get([]byte(key))
		if v == nil {
			resultIsNil = true
		}
		return nil
	})

	if err != nil {
		return false
	} else {
		if resultIsNil {
			return false
		} else {
			return true
		}
	}
}

func (d *Database) Delete(tableName string, key string) error {
	err := d.Db.(*bolt.DB).Update(func(tx *bolt.Tx) error {
		tx.Bucket([]byte(tableName)).Delete([]byte(key))
		return nil
	})

	return err
}

func (d *Database) ListTable(tableName string) ([][][]byte, error) {
	var results [][][]byte
	err := d.Db.(*bolt.DB).View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tableName))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			results = append(results, [][]byte{k, v})
		}
		return nil
	})
	return results, err
}

func (d *Database) Close() {
	d.Db.(*bolt.DB).Close()
}
