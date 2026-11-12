package dbbolt

import (
	"os"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

/*
	usage.go

	Read only visibility of what a BoltDB file holds, so an admin can see which
	table makes it grow. Uses one read transaction. A long read transaction does
	not block other readers or writers, except that bbolt cannot remap (grow) the
	file while a reader is open, so the walk is capped in time and reports
	"truncated" instead of running for minutes on a huge table.
*/

// DefaultUsageBudget is how long a usage walk may take before it stops and reports truncated
const DefaultUsageBudget = 5 * time.Second

// TableUsage and Usage live in dbinc so platforms without BoltDB can name them
type TableUsage = dbinc.TableUsage
type Usage = dbinc.Usage

type bucketCount struct {
	keys, buckets, bytes int64
}

// countBucket walks a bucket recursively. It checks the deadline at the first and then every 512th entry
// and returns false when it stopped early.
func countBucket(b *bolt.Bucket, c *bucketCount, deadline time.Time) bool {
	n := 0
	complete := true
	cur := b.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		n++
		if (n == 1 || n%512 == 0) && !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		if v == nil { //a nested bucket
			c.buckets++
			if sub := b.Bucket(k); sub != nil && !countBucket(sub, c, deadline) {
				complete = false
				break
			}
			continue
		}
		c.keys++
		c.bytes += int64(len(k) + len(v))
	}
	return complete
}

// countAll counts every top level bucket of a transaction (no deadline)
func countAll(tx *bolt.Tx) map[string]bucketCount {
	out := map[string]bucketCount{}
	tx.ForEach(func(name []byte, b *bolt.Bucket) error {
		var c bucketCount
		countBucket(b, &c, time.Time{})
		out[string(name)] = c
		return nil
	})
	return out
}

// Usage reports the file size, the free space inside it and per table key counts and payload sizes
// sorted by size. budget caps the time spent (0 = DefaultUsageBudget).
func (d *Database) Usage(budget time.Duration) (*Usage, error) {
	if budget <= 0 {
		budget = DefaultUsageBudget
	}
	db := d.Db.(*bolt.DB)
	start := time.Now()
	deadline := start.Add(budget)
	u := &Usage{Backend: "BoltDB", Path: db.Path(), Tables: []TableUsage{}}
	if fi, err := os.Stat(db.Path()); err == nil {
		u.FileBytes = fi.Size()
	}
	u.PageSize = db.Info().PageSize
	st := db.Stats()
	u.FreePages = st.FreePageN
	u.PendingPages = st.PendingPageN
	u.FreelistBytes = st.FreelistInuse
	u.FreeBytes = int64(st.FreePageN+st.PendingPageN) * int64(u.PageSize)

	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			u.TotalTables++
			if u.Truncated { //out of time: list the table without counting it
				u.Tables = append(u.Tables, TableUsage{Name: string(name), Truncated: true})
				return nil
			}
			var c bucketCount
			ok := countBucket(b, &c, deadline)
			if !ok {
				u.Truncated = true
			}
			u.Tables = append(u.Tables, TableUsage{Name: string(name), Keys: c.keys, Buckets: c.buckets, Bytes: c.bytes, Truncated: !ok})
			u.PayloadBytes += c.bytes
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(u.Tables, func(i, j int) bool {
		if u.Tables[i].Bytes != u.Tables[j].Bytes {
			return u.Tables[i].Bytes > u.Tables[j].Bytes
		}
		return u.Tables[i].Name < u.Tables[j].Name
	})
	u.ElapsedMs = time.Since(start).Milliseconds()
	return u, nil
}
