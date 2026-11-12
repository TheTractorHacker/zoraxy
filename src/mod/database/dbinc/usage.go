package dbinc

import "errors"

// ErrUsageUnsupported is returned by backends that cannot report usage (only BoltDB can)
var ErrUsageUnsupported = errors.New("usage statistics are only available for the BoltDB backend")

// TableUsage is the size of one top level bucket (a "table")
type TableUsage struct {
	Name      string `json:"name"`
	Keys      int64  `json:"keys"`                //key/value pairs, including those of nested buckets
	Buckets   int64  `json:"nestedBuckets"`       //nested buckets below the table
	Bytes     int64  `json:"bytes"`               //sum of key and value sizes (payload, not pages)
	Truncated bool   `json:"truncated,omitempty"` //counting stopped at the time budget, the numbers are a lower bound
}

// Usage is the result of Usage()
type Usage struct {
	Backend       string       `json:"backend"`
	Path          string       `json:"path"`
	FileBytes     int64        `json:"fileBytes"` //size on disk
	PageSize      int          `json:"pageSize"`
	FreePages     int          `json:"freePages"`     //pages inside the file that are free for reuse
	PendingPages  int          `json:"pendingPages"`  //freed in a recent transaction, not yet reusable
	FreeBytes     int64        `json:"freeBytes"`     //(free + pending) pages in bytes: space inside the file that holds no data
	FreelistBytes int          `json:"freelistBytes"` //bytes of the in-memory free list
	TotalTables   int          `json:"totalTables"`
	PayloadBytes  int64        `json:"payloadBytes"` //sum of Bytes of all counted tables
	Tables        []TableUsage `json:"tables"`       //biggest first
	Truncated     bool         `json:"truncated"`    //the time budget ran out; see the per table flags
	ElapsedMs     int64        `json:"elapsedMs"`
}
