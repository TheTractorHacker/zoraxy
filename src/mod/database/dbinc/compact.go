package dbinc

import "time"

// CompactOptions tunes CompactFile. The zero value is the production behaviour.
type CompactOptions struct {
	OpenTimeout time.Duration           //wait for the lock, 0 = DefaultOpenTimeout
	TxMaxSize   int64                   //bytes per compaction transaction, 0 = 16 MiB
	Now         func() time.Time        //clock for the backup name (tests)
	Step        func(step string) error //called before each step ("backup", "compact", "verify", "swap"); an error aborts (failure injection in tests)
	Logf        func(format string, a ...interface{})
}

// CompactResult describes a finished compaction
type CompactResult struct {
	Path        string
	BackupPath  string
	BytesBefore int64
	BytesAfter  int64
	Tables      int
	Keys        int64
	Elapsed     time.Duration
}

// StepHook returns the error of a failure injection, nil when there is no hook
func (o *CompactOptions) StepHook(name string) error {
	if o.Step != nil {
		return o.Step(name)
	}
	return nil
}

// Logff logs through Logf when it is set
func (o *CompactOptions) Logff(format string, a ...interface{}) {
	if o.Logf != nil {
		o.Logf(format, a...)
	}
}
