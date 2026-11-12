package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/info/logger"
)

/*
	dbopenfail.go

	When the database cannot be opened because another process holds its lock,
	say so and exit with a non-zero status, instead of hanging (BoltDB used to
	wait for the lock forever, leaving a service that is "active (running)" with
	no listeners and a log that stops at "Using BoltDB as the database backend").
*/

// reportDatabaseOpenError handles the error of opening the system database at
// startup. A lock held elsewhere is logged through the normal logger, printed
// to stderr (so journalctl shows it) and ends the process with status 1; any
// other error keeps the old behaviour of a fatal log line.
func reportDatabaseOpenError(l *logger.Logger, err error) {
	var locked *dbinc.LockedError
	if !errors.As(err, &locked) {
		log.Fatal(err)
	}
	msg := "Unable to start: " + locked.Error()
	if l != nil {
		l.Log("database", msg, nil, false)
	}
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
