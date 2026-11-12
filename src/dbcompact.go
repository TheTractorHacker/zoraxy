package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

/*
	dbcompact.go

	zoraxy -compact-db -dbpath ./sys.db

	Offline compaction of the BoltDB database. Zoraxy must be stopped: a database
	that another process holds is refused after the normal 10 second lock wait.
	The steps and the safety rules are in mod/database/dbbolt/compact.go.
*/

// runCompactDatabase runs the -compact-db mode and returns the process exit code
func runCompactDatabase(dbPath string, backend string, out, errOut io.Writer) int {
	if backend == "leveldb" {
		fmt.Fprintln(errOut, "-compact-db works on the BoltDB database file only (LevelDB compacts itself).")
		return 1
	}
	fmt.Fprintf(out, "Compacting %s (Zoraxy must not be running; waiting up to 10 seconds if the database is locked)\n", dbPath)
	res, err := database.CompactFile(dbPath, dbinc.CompactOptions{
		Logf: func(format string, a ...interface{}) { fmt.Fprintf(out, "  "+format+"\n", a...) },
	})
	if err != nil {
		var locked *dbinc.LockedError
		if errors.As(err, &locked) {
			fmt.Fprintln(errOut, "Cannot compact: "+err.Error())
		} else {
			fmt.Fprintln(errOut, "Compaction failed: "+err.Error())
		}
		fmt.Fprintln(errOut, "The database was not changed.")
		return 1
	}
	fmt.Fprintf(out, "Done in %s: %s -> %s (%s smaller), %d tables, %d keys, all verified.\n",
		res.Elapsed.Round(10_000_000), humanBytes(res.BytesBefore), humanBytes(res.BytesAfter),
		humanBytes(res.BytesBefore-res.BytesAfter), res.Tables, res.Keys)
	fmt.Fprintf(out, "Backup of the old database: %s\nDelete the backup yourself once Zoraxy has run fine with the new file.\n", res.BackupPath)
	return 0
}

func humanBytes(n int64) string {
	neg := ""
	if n < 0 {
		neg, n = "-", -n
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%s%d B", neg, n)
	}
	return strings.TrimSpace(fmt.Sprintf("%s%.1f %s", neg, f, units[i]))
}
