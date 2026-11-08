package statistic

import (
	"os"
	"testing"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

// Upstream #561: today's statistics must survive a restart of the process.
func TestTodayStatsSurviveRestart(t *testing.T) {
	dbPath := "test_restart_db"
	db, err := database.NewDatabase(dbPath, dbinc.BackendLevelDB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()

	first, err := NewStatisticCollector(CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	first.DailySummary.TotalRequest = 4242
	first.DailySummary.RequestClientIp.Store("1.2.3.4", 7)
	first.Close() // what ShutdownSeq does on SIGTERM

	second, err := NewStatisticCollector(CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	if second.DailySummary.TotalRequest != 4242 {
		t.Fatalf("today's total lost on restart: got %d", second.DailySummary.TotalRequest)
	}
	if v, ok := second.DailySummary.RequestClientIp.Load("1.2.3.4"); !ok || v.(int) != 7 {
		t.Fatalf("client ip counter lost on restart: %v %v", v, ok)
	}
}
