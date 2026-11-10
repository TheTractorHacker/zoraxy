package ruleset

import "testing"

// a stale write (older "updated" stamp) is refused for update and enable/disable, even within the same second
func TestStaleWriteConflict(t *testing.T) {
	e, _ := newPersisted(t)
	r1, err := e.Create("", in("one", `http.path == "/1"`, Action{Type: ActBlock, Status: 403}), -1)
	if err != nil {
		t.Fatal(err)
	}
	stamp := r1.Updated
	// session B changes the rule (same second as the create)
	if _, err := e.SetEnabled("", r1.ID, false); err != nil {
		t.Fatal(err)
	}
	// session A still holds the old stamp
	stale := in("one edited", `http.path == "/1x"`, Action{Type: ActBlock, Status: 403})
	stale.IfUpdated = &stamp
	if _, err := e.Update("", r1.ID, stale); err == nil {
		t.Fatal("stale update accepted")
	} else if _, ok := err.(ErrConflict); !ok {
		t.Fatalf("error type %T", err)
	}
	if _, err := e.SetEnabledIf("", r1.ID, true, &stamp); err == nil {
		t.Fatal("stale enable accepted")
	}
	cur, _ := e.SetEnabledIf("", r1.ID, true, nil)
	fresh := in("one edited", `http.path == "/1x"`, Action{Type: ActBlock, Status: 403})
	fresh.IfUpdated = &cur.Updated
	if _, err := e.Update("", r1.ID, fresh); err != nil {
		t.Fatalf("fresh update refused: %v", err)
	}
}
