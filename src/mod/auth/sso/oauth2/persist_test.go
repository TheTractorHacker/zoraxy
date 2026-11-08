package oauth2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func newRouterOn(t *testing.T, db *database.Database, uuid string, shared bool, idp *fakeIdP) *OAuth2Router {
	t.Helper()
	lg, _ := logger.NewFmtLogger()
	ar := NewOAuth2Router(&OAuth2RouterOptions{
		Logger: lg, Database: db, SystemUUID: uuid, SharedKey: shared,
		OAuth2ClientId: testClientID, OAuth2ClientSecret: testClientSecret,
		OAuth2Issuer: idp.issuer(), OAuth2CodeChallengeMethod: "PKCE_S256",
	})
	t.Cleanup(ar.Close)
	return ar
}

func storedSessionIDs(t *testing.T, db *database.Database) []string {
	t.Helper()
	rows, _ := db.ListTable(sessionTable)
	var ids []string
	for _, kv := range rows {
		ids = append(ids, string(kv[0]))
	}
	return ids
}

func TestSessionSurvivesRestartAndRefreshTokenStaysServerSide(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	ar := newRouterOn(t, db, testNodeUUID, false, idp)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)

	// The browser never sees tokens or claims
	for _, c := range b.cookies {
		if strings.Contains(c.Value, "alice") || strings.Contains(c.Value, "eyJ") {
			t.Fatalf("cookie %s carries session content: %s", c.Name, c.Value)
		}
	}
	// At rest: encrypted, no claim / token readable in the database
	var refresh string
	for _, item := range ar.store.sessions.Items() {
		refresh = item.Value().refreshToken
	}
	if refresh == "" {
		t.Fatal("test needs a refresh token")
	}
	rows, _ := db.ListTable(sessionTable)
	if len(rows) != 1 {
		t.Fatalf("expected one persisted session, got %d", len(rows))
	}
	for _, needle := range []string{"alice", "a@example.com", refresh, "user-1"} {
		if bytes.Contains(rows[0][1], []byte(needle)) {
			t.Fatalf("session record leaks %q at rest", needle)
		}
	}

	// "Restart": a new router (new process) on the same database and node identity
	ar.Close()
	ar2 := newRouterOn(t, db, testNodeUUID, false, idp)
	b.ar = ar2
	if !authed(b, appURL+"/dash") {
		t.Fatal("session lost across restart")
	}
	// the refresh token survived too: an expired access token is refreshed, not re-logged-in
	ar2.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	for _, item := range ar2.store.sessions.Items() {
		item.Value().accessExpiry = time.Now().Add(-time.Minute)
	}
	before := idp.refreshCount
	if !authed(b, appURL+"/dash") || idp.refreshCount != before+1 {
		t.Fatalf("refresh after restart: refreshCount %d -> %d", before, idp.refreshCount)
	}
	// ... and the rotated access expiry is persisted: a second restart does not need another refresh
	ar2.Close()
	ar3 := newRouterOn(t, db, testNodeUUID, false, idp)
	b.ar = ar3
	if !authed(b, appURL+"/dash") {
		t.Fatal("session lost on second restart")
	}
}

func TestPersistedSessionNotReadableWithAnotherKey(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	ar := newRouterOn(t, db, testNodeUUID, false, idp)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	ar.Close()
	other := newRouterOn(t, db, "99999999-2222-3333-4444-555555555555", false, idp)
	b.ar = other
	if authed(b, appURL+"/") {
		t.Fatal("session accepted by a node with a different key")
	}
}

func TestTamperedPersistedSessionRejected(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	ar := newRouterOn(t, db, testNodeUUID, false, idp)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	ids := storedSessionIDs(t, db)
	if len(ids) != 1 {
		t.Fatal(ids)
	}
	var rec sessionRecord
	db.Read(sessionTable, ids[0], &rec)

	restart := func() *OAuth2Router {
		ar.Close()
		ar = newRouterOn(t, db, testNodeUUID, false, idp)
		b.ar = ar
		return ar
	}
	// flip one ciphertext bit
	bad := rec
	bad.Blob = append([]byte(nil), rec.Blob...)
	bad.Blob[len(bad.Blob)-1] ^= 1
	db.Write(sessionTable, ids[0], bad)
	restart()
	if authed(b, appURL+"/") {
		t.Fatal("tampered record accepted")
	}
	if db.KeyExists(sessionTable, ids[0]) {
		t.Fatal("tampered record not removed")
	}

	// a valid record moved to another session id (AAD binds the id) is refused
	b2 := newBrowser(t, ar)
	mustLogin(t, b2, idp)
	b3 := newBrowser(t, ar)
	mustLogin(t, b3, idp)
	ids = storedSessionIDs(t, db)
	if len(ids) != 2 {
		t.Fatal(ids)
	}
	var r0, r1 sessionRecord
	db.Read(sessionTable, ids[0], &r0)
	db.Read(sessionTable, ids[1], &r1)
	db.Write(sessionTable, ids[1], r0) //record 0 stored under id 1
	restart()
	b2.ar, b3.ar = ar, ar
	if authed(b2, appURL+"/") && authed(b3, appURL+"/") {
		t.Fatal("a record moved to another id was accepted")
	}

	// extending the plaintext expiry does not extend the session (the sealed expiry is authoritative)
	b4 := newBrowser(t, ar)
	mustLogin(t, b4, idp)
	for _, id := range storedSessionIDs(t, db) {
		var r sessionRecord
		db.Read(sessionTable, id, &r)
		r.Prov = "other"
		db.Write(sessionTable, id, r) //plaintext provider label is only a purge hint
	}
	restart()
	b4.ar = ar
	if !authed(b4, appURL+"/") {
		t.Fatal("the plaintext provider hint must not affect validation")
	}
}

func TestLogoutRevokesPersistedSession(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	ar := newRouterOn(t, db, testNodeUUID, false, idp)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	saved := *b.cookies[sessionCookie]
	if w, _ := b.do(b.request("GET", appURL+"/internal/oauth2/logout")); w.Code != http.StatusFound {
		t.Fatalf("logout: %d", w.Code)
	}
	if n := len(storedSessionIDs(t, db)); n != 0 {
		t.Fatalf("session record left after logout: %d", n)
	}
	// replaying the old cookie, also after a restart, fails
	ar.Close()
	ar2 := newRouterOn(t, db, testNodeUUID, false, idp)
	replay := newBrowser(t, ar2)
	replay.cookies[sessionCookie] = &saved
	if authed(replay, appURL+"/") {
		t.Fatal("logged out session replayed")
	}
}

func TestPersistedSessionExpiryAndBound(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	ar := newRouterOn(t, db, testNodeUUID, false, idp)
	p := ar.store.persist
	p.max = 3

	mk := func(i int, hard time.Duration) *session {
		return &session{
			id: "id-" + string(rune('a'+i)), provider: DefaultProviderID, host: "app.example.com", claims: map[string]any{"sub": "u"},
			accessExpiry: time.Now().Add(hard), hardExpiry: time.Now().Add(hard),
		}
	}
	for i := 0; i < 6; i++ {
		p.save(mk(i, time.Duration(i+1)*time.Hour))
	}
	if n := len(storedSessionIDs(t, db)); n > 3 {
		t.Fatalf("table not bounded: %d", n)
	}
	// the sessions with the latest expiry are the ones kept
	kept := storedSessionIDs(t, db)
	for _, id := range kept {
		if id == "id-a" || id == "id-b" {
			t.Fatalf("earliest expiry should be dropped first, kept %v", kept)
		}
	}
	// expired records are cleaned up and never loaded
	p.save(mk(9, -time.Hour))
	p.cleanup()
	for _, id := range storedSessionIDs(t, db) {
		if id == "id-j" {
			t.Fatal("expired record survived the cleanup")
		}
	}
	p.now = func() time.Time { return time.Now().Add(100 * time.Hour) }
	p.cleanup()
	if n := len(storedSessionIDs(t, db)); n != 0 {
		t.Fatalf("all records expired, %d left", n)
	}
	// an expired record read directly is not returned
	p.now = time.Now
	p.save(mk(1, time.Hour))
	p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if p.load("id-b") != nil {
		t.Fatal("expired record loaded")
	}
}

func TestSessionsNotPersistedWithoutStableKey(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	ar := newRouterOn(t, db, "", false, idp)
	if ar.store.persist != nil {
		t.Fatal("a random per-process key must not be used for persistence")
	}
	mustLogin(t, newBrowser(t, ar), idp)
	if db.TableExists(sessionTable) && len(storedSessionIDs(t, db)) != 0 {
		t.Fatal("session stored")
	}
}

func TestClusterSecretSharedSessionAcrossNodes(t *testing.T) {
	idp := newFakeIdP(t)
	shared := "shared-key-material-derived-from-cluster-secret"
	nodeA := newRouterOn(t, newTestDB(t), shared, true, idp)
	nodeB := newRouterOn(t, newTestDB(t), shared, true, idp)
	b := newBrowser(t, nodeA)
	mustLogin(t, b, idp)
	if b.cookies[ticketCookie] == nil {
		t.Fatal("no portable ticket issued with a shared key")
	}
	if len(b.cookies[ticketCookie].Value) > ticketMaxBytes {
		t.Fatal("ticket too large")
	}
	for _, needle := range []string{"alice", "a@example.com"} {
		if strings.Contains(b.cookies[ticketCookie].Value, needle) {
			t.Fatal("ticket is not encrypted")
		}
	}

	// Node B has never seen this session but accepts it through the ticket
	b.ar = nodeB
	before := idp.refreshCount
	hdr := b.request("GET", appURL+"/dash")
	if _, err := b.do(hdr); err != nil {
		t.Fatal("node B refused a session of node A")
	}
	if idp.refreshCount != before {
		t.Fatal("unexpected refresh")
	}
	// the rebuilt session has no refresh token (those never leave the issuing node) and ends with the ticket
	for _, item := range nodeB.store.sessions.Items() {
		s := item.Value()
		if s.refreshToken != "" || s.idToken != "" {
			t.Fatal("tokens must not travel in the ticket")
		}
		if time.Until(s.hardExpiry) > ticketMaxLife+time.Minute {
			t.Fatalf("ticket session lives too long: %v", time.Until(s.hardExpiry))
		}
	}
	// node B now has the session itself (persisted), the ticket is no longer needed there
	delete(b.cookies, ticketCookie)
	if !authed(b, appURL+"/dash") {
		t.Fatal("session not kept on node B")
	}

	// without the ticket a node that never saw the session sends the user to login
	nodeC := newRouterOn(t, newTestDB(t), shared, true, idp)
	c := newBrowser(t, nodeC)
	c.cookies[sessionCookie] = b.cookies[sessionCookie]
	if authed(c, appURL+"/dash") {
		t.Fatal("node C accepted a session id it has no record of")
	}

	// a node with a different cluster secret accepts neither
	foreign := newRouterOn(t, newTestDB(t), "another-cluster-secret-material-xxxxxxxx", true, idp)
	f := newBrowser(t, foreign)
	for _, c := range b.cookies {
		f.cookies[c.Name] = c
	}
	f.cookies[ticketCookie] = &http.Cookie{Name: ticketCookie, Value: "x"}
	if authed(f, appURL+"/dash") {
		t.Fatal("foreign cluster accepted the session")
	}
}

func TestTicketRejectedWhenTamperedForeignOrExpired(t *testing.T) {
	idp := newFakeIdP(t)
	shared := "shared-key-material-derived-from-cluster-secret"
	nodeA := newRouterOn(t, newTestDB(t), shared, true, idp)
	b := newBrowser(t, nodeA)
	mustLogin(t, b, idp)
	ticket := b.cookies[ticketCookie].Value
	sess := b.cookies[sessionCookie]

	try := func(sc, tc *http.Cookie) bool {
		n := newRouterOn(t, newTestDB(t), shared, true, idp)
		x := newBrowser(t, n)
		x.cookies[sessionCookie], x.cookies[ticketCookie] = sc, tc
		return authed(x, appURL+"/")
	}
	if !try(sess, b.cookies[ticketCookie]) {
		t.Fatal("control: valid cookies refused")
	}
	flipped := []byte(ticket)
	if flipped[20] == 'A' {
		flipped[20] = 'B'
	} else {
		flipped[20] = 'A'
	}
	if try(sess, &http.Cookie{Name: ticketCookie, Value: string(flipped)}) {
		t.Fatal("tampered ticket accepted")
	}
	// a ticket of another session id cannot be combined with this session cookie
	other := newBrowser(t, nodeA)
	mustLogin(t, other, idp)
	if try(sess, other.cookies[ticketCookie]) {
		t.Fatal("ticket of another session accepted")
	}
	// expired ticket
	s := &session{id: "x", provider: DefaultProviderID, host: "app.example.com", claims: map[string]any{"sub": "u"},
		accessExpiry: time.Now().Add(-time.Second), hardExpiry: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(ticketPayload{SID: "x", Provider: s.provider, Host: s.host, Claims: s.claims, Exp: time.Now().Add(-time.Second).Unix()})
	expired := encodeTicketForTest(nodeA.store, "x", raw)
	if nodeA.store.openTicket(expired, "x", "", "app.example.com") != nil {
		t.Fatal("expired ticket accepted")
	}
	// a ticket is bound to the host
	if nodeA.store.openTicket(ticket, "ignored", "", "app.example.com") != nil {
		t.Fatal("ticket accepted for another session id")
	}
}

func encodeTicketForTest(s *sessionStore, sid string, raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(seal(s.ticketAEAD(), "ticket|"+sid, raw))
}

func TestTicketsOffWithoutSharedKey(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	if b.cookies[ticketCookie] != nil {
		t.Fatal("tickets must only exist with a cluster secret")
	}
}
