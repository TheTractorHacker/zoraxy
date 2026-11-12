package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	db "imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/info/logger"
)

// seeded BoltDB with a big and a small table behind the real managed router: an admin gets the sorted
// table list, a viewer and an anonymous request never reach the handler.
func TestDatabaseUsageEndpoint(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sys.db")
	oldPath, oldDB, oldAgent := path_database, sysdb, authAgent
	t.Cleanup(func() { path_database, sysdb, authAgent = oldPath, oldDB, oldAgent })
	path_database = &file

	d, err := db.NewDatabase(file, dbinc.BackendBoltDB)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	sysdb = d
	for i := 0; i < 50; i++ {
		d.Write("stats", fmt.Sprintf("2026_01_%02d", i), strings.Repeat("s", 4000))
	}
	for i := 0; i < 5; i++ {
		d.Write("settings", fmt.Sprint(i), true)
	}

	lg, _ := logger.NewFmtLogger()
	old := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	defer func() { auth.ProfileAdmin = old }()
	authAgent = auth.NewAuthenticationAgent("t", []byte("0123456789abcdef0123456789abcdef"), d, false, lg, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login.html", http.StatusTemporaryRedirect)
	})
	authAgent.CreateUserAccount("root", "password-1", "")
	authAgent.CreateUser("view", "password-2", auth.RoleViewer)
	mux := http.NewServeMux()
	rt := auth.NewManagedHTTPRouter(auth.RouterOption{AuthAgent: authAgent, RequireAuth: true, TargetMux: mux})
	RegisterDatabaseUsageAPIs(rt)

	login := func(user, pw string) *http.Cookie {
		form := url.Values{"username": {user}, "password": {pw}}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authAgent.HandleLogin(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == authAgent.SessionName && c.Value != "" {
				return c
			}
		}
		t.Fatal("login failed for " + user)
		return nil
	}
	get := func(c *http.Cookie, method string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/system/dbusage", nil)
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// admin
	w := get(login("root", "password-1"), "GET")
	if w.Code != 200 {
		t.Fatalf("admin: status %d: %s", w.Code, w.Body.String())
	}
	var resp dbUsageResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Supported || resp.Backend != "BoltDB" || resp.Usage == nil || resp.Usage.FileBytes <= 0 || resp.LargeBytes != 200<<20 {
		t.Fatalf("unexpected response %+v", resp)
	}
	if !filepath.IsAbs(resp.Path) {
		t.Fatalf("path should be absolute: %s", resp.Path)
	}
	tb := resp.Usage.Tables
	if len(tb) < 2 || tb[0].Name != "stats" || tb[0].Keys != 50 || tb[0].Bytes < 50*4000 {
		t.Fatalf("stats must be first with 50 keys: %+v", tb)
	}
	var settings *struct{ keys int64 }
	for _, x := range tb {
		if x.Name == "settings" {
			settings = &struct{ keys int64 }{x.Keys}
		}
	}
	if settings == nil || settings.keys != 5 {
		t.Fatalf("settings table missing or wrong: %+v", tb)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response must not be cached")
	}

	// the endpoint is read only
	if w := get(login("root", "password-1"), "POST"); w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusForbidden {
		t.Errorf("POST: %d", w.Code)
	}
	// viewer: refused at the router, nothing about the database leaks
	if w := get(login("view", "password-2"), "GET"); w.Code != http.StatusForbidden || bytes.Contains(w.Body.Bytes(), []byte("stats")) {
		t.Errorf("viewer GET: status %d body %q", w.Code, w.Body.String())
	}
	// anonymous: not the handler
	if w := get(nil, "GET"); w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte("stats")) {
		t.Errorf("anonymous GET: status %d", w.Code)
	}
	// and the handler itself refuses a viewer when called directly
	r := httptest.NewRequest("GET", "/api/system/dbusage", nil)
	r.AddCookie(login("view", "password-2"))
	rec := httptest.NewRecorder()
	HandleDatabaseUsage(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("handler without the router: %d", rec.Code)
	}
}

func TestRunCompactDatabase(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sys.db")
	d, err := db.NewDatabase(file, dbinc.BackendBoltDB)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		d.Write("t", fmt.Sprint(i), strings.Repeat("z", 3000))
	}
	for i := 0; i < 290; i++ {
		d.Delete("t", fmt.Sprint(i))
	}

	// refused while the database is open (locked); the original stays
	var out, errOut bytes.Buffer
	if code := runCompactDatabase(file, "boltdb", &out, &errOut); code == 0 {
		t.Fatal("must refuse a locked database")
	}
	if !strings.Contains(errOut.String(), "sudo lsof "+file) || !strings.Contains(errOut.String(), "was not changed") {
		t.Fatalf("stderr: %s", errOut.String())
	}
	d.Close()

	out.Reset()
	errOut.Reset()
	if code := runCompactDatabase(file, "boltdb", &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"Backup of the old database:", "all verified", "1 tables, 10 keys"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if code := runCompactDatabase(file, "leveldb", &out, &errOut); code == 0 {
		t.Error("leveldb must be refused")
	}
}

// repeated calls inside the TTL reuse one walk (no new read transaction), and a different
// database never gets another one's cached answer
func TestDatabaseUsageIsCached(t *testing.T) {
	oldDB := sysdb
	t.Cleanup(func() { sysdb = oldDB; dbUsageCache.Lock(); dbUsageCache.owner = nil; dbUsageCache.Unlock() })
	open := func() *db.Database {
		d, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys.db"), dbinc.BackendBoltDB)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	}
	a, b := open(), open()
	a.Write("one", "k", "v")
	sysdb = a
	u1, err := cachedDatabaseUsage()
	if err != nil {
		t.Fatal(err)
	}
	a.Write("two", "k", "v") //a new table after the first walk
	u2, _ := cachedDatabaseUsage()
	if u1 != u2 {
		t.Error("the second call inside the TTL must return the cached result")
	}
	sysdb = b
	u3, _ := cachedDatabaseUsage()
	if u3 == u1 {
		t.Error("another database must not get the cached result")
	}
	sysdb = a
	dbUsageCache.Lock()
	dbUsageCache.at = time.Now().Add(-2 * dbUsageCacheTTL)
	dbUsageCache.owner = a
	dbUsageCache.Unlock()
	if u4, _ := cachedDatabaseUsage(); u4 == u1 {
		t.Error("an expired entry must be refreshed")
	}
}
