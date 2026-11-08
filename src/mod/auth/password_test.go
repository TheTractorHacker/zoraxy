package auth

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	db "imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

// fast profile so unit tests stay quick
var testProfile = PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}

func TestHashPassword_FormatAndParams(t *testing.T) {
	h := HashPassword("hunter2")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected encoding/params: %s", h)
	}
	if strings.Count(h, "$") != 5 {
		t.Fatalf("not self describing: %s", h)
	}
	if h == HashPassword("hunter2") {
		t.Fatal("hashes of the same password must differ (random salt)")
	}
	if ok, rehash := VerifyPassword("hunter2", h, ProfileAdmin); !ok || rehash {
		t.Fatalf("fresh hash should verify without rehash: ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := VerifyPassword("hunter3", h, ProfileAdmin); ok {
		t.Fatal("wrong password accepted")
	}
}

func TestVerifyPassword_LegacySHA512(t *testing.T) {
	legacy := Hash("oldpass")
	if !IsLegacyPasswordHash(legacy) {
		t.Fatal("Hash output should be recognised as legacy")
	}
	ok, rehash := VerifyPassword("oldpass", legacy, ProfileAdmin)
	if !ok || !rehash {
		t.Fatalf("legacy hash must verify and request upgrade: ok=%v rehash=%v", ok, rehash)
	}
	if ok, rehash := VerifyPassword("nope", legacy, ProfileAdmin); ok || rehash {
		t.Fatal("wrong password against legacy hash must fail without upgrade")
	}
}

func TestVerifyPassword_RejectsGarbage(t *testing.T) {
	for _, stored := range []string{"", "plain", "$argon2id$", "$argon2id$v=19$m=0,t=0,p=0$AAAA$AAAA", "$argon2id$v=19$m=99999999,t=3,p=2$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if ok, _ := VerifyPassword("x", stored, ProfileAdmin); ok {
			t.Errorf("garbage hash %q accepted", stored)
		}
	}
}

func TestVerifyPassword_WeakerParamsRequestRehash(t *testing.T) {
	h := HashPasswordWithProfile("pw", testProfile)
	ok, rehash := VerifyPassword("pw", h, ProfileAdmin)
	if !ok || !rehash {
		t.Fatalf("weaker params should verify and request rehash: ok=%v rehash=%v", ok, rehash)
	}
}

func newTestAgent(t *testing.T) *AuthAgent {
	t.Helper()
	sysdb, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sysdb.Close() })
	lg, _ := logger.NewFmtLogger()
	return NewAuthenticationAgent("test", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, nil)
}

var _ = sessions.NewCookieStore

// A legacy admin hash already in the DB keeps working and is upgraded on login
func TestAdminLogin_LegacyHashMigrates(t *testing.T) {
	a := newTestAgent(t)
	if err := a.Database.Write("auth", "passhash/admin", Hash("secret")); err != nil {
		t.Fatal(err)
	}

	if ok := a.ValidateUsernameAndPassword("admin", "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	var stored string
	a.Database.Read("auth", "passhash/admin", &stored)
	if !IsLegacyPasswordHash(stored) {
		t.Fatal("failed login must not touch the stored hash")
	}

	if ok := a.ValidateUsernameAndPassword("admin", "secret"); !ok {
		t.Fatal("legacy hash must keep verifying")
	}
	a.Database.Read("auth", "passhash/admin", &stored)
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Fatalf("hash not upgraded after login: %s", stored)
	}
	if ok := a.ValidateUsernameAndPassword("admin", "secret"); !ok {
		t.Fatal("upgraded hash must verify")
	}
	if ok := a.ValidateUsernameAndPassword("admin", "wrong"); ok {
		t.Fatal("wrong password accepted after upgrade")
	}
}

// The -reset_ac flow drops the auth table; a new account must then work
func TestResetAccountFlow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sys")
	backend := "auto"
	sysdb, err := db.NewDatabase(dir, db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	lg, _ := logger.NewFmtLogger()
	a := NewAuthenticationAgent("test", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, nil)
	if err := a.CreateUserAccount("admin", "pw-one", ""); err != nil {
		t.Fatal(err)
	}
	sysdb.Close()

	ResetAccount(&backend, &dir)

	sysdb, err = db.NewDatabase(dir, db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sysdb.Close()
	a = NewAuthenticationAgent("test", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, nil)
	if a.UserExists("admin") {
		t.Fatal("reset must remove users")
	}
	if err := a.CreateUserAccount("admin", "pw-two", ""); err != nil {
		t.Fatal(err)
	}
	if !a.ValidateUsernameAndPassword("admin", "pw-two") || a.ValidateUsernameAndPassword("admin", "pw-one") {
		t.Fatal("new account after reset not working")
	}
}
