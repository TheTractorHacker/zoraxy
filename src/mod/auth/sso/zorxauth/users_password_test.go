package zorxauth

import (
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
)

func TestValidateUsername_LegacyHashVerifiesAndUpgrades(t *testing.T) {
	ar, _ := newTestGateway(t)
	if err := ar.saveUser(&User{ID: "bob-id", Username: "bob", Email: "bob@example.com", PasswordHash: auth.Hash("hunter22")}, ""); err != nil {
		t.Fatal(err)
	}

	if ar.ValidateUsername("bob", "wrong-password") {
		t.Fatal("wrong password accepted")
	}
	u, _ := ar.getUserByUsername("bob")
	if !auth.IsLegacyPasswordHash(u.PasswordHash) {
		t.Fatal("failed login must not change the stored hash")
	}

	if !ar.ValidateUsername("bob", "hunter22") {
		t.Fatal("legacy hash must keep verifying")
	}
	u, _ = ar.getUserByUsername("bob")
	if !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		t.Fatalf("hash not upgraded: %s", u.PasswordHash)
	}
	if u.Email != "bob@example.com" || u.ID != "bob-id" {
		t.Fatal("upgrade must only change the password hash")
	}
	if !ar.ValidateUsername("bob", "hunter22") || ar.ValidateUsername("bob", "wrong-password") {
		t.Fatal("upgraded hash verification broken")
	}
	if !ar.ValidateUsername("bob@example.com", "hunter22") {
		t.Fatal("login by email broken")
	}
}

func TestHashPassword_IsSaltedArgon2id(t *testing.T) {
	a, b := hashPassword("same"), hashPassword("same")
	if a == b || !strings.HasPrefix(a, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("expected salted argon2id, got %s", a)
	}
}
