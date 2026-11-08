package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

/*
	password.go

	Password hashing for the admin account, basic auth credentials and
	ZorxAuth users.

	New hashes are argon2id with a random per-password salt, stored as a
	self-describing string:

		$argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>

	Hashes written by older versions are unsalted hex SHA-512 (128 chars).
	They keep verifying, and VerifyPassword reports needsRehash=true so the
	caller can transparently re-store them as argon2id after a successful
	login. No database layout change is involved, only the stored string.
*/

// PasswordProfile are the argon2id cost parameters
type PasswordProfile struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

var (
	// ProfileAdmin is used for the admin account and ZorxAuth users, which are
	// only verified at login time
	ProfileAdmin = PasswordProfile{MemoryKiB: 64 * 1024, Time: 3, Threads: 2}

	// ProfileBasicAuth is a cheaper profile (OWASP minimum, 19 MiB / t=2 / p=1)
	// for basic auth credentials. Basic auth is checked on every request, see
	// the verified-credential cache in the dynamicproxy package
	ProfileBasicAuth = PasswordProfile{MemoryKiB: 19 * 1024, Time: 2, Threads: 1}
)

const (
	argon2SaltLen = 16
	argon2KeyLen  = 32

	// Sanity limits for parameters read back from storage
	argon2MaxMemoryKiB = 1024 * 1024
	argon2MaxTime      = 16
)

// argon2Slots bounds how many argon2 computations run at once so a burst of
// logins cannot allocate (slots x memory) without limit
var argon2Slots = make(chan struct{}, 4)

func argon2idKey(password string, salt []byte, memKiB, timeCost uint32, threads uint8, keyLen uint32) []byte {
	argon2Slots <- struct{}{}
	defer func() { <-argon2Slots }()
	return argon2.IDKey([]byte(password), salt, timeCost, memKiB, threads, keyLen)
}

// HashPassword hashes a password with argon2id (admin profile)
func HashPassword(raw string) string {
	return HashPasswordWithProfile(raw, ProfileAdmin)
}

// HashPasswordWithProfile hashes a password with argon2id and a fresh random salt
func HashPasswordWithProfile(raw string, p PasswordProfile) string {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		//No entropy source: refusing is safer than storing an unsalted hash
		panic("auth: unable to read random salt: " + err.Error())
	}
	key := argon2idKey(raw, salt, p.MemoryKiB, p.Time, p.Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

type parsedArgon2 struct {
	memKiB, timeCost uint32
	threads          uint8
	salt, key        []byte
}

func parseArgon2idHash(encoded string) (*parsedArgon2, bool) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, false
	}
	if m == 0 || m > argon2MaxMemoryKiB || t == 0 || t > argon2MaxTime || p == 0 {
		return nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return nil, false
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return nil, false
	}
	return &parsedArgon2{m, t, p, salt, key}, true
}

// IsLegacyPasswordHash reports whether the stored string is an old unsalted
// SHA-512 hex digest
func IsLegacyPasswordHash(stored string) bool {
	if len(stored) != sha512.Size*2 {
		return false
	}
	_, err := hex.DecodeString(stored)
	return err == nil
}

/*
VerifyPassword checks a password against a stored hash, either argon2id or the
legacy unsalted SHA-512. All comparisons are constant time.

needsRehash is true only when the password was correct and the stored hash is
legacy or weaker than the given profile, i.e. the caller should store
HashPasswordWithProfile(raw, profile) in its place.
*/
func VerifyPassword(raw string, stored string, profile PasswordProfile) (ok bool, needsRehash bool) {
	if stored == "" {
		return false, false
	}

	if strings.HasPrefix(stored, "$argon2id$") {
		parsed, valid := parseArgon2idHash(stored)
		if !valid {
			return false, false
		}
		key := argon2idKey(raw, parsed.salt, parsed.memKiB, parsed.timeCost, parsed.threads, uint32(len(parsed.key)))
		if subtle.ConstantTimeCompare(key, parsed.key) != 1 {
			return false, false
		}
		weaker := parsed.memKiB < profile.MemoryKiB || parsed.timeCost < profile.Time || parsed.threads < profile.Threads
		return true, weaker
	}

	if IsLegacyPasswordHash(stored) {
		if subtle.ConstantTimeCompare([]byte(Hash(raw)), []byte(strings.ToLower(stored))) == 1 {
			return true, true
		}
	}
	return false, false
}
