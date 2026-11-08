package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
	altcha.go

	Altcha provider (upstream #1198): a self-hosted proof-of-work CAPTCHA, no external service.

	  1. The page asks GET AltchaChallengePath. The server answers with a random salt, a secret
	     number n in [0, maxnumber], challenge = SHA-256(salt + n) and signature = HMAC-SHA-256(secret, challenge).
	     The salt carries an expiry ("?expires=<unix>").
	  2. The browser searches n by hashing (the "work"), then POSTs base64(JSON{algorithm, challenge,
	     number, salt, signature}) as form field "altcha" to the normal verify path.
	  3. The server recomputes the hash, verifies the HMAC (constant time), the expiry, and that the
	     challenge was not used before (bounded replay cache), then issues the usual signed session cookie.

	The Config.SecretKey is the HMAC key (use a long random string); Config.SiteKey is unused.
	Compatible with the Altcha widget payload format; the built-in challenge page ships its own small
	solver, so nothing is loaded from a third party.
*/

const (
	// AltchaChallengePath serves challenges
	AltchaChallengePath = "/.zoraxy/captcha/altcha"
	// AltchaField is the form field the solved payload is POSTed as
	AltchaField = "altcha"

	DefaultAltchaMaxNumber = 100000
	MinAltchaMaxNumber     = 1000
	MaxAltchaMaxNumber     = 2000000
	altchaTTL              = 5 * time.Minute
	altchaReplayMax        = 20000
	altchaMaxPayload       = 2048
)

var errAltcha = errors.New("verification failed: invalid proof of work")

type altchaReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var altchaUsed = &altchaReplay{seen: map[string]time.Time{}}

// markUsed returns false if the challenge was already redeemed
func (a *altchaReplay) markUsed(challenge string, exp time.Time, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, dup := a.seen[challenge]; dup {
		return false
	}
	if len(a.seen) >= altchaReplayMax {
		for k, e := range a.seen {
			if now.After(e) {
				delete(a.seen, k)
			}
		}
		if len(a.seen) >= altchaReplayMax {
			return false //full of live entries: refuse rather than allow replays
		}
	}
	a.seen[challenge] = exp
	return true
}

// AltchaChallenge is the JSON sent to the widget / page
type AltchaChallenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
	MaxNumber int    `json:"maxnumber"`
}

func altchaHMAC(secret, challenge string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(challenge))
	return hex.EncodeToString(m.Sum(nil))
}

func altchaHash(salt string, number int) string {
	h := sha256.Sum256([]byte(salt + strconv.Itoa(number)))
	return hex.EncodeToString(h[:])
}

func clampAltchaMax(n int) int {
	if n <= 0 {
		return DefaultAltchaMaxNumber
	}
	if n < MinAltchaMaxNumber {
		return MinAltchaMaxNumber
	}
	if n > MaxAltchaMaxNumber {
		return MaxAltchaMaxNumber
	}
	return n
}

// NewAltchaChallenge creates a signed challenge
func NewAltchaChallenge(secret string, maxNumber int, now time.Time) (*AltchaChallenge, error) {
	if secret == "" {
		return nil, errors.New("altcha needs a secret key")
	}
	maxNumber = clampAltchaMax(maxNumber)
	rnd := make([]byte, 12)
	if _, err := rand.Read(rnd); err != nil {
		return nil, err
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	secretNumber := int((uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % uint32(maxNumber+1))
	salt := hex.EncodeToString(rnd) + "?expires=" + strconv.FormatInt(now.Add(altchaTTL).Unix(), 10)
	ch := altchaHash(salt, secretNumber)
	return &AltchaChallenge{Algorithm: "SHA-256", Challenge: ch, Salt: salt, Signature: altchaHMAC(secret, ch), MaxNumber: maxNumber}, nil
}

// HandleAltchaChallenge answers GET AltchaChallengePath
func HandleAltchaChallenge(w http.ResponseWriter, r *http.Request, config *Config) {
	if r.Method != http.MethodGet || config == nil || config.Provider != ProviderAltcha {
		http.NotFound(w, r)
		return
	}
	ch, err := NewAltchaChallenge(config.SecretKey, config.AltchaMaxNumber, time.Now())
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(ch)
}

type altchaPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// VerifyAltcha checks a solved payload (base64 JSON as produced by the widget)
func VerifyAltcha(payload, secret string, now time.Time) error {
	if secret == "" || payload == "" || len(payload) > altchaMaxPayload {
		return errAltcha
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(payload))
		if err != nil {
			return errAltcha
		}
	}
	var p altchaPayload
	if err := json.Unmarshal(raw, &p); err != nil || !strings.EqualFold(p.Algorithm, "SHA-256") {
		return errAltcha
	}
	if p.Number < 0 || p.Number > MaxAltchaMaxNumber || len(p.Salt) > 128 || len(p.Challenge) != 64 {
		return errAltcha
	}
	//Signature first (constant time): proves the server issued this challenge
	want := altchaHMAC(secret, p.Challenge)
	if subtle.ConstantTimeCompare([]byte(want), []byte(strings.ToLower(p.Signature))) != 1 {
		return errAltcha
	}
	//Expiry from the (now authenticated through the challenge hash) salt
	var exp time.Time
	if i := strings.Index(p.Salt, "?expires="); i >= 0 {
		unix, err := strconv.ParseInt(p.Salt[i+len("?expires="):], 10, 64)
		if err != nil {
			return errAltcha
		}
		exp = time.Unix(unix, 0)
	} else {
		return errAltcha //we always issue an expiry
	}
	if now.After(exp) {
		return fmt.Errorf("verification failed: challenge expired")
	}
	//The work: the number must hash (with the salt) to the signed challenge
	if subtle.ConstantTimeCompare([]byte(altchaHash(p.Salt, p.Number)), []byte(strings.ToLower(p.Challenge))) != 1 {
		return errAltcha
	}
	if !altchaUsed.markUsed(strings.ToLower(p.Challenge), exp, now) {
		return fmt.Errorf("verification failed: challenge already used")
	}
	return nil
}
