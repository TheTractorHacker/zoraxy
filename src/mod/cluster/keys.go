// Package cluster implements the optional high availability features of
// Zoraxy: a shared secret for node independent session keys, a health
// endpoint for external load balancers and a primary to follower
// configuration sync.
//
// Everything here is inert unless the operator opts in. With no cluster
// secret configured, KeyMaterial returns its input unchanged so every key
// derived from the node UUID stays byte-identical to earlier releases.
package cluster

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Key derivation purposes. Each purpose yields an independent key from the
// same cluster secret (HKDF domain separation), so a leak of one derived key
// does not expose the others.
const (
	PurposeCaptchaSession = "captcha-session"
	PurposeStickySession  = "lb-sticky-session"
	PurposeSyncToken      = "sync-token"
	PurposeSyncSign       = "sync-signature"
	PurposeSyncEncrypt    = "sync-encryption"
	PurposeFingerprint    = "secret-fingerprint"
)

// MinSecretLength is the shortest accepted cluster secret (characters).
// Generated secrets are 32 random bytes in hex (64 characters).
const MinSecretLength = 32

const hkdfSalt = "zoraxy-cluster-v1"

// DeriveKey derives n bytes for the given purpose from the cluster secret
// using HKDF-SHA256.
func DeriveKey(secret string, purpose string, n int) []byte {
	k, err := hkdf.Key(sha256.New, []byte(secret), []byte(hkdfSalt), purpose, n)
	if err != nil {
		panic("cluster: hkdf failed: " + err.Error())
	}
	return k
}

// KeyMaterial returns the string to use where a session key was previously
// derived from the node UUID. Without a cluster secret it returns nodeUUID
// unchanged. With one it returns a purpose-specific key (hex) that is
// identical on every node sharing the secret.
func KeyMaterial(clusterSecret, nodeUUID, purpose string) string {
	if clusterSecret == "" {
		return nodeUUID
	}
	return hex.EncodeToString(DeriveKey(clusterSecret, purpose, 32))
}

// GenerateSecret returns a new random cluster secret: 32 random bytes, hex.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateSecret rejects secrets that are too short to be safe.
func ValidateSecret(s string) error {
	if len(s) < MinSecretLength {
		return errors.New("cluster secret must be at least 32 characters (use the generate button or `-cluster_gen_secret`)")
	}
	return nil
}

// Fingerprint returns a short non-reversible identifier of the secret so
// operators can compare secrets across nodes without displaying them.
func Fingerprint(secret string) string {
	if secret == "" {
		return ""
	}
	return hex.EncodeToString(DeriveKey(secret, PurposeFingerprint, 4))
}
