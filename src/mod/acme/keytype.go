package acme

import (
	"fmt"
	"strings"

	"github.com/go-acme/lego/v5/certcrypto"
)

// DefaultKeyType is the certificate key type used when nothing else is configured.
// It is the historic Zoraxy default and must not change silently.
const DefaultKeyType = "RSA2048"

// KeyTypeNames lists the key types a certificate (or CSR) can be requested with, in UI order.
var KeyTypeNames = []string{"RSA2048", "RSA3072", "RSA4096", "EC256", "EC384"}

// ParseKeyType maps a user facing key type name to the lego key type. The empty string means
// "use the default" and returns RSA2048. Names are case insensitive.
func ParseKeyType(name string) (certcrypto.KeyType, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "", "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA3072":
		return certcrypto.RSA3072, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "EC256":
		return certcrypto.EC256, nil
	case "EC384":
		return certcrypto.EC384, nil
	}
	return "", fmt.Errorf("unsupported key type %q (supported: %s)", name, strings.Join(KeyTypeNames, ", "))
}

// NormalizeKeyType returns the canonical spelling of a key type name ("" stays "").
func NormalizeKeyType(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", nil
	}
	if _, err := ParseKeyType(name); err != nil {
		return "", err
	}
	return strings.ToUpper(strings.TrimSpace(name)), nil
}
