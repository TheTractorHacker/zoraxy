package acme

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/plesk"
)

// newPleskProvider builds the lego Plesk DNS provider from the UI credentials.
//
// lego keeps the Plesk server URL in the unexported Config.baseURL field (it can
// only be set through the PLESK_SERVER_BASE_URL environment variable), so the
// generic JSON based provider factory silently drops it and fails with
// "plesk: missing server base URL" (upstream #1156). Set the field via reflection
// instead of mutating process wide environment variables.
func newPleskProvider(credentials map[string]any, propagationTimeout int, pollingInterval int) (challenge.Provider, error) {
	raw, err := json.Marshal(credentials)
	if err != nil {
		return nil, err
	}

	cfg := plesk.NewDefaultConfig()
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	cfg.PropagationTimeout = time.Duration(propagationTimeout) * time.Second
	cfg.PollingInterval = time.Duration(pollingInterval) * time.Second

	baseURL := ""
	for key, value := range credentials {
		if strings.EqualFold(key, "baseURL") {
			baseURL, _ = value.(string)
		}
	}

	field := reflect.ValueOf(cfg).Elem().FieldByName("baseURL")
	if !field.IsValid() || field.Kind() != reflect.String || !field.CanAddr() {
		return nil, errors.New("plesk: unsupported lego version, cannot set the server base URL")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().SetString(strings.TrimSpace(baseURL))

	return plesk.NewDNSProviderConfig(cfg)
}
