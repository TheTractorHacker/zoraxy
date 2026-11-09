package waf

import (
	"fmt"
	"strings"
)

/*
	respconfig.go

	Configuration of response inspection (outbound data-leak detection).
	The detector itself lives in respinspect.go and respsignatures.go.

	A ResponseConfig is a sparse map: group -> action. A missing or empty
	action means "inherit". Policy, profile and endpoint overrides are merged
	per group, the most specific non-empty value wins (see MergeResponse).
*/

// Response protection groups
const (
	GroupStackTrace = "stacktrace" // stack traces and framework debug pages
	GroupDBError    = "dberror"    // database error messages
	GroupSecrets    = "secrets"    // private keys, API tokens, credentials
	GroupDirListing = "dirlisting" // "Index of /" style directory listings
	GroupHeaders    = "headers"    // Server / X-Powered-By / X-AspNet-Version banners
)

// Response actions
const (
	RespActionOff   = "off"
	RespActionLog   = "log"
	RespActionBlock = "block" // body groups only
	RespActionStrip = "strip" // headers group only
)

// Response inspection window, in KiB
const (
	DefaultResponseWindowKiB = 64
	MaxResponseWindowKiB     = 1024
)

// ResponseGroups lists the groups in display order
var ResponseGroups = []string{GroupStackTrace, GroupDBError, GroupSecrets, GroupDirListing, GroupHeaders}

// ResponseConfig is the response protection setting of a Config, Policy, Profile or Overrides
type ResponseConfig struct {
	WindowKiB int               `json:",omitempty"` // Bytes of the response body that are inspected (KiB), 0 = inherit / default 64, max 1024
	Groups    map[string]string `json:",omitempty"` // group -> off | log | block (strip for headers); "" / missing = inherit
}

func validResponseAction(group, action string) bool {
	switch action {
	case "", RespActionOff, RespActionLog:
		return true
	case RespActionBlock:
		return group != GroupHeaders
	case RespActionStrip:
		return group == GroupHeaders
	}
	return false
}

// Validate checks group names, actions and the window size. A nil config is valid.
func (rc *ResponseConfig) Validate() error {
	if rc == nil {
		return nil
	}
	if rc.WindowKiB < 0 || rc.WindowKiB > MaxResponseWindowKiB {
		return fmt.Errorf("response inspection window must be between 1 and %d KiB", MaxResponseWindowKiB)
	}
	for g, a := range rc.Groups {
		known := false
		for _, k := range ResponseGroups {
			if k == g {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("unknown response protection group %q", g)
		}
		if !validResponseAction(g, strings.ToLower(strings.TrimSpace(a))) {
			return fmt.Errorf("invalid action %q for response protection group %q", a, g)
		}
	}
	return nil
}

// Action returns the normalized action of a group ("" = not set)
func (rc *ResponseConfig) Action(group string) string {
	if rc == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(rc.Groups[group]))
}

// Active reports whether any group does something
func (rc *ResponseConfig) Active() bool {
	for _, g := range ResponseGroups {
		if a := rc.Action(g); a != "" && a != RespActionOff {
			return true
		}
	}
	return false
}

// MergeResponse overlays over on top of base per group. Either may be nil. The result is a new value
// (nil when both are nil) that never aliases its inputs.
func MergeResponse(base, over *ResponseConfig) *ResponseConfig {
	if base == nil && over == nil {
		return nil
	}
	out := &ResponseConfig{Groups: map[string]string{}}
	for _, src := range []*ResponseConfig{base, over} {
		if src == nil {
			continue
		}
		if src.WindowKiB > 0 {
			out.WindowKiB = src.WindowKiB
		}
		for g, a := range src.Groups {
			if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
				out.Groups[g] = a
			}
		}
	}
	return out
}

// resolveResponse applies the policy, profile and endpoint response settings to a resolved config.
// Called once from Resolve; the per-group override rule is documented in DEVELOPMENT.md.
func (s *State) resolveResponse(cfg *Config, prof *Profile, x *Overrides) {
	rc := MergeResponse(nil, s.Policy.Response)
	if prof != nil {
		rc = MergeResponse(rc, prof.Response)
	}
	if x != nil {
		rc = MergeResponse(rc, x.Response)
	}
	if rc.Active() {
		cfg.Response = rc
	}
}
