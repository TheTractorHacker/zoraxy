package waf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

/*
	config.go

	Per-endpoint WAF configuration. A nil *Config (or Mode "off") means the
	WAF is disabled for the endpoint and the request path costs a nil check.
*/

const (
	ModeOff           = "off"
	ModeDetectionOnly = "detection_only"
	ModeBlock         = "block"

	DefaultParanoiaLevel    = 1
	DefaultInboundThreshold = 5
	DefaultMaxBodyBytes     = 128 * 1024
	MaxAllowedBodyBytes     = 64 * 1024 * 1024
)

// PathExclusion disables the given rules for requests whose path matches
type PathExclusion struct {
	Path    string   // Request path, must start with "/"
	Exact   bool     // Match the path exactly instead of as a prefix
	RuleIDs []string // Rule IDs or ranges (e.g. "942100" or "942100-942199")
}

// Config is the WAF configuration stored in a ProxyEndpoint
type Config struct {
	Mode             string          // off (default), detection_only, block
	ParanoiaLevel    int             // CRS paranoia level 1-4, default 1
	InboundThreshold int             // CRS inbound anomaly score threshold, default 5
	MaxBodyBytes     int64           // Request body inspection limit in bytes, default 128 KiB
	ExcludedRuleIDs  []string        // Rules disabled for the whole endpoint
	PathExclusions   []PathExclusion // Rules disabled for specific paths
	CustomRules      string          // Extra SecLang directives, validated on save
}

var (
	ruleIDPattern = regexp.MustCompile(`^[0-9]{1,9}(-[0-9]{1,9})?$`)
	// Directives that are managed by the settings above, or that would let a
	// rule author touch the filesystem or change engine behaviour globally.
	forbiddenDirective = regexp.MustCompile(`(?i)^\s*(include|secruleengine|secrequestbody\w*|secresponsebody\w*|secaudit\w*|secdebug\w*|secdatadir|secuploaddir|sectmpdir|secargumentslimit|secconnengine|secwebappid|secdefaultaction)\b`)
)

// Enabled reports whether the config turns the WAF on
func (c *Config) Enabled() bool {
	return c != nil && (c.Mode == ModeDetectionOnly || c.Mode == ModeBlock)
}

// Normalize returns a copy with defaults applied
func (c *Config) Normalize() Config {
	var n Config
	if c != nil {
		n = *c
	}
	n.Mode = strings.ToLower(strings.TrimSpace(n.Mode))
	if n.Mode == "" {
		n.Mode = ModeOff
	}
	if n.ParanoiaLevel == 0 {
		n.ParanoiaLevel = DefaultParanoiaLevel
	}
	if n.InboundThreshold <= 0 {
		n.InboundThreshold = DefaultInboundThreshold
	}
	if n.MaxBodyBytes <= 0 {
		n.MaxBodyBytes = DefaultMaxBodyBytes
	}
	n.ExcludedRuleIDs = append([]string(nil), n.ExcludedRuleIDs...)
	n.PathExclusions = append([]PathExclusion(nil), n.PathExclusions...)
	n.CustomRules = strings.TrimSpace(n.CustomRules)
	return n
}

// Validate checks everything that can be checked without compiling rules
func (c *Config) Validate() error {
	n := c.Normalize()
	switch n.Mode {
	case ModeOff, ModeDetectionOnly, ModeBlock:
	default:
		return fmt.Errorf("invalid WAF mode %q", n.Mode)
	}
	if n.ParanoiaLevel < 1 || n.ParanoiaLevel > 4 {
		return errors.New("paranoia level must be between 1 and 4")
	}
	if n.InboundThreshold > 10000 {
		return errors.New("anomaly threshold is too large")
	}
	if n.MaxBodyBytes > MaxAllowedBodyBytes {
		return fmt.Errorf("body inspection limit must not exceed %d bytes", MaxAllowedBodyBytes)
	}
	for _, id := range n.ExcludedRuleIDs {
		if !ruleIDPattern.MatchString(strings.TrimSpace(id)) {
			return fmt.Errorf("invalid rule ID %q", id)
		}
	}
	for _, pe := range n.PathExclusions {
		if !strings.HasPrefix(pe.Path, "/") || strings.ContainsAny(pe.Path, "\"\\\r\n\x00") {
			return fmt.Errorf("invalid exclusion path %q (must start with / and not contain quotes or backslashes)", pe.Path)
		}
		if len(pe.RuleIDs) == 0 {
			return fmt.Errorf("path exclusion %q has no rule IDs", pe.Path)
		}
		for _, id := range pe.RuleIDs {
			if !ruleIDPattern.MatchString(strings.TrimSpace(id)) {
				return fmt.Errorf("invalid rule ID %q", id)
			}
		}
	}
	for i, line := range strings.Split(n.CustomRules, "\n") {
		if forbiddenDirective.MatchString(line) {
			return fmt.Errorf("custom rules line %d: directive not allowed here (%s)", i+1, strings.Fields(line)[0])
		}
		if strings.Contains(strings.ToLower(line), "fromfile") {
			return fmt.Errorf("custom rules line %d: file based operators are not allowed", i+1)
		}
	}
	return nil
}

// Hash returns a stable identifier of the effective configuration, used to
// share compiled WAF instances between endpoints with identical settings.
func (c *Config) Hash() string {
	n := c.Normalize()
	b, _ := json.Marshal(n)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
