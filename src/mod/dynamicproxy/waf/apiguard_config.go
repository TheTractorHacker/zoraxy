package waf

import (
	"fmt"
	"strings"
)

/*
	apiguard_config.go

	API protection configuration: structural limits for request bodies, a
	method / content type allow-list per path prefix and optional OpenAPI
	validation. It lives next to, not inside, the Coraza based WAF Config, so
	changing it never recompiles the Core Rule Set.

	Layers (policy, profile, proxy rule) are merged by MergeAPI.
*/

// Modes of the API protection. "" means "use the lower layer".
const (
	APIModeInherit = ""
	APIModeOff     = "off"
	APIModeLog     = "log"
	APIModeBlock   = "block"
)

// Defaults of the structural limits. A limit of 0 in APILimits means "default", -1 means "unlimited".
const (
	DefaultAPIMaxBodyBytes      = 1 << 20
	DefaultJSONMaxDepth         = 20
	DefaultJSONMaxKeys          = 1000
	DefaultJSONMaxArrayLen      = 10000
	DefaultJSONMaxStringLen     = 64 * 1024
	DefaultXMLMaxDepth          = 20
	DefaultXMLMaxElements       = 10000
	DefaultXMLMaxAttributes     = 50
	DefaultFormMaxFields        = 1000
	DefaultMultipartMaxParts    = 100
	DefaultMultipartMaxFiles    = 20
	DefaultQueryMaxParams       = 100
	DefaultQueryMaxParamLen     = 4096
	DefaultURLMaxLen            = 8192
	DefaultHeaderMaxCount       = 100
	DefaultHeaderMaxSize        = 8192
	MaxAPIBodyBytes             = 64 << 20
	maxAPILimitValue            = 10_000_000
	maxAPIDepthValue            = 1000
	hardNestingCap              = 10000 // recursion guard when the depth limit is "unlimited"
	MaxAPIAllowRules            = 200
	MaxOpenAPISpecBytes         = 2 << 20
	maxAPIAllowListEntryLength  = 512
	maxAPIAllowListMethodsTypes = 32
)

// APILimits are the structural limits. Zero = default, -1 = unlimited.
// Booleans are named so that their zero value is the safe choice.
type APILimits struct {
	MaxBodyBytes int64 // request body bytes; bodies are buffered up to this size to be checked and replayed

	JSONMaxDepth        int  // nesting depth of arrays / objects
	JSONMaxKeys         int  // keys in one object
	JSONMaxArrayLen     int  // elements in one array
	JSONMaxStringLen    int  // bytes of one string (raw, including escapes)
	RejectDuplicateKeys bool // duplicate keys inside one object
	RejectInvalidUTF8   bool // strings that are not valid UTF-8

	XMLMaxDepth    int  // element nesting depth
	XMLMaxElements int  // total elements
	XMLMaxAttrs    int  // attributes of one element
	AllowDoctype   bool // DOCTYPE is rejected (XXE) unless set; entity declarations are always rejected

	FormMaxFields     int // fields of a urlencoded or multipart form
	MultipartMaxParts int // parts of a multipart body
	MultipartMaxFiles int // file parts of a multipart body

	QueryMaxParams   int // query string parameters
	QueryMaxParamLen int // bytes of one query / form parameter (name=value)
	URLMaxLen        int // bytes of the request target
	HeaderMaxCount   int // request header lines
	HeaderMaxSize    int // bytes of one header (name + value)

	AllowContentTypeMismatch bool // do not report bodies that do not parse as their declared type
}

// APIAllowRule restricts the methods and body content types for a path prefix.
// Path matches on segment boundaries: "/api" matches "/api" and "/api/x" but not "/apix".
// A trailing "*" ("/api*") is a plain string prefix.
type APIAllowRule struct {
	Path         string
	Methods      []string `json:",omitempty"` // empty = any method
	ContentTypes []string `json:",omitempty"` // empty = any; "type/subtype" or "type/*", checked on requests with a body
}

// OpenAPIConfig is the optional OpenAPI 3.x validation
type OpenAPIConfig struct {
	Spec              string // JSON or YAML document, size limited, validated on save
	AllowUnknownPaths bool   `json:",omitempty"` // requests for paths that are not in the spec are not violations
	SkipBody          bool   `json:",omitempty"` // validate method, path and parameters only
	BlockUnknown      bool   `json:",omitempty"` // fail closed: block when the spec cannot be used or validation fails internally
}

// APIConfig is the API protection of one layer
type APIConfig struct {
	Mode      string         `json:",omitempty"` // "" = inherit, off, log, block
	Limits    *APILimits     `json:",omitempty"` // nil = inherit (or defaults)
	AllowList []APIAllowRule `json:",omitempty"` // additive across layers
	OpenAPI   *OpenAPIConfig `json:",omitempty"` // nil = inherit
}

// DefaultAPILimits returns the limits with every default filled in
func DefaultAPILimits() APILimits { return (&APILimits{}).Effective() }

func pick(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0 // unlimited
	}
	return v
}

// Effective returns the limits with defaults applied. In the result 0 means unlimited.
func (l *APILimits) Effective() APILimits {
	var in APILimits
	if l != nil {
		in = *l
	}
	e := in
	switch {
	case in.MaxBodyBytes == 0:
		e.MaxBodyBytes = DefaultAPIMaxBodyBytes
	case in.MaxBodyBytes < 0:
		e.MaxBodyBytes = MaxAPIBodyBytes // buffering is always bounded
	}
	e.JSONMaxDepth = pick(in.JSONMaxDepth, DefaultJSONMaxDepth)
	e.JSONMaxKeys = pick(in.JSONMaxKeys, DefaultJSONMaxKeys)
	e.JSONMaxArrayLen = pick(in.JSONMaxArrayLen, DefaultJSONMaxArrayLen)
	e.JSONMaxStringLen = pick(in.JSONMaxStringLen, DefaultJSONMaxStringLen)
	e.XMLMaxDepth = pick(in.XMLMaxDepth, DefaultXMLMaxDepth)
	e.XMLMaxElements = pick(in.XMLMaxElements, DefaultXMLMaxElements)
	e.XMLMaxAttrs = pick(in.XMLMaxAttrs, DefaultXMLMaxAttributes)
	e.FormMaxFields = pick(in.FormMaxFields, DefaultFormMaxFields)
	e.MultipartMaxParts = pick(in.MultipartMaxParts, DefaultMultipartMaxParts)
	e.MultipartMaxFiles = pick(in.MultipartMaxFiles, DefaultMultipartMaxFiles)
	e.QueryMaxParams = pick(in.QueryMaxParams, DefaultQueryMaxParams)
	e.QueryMaxParamLen = pick(in.QueryMaxParamLen, DefaultQueryMaxParamLen)
	e.URLMaxLen = pick(in.URLMaxLen, DefaultURLMaxLen)
	e.HeaderMaxCount = pick(in.HeaderMaxCount, DefaultHeaderMaxCount)
	e.HeaderMaxSize = pick(in.HeaderMaxSize, DefaultHeaderMaxSize)
	return e
}

func checkLimit(name string, v, max int) error {
	if v < -1 || v > max {
		return fmt.Errorf("%s must be between 1 and %d (0 = default, -1 = unlimited)", name, max)
	}
	return nil
}

// Validate checks the limit values
func (l *APILimits) Validate() error {
	if l == nil {
		return nil
	}
	if l.MaxBodyBytes < -1 || l.MaxBodyBytes > MaxAPIBodyBytes {
		return fmt.Errorf("maximum body size must be between 1 and %d bytes (0 = default, -1 = maximum)", MaxAPIBodyBytes)
	}
	for _, c := range []struct {
		name string
		v    int
		max  int
	}{
		{"JSON depth", l.JSONMaxDepth, maxAPIDepthValue},
		{"JSON keys per object", l.JSONMaxKeys, maxAPILimitValue},
		{"JSON array length", l.JSONMaxArrayLen, maxAPILimitValue},
		{"JSON string length", l.JSONMaxStringLen, MaxAPIBodyBytes},
		{"XML depth", l.XMLMaxDepth, maxAPIDepthValue},
		{"XML elements", l.XMLMaxElements, maxAPILimitValue},
		{"XML attributes per element", l.XMLMaxAttrs, maxAPILimitValue},
		{"form fields", l.FormMaxFields, maxAPILimitValue},
		{"multipart parts", l.MultipartMaxParts, maxAPILimitValue},
		{"multipart files", l.MultipartMaxFiles, maxAPILimitValue},
		{"query parameters", l.QueryMaxParams, maxAPILimitValue},
		{"parameter length", l.QueryMaxParamLen, MaxAPIBodyBytes},
		{"URL length", l.URLMaxLen, MaxAPIBodyBytes},
		{"header count", l.HeaderMaxCount, maxAPILimitValue},
		{"header size", l.HeaderMaxSize, MaxAPIBodyBytes},
	} {
		if err := checkLimit(c.name, c.v, c.max); err != nil {
			return err
		}
	}
	return nil
}

func validToken(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~/", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// Validate checks an allow-list rule
func (a *APIAllowRule) Validate() error {
	p := a.Path
	if !strings.HasPrefix(p, "/") || len(p) > maxAPIAllowListEntryLength {
		return fmt.Errorf("allow-list path %q must start with / and be at most %d characters", p, maxAPIAllowListEntryLength)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] == 0x7f || p[i] == '\\' || p[i] == '%' || p[i] == '"' {
			return fmt.Errorf("allow-list path %q contains a space, control character, quote, backslash or %%", p)
		}
	}
	if len(a.Methods) > maxAPIAllowListMethodsTypes || len(a.ContentTypes) > maxAPIAllowListMethodsTypes {
		return fmt.Errorf("allow-list entry %q has too many methods or content types", p)
	}
	for _, m := range a.Methods {
		if !validToken(m) || strings.Contains(m, "/") {
			return fmt.Errorf("allow-list path %q: invalid method %q", p, m)
		}
	}
	for _, ct := range a.ContentTypes {
		if !validToken(ct) || strings.Count(ct, "/") != 1 || strings.HasPrefix(ct, "/") || strings.HasSuffix(ct, "/") {
			return fmt.Errorf("allow-list path %q: invalid content type %q (use type/subtype or type/*)", p, ct)
		}
	}
	return nil
}

// Validate checks everything that can be checked without compiling the spec
func (c *APIConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case APIModeInherit, APIModeOff, APIModeLog, APIModeBlock:
	default:
		return fmt.Errorf("invalid API protection mode %q (use off, log or block)", c.Mode)
	}
	if err := c.Limits.Validate(); err != nil {
		return err
	}
	if len(c.AllowList) > MaxAPIAllowRules {
		return fmt.Errorf("too many allow-list entries (maximum %d)", MaxAPIAllowRules)
	}
	for i := range c.AllowList {
		if err := c.AllowList[i].Validate(); err != nil {
			return err
		}
	}
	if c.OpenAPI != nil && strings.TrimSpace(c.OpenAPI.Spec) != "" {
		if len(c.OpenAPI.Spec) > MaxOpenAPISpecBytes {
			return fmt.Errorf("OpenAPI spec is too large (%d bytes, maximum %d)", len(c.OpenAPI.Spec), MaxOpenAPISpecBytes)
		}
		if _, err := CompileOpenAPI(c.OpenAPI.Spec); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a deep copy
func (c *APIConfig) Clone() *APIConfig {
	if c == nil {
		return nil
	}
	n := *c
	if c.Limits != nil {
		l := *c.Limits
		n.Limits = &l
	}
	n.AllowList = nil
	for _, r := range c.AllowList {
		r.Methods = append([]string(nil), r.Methods...)
		r.ContentTypes = append([]string(nil), r.ContentTypes...)
		n.AllowList = append(n.AllowList, r)
	}
	if c.OpenAPI != nil {
		o := *c.OpenAPI
		n.OpenAPI = &o
	}
	return &n
}

// IsEmpty reports a config that changes nothing
func (c *APIConfig) IsEmpty() bool {
	return c == nil || (c.Mode == "" && c.Limits == nil && len(c.AllowList) == 0 && c.OpenAPI == nil)
}

// MergeAPI merges layers from the least to the most specific one (policy, profile, proxy rule).
// Mode, Limits and OpenAPI of a later layer replace the earlier ones when set; allow-list
// entries are added up. The result is nil when API protection ends up off.
func MergeAPI(layers ...*APIConfig) *APIConfig {
	out := &APIConfig{}
	for _, l := range layers {
		if l == nil {
			continue
		}
		if m := strings.ToLower(strings.TrimSpace(l.Mode)); m != "" {
			out.Mode = m
		}
		if l.Limits != nil {
			c := *l.Limits
			out.Limits = &c
		}
		if l.OpenAPI != nil {
			o := *l.OpenAPI
			out.OpenAPI = &o
		}
		out.AllowList = append(out.AllowList, l.Clone().AllowList...)
	}
	if out.Mode != APIModeLog && out.Mode != APIModeBlock {
		return nil
	}
	return out
}

// ResolveAPI computes the effective API protection of an endpoint setting. It never fails; nil = off.
// Layers: global policy (only where the endpoint inherits from it, i.e. the policy is enabled, or
// the endpoint uses a fixed mode / profile), the profile and the endpoint's own settings.
// The "custom" source is standalone, like its WAF config: only the endpoint's own settings count.
func (s *State) ResolveAPI(set Setting) *APIConfig {
	switch set.EffectiveSource() {
	case SourceOff:
		return nil
	case SourceCustom:
		return MergeAPI(set.API)
	case SourceInherit:
		if !s.Policy.Enabled {
			return MergeAPI(set.API)
		}
		return MergeAPI(s.Policy.API, set.API)
	case SourceProfile:
		if p, ok := s.Profile(set.Profile); ok {
			return MergeAPI(s.Policy.API, p.API, set.API)
		}
	}
	return MergeAPI(s.Policy.API, set.API)
}
