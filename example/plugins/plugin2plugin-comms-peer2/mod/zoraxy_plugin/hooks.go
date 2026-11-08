package zoraxy_plugin

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

/*
	Request / Response Hooks (filter API)

	Hooks let a plugin act as a middleware / WAF style filter instead of (or in
	addition to) capturing traffic. A plugin opts in by filling IntroSpect.Hooks.
	Plugins without Hooks behave exactly like before.

	Stages
		pre_auth   right after the access rules (blacklist / whitelist), before WAF,
		           exploit detection, rate limit, CAPTCHA and authentication.
		           Use it for bot filters. The verdict "capture" is NOT honoured here
		           because it would skip authentication (treated as "allow").
		post_auth  after authentication, where legacy capture plugins run.
		response   just before the response headers of a proxied response are sent
		           to the client. Only header changes are possible.

	Call flow
		Zoraxy -> POST <filter_request_path> (or <filter_response_path>) with a
		FilterRequest JSON body. The plugin answers 200 with a FilterVerdict JSON.
		Every call carries the X-Zoraxy-RequestID header (stable for the whole
		request across stages) and X-Zoraxy-Plugin-Token (see VerifyInvokeToken).

	Ordering semantics
		Plugins are ordered by Priority (lower first), ties keep the tag / group
		order and then plugin ID. Filter plugins of the same stage are called
		concurrently and all see the request as it was when the stage started
		(they do NOT see each other's modifications). Verdicts are then merged in
		priority order: the first "deny" wins, "modify" operations are applied
		in priority order (a later plugin overrides an earlier one on conflict),
		and the first "capture" (post_auth only) wins.

	Failure semantics
		Each call has a timeout (TimeoutMs, default 2000, max 10000). A failure is a
		transport error, timeout, non-200 status, oversized or invalid verdict. After
		a few consecutive failures the plugin is skipped for a cooldown (circuit
		breaker). While failing, a "fail_open" plugin is ignored (request continues)
		and a "fail_closed" plugin makes Zoraxy answer 503 (502 at the response stage).
		fail_closed is only honoured when the Zoraxy admin enabled it for the plugin.
*/

// HookAPIVersion is the version of the hooks / filter API described in this file.
const HookAPIVersion = 1

// HookStage is a point in the request pipeline a plugin can register for.
type HookStage string

const (
	HookStagePreAuth  HookStage = "pre_auth"
	HookStagePostAuth HookStage = "post_auth"
	HookStageResponse HookStage = "response"
)

// FailurePolicy decides what Zoraxy does with a request when the plugin cannot answer.
type FailurePolicy string

const (
	FailureOpen   FailurePolicy = "fail_open"   // default, continue as if the plugin allowed the request
	FailureClosed FailurePolicy = "fail_closed" // reject the request; needs admin consent in the Zoraxy UI
)

// Limits enforced by Zoraxy and the helper functions in this package.
const (
	MaxBodyPreviewBytes  = 64 * 1024  // upper bound of HookSettings.BodyPreviewBytes
	DefaultHookTimeoutMs = 2000       // used when HookSettings.TimeoutMs is 0
	MaxHookTimeoutMs     = 10000      // upper bound of HookSettings.TimeoutMs
	MaxDenyBodyBytes     = 64 * 1024  // upper bound of DenyAction.Body
	MaxVerdictBytes      = 256 * 1024 // upper bound of the whole verdict JSON
	MaxHeaderOps         = 32         // header operations per verdict
	MaxHeaderValueBytes  = 8 * 1024   // single header value
	MaxPathBytes         = 4 * 1024   // rewritten path
	MaxQueryBytes        = 8 * 1024   // rewritten query
	InvokeTokenHeader    = "X-Zoraxy-Plugin-Token"
	RequestIDHeader      = "X-Zoraxy-RequestID"
)

// HookSettings is the optional "hooks" object of the introspection payload.
type HookSettings struct {
	Version            int           `json:"version"`                        //Hooks API version the plugin was written for, use HookAPIVersion
	Stages             []HookStage   `json:"stages"`                         //Stages to register for. Empty = no filter registration
	FilterRequestPath  string        `json:"filter_request_path,omitempty"`  //Endpoint called for pre_auth / post_auth (e.g. /filter)
	FilterResponsePath string        `json:"filter_response_path,omitempty"` //Endpoint called for the response stage, defaults to FilterRequestPath
	Priority           int           `json:"priority,omitempty"`             //Lower runs first. Default 0
	TimeoutMs          int           `json:"timeout_ms,omitempty"`           //Per call timeout, default 2000, capped at 10000
	FailurePolicy      FailurePolicy `json:"failure_policy,omitempty"`       //fail_open (default) or fail_closed (needs admin consent)
	BodyPreviewBytes   int           `json:"body_preview_bytes,omitempty"`   //0 = never send a body. Max 65536
	BodyContentTypes   []string      `json:"body_content_types,omitempty"`   //Media types that get a body preview, e.g. application/json, text/*. Empty = none
}

// HasStage reports whether the plugin registered for the stage.
func (h *HookSettings) HasStage(s HookStage) bool {
	if h == nil {
		return false
	}
	for _, st := range h.Stages {
		if st == s {
			return true
		}
	}
	return false
}

// PathForStage returns the filter endpoint for the stage ("" if none).
func (h *HookSettings) PathForStage(s HookStage) string {
	if h == nil {
		return ""
	}
	if s == HookStageResponse && h.FilterResponsePath != "" {
		return h.FilterResponsePath
	}
	return h.FilterRequestPath
}

// EffectiveTimeout returns the call timeout after applying default and cap.
func (h *HookSettings) EffectiveTimeout() time.Duration {
	ms := DefaultHookTimeoutMs
	if h != nil && h.TimeoutMs > 0 {
		ms = h.TimeoutMs
	}
	if ms > MaxHookTimeoutMs {
		ms = MaxHookTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// EffectiveBodyPreviewBytes returns the body preview size after clamping to [0, MaxBodyPreviewBytes].
func (h *HookSettings) EffectiveBodyPreviewBytes() int {
	if h == nil || h.BodyPreviewBytes <= 0 || len(h.BodyContentTypes) == 0 {
		return 0
	}
	if h.BodyPreviewBytes > MaxBodyPreviewBytes {
		return MaxBodyPreviewBytes
	}
	return h.BodyPreviewBytes
}

// WantsBodyFor reports whether a body with the given Content-Type header should be previewed.
func (h *HookSettings) WantsBodyFor(contentType string) bool {
	if h.EffectiveBodyPreviewBytes() == 0 {
		return false
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if mt == "" {
		return false
	}
	for _, want := range h.BodyContentTypes {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" || want == "*/*" || want == "*" {
			continue //wildcard-everything is not allowed, list the types you need
		}
		if want == mt {
			return true
		}
		if strings.HasSuffix(want, "/*") && strings.HasPrefix(mt, strings.TrimSuffix(want, "*")) {
			return true
		}
	}
	return false
}

/*
	Wire format (Zoraxy -> plugin)
*/

// FilterResponseInfo describes the upstream response at the response stage.
type FilterResponseInfo struct {
	Status int                 `json:"status"`
	Header map[string][]string `json:"header"`
}

// FilterRequest is the JSON body POSTed to the plugin filter endpoint.
type FilterRequest struct {
	Version       int                        `json:"version"`                  //HookAPIVersion
	Stage         HookStage                  `json:"stage"`                    //The stage being executed
	RequestID     string                     `json:"request_id"`               //Same value as the X-Zoraxy-RequestID header
	Request       DynamicSniffForwardRequest `json:"request"`                  //Sniff style description of the request (as modified by earlier stages)
	BodyPreview   []byte                     `json:"body_preview,omitempty"`   //First bytes of the body (base64 in JSON), only if requested in the manifest
	BodyTruncated bool                       `json:"body_truncated,omitempty"` //True if the body is longer than BodyPreview
	Response      *FilterResponseInfo        `json:"response,omitempty"`       //Only set at the response stage
}

/*
	Wire format (plugin -> Zoraxy)
*/

// Verdict actions
const (
	ActionAllow   = "allow"   // continue
	ActionDeny    = "deny"    // answer the client with Deny
	ActionModify  = "modify"  // apply Modify, then continue
	ActionCapture = "capture" // post_auth only: proxy the whole request to the plugin dynamic capture ingress
)

// HeaderOps describes header changes. Names are case insensitive. Applied in the
// order remove, set, add.
type HeaderOps struct {
	Add    map[string]string `json:"add,omitempty"`    //Append a value
	Set    map[string]string `json:"set,omitempty"`    //Replace all values
	Remove []string          `json:"remove,omitempty"` //Delete the header
}

// DenyAction is what is written to the client on "deny".
type DenyAction struct {
	Status  int               `json:"status,omitempty"`  //400-599, default 403
	Body    string            `json:"body,omitempty"`    //Up to 64 KiB
	Headers map[string]string `json:"headers,omitempty"` //Safe headers only (Content-Type, Cache-Control, Retry-After, ...)
}

// ModifyAction is applied on "modify".
type ModifyAction struct {
	RequestHeaders  *HeaderOps `json:"request_headers,omitempty"`  //Request stages only
	Path            *string    `json:"path,omitempty"`             //Request stages only. Absolute path, same host
	Query           *string    `json:"query,omitempty"`            //Request stages only. Raw query without leading ?
	ResponseHeaders *HeaderOps `json:"response_headers,omitempty"` //Response stage only
}

// FilterVerdict is the JSON the plugin answers with (HTTP 200).
type FilterVerdict struct {
	Version int           `json:"version"`          //HookAPIVersion
	Action  string        `json:"action"`           //allow | deny | modify | capture
	Reason  string        `json:"reason,omitempty"` //Free text for the Zoraxy log
	Deny    *DenyAction   `json:"deny,omitempty"`
	Modify  *ModifyAction `json:"modify,omitempty"`
}

/*
	Plugin author helpers
*/

// Allow returns an "allow" verdict.
func Allow() *FilterVerdict { return &FilterVerdict{Version: HookAPIVersion, Action: ActionAllow} }

// Capture returns a "capture" verdict (post_auth only).
func Capture() *FilterVerdict { return &FilterVerdict{Version: HookAPIVersion, Action: ActionCapture} }

// Deny returns a "deny" verdict answering the client with status and body.
func Deny(status int, body string) *FilterVerdict {
	return &FilterVerdict{Version: HookAPIVersion, Action: ActionDeny, Deny: &DenyAction{Status: status, Body: body}}
}

// ModifyRequestHeaders returns a "modify" verdict applying request header operations.
func ModifyRequestHeaders(ops HeaderOps) *FilterVerdict {
	return &FilterVerdict{Version: HookAPIVersion, Action: ActionModify, Modify: &ModifyAction{RequestHeaders: &ops}}
}

// ModifyResponseHeaders returns a "modify" verdict applying response header operations.
func ModifyResponseHeaders(ops HeaderOps) *FilterVerdict {
	return &FilterVerdict{Version: HookAPIVersion, Action: ActionModify, Modify: &ModifyAction{ResponseHeaders: &ops}}
}

// WithReason sets the log reason and returns the verdict for chaining.
func (v *FilterVerdict) WithReason(reason string) *FilterVerdict {
	v.Reason = reason
	return v
}

// HeaderValue returns the first value of a request header (case insensitive).
func (f *FilterRequest) HeaderValue(name string) string {
	for k, v := range f.Request.Header {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// FilterHandler is called for every filter call. Returning nil means allow.
type FilterHandler func(*FilterRequest) *FilterVerdict

// NewFilterHandler returns an http.Handler for the filter endpoint. It checks the
// invoke token (ConfigureSpec.InvokeToken; pass "" to disable the check), decodes the
// FilterRequest, calls the handler and encodes the verdict. Mount it on the path
// declared as HookSettings.FilterRequestPath / FilterResponsePath.
func NewFilterHandler(invokeToken string, handler FilterHandler) http.Handler {
	return RequireInvokeToken(invokeToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2*MaxBodyPreviewBytes+MaxVerdictBytes))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req FilterRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		verdict := handler(&req)
		if verdict == nil {
			verdict = Allow()
		}
		if verdict.Version == 0 {
			verdict.Version = HookAPIVersion
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verdict)
	}))
}

// RequireInvokeToken wraps a handler so that only calls carrying the Zoraxy invoke
// token are served. An empty token disables the check (older Zoraxy versions do not
// send one). Use it for filter and sniff endpoints so other local processes cannot
// call them.
func RequireInvokeToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !VerifyInvokeToken(token, r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// VerifyInvokeToken checks the X-Zoraxy-Plugin-Token header in constant time.
func VerifyInvokeToken(token string, r *http.Request) bool {
	if token == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(r.Header.Get(InvokeTokenHeader))) == 1
}
