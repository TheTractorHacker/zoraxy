package waf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

/*
	openapi.go

	Optional OpenAPI 3.x request validation on top of github.com/getkin/kin-openapi
	(MIT, pure Go). Only the request side is validated: method + path, path /
	query / header parameters and (JSON) request bodies. External $refs (files,
	URLs) are never followed, security requirements are not evaluated, and
	response schemas are not checked.

	A spec is compiled once per distinct text (small cache), at save time for
	validation and again when the runtime is built. A spec that fails to compile
	is rejected on save; if one still fails at runtime the guard fails open
	(logged) unless OpenAPIConfig.BlockUnknown is set.
*/

const openAPICompileTimeout = 10 * time.Second

// SpecSummary describes a compiled spec for the UI
type SpecSummary struct {
	Title      string `json:"title"`
	Version    string `json:"version"`
	OpenAPI    string `json:"openapi"`
	Paths      int    `json:"paths"`
	Operations int    `json:"operations"`
}

// OpenAPIRuntime is a compiled spec. Safe for concurrent use.
type OpenAPIRuntime struct {
	doc     *openapi3.T
	router  routers.Router
	Summary SpecSummary
}

var (
	oaCacheMu sync.Mutex
	oaCache   = map[[32]byte]*OpenAPIRuntime{}
	oaOrder   [][32]byte
)

const oaCacheMax = 32

// CompileOpenAPI parses, validates and indexes a JSON or YAML OpenAPI 3.x document.
// It never panics and gives up after a timeout.
func CompileOpenAPI(spec string) (rt *OpenAPIRuntime, err error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("OpenAPI spec is empty")
	}
	if len(spec) > MaxOpenAPISpecBytes {
		return nil, fmt.Errorf("OpenAPI spec is too large (%d bytes, maximum %d)", len(spec), MaxOpenAPISpecBytes)
	}
	key := sha256.Sum256([]byte(spec))
	oaCacheMu.Lock()
	if c, ok := oaCache[key]; ok {
		oaCacheMu.Unlock()
		return c, nil
	}
	oaCacheMu.Unlock()

	type result struct {
		rt  *OpenAPIRuntime
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{nil, fmt.Errorf("OpenAPI spec could not be processed (internal error: %v)", r)}
			}
		}()
		r, e := compileOpenAPI([]byte(spec))
		ch <- result{r, e}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		oaCacheMu.Lock()
		if len(oaOrder) >= oaCacheMax {
			delete(oaCache, oaOrder[0])
			oaOrder = oaOrder[1:]
		}
		oaCache[key] = res.rt
		oaOrder = append(oaOrder, key)
		oaCacheMu.Unlock()
		return res.rt, nil
	case <-time.After(openAPICompileTimeout):
		return nil, errors.New("OpenAPI spec took too long to process")
	}
}

func compileOpenAPI(data []byte) (*OpenAPIRuntime, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false // never read files or URLs named by a spec
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec is not valid: %s", cleanMsg(err.Error()))
	}
	if doc == nil || !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, errors.New("only OpenAPI 3.x documents are supported (the document needs an \"openapi: 3.x.y\" field)")
	}
	if doc.Paths == nil || doc.Paths.Len() == 0 {
		return nil, errors.New("OpenAPI spec has no paths")
	}
	ctx, cancel := context.WithTimeout(context.Background(), openAPICompileTimeout)
	defer cancel()
	if err := doc.Validate(ctx, openapi3.DisableExamplesValidation()); err != nil {
		return nil, fmt.Errorf("OpenAPI spec is not valid: %s", cleanMsg(err.Error()))
	}
	doc.Servers = pathOnlyServers(doc.Servers)
	router, err := legacy.NewRouter(doc, openapi3.DisableExamplesValidation())
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec cannot be routed: %s", cleanMsg(err.Error()))
	}
	sum := SpecSummary{OpenAPI: doc.OpenAPI, Paths: doc.Paths.Len()}
	if doc.Info != nil {
		sum.Title, sum.Version = truncate(doc.Info.Title, 100), truncate(doc.Info.Version, 40)
	}
	for _, item := range doc.Paths.Map() {
		sum.Operations += len(item.Operations())
	}
	return &OpenAPIRuntime{doc: doc, router: router, Summary: sum}, nil
}

// pathOnlyServers reduces the servers of a spec to their base paths, so requests match
// whatever host name the proxy is reached under.
func pathOnlyServers(in openapi3.Servers) openapi3.Servers {
	seen := map[string]bool{}
	var out openapi3.Servers
	for _, s := range in {
		if s == nil {
			continue
		}
		raw := s.URL
		for name, v := range s.Variables {
			if v != nil {
				raw = strings.ReplaceAll(raw, "{"+name+"}", v.Default)
			}
		}
		p := raw
		if u, err := url.Parse(raw); err == nil {
			p = u.Path
		}
		p = strings.TrimRight(p, "/")
		if strings.Contains(p, "{") || seen[p] {
			continue
		}
		seen[p] = true
		if p == "" {
			p = "/"
		}
		out = append(out, &openapi3.Server{URL: p})
	}
	return out
}

func cleanMsg(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, "\n", "; ")
	return truncate(s, 400)
}

// oaResult is the outcome of validating one request
type oaResult struct {
	OK     bool
	Code   string // violation code when !OK
	Detail string
	Err    bool // internal failure, not the request's fault
}

// Validate checks the request against the spec. body is the full buffered request body (may be nil).
// The request itself is not modified or consumed.
func (o *OpenAPIRuntime) Validate(r *http.Request, body []byte, cfg *OpenAPIConfig) (res oaResult) {
	defer func() {
		if rec := recover(); rec != nil {
			res = oaResult{Code: codeOpenAPIError, Detail: "validator error", Err: true}
		}
	}()
	// A shallow clone with an independent body so the real request is untouched
	clone := r.Clone(r.Context())
	clone.Body = http.NoBody
	if len(body) > 0 {
		clone.Body = nopCloser{bytes.NewReader(body)}
	}
	route, params, err := o.router.FindRoute(clone)
	if err != nil {
		if cfg.AllowUnknownPaths {
			return oaResult{OK: true}
		}
		if err.Error() == routers.ErrMethodNotAllowed.Error() {
			return oaResult{Code: codeOpenAPIMethod, Detail: "method not allowed for this path in the spec"}
		}
		return oaResult{Code: codeOpenAPIPath, Detail: "path not in the spec"}
	}
	opts := &openapi3filter.Options{
		AuthenticationFunc:  openapi3filter.NoopAuthenticationFunc,
		SkipSettingDefaults: true,
		ExcludeRequestBody:  cfg.SkipBody || (r.ContentLength != 0 && !isJSONRequest(r)),
	}
	in := &openapi3filter.RequestValidationInput{Request: clone, PathParams: params, Route: route, Options: opts}
	if err := openapi3filter.ValidateRequest(r.Context(), in); err != nil {
		return classifyOAError(err)
	}
	return oaResult{OK: true}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func isJSONRequest(r *http.Request) bool {
	k, _ := bodyKind(r.Header.Get("Content-Type"))
	return k == kindJSON
}

func classifyOAError(err error) oaResult {
	var re *openapi3filter.RequestError
	if errors.As(err, &re) {
		if re.Parameter != nil {
			return oaResult{Code: codeOpenAPIParam, Detail: fmt.Sprintf("%s parameter %q is invalid or missing", re.Parameter.In, truncate(re.Parameter.Name, 60))}
		}
		if re.RequestBody != nil {
			d := "request body does not match the spec"
			var se *openapi3.SchemaError
			if errors.As(err, &se) {
				d = "request body: " + cleanMsg(truncate(se.Reason, 100))
				if p := se.JSONPointer(); len(p) > 0 {
					d += " at /" + truncate(strings.Join(p, "/"), 80)
				}
			} else if strings.Contains(re.Reason, "header Content-Type has unexpected value") || strings.Contains(re.Reason, "content type") {
				return oaResult{Code: codeOpenAPIContentType, Detail: "content type not accepted by the spec"}
			}
			return oaResult{Code: codeOpenAPIBody, Detail: d}
		}
		return oaResult{Code: codeOpenAPIBody, Detail: "request does not match the spec"}
	}
	var sec *openapi3filter.SecurityRequirementsError
	if errors.As(err, &sec) {
		return oaResult{OK: true}
	}
	return oaResult{Code: codeOpenAPIError, Detail: "request could not be validated", Err: true}
}
