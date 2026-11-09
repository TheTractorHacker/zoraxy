package uptime

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

/*
	statusspec.go

	Which HTTP status codes of the health check mean "the upstream is up".

	A spec is a comma separated list of: "any" (every answer except the gateway style failures,
	see statusMeansReachable), a class like "2xx", a code like "401" or a range like "200-399".
	An empty spec means "inherit": a rule uses the global spec, the global spec defaults to "any".
	"200-399" reproduces the old strict behaviour.
*/

type StatusSpec struct {
	any    bool
	ranges [][2]int
	text   string
}

func (s *StatusSpec) String() string { return s.text }

// ParseStatusSpec parses and validates a spec. An empty spec returns nil, nil (inherit).
func ParseStatusSpec(spec string) (*StatusSpec, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" {
		return nil, nil
	}
	if len(spec) > 200 {
		return nil, fmt.Errorf("status list is too long")
	}
	out := &StatusSpec{}
	var norm []string
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case tok == "any":
			out.any = true
		case len(tok) == 3 && tok[1:] == "xx" && tok[0] >= '1' && tok[0] <= '5':
			c := int(tok[0]-'0') * 100
			out.ranges = append(out.ranges, [2]int{c, c + 99})
		default:
			lo, hi, isRange := 0, 0, strings.Contains(tok, "-")
			var err1, err2 error
			if isRange {
				p := strings.SplitN(tok, "-", 2)
				lo, err1 = strconv.Atoi(strings.TrimSpace(p[0]))
				hi, err2 = strconv.Atoi(strings.TrimSpace(p[1]))
			} else {
				lo, err1 = strconv.Atoi(tok)
				hi, err2 = lo, err1
			}
			if err1 != nil || err2 != nil || lo < 100 || hi > 599 || lo > hi {
				return nil, fmt.Errorf("invalid status %q: use codes like 401, ranges like 200-399, classes like 2xx or \"any\"", tok)
			}
			out.ranges = append(out.ranges, [2]int{lo, hi})
		}
		norm = append(norm, tok)
	}
	if len(norm) == 0 {
		return nil, nil
	}
	out.text = strings.Join(norm, ",")
	return out, nil
}

// Match reports whether the status code counts as up under this spec.
func (s *StatusSpec) Match(code int) bool {
	if s == nil {
		return statusMeansReachable(code)
	}
	if code <= 0 {
		return false
	}
	if s.any && statusMeansReachable(code) {
		return true
	}
	for _, r := range s.ranges {
		if code >= r[0] && code <= r[1] {
			return true
		}
	}
	return false
}

var defaultSpec atomic.Pointer[StatusSpec]

// SetDefaultHealthyStatus sets the global spec ("" restores "any").
func SetDefaultHealthyStatus(spec string) error {
	s, err := ParseStatusSpec(spec)
	if err != nil {
		return err
	}
	defaultSpec.Store(s)
	return nil
}

// DefaultHealthyStatus returns the global spec text ("" = any).
func DefaultHealthyStatus() string {
	if s := defaultSpec.Load(); s != nil {
		return s.String()
	}
	return ""
}

// specFor picks the spec of a target: its own, else the global one, else "any".
func specFor(t *Target) *StatusSpec {
	if t != nil {
		if s, err := ParseStatusSpec(t.HealthyStatus); err == nil && s != nil {
			return s
		}
	}
	return defaultSpec.Load()
}
