package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

/*
	Per-node variables

	Managed files may contain placeholders such as {{node.upstream_ip}}.
	They are resolved on the node when a bundle is applied. Substitution is
	textual inside JSON files, so it is strict:

	  - variable names are [a-z][a-z0-9_]{0,31}
	  - values are limited to a safe charset (hostnames, IPs, ports, simple
	    paths): no quotes, backslashes, braces, whitespace or control chars,
	    so a value can never break out of a JSON string
	  - any "{{node." that is not a well formed placeholder is an error
	  - a placeholder without a value is an error (nothing is applied)
	  - the result must still be valid JSON
	  - only JSON files of non certificate scopes are processed
*/

var (
	varNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	varValuePattern = regexp.MustCompile(`^[A-Za-z0-9._:/@+\-\[\]]{0,253}$`)
	placeholderRe   = regexp.MustCompile(`\{\{node\.([a-z][a-z0-9_]{0,31})\}\}`)
)

const (
	maxVarsPerScope = 64
	varMarker       = "{{node."
)

// ReservedVars are filled in by the node itself and cannot be set by the hub.
var ReservedVars = []string{"id", "name", "group"}

// ValidateVars checks a variable map.
func ValidateVars(v map[string]string) error {
	if len(v) > maxVarsPerScope {
		return fmt.Errorf("at most %d variables", maxVarsPerScope)
	}
	for k, val := range v {
		if !varNamePattern.MatchString(k) {
			return fmt.Errorf("variable name %q must match [a-z][a-z0-9_]{0,31}", k)
		}
		for _, r := range ReservedVars {
			if k == r {
				return fmt.Errorf("variable name %q is reserved", k)
			}
		}
		if !varValuePattern.MatchString(val) {
			return fmt.Errorf("value of variable %q contains characters that are not allowed (letters, digits and . _ : / @ + - [ ] only)", k)
		}
	}
	return nil
}

func isTemplated(path string) bool {
	if strings.HasPrefix(path, certRoot+"/") {
		return false
	}
	return strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".config")
}

// PlaceholdersIn returns the sorted variable names referenced by data, or an
// error for malformed placeholders.
func PlaceholdersIn(data []byte) ([]string, error) {
	s := string(data)
	found := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
		found[m[1]] = true
	}
	stripped := placeholderRe.ReplaceAllString(s, "")
	if strings.Contains(stripped, varMarker) {
		return nil, errors.New("malformed {{node.*}} placeholder (names are [a-z][a-z0-9_]{0,31}, no spaces)")
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// Substitute resolves the placeholders of data with vars.
func Substitute(path string, data []byte, vars map[string]string) ([]byte, error) {
	names, err := PlaceholdersIn(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(names) == 0 {
		return data, nil
	}
	for _, n := range names {
		val, ok := vars[n]
		if !ok {
			return nil, fmt.Errorf("%s: variable %q is not defined for this node", path, n)
		}
		if !varValuePattern.MatchString(val) {
			return nil, fmt.Errorf("%s: value of variable %q is not allowed", path, n)
		}
	}
	out := placeholderRe.ReplaceAllStringFunc(string(data), func(m string) string {
		return vars[placeholderRe.FindStringSubmatch(m)[1]]
	})
	if !json.Valid([]byte(out)) {
		return nil, fmt.Errorf("%s: not valid JSON after variable substitution", path)
	}
	return []byte(out), nil
}

// ResolveFiles substitutes variables in all templated files (copy).
func ResolveFiles(files []FileEntry, vars map[string]string) ([]FileEntry, error) {
	out := make([]FileEntry, len(files))
	for i, f := range files {
		out[i] = f
		if !isTemplated(f.Path) {
			continue
		}
		d, err := Substitute(f.Path, f.Data, vars)
		if err != nil {
			return nil, err
		}
		out[i].Data = d
	}
	return out, nil
}

// MissingVars returns, per file, the placeholders that vars does not define
// (used by the hub to refuse a publish that a node could not apply).
func MissingVars(files []FileEntry, vars map[string]string) ([]string, error) {
	missing := map[string]bool{}
	for _, f := range files {
		if !isTemplated(f.Path) {
			continue
		}
		names, err := PlaceholdersIn(f.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		for _, n := range names {
			if _, ok := vars[n]; !ok {
				missing[n] = true
			}
		}
	}
	out := make([]string, 0, len(missing))
	for k := range missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
