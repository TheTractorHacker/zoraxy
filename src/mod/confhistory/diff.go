package confhistory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MaskText is what a secret value is replaced with in every diff.
const MaskText = "••••"

// MaskChangedText marks a secret that has a different value after the change.
const MaskChangedText = "•••• (changed)"

var secretWords = []string{
	"pass", "secret", "token", "credential", "private", "apikey", "api_key", "api-key", "authorization",
	"hmac", "salt", "hash", "bearer", "cookie", "signing", "webhook", "dnsapi", "psk", "passphrase",
}

var secretHeaderRe = regexp.MustCompile(`(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-.*(token|secret|key).*|.*(token|secret|password).*)$`)

// isSecretKey decides by the field name whether a value must be hidden.
func isSecretKey(k string) bool {
	l := strings.ToLower(k)
	for _, w := range secretWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return l == "key" || l == "kid" || strings.HasSuffix(l, "key") || strings.HasSuffix(l, "_kid")
}

// secretLeaf is a masked value; raw is only used to detect whether the secret
// changed and is never marshalled.
type secretLeaf struct{ raw string }

// maskTree hides secrets; objects and arrays under a secret key are masked as a whole.
func maskTree(v any, force bool) any {
	if force {
		switch t := v.(type) {
		case map[string]any, []any:
			b, _ := json.Marshal(t)
			return &secretLeaf{raw: string(b)}
		}
	}
	switch t := v.(type) {
	case map[string]any:
		hdrSecret := false
		for _, nk := range []string{"Key", "Name", "key", "name", "Header", "header"} {
			if s, ok := t[nk].(string); ok && secretHeaderRe.MatchString(s) {
				hdrSecret = true
			}
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = maskTree(e, isSecretKey(k) || hdrSecret && strings.EqualFold(k, "value"))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = maskTree(e, force)
		}
		return out
	case string:
		if force && t != "" {
			return &secretLeaf{raw: t}
		}
	}
	return v
}

// finalize replaces secret leaves by their display text; a leaf whose
// counterpart in peer differs is shown as changed.
func finalize(v, peer any) any {
	switch t := v.(type) {
	case *secretLeaf:
		if p, ok := peer.(*secretLeaf); ok && p.raw != t.raw {
			return MaskChangedText
		}
		if peer == nil {
			return MaskChangedText //secret added or removed
		}
		return MaskText
	case map[string]any:
		pm, _ := peer.(map[string]any)
		out := make(map[string]any, len(t))
		for k, e := range t {
			var pe any
			if pm != nil {
				pe = pm[k]
			}
			out[k] = finalize(e, pe)
		}
		return out
	case []any:
		pl, _ := peer.([]any)
		out := make([]any, len(t))
		for i, e := range t {
			var pe any
			if i < len(pl) {
				pe = pl[i]
			}
			out[i] = finalize(e, pe)
		}
		return out
	}
	return v
}

func parseJSON(b []byte) (any, bool) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if dec.More() {
		return nil, false
	}
	return v, true
}

func prettyJSON(v any) []string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
}

// DiffLine is one line of a diff: ctx, add or del.
type DiffLine struct {
	T string `json:"t"`
	S string `json:"s"`
}

// Hunk is a run of changed lines with context.
type Hunk struct {
	OldStart int        `json:"oldStart"`
	NewStart int        `json:"newStart"`
	Lines    []DiffLine `json:"lines"`
}

// FileDiff is the masked difference of one object between two versions.
type FileDiff struct {
	Path    string `json:"path"`
	Label   string `json:"label"`
	Area    string `json:"area"`
	Change  string `json:"change"` // added | changed | removed
	Hidden  bool   `json:"hidden,omitempty"`
	Note    string `json:"note,omitempty"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	Hunks   []Hunk `json:"hunks,omitempty"`
}

const (
	diffContext   = 3
	maxDiffLines  = 3000
	maxLCSCells   = 4_000_000
	maxDiffSource = 4 << 20
)

// diffEntry builds the masked diff of one path. old / new are nil when the
// object does not exist on that side.
func (m *Manager) diffEntry(path, change string, old, cur []byte) FileDiff {
	fd := FileDiff{Path: path, Label: m.Label(path), Area: m.reg.AreaOf(path), Change: change}
	if m.reg.NoContent(path) {
		fd.Hidden, fd.Note = true, fmt.Sprintf("content is never shown (%d -> %d bytes)", len(old), len(cur))
		return fd
	}
	if len(old) > maxDiffSource || len(cur) > maxDiffSource {
		fd.Hidden, fd.Note = true, "too large to compare"
		return fd
	}
	var ov, nv any
	var oOK, nOK bool
	if old != nil {
		if ov, oOK = parseJSON(old); !oOK {
			fd.Hidden, fd.Note = true, "not JSON, content not shown"
			return fd
		}
	}
	if cur != nil {
		if nv, nOK = parseJSON(cur); !nOK {
			fd.Hidden, fd.Note = true, "not JSON, content not shown"
			return fd
		}
	}
	all := m.reg.MaskAll(path)
	mask := func(v any) any {
		if v == nil {
			return nil
		}
		if all {
			if obj, ok := v.(map[string]any); ok {
				out := make(map[string]any, len(obj))
				for k, e := range obj {
					out[k] = maskTree(e, true)
				}
				return out
			}
		}
		return maskTree(v, false)
	}
	mo, mn := mask(ov), mask(nv)
	var oldLines, newLines []string
	po, pn := mn, mo
	if old == nil || cur == nil { //added or removed object: secrets are simply hidden, not "changed"
		po, pn = mo, mn
	}
	if old != nil {
		oldLines = prettyJSON(finalize(mo, po))
	}
	if cur != nil {
		newLines = prettyJSON(finalize(mn, pn))
	}
	fd.Hunks, fd.Added, fd.Removed = lineDiff(oldLines, newLines)
	if fd.Added == 0 && fd.Removed == 0 && change == "changed" {
		fd.Note = "only hidden values or formatting differ"
	}
	return fd
}

// lineDiff computes an LCS line diff and groups it into hunks.
func lineDiff(a, b []string) ([]Hunk, int, int) {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	var ops []DiffLine // full op list for the middle part
	if len(ma)*len(mb) > maxLCSCells {
		for _, l := range ma {
			ops = append(ops, DiffLine{"del", l})
		}
		for _, l := range mb {
			ops = append(ops, DiffLine{"add", l})
		}
	} else {
		ops = lcsOps(ma, mb)
	}
	all := make([]DiffLine, 0, pre+len(ops)+suf)
	for _, l := range a[:pre] {
		all = append(all, DiffLine{"ctx", l})
	}
	all = append(all, ops...)
	for _, l := range a[len(a)-suf:] {
		all = append(all, DiffLine{"ctx", l})
	}
	added, removed := 0, 0
	for _, o := range ops {
		if o.T == "add" {
			added++
		} else {
			removed++
		}
	}
	// group into hunks: every changed line plus diffContext lines around it,
	// overlapping ranges merged
	oldNo, newNo := 1, 1
	lineNo := make([][2]int, len(all))
	for k, l := range all {
		lineNo[k] = [2]int{oldNo, newNo}
		if l.T != "add" {
			oldNo++
		}
		if l.T != "del" {
			newNo++
		}
	}
	var hunks []Hunk
	total := 0
	for i := 0; i < len(all); {
		if all[i].T == "ctx" {
			i++
			continue
		}
		start := max(i-diffContext, 0)
		end := i + 1
		for j := end; j < len(all); j++ {
			if all[j].T != "ctx" {
				end = j + 1
			} else if j-end >= 2*diffContext {
				break
			}
		}
		end = min(end+diffContext, len(all))
		h := Hunk{OldStart: lineNo[start][0], NewStart: lineNo[start][1], Lines: append([]DiffLine(nil), all[start:end]...)}
		total += len(h.Lines)
		if total > maxDiffLines {
			hunks = append(hunks, Hunk{OldStart: h.OldStart, NewStart: h.NewStart, Lines: []DiffLine{{"ctx", "... diff truncated ..."}}})
			break
		}
		hunks = append(hunks, h)
		i = end
	}
	return hunks, added, removed
}

func lcsOps(a, b []string) []DiffLine {
	n, m := len(a), len(b)
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out []DiffLine
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, DiffLine{"ctx", a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			out = append(out, DiffLine{"del", a[i]})
			i++
		default:
			out = append(out, DiffLine{"add", b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, DiffLine{"del", a[i]})
	}
	for ; j < m; j++ {
		out = append(out, DiffLine{"add", b[j]})
	}
	return out
}

// Diff compares two versions (from == 0: against an empty configuration) and
// returns the masked per-object differences. Secrets never leave this function.
func (m *Manager) Diff(from, to int64) ([]FileDiff, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.diffLocked(from, to)
}

func (m *Manager) diffLocked(from, to int64) ([]FileDiff, error) {
	var a manifest
	var err error
	if from != 0 {
		if _, err = m.getLocked(from); err != nil {
			return nil, err
		}
		if a, err = m.loadManifest(from); err != nil {
			return nil, err
		}
	}
	if _, err = m.getLocked(to); err != nil {
		return nil, err
	}
	b, err := m.loadManifest(to)
	if err != nil {
		return nil, err
	}
	return m.diffManifestsFull(a, b)
}

func (m *Manager) diffManifestsFull(a, b manifest) ([]FileDiff, error) {
	paths := map[string]bool{}
	for p := range a {
		paths[p] = true
	}
	for p := range b {
		paths[p] = true
	}
	var out []FileDiff
	for _, p := range sortedKeys(paths) {
		ae, aok := a[p]
		be, bok := b[p]
		var change string
		switch {
		case !aok:
			change = "added"
		case !bok:
			change = "removed"
		case ae.Blob != be.Blob:
			change = "changed"
		default:
			continue
		}
		var ob, nb []byte
		var err error
		if aok {
			if ob, err = m.getBlob(ae.Blob); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
		}
		if bok {
			if nb, err = m.getBlob(be.Blob); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
		}
		out = append(out, m.diffEntry(p, change, ob, nb))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
