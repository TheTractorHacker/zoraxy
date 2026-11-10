package confhistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

/*
	Restore

	  1. open the target version (every blob is authenticated)
	  2. plan: compare it with the live configuration, limited to the scope;
	     files owned by a Fleet hub / cluster primary are skipped and reported
	  3. dry run stops here and returns the plan with masked diffs
	  4. take a pre-restore snapshot (the way back), validate every file that
	     will be written (path allow-list, size, JSON, the loaders' validators)
	  5. stage the files below conf/.history/staging-*, write pending.json
	     (phase "applying"), swap with renames while keeping the old files in
	     conf/.history/backup-*, apply the table changes
	  6. phase "applied", ask the process to restart
	  7. the restarted process must stay healthy for HealthyAfter, otherwise
	     the next start (BootGuard) puts the old files and tables back

	A failure before step 5 changes nothing. A failure during step 5 undoes
	every rename and table write already done.
*/

// ErrNothingToRestore is returned when the live configuration already equals the version.
var ErrNothingToRestore = errors.New("the current configuration already matches this version (nothing to restore)")

// ConfirmWord must be sent to restore the whole configuration.
const ConfirmWord = "RESTORE"

// RestoreRequest asks for a restore.
type RestoreRequest struct {
	ID      int64
	Scope   string // "" / "all" or an area id
	DryRun  bool
	Actor   string
	Confirm string
}

// Skipped is an object a restore did not touch.
type Skipped struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

// RestoreResult describes (dry run) or reports a restore.
type RestoreResult struct {
	Version    Meta       `json:"version"`
	Scope      string     `json:"scope"`
	DryRun     bool       `json:"dryRun"`
	Items      []Change   `json:"items"` // what changes (restore direction: kind relative to the live config)
	Skipped    []Skipped  `json:"skipped"`
	Diffs      []FileDiff `json:"diffs,omitempty"`
	Applied    bool       `json:"applied"`
	Pre        int64      `json:"preVersion,omitempty"`
	Restarting bool       `json:"restarting"`
	NeedsWord  bool       `json:"needsConfirmWord"`
	Message    string     `json:"message,omitempty"`
}

type pendFile struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"` // write | delete
	HadOld bool   `json:"hadOld"`
}

type pendingRestore struct {
	Phase     string     `json:"phase"` // applying | applied
	At        int64      `json:"at"`
	Pre       int64      `json:"pre"`
	From      int64      `json:"from"`
	Scope     string     `json:"scope"`
	Actor     string     `json:"actor"`
	BackupDir string     `json:"backupDir"`
	Files     []pendFile `json:"files"`
	Tables    []string   `json:"tables"`
	Attempts  int        `json:"attempts"`
}

var errCrash = errors.New("simulated crash")

// step runs a test failure hook.
func (m *Manager) step(name string) error { return m.failAt[name] }

func (m *Manager) readPending() *pendingRestore {
	raw, err := os.ReadFile(m.dir(pendingFile))
	if err != nil {
		return nil
	}
	var p pendingRestore
	if json.Unmarshal(raw, &p) != nil || p.Phase == "" {
		return nil
	}
	return &p
}

func (m *Manager) writePending(p *pendingRestore) error {
	raw, _ := json.Marshal(p)
	return writeAtomic(m.dir(pendingFile), raw, 0o600)
}

func (m *Manager) inScope(path, scope string) bool {
	area := m.reg.AreaOf(path)
	if area == "" {
		return false
	}
	if scope == "all" {
		return !m.reg.IsOptIn(area)
	}
	return area == scope
}

func (m *Manager) normScope(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return "all", nil
	}
	for _, a := range m.reg.Areas() {
		if a.ID == s {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown scope %q", s)
}

// plan compares target with the live state.
func (m *Manager) plan(target, cur State, scope string) (items []Change, skipped []Skipped, writes []Entry, deletes []string) {
	paths := map[string]bool{}
	for p := range target {
		paths[p] = true
	}
	for p := range cur {
		paths[p] = true
	}
	for _, p := range sortedKeys(paths) {
		if !m.inScope(p, scope) {
			continue
		}
		te, tok := target[p]
		ce, cok := cur[p]
		var kind string
		switch {
		case tok && !cok:
			kind = "added"
		case !tok && cok:
			kind = "removed"
		case tok && cok && !bytes.Equal(te.Data, ce.Data):
			kind = "changed"
		default:
			continue
		}
		if m.opt.Managed != nil && !strings.HasPrefix(p, dbPrefix) {
			if why := m.opt.Managed(p); why != "" {
				skipped = append(skipped, Skipped{Path: p, Label: m.Label(p), Reason: why})
				continue
			}
		}
		items = append(items, m.change(p, kind))
		if kind == "removed" {
			deletes = append(deletes, p)
		} else {
			writes = append(writes, te)
		}
	}
	return
}

// validateWrites checks everything that is about to be written.
func (m *Manager) validateWrites(writes []Entry) error {
	var total int64
	for _, e := range writes {
		if !m.reg.ValidEntry(e.Path) {
			return fmt.Errorf("%q is not an allowed configuration path", e.Path)
		}
		if len(e.Data) > maxFileBytes {
			return fmt.Errorf("%s is larger than the allowed %d MiB", e.Path, maxFileBytes>>20)
		}
		total += int64(len(e.Data))
		if total > maxStateBytes {
			return errors.New("the restore is larger than the allowed size")
		}
		if strings.HasPrefix(e.Path, dbPrefix) {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(e.Data, &obj); err != nil {
				return fmt.Errorf("%s: not a valid table export: %w", e.Path, err)
			}
			continue
		}
		if strings.HasSuffix(e.Path, ".json") || strings.HasSuffix(e.Path, ".config") {
			if !json.Valid(e.Data) {
				return fmt.Errorf("%s is not valid JSON", e.Path)
			}
		}
		if m.opt.Validate != nil {
			if err := m.opt.Validate(e.Path, e.Data); err != nil {
				return fmt.Errorf("%s: %w", e.Path, err)
			}
		}
	}
	return nil
}

// Restore plans (dry run) or performs a restore. See the package comment of
// this file for the guarantees.
func (m *Manager) Restore(req RestoreRequest) (res *RestoreResult, retErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	recorded, crashed, planned := false, false, false
	var preID int64
	var scope string

	scope, err := m.normScope(req.Scope)
	if err != nil {
		return nil, err
	}
	defer func() { //every refused or failed real restore is recorded for the UI
		if retErr != nil && planned && !recorded && !crashed && !errors.Is(retErr, ErrNothingToRestore) {
			m.recordRestoreLocked(&RestoreRecord{At: m.now().Unix(), From: req.ID, Pre: preID, Scope: scope, Actor: req.Actor, Result: "failed", Detail: retErr.Error()})
		}
	}()
	meta, err := m.getLocked(req.ID)
	if err != nil {
		return nil, err
	}
	if m.readPending() != nil && !req.DryRun {
		return nil, errors.New("a previous restore is still waiting for its health confirmation; wait for it or let it roll back")
	}
	target, err := m.loadState(req.ID)
	if err != nil {
		return nil, fmt.Errorf("version %d cannot be read: %w", req.ID, err)
	}
	cur, _, err := m.collect()
	if err != nil {
		return nil, err
	}
	items, skipped, writes, deletes := m.plan(target, cur, scope)
	res = &RestoreResult{Version: meta, Scope: scope, DryRun: req.DryRun, Items: items, Skipped: skipped, NeedsWord: scope == "all"}
	if res.Items == nil {
		res.Items = []Change{}
	}
	if res.Skipped == nil {
		res.Skipped = []Skipped{}
	}

	if req.DryRun {
		// Show the restore direction: from the live state to the version.
		for _, it := range items {
			var ob, nb []byte
			if e, ok := cur[it.Path]; ok {
				ob = e.Data
			}
			if e, ok := target[it.Path]; ok {
				nb = e.Data
			}
			res.Diffs = append(res.Diffs, m.diffEntry(it.Path, it.Kind, ob, nb))
		}
		res.Message = "Preview only: nothing was changed."
		return res, nil
	}

	if len(items) == 0 {
		if len(skipped) > 0 {
			return res, errors.New("everything that differs is managed by a Fleet hub or cluster primary and was skipped; nothing to restore here")
		}
		return res, ErrNothingToRestore
	}
	if scope == "all" && strings.TrimSpace(req.Confirm) != ConfirmWord {
		return res, fmt.Errorf("restoring the whole configuration needs the confirmation word %s", ConfirmWord)
	}

	planned = true
	// Stage 1: validate before anything is touched
	if err := m.step("validate"); err != nil {
		return res, err
	}
	if err := m.validateWrites(writes); err != nil {
		return res, fmt.Errorf("restore refused, the running configuration was not changed: %w", err)
	}
	for _, p := range deletes {
		if !m.reg.ValidEntry(p) {
			return res, fmt.Errorf("restore refused: %q is not an allowed configuration path", p)
		}
	}

	// Stage 2: the way back
	m.hold[req.ID] = true
	defer delete(m.hold, req.ID)
	pre, _, err := m.captureLocked(CaptureInfo{Actor: req.Actor, Trigger: "pre-restore",
		Summary: fmt.Sprintf("Before restoring version %d (%s)", req.ID, m.scopeLabel(scope))})
	if err != nil {
		return res, fmt.Errorf("could not take the pre-restore snapshot, nothing was changed: %w", err)
	}
	m.hold[pre.ID] = true
	res.Pre, preID = pre.ID, pre.ID

	tag := m.now().UTC().Format("20060102T150405.000")
	staging := m.dir("staging-" + tag)
	backup := m.dir("backup-" + tag)
	cleanStaging := func() {
		if !crashed {
			os.RemoveAll(staging)
		}
	}
	defer cleanStaging()

	// Stage 3: stage the files
	fileWrites := make([]Entry, 0, len(writes))
	var tableWrites []Entry
	for _, e := range writes {
		if strings.HasPrefix(e.Path, dbPrefix) {
			tableWrites = append(tableWrites, e)
		} else {
			fileWrites = append(fileWrites, e)
		}
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return res, err
	}
	for _, e := range fileWrites {
		dst := filepath.Join(staging, filepath.FromSlash(e.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return res, err
		}
		if err := os.WriteFile(dst, e.Data, fileMode(e.Mode)); err != nil {
			return res, fmt.Errorf("staging %s failed, nothing was changed: %w", e.Path, err)
		}
	}
	if err := m.step("stage"); err != nil {
		if errors.Is(err, errCrash) {
			crashed = true
		}
		return res, err
	}
	// verify what was staged
	for _, e := range fileWrites {
		b, err := os.ReadFile(filepath.Join(staging, filepath.FromSlash(e.Path)))
		if err != nil || !bytes.Equal(b, e.Data) {
			return res, fmt.Errorf("staged copy of %s does not match, nothing was changed", e.Path)
		}
	}

	// Stage 4: swap
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return res, err
	}
	pend := &pendingRestore{Phase: "applying", At: m.now().Unix(), Pre: pre.ID, From: req.ID, Scope: scope, Actor: req.Actor, BackupDir: backup}
	for _, e := range fileWrites {
		_, err := os.Lstat(filepath.Join(m.opt.ConfDir, filepath.FromSlash(e.Path)))
		pend.Files = append(pend.Files, pendFile{Path: e.Path, Kind: "write", HadOld: err == nil})
	}
	for _, p := range deletes {
		if strings.HasPrefix(p, dbPrefix) {
			continue
		}
		pend.Files = append(pend.Files, pendFile{Path: p, Kind: "delete", HadOld: true})
	}
	for _, e := range tableWrites {
		pend.Tables = append(pend.Tables, strings.TrimPrefix(e.Path, dbPrefix))
	}
	for _, p := range deletes {
		if t, ok := strings.CutPrefix(p, dbPrefix); ok {
			pend.Tables = append(pend.Tables, t)
		}
	}
	if err := m.writePending(pend); err != nil {
		os.RemoveAll(backup)
		return res, err
	}
	rollback := func() error {
		err := m.rollbackFiles(pend)
		if e2 := m.applyTables(pend.Tables, cur); e2 != nil && err == nil {
			err = e2
		}
		return err
	}
	fail := func(cause error) (*RestoreResult, error) {
		if errors.Is(cause, errCrash) {
			crashed = true
			return res, cause
		}
		rbErr := rollback()
		os.Remove(m.dir(pendingFile))
		os.RemoveAll(backup)
		recorded = true
		m.recordRestoreLocked(&RestoreRecord{At: m.now().Unix(), From: req.ID, Pre: pre.ID, Scope: scope, Actor: req.Actor, Result: "failed", Detail: cause.Error()})
		if rbErr != nil {
			return res, fmt.Errorf("restore failed (%v) and the rollback was incomplete (%v); the pre-restore snapshot %d has the previous configuration", cause, rbErr, pre.ID)
		}
		return res, fmt.Errorf("restore failed, the previous configuration was put back: %w", cause)
	}

	for _, pf := range pend.Files {
		if err := m.step("swap:" + pf.Path); err != nil {
			return fail(err)
		}
		dst := filepath.Join(m.opt.ConfDir, filepath.FromSlash(pf.Path))
		bak := filepath.Join(backup, filepath.FromSlash(pf.Path))
		if fi, err := os.Lstat(dst); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				return fail(fmt.Errorf("%s is not a regular file", pf.Path))
			}
			if err := os.MkdirAll(filepath.Dir(bak), 0o700); err != nil {
				return fail(err)
			}
			if err := os.Rename(dst, bak); err != nil {
				return fail(fmt.Errorf("backup of %s failed: %w", pf.Path, err))
			}
		}
		if pf.Kind == "write" {
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return fail(err)
			}
			if err := os.Rename(filepath.Join(staging, filepath.FromSlash(pf.Path)), dst); err != nil {
				return fail(fmt.Errorf("install of %s failed: %w", pf.Path, err))
			}
		}
	}
	if err := m.step("tables"); err != nil {
		return fail(err)
	}
	if len(pend.Tables) > 0 {
		if err := m.applyTables(pend.Tables, target); err != nil {
			return fail(err)
		}
	}
	pend.Phase = "applied"
	if err := m.writePending(pend); err != nil {
		return fail(err)
	}
	if _, _, err := m.captureLocked(CaptureInfo{Actor: req.Actor, Trigger: "restore",
		Summary: fmt.Sprintf("Restored version %d (%s)", req.ID, m.scopeLabel(scope))}); err != nil {
		m.opt.Logf("[history] snapshot after restore failed: %v", err)
	}
	rec := &RestoreRecord{At: m.now().Unix(), From: req.ID, Pre: pre.ID, Scope: scope, Actor: req.Actor, Result: "pending"}
	if m.opt.Reload != nil {
		rec.Restarted = true
		m.recordRestoreLocked(rec)
		if err := m.opt.Reload(); err != nil {
			rbErr := rollback()
			os.Remove(m.dir(pendingFile))
			os.RemoveAll(backup)
			recorded = true
			m.recordRestoreLocked(&RestoreRecord{At: m.now().Unix(), From: req.ID, Pre: pre.ID, Scope: scope, Actor: req.Actor, Result: "failed", Detail: "restart failed: " + err.Error()})
			if rbErr != nil {
				return res, fmt.Errorf("restart failed (%v) and the rollback was incomplete (%v); the pre-restore snapshot %d has the previous configuration", err, rbErr, pre.ID)
			}
			return res, fmt.Errorf("restart failed, the previous configuration was put back: %w", err)
		}
		res.Restarting = true
		res.Message = fmt.Sprintf("Restored version %d. Zoraxy is restarting; if it does not come back healthy within %d seconds the previous configuration is put back automatically.", req.ID, int(m.opt.HealthyAfter.Seconds()))
	} else {
		rec.Result = "confirmed"
		m.recordRestoreLocked(rec)
		os.Remove(m.dir(pendingFile))
		os.RemoveAll(backup)
		res.Message = fmt.Sprintf("Restored version %d. Restart Zoraxy to load it.", req.ID)
	}
	res.Applied = true
	return res, nil
}

func (m *Manager) scopeLabel(scope string) string {
	if scope == "all" {
		return "whole configuration"
	}
	return m.reg.AreaLabel(scope)
}

func fileMode(mode uint32) os.FileMode {
	return os.FileMode(mode&0o666) | 0o600
}

// rollbackFiles undoes the renames of a restore (also used after a crash).
func (m *Manager) rollbackFiles(p *pendingRestore) error {
	var errs []string
	for i := len(p.Files) - 1; i >= 0; i-- {
		pf := p.Files[i]
		rel := filepath.FromSlash(pf.Path)
		if !m.reg.ValidFile(pf.Path) {
			continue
		}
		dst := filepath.Join(m.opt.ConfDir, rel)
		bak := filepath.Join(p.BackupDir, rel)
		if _, err := os.Lstat(bak); err == nil {
			os.Remove(dst)
			if err := os.Rename(bak, dst); err != nil {
				errs = append(errs, err.Error())
			}
		} else if pf.Kind == "write" && !pf.HadOld {
			os.Remove(dst)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// applyTables makes the listed tables equal to the exports in src (a missing
// export means an empty table).
func (m *Manager) applyTables(tables []string, src State) error {
	if m.opt.DB == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, t := range tables {
		if seen[t] {
			continue
		}
		seen[t] = true
		if !m.reg.ValidTable(dbPrefix + t) {
			return fmt.Errorf("table %q is not allowed", t)
		}
		var want map[string]json.RawMessage
		if e, ok := src[dbPrefix+t]; ok {
			if err := json.Unmarshal(e.Data, &want); err != nil {
				return fmt.Errorf("table %s: %w", t, err)
			}
		}
		if !m.opt.DB.TableExists(t) {
			if len(want) == 0 {
				continue
			}
			if err := m.opt.DB.NewTable(t); err != nil {
				return err
			}
		}
		rows, err := m.opt.DB.ListTable(t)
		if err != nil {
			return err
		}
		have := map[string][]byte{}
		for _, kv := range rows {
			if len(kv) == 2 {
				have[string(kv[0])] = kv[1]
			}
		}
		for k := range have {
			if _, ok := want[k]; !ok && json.Valid(have[k]) { //keep non JSON rows we never exported
				if err := m.opt.DB.Delete(t, k); err != nil {
					return fmt.Errorf("table %s: %w", t, err)
				}
			}
		}
		for _, k := range sortedKeys(want) {
			if cur, ok := have[k]; ok {
				var a, b bytes.Buffer
				if json.Compact(&a, cur) == nil && json.Compact(&b, want[k]) == nil && bytes.Equal(a.Bytes(), b.Bytes()) {
					continue
				}
			}
			if err := m.step("db:" + t + "/" + k); err != nil {
				return err
			}
			if err := m.opt.DB.Write(t, k, want[k]); err != nil {
				return fmt.Errorf("table %s: %w", t, err)
			}
		}
	}
	return nil
}

func (m *Manager) recordRestoreLocked(rec *RestoreRecord) {
	idx, err := m.loadIndexLocked()
	if err != nil {
		return
	}
	idx.LastRestore = rec
	if err := m.saveIndexLocked(); err != nil {
		m.opt.Logf("[history] could not record the restore outcome: %v", err)
	}
}

// ---------------------------------------------------------------- boot guard

// BootGuard must run early in main(), right after sys.db is open and before
// any module reads its configuration. It finishes the job of a restore that
// did not complete: after a crash during the swap the old files come back at
// once; when the first start with the restored configuration never confirmed
// healthy (a second start finds the marker again) the pre-restore state is put
// back.
func (m *Manager) BootGuard() {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.readPending()
	if p == nil {
		return
	}
	reason := ""
	switch {
	case p.Phase == "applying":
		reason = "the restore was interrupted while it was being applied"
	case p.Attempts < 1:
		p.Attempts++
		m.writePending(p)
		return
	default:
		reason = "Zoraxy did not become healthy with the restored configuration"
	}
	err := m.rollbackFiles(p)
	if len(p.Tables) > 0 && m.opt.DB != nil {
		if pre, e := m.loadState(p.Pre); e == nil {
			if e2 := m.applyTables(p.Tables, pre); e2 != nil && err == nil {
				err = e2
			}
		} else if err == nil {
			err = fmt.Errorf("pre-restore snapshot %d unreadable: %w", p.Pre, e)
		}
	}
	rec := &RestoreRecord{At: m.now().Unix(), From: p.From, Pre: p.Pre, Scope: p.Scope, Actor: p.Actor, Result: "rolled_back", Detail: reason + "; the previous configuration was restored", Restarted: true}
	if err != nil {
		rec.Result, rec.Detail = "failed", reason+"; the rollback was incomplete: "+err.Error()+fmt.Sprintf(" (snapshot %d holds the previous configuration)", p.Pre)
		m.opt.Logf("[history] %s", rec.Detail)
	} else {
		os.RemoveAll(p.BackupDir)
		os.Remove(m.dir(pendingFile))
		m.opt.Logf("[history] restore of version %d rolled back: %s", p.From, reason)
	}
	m.recordRestoreLocked(rec)
}

// MarkHealthy confirms a restore after a stable start (call it HealthyAfter
// after boot). It drops the working backup.
func (m *Manager) MarkHealthy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.readPending()
	if p == nil || p.Phase != "applied" {
		return
	}
	os.Remove(m.dir(pendingFile))
	os.RemoveAll(p.BackupDir)
	if idx, err := m.loadIndexLocked(); err == nil && idx.LastRestore != nil && idx.LastRestore.Result == "pending" {
		idx.LastRestore.Result = "confirmed"
		m.saveIndexLocked()
	}
}

// HealthyAfter is the confirmation delay.
func (m *Manager) HealthyAfter() time.Duration { return m.opt.HealthyAfter }

// cleanStale removes working folders no pending restore refers to.
func (m *Manager) cleanStale() {
	m.mu.Lock()
	defer m.mu.Unlock()
	pend := m.readPending()
	ents, err := os.ReadDir(m.dir())
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() && (strings.HasPrefix(n, "staging-") || strings.HasPrefix(n, "backup-")) {
			if pend != nil && filepath.Base(pend.BackupDir) == n {
				continue
			}
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		os.RemoveAll(m.dir(n))
	}
}
