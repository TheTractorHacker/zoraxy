package dynamicproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	basicauth_ext.go

	Two opt-in extensions of basic auth (upstream #621, #1006):

	1. Named credential lists. A list (name -> credentials with argon2id hashes) is stored once
	   and assigned to any number of proxy rules through AuthenticationProvider.BasicAuthListNames.
	   A request is accepted if the username / password matches the rule's own credentials OR any
	   assigned list. Unknown list names grant nothing. Lists are persisted to a 0600 file.

	2. Path scoped basic auth. AuthenticationProvider.BasicAuthScopePrefixes limits basic auth to
	   requests below one of the prefixes (e.g. a virtual directory such as /admin); everything else
	   is served without it. Scope matching is deliberately LIBERAL: a request is in scope if ANY
	   plausible reading of its path (encoded dots / slashes, ;params, backslashes, double encoding,
	   dot segments) falls under a prefix, the same hardening as path rules, so crafted paths cannot
	   slip below the protected prefix. A broken scope config fails closed (503).
*/

const (
	maxCredentialLists   = 100
	maxCredsPerList      = 500
	maxScopePrefixes     = 50
	maxBasicListNames    = 20
	maxCredentialListLen = 64
)

var credListNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)

// CredentialLists is the store of named basic auth credential lists
type CredentialLists struct {
	mu    sync.RWMutex
	path  string
	lists map[string][]*BasicAuthCredentials
}

// NewCredentialLists loads (or creates empty) the store at path ("" = memory only)
func NewCredentialLists(path string) (*CredentialLists, error) {
	c := &CredentialLists{path: path, lists: map[string][]*BasicAuthCredentials{}}
	if path == "" {
		return c, nil
	}
	js, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(js, &c.lists); err != nil {
		return nil, fmt.Errorf("credential lists: %w", err)
	}
	return c, nil
}

func (c *CredentialLists) saveLocked() error {
	if c.path == "" {
		return nil
	}
	js, err := json.MarshalIndent(c.lists, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, js, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Names returns the list names, sorted
func (c *CredentialLists) Names() []string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.lists))
	for n := range c.lists {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Usernames returns the usernames of a list (never the hashes)
func (c *CredentialLists) Usernames(name string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []string
	for _, cr := range c.lists[name] {
		out = append(out, cr.Username)
	}
	return out
}

// copyOf returns value copies of the credentials of the named lists
func (c *CredentialLists) copyOf(names []string) []*BasicAuthCredentials {
	if c == nil || len(names) == 0 {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*BasicAuthCredentials
	for _, n := range names {
		for _, cr := range c.lists[n] {
			cp := *cr
			out = append(out, &cp)
		}
	}
	return out
}

// Set replaces a list. An empty Password keeps the stored hash of an existing user.
// hash turns a clear password into a stored hash.
func (c *CredentialLists) Set(name string, users []*BasicAuthUnhashedCredentials, hash func(string) string) error {
	if !credListNameRe.MatchString(name) {
		return errors.New("list name must be 1-64 characters: letters, digits, space, _ . -")
	}
	if len(users) > maxCredsPerList {
		return fmt.Errorf("too many users (max %d)", maxCredsPerList)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.lists[name]; !exists && len(c.lists) >= maxCredentialLists {
		return errors.New("too many credential lists")
	}
	old := map[string]string{}
	for _, cr := range c.lists[name] {
		old[cr.Username] = cr.PasswordHash
	}
	next := make([]*BasicAuthCredentials, 0, len(users))
	seen := map[string]bool{}
	for _, u := range users {
		if u == nil || u.Username == "" || len(u.Username) > 128 {
			return errors.New("invalid username")
		}
		if seen[u.Username] {
			return errors.New("duplicate username " + u.Username)
		}
		seen[u.Username] = true
		switch {
		case u.Password != "":
			next = append(next, &BasicAuthCredentials{Username: u.Username, PasswordHash: hash(u.Password)})
		case old[u.Username] != "":
			next = append(next, &BasicAuthCredentials{Username: u.Username, PasswordHash: old[u.Username]})
		default:
			return errors.New("a password is required for new user " + u.Username)
		}
	}
	prev, had := c.lists[name]
	c.lists[name] = next
	if err := c.saveLocked(); err != nil {
		if had {
			c.lists[name] = prev
		} else {
			delete(c.lists, name)
		}
		return err
	}
	return nil
}

// Delete removes a list
func (c *CredentialLists) Delete(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, ok := c.lists[name]
	if !ok {
		return errors.New("no such list")
	}
	delete(c.lists, name)
	if err := c.saveLocked(); err != nil {
		c.lists[name] = prev
		return err
	}
	return nil
}

// Exists reports whether a list exists
func (c *CredentialLists) Exists(name string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.lists[name]
	return ok
}

// ValidateBasicAuthExtras checks scope prefixes and list names before they are stored
func ValidateBasicAuthExtras(prefixes []string, listNames []string, lists *CredentialLists) error {
	if len(prefixes) > maxScopePrefixes {
		return fmt.Errorf("too many scope prefixes (max %d)", maxScopePrefixes)
	}
	for _, p := range prefixes {
		if _, err := compilePathRule(&PathRule{MatchMode: PathRuleMatchPrefix, Pattern: p, Action: PathRuleDeny}); err != nil {
			return fmt.Errorf("scope prefix %q: %w", p, err)
		}
	}
	if len(listNames) > maxBasicListNames {
		return fmt.Errorf("too many credential lists (max %d)", maxBasicListNames)
	}
	for _, n := range listNames {
		if !lists.Exists(n) {
			return fmt.Errorf("credential list %q does not exist", n)
		}
	}
	return nil
}

// initBasicScope compiles AuthenticationProvider.BasicAuthScopePrefixes
func (pe *ProxyEndpoint) initBasicScope() {
	pe.basicScope, pe.basicScopeErr = nil, nil
	ap := pe.AuthenticationProvider
	if ap == nil || len(ap.BasicAuthScopePrefixes) == 0 {
		return
	}
	if len(ap.BasicAuthScopePrefixes) > maxScopePrefixes {
		pe.basicScopeErr = errors.New("too many scope prefixes")
		return
	}
	for _, p := range ap.BasicAuthScopePrefixes {
		c, err := compilePathRule(&PathRule{MatchMode: PathRuleMatchPrefix, Pattern: p, Action: PathRuleDeny})
		if err != nil {
			pe.basicScopeErr = fmt.Errorf("basic auth scope %q: %w", p, err)
			pe.basicScope = nil
			return
		}
		pe.basicScope = append(pe.basicScope, c)
	}
}

// basicAuthInScope reports whether basic auth applies to the request
func basicAuthInScope(pe *ProxyEndpoint, r *http.Request) bool {
	if len(pe.basicScope) == 0 {
		return true //no scope configured: whole host (unchanged behaviour)
	}
	target := pathmatch.RequestTarget(r)
	for _, s := range pe.basicScope {
		if s.matchesRequest(target, r.Method) {
			return true
		}
	}
	return false
}

// listCredentialsFor returns copies of the credentials of the lists assigned to the endpoint
func (pe *ProxyEndpoint) listCredentialsFor() []*BasicAuthCredentials {
	if pe.parent == nil || pe.parent.Option == nil || pe.AuthenticationProvider == nil {
		return nil
	}
	return pe.parent.Option.BasicAuthLists.copyOf(pe.AuthenticationProvider.BasicAuthListNames)
}
