package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	users.go

	Multiple admin panel accounts with roles (upstream #89, #501).

	Storage (table "auth", next to the existing passhash/<user> and email/<user>):
	  role/<user>      "admin" | "viewer"  (missing = admin, so accounts created by older
	                   versions keep full access after an upgrade)
	  disabled/<user>  true when the account is disabled
	  sessver/<user>   session generation, bumped when the password changes or the account
	                   is disabled / deleted / renamed. A session cookie is only accepted
	                   while its generation still matches (missing = 0, so existing
	                   logins survive the upgrade).

	The role is always read from the database, never from the cookie.
*/

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"

	MinNewPasswordLength = 8
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)

// ValidUsername checks a name for a new or renamed account
func ValidUsername(name string) bool { return usernameRe.MatchString(name) }

// UserInfo is the public view of an account
type UserInfo struct {
	Username string
	Role     string
	Disabled bool
}

type userState struct {
	at       time.Time
	exists   bool
	role     string
	disabled bool
	ver      int
}

type userCache struct {
	mu sync.RWMutex
	m  map[string]userState
}

var errLastAdmin = errors.New("refused: this would leave no enabled admin account")

func (a *AuthAgent) loadState(username string) userState {
	a.cache.mu.RLock()
	st, ok := a.cache.m[username]
	a.cache.mu.RUnlock()
	if ok && time.Since(st.at) < 30*time.Second {
		return st
	}
	st = userState{role: RoleAdmin, at: time.Now()}
	st.exists = a.UserExists(username)
	if st.exists {
		var role string
		if a.Database.Read("auth", "role/"+username, &role) == nil && role == RoleViewer {
			st.role = RoleViewer
		}
		var dis bool
		if a.Database.Read("auth", "disabled/"+username, &dis) == nil {
			st.disabled = dis
		}
		var ver int
		a.Database.Read("auth", "sessver/"+username, &ver)
		st.ver = ver
	}
	a.cache.mu.Lock()
	if a.cache.m == nil {
		a.cache.m = map[string]userState{}
	}
	a.cache.m[username] = st
	a.cache.mu.Unlock()
	return st
}

func (a *AuthAgent) invalidate(usernames ...string) {
	a.cache.mu.Lock()
	for _, u := range usernames {
		delete(a.cache.m, u)
	}
	a.cache.mu.Unlock()
}

// GetRole returns the role of an account (unknown accounts: "")
func (a *AuthAgent) GetRole(username string) string {
	st := a.loadState(username)
	if !st.exists {
		return ""
	}
	return st.role
}

// RequestRole returns the role of the logged-in user of a request ("" = not logged in)
func (a *AuthAgent) RequestRole(r *http.Request) string {
	name, ok := a.sessionUser(r)
	if !ok {
		return ""
	}
	return a.GetRole(name)
}

// sessionUser returns the username of a valid session (account exists, enabled,
// session generation current)
func (a *AuthAgent) sessionUser(r *http.Request) (string, bool) {
	session, err := a.SessionStore.Get(r, a.SessionName)
	if err != nil {
		return "", false
	}
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		return "", false
	}
	name, ok := session.Values["username"].(string)
	if !ok || name == "" {
		return "", false
	}
	if a.sessionExpired(session.Values) || a.legacySessionTooOld(r, session.Values) {
		return "", false
	}
	ver, _ := session.Values["sessver"].(int)
	st := a.loadState(name)
	if !st.exists || st.disabled || st.ver != ver {
		return "", false
	}
	return name, true
}

// ListUserInfo lists all accounts sorted by name
func (a *AuthAgent) ListUserInfo() []UserInfo {
	out := []UserInfo{}
	for _, n := range a.ListUsers() {
		st := a.loadState(n)
		out = append(out, UserInfo{Username: n, Role: st.role, Disabled: st.disabled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (a *AuthAgent) enabledAdminsExcluding(except string) int {
	n := 0
	for _, u := range a.ListUserInfo() {
		if u.Username != except && u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

func validRole(role string) bool { return role == RoleAdmin || role == RoleViewer }

// CreateUser creates an account with a role (admin API; enforces name and password rules)
func (a *AuthAgent) CreateUser(username, password, role string) error {
	if !ValidUsername(username) {
		return errors.New("username must be 1-64 characters of letters, digits and _ . @ -")
	}
	if len(password) < MinNewPasswordLength {
		return errors.New("password must be at least 8 characters")
	}
	if !validRole(role) {
		return errors.New("role must be admin or viewer")
	}
	if err := a.CreateUserAccount(username, password, ""); err != nil {
		return err
	}
	if role == RoleViewer {
		if err := a.Database.Write("auth", "role/"+username, RoleViewer); err != nil {
			a.UnregisterUser(username)
			return err
		}
	}
	a.invalidate(username)
	return nil
}

// SetRole changes the role of an account
func (a *AuthAgent) SetRole(username, role string) error {
	if !validRole(role) {
		return errors.New("role must be admin or viewer")
	}
	st := a.loadState(username)
	if !st.exists {
		return errors.New("no such user")
	}
	if role != RoleAdmin && st.role == RoleAdmin && !st.disabled && a.enabledAdminsExcluding(username) == 0 {
		return errLastAdmin
	}
	if err := a.Database.Write("auth", "role/"+username, role); err != nil {
		return err
	}
	a.bumpSession(username)
	return nil
}

// SetDisabled disables or enables an account; disabling ends its sessions
func (a *AuthAgent) SetDisabled(username string, disabled bool) error {
	st := a.loadState(username)
	if !st.exists {
		return errors.New("no such user")
	}
	if disabled && st.role == RoleAdmin && !st.disabled && a.enabledAdminsExcluding(username) == 0 {
		return errLastAdmin
	}
	if err := a.Database.Write("auth", "disabled/"+username, disabled); err != nil {
		return err
	}
	a.bumpSession(username)
	return nil
}

// DeleteUser removes an account (never the last enabled admin)
func (a *AuthAgent) DeleteUser(username string) error {
	st := a.loadState(username)
	if !st.exists {
		return errors.New("no such user")
	}
	if st.role == RoleAdmin && !st.disabled && a.enabledAdminsExcluding(username) == 0 {
		return errLastAdmin
	}
	a.Database.Delete("auth", "role/"+username)
	a.Database.Delete("auth", "disabled/"+username)
	a.Database.Delete("auth", "sessver/"+username)
	err := a.UnregisterUser(username)
	a.invalidate(username)
	return err
}

// bumpSession invalidates all sessions of an account
func (a *AuthAgent) bumpSession(username string) {
	ver := a.loadState(username).ver + 1
	a.Database.Write("auth", "sessver/"+username, ver)
	a.invalidate(username)
}

// SetPassword replaces the password of an account and ends all of its sessions
func (a *AuthAgent) SetPassword(username, newPassword string) error {
	if len(newPassword) < MinNewPasswordLength {
		return errors.New("password must be at least 8 characters")
	}
	if !a.UserExists(username) {
		return errors.New("no such user")
	}
	if err := a.Database.Write("auth", "passhash/"+username, HashPassword(newPassword)); err != nil {
		return err
	}
	a.bumpSession(username)
	return nil
}

// RenameUser changes the username (upstream #501). All sessions of the account end.
func (a *AuthAgent) RenameUser(oldName, newName string) error {
	if !ValidUsername(newName) {
		return errors.New("username must be 1-64 characters of letters, digits and _ . @ -")
	}
	if oldName == newName {
		return nil
	}
	if !a.UserExists(oldName) {
		return errors.New("no such user")
	}
	if a.UserExists(newName) {
		return errors.New("a user with that name already exists")
	}
	st := a.loadState(oldName)
	var hash, email string
	if err := a.Database.Read("auth", "passhash/"+oldName, &hash); err != nil {
		return err
	}
	a.Database.Read("auth", "email/"+oldName, &email)
	//Write the new records first so a failure in the middle can never lose the account
	if err := a.Database.Write("auth", "passhash/"+newName, hash); err != nil {
		return err
	}
	if email != "" {
		a.Database.Write("auth", "email/"+newName, email)
	}
	if st.role == RoleViewer {
		a.Database.Write("auth", "role/"+newName, RoleViewer)
	}
	if st.disabled {
		a.Database.Write("auth", "disabled/"+newName, true)
	}
	a.Database.Write("auth", "sessver/"+newName, st.ver+1)
	a.Database.Delete("auth", "passhash/"+oldName)
	a.Database.Delete("auth", "email/"+oldName)
	a.Database.Delete("auth", "role/"+oldName)
	a.Database.Delete("auth", "disabled/"+oldName)
	a.Database.Delete("auth", "sessver/"+oldName)
	a.invalidate(oldName, newName)
	return nil
}

/* Login / session glue */

// loginAllowed is checked after the password verified: disabled accounts cannot log in
func (a *AuthAgent) loginAllowed(username string) bool {
	st := a.loadState(username)
	return st.exists && !st.disabled
}

// IssueSession (re)creates the session cookie of a user at the current session generation
func (a *AuthAgent) IssueSession(w http.ResponseWriter, r *http.Request, username string, rememberme bool) {
	a.LoginUserByRequest(w, r, username, rememberme)
}

/* Audit log */

// AuditEntry is one line of the audit log
type AuditEntry struct {
	Time   int64
	Actor  string
	Event  string
	Target string `json:",omitempty"`
	IP     string `json:",omitempty"`
	Detail string `json:",omitempty"`
}

const auditMaxBytes = 2 << 20

type auditLog struct {
	mu     sync.Mutex
	path   string
	recent []AuditEntry
}

// SetAuditFile enables the persistent audit log (JSON lines, rotated at 2 MiB)
func (a *AuthAgent) SetAuditFile(path string) {
	a.audit.mu.Lock()
	a.audit.path = path
	a.audit.mu.Unlock()
}

// Audit records an admin account event. Secrets must never be passed in.
func (a *AuthAgent) Audit(actor, event, target, ip, detail string) {
	e := AuditEntry{Time: time.Now().Unix(), Actor: actor, Event: event, Target: target, IP: ip, Detail: detail}
	a.audit.mu.Lock()
	defer a.audit.mu.Unlock()
	a.audit.recent = append(a.audit.recent, e)
	if len(a.audit.recent) > 200 {
		a.audit.recent = a.audit.recent[len(a.audit.recent)-200:]
	}
	if a.audit.path == "" {
		return
	}
	line, _ := json.Marshal(e)
	appendLineRotating(a.audit.path, append(line, '\n'))
}

// RecentAudit returns the latest entries, newest first
func (a *AuthAgent) RecentAudit() []AuditEntry {
	a.audit.mu.Lock()
	defer a.audit.mu.Unlock()
	out := make([]AuditEntry, len(a.audit.recent))
	for i, e := range a.audit.recent {
		out[len(out)-1-i] = e
	}
	return out
}

/* HTTP API (admin only, mutations POST) */

func (a *AuthAgent) currentAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	name, ok := a.sessionUser(r)
	if !ok {
		http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
		return "", false
	}
	if a.GetRole(name) != RoleAdmin {
		http.Error(w, "403 - Admin role required", http.StatusForbidden)
		return "", false
	}
	return name, true
}

// HandleUserList lists accounts and recent audit entries (GET, admin)
func (a *AuthAgent) HandleUserList(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.currentAdmin(w, r); !ok {
		return
	}
	js, _ := json.Marshal(struct {
		Users []UserInfo
		Audit []AuditEntry
	}{a.ListUserInfo(), a.RecentAudit()})
	utils.SendJSONResponse(w, string(js))
}

// HandleUserAction handles POST action=create|delete|disable|enable|setRole|setPassword|rename
func (a *AuthAgent) HandleUserAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor, ok := a.currentAdmin(w, r)
	if !ok {
		return
	}
	action, _ := utils.PostPara(r, "action")
	target, _ := utils.PostPara(r, "username")
	ip := clientAddr(r)
	var err error
	detail := ""
	switch action {
	case "create":
		role, _ := utils.PostPara(r, "role")
		pw, _ := utils.PostPara(r, "password")
		if role == "" {
			role = RoleViewer
		}
		detail = "role=" + role
		err = a.CreateUser(target, pw, role)
	case "delete":
		if target == actor {
			err = errors.New("you cannot delete your own account; ask another admin")
		} else {
			err = a.DeleteUser(target)
		}
	case "disable", "enable":
		if target == actor && action == "disable" {
			err = errors.New("you cannot disable your own account")
		} else {
			err = a.SetDisabled(target, action == "disable")
		}
	case "setRole":
		role, _ := utils.PostPara(r, "role")
		detail = "role=" + role
		err = a.SetRole(target, role)
	case "setPassword":
		pw, _ := utils.PostPara(r, "password")
		err = a.SetPassword(target, pw)
	case "rename":
		newName, _ := utils.PostPara(r, "newUsername")
		detail = "to=" + newName
		err = a.RenameUser(target, newName)
		if err == nil && target == actor {
			a.Audit(actor, "user.rename", target, ip, detail)
			a.Logout(w, r) //the session belongs to the old name
			utils.SendOK(w)
			return
		}
	default:
		err = errors.New("unknown action")
	}
	if err != nil {
		a.Audit(actor, "user."+action+".failed", target, ip, err.Error())
		utils.SendErrorResponse(w, err.Error())
		return
	}
	a.Audit(actor, "user."+action, target, ip, detail)
	utils.SendOK(w)
}

// HandleChangeOwnPassword lets any logged-in user (including viewers) change their own password.
// Other sessions of the account end; the current session is re-issued.
func (a *AuthAgent) HandleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, ok := a.sessionUser(r)
	if !ok {
		http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
		return
	}
	oldPassword, err := utils.PostPara(r, "oldPassword")
	if err != nil {
		utils.SendErrorResponse(w, "empty current password")
		return
	}
	newPassword, err := utils.PostPara(r, "newPassword")
	if err != nil {
		utils.SendErrorResponse(w, "empty new password")
		return
	}
	confirmPassword, _ := utils.PostPara(r, "confirmPassword")
	if newPassword != confirmPassword {
		utils.SendErrorResponse(w, "confirm password not match")
		return
	}
	if okPw, _ := a.ValidateUsernameAndPasswordWithReason(username, oldPassword); !okPw {
		a.Audit(username, "password.change.failed", username, clientAddr(r), "wrong current password")
		if a.OnLoginFailure != nil {
			a.OnLoginFailure(r, username)
		}
		utils.SendErrorResponse(w, "Invalid current password given")
		return
	}
	if err := a.SetPassword(username, newPassword); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	a.Audit(username, "password.change", username, clientAddr(r), "")
	a.IssueSession(w, r, username, sessionRemember(a, r))
	utils.SendOK(w)
}

func sessionRemember(a *AuthAgent, r *http.Request) bool {
	s, err := a.SessionStore.Get(r, a.SessionName)
	if err != nil {
		return false
	}
	b, _ := s.Values["rememberMe"].(bool)
	return b
}

func clientAddr(r *http.Request) string {
	h := r.RemoteAddr
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = strings.Trim(h[:i], "[]")
	}
	return h
}

// appendLineRotating appends to a log file, rotating it to <path>.1 above auditMaxBytes
func appendLineRotating(path string, line []byte) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > auditMaxBytes {
		os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(line)
}
