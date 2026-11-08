//go:build !windows

package plugins

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

/*
	runas_unix.go

	Run plugin processes as an unprivileged OS user (upstream #760).

	ManagerOptions.RunAsUser / RunAsGroup (flags -plugin_user / -plugin_group) are names or numeric ids.
	When RunAsUser is set the plugin process is started with that uid / gid (syscall.SysProcAttr.Credential,
	supplementary groups of the Zoraxy process are NOT inherited, only the group given or the user's
	primary group), and HOME / USER / LOGNAME of the environment are set to the user's.

	Only root can switch users, so a non-root Zoraxy gets a clear error instead of silently running the plugin
	with its own privileges (fail closed).

	File ownership is not touched. The user needs to be able to execute the plugin binary and to enter its
	folder, and should own the folder if the plugin saves data there. This is checked before the start and the
	error says which command fixes it, for example: chown -R plugin:plugin ./plugins/<name>.
*/

var (
	geteuid     = os.Geteuid //test seam
	lookupUser  = user.Lookup
	lookupUID   = user.LookupId
	lookupGroup = user.LookupGroup
)

// runAsCredential resolves the configured user and group into numeric ids
func runAsCredential(userSpec, groupSpec string) (*syscall.Credential, *user.User, error) {
	u, err := lookupUser(userSpec)
	if err != nil {
		if _, convErr := strconv.ParseUint(userSpec, 10, 32); convErr == nil {
			u, err = lookupUID(userSpec)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("plugin user %q not found: %w", userSpec, err)
		}
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin user %q has a non numeric uid", userSpec)
	}
	gidStr := u.Gid
	if g := strings.TrimSpace(groupSpec); g != "" {
		grp, err := lookupGroup(g)
		if err != nil {
			if _, convErr := strconv.ParseUint(g, 10, 32); convErr != nil {
				return nil, nil, fmt.Errorf("plugin group %q not found: %w", g, err)
			}
			gidStr = g //numeric gid without a group entry
		} else {
			gidStr = grp.Gid
		}
	}
	gid, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin group %q has a non numeric gid", groupSpec)
	}
	if uid == 0 || gid == 0 {
		return nil, nil, errors.New("plugin user / group resolve to root, which defeats the purpose; choose an unprivileged account")
	}
	//Groups left empty: setgroups(0) drops the supplementary groups of the Zoraxy process
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, u, nil
}

// canAccess reports whether uid / gid has the wanted permission bits (4 read, 2 write, 1 execute) on info
func canAccess(info os.FileInfo, uid, gid uint32, want uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true //cannot tell, do not block
	}
	mode := uint32(info.Mode().Perm())
	var bits uint32
	switch {
	case st.Uid == uid:
		bits = (mode >> 6) & 7
	case st.Gid == gid:
		bits = (mode >> 3) & 7
	default:
		bits = mode & 7
	}
	return bits&want == want
}

// checkRunAsAccess makes sure the target user can run the binary and enter its folder
func checkRunAsAccess(binary string, cred *syscall.Credential, userName string) error {
	dir := filepath.Dir(binary)
	fix := fmt.Sprintf("fix the permissions, for example: chown -R %s %s", userName, dir)
	//Every parent directory must be searchable (x) by the user
	for d := dir; ; d = filepath.Dir(d) {
		info, err := os.Stat(d)
		if err != nil {
			return err
		}
		if !canAccess(info, cred.Uid, cred.Gid, 1) {
			return fmt.Errorf("user %s cannot enter %s: %s", userName, d, fix)
		}
		if d == filepath.Dir(d) {
			break
		}
	}
	info, err := os.Stat(binary)
	if err != nil {
		return err
	}
	if !canAccess(info, cred.Uid, cred.Gid, 5) {
		return fmt.Errorf("user %s cannot read and execute %s: %s", userName, binary, fix)
	}
	return nil
}

func runAsEnv(base []string, u *user.User) []string {
	env := make([]string, 0, len(base)+3)
	for _, kv := range base {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "USER=") || strings.HasPrefix(kv, "LOGNAME=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+u.HomeDir, "USER="+u.Username, "LOGNAME="+u.Username)
}

// applyRunAs configures cmd to run as the configured unprivileged user. A no-op when no user is configured.
func (m *Manager) applyRunAs(cmd *exec.Cmd, binary string) error {
	if m.Options == nil || strings.TrimSpace(m.Options.RunAsUser) == "" {
		return nil
	}
	if geteuid() != 0 {
		return errors.New("plugins are configured to run as user " + m.Options.RunAsUser + " (-plugin_user) but Zoraxy is not running as root, so it cannot switch users; start Zoraxy as root or remove the setting")
	}
	cred, u, err := runAsCredential(strings.TrimSpace(m.Options.RunAsUser), m.Options.RunAsGroup)
	if err != nil {
		return err
	}
	if err := checkRunAsAccess(binary, cred, u.Username); err != nil {
		return err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = cred
	cmd.Env = runAsEnv(os.Environ(), u)
	return nil
}
