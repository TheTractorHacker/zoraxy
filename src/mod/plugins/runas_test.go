//go:build !windows

package plugins

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

func newRunAsManager(userName, group string) *Manager {
	lg, _ := logger.NewFmtLogger()
	return &Manager{Options: &ManagerOptions{RunAsUser: userName, RunAsGroup: group, Logger: lg}}
}

func TestRunAs_NoopWhenUnset(t *testing.T) {
	cmd := exec.Command("true")
	if err := newRunAsManager("", "").applyRunAs(cmd, "/bin/true"); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr != nil || cmd.Env != nil {
		t.Fatal("process attributes changed although no user is configured")
	}
}

func TestRunAs_RefusedWhenNotRoot(t *testing.T) {
	old := geteuid
	defer func() { geteuid = old }()
	geteuid = func() int { return 1000 }
	cmd := exec.Command("true")
	err := newRunAsManager("nobody", "").applyRunAs(cmd, "/bin/true")
	if err == nil || !strings.Contains(err.Error(), "not running as root") {
		t.Fatalf("expected a clear not-root error, got %v", err)
	}
	if cmd.SysProcAttr != nil {
		t.Fatal("credential set although the switch is refused")
	}
}

// Simulates root with a made-up directory so the whole path runs without privileges
func TestRunAs_SetsCredentialAndEnv(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if cur.Uid == "0" {
		t.Skip("test needs an unprivileged current user")
	}
	oldEuid, oldLookup := geteuid, lookupUser
	defer func() { geteuid, lookupUser = oldEuid, oldLookup }()
	geteuid = func() int { return 0 }

	dir := t.TempDir()
	bin := filepath.Join(dir, "plugin")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin)
	if err := newRunAsManager(cur.Username, "").applyRunAs(cmd, bin); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("no credential set")
	}
	if strconv.FormatUint(uint64(cmd.SysProcAttr.Credential.Uid), 10) != cur.Uid {
		t.Fatalf("uid = %d, want %s", cmd.SysProcAttr.Credential.Uid, cur.Uid)
	}
	if len(cmd.SysProcAttr.Credential.Groups) != 0 {
		t.Fatal("supplementary groups of the Zoraxy process would be inherited")
	}
	hasHome := false
	for _, kv := range cmd.Env {
		if kv == "HOME="+cur.HomeDir {
			hasHome = true
		}
	}
	if !hasHome {
		t.Fatal("HOME not set to the plugin user's home")
	}

	//Unknown user
	cmd = exec.Command(bin)
	if err := newRunAsManager("no-such-user-xyz", "").applyRunAs(cmd, bin); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown user: %v", err)
	}
	//Unknown group
	if err := newRunAsManager(cur.Username, "no-such-group-xyz").applyRunAs(exec.Command(bin), bin); err == nil {
		t.Fatal("unknown group accepted")
	}
}

func TestRunAs_RefusesRootAccounts(t *testing.T) {
	oldEuid := geteuid
	defer func() { geteuid = oldEuid }()
	geteuid = func() int { return 0 }
	root, err := user.Lookup("root")
	if err != nil {
		t.Skip(err)
	}
	if err := newRunAsManager(root.Username, "").applyRunAs(exec.Command("true"), "/bin/true"); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root as plugin user accepted: %v", err)
	}
}

func TestRunAs_AccessCheck(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "plugin")
	os.WriteFile(bin, []byte("x"), 0700)
	//A uid / gid that is neither owner nor group: "other" bits apply, 0700 gives nothing
	cred := &syscall.Credential{Uid: 4242421, Gid: 4242421}
	err := checkRunAsAccess(bin, cred, "plugin")
	if err == nil || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("expected a permission error that names the fix, got %v", err)
	}
	// The owner passes
	self := &syscall.Credential{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
	if err := checkRunAsAccess(bin, self, "me"); err != nil {
		t.Fatalf("owner refused: %v", err)
	}
	//World executable binary in a world searchable dir passes for strangers
	os.Chmod(bin, 0755)
	os.Chmod(dir, 0755)
	if err := checkRunAsAccess(bin, cred, "plugin"); err != nil && !strings.Contains(err.Error(), "cannot enter") {
		t.Fatalf("world readable binary refused: %v", err)
	}
}
