package streamproxy_test

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/streamproxy"
)

// Upstream #1075: access rules (blacklist / whitelist) can be attached to a stream proxy instance.
func TestStreamProxyAppliesAccessRule(t *testing.T) {
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	dir := t.TempDir()
	sysdb, err := database.NewDatabase(filepath.Join(dir, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sysdb.Close()
	lg, _ := logger.NewFmtLogger()
	ac, err := access.NewAccessController(&access.Options{
		Logger: *lg, ConfigFolder: filepath.Join(dir, "access"), TrustedProxiesFile: filepath.Join(dir, "tp.json"),
		Database: sysdb, SkipPublicIPCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocked := &access.AccessRule{ID: "blocked", Name: "block loopback", BlacklistEnabled: true}
	if err := ac.AddNewAccessRule(blocked); err != nil {
		t.Fatal(err)
	}
	blocked.AddIPToBlackList("127.0.0.1", "test")
	lanOnly := &access.AccessRule{ID: "lanonly", Name: "lan only", WhitelistEnabled: true}
	if err := ac.AddNewAccessRule(lanOnly); err != nil {
		t.Fatal(err)
	}

	mgr, err := streamproxy.NewStreamProxy(&streamproxy.Options{
		DefaultTimeout: 1, ConfigStore: t.TempDir(), Logger: lg, AccessController: ac,
	})
	if err != nil {
		t.Fatal(err)
	}

	try := func(ruleID string) bool {
		addr := freeLoopbackAddr(t)
		id := mgr.NewConfig(&streamproxy.ProxyRelayOptions{Name: ruleID, ListeningAddr: addr, ProxyAddr: target.Addr().String(), UseTCP: true, Timeout: 1, AccessRuleUUID: ruleID})
		cfg, _ := mgr.GetConfigByUUID(id)
		stop := make(chan bool, 1)
		go cfg.Port2host(addr, target.Addr().String(), stop)
		defer func() { stop <- true }()
		var c net.Conn
		for i := 0; i < 50; i++ {
			if c, err = net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if c == nil {
			t.Fatalf("relay %s never came up", ruleID)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("ping"))
		buf := make([]byte, 4)
		_, err := io.ReadFull(c, buf)
		return err == nil && string(buf) == "ping"
	}

	if !try("default") {
		t.Fatal("default rule must let loopback through")
	}
	if try("blocked") {
		t.Fatal("client in the rule's blacklist was served by the stream proxy")
	}
	if try("lanonly") {
		t.Fatal("client outside the rule's whitelist was served by the stream proxy")
	}
}
