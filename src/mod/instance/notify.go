package instance

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// sd_notify without a dependency. When NOTIFY_SOCKET is unset (Type=simple units, a terminal, Docker)
// every function here is a silent no-op, so existing deployments behave exactly as before.

// notifySocketEnv is a var so tests can point it elsewhere without touching the process environment.
var notifySocketEnv = func() string { return os.Getenv("NOTIFY_SOCKET") }

var notifyMu sync.Mutex

// Notify sends one raw sd_notify datagram, for example "READY=1" or "STATUS=Starting".
// It returns nil when NOTIFY_SOCKET is unset.
func Notify(state string) error {
	addr := notifySocketEnv()
	if addr == "" {
		return nil
	}
	if addr[0] == '@' { //abstract socket
		addr = "\x00" + addr[1:]
	} else if addr[0] != '/' {
		return nil //not an address we understand; never fail startup over it
	}
	notifyMu.Lock()
	defer notifyMu.Unlock()
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	//A datagram write blocks when the receiver's queue is full: never let a stuck notify socket hold up startup
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte(state))
	return err
}

// NotifyStatus publishes a free text status line shown by "systemctl status". Other packages may call it,
// for example NotifyStatus("Waiting for database lock..."). Newlines are removed because they would
// end the field.
func NotifyStatus(msg string) {
	msg = strings.NewReplacer("\r", " ", "\n", " ").Replace(msg)
	_ = Notify("STATUS=" + msg)
}

// NotifyReady tells systemd the service is up: the unit leaves "activating (start)". Call it only
// after the listeners are bound.
func NotifyReady(status string) {
	msg := "READY=1"
	if status != "" {
		msg += "\nSTATUS=" + strings.NewReplacer("\r", " ", "\n", " ").Replace(status)
	}
	_ = Notify(msg)
}

// NotifyStopping tells systemd a clean shutdown has begun (so a slow stop is not mistaken for a hang).
func NotifyStopping() {
	_ = Notify("STOPPING=1\nSTATUS=Shutting down")
}

// NotifyEnabled reports whether a notify socket is configured.
func NotifyEnabled() bool { return notifySocketEnv() != "" }
