package instance

import (
	"errors"
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
	addr, ok := notifyAddr(notifySocketEnv())
	if !ok {
		return nil
	}
	//The send runs in its own goroutine and is abandoned after notifyTimeout: a socket whose receiver is
	//stuck (or a kernel that does not complete the send) must never hold up startup or shutdown.
	if !notifyMu.TryLock() {
		return errors.New("a previous notification is still being sent")
	}
	res := make(chan error, 1)
	go func() {
		defer notifyMu.Unlock()
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
		if err != nil {
			res <- err
			return
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte(state))
		res <- err
	}()
	select {
	case err := <-res:
		return err
	case <-time.After(notifyTimeout):
		return errors.New("sending the notification timed out")
	}
}

var notifyTimeout = 2 * time.Second

// notifyAddr converts $NOTIFY_SOCKET into a unix socket name: a path, or an abstract socket ("@name" ->
// NUL + name). ok is false for empty or unknown forms (ignored, never an error).
func notifyAddr(v string) (string, bool) {
	switch {
	case v == "":
		return "", false
	case v[0] == '@':
		return "\x00" + v[1:], true
	case v[0] == '/':
		return v, true
	}
	return "", false
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
