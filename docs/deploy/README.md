# Running Zoraxy under systemd

`zoraxy.service` in this folder is a reference unit. Every line has a comment saying what it is for.

## Why `Type=notify`

With a plain `Type=simple` unit, systemd calls the service "active" the moment the process exists,
even if Zoraxy is stuck before it opens any port. With `Type=notify`, Zoraxy sends `READY=1` only
after the admin interface and the reverse proxy have bound their ports, and `STATUS=` lines while it
works. If you do not use the notify unit nothing changes: Zoraxy does nothing special when
`NOTIFY_SOCKET` is not set (terminal, Docker, `Type=simple`).

What you see in `systemctl status zoraxy`:

| State | Meaning |
|---|---|
| `activating (start)` | Zoraxy is starting. The `Status:` line says what it is doing (for example `Starting`). |
| `active (running)` and `Status: "Admin listening on [::]:8000; reverse proxy listening on port 443"` | Ready. The ports are bound. |
| `active (running)` and `Status: "...WARNING reverse proxy could not bind its port..."` | Zoraxy is up but another program holds the proxy port. Run `sudo ./zoraxy -doctor`. |
| `failed` with `Result: timeout` after 120 s | The start never became ready (for example it waited on a locked database). `TimeoutStartSec=120` killed it. Run `sudo ./zoraxy -doctor`. |

## Switching an existing `Type=simple` unit to `Type=notify`

```bash
systemctl cat zoraxy                                   # note your current ExecStart= and WorkingDirectory=
sudo cp /etc/systemd/system/zoraxy.service /etc/systemd/system/zoraxy.service.bak
sudo cp docs/deploy/zoraxy.service /etc/systemd/system/zoraxy.service
sudo nano /etc/systemd/system/zoraxy.service           # put YOUR ExecStart= (with your flags) and WorkingDirectory= back
sudo systemctl daemon-reload
sudo systemctl restart zoraxy
systemctl status zoraxy                                # "activating (start)" for a moment, then "active (running)"
```

Only `Type=notify` (plus optionally `TimeoutStartSec=120`) is needed for the readiness check. The
rest of the reference unit is optional. If the new unit misbehaves, copy the `.bak` back, run
`sudo systemctl daemon-reload` and `sudo systemctl restart zoraxy`.

Do not use `Type=notify` with a Zoraxy binary older than this feature: systemd would wait for a
`READY=1` that never comes and kill the service after the timeout.

## The Ctrl+Z incident, in 6 lines

1. Someone ran `sudo ./start.sh` next to the service and pressed `Ctrl+Z` (the shell said `Stopped sudo ./start.sh`).
2. `Ctrl+Z` sends SIGTSTP: the process is frozen, not stopped. It keeps its listening sockets.
3. The kernel keeps accepting connections into the queue of those sockets, and nobody answers: the accept queue filled up (4097/4096) and browsers got "connection refused".
4. `systemctl start zoraxy` started a second copy, which waited forever for the database lock the frozen copy held: `active`, 16 MB, silent log.
5. `kill <pid>` did nothing, because a frozen process cannot handle SIGTERM. Only `kill -9` works.
6. Fix: `sudo kill -9 <pid>` (and its plugins), then `sudo systemctl restart zoraxy`. The database recovers from a kill -9 cleanly.

Never run `start.sh` next to the service. Use `sudo systemctl restart zoraxy`. To stop something you
started by hand use `Ctrl+C`, never `Ctrl+Z`. `src/start.sh` now refuses to start when the service
is active or another Zoraxy runs (override with `FORCE=1`).

## `zoraxy -doctor`

A read-only check that never opens `sys.db` and never binds a port, so it is safe to run next to a
live or frozen instance. Use the same flags as your service for `-port`, `-dbpath`,
`-default_inbound_port` and `-fleet_port`, so it checks the right file and ports.

```bash
cd /opt/zoraxy && sudo ./zoraxy -doctor -dbpath ./sys.db -port :8000
```

It reports:

* other Zoraxy processes: PID, state (`stopped` = frozen), age, and whether they run under a service or a login session;
* who holds the database lock (read from `/proc/locks`);
* the systemd unit `zoraxy`: whether it exists and is active, and its main PID;
* who owns the listening ports of this configuration (admin port, 443, 80, `-fleet_port`) and the accept queue of each
  (`4097/4096` is flagged: `connections are piling up, nothing is accepting`);
* a verdict and the exact commands to fix each problem (`kill -CONT`, `kill -9`, `systemctl restart`).

Exit code: `0` healthy, `1` problems found. It works as a normal user, but then it cannot see the
processes of other users (and which process owns a socket); it prints what it could not see. Run it
with `sudo` for the complete picture. Linux only; on other systems it says so and checks nothing.
The ports 80 and 443 are checked as "fine if not listening", because inbound can be disabled in the
settings, which `-doctor` does not read.
