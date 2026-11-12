#!/bin/sh
# Start Zoraxy by hand, in the foreground, for a quick test or a first run.
#
# Stop it with Ctrl+C. NEVER press Ctrl+Z: that freezes Zoraxy (and its plugins) but leaves its
# ports open, so browsers hang or get "connection refused", and the frozen process keeps the
# database locked so a second start (for example systemctl start zoraxy) waits forever.
#
# If Zoraxy is installed as a systemd service, do not run this script next to it:
#   sudo systemctl restart zoraxy     # restart
#   sudo systemctl stop zoraxy        # stop, then run this script if you really want a manual run
# To start anyway (you know what you are doing): FORCE=1 ./start.sh
# To see what is running and who holds the database: sudo ./zoraxy -doctor

# A unit whose ExecStart is this script runs inside zoraxy.service's own cgroup: that is fine, so the
# guard is skipped. (INVOCATION_ID is not used for this: terminals started as user services inherit it.)
in_unit=""
if grep 'zoraxy\.service' /proc/self/cgroup >/dev/null 2>&1; then in_unit=1; fi

if [ -z "$FORCE" ] && [ -z "$in_unit" ]; then
    refuse=""

    if command -v systemctl >/dev/null 2>&1; then
        state=$(systemctl is-active zoraxy 2>/dev/null)
        case "$state" in
            active | activating | reloading)
                refuse="the systemd service 'zoraxy' is $state. A second copy would fight it for the database and the ports."
                ;;
        esac
    fi

    if [ -z "$refuse" ] && command -v pgrep >/dev/null 2>&1; then
        others=$(pgrep -x zoraxy 2>/dev/null | tr '\n' ' ')
        if [ -n "$others" ]; then
            refuse="another Zoraxy is already running (PID $others). Only one can hold the database."
        fi
    fi

    if [ -n "$refuse" ]; then
        {
            echo "start.sh: not starting, $refuse"
            echo
            echo "  To restart the service:   sudo systemctl restart zoraxy"
            echo "  To see who is running it: sudo ./zoraxy -doctor"
            echo "  To start by hand anyway:  FORCE=1 ./start.sh"
            echo
            echo "  Reminder: stop a foreground Zoraxy with Ctrl+C, never Ctrl+Z (a frozen Zoraxy keeps its"
            echo "  ports and database lock and blocks everything)."
        } >&2
        exit 1
    fi
fi

sudo ./zoraxy
