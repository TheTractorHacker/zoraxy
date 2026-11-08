#!/usr/bin/env bash
# Admin end-to-end suite. Builds Zoraxy from this checkout into tools/e2e-admin/.build and runs the scenarios
# against throw-away instances (ports 28830-28849 by default, E2E_PORT_BASE to change).
#   run.sh [--only name[,name]] [--list]
# PY=<python with playwright+chromium> for the UI scenarios (default ~/ui-test-tools/py.sh).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
mkdir -p "$here/.build" "${GOTMPDIR:-$HOME/.cache/go-tmp}"
export GOTMPDIR="${GOTMPDIR:-$HOME/.cache/go-tmp}"
if [ -z "${E2E_SKIP_BUILD:-}" ]; then (cd "$root/src" && go build -o "$here/.build/zoraxy" .); fi
PY="${PY:-$HOME/ui-test-tools/py.sh}"
exec "$PY" "$here/run.py" "$@"
