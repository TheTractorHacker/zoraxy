#!/usr/bin/env bash
# Top bar scenario: builds Zoraxy, starts TWO throw-away instances in temp dirs (one -noauth on PORT, one WITH authentication on
# PORT+10) and runs smoke.py --topnav-only, plus the signed-in account menu / Log out checks against the second instance.
# Env: PY (python with playwright), PORT (default 18800), OUT (screenshot directory).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-18800}"
APORT="$((PORT+10))"
tmp="$(mktemp -d)"
pids=""
trap 'for p in $pids; do kill "$p" 2>/dev/null || true; done; rm -rf "$tmp"' EXIT
(cd "$root/src" && go build -o "$tmp/zoraxy" .)
for kind in na au; do
  mkdir -p "$tmp/$kind"
  ln -s "$root/src/web" "$tmp/$kind/web"
done
(cd "$tmp/na" && exec ../zoraxy -noauth -dev -default_inbound_port "$((PORT+1))" -port ":$PORT" -conf ./conf -dbpath ./sys.db >>zoraxy.log 2>&1) &
pids="$pids $!"
(cd "$tmp/au" && exec ../zoraxy -dev -default_inbound_port "$((APORT+1))" -port ":$APORT" -conf ./conf -dbpath ./sys.db >>zoraxy.log 2>&1) &
pids="$pids $!"
for p in $PORT $APORT; do
  for _ in $(seq 60); do curl -s -o /dev/null "http://127.0.0.1:$p/login.html" && break; sleep 0.5; done
done
"$PY" "$here/smoke.py" --url "http://127.0.0.1:$PORT" --topnav-only --topnav-auth-url "http://127.0.0.1:$APORT" ${OUT:+--out "$OUT"} "$@"
