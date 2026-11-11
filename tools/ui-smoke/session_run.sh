#!/usr/bin/env bash
# Session lifetime scenario: builds Zoraxy, starts a throw-away instance WITH authentication (no -noauth) in a temp dir
# and runs session_smoke.py (register a throw-away account, cookie lifetime, settings card, session-expired banner).
# Env: PY (python with playwright), PORT (default 18790), OUT (screenshot directory).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-18790}"
tmp="$(mktemp -d)"
pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
(cd "$root/src" && go build -o "$tmp/zoraxy" .)
ln -s "$root/src/web" "$tmp/web"
(cd "$tmp" && exec ./zoraxy -dev -default_inbound_port "$((PORT+1))" -port ":$PORT" -conf ./conf -dbpath ./sys.db >>zoraxy.log 2>&1) &
pid=$!
for _ in $(seq 60); do curl -fs "http://127.0.0.1:$PORT/login.html" >/dev/null && break; sleep 0.5; done
"$PY" "$here/session_smoke.py" --url "http://127.0.0.1:$PORT" ${OUT:+--out "$OUT"} "$@"
