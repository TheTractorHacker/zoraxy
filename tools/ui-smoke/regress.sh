#!/usr/bin/env bash
# Build Zoraxy from this checkout, start a throw-away -noauth instance in a temp dir and run the targeted
# UI regression scenarios (regress.py) against it. PY must be a python with playwright + chromium.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-28784}"
tmp="$(mktemp -d)"
pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
(cd "$root/src" && go build -o "$tmp/zoraxy" .)
ln -s "$root/src/web" "$tmp/web"
(cd "$tmp" && exec ./zoraxy -noauth -dev -port ":$PORT" -conf ./conf -dbpath ./sys.db >zoraxy.log 2>&1) &
pid=$!
for _ in $(seq 60); do curl -fs "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 0.5; done
"$PY" "$here/regress.py" --url "http://127.0.0.1:$PORT" "$@"
