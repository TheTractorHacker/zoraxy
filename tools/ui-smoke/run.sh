#!/usr/bin/env bash
# Build Zoraxy from this checkout, start a throw-away -noauth instance in a temp dir
# (own conf/db/port; never your real config) and run smoke.py against it.
# Needs a python with playwright + chromium installed (see DEVELOPMENT.md); set PY to override.
# Extra arguments are passed to smoke.py (e.g. --out DIR).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-18765}"
tmp="$(mktemp -d)"
pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
(cd "$root/src" && go build -o "$tmp/zoraxy" .)
ln -s "$root/src/web" "$tmp/web"
# fake zrok program for the Tunnels (zrok) flow: never a real zrok account
mkdir -p "$tmp/fakebin"
cat >"$tmp/fakebin/zrok" <<'EOF'
#!/bin/sh
case "$1" in
  version) echo "v1.1.11";;
  share) echo "access your share at: https://abc123.share.zrok.io"; sleep 300;;
  *) echo "ok $1";;
esac
EOF
chmod +x "$tmp/fakebin/zrok"
# A rule from an older version whose host name is hostile markup. The API refuses such a name now, but configs written by
# older versions can still hold one, and the admin UI must show it as plain text (consistency_smoke.py).
mkdir -p "$tmp/conf/proxy"
cat >"$tmp/conf/proxy/\"><img src=x onerror=window.__xss=1>.smoke-xss.example.com.config" <<'EOF2'
{"ProxyType":1,"RootOrMatchingDomain":"\"><img src=x onerror=window.__xss=1>.smoke-xss.example.com","MatchingDomainAlias":[],"ActiveOrigins":[{"OriginIpOrDomain":"127.0.0.1:9","Weight":1}],"InactiveOrigins":[],"AccessFilterUUID":"default"}
EOF2
(cd "$tmp" && exec ./zoraxy -noauth -dev -allow_external_tools -default_inbound_port "$((PORT+1))" -port ":$PORT" -conf ./conf -dbpath ./sys.db >zoraxy.log 2>&1) &
pid=$!
for _ in $(seq 60); do curl -fs "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 0.5; done
"$PY" "$here/smoke.py" --zrok-fake "$tmp/fakebin/zrok" --url "http://127.0.0.1:$PORT" "$@"
