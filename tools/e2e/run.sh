#!/usr/bin/env bash
# Run the data-plane end-to-end suite. Usage: tools/e2e/run.sh [--only name[,name]] [--list]
# Needs: go, python3, openssl. Playwright (PY=$HOME/ui-test-tools/py.sh) only for the UI scenarios.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export GOTMPDIR="${GOTMPDIR:-$HOME/.cache/go-tmp}"
mkdir -p "$GOTMPDIR"
exec "${PY:-python3}" "$here/run.py" "$@"
