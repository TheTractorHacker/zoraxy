#!/usr/bin/env bash
# Cross-compile the Linux release binaries, sign them and verify the result.
#
#   tools/build_release.sh -t TAG [-b BUILD] [-k PRIVATE_KEY.pem] [-o DIST_DIR]
#
# TAG is the GitHub release tag (e.g. v3.3.6-topic.1); it is signed into
# SHA256SUMS so the updater can refuse a replayed older release. BUILD is a
# monotonically increasing integer (default: current unix time) and must be
# larger than the previous release's build.
#
# The private key defaults to $ZORAXY_RELEASE_KEY, then
# ~/.zoraxy-release-key/private.pem. It is only passed by path to
# tools/sign_release.go and is never read, copied or printed by this script.
# The committed public key (src/mod/updater/release_pubkey.pem) is used to
# verify the produced SHA256SUMS.sig, so a wrong key aborts the build.
#
# Nothing is published: attach the files in DIST_DIR to a GitHub release by hand.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
key="${ZORAXY_RELEASE_KEY:-$HOME/.zoraxy-release-key/private.pem}"
dist="$root/dist"
pub="${ZORAXY_RELEASE_PUB:-$root/src/mod/updater/release_pubkey.pem}"

tag=""
build="$(date +%s)"

while getopts "k:o:t:b:" opt; do
  case "$opt" in
    k) key="$OPTARG" ;;
    o) dist="$OPTARG" ;;
    t) tag="$OPTARG" ;;
    b) build="$OPTARG" ;;
    *) echo "usage: $0 -t tag [-b build] [-k private.pem] [-o dist_dir]" >&2; exit 2 ;;
  esac
done

[ -n "$tag" ] || { echo "-t TAG is required (the release tag to sign)" >&2; exit 2; }
# The in-app updater smoke-tests the new binary and requires "Version X.Y.Z" in its output to match the tag.
srcver=$(sed -n 's/.*SYSTEM_VERSION *= *"\([^"]*\)".*/\1/p' "$(dirname "$0")/../src/def.go" | head -1)
tagver=$(printf '%s' "$tag" | sed -n 's/^v\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p')
[ "$srcver" = "$tagver" ] || { echo "tag $tag has base version '$tagver' but src/def.go SYSTEM_VERSION is '$srcver': the in-app updater would reject this build" >&2; exit 2; }
[ -r "$key" ] || { echo "private key not readable: $key (use -k or \$ZORAXY_RELEASE_KEY)" >&2; exit 1; }
[ -r "$pub" ] || { echo "public key not found: $pub" >&2; exit 1; }

rm -rf "$dist"
mkdir -p "$dist"

# name:GOARCH[:GOARM]
targets=(
  "amd64:amd64:"
  "arm64:arm64:"
  "arm:arm:6"
  "386:386:"
  "riscv64:riscv64:"
  "mipsle:mipsle:"
)

cd "$root/src"
for t in "${targets[@]}"; do
  IFS=: read -r name goarch goarm <<<"$t"
  out="$dist/zoraxy_linux_$name"
  echo "building $out"
  env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" ${goarm:+GOARM=$goarm} \
    go build -trimpath -ldflags "-s -w" -o "$out" .
  chmod 755 "$out"
done
cd "$root"

echo "signing"
go run tools/sign_release.go -dist "$dist" -key "$key" -pub "$pub" -tag "$tag" -build "$build"

echo "verifying with the committed public key"
go run tools/sign_release.go -verify -dist "$dist" -pub "$pub"

echo
echo "Release assets in $dist:"
ls -l "$dist"
echo "Attach all of them (binaries, SHA256SUMS, SHA256SUMS.sig) to the GitHub release."
