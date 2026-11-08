#!/usr/bin/env bash
# Cross-compile the Linux release binaries, sign them and verify the result.
#
#   tools/build_release.sh [-k PRIVATE_KEY.pem] [-o DIST_DIR]
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

while getopts "k:o:" opt; do
  case "$opt" in
    k) key="$OPTARG" ;;
    o) dist="$OPTARG" ;;
    *) echo "usage: $0 [-k private.pem] [-o dist_dir]" >&2; exit 2 ;;
  esac
done

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
go run tools/sign_release.go -dist "$dist" -key "$key" -pub "$pub"

echo "verifying with the committed public key"
go run tools/sign_release.go -verify -dist "$dist" -pub "$pub"

echo
echo "Release assets in $dist:"
ls -l "$dist"
echo "Attach all of them (binaries, SHA256SUMS, SHA256SUMS.sig) to the GitHub release."
