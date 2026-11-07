#!/usr/bin/env bash
# Build the npm distribution of warden into npm/dist/ (nothing is published).
#
#   scripts/build-npm.sh            # all platforms
#   PLATFORMS="linux-x64" scripts/build-npm.sh
#
# Produces:
#   npm/dist/warden/                  @decnutz/warden (launcher, no binaries)
#   npm/dist/warden-<os>-<cpu>/       @decnutz/warden-<os>-<cpu> (one binary each)
# then runs `npm pack` on each so the tarballs can be inspected.
#
# Release (by a maintainer, by hand): publish every platform package FIRST,
# then the launcher package — the launcher's optionalDependencies pin the
# exact same version.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(node -p 'require("./npm/warden/package.json").version')"
GOVERSION_IN_SRC="$(sed -n 's/^var version = "\(.*\)"/\1/p' cmd/warden/main.go)"
if [[ "$VERSION" != "$GOVERSION_IN_SRC" ]]; then
  echo "version mismatch: npm/warden/package.json=$VERSION cmd/warden/main.go=$GOVERSION_IN_SRC" >&2
  exit 1
fi
PLATFORMS="${PLATFORMS:-linux-x64 linux-arm64 darwin-x64 darwin-arm64 win32-x64 win32-arm64}"
DIST=npm/dist
rm -rf "$DIST"
mkdir -p "$DIST"

goarch() { case "$1" in x64) echo amd64 ;; arm64) echo arm64 ;; *) echo "bad cpu $1" >&2; exit 1 ;; esac; }

for p in $PLATFORMS; do
  os="${p%-*}"; cpu="${p#*-}"
  goos="$os"; exe="warden"
  if [[ "$os" == "win32" ]]; then goos=windows; exe="warden.exe"; fi
  dir="$DIST/warden-$p"
  mkdir -p "$dir/bin"
  echo "building $p…"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$(goarch "$cpu")" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$dir/bin/$exe" ./cmd/warden
  cat > "$dir/package.json" <<JSON
{
  "name": "@decnutz/warden-$p",
  "version": "$VERSION",
  "description": "warden binary for $os/$cpu (installed automatically by @decnutz/warden)",
  "license": "MIT",
  "repository": { "type": "git", "url": "git+https://github.com/calasdan-sketch/warden.git" },
  "os": ["$os"],
  "cpu": ["$cpu"],
  "files": ["bin/$exe"],
  "preferUnplugged": true
}
JSON
  cp LICENSE "$dir/"
done

mkdir -p "$DIST/warden"
cp -r npm/warden/bin npm/warden/package.json "$DIST/warden/"
cp README.md LICENSE "$DIST/warden/"

# Smoke test: the launcher must find and run the binary for this host.
host="$(node -p 'process.platform + "-" + process.arch')"
if [[ -x "$DIST/warden-$host/bin/warden" ]]; then
  out="$(WARDEN_BINARY="$DIST/warden-$host/bin/warden" node "$DIST/warden/bin/warden.js" version)"
  [[ "$out" == "warden $VERSION" ]] || { echo "launcher smoke test failed: $out" >&2; exit 1; }
  echo "launcher smoke test: $out"
fi

for d in "$DIST"/*/; do (cd "$d" && npm pack --silent >/dev/null && ls *.tgz); done
