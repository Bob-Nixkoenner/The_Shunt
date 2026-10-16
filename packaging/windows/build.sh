#!/usr/bin/env bash
# Builds the Windows ZIP (+ setup.exe if ISCC is set): $DIST/the-shunt-windows-amd64.zip (default dist/)
# (shuntd-win.exe, shunt-desktop.exe, wintun.dll, install.ps1, uninstall.ps1, README.txt)
# VERSION=v1.2.3 sets the version shown by the program (default: git describe).
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
DIST=${DIST:-dist}; mkdir -p "$DIST"; DIST=$(cd "$DIST" && pwd)
OUT=$(mktemp -d); tmp=$(mktemp -d); trap 'rm -rf "$OUT" "$tmp"' EXIT
export CGO_ENABLED=0
GOOS=windows GOARCH=amd64
export GOOS GOARCH
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=$VERSION" -o "$OUT/shunt-desktop.exe" ./cmd/shunt-desktop
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/shuntd-win.exe" ./cmd/shuntd-win

# wintun.dll: WireGuard's signed driver library, pinned by checksum
WINTUN_VER=0.14.1
WINTUN_SHA=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
curl -fsSL -o "$tmp/wintun.zip" "https://www.wintun.net/builds/wintun-$WINTUN_VER.zip"
echo "$WINTUN_SHA  $tmp/wintun.zip" | sha256sum -c -
unzip -oq "$tmp/wintun.zip" -d "$tmp" && cp "$tmp/wintun/bin/amd64/wintun.dll" "$OUT/"

GOOS=linux GOARCH=amd64 go run ./packaging/windows/mkico "$OUT/the-shunt.ico"
cp packaging/windows/install.ps1 packaging/windows/uninstall.ps1 packaging/windows/README.txt "$OUT/"
# STAGE_DIR=<dir>: also leave the staged files there (for a separate Windows job that runs ISCC)
if [ -n "${STAGE_DIR:-}" ]; then mkdir -p "$STAGE_DIR"; cp -r "$OUT/." "$STAGE_DIR/"; fi
# Setup.exe (Inno Setup): ISCC=/path/to/ISCC.exe (runs under wine on Linux); skipped if not set
if [ -n "${ISCC:-}" ]; then
  ISS=$(realpath packaging/windows/the-shunt.iss); SRC=$OUT; DST=$DIST
  if [ "$(uname)" != MINGW ] && command -v winepath >/dev/null; then
    SRC=$(winepath -w "$OUT"); DST=$(winepath -w "$DIST"); ISS=$(winepath -w "$ISS")
  fi
  wine "$ISCC" /Qp "/DAppVersion=${VERSION#v}" "/DSrcDir=$SRC" "/DOutDir=$DST" "$ISS"
  mv "$DIST/the-shunt-setup.exe" "$DIST/the-shunt-windows-amd64-setup.exe"
fi
rm -f "$DIST/the-shunt-windows-amd64.zip"; (cd "$OUT" && zip -qr "$DIST/the-shunt-windows-amd64.zip" .)
echo "$DIST/the-shunt-windows-amd64.zip ($VERSION)"
