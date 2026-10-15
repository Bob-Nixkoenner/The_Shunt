#!/usr/bin/env bash
# Builds the Windows ZIP: dist/the-shunt-windows-amd64.zip
# (shuntd-win.exe, shunt-desktop.exe, wintun.dll, install.ps1, uninstall.ps1, README.txt)
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
OUT=dist/windows; rm -rf "$OUT"; mkdir -p "$OUT"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=$VERSION" -o "$OUT/shunt-desktop.exe" ./cmd/shunt-desktop
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/shuntd-win.exe" ./cmd/shuntd-win

# wintun.dll: WireGuard's signed driver library, pinned by checksum
WINTUN_VER=0.14.1
WINTUN_SHA=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/wintun.zip" "https://www.wintun.net/builds/wintun-$WINTUN_VER.zip"
echo "$WINTUN_SHA  $tmp/wintun.zip" | sha256sum -c -
unzip -oq "$tmp/wintun.zip" -d "$tmp" && cp "$tmp/wintun/bin/amd64/wintun.dll" "$OUT/"

cp packaging/windows/install.ps1 packaging/windows/uninstall.ps1 packaging/windows/README.txt "$OUT/"
mkdir -p dist; (cd "$OUT" && zip -qr "../the-shunt-windows-amd64.zip" .)
echo "dist/the-shunt-windows-amd64.zip ($VERSION)"
