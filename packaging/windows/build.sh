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

# Tor (Tor Expert Bundle: tor.exe + lyrebird.exe for obfs4/snowflake/meek), pinned by checksum;
# installed in <app>\tor, used by tunnels with driver = "tor". NO_TOR=1 leaves it out.
if [ -z "${NO_TOR:-}" ]; then
  TOR_VER=15.0.26
  TOR_SHA=c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252
  curl -fsSL -o "$tmp/tor.tgz" "https://dist.torproject.org/torbrowser/$TOR_VER/tor-expert-bundle-windows-x86_64-$TOR_VER.tar.gz"
  echo "$TOR_SHA  $tmp/tor.tgz" | sha256sum -c -
  mkdir -p "$tmp/torx" "$OUT/tor/pt" "$OUT/tor/licenses"
  tar xzf "$tmp/tor.tgz" -C "$tmp/torx"
  cp "$tmp/torx/tor/tor.exe" "$OUT/tor/"
  cp "$tmp/torx/tor/pluggable_transports/lyrebird.exe" "$OUT/tor/pt/"
  cp "$tmp/torx/docs/tor.txt" "$tmp/torx/docs/lyrebird.txt" "$tmp/torx/docs/openssl.txt" "$tmp/torx/docs/libevent.txt" "$tmp/torx/docs/zlib.txt" "$OUT/tor/licenses/"
else
  mkdir -p "$OUT/tor"; : >"$OUT/tor/.none" # the Setup script copies the folder
fi
GOOS=linux GOARCH=amd64 go run ./packaging/windows/mkico "$OUT/the-shunt.ico"
cp packaging/windows/disclaimer.txt packaging/windows/disclaimer-de.txt packaging/windows/install.ps1 packaging/windows/uninstall.ps1 packaging/windows/README.txt "$OUT/"
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
