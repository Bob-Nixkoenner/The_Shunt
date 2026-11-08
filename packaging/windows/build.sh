#!/usr/bin/env bash
# Builds the Windows ZIP (+ setup.exe if ISCC is set): $DIST/the-shunt-windows-amd64.zip (default dist/)
# (shuntd-win.exe, shunt-desktop.exe, wintun.dll, install.ps1, uninstall.ps1, README.txt)
# VERSION=v1.2.3 sets the version shown by the program (default: git describe).
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
DIST=${DIST:-dist}; mkdir -p "$DIST"; DIST=$(cd "$DIST" && pwd)
SYSOS="cmd/shunt-desktop/resource_windows_amd64.syso cmd/shuntd-win/resource_windows_amd64.syso"
OUT=$(mktemp -d); tmp=$(mktemp -d); trap 'rm -rf "$OUT" "$tmp" $SYSOS' EXIT
export CGO_ENABLED=0
GOOS=windows GOARCH=amd64
export GOOS GOARCH
# VERSIONINFO resource (ProductVersion/FileVersion in the file properties): a .syso next to each main package
# for the build only (packaging/windows/mkversion writes it, no extra tool needed)
GOOS=linux GOARCH=amd64 go run ./packaging/windows/mkversion "$VERSION" "The Shunt (desktop)" shunt-desktop.exe cmd/shunt-desktop/resource_windows_amd64.syso
GOOS=linux GOARCH=amd64 go run ./packaging/windows/mkversion "$VERSION" "The Shunt (service)" shuntd-win.exe cmd/shuntd-win/resource_windows_amd64.syso
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=$VERSION" -o "$OUT/shunt-desktop.exe" ./cmd/shunt-desktop
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/shuntd-win.exe" ./cmd/shuntd-win

# wintun.dll: WireGuard's signed driver library, pinned by checksum
WINTUN_VER=0.14.1
WINTUN_SHA=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
curl -fsSL -o "$tmp/wintun.zip" "https://www.wintun.net/builds/wintun-$WINTUN_VER.zip"
echo "$WINTUN_SHA  $tmp/wintun.zip" | sha256sum -c -
unzip -oq "$tmp/wintun.zip" -d "$tmp" && cp "$tmp/wintun/bin/amd64/wintun.dll" "$OUT/"

# Tor (Tor Expert Bundle: tor.exe + lyrebird.exe for obfs4/snowflake/meek), pinned by checksum;
# installed in <app>\tor, used by tunnels with driver = "tor". NO_TOR=1 leaves it out (warns; REQUIRE_TOR=1 makes that an error).
if [ -z "${NO_TOR:-}" ]; then
  # pins live in packaging/tor-versions.json; .github/scripts/tor-bundle.sh verifies them
  # (sha256 + GPG signature of the Tor Browser Developers key) and tor-watch.yml checks weekly
  TOR_VER=$(sed -n 's/.*"tor-bundle-windows": *"\([^"]*\)".*/\1/p' packaging/tor-versions.json)
  TOR_SHA=$(sed -n 's/.*"tor-bundle-windows-sha256": *"\([^"]*\)".*/\1/p' packaging/tor-versions.json)
  curl -fsSL -o "$tmp/tor.tgz" "https://dist.torproject.org/torbrowser/$TOR_VER/tor-expert-bundle-windows-x86_64-$TOR_VER.tar.gz"
  echo "$TOR_SHA  $tmp/tor.tgz" | sha256sum -c -
  if command -v gpg >/dev/null && [ "${VERIFY_SIG:-1}" = 1 ]; then bash .github/scripts/tor-bundle.sh verify; fi
  mkdir -p "$tmp/torx" "$OUT/tor/pt" "$OUT/tor/licenses"
  tar xzf "$tmp/tor.tgz" -C "$tmp/torx"
  cp "$tmp/torx/tor/tor.exe" "$OUT/tor/"
  cp "$tmp/torx/tor/pluggable_transports/lyrebird.exe" "$OUT/tor/pt/"
  [ -s "$OUT/tor/tor.exe" ] && [ -s "$OUT/tor/pt/lyrebird.exe" ] || { echo "ERROR: tor.exe or lyrebird.exe missing after unpacking the bundle" >&2; exit 1; }
  # GeoIP tables: without them tor warns at every start (and cannot pick by country)
  cp "$tmp/torx/data/geoip" "$tmp/torx/data/geoip6" "$OUT/tor/"
  cp "$tmp/torx/docs/tor.txt" "$tmp/torx/docs/lyrebird.txt" "$tmp/torx/docs/openssl.txt" "$tmp/torx/docs/libevent.txt" "$tmp/torx/docs/zlib.txt" "$OUT/tor/licenses/"
else
  if [ -n "${REQUIRE_TOR:-}" ]; then echo "ERROR: NO_TOR is set but REQUIRE_TOR is set (releases ship tor.exe + lyrebird.exe)" >&2; exit 1; fi
  echo "WARNING: NO_TOR set: this build has no tor.exe/lyrebird.exe (no Tor tunnels, no bridges)." >&2
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
