#!/usr/bin/env bash
# Builds lyrebird (obfs4, meek, webtunnel, snowflake: the pluggable transports
# Tor tunnels use for bridges) from the version pinned in packaging/pt/go.mod.
# Usage: [GOARCH=arm64] OUT=<dir> bash packaging/pt/build.sh
# Update the pin: cd packaging/pt && go get -tool <module>/lyrebird/cmd/lyrebird@<commit of the newest lyrebird-x.y.z tag>
set -euo pipefail
cd "$(dirname "$0")"
OUT=${OUT:?set OUT to the target directory}
mkdir -p "$OUT"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/lyrebird" \
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/cmd/lyrebird
