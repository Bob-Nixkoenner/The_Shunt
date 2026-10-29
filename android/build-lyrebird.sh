#!/usr/bin/env bash
# Builds lyrebird (obfs4, meek, webtunnel, snowflake) for the Android app's built-in Tor
# -> android/app/src/main/jniLibs/<abi>/liblyrebird.so (a program, like libtor.so).
# Version: the pin in packaging/pt/go.mod. cgo with the NDK, so names are resolved by
# Android's libc (Go's own resolver finds no /etc/resolv.conf on Android; snowflake and
# meek need DNS). -checklinkname=0: a dependency (wlynxg/anet) links into net internals.
set -euo pipefail
cd "$(dirname "$0")/../packaging/pt"
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
NDK=${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
OUT=$PWD/../../android/app/src/main/jniLibs
for a in "arm64 aarch64 arm64-v8a" "amd64 x86_64 x86_64"; do
	set -- $a
	mkdir -p "$OUT/$3"
	CC=$TC/$2-linux-android29-clang GOOS=android GOARCH=$1 CGO_ENABLED=1 \
		go build -tags netcgo -trimpath -ldflags "-s -w -checklinkname=0" -o "$OUT/$3/liblyrebird.so" \
		gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/cmd/lyrebird
done
echo "liblyrebird.so -> $OUT/{arm64-v8a,x86_64}"
