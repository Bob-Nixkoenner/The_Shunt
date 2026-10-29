#!/usr/bin/env bash
# Fetches the Tor program for the Android app (built-in Tor, see
# docs and android-tor-plan.md): libtor.so from the Guardian Project's
# tor-android AAR on Maven Central, checked against a pinned SHA-256, for
# arm64 and x86_64 -> android/app/src/main/jniLibs/<abi>/libtor.so.
# (Like libopenvpn.so it is a program, not a library; the name is what Android
# lets an app run from its library folder.) Tor is BSD-3-Clause.
# Update: change VER and SHA (sha256sum of the .aar), also packaging/tor-versions.json.
set -euo pipefail
cd "$(dirname "$0")/.."

VER=0.4.9.14
SHA=28ff2bb6d4d42eabe57183dedd7a97fce77e8ce4b6f5af6fa03993b3ca054edd
URL=https://repo1.maven.org/maven2/info/guardianproject/tor-android/$VER/tor-android-$VER.aar
CACHE=${CACHE:-$HOME/.cache/shunt-tor}
OUT=android/app/src/main/jniLibs
mkdir -p "$CACHE"
AAR=$CACHE/tor-android-$VER.aar
if ! { [ -f "$AAR" ] && echo "$SHA  $AAR" | sha256sum -c --status; }; then
	curl -fsSL -o "$AAR" "$URL"
	echo "$SHA  $AAR" | sha256sum -c --status || { echo "tor-android $VER: checksum mismatch" >&2; rm -f "$AAR"; exit 1; }
fi
for abi in arm64-v8a x86_64; do
	mkdir -p "$OUT/$abi"
	unzip -p "$AAR" "jni/$abi/libtor.so" > "$OUT/$abi/libtor.so"
	chmod 755 "$OUT/$abi/libtor.so"
done
echo "libtor.so $VER -> $OUT/{arm64-v8a,x86_64}"
