#!/usr/bin/env bash
# Builds the openvpn program for the Android app (OpenVPN tunnels, see
# docs/ANDROID.md): OpenSSL (static) + OpenVPN 2 in its Android mode
# (TARGET_ANDROID: no tun of its own, it asks over the management socket),
# for arm64 and x86_64. Output: android/app/src/main/jniLibs/<abi>/libopenvpn.so
# (the "lib…so" name: Android only runs programs from the app's library folder).
# ABIS=host builds the same Android mode for this Linux machine, for the Go
# tests (internal/splitstack/ovpn_test.go): ~/.cache/shunt-openvpn/host/openvpn
#
# OpenVPN is GPL-2.0 (with OpenSSL exception) and runs as a separate program,
# controlled over a socket; its exact source is the release below.
# Needs: ANDROID_HOME with the NDK, curl, make, perl.
set -euo pipefail
cd "$(dirname "$0")/.."

OPENSSL_VER=3.5.9
OPENSSL_SHA=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
OPENVPN_VER=2.7.8
OPENVPN_SHA=c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36
API=29

export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
NDK=${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64
CACHE=${CACHE:-$HOME/.cache/shunt-openvpn}
OUT=android/app/src/main/jniLibs
JOBS=$(($(nproc) * 8 / 10)); ((JOBS > 0)) || JOBS=1
mkdir -p "$CACHE"

fetch() { # url sha256
	local f=$CACHE/${1##*/}
	[[ -f $f ]] || curl -fsSL -o "$f.part" "$1" && { [[ -f $f ]] || mv "$f.part" "$f"; }
	echo "$2  $f" | sha256sum -c --quiet || { rm -f "$f"; echo "checksum mismatch: $f" >&2; exit 1; }
}
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz" $OPENSSL_SHA
fetch "https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN_VER/openvpn-$OPENVPN_VER.tar.gz" $OPENVPN_SHA

build() { # abi openssl-target clang-triple ("" = this machine)
	local abi=$1 ossl=$2 triple=$3
	local W=$CACHE/build-$abi
	local dst=$OUT/$abi/libopenvpn.so
	[[ -n $triple ]] || dst=$CACHE/host/openvpn
	# built before with the same versions and NDK (the CI cache is keyed on
	# this script): reuse it, OpenSSL + OpenVPN take minutes per ABI
	local done=$CACHE/done/$abi-openssl$OPENSSL_VER-openvpn$OPENVPN_VER-${NDK##*/}-api$API
	if [[ -f $done ]]; then
		mkdir -p "$(dirname "$dst")" && cp "$done" "$dst"
		echo "cached $dst"
		return
	fi
	rm -rf "$W" && mkdir -p "$W/prefix"
	local host=() osslapi=()
	if [[ -n $triple ]]; then
		export PATH=$TC/bin:$PATH ANDROID_NDK_ROOT=$NDK
		export CC="$TC/bin/$triple$API-clang" AR=$TC/bin/llvm-ar RANLIB=$TC/bin/llvm-ranlib STRIP=$TC/bin/llvm-strip
		host=(--host="$triple") osslapi=(-D__ANDROID_API__=$API)
	else
		export CC=cc AR=ar RANLIB=ranlib STRIP=strip
	fi

	echo "== OpenSSL $OPENSSL_VER ($abi)"
	tar xzf "$CACHE/openssl-$OPENSSL_VER.tar.gz" -C "$W"
	(cd "$W/openssl-$OPENSSL_VER" &&
		./Configure "$ossl" "${osslapi[@]}" no-shared no-tests no-apps no-docs no-engine no-legacy \
			--prefix="$W/prefix" --libdir=lib >/dev/null &&
		make -s -j"$JOBS" build_libs >/dev/null && make -s install_dev >/dev/null)

	echo "== OpenVPN $OPENVPN_VER ($abi)"
	tar xzf "$CACHE/openvpn-$OPENVPN_VER.tar.gz" -C "$W"
	(cd "$W/openvpn-$OPENVPN_VER" &&
		./configure "${host[@]}" --disable-lzo --disable-lz4 --enable-comp-stub \
			--disable-plugins --disable-dco --disable-unit-tests --disable-debug \
			OPENSSL_CFLAGS="-I$W/prefix/include" OPENSSL_LIBS="-L$W/prefix/lib -lssl -lcrypto" \
			LIBCAPNG_CFLAGS=" " LIBCAPNG_LIBS=" " CFLAGS="-O2 -fPIE" LDFLAGS="-pie -Wl,-z,max-page-size=16384" >/dev/null &&
		# configure only knows Linux: switch config.h to the Android target
		# (as "OpenVPN for Android" does with its own config.h). No libcap-ng
		# on Android.
		sed -i -e 's|^#define TARGET_LINUX 1|#define TARGET_ANDROID 1|' -e 's|^#define HAVE_LIBCAPNG 1|/* no libcap-ng */|' config.h &&
		grep -q '^#define TARGET_ANDROID 1' config.h &&
		make -s -j"$JOBS" >/dev/null)
	mkdir -p "$(dirname "$dst")" "$(dirname "$done")"
	"$STRIP" -o "$dst" "$W/openvpn-$OPENVPN_VER/src/openvpn/openvpn"
	cp "$dst" "$done"
	echo "built $dst ($(du -h "$dst" | cut -f1))"
}

abis=${ABIS:-arm64-v8a x86_64}
for abi in $abis; do
	case $abi in
	arm64-v8a) build arm64-v8a android-arm64 aarch64-linux-android ;;
	x86_64) build x86_64 android-x86_64 x86_64-linux-android ;;
	host) build host linux-x86_64 "" ;;
	*) echo "unknown ABI $abi" >&2; exit 1 ;;
	esac
done
