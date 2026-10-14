#!/usr/bin/env bash
# End-to-end test of the Android app in the emulator (google_apis image,
# booted, adb connected). Two WireGuard servers run on the host
# (wgserver, reached as 10.0.2.2); the app routes the adb shell through
# "work" and everything else (here: root) through "home".
#
#   test/android/emulator-test.sh            # builds core + APK first
#   NOBUILD=1 test/android/emulator-test.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk} JAVA_HOME=${JAVA_HOME:-$HOME/Android/jdk}
ADB=$ANDROID_HOME/platform-tools/adb
GRADLE=${GRADLE:-gradle}
PKG=org.theshunt.app
W=$(mktemp -d)
trap 'kill $SRV 2>/dev/null; rm -rf "$W"' EXIT
fails=0
check() { # check "what" expected actual
	if [[ $3 == *"$2"* ]]; then echo "  ok   $1"; else echo "  FAIL $1: expected '$2', got '$3'"; fails=$((fails + 1)); fi
}

if [[ -z ${NOBUILD:-} ]]; then
	android/build-core.sh
	(cd android && $GRADLE -q assembleDebug)
fi
$ADB install -r android/app/build/outputs/apk/debug/app-debug.apk >/dev/null

go build -o "$W/wgserver" ./test/android/wgserver
"$W/wgserver" -out "$W" 2>"$W/server.log" &
SRV=$!
for _ in $(seq 50); do [[ -f $W/settings.json ]] && break; sleep 0.2; done

# settings straight into the app's files (debug build: run-as), VPN
# permission without the dialog
$ADB shell am force-stop $PKG
# DNS filter: a tiny list in place of easylist (fresh, so nothing is downloaded)
python3 - "$W/settings.json" <<'PY2'
import json, sys
p = sys.argv[1]; c = json.load(open(p)); c["filter_lists"] = ["easylist"]; json.dump(c, open(p, "w"))
PY2
printf '||blocked.test^\n' >"$W/easylist"
$ADB push "$W/settings.json" /data/local/tmp/shunt-settings.json >/dev/null
$ADB push "$W/easylist" /data/local/tmp/shunt-easylist >/dev/null
$ADB shell "run-as $PKG sh -c 'mkdir -p files/blocklists && cp /data/local/tmp/shunt-settings.json files/settings.json && cp /data/local/tmp/shunt-easylist files/blocklists/easylist && touch files/blocklists/easylist'"
$ADB shell appops set $PKG ACTIVATE_VPN allow

# start: the switch on the status screen
$ADB shell am start -W -n $PKG/.MainActivity >/dev/null
sleep 2
$ADB shell uiautomator dump /data/local/tmp/ui.xml >/dev/null
bounds=$($ADB shell cat /data/local/tmp/ui.xml | grep -o 'class="android.view.View"[^>]*checkable="true"[^>]*bounds="[^"]*"' | grep -o 'bounds="[^"]*"' | head -1)
read -r x1 y1 x2 y2 <<<"$(echo "$bounds" | tr -c '0-9' ' ')"
$ADB shell input tap $(((x1 + x2) / 2)) $(((y1 + y2) / 2))
for _ in $(seq 30); do
	$ADB shell dumpsys connectivity | grep -q 'VPN.*CONNECTED\|type: VPN\[' && break
	sleep 1
done
sleep 3

get() { # get [root] -> HTTP body from 10.9.0.1 inside the tunnel
	$ADB shell "printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 5 10.9.0.1 80" 2>&1 | tail -1 | tr -d '\r'
}
echo "== routes per app"
check "adb shell (com.android.shell) -> tunnel work" "tunnel=work" "$(get)"
if $ADB root >/dev/null 2>&1; then
	sleep 2; $ADB wait-for-device
	check "root (no rule) -> default route, tunnel home" "tunnel=home" "$(get)"
	$ADB unroot >/dev/null 2>&1 || true
	sleep 2; $ADB wait-for-device
fi
echo "== DNS through the tunnel's DNS server"
check "name resolves via the tunnel DNS (10.9.0.1)" "10.9.0.1" "$($ADB shell ping -c1 -W2 anything.test 2>&1 | head -1)"
grep -q 'work: DNS anything.test' "$W/server.log" && echo "  ok   query arrived at the work tunnel's DNS" ||
	{ echo "  FAIL query did not arrive at the work tunnel's DNS"; fails=$((fails + 1)); }
echo "== DNS filter"
check "listed name is blocked (NXDOMAIN)" "unknown host" "$($ADB shell ping -c1 -W2 blocked.test 2>&1 | head -1)"
grep -q 'DNS blocked.test' "$W/server.log" && { echo "  FAIL blocked name reached the upstream"; fails=$((fails + 1)); } || echo "  ok   blocked name never reached the upstream"
echo "== status"
$ADB logcat -d -s Shunt | tail -5
((fails == 0)) && echo "ALL OK" || { echo "$fails FAILED"; exit 1; }
