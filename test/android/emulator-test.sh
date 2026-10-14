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
GRADLE=${GRADLE:-./gradlew} # inside android/
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
$ADB logcat -c
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
# no notification permission dialog in front of the switch (Android 13+)
$ADB shell pm grant $PKG android.permission.POST_NOTIFICATIONS 2>/dev/null || true

# start: the switch on the status screen
$ADB shell am start -W -n $PKG/.MainActivity >/dev/null
sleep 2
vpn_up() { $ADB shell dumpsys connectivity | grep -q 'VPN.*CONNECTED\|type: VPN\['; }
toggle() { # tap the VPN switch on the status screen
	$ADB shell uiautomator dump /data/local/tmp/ui.xml >/dev/null
	local bounds
	bounds=$($ADB shell cat /data/local/tmp/ui.xml | grep -o 'class="android.view.View"[^>]*checkable="true"[^>]*bounds="[^"]*"' | grep -o 'bounds="[^"]*"' | head -1 || true)
	[[ -n $bounds ]] || { echo "VPN switch not found on screen (system dialog in front?)"; exit 1; }
	read -r x1 y1 x2 y2 <<<"$(echo "$bounds" | tr -c '0-9' ' ')"
	$ADB shell input tap $(((x1 + x2) / 2)) $(((y1 + y2) / 2))
}
wait_vpn() { # wait_vpn up|down
	for _ in $(seq 30); do
		if vpn_up; then [[ $1 == up ]] && return 0; else [[ $1 == down ]] && return 0; fi
		sleep 1
	done
	return 1
}
sleep 2
# with always-on VPN set for the app, Android has started it already
if vpn_up; then echo "  ok   VPN already up (always-on started it)"; else toggle; wait_vpn up || true; fi
sleep 3
$ADB logcat -d -s Shunt | grep -q 'E Shunt' && { $ADB logcat -d -s Shunt | tail -20; echo "VPN start failed"; exit 1; }
$ADB shell dumpsys connectivity | grep -q 'VPN.*CONNECTED\|type: VPN\[' || { echo "VPN is not up"; exit 1; }

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
echo "== network change (Wi-Fi off -> mobile data)"
$ADB shell svc wifi disable
sleep 8
check "tunnel still works on mobile data" "tunnel=work" "$(get)"
$ADB shell svc wifi enable
sleep 8
check "and back on Wi-Fi" "tunnel=work" "$(get)"
echo "== switch off and on again"
$ADB shell am start -W -n $PKG/.MainActivity >/dev/null
sleep 1
toggle
wait_vpn down && echo "  ok   VPN off" || { echo "  FAIL VPN still up"; fails=$((fails + 1)); }
toggle
wait_vpn up && sleep 3 && check "VPN on again, tunnel works" "tunnel=work" "$(get)" || { echo "  FAIL VPN did not come back"; fails=$((fails + 1)); }
tap_text() { # tap the first view whose text starts with $1
	$ADB shell uiautomator dump /data/local/tmp/ui.xml >/dev/null
	local b
	b=$($ADB shell cat /data/local/tmp/ui.xml | grep -o "text=\"$1[^\"]*\"[^>]*bounds=\"[^\"]*\"" | grep -o 'bounds="[^"]*"' | head -1)
	[[ -n $b ]] || { echo "  FAIL no '$1' on screen"; fails=$((fails + 1)); return 1; }
	read -r x1 y1 x2 y2 <<<"$(echo "$b" | tr -c '0-9' ' ')"
	$ADB shell input tap $(((x1 + x2) / 2)) $(((y1 + y2) / 2))
}
echo "== panic and pass"
$ADB shell am start -n $PKG/.MainActivity >/dev/null
sleep 2
if tap_text "PANIC"; then
	sleep 2
	check "panic blocks the tunnel too (refused at once)" "refused" "$(get)"
	tap_text "Release" && sleep 2
	check "after panic: tunnel again" "tunnel=work" "$(get)"
fi
if tap_text "Pass 5 min" && sleep 1 && tap_text "Pass 5 min"; then # button, then the dialog's confirm
	sleep 2
	r=$(get || true)
	[[ $r != *tunnel=* ]] && echo "  ok   pass: the shell goes direct (tunnel-only address unreachable)" || { echo "  FAIL pass: still through the tunnel: $r"; fails=$((fails + 1)); }
	tap_text "End pass" && sleep 2
	check "after the pass: tunnel again" "tunnel=work" "$(get)"
fi
echo "== status notification"
n=$($ADB shell dumpsys notification --noredact | grep -A30 "pkg=$PKG" | grep -o 'android.text=[^,]*' | head -1)
check "notification shows the state" "android.text=" "$n"
echo "== status"
$ADB logcat -d -s Shunt | tail -5
((fails == 0)) && echo "ALL OK" || { echo "$fails FAILED"; exit 1; }
