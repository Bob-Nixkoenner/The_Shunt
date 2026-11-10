#!/usr/bin/env bash
# Android network-change leak lab (AN01-AN09), emulator without window.
# Complements emulator-test.sh, which only checks "tunnel works afterwards".
#
# Measuring points
#   1. in the emulator (root): iptables NFLOG on wlan0/eth0 per UID class
#        group 7 = load-generator app UID, 8 = all other app UIDs (not Shunt),
#        9 = system UIDs 1000-9999 (informational)
#   2. on the host: emulator started with  -tcpdump <file>  (survives guest reboot);
#        allowed = UDP to 10.0.2.2:51901-51903 (wgserver), everything else is listed
#   3. the load generator logs every 0.4 s: tunnel answer, DNS canary, fixed-IP probe
#
#   RES=<dir> GENUID=<app uid> test/android/netchange-lab.sh setup
#   ... netchange-lab.sh run AN01   (needs: setup done, VPN up)
#   ... netchange-lab.sh hostleaks <pcap> <t0> <t1>
set -uo pipefail
ADB=${ADB:-$HOME/Android/Sdk/platform-tools/adb -s emulator-5554}
RES=${RES:?set RES to the results directory}
GENUID=${GENUID:-10145} # com.android.chrome in the google_apis image
PKG=org.theshunt.app
HOSTPCAP=${HOSTPCAP:-$RES/emu-base.pcap}
mkdir -p "$RES"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$RES/lab.log"; }
sh() { $ADB shell "$@"; }

vpn_up() { sh "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc -w 3 10.9.0.1 80" 2>/dev/null | grep -q tunnel=; }

leak_rules() { # (re)install NFLOG rules, needs root
	local U cmd
	# multi-user output is uid:10225,1010225: the first one is the app's
	U=$(sh pm list packages -U $PKG | sed 's/.*uid://; s/,.*//' | tr -d '\r')
	for cmd in iptables ip6tables; do
		sh "$cmd -S OUTPUT | grep -q NFLOG && { $cmd -S OUTPUT | grep NFLOG | sed 's/^-A/-D/' | while read l; do $cmd \$l; done; }" 2>/dev/null
		for IF in wlan0 eth0; do
			sh "$cmd -I OUTPUT -o $IF -m owner --uid-owner $GENUID -j NFLOG --nflog-group 7 --nflog-prefix GEN-$IF"
			sh "$cmd -I OUTPUT -o $IF -m owner --uid-owner 10000-$((GENUID - 1)) -j NFLOG --nflog-group 8 --nflog-prefix OTH-$IF"
			sh "$cmd -I OUTPUT -o $IF -m owner --uid-owner $((GENUID + 1))-$((U - 1)) -j NFLOG --nflog-group 8 --nflog-prefix OTH-$IF"
			sh "$cmd -I OUTPUT -o $IF -m owner --uid-owner $((U + 1))-99999 -j NFLOG --nflog-group 8 --nflog-prefix OTH-$IF"
			sh "$cmd -I OUTPUT -o $IF -m owner --uid-owner 1000-9999 -j NFLOG --nflog-group 9 --nflog-prefix SYS-$IF"
		done
	done
}

start_capture() { # on-device tcpdumps + load generator
	sh 'rm -f /data/local/tmp/leak*.pcap /data/local/tmp/gen.log; touch /data/local/tmp/gen.log; chmod 666 /data/local/tmp/gen.log'
	for g in 7 8 9; do
		sh "nohup tcpdump -U -i nflog:$g -w /data/local/tmp/leak$g.pcap >/dev/null 2>&1 &"
	done
	sh "cat > /data/local/tmp/gen.sh" <<'EOF'
L=/data/local/tmp/gen.log
( while :; do t=$(date +%s.%N); r=$(printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 1 10.9.0.1 80 2>&1 | tail -1 | tr -d '\r'); echo "$t T ${r:-none}" >> $L; sleep 0.1; done ) &
( while :; do t=$(date +%s.%N); nc -w 1 203.0.113.7 80 </dev/null >/dev/null 2>&1; echo "$t F x" >> $L; sleep 0.2; done ) &
( n=0; while :; do n=$((n+1)); t=$(date +%s.%N); ping -c1 -W1 $n-canary.shuntlab.test >/dev/null 2>&1; echo "$t D $n" >> $L; sleep 0.2; done ) &
wait
EOF
	sh "nohup su $GENUID sh /data/local/tmp/gen.sh >/dev/null 2>&1 &"
}

stop_capture() { # pull results into $RES/$1-*
	sh 'pkill -f '[g]en.sh'; pkill tcpdump' 2>/dev/null
	sleep 1
	for g in 7 8 9; do $ADB pull /data/local/tmp/leak$g.pcap "$RES/$1-leak$g.pcap" >/dev/null 2>&1; done
	$ADB pull /data/local/tmp/gen.log "$RES/$1-gen.log" >/dev/null 2>&1
}

nflog_count() { tcpdump -nn -tt -r "$1" 2>/dev/null | wc -l; }

gaps() { # tunnel gaps from gen.log: gaps longer than 0.8 s between answers "tunnel="
	LC_ALL=C awk '$2=="T" && $3 ~ /^tunnel=/ { if (last && $1 - last > 0.8) printf "  gap %.0f ms (%.1f -> %.1f)\n", ($1-last)*1000, last, $1; last=$1 } END { if (!last) print "  no tunnel answer at all" }' "$1"
}

hostleaks() { # hostleaks pcap t0 t1 : outbound frames not UDP to wgserver in [t0,t1]
	tcpdump -nn -tt -r "$1" 2>/dev/null | awk -v a="$2" -v b="$3" '
		$1 >= a && $1 <= b && $0 !~ /10\.0\.2\.2\.5190[123]/ && $0 !~ /> 10\.0\.2\.2\.5190/ { print }' |
		grep -E ' (10\.0\.2\.1[56]|fec0|fe80)[^ ]* >|IP6 ' | head -${4:-40}
}

analyze() { # analyze <tag> : summary of one run (gaps, nflog per group, host frames outside the tunnel)
	local tag=$1 t0 tm t1 g
	read -r t0 tm t1 <"$RES/$tag.times"
	echo "== $tag (t0=$t0, second event at +$(LC_ALL=C awk -v a="$t0" -v b="$tm" 'BEGIN{printf "%.0f", b-a}') s, end +$(LC_ALL=C awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f", b-a}') s)"
	echo "-- tunnel gaps > 0.8 s (T probe every ~0.15 s), time relative to t0:"
	LC_ALL=C awk -v a="$t0" '$2=="T" && $3 ~ /^tunnel=/ { if (last && $1-last > 0.8) printf "   gap %.0f ms at +%.1f s\n", ($1-last)*1000, last-a; last=$1; end=$1 } $2=="T" { end=$1 } END { if (!last) print "   no tunnel answer"; else if (end-last > 0.8) printf "   OPEN gap at the end: no answer for %.1f s after +%.1f s (log ends +%.1f s)\n", end-last, last-a, end-a }' "$RES/$tag-gen.log"
	echo "-- generator app (uid $GENUID) packets outside tun0 (NFLOG 7): $(nflog_count "$RES/$tag-leak7.pcap"); other apps (8): $(nflog_count "$RES/$tag-leak8.pcap"); system uids (9): $(nflog_count "$RES/$tag-leak9.pcap")"
	for g in 7 8 9 10 11; do [[ -s $RES/$tag-leak$g.pcap ]] && { echo "-- group $g by UID/destination:"; python3 -I "$(dirname "$0")/nflog_uids.py" "$RES/$tag-leak$g.pcap" | awk '{sub(/^[0-9.]+ /,""); print}' | sed 's/:[0-9]* >/ >/' | sort | uniq -c | sort -rn | head -${N:-6}; }; done
	echo "-- system uid destinations (group 9):"
	tcpdump -nn -r "$RES/$tag-leak9.pcap" 2>/dev/null | awk '{print $4,$5,$6}' | sed 's/\.[0-9]*:*$//' | sort | uniq -c | sort -rn | head -5
	echo "-- host capture (eth0 only), frames not WG-UDP, not mDNS/IGMP/ND/ARP/ICMP noise:"
	tcpdump -nn -tt -r "$HOSTPCAP" 2>/dev/null | LC_ALL=C awk -v a="$(LC_ALL=C awk -v x="$t0" 'BEGIN{printf "%d", x-3600}')" -v b="$(LC_ALL=C awk -v x="$t1" 'BEGIN{printf "%d", x-3600}')" '$1>=a&&$1<=b' |
		grep -v '5190[123]\|:5353\|\.5353\|ff02::\|igmp\|ARP\|ICMP\|224\.0\.0\|DHCP\|BOOTP' | head -${N:-15} | cut -c1-150
}

dump_ui() { for _ in 1 2 3 4 5; do $ADB shell uiautomator dump /data/local/tmp/ui.xml >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
toggle() { # tap the VPN switch on the status screen
	dump_ui
	local b x1 y1 x2 y2
	b=$($ADB shell cat /data/local/tmp/ui.xml | grep -o 'class="android.view.View"[^>]*checkable="true"[^>]*bounds="[^"]*"' | grep -o 'bounds="[^"]*"' | head -1)
	[[ -n $b ]] || { log "switch not found"; return 1; }
	read -r x1 y1 x2 y2 <<<"$(echo "$b" | tr -c '0-9' ' ')"
	sh input tap $(((x1 + x2) / 2)) $(((y1 + y2) / 2))
}

an08() { # AN08: DNS race / DoT probe at switch-on without always-on, Google push (gms) outside the tunnel
	local tag=${1:-O-AN08} t0 t1 D
	mode O; sh am force-stop $PKG; sleep 3
	vpn_up && { log "AN08: VPN still up, abort"; return 1; }
	sh settings put global private_dns_mode opportunistic
	leak_rules
	start_capture
	D=$(sh dumpsys connectivity | grep -o 'DnsAddresses: \[ /10.111.0.53' | head -1) # only to see that the address is known
	for ip in iptables ip6tables; do :; done
	sh "iptables -I OUTPUT -d 10.111.0.53 -j NFLOG --nflog-group 10 --nflog-prefix DNSIP"
	sh "iptables -I OUTPUT -o eth0 -m owner --uid-owner 0 -j NFLOG --nflog-group 11 --nflog-prefix ROOT-eth0"
	sh "iptables -I OUTPUT -o wlan0 -m owner --uid-owner 0 -j NFLOG --nflog-group 11 --nflog-prefix ROOT-wlan0"
	for g in 10 11; do sh "nohup tcpdump -U -i nflog:$g -w /data/local/tmp/leak$g.pcap >/dev/null 2>&1 &"; done
	sleep 5; t0=$(date +%s.%N)
	sh am start -W -n $PKG/.MainActivity >/dev/null; sleep 3
	toggle
	for _ in $(seq 40); do vpn_up && break; sleep 1; done
	log "AN08: VPN up $(vpn_up && echo yes || echo no) after $(LC_ALL=C awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.0f", b-a}') s"
	sleep 20; t1=$(date +%s.%N)
	echo "$t0 $t0 $t1" >"$RES/$tag.times"
	for g in 10 11; do $ADB pull /data/local/tmp/leak$g.pcap "$RES/$tag-leak$g.pcap" >/dev/null 2>&1; done
	stop_capture "$tag"
	sh settings put global private_dns_mode off
	for g in 7 8 9 10 11; do log "$tag nflog group $g: $(nflog_count "$RES/$tag-leak$g.pcap") packets"; done
}

setup() {
	$ADB root >/dev/null; sleep 2
	$ADB install -r "${APK:-$RES/rc23.apk}" >/dev/null
	log "apk installed, uid $(sh pm list packages -U $PKG | tr -d '\r')"
	if ! pgrep -f "$RES/wgserver" >/dev/null; then
		mkdir -p "$RES/wg"
		nohup nice -n 5 "$RES/wgserver" -out "$RES/wg" >/dev/null 2>"$RES/wg/server.log" </dev/null &
		for _ in $(seq 50); do [[ -f $RES/wg/settings.json ]] && break; sleep 0.2; done
	fi
	sh am force-stop $PKG
	$ADB push "$RES/wg/settings.json" /data/local/tmp/shunt-settings.json >/dev/null
	sh "run-as $PKG sh -c 'mkdir -p files && cp /data/local/tmp/shunt-settings.json files/settings.json'"
	sh appops set $PKG ACTIVATE_VPN allow
	sh pm grant $PKG android.permission.POST_NOTIFICATIONS 2>/dev/null
	leak_rules
	log "leak rules set"
}

mode() { # mode S|O : always-on + block without VPN (S) or neither (O)
	if [[ $1 == S ]]; then
		# NOTE: Android does not treat this as real Always-on (the app shows "no kill switch", the system does not restart the VPN
		# after install -r / a crash). Valid Always-on + lockdown runs need the Android VPN settings (gear of the app, then
		# "Block connections without VPN"); the first start also needs the consent page ("Accept") tapped.
		sh settings put secure always_on_vpn_app $PKG
		sh settings put secure always_on_vpn_lockdown 1
	else
		sh settings put secure always_on_vpn_lockdown 0
		sh settings put secure always_on_vpn_app null
	fi
}

event() { # the action of each test; $1 = ID
	case $1 in
	AN01) sh svc wifi disable; sleep 20; sh svc wifi enable ;; # AN02 is the second half
	AN00) sleep 40 ;; # baseline without event
	AN03) sh cmd connectivity airplane-mode enable; sleep 10; sh cmd connectivity airplane-mode disable; sleep 15 ;;
	AN04) for _ in 1 2 3 4 5; do sh svc wifi disable; sleep 1; sh svc wifi enable; sleep 1; done; sleep 15 ;;
	AN05) $ADB reboot ;;
	AN06c) sh am crash $PKG >/dev/null 2>&1 || sh am force-stop $PKG; sleep 60 ;;
	AN06f) sh am force-stop $PKG; sleep 60 ;;
	AN07) $ADB install -r "${APK:-$RES/rc23.apk}" >/dev/null; sleep 30 ;;
	AN09) sh input keyevent 26; sleep 2; sh dumpsys deviceidle force-idle >/dev/null; sleep "${IDLE:-300}"; sh dumpsys deviceidle unforce >/dev/null; sh input keyevent 224; sleep 20 ;;
	esac
}

run() { # run ID [label]
	local id=$1 t0 t1 tag=${2:-$1}
	vpn_up || { log "$id: VPN not up, abort"; return 1; }
	start_capture
	sleep 12
	t0=$(date +%s.%N)
	log "$id event start"
	if [[ $id == AN01 ]]; then # AN01 wifi off, then AN02 wifi on, measured in two windows
		sh svc wifi disable; sleep 20
		local tm=$(date +%s.%N)
		sh svc wifi enable; sleep 20
		t1=$(date +%s.%N)
		echo "$t0 $tm $t1" >"$RES/$tag.times"
	elif [[ $id == AN05 ]]; then
		event AN05
		$ADB wait-for-device
		for _ in $(seq 120); do [[ $(sh getprop sys.boot_completed 2>/dev/null | tr -d '\r') == 1 ]] && break; sleep 2; done
		sleep 90
		t1=$(date +%s.%N)
		echo "$t0 $t0 $t1" >"$RES/$tag.times"
		$ADB root >/dev/null; sleep 3
		log "$id: after boot, VPN up: $(vpn_up && echo yes || echo no)"
		log "$id: NFLOG rules are gone after boot, only the host capture counts"
		stop_capture "$tag"
		return 0
	else
		event "$id"
		t1=$(date +%s.%N)
		echo "$t0 $t0 $t1" >"$RES/$tag.times"
	fi
	sleep 3
	stop_capture "$tag"
	for g in 7 8 9; do log "$tag nflog group $g: $(nflog_count "$RES/$tag-leak$g.pcap") packets"; done
	log "$tag tunnel gaps:"; gaps "$RES/$tag-gen.log" | tee -a "$RES/lab.log"
}

"$@"
