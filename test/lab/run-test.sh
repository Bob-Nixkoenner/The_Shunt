# Sourced by lab.sh: runs one test file from tests/.
#
# A test file sets (defaults in brackets):
#   ID, TITLE                 e.g. A01, "App on the tunnel leaves only via CT130"
#   MODE [normal]             gateway mode (labctl mode)
#   CONFIG [base]             configs/<CONFIG>.toml becomes the client's shunt.toml
#   EXPECT_CANARY [tunnel]    where the canary name may show up: tunnel|gw|none|any
#   ALLOW=()                  extra things the café network may see:
#                             comm:<name> (packets of that process), dst:ip:port/proto,
#                             net:<cidr>:port/proto (rotating addresses), dns
#   CHECKS=()                 fingerprint = DHCP name, EUI-64, real MAC … count as findings
#   RENEW [0]                 1 = reconnect the client's network while capturing
#   SCAN [0]                  1 = nmap the client from the gateway while it runs
#   EXPECT_OPEN=()            ports that may be open in the scan ("22/tcp")
#   NETEM                     tc netem args on the lab LAN during the test
#   SETTLE [3]                seconds to wait after setup before the client script
#   NOTE                      extra text for the report
#   CLIENT                    bash script run in the client as $USER_VM; $1 = canary
#                             name; print "FAIL <text>" for a failed client-side check
#   during()                  optional function run on the laptop alongside CLIENT
#                             (e.g. `sleep 5; gw labctl mode tunnelkill`)

# Platform hooks (Linux client); winclient.sh replaces them for CLIENT_OS=windows.
client_trace() { # start | stop | fetch <dir>
	case $1 in
	start) client "sudo -n /usr/local/lib/shuntlab/trace.sh start /tmp/shuntlab-trace.log" ;;
	stop) client "sudo -n /usr/local/lib/shuntlab/trace.sh stop /tmp/shuntlab-trace.log" ;;
	fetch) client_cp_from /tmp/shuntlab-trace.log "$2/trace.log" || true ;;
	esac
}
client_version() { client 'shunt version 2>/dev/null' | tr -d '\r'; }

jarr() { local o='' x; for x in "$@"; do o+="\"$x\","; done; echo "${o%,}"; }

PASSED=()
FOUND=()
CLIENT_IF=${CLIENT_IF:-enp0s3}
TUNNEL_IP=${TUNNEL_IP:-10.66.0.12}

resolve_test() {
	local t=$1
	[[ -f $t ]] && { echo "$t"; return; }
	compgen -G "${TESTS_DIR:-$HERE/tests}/$t*.${TEST_EXT:-sh}" | head -1
}

apply_config() { # $1 = config name; restarts shuntd only when it changed
	local want
	want=$(sha256sum <"$HERE/configs/$1.toml" | cut -c1-16)
	if [[ $(client "sudo -n sha256sum /etc/shunt/shunt.toml | cut -c1-16") != "$want" ]]; then
		VBoxManage "${GC[@]}" copyto "$HERE/configs/$1.toml" /tmp/shunt.toml
		client "sudo -n install -m644 /tmp/shunt.toml /etc/shunt/shunt.toml && sudo -n systemctl restart shuntd && sleep 4"
	fi
}

renew_client() {
	client "c=\$(nmcli -g GENERAL.CONNECTION dev show $CLIENT_IF); sudo -n nmcli -w 30 con up \"\$c\" >/dev/null" || true
	sleep 4
}

run_test() {
	local file
	file=$(resolve_test "$1")
	[[ -n $file ]] || { echo "no test $1" >&2; return 1; }
	# defaults, then the test file
	ID='' TITLE='' MODE=normal CONFIG=base EXPECT_CANARY=tunnel RENEW=0 SCAN=0 NETEM='' SETTLE=3 NOTE='' CLIENT=''
	ALLOW=() CHECKS=() EXPECT_OPEN=()
	unset -f during
	# shellcheck disable=SC1090
	source "$file"
	# CONFIG_FORCE: run a test with another config (e.g. ks = Windows kill switch on)
	[[ -z ${CONFIG_FORCE:-} ]] || CONFIG=$CONFIG_FORCE

	local stamp run out canary cur
	stamp=$(date +%Y%m%d-%H%M%S)
	run="$ID-$stamp"
	out=$LAB_OUT/$(date +%F)/$run
	mkdir -p "$out"
	canary="${ID,,}-$(date +%s).shuntlab.test"
	echo "== $ID $TITLE  (mode $MODE, config $CONFIG)"

	# a special mode left over from the previous test (tunnelkill!) would let the
	# config change below start with a dead tunnel: back to normal first
	cur=$(gw cat /etc/shuntlab/mode)
	if [[ $cur != normal && $cur != "$MODE" ]]; then
		gw labctl mode normal >/dev/null
		renew_client
		cur=normal
	fi
	apply_config "$CONFIG"
	gw labctl netem off >/dev/null

	# captures first, so DHCP after a mode change is in them
	gw labctl cap start "$run" >/dev/null
	local ct_pid=''
	if ct130 true 2>/dev/null; then
		ct_pid=$(ct130 "nohup timeout 900 tcpdump -i $CT130_IF -U -s 0 -w /tmp/shuntlab-$run.pcap </dev/null >/dev/null 2>&1 & echo \$!")
	else
		echo "   (CT130 not reachable: no capture at the tunnel exit)"
	fi
	client_trace start

	if [[ $cur != "$MODE" ]]; then
		gw labctl mode "$MODE" >/dev/null
		RENEW=1
	fi
	((RENEW)) && renew_client
	[[ -n $NETEM ]] && gw labctl netem $NETEM >/dev/null
	sleep "$SETTLE"

	local dpid=''
	if declare -F during >/dev/null; then
		during >"$out/during.log" 2>&1 &
		dpid=$!
	fi
	((SCAN)) && gw labctl scan "$run" >/dev/null 2>&1 &
	local spid=$!
	printf '%s\n' "$CLIENT" | client_script "$canary" >"$out/client.out" 2>&1 || true
	[[ -n $dpid ]] && wait "$dpid" 2>/dev/null
	((SCAN)) && wait "$spid" 2>/dev/null
	sleep 2

	client_trace stop
	gw labctl netem off >/dev/null
	gw labctl cap stop "$run" >/dev/null
	client_trace fetch "$out"
	if [[ -n $ct_pid ]]; then
		ct130 "kill $ct_pid; sleep 1" || true
		ct130 "cat /tmp/shuntlab-$run.pcap" >"$out/ct130.pcap" && ct130 "rm -f /tmp/shuntlab-$run.pcap"
	fi

	local ver lease mac ip4
	ver=$(client_version)
	lease=$(gw labctl client 2>/dev/null || true)
	read -r mac ip4 _ <<<"$lease"
	python3 - "$out/meta.json" <<EOF
import json, sys
json.dump({
 "id": "$ID", "title": """$TITLE""", "mode": "$MODE", "config": "$CONFIG",
 "canary": "$canary", "expect_canary": "$EXPECT_CANARY",
 "allow": [$(jarr "${ALLOW[@]}")], "checks": [$(jarr "${CHECKS[@]}")],
 "expect_open": [$(jarr "${EXPECT_OPEN[@]}")],
 "endpoints": $(gw cat /etc/shuntlab/endpoints | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))'),
 "client_mac": "${mac:-}", "client_ips": ["${ip4:-}"], "tunnel_ip": "$TUNNEL_IP",
 "shunt_version": "$ver", "started": "$stamp", "note": """$NOTE""",
}, open(sys.argv[1], "w"), indent=1)
EOF
	# analysis runs on the gateway (scapy, p0f); everything ends up in $out
	local gdir=/var/lib/shuntlab/cap/$run
	gw rm -rf /tmp/shuntlab-up
	gw_cp_to "$out" /tmp/shuntlab-up
	gw bash -c "cp -n /tmp/shuntlab-up/* $gdir/ && rm -rf /tmp/shuntlab-up && python3 /usr/local/lib/analyze.py $gdir" | tee "$out/verdict.txt"
	gw tar -C "$gdir" -cf - . | tar -C "$out" -xf -
	if grep -q ": FUND" "$out/verdict.txt"; then FOUND+=("$ID"); else PASSED+=("$ID"); fi
	echo "   → $out/report.md"
}

summary() {
	echo
	echo "OK:   ${PASSED[*]:-–}"
	echo "FUND: ${FOUND[*]:-–}"
}

if [[ ${CLIENT_OS:-linux} == windows ]]; then source "$HERE/winclient.sh"; fi
