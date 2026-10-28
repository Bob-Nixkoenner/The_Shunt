#!/usr/bin/env bash
# End-to-end test in network namespaces. Needs root, nft, ip, wg, python3.
#
#   ns shunt-wan  10.99.0.1  fd99::1   whoami HTTP server (prints client IP)
#                 10.66.0.1            WireGuard server (wireguard-go)
#        |  veth
#   ns shunt-cli  10.99.0.2  fd99::2   shuntd + test clients
#                 10.66.0.2            tunnel "vps" (IPv4 only)
#
# A request that left directly shows up as 10.99.0.2, one that went through
# the tunnel as 10.66.0.2. Anything else (or nothing) is what we test for.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
chmod 755 "$WORK" # test apps run as nobody
BIN=$WORK/bin
CG=shunt-it
SOCK=$WORK/shuntd.sock
WAN=shunt-wan
CLI=shunt-cli
PASS=0
FAIL=0
HAVE_V6=0
[[ -d /proc/sys/net/ipv6 ]] && HAVE_V6=1

cleanup() {
	set +e
	[[ -n ${SHUNTD_PID:-} ]] && kill "$SHUNTD_PID" 2>/dev/null && wait "$SHUNTD_PID" 2>/dev/null
	pkill -f "^$BIN/" 2>/dev/null
	[[ -n ${WHOAMI_PID:-} ]] && kill "$WHOAMI_PID" 2>/dev/null
	ip netns exec $WAN pkill -f "^$BIN/wireguard-go" 2>/dev/null
	ip netns exec $WAN pkill -f "^$BIN/fakedns" 2>/dev/null
	[[ -n ${OVPN_SRV_PID:-} ]] && kill "$OVPN_SRV_PID" 2>/dev/null
	[[ -n ${PORTAL_PID:-} ]] && kill "$PORTAL_PID" 2>/dev/null
	ip netns del $CLI 2>/dev/null
	rm -rf "/etc/netns/$CLI"
	groupdel shunttest 2>/dev/null
	ip netns del $WAN 2>/dev/null
	find "$CGMNT/$CG" -depth -type d -exec rmdir {} + 2>/dev/null
	[[ -n ${KEEP_LOGS:-} ]] && cp "$WORK"/*.log "$KEEP_LOGS"/ 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

# cgroup2 mount (hybrid hosts have it under unified/)
CGMNT=/sys/fs/cgroup
[[ $(stat -fc %T $CGMNT) == cgroup2fs ]] || CGMNT=/sys/fs/cgroup/unified

echo "== build"
mkdir -p "$BIN"
(cd "$ROOT" && go build -o "$BIN/" ./cmd/shuntd ./cmd/shunt ./test/integration/fakedns && go build -o "$BIN/wireguard-go" golang.zx2c4.com/wireguard)

groupadd -f shunttest
TGID=$(getent group shunttest | cut -d: -f3)
# an unprivileged member of the socket group (like a desktop user)
MEMBER=(setpriv --reuid=65534 --regid=65534 --groups="$TGID")

echo "== topology"
ip netns del $WAN 2>/dev/null || true
ip netns del $CLI 2>/dev/null || true
ip netns add $WAN
ip netns add $CLI
NETNS_RESOLV=/etc/netns/$CLI/resolv.conf
mkdir -p "/etc/netns/$CLI"
printf 'nameserver 10.99.0.1\n' >"$NETNS_RESOLV"
ip -n $WAN link add wan0 type veth peer name cli0
ip -n $WAN link set cli0 netns $CLI
ip -n $WAN addr add 10.99.0.1/24 dev wan0
ip -n $WAN addr add 10.99.0.3/24 dev wan0   # target of the domain rule
((HAVE_V6)) && ip -n $WAN addr add fd99::1/64 dev wan0 nodad
ip -n $CLI addr add 10.99.0.2/24 dev cli0
((HAVE_V6)) && ip -n $CLI addr add fd99::2/64 dev cli0 nodad
for ns in $WAN $CLI; do ip -n $ns link set lo up; done
ip -n $WAN link set wan0 up
ip -n $CLI link set cli0 up
ip -n $CLI route add default via 10.99.0.1

SRV_KEY=$(wg genkey); SRV_PUB=$(echo "$SRV_KEY" | wg pubkey)
CLI_KEY=$(wg genkey); CLI_PUB=$(echo "$CLI_KEY" | wg pubkey)

ip netns exec $WAN "$BIN/wireguard-go" -f wgs >/dev/null 2>&1 &
for _ in $(seq 50); do ip -n $WAN link show wgs >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec $WAN wg set wgs listen-port 51820 private-key <(echo "$SRV_KEY") \
	peer "$CLI_PUB" allowed-ips 10.66.0.2/32
ip -n $WAN addr add 10.66.0.1/24 dev wgs
ip -n $WAN link set wgs up

ip netns exec $WAN python3 "$ROOT/test/integration/whoami.py" 8080 8081 853 &
WHOAMI_PID=$!
# a Wi-Fi login page that can be switched on (captive portal detection)
echo online >"$WORK/portal.mode"
ip netns exec $WAN python3 "$ROOT/test/integration/portal.py" 10.99.0.1 "$WORK/portal.mode" &
PORTAL_PID=$!
export SHUNT_CAPTIVE_URL=http://10.99.0.1:8090/check
export SHUNT_LINK_KINDS=cli0=ethernet,cli1=wifi
# the test may run in a desktop session: never pop up polkit password dialogs
export SHUNT_POLKIT_NO_DIALOG=1
# the leak test probes are started by shuntd: it must know the test's IP echo
export SHUNT_PROBE_IP_URL=http://10.99.0.1:8080
# two DNS servers: one reachable directly, one only through the tunnel
ip netns exec $WAN "$BIN/fakedns" serve -tag direct -listen 10.99.0.1:53 -a site.test=10.99.0.3 -a blocked.site.test=0.0.0.0 &
ip netns exec $WAN "$BIN/fakedns" serve -tag tunnel -listen 10.66.0.1:53 -a site.test=10.99.0.3 -a blocked.site.test=0.0.0.0 &

mkdir -p "$WORK/etc"
cat >"$WORK/etc/vps.conf" <<EOF
[Interface]
PrivateKey = $CLI_KEY
Address = 10.66.0.2/32
DNS = 10.66.0.1
PostUp = touch /tmp/pwned   # must be ignored

[Peer]
PublicKey = $SRV_PUB
Endpoint = 10.99.0.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 5
EOF
chmod 600 "$WORK/etc/vps.conf"

write_config() { # $1 = default route, $2 = "system" to use the system resolver
	local direct='direct = "lan"'
	[[ ${2:-} == system ]] && direct=''
	cat >"$WORK/etc/shunt.toml" <<EOF
[daemon]
socket = "$SOCK"
socket_group = "shunttest"
cgroup_root = "$CG"
default_route = "$1"

[dns]
$direct

[dns.upstream.lan]
addr = "10.99.0.1"

[dns_filter]
normal = ["testlist"]
paranoid = ["testlist", "evil"]
allow = ["ok.ads.filter.test"]

[tunnel.vps]
config = "vps.conf"
driver = "${SHUNT_DRIVER:-auto}"
dns_filter = "paranoid"
${VPS_EXTRA:-}
${EXTRA_TUNNELS:-}

[[rule]]
name = "site.test through the tunnel"
domain = ["site.test"]
route = "tunnel:vps"

[group.torrent]
[group.nofilter]

[[rule]]
name = "no DNS filter for this group"
group = ["nofilter"]
dns_filter = "off"

[[rule]]
name = "profile sm through the tunnel"
app = ["proftest"]
args = ["-P sm"]
route = "tunnel:vps"

[[rule]]
name = "apptest auto-detected"
app = ["apptest"]
route = "tunnel:vps"

[[rule]]
name = "port 8081 through the tunnel"
cidr = ["10.99.0.1"]
port = ["tcp/8081"]
route = "tunnel:vps"

[[rule]]
name = "torrent group blocked from 8080"
group = ["torrent"]
port = ["tcp/8080"]
route = "block"
EOF
}
write_config direct

# DNS filter lists, as if downloaded already (the namespaces have no
# internet): cache file name = <list>-<first 6 bytes of sha256(url)>.txt
seed_list() { # name, content
	local url="https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/$1"
	mkdir -p "$WORK/etc/blocklists"
	printf '%s\n' "$2" >"$WORK/etc/blocklists/$1-$(printf %s "$url" | sha256sum | cut -c1-12).txt"
}
seed_list testlist '||ads.filter.test^'
seed_list evil '0.0.0.0 evil.filter.test'

# --- helpers ----------------------------------------------------------------
# `ip netns exec` remounts /sys, so mount cgroup2 again for everything that
# needs it (shuntd, nft resolving cgroup paths, tests joining cgroups)
cli() { ip netns exec $CLI unshare -m sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' _ "$@"; }
shunt() { cli "$BIN/shunt" -s "$SOCK" "$@"; }
fetch() { cli timeout 5 "$@" 2>/dev/null || true; }
fetch_long() { cli env SHUNT_PROBE_IP_URL="${SHUNT_PROBE_IP_URL:-}" timeout 40 "$@" 2>/dev/null || true; }

# grep -q stops reading at the first match; with pipefail the writer's
# SIGPIPE would then fail the whole pipeline
gq() { grep "$@" >/dev/null; }

check() { # name expected actual
	if [[ "$3" == "$2" ]]; then
		echo "  ok   $1"
		PASS=$((PASS + 1))
	else
		echo "  FAIL $1: expected '$2', got '$3'"
		FAIL=$((FAIL + 1))
	fi
}

start_shuntd() {
	# shuntd and the nft binary it calls must see cgroup2 at /sys/fs/cgroup
	# no shell function here: $! must be shuntd itself (exec chain), not a subshell
	# same capabilities as the systemd unit: nothing but CAP_NET_ADMIN and
	# CAP_CHOWN (no CAP_SYS_PTRACE, no CAP_DAC_OVERRIDE, ...)
	ip netns exec $CLI unshare -m sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' _ \
		setpriv --bounding-set=-all,+net_admin,+chown --inh-caps=-all \
		"$BIN/shuntd" -c "$WORK/etc/shunt.toml" run 2>"$WORK/shuntd.log" &
	SHUNTD_PID=$!
	for _ in $(seq 50); do [[ -S $SOCK ]] && return; sleep 0.1; done
	echo "shuntd did not start:"; cat "$WORK/shuntd.log"; exit 1
}

dnsq() { fetch "$BIN/fakedns" query "$@"; }
dnsq_via() { local via=$1; shift; fetch "$BIN/shunt" -s "$SOCK" run --via "$via" -- "$BIN/fakedns" query "$@"; }
failed_closed() { case $1 in SERVFAIL | ERROR | REFUSED | "") echo yes ;; *) echo "no ($1)" ;; esac; }

URL=http://10.99.0.1:8080
URL_SITE=http://10.99.0.3:8080
URL81=http://10.99.0.1:8081
URL6='http://[fd99::1]:8080'

# --- tests --------------------------------------------------------------------
echo "== static checks"
mkdir -p "$CGMNT/$CG"
out=$(cli "$BIN/shuntd" -c "$WORK/etc/shunt.toml" check)
check "check prints ruleset" yes "$(grep -q 'chain route_out' <<<"$out" && echo yes || echo no)"
chmod 644 "$WORK/etc/vps.conf"
check "world readable key refused" refused "$("$BIN/shuntd" -c "$WORK/etc/shunt.toml" check >/dev/null 2>&1 && echo accepted || echo refused)"
chmod 600 "$WORK/etc/vps.conf"

echo "== daemon up, default direct"
start_shuntd
for _ in $(seq 50); do shunt status | gq 'up/' && break; sleep 0.1; done
# debugging aid: SHUNT_HOLD=/path/to/file keeps the setup alive until the file exists
if [[ -n ${SHUNT_HOLD:-} ]]; then
	echo "holding, work dir $WORK; touch $SHUNT_HOLD to continue"
	until [[ -e $SHUNT_HOLD ]]; do sleep 1; done
fi
check "default traffic goes direct" 10.99.0.2 "$(fetch curl -s $URL)"
check "--via tunnel goes through tunnel" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
check "--via direct goes direct" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)"
check "--via block gets nothing" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via block -- curl -s $URL)"
check "children inherit the route" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- sh -c "curl -s $URL")"
check "cidr+port rule tunnels 8081" 10.66.0.2 "$(fetch curl -s $URL81)"
check "cidr+port rule leaves 8080 alone" 10.99.0.2 "$(fetch curl -s $URL)"
check "group rule blocks torrent:8080" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --group torrent -- curl -s $URL)"
check "group rule falls through on 8081" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --group torrent -- curl -s $URL81)"
if ((HAVE_V6)); then
	check "IPv6 direct works" fd99::2 "$(fetch curl -s -6 "$URL6")"
	check "IPv6 blocked for v4-only tunnel" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s -6 "$URL6")"
else
	echo "  skip IPv6 checks (kernel without IPv6)"
fi
check "wg-quick PostUp ignored" no "$([[ -e /tmp/pwned ]] && echo yes || echo no)"
echo "== app rules (auto-detected, no shunt run)"
printf '#!/bin/sh\nsleep 1\nexec curl -s "$1"\n' >"$BIN/apptest"
chmod +x "$BIN/apptest"
# apps run as another user, like desktop apps vs. the root daemon
NOBODY=(setpriv --reuid=65534 --regid=65534 --clear-groups)
check "app rule moves a normally started program" 10.66.0.2 "$(fetch "${NOBODY[@]}" "$BIN/apptest" $URL)"
check "shunt run wins over app rule" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via direct -- "$BIN/apptest" $URL)"
printf '#!/bin/sh\nsleep 1\nexec curl -s "$3"\n' >"$BIN/proftest"
chmod +x "$BIN/proftest"
check "args rule: profile sm tunnelled" 10.66.0.2 "$(fetch "${NOBODY[@]}" "$BIN/proftest" -P sm $URL)"
check "args rule: other profile untouched" 10.99.0.2 "$(fetch "${NOBODY[@]}" "$BIN/proftest" -P smart $URL)"
check "status shows app group" yes "$(shunt status | gq '^app:apptest auto-detected' && echo yes || echo no)"

cli "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- sleep 20 &
sleep 0.5
check "which shows the route of a process" yes "$(shunt which sleep | gq 'sleep  *tunnel:vps' && echo yes || echo "no: $(shunt which sleep)")"
echo "== permissions (group member, not root)"
mshunt() { cli "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" "$@"; }
check "member: status allowed" yes "$(mshunt status >/dev/null 2>&1 && echo yes || echo no)"
check "member: start app in a route" 10.66.0.2 "$(fetch "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
check "member: reload needs authorization" denied "$(mshunt reload >/dev/null 2>&1 && echo allowed || echo denied)"
check "member: config write needs authorization" denied "$(cli "${MEMBER[@]}" curl -s --unix-socket "$SOCK" -X PUT -o /dev/null -w '%{http_code}' --data-binary '{"raw":"x"}' http://shuntd/v1/config | sed 's/403/denied/')"
check "member: panic on allowed" yes "$(mshunt panic on >/dev/null 2>&1 && echo yes || echo no)"
check "member: panic off needs authorization" denied "$(mshunt panic off >/dev/null 2>&1 && echo allowed || echo denied)"
shunt panic off
esc=$(fetch "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- sh -c "'$BIN/shunt' -s '$SOCK' run --via direct -- curl -s $URL 2>&1")
check "tunnelled app cannot escape to direct" yes "$(grep -q 'leaving route tunnel:vps' <<<"$esc" && ! grep -q 10.99.0.2 <<<"$esc" && echo yes || echo "no: $esc")"
check "tunnelled app may move to block" "" "$(fetch "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- "$BIN/shunt" -s "$SOCK" run --via block -- curl -s $URL)"
check "root may move a tunnelled app" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)"
check "non-member gets no socket access" denied "$(cli setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN/shunt" -s "$SOCK" status >/dev/null 2>&1 && echo allowed || echo denied)"

echo "== DNS"
check "query goes to direct upstream" "direct 10.99.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)"
check "any resolver IP is redirected" "direct 10.99.0.2" "$(dnsq -server 192.0.2.53:53 -type TXT whoami.test)"
check "local stub is redirected" "direct 10.99.0.2" "$(dnsq -server 127.0.0.53:53 -type TXT whoami.test)"
check "DNS over TCP is redirected" "direct 10.99.0.2" "$(dnsq -tcp -server 10.99.0.1:53 -type TXT whoami.test)"
check "tunnelled app resolves via tunnel" "tunnel 10.66.0.2" "$(dnsq_via tunnel:vps -server 10.99.0.1:53 -type TXT whoami.test)"
check "blocked app gets no DNS" yes "$(failed_closed "$(dnsq_via block -server 10.99.0.1:53 -type TXT whoami.test)")"
# UDP has no connections: a blocked app reusing the source port a tunnelled
# app's query just used must not inherit that flow's route
check "same UDP port, tunnel first" "tunnel 10.66.0.2" "$(dnsq_via tunnel:vps -sport 40053 -server 10.99.0.1:53 -type TXT whoami.test)"
check "same UDP port, then block: still blocked" yes "$(failed_closed "$(dnsq_via block -sport 40053 -server 10.99.0.1:53 -type TXT whoami.test)")"
check "domain rule resolves via its tunnel" "tunnel 10.66.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT site.test)"
check "domain target direct before lookup" 10.99.0.2 "$(fetch curl -s $URL_SITE)"
check "domain rule A answer" 10.99.0.3 "$(dnsq -server 10.99.0.1:53 site.test)"
check "domain target tunnelled after lookup" 10.66.0.2 "$(fetch curl -s $URL_SITE)"
check "blocking answer (0.0.0.0) passed to the app" 0.0.0.0 "$(dnsq -server 10.99.0.1:53 blocked.site.test)"
check "blocking answer kept out of routing sets" 0 "$(cli nft list table inet shunt | grep -c '0\.0\.0\.0')"
check "Firefox DoH canary NXDOMAIN" NXDOMAIN "$(dnsq -server 10.99.0.1:53 use-application-dns.net)"
check "public DoH host NXDOMAIN" NXDOMAIN "$(dnsq -server 10.99.0.1:53 dns.google)"

echo "== DNS filter"
for _ in $(seq 50); do [[ $(dnsq -server 10.99.0.1:53 -type TXT x.ads.filter.test) == NXDOMAIN ]] && break; sleep 0.1; done
check "filter: listed name blocked (normal)" NXDOMAIN "$(dnsq -server 10.99.0.1:53 -type TXT x.ads.filter.test)"
check "filter: allowlist wins" "direct 10.99.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT ok.ads.filter.test)"
check "filter: paranoid-only list not used on normal" "direct 10.99.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT evil.filter.test)"
check "filter: tunnel's own level (paranoid)" NXDOMAIN "$(dnsq_via tunnel:vps -server 10.99.0.1:53 -type TXT evil.filter.test)"
check "filter: rule level off for its group" "direct 10.99.0.2" "$(fetch "$BIN/shunt" -s "$SOCK" run --group nofilter -- "$BIN/fakedns" query -server 10.99.0.1:53 -type TXT x.ads.filter.test)"
check "filter: rule without route keeps the default route" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --group nofilter -- curl -s $URL)"
check "filter: no download attempt for a cached list" yes "$(grep -q 'list download failed' "$WORK/shuntd.log" && echo no || echo yes)"
check "DoT port 853 blocked" "" "$(fetch curl -s http://10.99.0.1:853)"
check "status shows DNS upstreams" yes "$(shunt status | gq 'tunnel:vps .*udp://10.66.0.1:53' && echo yes || echo no)"
echo "== leak test"
lt=$(SHUNT_PROBE_IP_URL=$URL fetch_long "$BIN/shunt" -s "$SOCK" leaktest)
check "leaktest: direct ok" yes "$(grep -qE '^direct +10.99.0.2 +10.99.0.2 +OK' <<<"$lt" && echo yes || echo "no: $lt")"
check "leaktest: tunnel ok" yes "$(grep -qE '^tunnel:vps +10.66.0.2 +10.66.0.2 +OK' <<<"$lt" && echo yes || echo "no: $lt")"
check "leaktest: block blocked" yes "$(grep -qE '^block +- +- +BLOCKED' <<<"$lt" && echo yes || echo "no: $lt")"
check "status lists tunnel" yes "$(shunt status | gq '^vps .*up/' && echo yes || echo no)"
check "unknown group rejected" rejected "$(cli "$BIN/shunt" -s "$SOCK" run --group nope -- true >/dev/null 2>&1 && echo accepted || echo rejected)"

echo "== kill switch: tunnel interface disappears"
# The watchdog restores the tunnel every 30s; a result only counts if the
# interface was still gone after the probe, otherwise delete and retry.
while_down() { # name expected cmd...
	local name=$1 want=$2 got
	shift 2
	for _ in 1 2 3; do
		cli ip link del sh-vps 2>/dev/null || true
		got=$("$@")
		cli ip link show sh-vps >/dev/null 2>&1 || break
	done
	check "$name" "$want" "$got"
}
while_down "tunnel DNS fails closed" yes eval 'failed_closed "$(dnsq_via tunnel:vps -server 10.99.0.1:53 -type TXT whoami.test)"'
while_down "tunnel route blocked, no leak" "" fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL
check "direct still works" 10.99.0.2 "$(fetch curl -s $URL)"
echo "   (waiting for the watchdog to restore the tunnel)"
for _ in $(seq 45); do cli ip link show sh-vps >/dev/null 2>&1 && break; sleep 1; done
sleep 2
check "watchdog restored tunnel carries traffic" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
check "restored tunnel resolves DNS" "tunnel 10.66.0.2" "$(dnsq_via tunnel:vps -server 10.99.0.1:53 -type TXT whoami.test)"

echo "== reload: default route = tunnel"
write_config tunnel:vps
shunt reload
for _ in $(seq 50); do shunt status | gq 'up/' && break; sleep 0.1; done
check "default traffic via tunnel" 10.66.0.2 "$(fetch curl -s $URL)"
esc=$(fetch "${MEMBER[@]}" sh -c "'$BIN/shunt' -s '$SOCK' run --via direct -- curl -s $URL 2>&1")
check "default-route app cannot escape to direct" yes "$(grep -q 'leaving route tunnel:vps' <<<"$esc" && ! grep -q 10.99.0.2 <<<"$esc" && echo yes || echo "no: $esc")"
check "--via direct escapes default" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)"
hs=no
for _ in $(seq 25); do shunt status | gq ' ago ' && hs=yes && break; sleep 0.2; done
check "handshake shown in status (bypass mark)" yes "$hs"
check "default DNS via tunnel" "tunnel 10.66.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)"
((HAVE_V6)) && check "IPv6 default blocked (tunnel v4-only)" "" "$(fetch curl -s -6 "$URL6")"
# a server that does not clamp: its tunnel side can take 1500-byte packets
ip -n $WAN link set wgs mtu 1500
mss=$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s http://10.66.0.1:8080/mss)
check "TCP into a tunnel announces the tunnel's MSS (clamped)" yes "$([[ -n $mss && $mss -le 1380 ]] && echo yes || echo "no: $mss")"
ip -n $WAN link set wgs mtu 1420

echo "== config editing API"
capi() { curl -s --unix-socket "$SOCK" -X "$1" -o "$WORK/api.out" -w '%{http_code}' "http://shuntd$2" ${3:+-H 'Content-Type: application/json' --data-binary "$3"}; }
capi GET /v1/config >/dev/null
check "config view has no private keys" 0 "$(grep -c "$CLI_KEY" "$WORK/api.out")"
before=$(sha256sum "$WORK/etc/shunt.toml")
check "invalid config rejected" 422 "$(capi PUT /v1/config '{"raw":"[[rule]]\nroute=\"nowhere\"\n"}')"
check "file untouched after rejection" "$before" "$(sha256sum "$WORK/etc/shunt.toml")"
bad=$(python3 -c 'import json,sys; print(json.dumps({"raw": open(sys.argv[1]).read().replace("socket = ", "socket = \"/tmp/x\"  # ", 1)}))' "$WORK/etc/shunt.toml")
check "daemon section locked" 422 "$(capi PUT /v1/config "$bad")"
check "tunnel file outside tunnels dir rejected" yes "$(capi POST /v1/config/check "$(python3 -c 'import json,sys; print(json.dumps({"raw": open(sys.argv[1]).read() + "\n[tunnel.evil]\nconfig = \"/etc/shadow\"\n"}))' "$WORK/etc/shunt.toml")" >/dev/null; grep -q 'must be in' "$WORK/api.out" && echo yes || echo no)"
# structured save: put a block rule first, traffic must follow immediately
capi GET /v1/config >/dev/null
python3 - "$WORK/api.out" "$WORK/new.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
c = v["config"]
c["rule"].insert(0, {"name": "ui block test", "cidr": ["10.99.0.1"], "port": ["tcp/8080"], "route": "block"})
c["daemon"]["default_route"] = "direct"   # editable part of [daemon]
c["daemon"]["socket"] = "/tmp/evil.sock"  # locked part: must be ignored
json.dump({"config": c}, open(sys.argv[2], "w"))
PY
check "structured save accepted" 200 "$(capi PUT /v1/config "$(cat "$WORK/new.json")")"
check "saved rule is active" "" "$(fetch curl -s $URL)"
check "default route change saved" yes "$(grep -q 'default_route = "direct"' "$WORK/etc/shunt.toml" && echo yes || echo no)"
check "locked socket setting kept" yes "$(grep -q "socket = \"$SOCK\"" "$WORK/etc/shunt.toml" && echo yes || echo no)"
check "backup written" yes "$([[ -f $WORK/etc/shunt.toml.bak ]] && echo yes || echo no)"
cp "$WORK/etc/shunt.toml.bak" "$WORK/etc/shunt.toml" && shunt reload
check "restored config active again" 10.66.0.2 "$(fetch curl -s $URL)"
NEWKEY=$(wg genkey)
imp=$(python3 -c 'import json,sys; print(json.dumps({"name": "vps2", "conf": "[Interface]\nPrivateKey = %s\nAddress = 10.67.0.2/32\n[Peer]\nPublicKey = %s\nEndpoint = 10.99.0.1:51821\nAllowedIPs = 0.0.0.0/0\n" % (sys.argv[1], sys.argv[2])}))' "$NEWKEY" "$SRV_PUB")
check "tunnel import" 200 "$(capi POST /v1/tunnels "$imp")"
check "imported key file is 0600" 600 "$(stat -c %a "$WORK/etc/tunnels/vps2.conf" 2>/dev/null)"
check "imported tunnel in status" yes "$(shunt status | gq '^vps2 ' && echo yes || echo no)"
check "bad tunnel name rejected" 422 "$(capi POST /v1/tunnels '{"name":"../x","conf":"[Interface]"}')"
check "tunnel delete (shunt remove)" yes "$(shunt remove tunnel:vps2 2>&1 | gq 'removed' && echo yes || echo no)"
check "deleted tunnel file gone" no "$([[ -e $WORK/etc/tunnels/vps2.conf ]] && echo yes || echo no)"
check "deleted tunnel gone from status" no "$(shunt status | gq '^vps2 ' && echo yes || echo no)"
check "tunnel in use cannot be deleted" 422 "$(capi DELETE /v1/tunnels/vps)"
rm_out=$(shunt remove vps 2>&1 || true) # fails on purpose; no pipe under pipefail
check "shunt remove names the reason" yes "$(gq -E 'default route|uses tunnel' <<<"$rm_out" && echo yes || echo "no: $rm_out")"

echo "== system resolver changes are picked up without restart"
# `ip netns exec` bind-mounts this file over /etc/resolv.conf; rewrite it in
# place (same inode) the way NetworkManager would change the content.
write_config direct system
printf 'nameserver 192.0.2.1\n' >"$NETNS_RESOLV"
shunt reload
check "unreachable system resolver fails closed" yes "$(failed_closed "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)")"
printf 'nameserver 10.99.0.1\n' >"$NETNS_RESOLV"
check "new system resolver used without restart" "direct 10.99.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)"
check "status shows system resolver" yes "$(shunt status | gq 'system (udp://10.99.0.1:53)' && echo yes || echo no)"
write_config tunnel:vps
shunt reload

echo "== multi-hop: WireGuard inside WireGuard"
# second server only reachable through the first tunnel (10.66.0.1)
HOP_KEY=$(wg genkey); HOP_PUB=$(echo "$HOP_KEY" | wg pubkey)
HOPC_KEY=$(wg genkey); HOPC_PUB=$(echo "$HOPC_KEY" | wg pubkey)
ip netns exec $WAN "$BIN/wireguard-go" -f wgh >/dev/null 2>&1 &
for _ in $(seq 50); do ip -n $WAN link show wgh >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec $WAN wg set wgh listen-port 51822 private-key <(echo "$HOP_KEY") peer "$HOPC_PUB" allowed-ips 10.77.0.2/32
ip -n $WAN addr add 10.77.0.1/24 dev wgh
ip -n $WAN link set wgh up
cat >"$WORK/etc/hop.conf" <<EOF
[Interface]
PrivateKey = $HOPC_KEY
Address = 10.77.0.2/32
DNS = 10.66.0.1

[Peer]
PublicKey = $HOP_PUB
Endpoint = 10.66.0.1:51822
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5
EOF
chmod 600 "$WORK/etc/hop.conf"
EXTRA_TUNNELS=$'[tunnel.hop]\nconfig = "hop.conf"\nvia = "tunnel:vps"\n'
write_config tunnel:vps
shunt reload
got=
for _ in $(seq 30); do got=$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:hop -- curl -s $URL); [[ $got == 10.77.0.2 ]] && break; sleep 0.5; done
check "second hop carries traffic" 10.77.0.2 "$got"
check "second hop arrives through the first tunnel" yes "$(ip netns exec $WAN wg show wgh endpoints | gq '10.66.0.2:' && echo yes || echo "no: $(ip netns exec $WAN wg show wgh endpoints)")"
check "second hop MTU lowered" yes "$(cli ip link show sh-hop | gq 'mtu 1340' && echo yes || echo no)"
check "status shows the hop" yes "$(shunt status --json | gq '"via": *"tunnel:vps"' && echo yes || echo no)"
while_down "first hop down blocks the second, no leak" "" fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:hop -- curl -s $URL
check "tunnel used as hop cannot be deleted" 422 "$(capi DELETE /v1/tunnels/vps)"
ip netns exec $WAN pkill -f "^$BIN/wireguard-go -f wgh" || true
EXTRA_TUNNELS=
write_config tunnel:vps
for _ in $(seq 45); do cli ip link show sh-vps >/dev/null 2>&1 && break; sleep 1; done
shunt reload

if command -v openvpn >/dev/null; then
	echo "== OpenVPN tunnel (username/password, pushed DNS), as second hop too"
	O=$WORK/ovpn
	mkdir -p "$O"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=test-ca -keyout "$O/ca.key" -out "$O/ca.crt" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=server -keyout "$O/srv.key" -out "$O/srv.csr" 2>/dev/null
	printf 'extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyAgreement\n' >"$O/ext"
	openssl x509 -req -in "$O/srv.csr" -CA "$O/ca.crt" -CAkey "$O/ca.key" -CAcreateserial -days 2 -extfile "$O/ext" -out "$O/srv.crt" 2>/dev/null
	printf '#!/bin/sh\n[ "$(sed -n 1p "$1")" = alice ] && [ "$(sed -n 2p "$1")" = s3cret ]\n' >"$O/check.sh"
	chmod 755 "$O/check.sh"
	# listens on the WAN and inside the WireGuard tunnel (for the hop test)
	ip netns exec $WAN openvpn --dev ovs --dev-type tun --port 1194 --proto udp4 \
		--server 10.88.0.0 255.255.255.0 --topology subnet --ca "$O/ca.crt" --cert "$O/srv.crt" --key "$O/srv.key" --dh none \
		--verify-client-cert none --username-as-common-name --script-security 2 --auth-user-pass-verify "$O/check.sh" via-file \
		--push "dhcp-option DNS 10.88.0.1" --push "redirect-gateway def1" --keepalive 2 10 --verb 3 >"$WORK/ovpn-server.log" 2>&1 &
	OVPN_SRV_PID=$!
	for _ in $(seq 50); do ip -n $WAN addr show ovs 2>/dev/null | gq 10.88.0.1 && break; sleep 0.1; done
	ip netns exec $WAN "$BIN/fakedns" serve -tag ovpn -listen 10.88.0.1:53 &
	ovpn_conf() { printf 'client\ndev tun\nproto udp\nremote %s 1194\nnobind\nauth-user-pass\nremote-cert-tls server\n<ca>\n%s\n</ca>\n' "$1" "$(cat "$O/ca.crt")"; }
	j() { python3 -c 'import json,sys; d=dict(a.split("=",1) for a in sys.argv[2:]); d["conf"]=sys.argv[1]; print(json.dumps(d))' "$@"; }
	check "ovpn without login rejected" 422 "$(capi POST /v1/tunnels "$(j "$(ovpn_conf 10.99.0.1)" name=ovpn)")"
	check "ovpn server config rejected" 422 "$(capi POST /v1/tunnels "$(j "$(ovpn_conf 10.99.0.1)"$'\nmode server' name=ovpn username=alice password=s3cret)")"
	# provider style: DNS scripts in the file are switched off, not run
	check "ovpn import (scripts switched off)" 200 "$(capi POST /v1/tunnels "$(j "$(ovpn_conf 10.99.0.1)"$'\nscript-security 2\nup /bin/touch /tmp/ovpn-pwned' name=ovpn username=alice password=s3cret)")"
	check "import reports the removed lines" yes "$(gq 'not used from the OpenVPN file' "$WORK/api.out" && echo yes || echo no)"
	check "removed lines commented out in the stored file" yes "$(gq '^# removed by The Shunt: up' "$WORK/etc/tunnels/ovpn.ovpn" && echo yes || echo no)"
	check "ovpn auth file is 0600" 600 "$(stat -c %a "$WORK/etc/tunnels/ovpn.auth" 2>/dev/null)"
	got=
	for _ in $(seq 40); do got=$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ovpn -- curl -s $URL); [[ $got == 10.88.0.2 ]] && break; sleep 0.5; done
	check "ovpn tunnel carries traffic" 10.88.0.2 "$got"
	check "up script from the file not run" no "$([[ -e /tmp/ovpn-pwned ]] && echo yes || echo no)"
	if [[ -n ${SHUNT_HOLD_OVPN:-} ]]; then echo "holding $WORK"; until [[ -e $SHUNT_HOLD_OVPN ]]; do sleep 1; done; fi
	check "ovpn: pushed DNS used through the tunnel" "ovpn 10.88.0.2" "$(dnsq_via tunnel:ovpn -server 10.99.0.1:53 -type TXT whoami.test)"
	check "ovpn: pushed redirect-gateway ignored" 10.66.0.2 "$(fetch curl -s $URL)"
	check "ovpn: status shows connection" yes "$(shunt status | gq '^ovpn .*up/openvpn .* ago' && echo yes || echo "no: $(shunt status | grep '^ovpn')")"
	check "ovpn tunnel delete" 204 "$(capi DELETE /v1/tunnels/ovpn)"
	sleep 1
	check "no openvpn client left running" no "$(pgrep -f 'openvpn --config' >/dev/null && echo yes || echo no)"
	check "ovpn auth file removed" no "$([[ -e $WORK/etc/tunnels/ovpn.auth ]] && echo yes || echo no)"
	# the other order: OpenVPN inside WireGuard
	check "ovpn import as hop via WireGuard" 200 "$(capi POST /v1/tunnels "$(j "$(ovpn_conf 10.66.0.1)" name=ovhop username=alice password=s3cret via=tunnel:vps)")"
	got=
	for _ in $(seq 40); do got=$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ovhop -- curl -s $URL); [[ $got == 10.88.0.2 ]] && break; sleep 0.5; done
	check "OpenVPN inside WireGuard carries traffic" 10.88.0.2 "$got"
	check "OpenVPN hop arrives through the WireGuard tunnel" yes "$(grep -q '10.66.0.2:[0-9]* .*Peer Connection Initiated' "$WORK/ovpn-server.log" && echo yes || echo no)"
	kill "$OVPN_SRV_PID"; wait "$OVPN_SRV_PID" 2>/dev/null; OVPN_SRV_PID=
	sleep 1
	check "ovpn server gone: blocked, no leak" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ovhop -- curl -s $URL)"
	check "ovpn server gone: DNS fails closed" yes "$(failed_closed "$(dnsq_via tunnel:ovhop -server 10.99.0.1:53 -type TXT whoami.test)")"
	check "ovpn hop delete" 204 "$(capi DELETE /v1/tunnels/ovhop)"
else
	echo "  skip OpenVPN checks (openvpn not installed)"
fi

echo "== network profiles"
GWMAC=$(ip -n $WAN link show wan0 | awk '/ether/{print $2}')
fetch curl -s $URL >/dev/null # make sure the gateway is in the neighbour table
EXTRA_TUNNELS=$'[[network]]\nname = "home"\ngateway_mac = ["'$GWMAC$'"]\ndefault_route = "direct"\n'
write_config tunnel:vps
shunt reload
for _ in $(seq 30); do shunt status | gq 'network profile "home"' && break; sleep 0.5; done
check "known gateway: profile default route" yes "$(shunt status | gq '^default route: *direct (network profile "home")' && echo yes || echo "no: $(shunt status | head -3)")"
check "known gateway: default traffic direct" 10.99.0.2 "$(fetch curl -s $URL)"
cli ip neigh replace 10.99.0.1 lladdr 02:00:00:00:00:01 dev cli0 nud permanent
for _ in $(seq 30); do shunt status | gq 'network profile' || break; sleep 0.5; done
check "other gateway: back to daemon default" yes "$(shunt status | gq '^default route: *tunnel:vps$' && echo yes || echo "no: $(shunt status | head -3)")"
cli ip neigh del 10.99.0.1 dev cli0
fetch curl -s $URL >/dev/null
for _ in $(seq 30); do shunt status | gq 'network profile "home"' && break; sleep 0.5; done
check "known gateway again: profile back" yes "$(shunt status | gq 'network profile "home"' && echo yes || echo no)"
EXTRA_TUNNELS=
write_config tunnel:vps
shunt reload

echo "== sticky routes (desktop / browser moves the process into its own scope)"
OUT=shunt-it-outside/app-cosmic-test-1.scope
mkdir -p "$CGMNT/$OUT"
check "process moved out by the desktop is put back" 10.66.0.2 "$(fetch_long "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- sh -c 'echo $$ > /sys/fs/cgroup/'"$OUT"'/cgroup.procs; sleep 0.5; exec curl -s '"$URL")"
check "children started after the move follow" 10.66.0.2 "$(fetch_long "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- sh -c 'echo $$ > /sys/fs/cgroup/'"$OUT"'/cgroup.procs; sh -c "sleep 0.5; curl -s '"$URL"'"; true')"
rmdir "$CGMNT/$OUT" "$CGMNT/shunt-it-outside" 2>/dev/null || true

echo "== rule priority: block and explicit routes"
EXTRA_TUNNELS=$'[[rule]]\nname = "lan direct"\ncidr = ["10.99.0.1"]\nport = ["tcp/8080"]\nroute = "direct"\n'
write_config tunnel:vps
shunt reload
check "rule applies to normal traffic" 10.99.0.2 "$(fetch curl -s $URL)"
check "block beats a CIDR rule" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via block -- curl -s $URL)"
check "app started in a tunnel keeps it" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
EXTRA_TUNNELS+=$'override_explicit = true\n'
write_config tunnel:vps
shunt reload
check "override_explicit: rule also for started apps" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
check "override_explicit: block still wins" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via block -- curl -s $URL)"

echo "== rules per network profile"
GWMAC=$(ip -n $WAN link show wan0 | awk '/ether/{print $2}')
fetch curl -s $URL >/dev/null
EXTRA_TUNNELS=$'[[network]]\nname = "home"\ngateway_mac = ["'$GWMAC$'"]\ndefault_route = "tunnel:vps"\n[[rule]]\nname = "home lan blocked"\ncidr = ["10.99.0.1"]\nport = ["tcp/8080"]\nroute = "block"\nnetwork = ["home"]\n'
write_config tunnel:vps
shunt reload
for _ in $(seq 30); do shunt status | gq 'network profile "home"' && break; sleep 0.5; done
check "rule active on its network" "" "$(fetch curl -s $URL)"
cli ip neigh replace 10.99.0.1 lladdr 02:00:00:00:00:03 dev cli0 nud permanent
for _ in $(seq 30); do shunt status | gq 'network profile' || break; sleep 0.5; done
cli ip neigh del 10.99.0.1 dev cli0
check "rule inactive on another network" 10.66.0.2 "$(fetch_long sh -c 'for i in 1 2 3 4 5; do r=$(curl -s --max-time 3 '"$URL"'); [ -n "$r" ] && echo "$r" && exit; sleep 1; done')"
EXTRA_TUNNELS=
write_config tunnel:vps
shunt reload

echo "== sticky routes survive a daemon restart"
OUT=shunt-it-outside/app-cosmic-test-2.scope
mkdir -p "$CGMNT/$OUT"
cli "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- sh -c 'sleep 6; echo $$ > /sys/fs/cgroup/'"$OUT"'/cgroup.procs; sleep 0.5; curl -s --max-time 5 '"$URL" >"$WORK/sticky.out" 2>/dev/null &
STICKY=$!
sleep 1
kill "$SHUNTD_PID"; wait "$SHUNTD_PID" 2>/dev/null || true
start_shuntd
for _ in $(seq 50); do shunt status | gq 'up/' && break; sleep 0.1; done
wait $STICKY || true
check "process placed before the restart is kept in its route" 10.66.0.2 "$(cat "$WORK/sticky.out")"
rmdir "$CGMNT/$OUT" "$CGMNT/shunt-it-outside" 2>/dev/null || true

echo "== app firewall (ask)"
SCOPE=user.slice/user-4242.slice/user@4242.service/app.slice/app-shunttest-1.scope
SYSSVC=system.slice/shunttest-fw.service
mkdir -p "$CGMNT/$SCOPE" "$CGMNT/$SYSSVC"
cp "$(command -v curl)" "$BIN/fwcurl"
cp "$(command -v curl)" "$BIN/fwcurl2"
# like a desktop launcher: a wrapper script in the session that execs the program
fwrun() { # cgroup program url
	# setsid: no controlling terminal (programs started from a terminal are not held)
	fetch_long setsid -w sh -c 'echo $$ > /sys/fs/cgroup/'"$1"'/cgroup.procs; sleep 1; exec setpriv --reuid=65534 --regid=65534 --clear-groups '"$2"' -s --retry 25 --retry-connrefused --retry-delay 1 --max-time 30 '"$3"
}
EXTRA_TUNNELS=$'[firewall]\nmode = "ask"\ntimeout = 4\n'
write_config direct
shunt reload
fwrun "$SCOPE" "$BIN/fwcurl" $URL >"$WORK/fw1.out" &
FW1=$!
got=
for _ in $(seq 40); do got=$(shunt pending | awk '/fwcurl/{print $1}'); [[ -n $got ]] && break; sleep 0.5; done
check "unknown program held and asked (not its wrapper)" yes "$([[ -n $got ]] && ! shunt pending | gq '^p[0-9]* *dash ' && echo yes || echo "no: $(shunt pending)")"
if [[ -z $got ]]; then
	echo "--- debug: ask_out"; cli nft list chain inet shunt ask_out || true
	echo "--- debug: cgroups"; find "$CGMNT/$CG/apps" -name cgroup.procs -path '*ask*' -exec sh -c 'echo "$1: $(cat "$1")"' _ {} \; || true
	echo "--- debug: scope"; cat "$CGMNT/$SCOPE/cgroup.procs" || true
	echo "--- debug: log"; grep -i 'firewall\|ask' "$WORK/shuntd.log" | tail -30 || true
	echo "--- debug: pending"; shunt pending || true
	echo "--- debug: fw processes"; ps -eo pid,args | grep -E 'fwcurl|sleep 1' | grep -v grep || true
fi
check "nothing went out while waiting" "" "$(cat "$WORK/fw1.out")"
shunt allow fwcurl --via tunnel:vps >/dev/null || true
wait $FW1
check "allowed via tunnel" 10.66.0.2 "$(cat "$WORK/fw1.out")"
check "decision remembered" yes "$(shunt firewall apps | gq 'fwcurl *tunnel:vps' && echo yes || echo no)"
check "next start goes straight through the tunnel" 10.66.0.2 "$(fwrun "$SCOPE" "$BIN/fwcurl" $URL)"
check "no answer: default route after the timeout" 10.99.0.2 "$(fwrun "$SCOPE" "$BIN/fwcurl2" $URL)"
check "system services are never held" 10.99.0.2 "$(fwrun "$SYSSVC" "$BIN/fwcurl2" $URL)"
# a program that execs at once (no pause after joining the scope) and several
# at the same time: exec events can get lost, none may slip out unasked
cp "$(command -v curl)" "$BIN/fwcurl3"
fwfast() { # program url: joins the scope and execs without any pause
	fetch_long setsid -w sh -c 'echo $$ > /sys/fs/cgroup/'"$SCOPE"'/cgroup.procs; exec setpriv --reuid=65534 --regid=65534 --clear-groups '"$1"' -s --max-time 35 '"$2"
}
FASTPIDS=()
for i in 1 2 3 4 5 6; do
	fwfast "$BIN/fwcurl3" $URL >"$WORK/fast$i.out" &
	FASTPIDS+=($!)
done
got=
for _ in $(seq 40); do got=$(shunt pending | awk '/fwcurl3/{print $1}'); [[ -n $got ]] && break; sleep 0.5; done
sleep 2
check "fast starts: held, nothing out while asked" "" "$(cat "$WORK"/fast?.out)"
shunt allow fwcurl3 --via tunnel:vps >/dev/null || true
wait "${FASTPIDS[@]}" || true
check "fast starts: all six went through the tunnel after the decision" 6 "$(cat "$WORK"/fast?.out | grep -c '^10.66.0.2$')"
# started from the system-service cgroup: a caller without a terminal (CI
# runner, ssh without -t) is held by the app firewall itself otherwise
insvc() { cli sh -c 'echo $$ > /sys/fs/cgroup/'"$SYSSVC"'/cgroup.procs; exec "$@"' _ "$@"; }
check "pending decision from inside a route refused" denied "$(insvc "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s --unix-socket "$SOCK" -X POST -o /dev/null -w '%{http_code}' --data '{"route":"direct"}' http://shuntd/v1/pending/p99 | sed 's/403/denied/')"
# a held program (waiting group) asks the daemon to start it direct
mkdir -p "$CGMNT/$CG/apps/ask/pesc"
esc=$(fetch sh -c 'echo $$ > /sys/fs/cgroup/'"$CG"'/apps/ask/pesc/cgroup.procs; exec "$@" 2>&1' _ "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)
check "held program cannot let itself out" yes "$(grep -q 'leaving route block' <<<"$esc" && ! grep -q 10.99.0.2 <<<"$esc" && echo yes || echo "no: $esc")"
rmdir "$CGMNT/$CG/apps/ask/pesc" 2>/dev/null || true
check "forget from inside a route refused" denied "$(insvc "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s --unix-socket "$SOCK" -X DELETE -o /dev/null -w '%{http_code}' "http://shuntd/v1/firewall/apps?key=$BIN/fwcurl" | sed 's/403/denied/')"
shunt firewall forget "$BIN/fwcurl" || true
check "forget removes the decision" no "$(shunt firewall apps | gq fwcurl && echo yes || echo no)"
EXTRA_TUNNELS=
write_config tunnel:vps
shunt reload
rmdir "$CGMNT/$SCOPE" "$CGMNT/$SYSSVC" "$CGMNT/user.slice/user-4242.slice/user@4242.service/app.slice" "$CGMNT/user.slice/user-4242.slice/user@4242.service" "$CGMNT/user.slice/user-4242.slice" 2>/dev/null || true

echo "== allow_lan: tunnel apps reach the local network"
check "without allow_lan the LAN goes through the tunnel" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
VPS_EXTRA='allow_lan = true'
write_config tunnel:vps
shunt reload
check "allow_lan: attached LAN goes direct" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"
check "allow_lan: the rest still through the tunnel" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s http://10.66.0.1:8080)"
check "allow_lan: LAN route in the tunnel table" yes "$(cli ip route show table 5301 | gq '10.99.0.0/24 dev cli0' && echo yes || echo "no: $(cli ip route show table 5301)")"
VPS_EXTRA=
write_config tunnel:vps
shunt reload
check "allow_lan off again: LAN through the tunnel" 10.66.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:vps -- curl -s $URL)"

echo "== Wi-Fi login page (captive portal)"
check "no portal: online" yes "$(shunt status --json | gq '"captive": "online"' && echo yes || echo "no: $(shunt status --json | grep captive)")"
echo portal >"$WORK/portal.mode"
# network change: the gateway briefly unreachable (like while associating),
# then reachable with the portal in front
cli ip neigh replace 10.99.0.1 lladdr 02:00:00:00:00:02 dev cli0 nud permanent
for _ in $(seq 40); do shunt status --json | gq '"captive": "online"' || break; sleep 0.5; done
cli ip neigh del 10.99.0.1 dev cli0
fetch curl -s $URL >/dev/null
for _ in $(seq 60); do shunt status --json | gq '"captive": "portal"' && break; sleep 0.5; done
check "portal detected after network change" yes "$(shunt status --json | gq '"captive_url": "http://login.portal.test/welcome"' && echo yes || echo "no: $(shunt status --json | grep captive)")"
check "status tells what to do" yes "$(shunt status | gq 'Wi-Fi login page in the way' && echo yes || echo no)"
check "login browser goes direct without password" 10.99.0.2 "$(fetch "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --group captive -- curl -s $URL)"
check "login browser asks the network's DNS" "direct 10.99.0.2" "$(fetch "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" run --group captive -- "$BIN/fakedns" query -server 192.0.2.53:53 -type TXT whoami.test)"
echo online >"$WORK/portal.mode"
for _ in $(seq 60); do shunt status --json | gq '"captive": "online"' && break; sleep 0.5; done
check "login done noticed without network change" yes "$(shunt status --json | gq '"captive": "online"' && echo yes || echo no)"
esc=$(fetch "${MEMBER[@]}" sh -c "'$BIN/shunt' -s '$SOCK' run --group captive -- curl -s $URL 2>&1")
check "no login page: login browser needs the password" yes "$(grep -q 'leaving route tunnel:vps' <<<"$esc" && ! grep -q 10.99.0.2 <<<"$esc" && echo yes || echo "no: $esc")"

echo "== editor conflicts, DNS health, restart"
capi GET /v1/config >/dev/null
ver=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$WORK/api.out")
echo "# changed by hand" >>"$WORK/etc/shunt.toml"
stale=$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(json.dumps({"config": v["config"], "version": v["version"]}))' "$WORK/api.out")
check "save based on an old version refused" 409 "$(capi PUT /v1/config "$stale")"
check "hand edit kept" yes "$(grep -q 'changed by hand' "$WORK/etc/shunt.toml" && echo yes || echo no)"
EXTRA_TUNNELS=$'[dns.upstream.bad]\naddr = "192.0.2.1"\n'
VPS_EXTRA='dns = "bad"'
write_config tunnel:vps
shunt reload
for _ in $(seq 8); do dnsq_via tunnel:vps -server 10.99.0.1:53 -type TXT whoami.test >/dev/null; sleep 2.5; done
check "unreachable tunnel DNS reported" yes "$(shunt status --json | gq '"tunnel:vps": "udp://192.0.2.1:53' && echo yes || echo "no: $(shunt status --json | grep -A2 dns_failing)")"
check "status warns about it" yes "$(shunt status | gq 'WARNING: *DNS for tunnel:vps fails' && echo yes || echo no)"
EXTRA_TUNNELS=
VPS_EXTRA=
write_config tunnel:vps
shunt reload
dnsq_via tunnel:vps -server 10.99.0.1:53 -type TXT whoami.test >/dev/null
check "DNS recovery clears the report" no "$(shunt status --json | gq dns_failing && echo yes || echo no)"
check "member: restart needs authorization" denied "$(cli "${MEMBER[@]}" "$BIN/shunt" -s "$SOCK" restart >/dev/null 2>&1 && echo allowed || echo denied)"
shunt restart >/dev/null
rc=0; wait "$SHUNTD_PID" || rc=$?; SHUNTD_PID=
check "restart exits with 75 for systemd" 75 "$rc"
check "kill switch kept during restart" "" "$(fetch curl -s $URL)"
start_shuntd
for _ in $(seq 50); do shunt status | gq 'up/' && break; sleep 0.1; done
got=; for _ in $(seq 20); do got=$(fetch curl -s $URL); [[ $got == 10.66.0.2 ]] && break; sleep 0.5; done
check "back after restart" 10.66.0.2 "$got"

echo "== link routes: Wi-Fi and cable at the same time"
# a second uplink, declared Wi-Fi via SHUNT_LINK_KINDS (exported at the top)
ip -n $WAN link add wan1 type veth peer name cli1
ip -n $WAN link set cli1 netns $CLI
ip -n $WAN addr add 10.98.0.1/24 dev wan1
ip -n $CLI addr add 10.98.0.2/24 dev cli1
ip -n $WAN link set wan1 up
ip -n $CLI link set cli1 up
ip -n $CLI route add default via 10.98.0.1 metric 200
got=; for _ in $(seq 30); do got=$(fetch "$BIN/shunt" -s "$SOCK" run --via link:wifi -- curl -s $URL); [[ $got == 10.98.0.2 ]] && break; sleep 0.5; done
check "link:wifi leaves over the Wi-Fi" 10.98.0.2 "$got"
check "link:ethernet leaves over the cable" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via link:ethernet -- curl -s $URL)"
check "default still through the tunnel" 10.66.0.2 "$(fetch curl -s $URL)"
check "link:mobile not connected: blocked" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via link:mobile -- curl -s $URL)"
check "link:wifi resolves over the Wi-Fi" "direct 10.98.0.2" "$(dnsq_via link:wifi -server 10.99.0.1:53 -type TXT whoami.test)"
check "link table has the Wi-Fi gateway" yes "$(cli ip route show table $((5300 + 0xe0)) | gq 'default via 10.98.0.1 dev cli1' && echo yes || echo "no: $(cli ip route show table $((5300 + 0xe0)))")"
ip -n $CLI link set cli1 down
got=x; for _ in $(seq 30); do got=$(fetch "$BIN/shunt" -s "$SOCK" run --via link:wifi -- curl -s $URL); [[ -z $got ]] && break; sleep 0.5; done
check "Wi-Fi gone: blocked, not over the cable" "" "$got"
ip -n $CLI link set cli1 up
ip -n $CLI route add default via 10.98.0.1 metric 200 2>/dev/null || true
got=; for _ in $(seq 30); do got=$(fetch "$BIN/shunt" -s "$SOCK" run --via link:wifi -- curl -s $URL); [[ $got == 10.98.0.2 ]] && break; sleep 0.5; done
check "Wi-Fi back: followed" 10.98.0.2 "$got"
ip -n $CLI link del cli1

echo "== panic"
shunt panic on
check "panic blocks everything" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)"
shunt panic off
check "panic off restores" 10.66.0.2 "$(fetch curl -s $URL)"

echo "== daemon stopped: tunnels fail closed, direct goes on"
kill "$SHUNTD_PID"; wait "$SHUNTD_PID" 2>/dev/null || true; SHUNTD_PID=
check "tunnel group blocked while daemon is down" "" "$(fetch sh -c "echo \$\$ > /sys/fs/cgroup/$CG/apps/via/tunnel-vps/cgroup.procs; curl -s $URL")"
check "default (tunnel) blocked while daemon is down" "" "$(fetch curl -s $URL)"
check "DNS fails closed while daemon is down" yes "$(failed_closed "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)")"
check "tunnel group DNS fails closed while daemon is down" yes "$(failed_closed "$(fetch sh -c "echo \$\$ > /sys/fs/cgroup/$CG/apps/via/tunnel-vps/cgroup.procs; exec $BIN/fakedns query -server 10.99.0.1:53 -type TXT whoami.test")")"
check "direct group still resolves while daemon is down" "direct 10.99.0.2" "$(fetch sh -c "echo \$\$ > /sys/fs/cgroup/$CG/apps/via/direct/cgroup.procs; exec $BIN/fakedns query -server 10.99.0.1:53 -type TXT whoami.test")"
check "direct group still connects while daemon is down" 10.99.0.2 "$(fetch sh -c "echo \$\$ > /sys/fs/cgroup/$CG/apps/via/direct/cgroup.procs; curl -s $URL")"
cli "$BIN/shuntd" cleanup
check "cleanup restores direct" 10.99.0.2 "$(fetch curl -s $URL)"
check "cleanup removes nft table" no "$(cli nft list tables | gq shunt && echo yes || echo no)"

echo
echo "passed: $PASS  failed: $FAIL"
if ((FAIL)); then
	echo "--- shuntd log"; cat "$WORK/shuntd.log"
	exit 1
fi
