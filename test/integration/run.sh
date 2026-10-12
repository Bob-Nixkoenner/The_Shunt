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
	ip netns del $CLI 2>/dev/null
	rm -rf "/etc/netns/$CLI"
	groupdel shunttest 2>/dev/null
	ip netns del $WAN 2>/dev/null
	find "$CGMNT/$CG" -depth -type d -exec rmdir {} + 2>/dev/null
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

[tunnel.vps]
config = "vps.conf"
driver = "${SHUNT_DRIVER:-auto}"

[[rule]]
name = "site.test through the tunnel"
domain = ["site.test"]
route = "tunnel:vps"

[group.torrent]

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

# --- helpers ----------------------------------------------------------------
# `ip netns exec` remounts /sys, so mount cgroup2 again for everything that
# needs it (shuntd, nft resolving cgroup paths, tests joining cgroups)
cli() { ip netns exec $CLI unshare -m sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' _ "$@"; }
shunt() { cli "$BIN/shunt" -s "$SOCK" "$@"; }
fetch() { cli timeout 5 "$@" 2>/dev/null || true; }
fetch_long() { cli env SHUNT_PROBE_IP_URL="${SHUNT_PROBE_IP_URL:-}" timeout 40 "$@" 2>/dev/null || true; }

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
for _ in $(seq 50); do shunt status | grep -q 'up/' && break; sleep 0.1; done
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
check "status shows app group" yes "$(shunt status | grep -q '^app:apptest auto-detected' && echo yes || echo no)"

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
check "domain rule resolves via its tunnel" "tunnel 10.66.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT site.test)"
check "domain target direct before lookup" 10.99.0.2 "$(fetch curl -s $URL_SITE)"
check "domain rule A answer" 10.99.0.3 "$(dnsq -server 10.99.0.1:53 site.test)"
check "domain target tunnelled after lookup" 10.66.0.2 "$(fetch curl -s $URL_SITE)"
check "blocking answer (0.0.0.0) passed to the app" 0.0.0.0 "$(dnsq -server 10.99.0.1:53 blocked.site.test)"
check "blocking answer kept out of routing sets" 0 "$(cli nft list table inet shunt | grep -c '0\.0\.0\.0')"
check "Firefox DoH canary NXDOMAIN" NXDOMAIN "$(dnsq -server 10.99.0.1:53 use-application-dns.net)"
check "public DoH host NXDOMAIN" NXDOMAIN "$(dnsq -server 10.99.0.1:53 dns.google)"
check "DoT port 853 blocked" "" "$(fetch curl -s http://10.99.0.1:853)"
check "status shows DNS upstreams" yes "$(shunt status | grep -q 'tunnel:vps .*udp://10.66.0.1:53' && echo yes || echo no)"
echo "== leak test"
lt=$(SHUNT_PROBE_IP_URL=$URL fetch_long "$BIN/shunt" -s "$SOCK" leaktest)
check "leaktest: direct ok" yes "$(grep -qE '^direct +10.99.0.2 +10.99.0.2 +OK' <<<"$lt" && echo yes || echo "no: $lt")"
check "leaktest: tunnel ok" yes "$(grep -qE '^tunnel:vps +10.66.0.2 +10.66.0.2 +OK' <<<"$lt" && echo yes || echo "no: $lt")"
check "leaktest: block blocked" yes "$(grep -qE '^block +- +- +BLOCKED' <<<"$lt" && echo yes || echo "no: $lt")"
check "status lists tunnel" yes "$(shunt status | grep -q '^vps .*up/' && echo yes || echo no)"
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
for _ in $(seq 50); do shunt status | grep -q 'up/' && break; sleep 0.1; done
check "default traffic via tunnel" 10.66.0.2 "$(fetch curl -s $URL)"
check "--via direct escapes default" 10.99.0.2 "$(fetch "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)"
hs=no
for _ in $(seq 25); do shunt status | grep -q ' ago ' && hs=yes && break; sleep 0.2; done
check "handshake shown in status (bypass mark)" yes "$hs"
check "default DNS via tunnel" "tunnel 10.66.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)"
((HAVE_V6)) && check "IPv6 default blocked (tunnel v4-only)" "" "$(fetch curl -s -6 "$URL6")"

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
check "imported tunnel in status" yes "$(shunt status | grep -q '^vps2 ' && echo yes || echo no)"
check "bad tunnel name rejected" 422 "$(capi POST /v1/tunnels '{"name":"../x","conf":"[Interface]"}')"
check "tunnel delete" 204 "$(capi DELETE /v1/tunnels/vps2)"
check "deleted tunnel file gone" no "$([[ -e $WORK/etc/tunnels/vps2.conf ]] && echo yes || echo no)"
check "tunnel in use cannot be deleted" 422 "$(capi DELETE /v1/tunnels/vps)"

echo "== system resolver changes are picked up without restart"
# `ip netns exec` bind-mounts this file over /etc/resolv.conf; rewrite it in
# place (same inode) the way NetworkManager would change the content.
write_config direct system
printf 'nameserver 192.0.2.1\n' >"$NETNS_RESOLV"
shunt reload
check "unreachable system resolver fails closed" yes "$(failed_closed "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)")"
printf 'nameserver 10.99.0.1\n' >"$NETNS_RESOLV"
check "new system resolver used without restart" "direct 10.99.0.2" "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)"
check "status shows system resolver" yes "$(shunt status | grep -q 'system (udp://10.99.0.1:53)' && echo yes || echo no)"
write_config tunnel:vps
shunt reload

echo "== panic"
shunt panic on
check "panic blocks everything" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via direct -- curl -s $URL)"
shunt panic off
check "panic off restores" 10.66.0.2 "$(fetch curl -s $URL)"

echo "== daemon stopped: fail closed"
kill "$SHUNTD_PID"; wait "$SHUNTD_PID" 2>/dev/null || true; SHUNTD_PID=
check "tunnel group blocked while daemon is down" "" "$(fetch sh -c "echo \$\$ > /sys/fs/cgroup/$CG/apps/via/tunnel-vps/cgroup.procs; curl -s $URL")"
check "default (tunnel) blocked while daemon is down" "" "$(fetch curl -s $URL)"
check "DNS fails closed while daemon is down" yes "$(failed_closed "$(dnsq -server 10.99.0.1:53 -type TXT whoami.test)")"
cli "$BIN/shuntd" cleanup
check "cleanup restores direct" 10.99.0.2 "$(fetch curl -s $URL)"
check "cleanup removes nft table" no "$(cli nft list tables | grep -q shunt && echo yes || echo no)"

echo
echo "passed: $PASS  failed: $FAIL"
if ((FAIL)); then
	echo "--- shuntd log"; cat "$WORK/shuntd.log"
	exit 1
fi
