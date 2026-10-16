#!/usr/bin/env bash
# Tailscale/Headscale tunnel, end to end in network namespaces.
# Needs root, nft, ip, python3 and the binaries headscale, tailscaled and
# tailscale (HEADSCALE, TAILSCALED, TAILSCALE, default: in PATH; the test
# is skipped when one is missing).
#
#   ns shunt-net  192.0.2.2  whoami HTTP server :8080 (prints client IP);
#        |  veth            only reachable through the exit node
#   ns shunt-wan  172.31.0.1  headscale 10.99.0.1:8085
#                 10.99.0.1  tailscaled "exit", exit node, forwards
#        |  veth
#   ns shunt-cli  10.99.0.2  shuntd; tunnel "ts" (tailscaled in its own
#                            namespace behind veth sh-ts) with exit_node
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HEADSCALE=${HEADSCALE:-$(command -v headscale || true)}
TAILSCALED=${TAILSCALED:-$(command -v tailscaled || true)}
TAILSCALE=${TAILSCALE:-$(command -v tailscale || true)}
if [[ -z $HEADSCALE || -z $TAILSCALED || -z $TAILSCALE ]]; then
	echo "skip: headscale, tailscaled and tailscale are needed"
	exit 0
fi
WORK=$(mktemp -d)
chmod 755 "$WORK"
BIN=$WORK/bin
CG=shunt-ts
SOCK=$WORK/shuntd.sock
WAN=shunt-wan
NET=shunt-net
CLI=shunt-cli
PASS=0
FAIL=0

cleanup() {
	set +e
	[[ -n ${SHUNTD_PID:-} ]] && kill "$SHUNTD_PID" 2>/dev/null && wait "$SHUNTD_PID" 2>/dev/null
	pkill -f "^$BIN/" 2>/dev/null
	for p in ${WAN_PIDS:-}; do kill "$p" 2>/dev/null; done
	ip netns del $CLI 2>/dev/null
	ip netns del $WAN 2>/dev/null
	ip netns del $NET 2>/dev/null
	groupdel shunttest 2>/dev/null
	find "$CGMNT/$CG" -depth -type d -exec rmdir {} + 2>/dev/null
	rm -rf /var/lib/shunt/ts-ts
	[[ -n ${KEEP_LOGS:-} ]] && cp "$WORK"/*.log "$KEEP_LOGS"/ 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

CGMNT=/sys/fs/cgroup
[[ $(stat -fc %T $CGMNT) == cgroup2fs ]] || CGMNT=/sys/fs/cgroup/unified

echo "== build"
mkdir -p "$BIN"
(cd "$ROOT" && go build -o "$BIN/" ./cmd/shuntd ./cmd/shunt)
groupadd -f shunttest

echo "== topology"
ip netns del $WAN 2>/dev/null || true
ip netns del $CLI 2>/dev/null || true
ip netns del $NET 2>/dev/null || true
ip netns add $NET
ip netns add $WAN
ip netns add $CLI
ip -n $WAN link add wan0 type veth peer name cli0
ip -n $WAN link set cli0 netns $CLI
ip -n $WAN addr add 10.99.0.1/24 dev wan0
ip -n $CLI addr add 10.99.0.2/24 dev cli0
ip -n $WAN link add net0 type veth peer name tgt0
ip -n $WAN link set tgt0 netns $NET
ip -n $WAN addr add 172.31.0.1/24 dev net0
ip -n $NET addr add 172.31.0.2/24 dev tgt0
# the target sits behind the exit node, not on its link: exit nodes do not
# forward into their own directly connected networks
ip -n $NET addr add 192.0.2.2/32 dev lo
ip -n $WAN link set net0 up
# tailscaled's own sockets bind to the default interface: there must be one
ip -n $WAN route add default via 172.31.0.2
ip -n $NET link set tgt0 up
for ns in $WAN $CLI $NET; do ip -n $ns link set lo up; done
ip -n $WAN link set wan0 up
ip -n $CLI link set cli0 up
ip -n $CLI route add default via 10.99.0.1
WAN_PIDS=""
wan() { ip netns exec $WAN "$@"; }

ip netns exec $NET python3 "$ROOT/test/integration/whoami.py" 8080 >/dev/null 2>&1 &
WAN_PIDS="$!"

echo "== headscale and the exit node"
cat >"$WORK/headscale.yaml" <<EOF
server_url: http://10.99.0.1:8085
listen_addr: 10.99.0.1:8085
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: $WORK/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: true
    region_id: 999
    region_code: test
    region_name: test
    private_key_path: $WORK/derp.key
    stun_listen_addr: 10.99.0.1:3478
    ipv4: 10.99.0.1
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: $WORK/db.sqlite
dns:
  magic_dns: false
  base_domain: shunt.test
  nameservers:
    global:
      - 10.99.0.1
unix_socket: $WORK/hs.sock
log:
  level: warn
EOF
HS=("$HEADSCALE" -c "$WORK/headscale.yaml")
wan "${HS[@]}" serve >"$WORK/headscale.log" 2>&1 &
WAN_PIDS="$WAN_PIDS $!"
for _ in $(seq 100); do [[ -S $WORK/hs.sock ]] && break; sleep 0.1; done
"${HS[@]}" users create shunt >/dev/null
KEY=$("${HS[@]}" preauthkeys create --user 1 --reusable --expiration 1h 2>/dev/null | tail -1)
[[ -n $KEY ]] || { echo "no auth key"; exit 1; }

wan sysctl -qw net.ipv4.ip_forward=1
# the target answers tailnet addresses through the exit node's namespace
ip -n $NET route add 100.64.0.0/10 via 172.31.0.1
wan "$TAILSCALED" --tun=tsx --state="$WORK/exit.state" --socket="$WORK/exit.sock" --no-logs-no-support >"$WORK/exit.log" 2>&1 &
WAN_PIDS="$WAN_PIDS $!"
for _ in $(seq 100); do [[ -S $WORK/exit.sock ]] && break; sleep 0.1; done
wan "$TAILSCALE" --socket="$WORK/exit.sock" up --login-server=http://10.99.0.1:8085 --auth-key="$KEY" --hostname=exit --advertise-exit-node --timeout=30s >"$WORK/exit-up.log" 2>&1 || { cat "$WORK/exit-up.log"; exit 1; }
"${HS[@]}" nodes approve-routes -i 1 -r 0.0.0.0/0,::/0 >/dev/null

mkdir -p "$WORK/etc"
cat >"$WORK/etc/ts.ts" <<EOF
login_server = http://10.99.0.1:8085
auth_key = $KEY
hostname = shunt-client
exit_node = 100.64.0.1
EOF
chmod 600 "$WORK/etc/ts.ts"
cat >"$WORK/etc/shunt.toml" <<EOF
[daemon]
socket = "$SOCK"
socket_group = "shunttest"
cgroup_root = "$CG"
default_route = "direct"

[dns]
disabled = true

[tunnel.ts]
config = "ts.ts"
driver = "tailscale"
EOF

export SHUNT_LINK_KINDS=cli0=ethernet
cli() { ip netns exec $CLI unshare -m sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' _ "$@"; }
shunt() { cli "$BIN/shunt" -s "$SOCK" "$@"; }
fetch() { cli timeout 8 "$@" 2>/dev/null || true; }
fetchq() { cli timeout 3 "$@" 2>/dev/null || true; }
# the exit node may or may not NAT what it forwards (depends on the
# iptables flavour): both addresses mean "came through the exit node"
viaip() { cli timeout "${T:-8}" "$BIN/shunt" -s "$SOCK" run --via tunnel:ts -- curl -s -m "${T:-8}" "$@" 2>/dev/null | sed 's/^172\.31\.0\.1$/100.64.0.2/' || true; }
gq() { grep "$@" >/dev/null; }
check() {
	if [[ "$3" == "$2" ]]; then echo "  ok   $1"; PASS=$((PASS + 1)); else echo "  FAIL $1: expected '$2', got '$3'"; FAIL=$((FAIL + 1)); fi
}
URL=http://192.0.2.2:8080

echo "== daemon with a tailscale tunnel"
mkdir -p "$CGMNT/$CG"
cli "$BIN/shuntd" -c "$WORK/etc/shunt.toml" check >/dev/null || { echo "config check failed"; exit 1; }
# the tunnel needs CAP_SYS_ADMIN (namespace) and CAP_NET_RAW (tailscaled)
ip netns exec $CLI unshare -m sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' _ \
	setpriv --bounding-set=-all,+net_admin,+chown,+sys_admin,+net_raw --inh-caps=-all \
	"$BIN/shuntd" -c "$WORK/etc/shunt.toml" run 2>"$WORK/shuntd.log" &
SHUNTD_PID=$!
for _ in $(seq 50); do [[ -S $SOCK ]] && break; sleep 0.1; done
for _ in $(seq 150); do shunt status | gq 'ts .*up/tailscale  *[0-9]' && break; sleep 0.2; done
shunt status | head -8
# debugging aid: SHUNT_HOLD=/path/to/file keeps the setup alive until the file exists
if [[ -n ${SHUNT_HOLD:-} ]]; then
	echo "holding, work dir $WORK; touch $SHUNT_HOLD to continue"
	until [[ -e $SHUNT_HOLD ]]; do sleep 1; done
fi

check "tunnel reports connected" yes "$(shunt status | gq 'ts .*up/tailscale  *[0-9]' && echo yes || echo no)"
check "the target is not reachable directly" "" "$(fetch curl -s -m 3 $URL)"
# the direct path to the exit node needs a moment (no DERP relay here)
for _ in $(seq 20); do [[ $(T=2 viaip $URL) == 100.64.0.2 ]] && break; sleep 0.5; done
via=$(viaip $URL)
check "--via tunnel:ts leaves through the exit node (target sees the tailnet address)" 100.64.0.2 "$via"
check "tailscaled's rules stay in its namespace" no "$(ip -n $CLI rule | gq 'lookup 52' && echo yes || echo no)"
check "no global ip_forward" 0 "$(ip netns exec $CLI cat /proc/sys/net/ipv4/ip_forward)"
PEER=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1])+1)" "$(ip -n $CLI -4 -o addr show sh-ts | awk '{print $4}' | cut -d/ -f1)")
ip -n $WAN route add 198.18.0.0/15 via 10.99.0.2
# a refused connection (7) would mean the host forwarded the SYN into the namespace
check "the host is no router: a new connection from the uplink is dropped" 28 "$(ip netns exec $WAN curl -s -m 3 -o /dev/null -w '%{exitcode}' http://$PEER:8080/ 2>/dev/null || true)"
check "IPv6 into the tunnel is blocked" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ts -- curl -s -6 'http://[fd98::2]:8080')"

echo "== failing closed"
TSPID=$(cat "$WORK/tailscaled-ts.pid")
kill -STOP "$TSPID"
check "tunnel app gets nothing while tailscaled hangs" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ts -- curl -s -m 4 $URL)"
kill -CONT "$TSPID"
shunt panic on
check "panic: tunnel app blocked" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ts -- curl -s -m 4 $URL)"
shunt panic off
for _ in $(seq 20); do [[ $(T=2 viaip $URL) == 100.64.0.2 ]] && break; sleep 0.5; done
check "works again after panic off" 100.64.0.2 "$(viaip $URL)"
kill -KILL "$TSPID"
check "tunnel app gets nothing while tailscaled is dead" "" "$(fetch "$BIN/shunt" -s "$SOCK" run --via tunnel:ts -- curl -s -m 4 $URL)"
for _ in $(seq 40); do [[ $(T=2 viaip $URL) == 100.64.0.2 ]] && break; sleep 1; done
check "tailscaled is restarted" 100.64.0.2 "$(viaip $URL)"

echo "== shutdown cleans up"
kill "$SHUNTD_PID"; wait "$SHUNTD_PID" 2>/dev/null || true; SHUNTD_PID=""
check "veth gone" no "$(ip -n $CLI link show sh-ts >/dev/null 2>&1 && echo yes || echo no)"
check "no tailscaled left" 0 "$(pgrep -fc "tailscaled --tun=ts0" || true)"

echo
echo "passed: $PASS  failed: $FAIL"
((FAIL == 0)) || { echo "--- shuntd.log"; tail -30 "$WORK/shuntd.log"; exit 1; }
