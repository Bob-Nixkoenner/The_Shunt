#!/usr/bin/env bash
# Multi-hop series (MH01-MH08). One client VM per call, env file first (e.g. popos.env, sets CLIENT_VM,
# TUNNEL_IP and HOP_CONF = wg-hop-<vm>.conf). The hop address on wgt1 is 10.69.0.<same last octet>.
#   MH01 MH02 MH08   WireGuard in WireGuard, capture on wgt1
#   MH03             hop never comes up, capture on wgt0 (nothing may fall back to hop A)
#   MH04             OpenVPN in WireGuard, capture on tun0
#   MH05             WireGuard in OpenVPN, capture on wgt0
#   MH06/MH07        E01 E02 E05 (hostile network) and D06 (MTU) with CONFIG_FORCE=hop
set -u
cd "$(dirname "$0")"
HOPIP=${HOPIP:-10.69.0.${TUNNEL_IP##*.}}
[[ ${1:-} == --list ]] && { sed -n '2,10p' "$0"; exit 0; }
CT130_IF=wgt1 TUNNEL_IP=$HOPIP ./lab.sh run MH01 MH02 MH08
CT130_IF=wgt0 ./lab.sh run MH03
CT130_IF=tun0 TUNNEL_IP=${OVPN_IP:-10.67.0.3} ./lab.sh run MH04
CT130_IF=wgt0 ./lab.sh run MH05
CONFIG_FORCE=hop CT130_IF=wgt1 TUNNEL_IP=$HOPIP ./lab.sh run E01 E02 E05 D06
