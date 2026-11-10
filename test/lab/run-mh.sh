#!/usr/bin/env bash
# Multi-hop series (MH01-MH08). One client VM per call, env file first (e.g. popos.env, sets CLIENT_VM,
# TUNNEL_IP and HOP_CONF = wg-hop-<vm>.conf). The hop address on wgt1 (HOPIP) is read from the Address line
# of that file. Instead of HOP_CONF, HOP_VM=<name> picks $HOP_DIR/wg-hop-lab-<name>.conf (HOP_DIR as in run-test.sh).
# Without any of them: 10.69.0.<last octet of TUNNEL_IP>.
#   MH01 MH02 MH08   WireGuard in WireGuard, capture on wgt1
#   MH03             hop never comes up, capture on wgt0 (nothing may fall back to hop A)
#   MH04             OpenVPN in WireGuard, capture on tun0
#   MH05             WireGuard in OpenVPN, capture on wgt0
#   MH06/MH07        E01 E02 E05 (hostile network) and D06 (MTU) with CONFIG_FORCE=hop
set -u
cd "$(dirname "$0")"
[[ ${1:-} == --list ]] && { sed -n '2,11p' "$0"; exit 0; }
HOP_DIR=${HOP_DIR:-${LAB_VPN_DIR:-$PWD/vpn}}
[[ -z ${HOP_CONF:-} && -n ${HOP_VM:-} ]] && export HOP_CONF=$HOP_DIR/wg-hop-lab-$HOP_VM.conf
if [[ -z ${HOPIP:-} && -r ${HOP_CONF:-/nonexistent} ]]; then
	HOPIP=$(sed -n 's|^Address *= *\([0-9.]*\)/.*|\1|p' "$HOP_CONF" | head -n1)
fi
HOPIP=${HOPIP:-10.69.0.${TUNNEL_IP##*.}}
CT130_IF=wgt1 TUNNEL_IP=$HOPIP ./lab.sh run MH01 MH02 MH08
CT130_IF=wgt0 ./lab.sh run MH03
CT130_IF=tun0 TUNNEL_IP=${OVPN_IP:-10.67.0.3} ./lab.sh run MH04
CT130_IF=wgt0 ./lab.sh run MH05
CONFIG_FORCE=hop CT130_IF=wgt1 TUNNEL_IP=$HOPIP ./lab.sh run E01 E02 E05 D06
