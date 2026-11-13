# Addresses of the lab (sourced by lab.sh, run-test.sh, run-mh.sh). Neutral defaults only
# (see NEUTRAL-ADDRESSES.md); your own values go into lab-addr.local.sh (ignored by git).
LAB_EXIT_IP=${LAB_EXIT_IP:-198.51.100.230}        # address the tunnel exit shows to the internet
LAB_NET_WG=${LAB_NET_WG:-10.166.0.}               # WireGuard net of the exit (prefix ends in ".")
LAB_NET_OVPN=${LAB_NET_OVPN:-10.167.0.}           # OpenVPN (UDP) net
LAB_NET_OVPN_TCP=${LAB_NET_OVPN_TCP:-10.168.0.}   # OpenVPN (TCP 443) net
LAB_NET_HOP=${LAB_NET_HOP:-10.169.0.}             # inner hop net
LAB_NET_LAN=${LAB_NET_LAN:-192.168.250.}          # lab LAN (gateway side)
_LAB_ADDR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
[[ -f $_LAB_ADDR_DIR/lab-addr.local.sh ]] && source "$_LAB_ADDR_DIR/lab-addr.local.sh"
# derived addresses (after the local file, so a changed net carries over)
LAB_WG_SRV=${LAB_WG_SRV:-${LAB_NET_WG}1}          # server address inside the WireGuard net
LAB_OVPN_SRV=${LAB_OVPN_SRV:-${LAB_NET_OVPN}1}
LAB_HOP_SRV=${LAB_HOP_SRV:-${LAB_NET_HOP}1}
LAB_TUNNEL_IP=${LAB_TUNNEL_IP:-${LAB_NET_WG}12}   # client address, Linux VM
LAB_TUNNEL_IP_WIN=${LAB_TUNNEL_IP_WIN:-${LAB_NET_WG}15} # client address, Windows VM
export LAB_EXIT_IP LAB_NET_WG LAB_NET_OVPN LAB_NET_OVPN_TCP LAB_NET_HOP LAB_WG_SRV LAB_OVPN_SRV LAB_HOP_SRV LAB_TUNNEL_IP LAB_TUNNEL_IP_WIN LAB_NET_LAN
# lab_subst <text>: replaces @LAB_...@ placeholders (used in test files, whose CLIENT/PREP bodies are single-quoted)
lab_subst() {
	local s=$1 v
	for v in LAB_EXIT_IP LAB_NET_WG LAB_NET_OVPN LAB_NET_OVPN_TCP LAB_NET_HOP LAB_WG_SRV LAB_OVPN_SRV LAB_HOP_SRV LAB_TUNNEL_IP LAB_TUNNEL_IP_WIN LAB_NET_LAN; do
		s=${s//@$v@/${!v}}
	done
	printf '%s' "$s"
}
