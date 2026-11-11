# Shared helpers for the attacker scripts. Runs inside shunt-kali on the lab LAN (shuntlab).
# Every address comes from the environment or from the running system, never from this file.
#   IFACE   lab interface (default: the NIC in the KALI_IP subnet, see lab_iface; else eth0)
#   TARGET  victim address (the Shunt client), required by most scripts
#   GW      gateway address (default: default route of IFACE, else the .1 of IFACE's /24)
# lab.env (written by lab.sh kali-sync) carries KALI_IP, the fixed address on the lab LAN
[[ -f $(dirname "${BASH_SOURCE[0]}")/lab.env ]] && . "$(dirname "${BASH_SOURCE[0]}")/lab.env"
# The lab NIC is the one with an address in KALI_IP's /24, not the one with the default route
# (that is the NAT NIC used for ssh). Without KALI_IP: the first NIC with an IPv4 address and no default route.
lab_iface() {
	local n
	if [[ -n ${KALI_IP:-} ]]; then
		n=$(ip -4 -o addr show 2>/dev/null | awk -v p="${KALI_IP%.*}." 'index($4, p) == 1 {print $2; exit}')
		[[ -n $n ]] && { echo "$n"; return; }
	fi
	for n in $(ls /sys/class/net | grep -v '^lo$'); do
		ip -4 route show default dev "$n" 2>/dev/null | grep -q . && continue
		ip -4 -o addr show dev "$n" 2>/dev/null | grep -q . && { echo "$n"; return; }
	done
	ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}
IFACE=${IFACE:-$(lab_iface)}
IFACE=${IFACE:-eth0}
GW=${GW:-$(ip -4 route show default dev "$IFACE" 2>/dev/null | awk '{print $3; exit}')}
# The lab NIC has no default route by design (see lab_iface), so the line above is usually empty:
# then the gateway is the .1 of the lab NIC's own /24 (how the lab gateway VM is set up).
if [[ -z $GW ]]; then
	_lab_addr=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}')
	[[ -n $_lab_addr ]] && GW=${_lab_addr%.*}.1
	unset _lab_addr
fi
DURATION=${DURATION:-20}
need() { command -v "$1" >/dev/null || { echo "missing tool: $1 (apt install it in shunt-kali)" >&2; exit 2; }; }
need_target() { [[ -n ${TARGET:-} ]] || { echo "set TARGET=<victim address>" >&2; exit 2; }; }

# pick HOST PORT...: prints the first port that actually accepts a TCP connect
# (short timeout, real connect test, not just "probably open"). Prints nothing
# and returns 1 when none of the candidates answer - callers must check the
# exit code instead of assuming the first candidate.
pick() {
	local host=$1; shift
	local p
	for p in "$@"; do
		if command -v nc >/dev/null; then
			if nc -z -w2 "$host" "$p" 2>/dev/null; then echo "$p"; return 0; fi
		else
			if timeout 2 bash -c "exec 3<>/dev/tcp/$host/$p" 2>/dev/null; then
				exec 3>&- 2>/dev/null || true
				echo "$p"; return 0
			fi
		fi
	done
	return 1
}
