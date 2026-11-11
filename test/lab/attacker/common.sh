# Shared helpers for the attacker scripts. Runs inside shunt-kali on the lab LAN (shuntlab).
# Every address comes from the environment or from the running system, never from this file.
#   IFACE   lab interface (default: the interface with the default route, else eth0)
#   TARGET  victim address (the Shunt client), required by most scripts
#   GW      gateway address (default: read from the routing table)
IFACE=${IFACE:-$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')}
IFACE=${IFACE:-eth0}
GW=${GW:-$(ip -4 route show default dev "$IFACE" 2>/dev/null | awk '{print $3; exit}')}
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
