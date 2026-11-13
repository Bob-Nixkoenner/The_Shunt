#!/usr/bin/env bash
# Port scan against TARGET: nmap SYN scan, then a plain connect scan.
# Usage: TARGET=<ip> [PORTS=1-1024] [RATE=500] ./portscan.sh [syn|connect|both]
set -euo pipefail
. "$(dirname "$0")/common.sh"
need nmap; need_target
mode=${1:-both}
ports=${PORTS:-1-1024}
if [[ $mode == syn || $mode == both ]]; then
	echo "== SYN scan =="
	sudo nmap -Pn -sS -p "$ports" --min-rate "${RATE:-500}" "$TARGET" # no -e: nmap 7.99x hangs with it (IPv6 link-local bind), the route picks the lab NIC
fi
if [[ $mode == connect || $mode == both ]]; then
	echo "== connect scan =="
	nmap -Pn -sT -p "$ports" --min-rate "${RATE:-500}" "$TARGET"
fi
