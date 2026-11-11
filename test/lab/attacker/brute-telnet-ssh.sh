#!/usr/bin/env bash
# Credential guessing against the decoy ports (ssh, telnet), tiny word list.
# Usage: TARGET=<ip> [DURATION=20] [SSH_PORT=2222] [TELNET_PORT=23] ./brute-telnet-ssh.sh
# Port 22 often belongs to a real sshd on the client, so the ssh decoy is tried on 2222
# first (then 22); telnet on 23, then 2323. Set SSH_PORT / TELNET_PORT to force a port.
set -euo pipefail
. "$(dirname "$0")/common.sh"
need hydra; need_target
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
printf '%s\n' root admin user pi test guest >"$d/users"
printf '%s\n' root admin 1234 password 12345 raspberry guest >"$d/pass"
pick() { # first open port of the list
	for p in "$@"; do
		if timeout 3 bash -c "exec 3<>/dev/tcp/$TARGET/$p" 2>/dev/null; then echo "$p"; return; fi
	done
	echo "$1"
}
SSH_PORT=${SSH_PORT:-$(pick 2222 22)}
TELNET_PORT=${TELNET_PORT:-$(pick 23 2323)}
for svc in ssh telnet; do
	port=$SSH_PORT; [[ $svc == telnet ]] && port=$TELNET_PORT
	echo "== $svc on port $port =="
	timeout "$DURATION" hydra -L "$d/users" -P "$d/pass" -t 4 -s "$port" "$svc://$TARGET" || true
done
