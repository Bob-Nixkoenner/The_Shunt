#!/usr/bin/env bash
# Traffic for lab test R10 (brute_service): password guessing against a REAL service of the client
# (its sshd on port 22, not a decoy), plus the two controls that must stay quiet.
# Usage: TARGET=<ip> [PORT=22] [DURATION=40] ./brute-service.sh controls|attack
#   controls  6 short connections in 10 s (like a web client), then one connection held open 40 s with
#             3 reconnects (like Syncthing). Both must give no brute_service event.
#   attack    hydra (16 tasks) with a small harmless word list for DURATION seconds; without hydra
#             4 x brute.py ssh in parallel (one login per connection). Expected: brute_service and a block
#             (medium with >= 20 proven handshakes, or high).
# Lab only: the word list has no real credentials, the client's sshd refuses every try.
set -euo pipefail
. "$(dirname "$0")/common.sh"
need_target
HERE=$(dirname "$0")
PORT=${PORT:-22}
DURATION=${DURATION:-40}

case ${1:-} in
controls)
	echo "== control 1: 6 short connections in 10 s to $PORT =="
	for _ in 1 2 3 4 5 6; do
		timeout 3 bash -c "exec 3<>/dev/tcp/$TARGET/$PORT; head -c 64 <&3 >/dev/null" 2>/dev/null || true
		sleep 1.6
	done
	echo "== control 2: one connection held open 40 s, 3 reconnects =="
	for _ in 1 2 3; do
		timeout 13 bash -c "exec 3<>/dev/tcp/$TARGET/$PORT; sleep 12" 2>/dev/null || true
	done
	echo "controls done"
	;;
attack)
	words=$(mktemp); trap 'rm -f "$words"' EXIT
	for i in $(seq 1 300); do echo "lab-wrong-$i"; done >"$words"
	echo "== attack on $PORT for ${DURATION}s =="
	if command -v hydra >/dev/null; then
		timeout "$DURATION" hydra -I -q -t 16 -l labnobody -P "$words" -s "$PORT" "ssh://$TARGET" || true
	else
		need python3
		for _ in 1 2 3 4; do
			timeout "$DURATION" python3 "$HERE/brute.py" ssh "$TARGET" "$PORT" 200 &
		done
		wait || true
	fi
	echo "attack done"
	;;
*) echo "usage: TARGET=<ip> $0 controls|attack" >&2; exit 2 ;;
esac
