#!/usr/bin/env bash
# Credential guessing against the decoy ports (ssh, telnet) via brute.py, tiny word list.
# Usage: TARGET=<ip> [DURATION=20] [SSH_PORT=2222] [TELNET_PORT=23] ./brute-telnet-ssh.sh
# Port 22 often belongs to a real sshd on the client, so the ssh decoy is tried on 2222
# first (then 22); telnet on 23, then 2323. Set SSH_PORT / TELNET_PORT to force a port.
# Hydra was dropped: it hangs against the telnet decoy's correct IAC negotiation.
set -euo pipefail
. "$(dirname "$0")/common.sh"
need python3; need_target
HERE=$(dirname "$0")
N=${N:-10}

SSH_PORT=${SSH_PORT:-$(pick "$TARGET" 2222 22)} || { echo "FAIL kein erreichbarer Koederport fuer ssh (Kandidaten 2222, 22)" >&2; exit 1; }
TELNET_PORT=${TELNET_PORT:-$(pick "$TARGET" 23 2323)} || { echo "FAIL kein erreichbarer Koederport fuer telnet (Kandidaten 23, 2323)" >&2; exit 1; }

echo "== telnet on port $TELNET_PORT =="
timeout "$DURATION" python3 "$HERE/brute.py" telnet "$TARGET" "$TELNET_PORT" "$N" || true
echo "== ssh on port $SSH_PORT =="
timeout "$DURATION" python3 "$HERE/brute.py" ssh "$TARGET" "$SSH_PORT" "$N" || true
