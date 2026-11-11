#!/usr/bin/env bash
# Fixed-interval beacon to an external-looking address, to exercise beacon detection.
# Usage: DEST=<ip:port> [INTERVAL=5] [COUNT=12] ./beacon.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need curl
: "${DEST:?set DEST=<ip:port>}"
for ((i = 0; i < ${COUNT:-12}; i++)); do
	curl -s -m 2 "http://$DEST/" -o /dev/null || true
	sleep "${INTERVAL:-5}"
done
