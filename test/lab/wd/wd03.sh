#!/usr/bin/env bash
# WD03: Stop-Service Shunt 10x (WG-Tunnel), danach 10x mit Tor. Snapshot lab-rk1 (oder SNAP=...), Laptop-VM.
. "$(dirname "$0")/wdlib.sh"
cool; log "WD03 Start, Snapshot $SNAP"; up
(cd "$LAB" && bash lab.sh run "$TESTS_DIR/WD03.sh") 2>&1 | tee "$OUT/wd03-wg.log"
cool
if [[ ${WD_TOR:-0} == 1 ]]; then (cd "$LAB" && CONFIG_FORCE=tor WD_N=${WD_N_TOR:-10} bash lab.sh run "$TESTS_DIR/WD03.sh") 2>&1 | tee "$OUT/wd03-tor.log"; fi
log "WD03 fertig"
