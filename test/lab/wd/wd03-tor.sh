#!/usr/bin/env bash
# WD03 nur Tor-Variante an der laufenden VM (ohne Snapshot-Wiederherstellung). WD_N_TOR = Anzahl Durchlaeufe.
. "$(dirname "$0")/wdlib.sh"
cool; caps; log "WD03-Tor Start (WD_N=${WD_N_TOR:-5})"
(cd "$LAB" && CONFIG_FORCE=tor WD_N=${WD_N_TOR:-5} bash lab.sh run "$TESTS_DIR/WD03.sh") 2>&1 | tee "$OUT/wd03-tor.log"
log "WD03-Tor fertig"
