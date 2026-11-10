#!/usr/bin/env bash
# WD05: hartes Aus (controlvm poweroff) bei laufendem Dienst, neu starten; Probe ab Boot + Gateway-Mitschnitt.
. "$(dirname "$0")/wdlib.sh"
cool; log "WD05 Start, Snapshot $SNAP"; up
(cd "$LAB" && bash lab.sh run "$TESTS_DIR/WD05.sh") 2>&1 | tee "$OUT/wd05.log"
log "WD05 fertig"
