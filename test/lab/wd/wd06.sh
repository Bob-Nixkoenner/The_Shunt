#!/usr/bin/env bash
# WD06: Schnellstart an (WD_FASTBOOT=1) und aus (0): herunterfahren, kalt starten. Standard: erst an, dann aus.
# `lab.sh up` (Snapshot-Wiederherstellung) dauert am Laptop bis 12 min: NOUP=1 nutzt die laufende VM (Lab-Netz) weiter;
# vor dem ersten Lauf wird dann nur geprueft, dass sie laeuft, danach laufen die Varianten hintereinander ohne Wiederherstellung.
. "$(dirname "$0")/wdlib.sh"
first=1
for fb in ${WD_FB_LIST:-1 0}; do
  cool; log "WD06 Start Schnellstart=$fb, Snapshot $SNAP (NOUP=${NOUP:-0})"
  if [[ ${NOUP:-0} == 1 && $first == 1 ]]; then caps; elif [[ ${NOUP:-0} != 1 ]]; then up; fi
  first=0
  (cd "$LAB" && WD_FASTBOOT=$fb bash lab.sh run "$TESTS_DIR/WD06.sh") 2>&1 | tee "$OUT/wd06-fb$fb.log"
done
log "WD06 fertig"
