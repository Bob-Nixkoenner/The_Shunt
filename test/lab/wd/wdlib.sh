#!/usr/bin/env bash
# Gemeinsame Funktionen fuer wd03.sh / wd05.sh / wd06.sh (Windows-Herunterfahren-Tests am Laptop).
# Nutzt das Messlabor (~/projects/The_Shunt-rk3/test/lab): Gateway-Mitschnitt + Analyzer, Tests in tests-wd/.
LAB=${LAB:-$HOME/projects/The_Shunt-rk3/test/lab}
WDDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=${OUT:-$HOME/projects/shunt-lab-results/rk3-win-laptop}; mkdir -p "$OUT"
export CLIENT_OS=windows CLIENT_VM=${CLIENT_VM:-shunt-win11} CLIENT_USER=${CLIENT_USER:-shunt} PWFILE=${PWFILE:-$HOME/.shunt-win11-pw}
export LAB_OUT=$OUT TESTS_DIR=$WDDIR/tests-wd
SNAP=${SNAP:-lab-rk3}
log() { echo "$(date +%T) $*" | tee -a "$OUT/status.log"; }
# Laptop-Schutz: Caps neu setzen (lab.sh up setzt sie zurueck), Temperatur pruefen
caps() { VBoxManage controlvm "$CLIENT_VM" cpuexecutioncap 50 2>/dev/null; VBoxManage controlvm shunt-lab-gw cpuexecutioncap 35 2>/dev/null; }
temp() { local m=0 t; for z in /sys/class/thermal/thermal_zone*; do [[ $(cat $z/type 2>/dev/null) == x86_pkg_temp ]] && m=$(( $(cat $z/temp) / 1000 )); done; echo $m; }
cool() { while (( $(temp) > 75 )); do log "Temperatur $(temp) C: Pause 30 s"; sleep 30; done; }
lab() { (cd "$LAB" && bash lab.sh "$@"); }
up() { lab up "${1:-$SNAP}" >>"$OUT/up.log" 2>&1; caps; }
