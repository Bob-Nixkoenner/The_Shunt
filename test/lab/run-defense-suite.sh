#!/usr/bin/env bash
# Full defense lab run: Q01-Q03 and R01-R11 in one go (Linux client), with pre-checks, cool-down and a summary report.
#
#   run-defense-suite.sh [options]
#     --only T1,T2        run only these tests (default order: Q01 Q02 Q03 R01 ... R11)
#     --skip T1,T2        leave these out (R07 waits 660 s for the learning phase: --skip R07)
#     --client VM         client VM name (default CLIENT_VM from local.env, e.g. shunt-popos / shunt-debian)
#     --cooldown SEC      pause between tests (default 60)
#     --snapshot-reset S  before a retry restore client snapshot S (lab.sh up S); default: only restart shuntd
#     --shutdown-vms      at the end power off the VMs this script started itself (default: leave them running)
#     --ignore-belegung   do not abort on entries in the booking list (belegung.sh)
#     --dry-run           only list what would run, touch nothing
#     --help
#
# Pre-checks: booking list, running VMs, temperature (<75 C, else wait until <68 C, max 15 min), CLIENT_VM, local.env,
# build revision in the client package vs. git HEAD, kali-sync, Kali link/IP, suricata rules on Kali.
# Per test: restart shuntd, lab.sh run <T> with a time limit (20 min, R07 30 min), result OK/FUND/FEHLER from verdict.txt,
# at most one retry on FUND/FEHLER. Results: $LAB_OUT/<date>/suite-<time>/ (suite-report.md, suite.log), never in git.
# No background polling: everything runs in the foreground. Placeholder values only in this file.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
[[ -f $HERE/local.env ]] && { set -a; source "$HERE/local.env"; set +a; }   # shellcheck source=/dev/null
LAB_OUT=${LAB_OUT:-$HOME/projects/shunt-lab-results}
KALI_PORT=${KALI_PORT:-2226}; KALI_USER=${KALI_USER:-lab}; KALI_VM=${KALI_VM:-shunt-kali}
KALI_IP=${KALI_IP:-10.77.0.222}; GW_VM=${GW_VM:-shunt-lab-gw}
KEY=${KEY:-$HOME/.ssh/shunt-vm}
BELEGUNG=${BELEGUNG:-$HOME/Nextcloud/Shared/PC/Linux/_postfach/belegung/belegung.sh}
ALL_TESTS=(Q01 Q02 Q03 R01 R02 R03 R04 R05 R06 R07 R08 R09 R10 R11)
ONLY=""; SKIP=""; COOLDOWN=60; SNAP=""; SHUT=0; IGN=0; DRY=0
TEMP_HIGH=75; TEMP_LOW=68; TEMP_MAXWAIT=900
STARTED_VMS=()

usage() { sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//;$d'; }
while (($#)); do
	case $1 in
	--only) ONLY=${2:?}; shift 2 ;;
	--skip) SKIP=${2:?}; shift 2 ;;
	--client) CLIENT_VM=${2:?}; shift 2 ;;
	--cooldown) COOLDOWN=${2:?}; shift 2 ;;
	--snapshot-reset) SNAP=${2:?}; shift 2 ;;
	--shutdown-vms) SHUT=1; shift ;;
	--ignore-belegung) IGN=1; shift ;;
	--dry-run) DRY=1; shift ;;
	--help | -h) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done
[[ -n ${CLIENT_VM:-} ]] && export CLIENT_VM

in_list() { [[ ,$2, == *",$1,"* ]]; }
TESTS=()
for t in "${ALL_TESTS[@]}"; do
	[[ -n $ONLY ]] && ! in_list "$t" "$ONLY" && continue
	in_list "$t" "$SKIP" && continue
	TESTS+=("$t")
done
limit_for() { [[ $1 == R07 ]] && echo 1800 || echo 1200; }

if ((DRY)); then
	echo "dry run: nothing is started or changed"
	echo "client VM:  ${CLIENT_VM:-<not set: CLIENT_VM in local.env or --client>}"
	echo "local.env:  $([[ -f $HERE/local.env ]] && echo present || echo MISSING)"
	echo "cooldown:   ${COOLDOWN}s, retry: 1x on FUND/FEHLER, snapshot reset: ${SNAP:-no (shuntd restart only)}"
	echo "pre-checks: belegung list, running VMs, temperature <${TEMP_HIGH} C, build revision, kali-sync, Kali link/IP, suricata rules"
	for t in "${TESTS[@]}"; do
		f=$(compgen -G "$HERE/tests/$t-*.sh" | head -1)
		echo "  $t  limit $(limit_for "$t")s  $([[ -n $f ]] && echo "${f##*/}" || echo 'TEST FILE MISSING')$([[ $t == R07 ]] && echo '  (660 s learning phase)')"
	done
	exit 0
fi

: "${CLIENT_VM:?CLIENT_VM not set: set it in local.env or use --client}"
[[ -f $HERE/local.env ]] || { echo "local.env missing (copy local.env.example)" >&2; exit 1; }
((${#TESTS[@]})) || { echo "no tests selected" >&2; exit 1; }

START=$(date +%s)
OUTDIR=$LAB_OUT/$(date +%F)/suite-$(date +%H%M%S)
mkdir -p "$OUTDIR" || exit 1
LOG=$OUTDIR/suite.log
exec > >(tee -a "$LOG") 2>&1
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

cleanup() {
	local rc=$?
	trap - EXIT INT TERM
	pkill -P $$ 2>/dev/null   # only our own children
	if ((SHUT)) && ((${#STARTED_VMS[@]})); then
		for vm in "${STARTED_VMS[@]}"; do log "power off $vm (started by this script)"; VBoxManage controlvm "$vm" poweroff >/dev/null 2>&1; done
	fi
	log "end (rc=$rc), log: $LOG"
	exit "$rc"
}
trap cleanup EXIT INT TERM

lab() { "$HERE/lab.sh" "$@"; }
SSHO=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o LogLevel=ERROR -o ConnectTimeout=8)
kali() { ssh "${SSHO[@]}" -p "$KALI_PORT" "$KALI_USER@127.0.0.1" "$@"; }
vm_running() { VBoxManage list runningvms | grep -q "\"$1\""; }
client_sh() { timeout 120 "$HERE/lab.sh" ssh "$*" 2>/dev/null | tr -d '\r'; }

temp_c() { # package temperature in whole degrees C (x86_pkg_temp, else hottest zone)
	local z best=0 t type
	for z in /sys/class/thermal/thermal_zone*; do
		[[ -r $z/temp ]] || continue
		t=$(($(<"$z/temp") / 1000)); type=$(<"$z/type")
		[[ $type == x86_pkg_temp ]] && { echo "$t"; return; }
		((t > best)) && best=$t
	done
	echo "$best"
}
cool_wait() { # pause when >= TEMP_HIGH until < TEMP_LOW, give up after TEMP_MAXWAIT
	local t waited=0
	t=$(temp_c)
	((t < TEMP_HIGH)) && return 0
	log "temperature ${t} C >= ${TEMP_HIGH}: pause until < ${TEMP_LOW} C"
	while ((t >= TEMP_LOW)); do
		((waited >= TEMP_MAXWAIT)) && { log "ABORT: still ${t} C after $((TEMP_MAXWAIT / 60)) min"; return 1; }
		sleep 30; waited=$((waited + 30)); t=$(temp_c)
	done
	log "temperature ${t} C, going on"
}

# ---------- pre-checks ----------
log "defense suite: ${TESTS[*]} (client $CLIENT_VM)"
if [[ -x $BELEGUNG ]]; then
	bl=$("$BELEGUNG" list 2>&1); echo "$bl"
	if ((!IGN)) && grep -qE 'Status: *(läuft|vorrang)' <<<"$bl"; then
		echo "ABORT: booking list has running entries (look above; --ignore-belegung to override)" >&2; exit 1
	fi
else
	log "note: $BELEGUNG not found, booking list not checked"
fi
VBoxManage list runningvms
for vm in "$GW_VM" "$CLIENT_VM" "$KALI_VM"; do
	vm_running "$vm" && continue
	log "$vm not running: starting it"
	if [[ $vm == "$KALI_VM" ]]; then VBoxManage startvm "$vm" --type headless >/dev/null || { echo "ABORT: cannot start $vm" >&2; exit 1; }
	else lab up || { echo "ABORT: lab.sh up failed" >&2; exit 1; }; STARTED_VMS+=("$GW_VM"); fi
	STARTED_VMS+=("$vm")
	[[ $vm == "$KALI_VM" ]] && for _ in $(seq 40); do kali true 2>/dev/null && break; sleep 3; done
done
cool_wait || exit 1

CLIENT_OS_NAME=$(client_sh '. /etc/os-release; echo $PRETTY_NAME')
HEADREV=$(git -C "$HERE" rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
BUILT=$(client_sh 'grep -a -o "vcs.revision=[0-9a-f]*" /usr/bin/shuntd /usr/local/bin/shuntd 2>/dev/null | head -1 | cut -d= -f2' | head -c 7)
PKGVER=$(client_sh 'shunt version 2>/dev/null | head -1')
if [[ -z $BUILT ]]; then
	BUILD_NOTE="no VCS stamp in the client package (git worktree or -buildvcs=false): compare by package name ($PKGVER); checkout $HEADREV"
	log "WARNING build: $BUILD_NOTE"
elif [[ $BUILT != "$HEADREV" ]]; then
	BUILD_NOTE="client built at $BUILT, checkout at $HEADREV"
	log "WARNING build: $BUILD_NOTE: rebuild the package before testing"
	[[ ${BUILD_CHECK:-warn} == strict ]] && { echo "ABORT: BUILD_CHECK=strict" >&2; exit 1; }
else BUILD_NOTE="matches checkout $HEADREV"; fi

lab kali-sync || { echo "ABORT: kali-sync failed (Kali up? KALI_PORT=$KALI_PORT)" >&2; exit 1; }
if ! kali "ip -br addr | grep -F '$KALI_IP' | grep -qw UP"; then
	log "Kali: $KALI_IP not up on the lab NIC: lab.sh kali-net"
	lab kali-net >/dev/null 2>&1
	kali "ip -br addr | grep -F '$KALI_IP' | grep -qw UP" || { echo "ABORT: Kali has no UP lab NIC with $KALI_IP (check KALI_IP / NIC link)" >&2; exit 1; }
fi
rules=$(kali "sudo sh -c 'cat /var/lib/suricata/rules/suricata.rules 2>/dev/null | grep -c ^alert'" 2>/dev/null | tail -1)
if [[ ${rules:-0} == 0 ]]; then
	log "Kali: 0 suricata rules: suricata-update (once, needs internet on Kali)"
	kali "sudo timeout 300 suricata-update" >/dev/null 2>&1 || log "WARNING suricata-update failed: observer will show 0 alerts"
fi

# ---------- run ----------
declare -A RES DUR HEAT KINDS NOTE
shuntd_restart() { client_sh 'sudo -n systemctl restart shuntd; sleep 5; systemctl is-active shuntd' | tail -1; }
latest_dir() { # newest run dir of test $1 created after epoch $2
	local d
	for d in $(ls -dt "$LAB_OUT/$(date +%F)/$1"-* 2>/dev/null); do [[ $(stat -c %Y "$d") -ge $2 ]] && { echo "$d"; return; }; done
}
one_run() { # test -> sets RESULT, RUNDIR
	local t=$1 t0 rc
	t0=$(date +%s)
	RESULT=FEHLER; RUNDIR=""
	cool_wait || { RESULT=FEHLER; return; }
	log "$t: shuntd restart: $(shuntd_restart)"
	timeout "$(limit_for "$t")" "$HERE/lab.sh" run "$t" >"$OUTDIR/$t.out" 2>&1; rc=$?
	RUNDIR=$(latest_dir "$t" "$t0")
	if ((rc == 124)); then NOTE[$t]="time limit $(limit_for "$t") s"; return; fi
	[[ -n $RUNDIR && -f $RUNDIR/verdict.txt ]] || { NOTE[$t]="no verdict (lab.sh rc=$rc, see $t.out)"; return; }
	if grep -q ": FUND" "$RUNDIR/verdict.txt" || grep -q '^FAIL' "$RUNDIR/client.out" 2>/dev/null; then RESULT=FUND; else RESULT=OK; fi
}
collect() { # test: heat max + event counts of the last run (the client daemon still holds them)
	local t=$1 js heat max
	js=$(client_sh 'curl -s --unix-socket /run/shunt/shuntd.sock http://shunt/v1/defense')
	KINDS[$t]=$(grep -o '"counts":{[^}]*}' <<<"$js" | sed 's/"counts"://; s/[{}"]//g; s/:/=/g; s/,/ /g')
	heat=$(grep -o '"heat":[0-9]*' <<<"$js" | head -1 | cut -d: -f2)
	max=${heat:-0}
	if [[ -n $RUNDIR ]]; then
		for h in $(cat "$RUNDIR/client.out" "$RUNDIR/during.log" 2>/dev/null | grep -o '"heat":[0-9]*' | cut -d: -f2); do ((h > max)) && max=$h; done
	fi
	HEAT[$t]=$max
	[[ -n ${KINDS[$t]} ]] || KINDS[$t]="-"
}
first_hint() { # one line: first FUND line of the verdict or FAIL line
	[[ -n $RUNDIR ]] || return
	{ grep -m1 -E ': FUND|^FAIL' "$RUNDIR/verdict.txt" "$RUNDIR/client.out" 2>/dev/null | head -1 | cut -d: -f2- | tr '|' '/'; } || true
}
first=1
for t in "${TESTS[@]}"; do
	((first)) || { log "cool-down ${COOLDOWN}s"; sleep "$COOLDOWN"; }
	first=0
	s=$(date +%s); log "=== $t start"
	one_run "$t"
	if [[ $RESULT != OK ]]; then
		log "$t: $RESULT, one retry"
		[[ -n $SNAP ]] && { log "restore client snapshot $SNAP"; lab up "$SNAP" >/dev/null 2>&1 || true; }
		one_run "$t"; NOTE[$t]="${NOTE[$t]:+${NOTE[$t]}; }retry done"
	fi
	collect "$t"
	RES[$t]=$RESULT; DUR[$t]=$(($(date +%s) - s))
	h=$(first_hint); [[ -n $h ]] && NOTE[$t]="${NOTE[$t]:+${NOTE[$t]}; }$h"
	log "=== $t: $RESULT in ${DUR[$t]}s, heat max ${HEAT[$t]}, events ${KINDS[$t]}"
done

# ---------- report ----------
TOTAL=$(($(date +%s) - START))
{
	echo "# Defense suite report"
	echo
	echo "- Build revision: client: ${BUILT:-no VCS stamp} / checkout: $HEADREV ($BUILD_NOTE)"
	echo "- Date: $(date '+%F %H:%M')"
	echo "- Client OS: ${CLIENT_OS_NAME:-unknown} (VM $CLIENT_VM)"
	echo "- Total duration: $((TOTAL / 60)) min $((TOTAL % 60)) s"
	echo "- Results folder: $OUTDIR (local only, contains no network data in this report)"
	echo
	echo "| Test | Result | Duration | Heat max | Events by kind | Note |"
	echo "|---|---|---|---|---|---|"
	for t in "${TESTS[@]}"; do
		echo "| $t | ${RES[$t]} | ${DUR[$t]} s | ${HEAT[$t]} | ${KINDS[$t]} | ${NOTE[$t]:-} |"
	done
} >"$OUTDIR/suite-report.md"
log "report: $OUTDIR/suite-report.md"
bad=0; for t in "${TESTS[@]}"; do [[ ${RES[$t]} == OK ]] || bad=1; done
exit $bad
