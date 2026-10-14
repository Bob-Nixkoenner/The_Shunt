#!/usr/bin/env bash
# The CI checks (gofmt, vet, unit tests, race detector, fuzzing, cross builds,
# govulncheck) spread over helper machines over SSH, plus this machine.
#
#   test/farm.sh [--quick] [--only REGEX] [--hosts FILE] [--keep]
#
#   --quick   no race detector, no fuzzing, no govulncheck
#   --only    run only jobs whose name matches REGEX (e.g. --only 'race|splitstack')
#   --hosts   host list (default ~/.config/shunt-farm/hosts), one per line:
#               local 1                         this machine, 1 slot
#               worker@192.168.222.130 2        2 jobs at a time
#               worker@192.168.222.131 1 small  little RAM: no gvisor/race jobs
#             Hosts that do not answer, or have no Go (PATH or ~/opt/go/bin),
#             are skipped.
#   --keep    keep the logs of passed jobs too
#
# The tree this script lives in is copied (rsync, without .git and android/)
# to ~/jobs/shunt on every helper; jobs run there with nice. Logs and a
# summary go to ~/.cache/shunt-farm/<time>/. Exit status 1 if a job failed.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOSTS=${XDG_CONFIG_HOME:-$HOME/.config}/shunt-farm/hosts
QUICK=0 ONLY= KEEP=0
while (($#)); do
	case $1 in
	--quick) QUICK=1 ;;
	--only) ONLY=$2; shift ;;
	--hosts) HOSTS=$2; shift ;;
	--keep) KEEP=1 ;;
	-h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
	shift
done
if [[ ! -f $HOSTS ]]; then
	mkdir -p "$(dirname "$HOSTS")"
	printf '%s\n' 'local 1' 'worker@192.168.222.130 2' 'worker@192.168.222.131 1 small' 'arnonym@10.7.0.20 3' >"$HOSTS"
	echo "created $HOSTS"
fi

OUT=${XDG_CACHE_HOME:-$HOME/.cache}/shunt-farm/$(date +%F-%H%M%S)
mkdir -p "$OUT/logs"
Q=$OUT/queue
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=15)
REMOTE_ENV='export PATH=$HOME/opt/go/bin:$HOME/go/bin:$PATH; cd ~/jobs/shunt || exit 99'

# ---- jobs: "tags|name|command"; tags: big (needs RAM), local (this machine only)
jobs() {
	local gvisor='splitstack|mobile|winsplit'
	echo "|gofmt|test -z \"\$(gofmt -l .)\" || { gofmt -l .; exit 1; }"
	echo "big|vet|go vet \$(go list ./... | grep -v -e /internal/desktopapp -e /cmd/shunt-desktop)"
	echo "local|vet-desktop|go vet ./internal/desktopapp ./cmd/shunt-desktop"
	(cd "$ROOT" && go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...) |
		sed 's|^github.com/Bob-Nixkoenner/the_shunt|.|' | while read -r p; do
		local tag=
		[[ $p =~ $gvisor ]] && tag=big
		[[ $p == ./internal/desktopapp ]] && tag=local
		echo "$tag|test ${p#./}|go test -count=1 $p"
		if ((!QUICK)) && [[ $p =~ splitstack|mobile|daemon|dnsproxy|engine|health|stats|override|firewall|probe ]]; then
			echo "big|race ${p#./}|go test -race -count=1 $p"
		fi
	done
	if ((!QUICK)); then
		local f
		for f in wgconf:FuzzParse:500000 config:FuzzParse:500000 argv:FuzzSplit:500000 appwatch:FuzzParseExecEvents:500000 \
			ovpnconf:FuzzParse:500000 sqlitelite:FuzzRows:500000 sqlitelite:FuzzFile:20000; do
			IFS=: read -r pkg fn n <<<"$f"
			echo "|fuzz $pkg $fn|go test ./internal/$pkg -run '^\$' -fuzz '^$fn\$' -fuzztime ${n}x"
		done
		echo "|govulncheck|go run golang.org/x/vuln/cmd/govulncheck@latest ./..."
	fi
	echo "big|build arm64|GOARCH=arm64 go build -o /dev/null \$(go list ./... | grep -v /cmd/shunt-desktop)"
	echo "big|vet windows|GOOS=windows go vet \$(go list ./... | grep -v -e /internal/desktopapp -e /cmd/shunt-desktop)"
	echo "big|vet darwin|GOOS=darwin go vet \$(go list ./... | grep -v -e /internal/desktopapp -e /cmd/shunt-desktop)"
	echo "local|build desktop|go build -o /dev/null ./cmd/shunt-desktop"
}
jobs | { [[ -n $ONLY ]] && grep -E "^[^|]*\|[^|]*($ONLY)" || cat; } >"$Q"
TOTAL=$(wc -l <"$Q")
((TOTAL)) || { echo "no jobs match"; exit 2; }

# take HOST SMALL: pops the first job this host may run
take() {
	(
		flock 9
		local i=0 line tags
		while IFS= read -r line; do
			i=$((i + 1))
			tags=${line%%|*}
			[[ $tags == *local* && $1 != local ]] && continue
			[[ $tags == *big* && $2 == small ]] && continue
			sed -i "${i}d" "$Q"
			printf '%s\n' "$line"
			exit 0
		done <"$Q"
		exit 1
	) 9>"$Q.lock"
}

# run HOST SLOT SMALL: works through the queue
run() {
	local host=$1 slot=$2 small=$3 line name cmd t0 rc log
	while line=$(take "$host" "$small"); do
		name=${line#*|}; name=${name%%|*}
		cmd=${line#*|*|}
		log=$OUT/logs/$(tr ' /' '__' <<<"$name").log
		t0=$(date +%s)
		{
			echo "# $name on $host: $cmd"
			if [[ $host == local ]]; then
				(cd "$ROOT" && nice -n 10 bash -c "$cmd")
			else
				"${SSH[@]}" "$host" "$REMOTE_ENV; exec nice -n 10 bash -s" <<<"$cmd"
			fi
		} >"$log" 2>&1
		rc=$?
		printf '%s\t%s\t%s\t%ss\n' "$([[ $rc == 0 ]] && echo ok || echo FAIL)" "$name" "$host" "$(($(date +%s) - t0))" >>"$OUT/summary"
		if ((rc)); then
			echo "FAIL  $name ($host)"
			[[ $name == fuzz* && $host != local ]] && rsync -az "$host:jobs/shunt/internal/${name#fuzz }/" "$OUT/fuzz-${name// /_}/" --include='*/' --include='testdata/fuzz/**' --exclude='*' 2>/dev/null
		else
			echo "ok    $name ($host, $(($(date +%s) - t0))s)"
			((KEEP)) || rm -f "$log"
		fi
	done
}

# ---- hosts
declare -a WORKERS=()
while read -r -u 3 host slots size _; do
	[[ -z $host || $host == \#* ]] && continue
	slots=${slots:-1}
	if [[ $host == local ]]; then
		command -v go >/dev/null || { echo "skip local: no go"; continue; }
	else
		if ! "${SSH[@]}" "$host" 'export PATH=$HOME/opt/go/bin:$PATH; command -v go >/dev/null' 2>/dev/null; then
			echo "skip $host: not reachable or no go"
			continue
		fi
		"${SSH[@]}" "$host" 'mkdir -p ~/jobs/shunt' &&
			rsync -az --delete -e "${SSH[*]}" --exclude .git --exclude /android/ --exclude '*.apk' "$ROOT/" "$host:jobs/shunt/" ||
			{ echo "skip $host: rsync failed"; continue; }
		# download modules once per host before the slots start
		"${SSH[@]}" "$host" "$REMOTE_ENV; go mod download" >/dev/null 2>&1 || { echo "skip $host: go mod download failed"; continue; }
	fi
	WORKERS+=("$host $slots ${size:-}")
done 3<"$HOSTS"
((${#WORKERS[@]})) || { echo "no host usable"; exit 2; }

echo "== $TOTAL jobs on: ${WORKERS[*]%% *}  (logs: $OUT)"
START=$(date +%s)
for w in "${WORKERS[@]}"; do
	read -r host slots size <<<"$w"
	for ((s = 1; s <= slots; s++)); do
		run "$host" "$s" "${size:-}" &
	done
done
wait

left=$(wc -l <"$Q")
fails=$(grep -c '^FAIL' "$OUT/summary" 2>/dev/null)
echo
echo "== $((TOTAL - left - fails))/$TOTAL ok, $fails failed, $left not run (no fitting host), $(($(date +%s) - START))s"
awk -F'\t' '{n[$3]++; t[$3]+=$4} END {for (h in n) printf "   %-28s %3d jobs %5ds\n", h, n[h], t[h]}' "$OUT/summary"
if ((left)); then sed 's/^/   not run: /' "$Q"; fi
grep '^FAIL' "$OUT/summary" | while IFS=$'\t' read -r _ name host _; do
	echo "--- $name ($host): $OUT/logs/$(tr ' /' '__' <<<"$name").log"
	tail -15 "$OUT/logs/$(tr ' /' '__' <<<"$name").log" | sed 's/^/   /'
done
((fails == 0 && left == 0))
