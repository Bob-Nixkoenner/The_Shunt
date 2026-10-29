#!/usr/bin/env bash
# trace.sh start <file> | stop <file>   (root) – runs trace.bt in the background.
# The first line maps the monotonic clock to wall time for the analyzer.
set -euo pipefail
case $1 in
start)
	python3 -c 'import time; print("# clock", time.time(), time.clock_gettime_ns(time.CLOCK_MONOTONIC))' >"$2"
	nohup bpftrace -q --no-warnings /usr/local/lib/shuntlab/trace.bt </dev/null >>"$2" 2>"$2.err" &
	echo $! >"$2.pid"
	for _ in $(seq 40); do grep -q . "$2.err" 2>/dev/null && break; [[ $(wc -l <"$2") -gt 1 ]] && break; sleep 0.25; done
	sleep 2 ;; # probes attach
stop)
	kill -INT "$(cat "$2.pid")" 2>/dev/null || true
	sleep 1
	rm -f "$2.pid"
	chmod a+r "$2" "$2.err" ;;
esac
