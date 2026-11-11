#!/usr/bin/env bash
# Passive observer: Suricata (no Zeek: not installable on kali-rolling, libc6 conflict) on the lab interface, read-only, logs stay local in this VM.
# Usage:
#   ./observer.sh start          start in the background
#   ./observer.sh stop           stop and print a short summary
#   ./observer.sh status         show whether they are running
set -euo pipefail
. "$(dirname "$0")/common.sh"
LOGDIR=${OBSERVER_LOGDIR:-/var/log/shuntlab-observer}
SURIDIR="$LOGDIR/suricata"

start() {
	need suricata
	sudo mkdir -p "$SURIDIR"
	local rules=/var/lib/suricata/rules/suricata.rules
	if [[ ! -s $rules ]] || [[ $(sudo grep -c '^alert' "$rules" 2>/dev/null || echo 0) -eq 0 ]]; then
		echo "WARNING: 0 Regeln geladen (0 rules): run 'sudo suricata-update' once on Kali (needs internet), otherwise there are flows but no alerts" >&2
	fi
	# an old instance or a stale pid file must not hang the caller (ssh waits for open fds)
	if pgrep -x suricata >/dev/null; then
		echo "suricata already running: stopping the old instance first"
		sudo pkill -x suricata 2>/dev/null || true
		sleep 2
	fi
	sudo rm -f "$LOGDIR/suricata.pid"
	echo "starting suricata on $IFACE (passive, logs under $LOGDIR)"
	sudo suricata -i "$IFACE" -l "$SURIDIR" -D --pidfile "$LOGDIR/suricata.pid" </dev/null >/dev/null 2>&1 \
		|| { setsid nohup sudo suricata -i "$IFACE" -l "$SURIDIR" </dev/null >/dev/null 2>&1 & }
	echo "observer started"
}

stop() {
	echo "stopping observer"
	[[ -f $LOGDIR/suricata.pid ]] && sudo kill "$(cat "$LOGDIR/suricata.pid")" 2>/dev/null || true
	pkill -x suricata 2>/dev/null || true
	sleep 2
	summary
}

summary() {
	echo "== Beobachter sah: =="
	if [[ -f $SURIDIR/eve.json ]]; then
		echo "-- Suricata flows ohne Antwort (S0/REJ-aehnlich) je Quelle --"
		sudo grep '"event_type":"flow"' "$SURIDIR/eve.json" 2>/dev/null \
			| grep -E '"state":"(new|closed)"' | grep -E '"pkts_toclient":0' \
			| grep -o '"src_ip":"[^"]*"' | sort | uniq -c | sort -rn | head -20
	fi
	if [[ -f $SURIDIR/eve.json ]]; then
		echo "-- Suricata Alerts (eve.json) --"
		grep -o '"alert":{[^}]*"signature":"[^"]*"' "$SURIDIR/eve.json" 2>/dev/null \
			| grep -o '"signature":"[^"]*"' | sort | uniq -c | sort -rn
		echo "Regeln: Emerging Threats Open, wenn per suricata-update geladen (BSD-2-Clause-artige ET-Open-Lizenz, siehe https://rules.emergingthreats.net/OPEN_download_instructions.html); sonst nur Suricata-Standardregeln."
	else
		echo "-- keine Suricata eve.json gefunden --"
	fi
}

case "${1:-}" in
start) start ;;
stop) stop ;;
status)
	pgrep -x suricata >/dev/null && echo "suricata: running" || echo "suricata: stopped"
	;;
*) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
