#!/usr/bin/env bash
# Passive observer: Suricata + Zeek on the lab interface, read-only, logs stay local in this VM.
# Usage:
#   ./observer.sh start          start both in the background
#   ./observer.sh stop           stop both and print a short summary
#   ./observer.sh status         show whether they are running
set -euo pipefail
. "$(dirname "$0")/common.sh"
LOGDIR=${OBSERVER_LOGDIR:-/var/log/shuntlab-observer}
ZEEKDIR="$LOGDIR/zeek"
SURIDIR="$LOGDIR/suricata"
PIDFILE="$LOGDIR/zeek.pid"

start() {
	need zeek; need suricata
	sudo mkdir -p "$ZEEKDIR" "$SURIDIR"
	echo "starting zeek and suricata on $IFACE (passive, logs under $LOGDIR)"
	( cd "$ZEEKDIR" && sudo zeek -i "$IFACE" -C & echo $! | sudo tee "$PIDFILE" >/dev/null )
	sudo suricata -i "$IFACE" -l "$SURIDIR" -D --pidfile "$LOGDIR/suricata.pid" 2>/dev/null \
		|| sudo suricata -i "$IFACE" -l "$SURIDIR" >/dev/null 2>&1 &
	echo "observer started"
}

stop() {
	echo "stopping observer"
	[[ -f $PIDFILE ]] && sudo kill "$(cat "$PIDFILE")" 2>/dev/null || true
	[[ -f $LOGDIR/suricata.pid ]] && sudo kill "$(cat "$LOGDIR/suricata.pid")" 2>/dev/null || true
	pkill -x zeek 2>/dev/null || true
	pkill -x suricata 2>/dev/null || true
	sleep 2
	summary
}

summary() {
	echo "== Beobachter sah: =="
	if [[ -f $ZEEKDIR/conn.log ]]; then
		echo "-- Zeek conn.log, Zustaende S0/REJ je Quelle --"
		sudo zeek-cut id.orig_h conn_state <"$ZEEKDIR/conn.log" 2>/dev/null \
			| awk '$2=="S0"||$2=="REJ"{c[$1" "$2]++} END{for (k in c) print c[k], k}' \
			| sort -rn | head -20
	else
		echo "-- keine Zeek conn.log gefunden --"
	fi
	if [[ -f $ZEEKDIR/notice.log ]]; then
		echo "-- Zeek notice.log --"
		sudo zeek-cut note msg <"$ZEEKDIR/notice.log" 2>/dev/null | sort | uniq -c | sort -rn
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
	pgrep -x zeek >/dev/null && echo "zeek: running" || echo "zeek: stopped"
	pgrep -x suricata >/dev/null && echo "suricata: running" || echo "suricata: stopped"
	;;
*) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
