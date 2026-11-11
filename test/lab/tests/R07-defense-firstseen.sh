ID=R07
TITLE="Abwehr: Erstkontakt einer App nach der Lernphase -> first_seen, nur einmal, Ratenbegrenzung more=N"
CONFIG=defense-firstseen
# the client app is a copy of curl named labfs-curl: all its packets are allowed
ALLOW=(comm:labfs-curl)
EXPECT_CANARY=none
# learning phase of the app (internal/defense firstSeenLearn = 10 min, a constant, NO config/env switch):
# the test waits this long. Set FIRSTSEEN_LEARN_SECS lower only with a build that has such a switch.
FIRSTSEEN_LEARN_SECS=${FIRSTSEEN_LEARN_SECS:-660}
CLIENT_TIMEOUT=$((FIRSTSEEN_LEARN_SECS * 1000 + 600000))
NOTE="Lernphase-Schalter fuer Tests noetig: firstSeenLearn (10 min) ist eine Konstante in internal/defense/connobserve.go,
es gibt keinen Config-/Env-Schalter. Der Test wartet FIRSTSEEN_LEARN_SECS (Vorgabe 660 s). Ablauf: labfs-curl
(eigener comm) kontaktiert ein erstes Ziel (startet die Lernphase), wartet, kontaktiert ein neues Ziel -> genau
ein first_seen; derselbe Kontakt nochmal -> kein weiteres; 20 neue Ziele auf einmal -> hoechstens 6 Ereignisse
(6/min), nach >60 s ein weiteres neues Ziel -> Ereignis mit more=N. Ziele: unrouted Adressen in 198.18.0.0/15
(nicht privat im Sinne von destTarget, je /24 ein Ziel; curl haelt SYN_SENT 4 s, damit die Socket-Liste es sieht;
Annahme: auch nicht abgeschlossene Verbindungen werden gesehen, sonst Ziel auf Kali-Webserver umstellen).
Nicht in der Lab-VM gelaufen (Stand 11.11.)."
CLIENT="LEARN=$FIRSTSEEN_LEARN_SECS"'
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
cnt() { api "/v1/defense/events?since=0" | grep -o "\"kind\":\"first_seen\"" | wc -l; }
sudo -n install -m755 "$(command -v curl)" /usr/local/bin/labfs-curl || echo "FAIL curl-Kopie"
hit() { labfs-curl -s -m 4 -o /dev/null "http://$1/" || true; }
hit 198.18.1.1                              # first contact: starts the learning phase
sleep "$LEARN"
n0=$(cnt)
hit 198.18.2.1; sleep 8
n1=$(cnt)
[ "$n1" -eq $((n0 + 1)) ] || echo "FAIL erwartet genau 1 neues first_seen, vorher $n0 nachher $n1"
hit 198.18.2.1; sleep 8
n2=$(cnt)
[ "$n2" -eq "$n1" ] || echo "FAIL zweiter Kontakt zum selben Ziel erzeugte Ereignis ($n1 -> $n2)"
for i in $(seq 10 29); do hit 198.18.$i.1 & done; wait
sleep 8
n3=$(cnt)
[ $((n3 - n2)) -le 6 ] || echo "FAIL Ratenbegrenzung: $((n3 - n2)) Ereignisse fuer 20 Ziele (max 6)"
[ $((n3 - n2)) -ge 1 ] || echo "FAIL gar kein Ereignis fuer 20 neue Ziele"
sleep 65
hit 198.18.40.1; sleep 8
api "/v1/defense/events?since=0" | grep first_seen | grep -q "more=[0-9]" || echo "FAIL kein more=N am naechsten Ereignis"
true
'
after() { client "sudo -n rm -f /usr/local/bin/labfs-curl" || true; }
