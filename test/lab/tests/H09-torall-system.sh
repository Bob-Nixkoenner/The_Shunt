ID=H09
TITLE="tor-all: auch Systemdienste (NTP, apt, Konnektivitaetspruefung) gehen nur ueber Tor"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
NOTE="Im strengen Teil (tor-all an) werden chrony, apt update, die NetworkManager-Pruefung und ein snap-Aufruf angestossen; das Gateway darf nur tor sehen."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam nicht hoch"
sudo -n shunt tor-all on || echo "FAIL tor-all on abgelehnt"
echo "LABMARK strict_from $(date +%s.%N)"
sleep 2
sudo -n chronyc -a makestep >/dev/null 2>&1; sudo -n systemctl restart chrony 2>/dev/null
sudo -n timeout 60 apt-get -q update >/dev/null 2>&1 || echo "Hinweis: apt update ueber Tor nicht fertig (kein Fund)"
nmcli networking connectivity check >/dev/null 2>&1
timeout 20 snap find hello >/dev/null 2>&1
sleep 10
echo "LABMARK strict_until $(date +%s.%N)"
sudo -n shunt tor-all off
true
'
