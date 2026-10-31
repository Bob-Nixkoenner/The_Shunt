ID=H06
TITLE="Tor mit obfs4-Bruecken: tor spricht nur mit Bruecken, nie mit Relays"
CONFIG=tor-bridge
EXPECT_CANARY=any
# the built-in obfs4 bridges (internal/tunnel/tor_bridges.go): lyrebird's
# connections from before the trace have no process name
ALLOW=(comm:tor comm:lyrebird dst:146.57.248.225:22/tcp dst:209.148.46.65:443/tcp dst:212.83.43.74:443/tcp dst:212.83.43.95:443/tcp dst:37.218.245.14:38224/tcp dst:45.145.95.6:27015/tcp dst:51.222.13.177:80/tcp comm:chronyd comm:NetworkManager comm:snapd comm:systemd-timesyn comm:pacman dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp)
NOTE="Eingebaute obfs4-Bruecken. Nach dem Start darf keine TCP-Verbindung von tor/lyrebird zu einer Adresse aus dem Tor-Konsens gehen (das waeren normale Relays), und Web ueber Tor geht."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam ueber die Bruecken nicht hoch"
ok=0; for i in 1 2 3; do labtun -s -m40 https://check.torproject.org/api/ip | grep -q "\"IsTor\":true" && { ok=1; break; }; sleep 10; done
[ $ok = 1 ] || echo "FAIL Web geht nicht ueber Tor"
c=$(sudo -n sh -c "ls /var/lib/shunt/tor/*/cached-microdesc-consensus" 2>/dev/null | head -1)
[ -n "$c" ] || { echo "Hinweis: kein Konsens gefunden, Abgleich entfaellt"; exit 0; }
sudo -n awk "/^r /{print \$6}" "$c" | LC_ALL=C sort -u > /tmp/h06-relays
sudo -n ss -tnpH state established | grep -E "\"(tor|lyrebird)\"" | awk "{print \$4}" | sed "s/:[0-9]*\$//; s/[][]//g" | LC_ALL=C sort -u > /tmp/h06-peers
echo "tor/lyrebird verbunden mit: $(tr "\n" " " < /tmp/h06-peers)"
LC_ALL=C comm -12 /tmp/h06-relays /tmp/h06-peers | sed "s/^/FAIL Verbindung zu normalem Relay: /"
true
'
