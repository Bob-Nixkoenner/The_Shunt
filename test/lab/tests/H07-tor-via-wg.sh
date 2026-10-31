ID=H07
TITLE="Tor ueber WireGuard (via): das fremde Netz sieht nur WireGuard"
CONFIG=tor-via
EXPECT_CANARY=any
NOTE="tor laeuft mit via = tunnel:intern, alles andere ueber den Tunnel: am Gateway nur WireGuard zu CT130, keine Tor-Relays, und Web ueber Tor geht."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam ueber den Tunnel nicht hoch"
labtun -s -m30 https://check.torproject.org/api/ip | grep -q "\"IsTor\":true" || echo "FAIL Web geht nicht ueber Tor"
true
'
