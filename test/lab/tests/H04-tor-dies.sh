ID=H04
TITLE="Tor als App-Weg: tor stirbt oder haengt, die App geht nie direkt"
CONFIG=tor-app
EXPECT_CANARY=none
ALLOW=(comm:tor comm:chronyd comm:NetworkManager comm:snapd comm:systemd-timesyn comm:pacman dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp) # default route direct: the distro's own traffic may go direct
NOTE="labtun laeuft ueber Tor. tor wird angehalten (SIGSTOP) und beendet; labtun darf in beiden Faellen weder die Canary noch 1.1.1.1 erreichen, auch nicht direkt."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam nicht hoch"
labtun -s -m20 -o /dev/null https://check.torproject.org/ || echo "FAIL labtun erreicht nichts ueber Tor"
echo "LABMARK strict_from $(date +%s.%N)"
sudo -n pkill -STOP -x tor; sleep 1
labtun -s -m6 -o /dev/null "http://$1/" && echo "FAIL Canary erreichbar, waehrend tor haengt"
labtun -s -m6 -o /dev/null http://1.1.1.1/ && echo "FAIL 1.1.1.1 erreichbar, waehrend tor haengt"
sudo -n pkill -CONT -x tor; sudo -n pkill -x tor; sleep 1
labtun -s -m6 -o /dev/null "http://$1/" && echo "FAIL Canary erreichbar nach tor-Ende"
labtun -s -m6 -o /dev/null http://1.1.1.1/ && echo "FAIL 1.1.1.1 erreichbar nach tor-Ende"
echo "LABMARK strict_until $(date +%s.%N)"
sleep 15; tor_ready || echo "FAIL tor startet nicht wieder"
true
'
