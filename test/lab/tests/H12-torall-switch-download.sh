ID=H12
TITLE="tor-all einschalten waehrend zwei Downloads laufen: ab dem Umschalten kein Paket dieser Verbindungen mehr im Klartext"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
NOTE="Zwei Downloads vom Gateway (:8000) laufen schon: einer als App (Standardroute direct), einer in der cgroup von shuntd (wie dessen Listen-Downloads). Dann tor-all on. Ab LABMARK strict_from (mit Uhrabgleich) darf das Gateway kein Paket dieser Verbindungen mehr sehen, auch kein ACK/RST. Der Client schneidet zusaetzlich an seiner eigenen Karte mit (gleiche Uhr wie das Umschalten)."
during() {
	gw bash -c 'mkdir -p /tmp/shuntlab-h12 && truncate -s 4G /tmp/shuntlab-h12/big.bin && cd /tmp/shuntlab-h12 && timeout 75 python3 -m http.server 8000 >/dev/null 2>&1; rm -rf /tmp/shuntlab-h12'
}
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam nicht hoch (ohne tor-all)"
IF=$(ip -o route get 10.77.0.1 | grep -o "dev [^ ]*" | cut -d" " -f2)
sudo -n tcpdump -i "$IF" -n -U -s 96 -w /tmp/h12.pcap "host 10.77.0.1 and tcp port 8000" 2>/dev/null & TD=$!
sleep 2
labdir -s --limit-rate 2M -o /dev/null http://10.77.0.1:8000/big.bin & A=$!
DG=/sys/fs/cgroup/system.slice/shuntd.service/daemon
sudo -n bash -c "echo \$\$ > $DG/cgroup.procs; exec curl -s --limit-rate 2M -o /dev/null http://10.77.0.1:8000/big.bin" & D=$!
sleep 4
[ "$(sudo -n ss -tn state established dst 10.77.0.1 dport = :8000 | tail -n +2 | wc -l)" -ge 2 ] || echo "FAIL Downloads liefen vor dem Umschalten nicht"
sudo -n shunt tor-all on || echo "FAIL tor-all on abgelehnt"
T=$(date +%s.%N)
echo "LABMARK strict_from $T"
sleep 8
sudo -n pkill -f "big.bin"; sleep 2
echo "LABMARK strict_until $(date +%s.%N)"
sudo -n kill $TD; sleep 1
# own NIC, same clock as T: nothing of the two flows may leave after the switch returned
n=$(sudo -n tcpdump -r /tmp/h12.pcap -n -tt "src host $(ip -o -4 addr show dev $IF | grep -o "inet [0-9.]*" | cut -d" " -f2)" 2>/dev/null | awk -v t=$T "\$1 > t" | wc -l)
[ "$n" -eq 0 ] || echo "FAIL $n Pakete der Downloads nach dem Umschalten an der eigenen Karte"
sudo -n rm -f /tmp/h12.pcap
sudo -n shunt tor-all off; sleep 3
true
'
