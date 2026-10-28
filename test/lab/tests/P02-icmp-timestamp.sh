ID=P02
TITLE="ICMP-Timestamp-/Netmask-Anfragen aus dem LAN bleiben unbeantwortet"
EXPECT_CANARY=any
NOTE="Das Gateway schickt ICMP Timestamp (13) und Address-Mask (17) an die LAN-Adresse des Clients. Antwort = Uhr/Uptime-Fingerabdruck."
during() {
	sleep 3
	read -r mac ip _ <<<"$(gw labctl client)"
	gw python3 - "$mac" "$ip" <<'PY'
import sys
from scapy.all import Ether, IP, ICMP, srp, conf
conf.verb = 0
mac, ip = sys.argv[1], sys.argv[2]
for name, t in (("Timestamp", 13), ("Address-Mask", 17), ("Info", 15)):
    ans, _ = srp(Ether(dst=mac) / IP(src="10.77.0.1", dst=ip) / ICMP(type=t), iface="enp0s8", timeout=2, retry=1)
    for s, r in ans:
        print("FAIL Antwort auf ICMP %s: %s" % (name, r.summary()))
PY
}
CLIENT='sleep 12; true'
