ID=M09
TITLE="Weitergeleiteter Verkehr (Container/VM auf dem Client) bei laufendem Tunnel folgt dem Standardweg"
MODE=normal
EXPECT_CANARY=tunnel
NOTE="Wie M06, aber der Tunnel laeuft: Verkehr aus dem Namespace muss durch den Tunnel, nicht direkt (Docker/libvirt-Fall)."
CLIENT='
sudo -n sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns del m6 2>/dev/null
sudo -n ip netns add m6 && sudo -n ip link add m6h type veth peer name m6c netns m6
sudo -n ip addr add 172.31.6.1/24 dev m6h && sudo -n ip link set m6h up
sudo -n ip -n m6 addr add 172.31.6.2/24 dev m6c && sudo -n ip -n m6 link set m6c up && sudo -n ip -n m6 link set lo up
sudo -n ip -n m6 route add default via 172.31.6.1
sudo -n nft add table ip m6nat
sudo -n nft "add chain ip m6nat post { type nat hook postrouting priority 100; }"
sudo -n nft add rule ip m6nat post ip saddr 172.31.6.0/24 masquerade
sleep 4
for i in $(seq 6); do
  sudo -n ip netns exec m6 curl -s -m2 -o /dev/null "http://f$i-$1/"
  sudo -n ip netns exec m6 curl -s -m2 -o /dev/null http://1.1.1.1/
  sudo -n ip netns exec m6 dig +time=1 +tries=1 @9.9.9.9 "d$i-$1" >/dev/null 2>&1
  sleep 0.5
done
sudo -n nft delete table ip m6nat; sudo -n ip netns del m6; sudo -n ip link del m6h 2>/dev/null
true
'
