ID=M07
TITLE="Paket-Update bei laufendem Tunnel: Leck im Update-Fenster?"
EXPECT_CANARY=any
DEB=${M07_DEB:-$LAB_OUT/debs/$(ls -t "$LAB_OUT/debs" | grep -E '^the-shunt_.*amd64\.deb$' | head -1)}
NOTE="dpkg -i desselben Pakets waehrend labtun/labfree senden (Dienst-Neustart, Regeln kurz weg?)."
during() {
	sleep 4
	VBoxManage "${GC[@]}" copyto "$DEB" /tmp/m07.deb
	client 'sudo -n dpkg -i /tmp/m07.deb >/dev/null 2>&1; sudo -n systemctl is-active shuntd'
}
CLIENT='
for i in $(seq 45); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labfree-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.5
done
true
'
