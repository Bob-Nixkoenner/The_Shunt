ID=O06
TITLE="OpenVPN mit abgelaufenem Client-Zertifikat: Tunnel bleibt unten, nie direkt"
CONFIG=ovpn-variants
EXPECT_CANARY=none
ALLOW=(dst:192.168.222.130:1194/udp)
PREP='
cat >/tmp/exp.crt <<\EOF2
-----BEGIN CERTIFICATE-----
MIIBJzCBzaADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMMEmV4cGlyZWQt
bGFiLWNsaWVudDAeFw0yMDAxMDEwMDAwMDBaFw0yMDAxMDIwMDAwMDBaMB0xGzAZ
BgNVBAMMEmV4cGlyZWQtbGFiLWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABCNThmlnx/txRteMbFJW5cP/LqPcBTBfzPOjsa/1NFYZ0BJg7t0Z9xvkE6NH
Y9TTTOYufWOX+EdUZFAzZuchzW4wCgYIKoZIzj0EAwIDSQAwRgIhAPqxuBWVqSzD
Gqm3JbQkSvqucK47iY0MghOpwv6VgaGkAiEA2sFtLVEtcHfxIbIMxT9iAk9iTjrE
KptBTHcGUfo3QfE=
-----END CERTIFICATE-----
EOF2
cat >/tmp/exp.key <<\EOF2
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOGSMNp3D8HTJmhPm
izmpdemNoygJxl7I3ellm+1LI06hRANCAAQjU4ZpZ8f7cUbXjGxSVuXD/y6j3AUw
X8zzo7Gv9TRWGdASYO7dGfcb5BOjR2PU00zmLn1jl/hHVGRQM2bnIc1u
-----END PRIVATE KEY-----
EOF2
cat >/tmp/mk.sh <<\EOF2
cd /etc/shunt/tunnels
{ sed -e "/<cert>/,/<\/cert>/d" -e "/<key>/,/<\/key>/d" intern.ovpn; echo "<cert>"; cat /tmp/exp.crt; echo "</cert>"; echo "<key>"; cat /tmp/exp.key; echo "</key>"; } >expired.ovpn
chmod 600 expired.ovpn
EOF2
sudo -n bash /tmp/mk.sh
install -m755 /usr/bin/curl /tmp/labexp && sudo -n install -m755 /tmp/labexp /usr/local/bin/labexp
'
NOTE="Das Client-Zertifikat ist selbstsigniert und seit 2020 abgelaufen (Wegwerfschluessel, nur im Test). Der Server lehnt es ab. Erwartung: Tunnel bleibt unten, labexp (an den Tunnel gebunden) kommt nie durch, nichts im Klartext, Status nie ok."
CLIENT='
sleep 10
for i in $(seq 8); do
  labexp -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL labexp kam durch (abgelaufenes Zertifikat)"
  sleep 0.5
done
st=$(sudo -n shunt status 2>&1); echo "$st"
if grep -E "^expired .* ok " <<<"$st" >/dev/null; then echo "FAIL Status zeigt den Tunnel mit abgelaufenem Zertifikat als ok"; fi
true
'
