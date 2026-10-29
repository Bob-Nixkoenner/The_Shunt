ID=F01
TITLE="Tarnung: was verrät das Gerät beim Verbinden?"
RENEW=1
CHECKS=(fingerprint)
EXPECT_CANARY=any
NOTE="Neu verbinden, dann 20 s still mithören: DHCP-Optionen, MAC, IPv6-Adressen, mDNS/LLMNR."
CLIENT='sleep 20; hostnamectl --static; ip -6 addr show scope global | grep inet6; true'
