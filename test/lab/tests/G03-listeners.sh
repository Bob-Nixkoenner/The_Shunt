ID=G03
TITLE="Lauschende Dienste: shuntd-Web-UI/API nur lokal?"
EXPECT_CANARY=any
CLIENT='
sudo -n ss -Htlnp | awk "{print \$4, \$6}" | sed "s/^/tcp: /"
sudo -n ss -Htlnp | grep -E "shunt" | grep -vE "127\.0\.0\.1|\[::1\]|/run/" && echo "FAIL shunt lauscht nicht nur lokal"
true
'
