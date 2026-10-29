ID=D03
TITLE="shuntd stürzt ab (kill -9): Kill-Switch hält bis zum Neustart"
EXPECT_CANARY=any
CLIENT='
sudo -n systemctl kill -s KILL shuntd
for i in 1 2 3 4 5; do labtun -s -m2 -o /dev/null http://1.1.1.1/ ; labfree -s -m2 -o /dev/null "http://$i-$1/" ; sleep 1; done
sleep 5; systemctl is-active shuntd
'
