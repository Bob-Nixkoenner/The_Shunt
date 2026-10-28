ID=N03
TITLE="kill -9 shuntd waehrend Apps senden, danach Neustart durch systemd"
EXPECT_CANARY=any
NOTE="Wie D03, aber mit mehreren Absturzen hintereinander."
during() { sleep 4; for i in 1 2 3; do client 'sudo -n pkill -9 shuntd'; sleep 5; done; }
CLIENT='
for i in $(seq 30); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labfree-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.7
done
true
'
