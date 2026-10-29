ID=F03
TITLE="TCP/IP-Fingerabdruck an der Gegenseite (p0f an CT130)"
EXPECT_CANARY=any
CLIENT='
for u in http://example.com/ http://neverssl.com/ http://1.1.1.1/; do labtun -s -m6 -o /dev/null "$u"; done
true
'
