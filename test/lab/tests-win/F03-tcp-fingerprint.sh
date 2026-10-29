ID=F03
TITLE="TCP/IP-Fingerabdruck an der Gegenseite (p0f an CT130)"
EXPECT_CANARY=any
CLIENT='
foreach ($u in "http://example.com/","http://neverssl.com/","http://1.1.1.1/") { & C:\lab\labtun.exe -s -m6 -o NUL $u }
'
