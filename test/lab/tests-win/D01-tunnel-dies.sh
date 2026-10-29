ID=D01
TITLE="Tunnel fällt mitten im Betrieb aus: nichts im Klartext"
EXPECT_CANARY=any
NOTE="Nach 6 s schaltet das Gateway den Tunnel-Server weg (Modus tunnelkill)."
during() { sleep 6; gw labctl mode tunnelkill; }
CLIENT='
1..12 | ForEach-Object {
  & C:\lab\labtun.exe -s -m2 -o NUL "http://$_-$c/"
  & C:\lab\labfree.exe -s -m2 -o NUL http://1.1.1.1/
  Resolve-DnsName "d$_-$c" -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep 1
}
'
