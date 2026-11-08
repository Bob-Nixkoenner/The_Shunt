ID=MH02
TITLE="Multi-Hop: aeusserer Tunnel faellt aus, nichts im Klartext"
CONFIG=hop
EXPECT_CANARY=any
NOTE="Nach 6 s sperrt das Gateway CT130:51830 (tunnelkill). Kein Klartext und kein Versuch zu :51831 direkt am Gateway (der innere Hop darf nicht am aeusseren vorbei). Mitschnitt wie MH01 (CT130_IF=wgt1)."
during() { sleep 6; gw labctl mode tunnelkill; }
CLIENT='
1..12 | ForEach-Object {
  & C:\lab\labtun.exe -s -m2 -o NUL "http://$_-$c/"
  Resolve-DnsName "d$_-$c" -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep 1
}
'
