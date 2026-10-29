ID=W01
TITLE="Blocklisten-Download geht nicht direkt ins fremde Netz"
CONFIG=filter
EXPECT_CANARY=any
NOTE="Mit eingeschaltetem DNS-Filter lädt der Dienst die Listen (raw.githubusercontent.com). Standardweg ist der Tunnel, also darf der Download nicht direkt am Gateway auftauchen."
# empty cache: otherwise the restart downloads nothing and the test proves nothing
CLIENT='
Stop-Service Shunt -Force -WarningAction SilentlyContinue
Remove-Item -Recurse -Force C:\ProgramData\Shunt\blocklists -ErrorAction SilentlyContinue
Start-Service Shunt -WarningAction SilentlyContinue
Start-Sleep 40
"lists: " + (Get-ChildItem C:\ProgramData\Shunt\blocklists -ErrorAction SilentlyContinue).Count
Get-Content C:\ProgramData\Shunt\shuntd.log -Tail 4
'
