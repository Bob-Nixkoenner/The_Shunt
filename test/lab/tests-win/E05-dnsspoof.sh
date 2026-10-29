ID=E05
TITLE="Netz fälscht alle DNS-Antworten"
MODE=dnsspoof
ALLOW=(comm:* dns)
EXPECT_CANARY=any
NOTE="Windows: ohne Prozess-Zuordnung, daher ist hier jeder Klartext erlaubt; entscheidend ist, ob die Tunnel-App die gefälschte Antwort bekommt."
CLIENT='
$b = & C:\lab\labtun.exe -s -m8 http://example.com/; if ("$b" -like "*shuntlab gateway*") { "FAIL Tunnel-App bekam die gefälschte Antwort" }
$b = & C:\lab\labdir.exe -s -m8 http://example.com/; if ("$b" -like "*shuntlab gateway*") { "INFO direkte App bekam die gefälschte Antwort (erwartet)" }
'
