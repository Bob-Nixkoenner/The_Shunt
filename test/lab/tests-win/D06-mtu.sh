ID=D06
TITLE="Große Pakete/Downloads durch den Tunnel (MTU)"
EXPECT_CANARY=any
CLIENT='
& C:\lab\labtun.exe -s -m20 -o NUL -w "Download %{size_download} B in %{time_total}s\n" "https://speed.cloudflare.com/__down?bytes=5000000"; if ($LASTEXITCODE -ne 0) { "FAIL Download durch den Tunnel hängt" }
$f = "C:\lab\up.bin"; $b = New-Object byte[] 300000; (New-Object Random).NextBytes($b); [IO.File]::WriteAllBytes($f, $b)
& C:\lab\labtun.exe -s -m20 -o NUL -w "Upload %{size_upload} B\n" --data-binary "@$f" https://speed.cloudflare.com/__up; if ($LASTEXITCODE -ne 0) { "FAIL Upload durch den Tunnel hängt" }
'
