ID=D06
TITLE="Große Pakete/Downloads durch den Tunnel (MTU)"
EXPECT_CANARY=any
CLIENT='
labtun -s -m20 -o /dev/null -w "Download %{size_download} B in %{time_total}s\n" https://speed.cloudflare.com/__down?bytes=5000000 || echo "FAIL Download durch den Tunnel hängt"
head -c 300000 /dev/urandom | labtun -s -m20 -o /dev/null -w "Upload %{size_upload} B\n" --data-binary @- https://speed.cloudflare.com/__up || echo "FAIL Upload durch den Tunnel hängt"
'
