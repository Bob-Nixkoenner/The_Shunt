# D05 check: are the kill switch and quiet filters still there after an orderly
# restart, BEFORE the Shunt service runs?  (as administrator, e.g. via VirtualBox guest control)
#
#   d05-check.ps1 -Phase now                      count only (state now)
#   d05-check.ps1 -Phase before -Mode running     count, service Disabled, restart WITH the service running
#   d05-check.ps1 -Phase before -Mode stopped     count, stop the service, Disabled, restart
#                                                 (the service's shutdown path does NOT run)
#   d05-check.ps1 -Phase after                    after the boot: count (service not running), compare,
#                                                 service back to Automatic and started
#   -NoRestart: "before" does not restart itself (the caller runs Restart-Computer)
#
# Output: C:\lab\d05\<time>-<phase>.txt (+ filters/boottime XML), comparison at the end.
# Keys (internal/winsplit/wfp): kill switch persistent 5e4a7dxx, kill switch boot 5e4a80xx,
# quiet persistent 5e4a7fxx, quiet boot 5e4a81xx; providers 5e4a7c10 (kill switch), 5e4a7c30 (quiet).
param(
    [ValidateSet('now', 'before', 'after')][string]$Phase = 'now',
    [ValidateSet('running', 'stopped')][string]$Mode = 'running',
    [switch]$NoRestart
)
$ErrorActionPreference = 'Continue'
$dir = 'C:\lab\d05'
New-Item -ItemType Directory -Force $dir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# Keys: any GUID of ours (...-5f3b-4c2e-9a61-5348554e54xx), wherever it stands
# and with or without braces (netsh wfp show boottimepolicy writes another XML
# than show filters: no <filterKey>{...} there, the old pattern counted 0).
# Each key once.
function Count-Keys([string]$xmlPath) {
    $c = [ordered]@{ ks_persist = 0; ks_boot = 0; quiet_persist = 0; quiet_boot = 0 }
    if (-not (Test-Path $xmlPath)) { return $c }
    $txt = Get-Content -Raw $xmlPath
    $seen = @{}
    foreach ($m in [regex]::Matches($txt, '([0-9a-f]{8})-5f3b-4c2e-9a61-5348554e54[0-9a-f]{2}', 'IgnoreCase')) {
        $k = $m.Value.ToLower()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = 1
        $d1 = [Convert]::ToUInt32($m.Groups[1].Value, 16)
        if ($d1 -ge 0x5e4a7d00 -and $d1 -lt 0x5e4a7d80) { $c.ks_persist++ }
        elseif ($d1 -ge 0x5e4a8000 -and $d1 -lt 0x5e4a8080) { $c.ks_boot++ }
        elseif ($d1 -ge 0x5e4a7f00 -and $d1 -lt 0x5e4a7f80) { $c.quiet_persist++ }
        elseif ($d1 -ge 0x5e4a8100 -and $d1 -lt 0x5e4a8180) { $c.quiet_boot++ }
    }
    return $c
}

# Names (display data), for XML without keys: the quiet filters are all named
# "Quiet: ..." (58 per set since the D05 fix: 29 rules x ALE connect + outbound
# transport), the kill switch's carry the wireguard-windows names. show filters
# lists the persistent filters (and loaded boot-time copies), show
# boottimepolicy only the boot-time copies.
$ksNames = '^(Permit (unrestricted (in|out)bound traffic for The Shunt service|(in|out)bound (IPv[46] traffic on TUN|on loopback|DHCP (request|response)|traffic (to|from) the local network)|NDP type 13[3-7]|Hyper-V => Hyper-V)|(Allow|Block) DNS (in|out)bound|Block all (in|out)bound)'
function Count-Names([string]$xmlPath) {
    $c = [ordered]@{ ks = 0; quiet = 0; quiet_transport = 0 }
    if (-not (Test-Path $xmlPath)) { return $c }
    $txt = Get-Content -Raw $xmlPath
    foreach ($m in [regex]::Matches($txt, '<name>([^<]*)</name>')) {
        $n = $m.Groups[1].Value
        if ($n -like 'Quiet:*') {
            $c.quiet++
            if ($n -like '*outbound transport*') { $c.quiet_transport++ }
        } elseif ($n -match $ksNames) { $c.ks++ }
    }
    return $c
}

function Snapshot([string]$tag) {
    $f = Join-Path $dir "$stamp-$tag-filters.xml"
    $b = Join-Path $dir "$stamp-$tag-boottime.xml"
    netsh wfp show filters file=$f | Out-Null
    netsh wfp show boottimepolicy file=$b | Out-Null
    $loaded = Count-Keys $f
    $stored = Count-Keys $b
    $loadedN = Count-Names $f
    $storedN = Count-Names $b
    $svc = Get-Service Shunt -ErrorAction SilentlyContinue
    $prov = (Select-String -Path $f -Pattern '5e4a7c10|5e4a7c30' -AllMatches -ErrorAction SilentlyContinue | Measure-Object).Count
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $lines = @(
        "phase=$tag mode=$Mode time=$(Get-Date -Format o) lastboot=$($boot.ToString('o'))",
        "service status=$($svc.Status) start=$($svc.StartType)",
        "loaded (show filters):        ks_persist=$($loaded.ks_persist) ks_boot=$($loaded.ks_boot) quiet_persist=$($loaded.quiet_persist) quiet_boot=$($loaded.quiet_boot) provider-refs=$prov",
        "stored (show boottimepolicy): ks_boot=$($stored.ks_boot) quiet_boot=$($stored.quiet_boot) (persistent keys in it: ks=$($stored.ks_persist) quiet=$($stored.quiet_persist))",
        "by name (show filters):        ks=$($loadedN.ks) quiet=$($loadedN.quiet) quiet_transport=$($loadedN.quiet_transport)",
        "by name (show boottimepolicy): ks=$($storedN.ks) quiet=$($storedN.quiet) quiet_transport=$($storedN.quiet_transport)",
        "expected with the D05 fix: quiet 58 persistent + 58 boot (29 of each at outbound transport), equal before and after a restart"
    )
    $lines | Set-Content (Join-Path $dir "$stamp-$tag.txt")
    $lines | ForEach-Object { Write-Output $_ }
}

switch ($Phase) {
    'now' { Snapshot 'now' }
    'before' {
        Snapshot "before-$Mode"
        Set-Content (Join-Path $dir 'mode.txt') $Mode
        if ($Mode -eq 'stopped') {
            Stop-Service Shunt -ErrorAction SilentlyContinue
            (Get-Service Shunt).WaitForStatus('Stopped', '00:00:30')
            Snapshot 'before-stopped-after-stop'
        }
        # the service must not start after the boot: the count then shows what Windows loaded on its own
        Set-Service Shunt -StartupType Disabled
        if (-not $NoRestart) { Restart-Computer -Force }
    }
    'after' {
        $m = Get-Content (Join-Path $dir 'mode.txt') -ErrorAction SilentlyContinue
        if ($m) { $Mode = $m }
        Snapshot "after-$Mode"
        # shutdown and boot events (service stop, BFE, who restarted)
        Get-WinEvent -FilterHashtable @{LogName = 'System'; StartTime = (Get-Date).AddMinutes(-20); Id = 1074, 6005, 6006, 6008, 7036, 7031, 7043 } -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -ne 7036 -or $_.Message -match 'Shunt|Base Filtering|Basisfiltermodul|BFE' } |
            Sort-Object TimeCreated | ForEach-Object { '{0:HH:mm:ss} {1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -split "`n")[0] } |
            Tee-Object -FilePath (Join-Path $dir "$stamp-events.txt")
        Write-Output '--- before -> after (no service) ---'
        Get-ChildItem $dir -Filter '*-before-*.txt' | Where-Object { $_.Name -notmatch 'after-stop' } | Sort-Object Name | Select-Object -Last 1 | ForEach-Object { Get-Content $_.FullName }
        Get-ChildItem $dir -Filter '*-after-*.txt' | Sort-Object Name | Select-Object -Last 1 | ForEach-Object { Get-Content $_.FullName }
        Set-Service Shunt -StartupType Automatic
        Start-Service Shunt -ErrorAction SilentlyContinue
        Write-Output "service restarted: $((Get-Service Shunt).Status)"
    }
}
