#Requires -RunAsAdministrator
# Installs (or updates) The Shunt for Windows from the folder this script is in.
#   powershell -ExecutionPolicy Bypass -File install.ps1
param([string]$Dir = "$env:ProgramFiles\The Shunt")
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in 'shuntd-win.exe', 'shunt-desktop.exe', 'wintun.dll') {
    if (-not (Test-Path "$here\$f")) { throw "$f is missing next to install.ps1" }
}

$svc = Get-Service Shunt -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service Shunt; $svc.WaitForStatus('Stopped', '00:00:30') }
Get-Process shunt-desktop -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1

New-Item -ItemType Directory -Force $Dir | Out-Null
Copy-Item "$here\shuntd-win.exe", "$here\shunt-desktop.exe", "$here\wintun.dll" $Dir -Force
if (Test-Path "$here\the-shunt.ico") { Copy-Item "$here\the-shunt.ico" $Dir -Force }
if (Test-Path "$here\README.txt") { Copy-Item "$here\README.txt" $Dir -Force }
foreach ($ps in 'uninstall.ps1') { if (Test-Path "$here\$ps") { Copy-Item "$here\$ps" $Dir -Force } }

if (-not $svc) { & "$Dir\shuntd-win.exe" install; if ($LASTEXITCODE) { throw 'service install failed' } }
else { sc.exe config Shunt binPath= "`"$Dir\shuntd-win.exe`"" | Out-Null }
Start-Service Shunt

$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\The Shunt.lnk")
$lnk.TargetPath = "$Dir\shunt-desktop.exe"
if (Test-Path "$Dir\the-shunt.ico") { $lnk.IconLocation = "$Dir\the-shunt.ico" }
$lnk.Description = 'The Shunt - per-app split tunneling'
$lnk.Save()

Write-Host "The Shunt is installed in $Dir and the service runs."
Write-Host "Start 'The Shunt' from the Start menu. Config: $env:ProgramData\Shunt\shunt.toml"
