#Requires -RunAsAdministrator
# Removes The Shunt. -Purge also deletes the config, tunnels and traffic statistics.
param([string]$Dir = "$env:ProgramFiles\The Shunt", [switch]$Purge)
$ErrorActionPreference = 'Continue'
Get-Process shunt-desktop -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service Shunt -ErrorAction SilentlyContinue) {
    Stop-Service Shunt -ErrorAction SilentlyContinue
    Start-Sleep 2
    & "$Dir\shuntd-win.exe" uninstall
}
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\The Shunt.lnk" -ErrorAction SilentlyContinue
Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name TheShunt -ErrorAction SilentlyContinue
# launchers of this user (shortcuts only; %USERPROFILE%\ShuntProfiles holds junctions to browser profiles and is left alone)
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\The Shunt Launchers" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item "$env:ProgramData\Shunt" -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'The Shunt is removed.' $(if (-not $Purge) { "Config kept in $env:ProgramData\Shunt (use -Purge to delete it)." })
