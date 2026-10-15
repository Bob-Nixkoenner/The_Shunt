The Shunt for Windows
=====================

Install (as Administrator):
    powershell -ExecutionPolicy Bypass -File install.ps1

Then start "The Shunt" from the Start menu. It shows a tray icon and opens the
window (Microsoft Edge in app mode). Right-click the tray icon for panic mode,
autostart and the update check.

Files (C:\ProgramData\Shunt):
    shunt.toml    the configuration (same format as on Linux; the window edits it)
    tunnels\      WireGuard files (readable by Administrators and SYSTEM only)
    shuntd.log    service log
    stats.json    traffic per tunnel and month

What works: per-program routes by file name (app = ["firefox"] or
exe:C:\path\app.exe), rules by address / port / domain, WireGuard tunnels,
panic mode, 1-60 minute pass, leak test, Wi-Fi profiles by name.
Not yet: OpenVPN, link:* routes, groups, DNS filter, app firewall, kill
switch when the service is stopped.

Uninstall: powershell -ExecutionPolicy Bypass -File uninstall.ps1  [-Purge]
