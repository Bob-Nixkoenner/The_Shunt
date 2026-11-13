# Same variables as lab-addr.sh for PowerShell use. Neutral defaults; own values in lab-addr.local.ps1 (ignored by git).
# The test bodies get their addresses substituted on the host (lab_subst in lab-addr.sh), so the guest needs no copy.
$LAB_EXIT_IP     = if ($env:LAB_EXIT_IP) { $env:LAB_EXIT_IP } else { "198.51.100.230" }
$LAB_NET_WG      = if ($env:LAB_NET_WG) { $env:LAB_NET_WG } else { "10.166.0." }
$LAB_NET_OVPN    = if ($env:LAB_NET_OVPN) { $env:LAB_NET_OVPN } else { "10.167.0." }
$LAB_NET_OVPN_TCP = if ($env:LAB_NET_OVPN_TCP) { $env:LAB_NET_OVPN_TCP } else { "10.168.0." }
$LAB_NET_HOP     = if ($env:LAB_NET_HOP) { $env:LAB_NET_HOP } else { "10.169.0." }
$LAB_NET_LAN     = if ($env:LAB_NET_LAN) { $env:LAB_NET_LAN } else { "192.168.250." }
$LAB_WG_SRV      = "${LAB_NET_WG}1"
$LAB_OVPN_SRV    = "${LAB_NET_OVPN}1"
$LAB_HOP_SRV     = "${LAB_NET_HOP}1"
$LAB_TUNNEL_IP   = "${LAB_NET_WG}12"
$LAB_TUNNEL_IP_WIN = "${LAB_NET_WG}15"
$local = Join-Path $PSScriptRoot "lab-addr.local.ps1"
if (Test-Path $local) { . $local }
