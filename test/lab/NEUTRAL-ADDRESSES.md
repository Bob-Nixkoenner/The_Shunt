# Neutral lab addresses

The repo only contains these placeholder addresses. Your real lab values go into
`lab-addr.local.sh` / `lab-addr.local.ps1` (ignored by git, see `lab-addr.local.sh.example`).

| Variable | Neutral value | Meaning |
|---|---|---|
| `LAB_EXIT_IP` | `198.51.100.230` | address the tunnel exit shows to the internet |
| `LAB_NET_WG` | `10.166.0.` | WireGuard net of the exit |
| `LAB_NET_OVPN` | `10.167.0.` | OpenVPN (UDP) net |
| `LAB_NET_OVPN_TCP` | `10.168.0.` | OpenVPN (TCP 443) net |
| `LAB_NET_HOP` | `10.169.0.` | inner hop net |
| `LAB_NET_LAN` | `192.168.250.` | lab LAN |

Test files use `@LAB_...@` placeholders in single-quoted bodies; `run-test.sh` fills them in on the host
(`lab_subst`). Unit-test fixtures and docs use the neutral values (`10.207.0.`, `10.208.0.`, ...) directly.
Server addresses in the history use `203.0.113.0/24` and `198.51.100.0/24`.
