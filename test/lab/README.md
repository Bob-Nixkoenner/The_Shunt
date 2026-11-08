# Test lab

A client VM running Shunt sits behind a gateway VM that plays the untrusted
network (café Wi-Fi). Every test captures at three points and an analyzer puts
them side by side:

```
[client VM] ──intnet shuntlab──► [shunt-lab-gw] ──NAT──► … ──► [CT130 tunnel exit]
 1: bpftrace                      2: tcpdump, unbound,          3: tcpdump on wgt0
    process ↔ interface              dnsmasq, web log, nmap,
                                     attack modes
```

The rule at the gateway: the network may see tunnel transport to the
configured endpoints, link housekeeping (ARP, ND, DHCP) and what a test
explicitly allows. Everything else from the client is a finding, attributed to
a process through the client trace.

## Pieces

| Path | What |
|---|---|
| `lab.sh` | controller on the host (VirtualBox, no root needed) |
| `run-test.sh` | test runner, sourced by `lab.sh run` (test file format documented at the top) |
| `analyze.py` | analyzer, runs on the gateway (scapy, p0f) → `report.md`, `result.json` |
| `gw/` | gateway setup (`setup.sh`), `labctl` (modes, captures, scans), lab web server |
| `client/` | client setup (`prep.sh`), bpftrace tracer |
| `configs/` | `shunt.toml` variants for the client (`base`, `direct`, `allowlan`) |
| `tests/` | the tests, grouped A–G (route, DNS, IPv6, failures, hostile network, fingerprints, ports) |

The client is driven only through VirtualBox guest control, never over the
network: no management traffic in the captures, and a `default_route` into
the tunnel cannot cut the controller off.

Gateway modes (`lab.sh mode <m>`): `normal`, `tunnelvision` (DHCP option 121,
CVE-2024-3661), `localnet` (TunnelCrack LocalNet, the LAN claims 1.1.1.0/24),
`rogue-ra` (global-looking IPv6 prefix + RDNSS), `dnsspoof`, `captive`,
`tunnelkill`, `portsonly`. Plus `lab.sh netem <args>|off`.

Canary names (`<id>-<time>.shuntlab.test`): the gateway's unbound answers them,
so a canary seen at the gateway took the untrusted network; one seen in the
CT130 capture went through the tunnel.

## Setup (once)

```sh
lab.sh gw-create                  # linked clone of the client's "sauber" snapshot
VBoxManage startvm shunt-lab-gw --type headless
ssh-copy-id -i ~/.ssh/shunt-vm -p 2225 <user>@127.0.0.1
lab.sh gw-setup
lab.sh up sauber                  # client on the lab LAN
lab.sh client-prep the-shunt_<version>_amd64.deb   # → snapshot "lab-basis"
```

The client needs the VirtualBox Guest Additions, passwordless sudo and the
WireGuard config of the internal test server (`TUNNEL_CONF`, test keys, not in
git). The rogue DHCP/RA modes only ever run on the internal network `shuntlab`.

## Running

```sh
lab.sh up lab-basis      # fresh client
lab.sh run               # all tests; or: lab.sh run A01 E01 …
lab.sh detach            # client back to plain NAT (ssh :2224)
```

Results land in `~/projects/shunt-lab-results/<date>/<id>-<time>/` (pcaps,
logs, `report.md`). Keep pcaps out of git and shared folders: they may contain
clear text.

## Restore, promisc, CPU cap, multi-hop

- `lab.sh up <snapshot>` sets promisc on the physical NICs right after boot (old snapshots have no udev rule yet);
  `client-prep` does it before the first package download. A snapshot restore also resets the VirtualBox CPU cap:
  set `CLIENT_CAP` / `GW_CAP` (percent, e.g. 80) in `local.env` or the environment and `up` applies them again.
- `run-mh.sh`: the hop address (`HOPIP`) comes from the `Address` line of `HOP_CONF`
  (or `HOP_VM=<name>` -> `wg-hop-lab-<name>.conf`), not from the tunnel address.
- Analyzer: `LABMARK tor_end <epoch>` in the client output marks an intended end of tor; contentless TCP to port 9001
  within 15 s afterwards is reported as info. GitHub list downloads with a `direct` default route are info (#8).

## Windows client (CLIENT_OS=windows)

`CLIENT_OS=windows lab.sh run …` drives the Windows VM with PowerShell (`winclient.sh`, tests in `tests-win/`,
configs `configs/win-<CONFIG>.toml`). No process trace: findings come from the gateway/CT130 captures and the
`FAIL …` lines of the test scripts. Test IDs mirror the Linux ones where the test is the same idea.
The API is used through `curl.exe --unix-socket C:\ProgramData\Shunt\shuntd.sock` (status, reload).

Ported on 2026-11-08 (branch `lab-parity`, not run yet):

| Tests | What | Config |
|---|---|---|
| M01, M02 | ARP / CVE-2019-14899 against the tunnel address and the Shunt adapter address 10.111.0.2 | `win-base` |
| M03 | reload (API) and `Restart-Service` while apps send | `win-base` |
| M04 | rule on a tunnel with dead endpoint / wrong key (PREP writes `dead.conf`, `badkey.conf`, `labtog.exe`) | `win-m-broken` |
| M05 | rule switched live tunnel → direct → tunnel; "direct" is told by the exit IP (LAN targets always go direct on Windows) | `win-m-toggle` |
| FL01–FL03, FL07, FL08 | DNS filter with a local list (`C:\ProgramData\Shunt\lab-filter.txt`, PREP); only the `default` level exists on Windows, so no FL04 | `win-filter-lab`, `win-filter-lab-allow` |
| H04, H05, H06, H08 | Tor as app route: tor.exe suspended/killed, isolation, obfs4 bridges, `.onion` names. tor.exe's relay connections are allowed through the client's consensus (`LABALLOW`) | `win-tor-app`, `win-tor-bridge` |
| MH01–MH03, MH08 | WireGuard in WireGuard (`via`); the hop file is `WIN_HOP_CONF` (default `wg-hop-lab-win.conf`), installed by `winclient.sh`, `HOP_BADKEY=1` for MH03 | `win-hop` |

Multi-hop capture on CT130 (like `run-mh.sh`):

```sh
HOPIP=$(sed -n 's|^Address *= *\([0-9.]*\)/.*|\1|p' "$WIN_HOP_CONF" | head -n1)
CLIENT_OS=windows CT130_IF=wgt1 TUNNEL_IP=$HOPIP ./lab.sh run MH01 MH02 MH08
CLIENT_OS=windows CT130_IF=wgt0 ./lab.sh run MH03
```

Not ported because Windows lacks the feature: tor-all (H01–H03, H09–H11), Tor `via` (H07), OpenVPN (O*, MH04, MH05),
`dns_filter` per rule (FL04), `panic_kill` (P03), forwarded traffic (M06, M09).
