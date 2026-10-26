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
