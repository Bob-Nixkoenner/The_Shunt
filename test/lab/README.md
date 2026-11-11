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

## Machine-specific files (not in git)

`local.env.example` lists every variable (placeholders only). `local.env` holds the account (`USER_VM`), the test server (`CT130=user@address`) and `LAB_VPN_DIR`: the folder with the
VPN client configs of the test server (`wg-intern-linux-test.conf`, `ovpn-intern-linux-test.ovpn`, `wg-hop-*.conf`, test
keys). Without `LAB_VPN_DIR` the lab looks in `test/lab/vpn/` (ignored by git). The tests take the server's address from
`CT130` (`$CT130_IP`), none carries an address of its own.

### Attack tests (Q/R) and the attacker VM

- `lab.sh kali-sync` copies `attacker/` to `~/attacker/` on Kali and makes the scripts executable; the R tests call
  `kali_sync` themselves before they start an attack (a stale or non-executable copy was a cause of silent R-test failures).
- R02 (`brute-telnet-ssh.sh`) uses `attacker/brute.py`, a small standard-library Python 3 script, instead of Hydra:
  Hydra hangs against the telnet decoy's correct IAC option negotiation. The SSH part needs `python3-paramiko` on
  Kali (`apt install python3-paramiko`); without it, `brute.py ssh` prints that and exits non-zero, but the telnet
  part still runs. `brute.py selftest` runs a self-check against a local mini telnet server (and reports whether
  paramiko is present) without touching the lab network.
- `attacker/common.sh`'s `pick HOST PORT...` picks the first candidate port that actually accepts a TCP connect
  (`nc -z` or `/dev/tcp`, short timeout), not just the first one in the list; it returns non-zero and prints nothing
  when none of the candidates answer, so a caller that does not check the exit code is a bug, not a feature.
- Kali gets a fixed address outside the DHCP pool: set `KALI_IP` (see `local.env.example`) and run `lab.sh kali-net`.
  `gw-setup` writes it to `/etc/shuntlab/kali_ip`, and `labctl client` never returns Kali (by address or host name `kali*`).
- `PREP` and `CLIENT` of a test run in the client VM, not on the laptop: laptop functions and variables are not there.
  A CLIENT script that ends with a non-zero exit code without printing a `FAIL` line (e.g. a missing `${VAR:?}`) counts as FAIL;
  set `CLIENT_RC_OK=1` in a test that ends non-zero on purpose.
- Before `lab.sh run` the build check compares the commit embedded in the client's `shuntd` (`vcs.revision`) with
  `git rev-parse --short HEAD` and warns about a mismatch (`BUILD_CHECK=strict` stops, `off` skips): rebuild after every commit.
- R07 (first_seen): the learning phase (10 min) is a constant in `internal/defense`, no switch: the test waits
  `FIRSTSEEN_LEARN_SECS` (default 660). Config `defense-firstseen.toml`.
- R08 (tls): Kali serves a lab name with a certificate of test CA A, then of test CA B (`attacker/tlsmitm.sh`);
  config `defense-tls.toml` (`shunt-tls.lab.test` via the client's `/etc/hosts`). The pin of CA A is written by the test;
  the real first pin (trusted network / second path) is not covered.
- `dnsname:<name>` in `ALLOW` allows DNS queries for exactly that name. The defense's active DNS check asks `dns.google` and
  `one.one.one.one` (at the network's resolver and at 9.9.9.9), so Q01/Q02/R01-R06 allow them; Q03 runs with
  `defense.dns_probe = off` and must NOT see them.

### No internet in the lab LAN (apt)

The lab LAN has no internet, so `apt-get update` in `client-prep` used to hang. `prep.sh` now bounds it
(`PREP_APT_TIMEOUT`, default 60 s) and goes on with the existing package lists; packages that are not installed or cached
then fail at `apt-get install`. The Debian run used an `apt-get` wrapper that ignored `update`; either install the tools
(bpftrace, dnsutils, netcat-openbsd, curl) first while the VM has NAT (`lab.sh detach`) or point apt at a local mirror,
then run `client-prep`. A real offline mode (local package cache) is still missing.

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

## Reihenfolge im Gesamtlauf (Linux)
- **P01 immer als Letztes** (nach allen anderen Tests): P01 stellt die Uhr +10 min und zurueck, danach antwortet der VirtualBox-Gastdienst nicht mehr, alle folgenden Tests melden "Client nicht erreichbar".
- **M07** installiert das neueste Paket aus `$LAB_OUT/debs/`: dort muss das zu testende Paket (z. B. rk3j) das neueste sein, sonst laeuft der Rest des Laufs mit einer alten Version (Kopf von `report.md` pruefen: "Shunt: ...").
