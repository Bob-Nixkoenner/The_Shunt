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

**Arch, CachyOS, Fedora clients take a `.tar`, not the `.deb`.** Build it only
with the script, never by packing the `.deb` data yourself:

```sh
test/lab/make-files-tar.sh the-shunt_<version>_amd64.deb the-shunt-files.tar arch   # or fedora
lab.sh client-prep the-shunt-files.tar
```

The `.deb` data has `./lib/systemd/...` and `./usr/sbin/...`. On those systems
`/lib` and `/usr/sbin` are symlinks, and `tar -C / -xf` replaces a symlink by a
real directory: the client then boots into emergency mode and the snapshot is
lost. The script moves `lib/` to `usr/lib/`, leaves out `usr/sbin` and checks
that the tar has no entry that would replace a system symlink.

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
  `kali-net` also sets the NIC `up` (it can come up as link DOWN). `kali-sync` writes `~/attacker/lab.env` with `KALI_IP`;
  `attacker/common.sh` picks the lab interface as the NIC in that subnet, not the one with the default route (the NAT NIC for ssh).
- Observer (`attacker/observer.sh`): run `sudo suricata-update` once on Kali (needs internet), otherwise Suricata has no rules
  and the observer prints only flows; `observer.sh start` warns "0 Regeln geladen" in that case. The observer's summary
  is collected on the laptop by the test's `during()` (the CLIENT script runs in the VM and cannot read laptop files) and appears in
  the report under "Prüfung nebenher" ("Beobachter sah:"), also as `observer.txt` in the result folder.
- `gw-setup` runs `dpkg --configure -a` first (180 s timeout) and only warns when it fails or hangs, e.g. kernel modules
  installed without their image; if `apt-get install` then fails too, repair dpkg in the gateway by hand.
- Packages built from a git worktree carry no commit: Go embeds VCS data only for the main checkout, so the build check
  warns "no commit in the client's shuntd". That is expected there; compare by package file name or version (e.g. `abwehrN` in the
  version string) instead, or build with `BUILD_CHECK=off`.
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
- Clock: `LABMARK` times are the client's clock, `gw.pcap` the gateway's; the two guests differ by up to about 1 s
  (measured 0.6–0.8 s). For a test with `LABMARK`, the runner sends three clock probes (ping to the gateway on the
  direct route, payload = ping's send time + `LABCLOCK`) before and after the client script; the analyzer shifts the
  strict window and `tor_end` by the median offset, leaves the probes out and prints the offset in the report.
  Without the shift, packets sent before a switch looked like leaks after it (H01 on CachyOS, 2026-11-13).

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

## Gesamtdurchlauf (Abwehr-Suite)

`run-defense-suite.sh` runs Q01, Q02, Q03, R01-R08 in one go (R07 last, it waits 660 s for the learning phase).

```sh
./run-defense-suite.sh --dry-run                 # list only, touches nothing
./run-defense-suite.sh --client shunt-debian     # full run
./run-defense-suite.sh --skip R07 --cooldown 90  # without the learning-phase test
./run-defense-suite.sh --only R04,R05 --snapshot-reset lab-basis
```

Options: `--only`, `--skip`, `--client`, `--cooldown SEC` (default 60), `--snapshot-reset SNAP` (retry from a snapshot),
`--shutdown-vms` (only VMs the script started), `--ignore-belegung`, `--dry-run`, `--help`.

Before the start it checks the booking list, running VMs, temperature (pause above 75 C until below 68 C, 15 min at most),
`CLIENT_VM`, `local.env`, the build revision of the client package against `git rev-parse --short HEAD` (warning without a
VCS stamp), runs `kali-sync`, checks Kali's link/IP and runs `suricata-update` once when Kali has 0 rules. Per test it
restarts `shuntd`, runs `lab.sh run <T>` with a limit (20 min, R07 30 min) and retries once on FUND/FEHLER.
Results: `$LAB_OUT/<date>/suite-<time>/` with `suite-report.md` (table test, result, duration, heat max, events by kind,
one-line note) and `suite.log`. Local only, never in git.

## Addresses of your own lab

The repo only has neutral addresses (`NEUTRAL-ADDRESSES.md`). `lab-addr.sh` defines them as variables and
loads `lab-addr.local.sh` (ignored by git, template `lab-addr.local.sh.example`) with your real values;
`lab.sh` and `run-mh.sh` source it. Test files use `@LAB_...@` placeholders that `run-test.sh` replaces
on the host before anything is sent to a VM, so the Linux and Windows guests need no copy of the file.
`lab-addr.ps1` / `lab-addr.local.ps1` are the same for your own PowerShell use. Without a local file
the tests expect the neutral exit address and fail on a real lab.
