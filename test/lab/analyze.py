"""Lab analyzer: puts the three measuring points of one test side by side.

    python3 analyze.py <test dir>

The test dir holds meta.json (written by run-test.sh) and whatever was
captured: gw.pcap + unbound/dnsmasq/web logs (gateway), trace.log (client,
bpftrace), ct130.pcap (tunnel exit), scan-*.txt (nmap). Writes report.md and
result.json next to them. Runs on the gateway (needs scapy, p0f).

Rule at the gateway: the untrusted network may see tunnel transport to the
configured endpoints, link housekeeping (ARP, ND, DHCP, IGMP/MLD) and what the test
explicitly allows. Everything else from the client is a finding.
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
from collections import Counter, defaultdict

from scapy.all import (ARP, DHCP, DNS, DNSQR, ICMPv6ND_NS, IP, TCP, UDP, BOOTP, IPv6, Ether,
                       PcapReader, Raw)
from scapy.layers.dhcp6 import DHCP6, DHCP6OptClientId, DHCP6OptClientFQDN

D = sys.argv[1]
meta = json.load(open(os.path.join(D, "meta.json")))
CANARY = meta.get("canary", "").lower().rstrip(".")
client_mac = (meta.get("client_mac") or "").lower()
endpoints = set()
# Shunt's portal check (internal/captive), direct by design
CAPTIVE_HOSTS = {b"nmcheck.gnome.org"}
captive_dsts = set()
for _h in CAPTIVE_HOSTS:  # also SYNs that never got an answer (IPv6 in the lab)
    try:
        captive_dsts.update(a[4][0] for a in socket.getaddrinfo(_h.decode(), 80, proto=socket.IPPROTO_TCP))
    except OSError:
        pass
for e in meta.get("endpoints", []):  # ip:port/proto
    ip, rest = e.rsplit(":", 1)
    port, proto = rest.split("/")
    endpoints.add((ip, int(port), proto))
endpoint_ips = {e[0] for e in endpoints}
allow = meta.get("allow", [])
allow_comms = {a[5:] for a in allow if a.startswith("comm:")}
allow_dst = set()
for a in allow:
    if a.startswith("dst:"):
        ip, rest = a[4:].rsplit(":", 1)
        port, proto = rest.split("/")
        allow_dst.add((ip, int(port), proto))
# net:<cidr>:<port>/<proto>: a whole network (addresses that rotate, e.g. a
# distribution's connectivity check)
allow_net = []
for a in allow:
    if a.startswith("net:"):
        cidr, rest = a[4:].rsplit(":", 1)
        port, proto = rest.split("/")
        allow_net.append((ipaddress.ip_network(cidr, strict=False), int(port), proto))


def allowed_net(dst, dport, proto):
    try:
        ip = ipaddress.ip_address(dst)
    except ValueError:
        return False
    return any(ip in n and dport == p and proto == pr for n, p, pr in allow_net)


allow_dns = "dns" in allow
strict_fp = "fingerprint" in meta.get("checks", [])

findings = []  # (severity, group, text)


def find(sev, group, text):
    findings.append((sev, group, text))


def p(name):
    return os.path.join(D, name)


# --- Messpunkt 1: client trace -------------------------------------------------
trace = defaultdict(list)  # (dst, dport) -> [(comm, dev)]
trace_lines = 0
if os.path.exists(p("trace.log")):
    for line in open(p("trace.log"), errors="replace"):
        f = line.split()
        if len(f) != 9 or not f[0].isdigit():
            continue
        trace_lines += 1
        _, pid, comm, dev, proto, src, dst, dport, ln = f
        trace[(dst, int(dport))].append((comm, dev))


def who(dst, dport):
    """Processes that sent to dst:dport outside the tunnels; "kernel" = no user socket."""
    hits = [c for c, dev in trace.get((dst, dport), []) if not dev.startswith("sh-")]
    if not hits:
        return "?"
    named = [c for c in hits if c != "-"]
    if not named:
        return "kernel"
    return ", ".join(k for k, _ in Counter(named).most_common(3))


def allowed_comm(w):
    if "*" in allow_comms:  # no process trace (Windows client): allow whatever the test allows
        return True
    return w not in ("?", "kernel") and {x.strip() for x in w.split(",")} <= allow_comms


# --- Messpunkt 2: gateway ------------------------------------------------------
PROTO = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}
BROADCAST_NAMES = {5353: "mDNS", 5355: "LLMNR", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 1900: "SSDP",
                   3702: "WS-Discovery", 1716: "KDE Connect", 21027: "Syncthing-Discovery"}
# their payload carries the device name / a device ID that follows you across networks
PAYLOAD_IDS = re.compile(rb'"(deviceName|deviceId|id)"\s*:\s*"([^"]{1,64})"|(SYNC|deviceID)[^\x00]{0,8}')
fp = defaultdict(set)  # fingerprint facts seen by the network
gw_flows = Counter()  # (dst, port, proto, who) -> packets, for findings
tunnel_pkts = Counter()
gw_dns = []  # qnames asked through the untrusted network
captive_checks = Counter()
client_ips = set(meta.get("client_ips", []))
names = {}  # ip -> name, from DNS answers seen anywhere
inbound = set()  # (remote ip, remote port, client port) of connections opened towards the client
outbound = set()  # (remote ip, remote port, client port) the client opened
replies_lan = Counter()  # answers to the untrusted network's own probes
http_fp = set()


def learn_names(pkt):
    if DNS in pkt and pkt[DNS].qr == 1:
        for i in range(pkt[DNS].ancount or 0):
            try:
                rr = pkt[DNS].an[i]
                if rr.type in (1, 28):
                    names.setdefault(str(rr.rdata), rr.rrname.decode().rstrip("."))
            except Exception:
                pass


def label(ip):
    return f"{ip} ({names[ip]})" if ip in names else ip
src_v6 = set()
macs = set()


# per-network (F05): the client changes its MAC on purpose, so every sender
# on the lab LAN except the gateway is the client
any_mac = "per-network" in meta.get("checks", [])
gw_macs = set()
seen_by = defaultdict(set)  # (fingerprint key, value) -> sender MACs
if any_mac and os.path.exists(p("gw.pcap")):
    for pkt in PcapReader(p("gw.pcap")):
        # outer IP header only: ICMP errors from the client quote the
        # gateway's DHCP answers
        if Ether in pkt and IP in pkt and pkt[IP].src == "10.77.0.1":
            gw_macs.add(pkt[Ether].src.lower())


def is_client(pkt):
    if Ether not in pkt:
        return False
    if any_mac and gw_macs:
        return pkt[Ether].src.lower() not in gw_macs
    if client_mac:
        return pkt[Ether].src.lower() == client_mac
    return False


def eui64(addr, mac):
    if not mac:
        return False
    m = mac.split(":")
    iid = f"{int(m[0], 16) ^ 2:02x}{m[1]}:{m[2]}ff:fe{m[3]}:{m[4]}{m[5]}"
    return ipaddress.ip_address(addr).exploded.endswith(
        ipaddress.ip_address("::" + iid).exploded[-19:])


# strict window of the test (LABMARK lines, written right after the switch
# returned; client clock = gateway clock in the lab, guest time sync)
strict = meta.get("strict") or []
strict_from = bool(strict)
outside = 0


def in_strict(t):
    return any(a <= t and (b is None or t <= b) for a, b in strict)


if os.path.exists(p("gw.pcap")):
    for pkt in PcapReader(p("gw.pcap")):
        if Ether not in pkt:
            continue
        if strict and not in_strict(float(pkt.time)):
            outside += 1
            continue
        learn_names(pkt)
        if not is_client(pkt):
            if TCP in pkt and (pkt[TCP].flags & 0x12) == 0x02:  # SYN towards the client
                src = pkt[IP].src if IP in pkt else pkt[IPv6].src if IPv6 in pkt else ""
                inbound.add((src, pkt[TCP].sport, pkt[TCP].dport))
            # learn the client's MAC from DHCP if run-test.sh did not know it
            if not client_mac and BOOTP in pkt and pkt[BOOTP].op == 1:
                client_mac = pkt[Ether].src.lower()
            else:
                continue
        macs.add(pkt[Ether].src.lower())
        if ARP in pkt:
            continue
        if BOOTP in pkt and DHCP in pkt:
            for o in pkt[DHCP].options:
                if not isinstance(o, tuple):
                    continue
                k, v = o[0], o[1:]
                if k == "hostname":
                    fp["DHCP-Hostname (Opt. 12)"].add(v[0].decode(errors="replace"))
                elif k == "client_id":
                    fp["DHCP-Client-ID (Opt. 61)"].add(bytes(v[0]).hex(":"))
                    seen_by[("DHCP-Client-ID (Opt. 61)", bytes(v[0]).hex(":"))].add(pkt[Ether].src.lower())
                elif k == "vendor_class_id":
                    fp["DHCP-Vendor-Class (Opt. 60)"].add(v[0].decode(errors="replace"))
                elif k == "param_req_list":
                    fp["DHCP-Parameterliste (Opt. 55)"].add(",".join(str(x) for x in v[0]))
                elif k == "client_FQDN":
                    fp["DHCP-FQDN (Opt. 81)"].add(bytes(v[0])[3:].decode(errors="replace"))
            continue
        if DHCP6 in pkt or (UDP in pkt and pkt[UDP].dport == 547):
            if DHCP6OptClientId in pkt:
                fp["DHCPv6-DUID"].add(bytes(pkt[DHCP6OptClientId].duid).hex(":"))
                seen_by[("DHCPv6-DUID", bytes(pkt[DHCP6OptClientId].duid).hex(":"))].add(pkt[Ether].src.lower())
            if DHCP6OptClientFQDN in pkt:
                fp["DHCPv6-FQDN"].add(str(pkt[DHCP6OptClientFQDN].fqdn))
            continue
        if IPv6 in pkt:
            s = pkt[IPv6].src
            if not s.startswith("fe80") and s != "::":
                src_v6.add(s)
            if pkt[IPv6].nh == 58 or (ICMPv6ND_NS in pkt):
                # ND/RS/MLD: link housekeeping
                if pkt[IPv6].dst.startswith("ff02") or s.startswith("fe80") or s == "::":
                    continue
                # neighbour discovery from a global/ULA source (hop limit 255:
                # never leaves the link), e.g. checking the router is still there
                icmp_type = bytes(pkt[IPv6].payload)[:1]
                if pkt[IPv6].nh == 58 and pkt[IPv6].hlim == 255 and icmp_type and 133 <= icmp_type[0] <= 137:
                    continue
            dst, proto_n = pkt[IPv6].dst, pkt[IPv6].nh
        elif IP in pkt:
            dst, proto_n = pkt[IP].dst, pkt[IP].proto
            client_ips.add(pkt[IP].src)
        else:
            continue
        # IGMP and MLD (behind a hop-by-hop header) group reports: link housekeeping too
        if proto_n == 2 or (proto_n == 0 and dst.startswith("ff02")):
            continue
        proto = PROTO.get(proto_n, str(proto_n))
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0
        sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0
        # local broadcast/discovery protocols that shout the device name
        if proto == "udp" and dport in BROADCAST_NAMES:
            name = BROADCAST_NAMES[dport]
            if DNS in pkt:
                for i in range(pkt[DNS].qdcount or 0):
                    try:
                        fp[f"{name}-Anfrage"].add(pkt[DNS].qd[i].qname.decode().rstrip("."))
                    except Exception:
                        pass
                for i in range(pkt[DNS].ancount or 0):
                    try:
                        fp[f"{name}-Antwort (eigener Name)"].add(pkt[DNS].an[i].rrname.decode().rstrip("."))
                    except Exception:
                        pass
            if Raw in pkt and DNS not in pkt:
                for m in PAYLOAD_IDS.finditer(bytes(pkt[Raw].load)):
                    if m.group(2):
                        fp[f"{name}: {m.group(1).decode()}"].add(m.group(2).decode(errors="replace"))
            fp["Rundrufe"].add(name)
            continue
        if (dst, dport, proto) in endpoints:
            tunnel_pkts[(dst, dport, proto)] += 1
            continue
        if proto == "icmp" and dst in endpoint_ips:
            # e.g. port unreachable for a tunnel packet that arrives after a restart
            tunnel_pkts[(dst, 0, proto)] += 1
            continue
        # answers instead of new connections
        if TCP in pkt:
            fl = int(pkt[TCP].flags)
            if fl & 0x12 == 0x02:
                outbound.add((dst, dport, sport))
            if (dst, dport, sport) in inbound:
                replies_lan[(dst, f"tcp/{sport}")] += 1
                continue
            if (fl & 0x04 or fl & 0x12 == 0x12) and (dst, dport, sport) not in outbound \
                    and not allowed_comm(who(dst, dport)):
                # RST/SYN-ACK for a connection that never came in through this network,
                # e.g. one that arrived through the tunnel
                gw_flows[(dst, dport, "tcp-Antwort", who(dst, dport))] += 1
                continue
        if proto in ("icmp", "icmp6") and IP in pkt and pkt[IP].proto == 1 and pkt.getlayer(3) is not None \
                and getattr(pkt.getlayer(3), "type", None) in (0, 3):
            replies_lan[(dst, "icmp")] += 1
            continue
        if TCP in pkt and dport == 80 and pkt[TCP].payload:
            raw = bytes(pkt[TCP].payload)
            if raw[:4] in (b"GET ", b"POST", b"HEAD"):
                h = re.search(rb"\r\nHost: ([^\r]+)", raw)
                ua = re.search(rb"\r\nUser-Agent: ([^\r]+)", raw)
                http_fp.add(f"{h.group(1).decode() if h else '?'}, User-Agent: {ua.group(1).decode() if ua else '–'}"
                            f" ({who(dst, dport)})")
                if h and h.group(1) in CAPTIVE_HOSTS:
                    captive_dsts.add(dst)  # recognised by content too: no process trace across a reboot
        if proto in ("udp", "tcp") and dport == 53:
            if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
                q = pkt[DNS].qd[0].qname.decode(errors="replace").rstrip(".").lower()
                gw_dns.append((q, dst, who(dst, 53) if who(dst, 53) != "?" else who(dst, sport)))
            continue
        w = who(dst, dport)
        if (dst, dport, proto) in allow_dst or allowed_net(dst, dport, proto) or allowed_comm(w):
            continue
        if w == "shuntd" and proto == "tcp" and dport == 80:
            captive_checks[label(dst)] += 1  # Shunt's own portal check, direct by design
            continue
        gw_flows[(dst, dport, proto, w)] += 1

for k in [k for k in gw_flows if k[0] in captive_dsts and k[1] == 80 and k[2] == "tcp"]:
    captive_checks[label(k[0])] += gw_flows.pop(k)
for k, n in gw_flows.items():
    dst, dport, proto, w = k
    if proto == "tcp-Antwort":
        find("leak", "Antwort am Tunnel vorbei", f"tcp → {label(dst)}:{dport} ({n} Pakete), Prozess: {w}"
             " – Verbindung kam nicht über dieses Netz, die Antwort geht aber hier raus")
    else:
        find("leak", "Klartext im fremden Netz", f"{proto} → {label(dst)}:{dport} ({n} Pakete), Prozess: {w}")
for (dst, what), n in replies_lan.items():
    find("info", "Antwort ans fremde Netz", f"{what} an {dst}: {n} Pakete (das Gerät reagiert auf Anfragen aus dem Netz)")
for d, n in captive_checks.items():
    find("info", "Portal-Prüfung von shuntd", f"HTTP an {d}: {n} Pakete (direkt, gewollt)")
for q, dst, w in gw_dns:
    if allow_dns or allowed_comm(w):
        continue
    if w == "shuntd" and q.encode() in CAPTIVE_HOSTS:  # name of the portal check: the portal sits in front of any tunnel
        find("info", "Portal-Prüfung von shuntd", f"DNS {q} an {label(dst)} (Namensauflösung der Prüfung, gewollt)")
        continue
    find("leak", "DNS über das fremde Netz", f"{q} an {dst}, Prozess: {w}")

# unbound log as a second opinion (it also sees what scapy might miss, e.g. TCP DNS)
unbound_q = []
if os.path.exists(p("unbound.log")):
    for line in open(p("unbound.log"), errors="replace"):
        m = re.search(r"info: (\S+) (\S+)\. (\w+) IN$", line.strip())
        if m:
            unbound_q.append((m.group(1), m.group(2).lower(), m.group(3)))
web_hits = []
if os.path.exists(p("web.log")):
    for line in open(p("web.log"), errors="replace"):
        f = line.split()
        if len(f) >= 4:
            web_hits.append((f[1], f[3].lower(), f[4] if len(f) > 4 else ""))

# --- fingerprint evaluation ------------------------------------------------------
for a in sorted(src_v6):
    if eui64(a, client_mac):
        fp["IPv6 aus MAC abgeleitet (EUI-64)"].add(a)
    else:
        fp["IPv6-Adressen (Quelle)"].add(a)
for h in sorted(http_fp):
    fp["HTTP im Klartext (Host, User-Agent)"].add(h)
for m in macs:
    first = int(m.split(":")[0], 16)
    fp["MAC"].add(f"{m} ({'zufällig/lokal' if first & 2 else 'Hersteller-MAC'})")
if strict_fp:
    for k in ("DHCP-Hostname (Opt. 12)", "DHCP-FQDN (Opt. 81)", "DHCPv6-FQDN",
              "IPv6 aus MAC abgeleitet (EUI-64)", "mDNS-Antwort (eigener Name)", "LLMNR-Anfrage"):
        for v in sorted(fp.get(k, ())):
            find("leak", "Fingerabdruck", f"{k}: {v}")
    # device IDs and names in discovery broadcasts (KDE Connect, Syncthing, …)
    for k in sorted(k for k in fp if ": " in k and not k.endswith("(eigener Name)")):
        for v in sorted(fp[k]):
            find("leak", "Fingerabdruck", f"Rundruf {k}: {v}")
    for v in sorted(fp.get("MAC", ())):
        if "Hersteller" in v:
            find("leak", "Fingerabdruck", f"echte MAC sichtbar: {v}")
# per-network: the client joined two networks (F05); one value for both = recognisable across networks
if "per-network" in meta.get("checks", []):
    # a value counts as "in both" only when it came with two MACs (each
    # network has its own MAC) or the MAC itself stayed the same
    for k in ("DHCPv6-DUID", "DHCP-Client-ID (Opt. 61)", "MAC"):
        vals = fp.get(k, set())
        if k == "MAC" and len(vals) == 1:
            find("leak", "Wiedererkennbar", f"MAC in beiden Netzen gleich: {next(iter(vals))}")
        elif k != "MAC":
            for v in sorted(vals):
                if len(seen_by[(k, v)]) > 1 or (len(macs) == 1 and len(vals) == 1):
                    find("leak", "Wiedererkennbar", f"{k} in beiden Netzen gleich: {v}")
                elif len(macs) > 1:
                    find("info", "Wiedererkennbar", f"{k} nur mit einer MAC gesehen: {v}")
        if not vals and k != "DHCP-Client-ID (Opt. 61)":
            find("info", "Wiedererkennbar", f"{k}: nicht gesehen")

# --- p0f (what an observer guesses from TCP/IP details) --------------------------
def p0f(pcap):
    if not os.path.exists(pcap):
        return []
    try:
        out = subprocess.run(["p0f", "-r", pcap], capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return []
    return sorted({m.group(1).strip() for m in re.finditer(r"\| os\s+= (.+)", out) if "???" not in m.group(1)})


# --- Messpunkt 3: tunnel exit ----------------------------------------------------
ct_dns, ct_flows = [], Counter()
tun_ip = meta.get("tunnel_ip", "")
if os.path.exists(p("ct130.pcap")):
    for pkt in PcapReader(p("ct130.pcap")):
        learn_names(pkt)
        ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
        if ip is None or (tun_ip and ip.src != tun_ip):
            continue
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0
        proto = PROTO.get(ip.proto if IP in pkt else ip.nh, "?")
        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
            ct_dns.append(pkt[DNS].qd[0].qname.decode(errors="replace").rstrip(".").lower())
        ct_flows[(ip.dst, dport, proto)] += 1

# --- canary ----------------------------------------------------------------------
where = []
if CANARY:
    at_gw = any(CANARY in q for q, _, _ in gw_dns) or any(CANARY in q for _, q, _ in unbound_q) \
        or any(CANARY in h for _, h, _ in web_hits)
    at_tun = any(CANARY in q for q in ct_dns)
    where = [w for w, b in (("fremdes Netz", at_gw), ("Tunnel-Ausgang", at_tun)) if b]
    exp = meta.get("expect_canary", "tunnel")
    want = {"tunnel": ["Tunnel-Ausgang"], "gw": ["fremdes Netz"], "none": [], "any": None}[exp]
    if want is not None and where != want:
        if exp == "tunnel" and not os.path.exists(p("ct130.pcap")) and not at_gw:
            find("info", "Lockvogel", f"{CANARY}: kein CT130-Mitschnitt, nur: nicht im fremden Netz")
        else:
            find("leak" if "fremdes Netz" in where and exp != "gw" else "fail", "Lockvogel",
                 f"{CANARY}: erwartet {want or 'nirgends'}, gesehen {where or 'nirgends'}")

# --- port scan -------------------------------------------------------------------
open_ports = []
for f in sorted(os.listdir(D)):
    if f.startswith("scan-") and f.endswith(".txt"):
        for line in open(p(f)):
            m = re.match(r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)", line)
            if m and m.group(3) == "open":
                open_ports.append(f"{f[5:-4]}: {m.group(1)}/{m.group(2)} {m.group(4)}")
expect_open = set(meta.get("expect_open", []))
for o in open_ports:
    if o.split(": ", 1)[1].split()[0] not in expect_open:
        find("leak", "Offener Port", o)

# --- client-side checks (written by the test itself) ----------------------------
for name, label in (("client.out", "Prüfung im Client"), ("during.log", "Prüfung nebenher")):
    if os.path.exists(p(name)):
        for line in open(p(name), errors="replace"):
            if line.startswith("FAIL "):
                find("fail", label, line[5:].strip())

# --- report ----------------------------------------------------------------------
bad = [f for f in findings if f[0] in ("leak", "fail")]
verdict = "FUND" if bad else "OK"
r = [f"# {meta['id']} – {meta.get('title', '')}", "",
     f"**Ergebnis:** {verdict} · **Modus:** {meta.get('mode')} · **Shunt:** {meta.get('shunt_version', '?')}"
     f" · **Zeit:** {meta.get('started', '')}", ""]
if meta.get("note"):
    r += [meta["note"], ""]
r += ["## Funde", ""]
r += [f"- **{g}** ({s}): {t}" for s, g, t in findings] or ["- keine"]
r += ["", "## Fremdes Netz (Lab-Gateway)", "",
      f"- Tunnel-Transport: " + (", ".join(f"{i}:{pt}/{pr} {n} Pakete" for (i, pt, pr), n in tunnel_pkts.items()) or "keiner"),
      *([f"- Nur der strenge Teil gewertet (LABMARK): {outside} Pakete davor/danach nicht beurteilt"] if strict_from else []),
      f"- DNS-Anfragen über das fremde Netz: {len(gw_dns)} (unbound-Protokoll: {len(unbound_q)})",
      f"- HTTP-Aufrufe am Gateway: " + (", ".join(sorted({h for _, h, _ in web_hits})) or "keine")]
r += ["", "### Was das Netz über das Gerät erfährt", ""]
r += [f"- {k}: {', '.join(sorted(v))}" for k, v in sorted(fp.items())] or ["- nichts"]
os_gw = p0f(p("gw.pcap"))
if os_gw:
    r.append(f"- p0f (Betriebssystem laut Paketen): {', '.join(os_gw)}")
r += ["", "## Tunnel-Ausgang (CT130)", ""]
if os.path.exists(p("ct130.pcap")):
    r.append(f"- Ziele: " + (", ".join(f"{d}:{pt}/{pr} ({n})" for (d, pt, pr), n in ct_flows.most_common(12)) or "keine"))
    r.append(f"- DNS: " + (", ".join(sorted(set(ct_dns))[:20]) or "keine"))
    os_ct = p0f(p("ct130.pcap"))
    if os_ct:
        r.append(f"- p0f (was die Gegenseite errät): {', '.join(os_ct)}")
else:
    r.append("- kein Mitschnitt")
r += ["", "## Client (bpftrace)", "", f"- {trace_lines} Pakete protokolliert"]
per = Counter()
for (dst, dport), hits in trace.items():
    for comm, dev in hits:
        per[(comm, dev)] += 1
r += [f"- {c} über {d}: {n}" for (c, d), n in per.most_common(15)]
if CANARY:
    r += ["", f"Lockvogel `{CANARY}` gesehen: {', '.join(where) or 'nirgends'}"]
if open_ports or any(f.startswith("scan-") for f in os.listdir(D)):
    r += ["", "## Portscan", ""] + ([f"- {o}" for o in open_ports] or ["- nichts offen"])
if os.path.exists(p("client.out")):
    r += ["", "## Ausgabe im Client", "", "```", open(p("client.out"), errors="replace").read().strip()[-3000:], "```"]
open(p("report.md"), "w").write("\n".join(r) + "\n")
json.dump({"id": meta["id"], "verdict": verdict, "findings": findings}, open(p("result.json"), "w"), indent=1)
print(f"{meta['id']}: {verdict}" + "".join(f"\n  - {g}: {t}" for s, g, t in bad))
