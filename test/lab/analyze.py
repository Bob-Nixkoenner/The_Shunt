"""Lab analyzer: puts the three measuring points of one test side by side.

    python3 analyze.py <test dir>

The test dir holds meta.json (written by run-test.sh) and whatever was
captured: gw.pcap + unbound/dnsmasq/web logs (gateway), trace.log (client,
bpftrace), ct130.pcap (tunnel exit), scan-*.txt (nmap). Writes report.md and
result.json next to them. Runs on the gateway (needs scapy, p0f).

Rule at the gateway: the untrusted network may see tunnel transport to the
configured endpoints, link housekeeping (ARP, ND, DHCP) and what the test
explicitly allows. Everything else from the client is a finding.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

from scapy.all import (ARP, DHCP, DNS, DNSQR, ICMPv6ND_NS, IP, TCP, UDP, BOOTP, IPv6, Ether,
                       PcapReader)
from scapy.layers.dhcp6 import DHCP6, DHCP6OptClientId, DHCP6OptClientFQDN

D = sys.argv[1]
meta = json.load(open(os.path.join(D, "meta.json")))
CANARY = meta.get("canary", "").lower().rstrip(".")
client_mac = (meta.get("client_mac") or "").lower()
endpoints = set()
for e in meta.get("endpoints", []):  # ip:port/proto
    ip, rest = e.rsplit(":", 1)
    port, proto = rest.split("/")
    endpoints.add((ip, int(port), proto))
allow = meta.get("allow", [])
allow_comms = {a[5:] for a in allow if a.startswith("comm:")}
allow_dst = set()
for a in allow:
    if a.startswith("dst:"):
        ip, rest = a[4:].rsplit(":", 1)
        port, proto = rest.split("/")
        allow_dst.add((ip, int(port), proto))
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
    hits = trace.get((dst, dport))
    if not hits:
        return "?"
    c = Counter(h[0] for h in hits)
    return ", ".join(f"{k}" for k, _ in c.most_common(3))


# --- Messpunkt 2: gateway ------------------------------------------------------
PROTO = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}
BROADCAST_NAMES = {5353: "mDNS", 5355: "LLMNR", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 1900: "SSDP",
                   3702: "WS-Discovery"}
fp = defaultdict(set)  # fingerprint facts seen by the network
gw_flows = Counter()  # (dst, port, proto, who) -> packets, for findings
tunnel_pkts = Counter()
gw_dns = []  # qnames asked through the untrusted network
client_ips = set(meta.get("client_ips", []))
src_v6 = set()
macs = set()


def is_client(pkt):
    if Ether in pkt and client_mac:
        return pkt[Ether].src.lower() == client_mac
    return False


def eui64(addr, mac):
    if not mac:
        return False
    m = mac.split(":")
    iid = f"{int(m[0], 16) ^ 2:02x}{m[1]}:{m[2]}ff:fe{m[3]}:{m[4]}{m[5]}"
    return ipaddress.ip_address(addr).exploded.endswith(
        ipaddress.ip_address("::" + iid).exploded[-19:])


if os.path.exists(p("gw.pcap")):
    for pkt in PcapReader(p("gw.pcap")):
        if Ether not in pkt:
            continue
        if not is_client(pkt):
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
            dst, proto_n = pkt[IPv6].dst, pkt[IPv6].nh
        elif IP in pkt:
            dst, proto_n = pkt[IP].dst, pkt[IP].proto
            client_ips.add(pkt[IP].src)
        else:
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
            fp["Rundrufe"].add(name)
            continue
        if (dst, dport, proto) in endpoints:
            tunnel_pkts[(dst, dport, proto)] += 1
            continue
        if proto in ("udp", "tcp") and dport == 53:
            if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
                q = pkt[DNS].qd[0].qname.decode(errors="replace").rstrip(".").lower()
                gw_dns.append((q, dst, who(dst, 53) if who(dst, 53) != "?" else who(dst, sport)))
            continue
        w = who(dst, dport)
        if (dst, dport, proto) in allow_dst or (w != "?" and set(x.strip() for x in w.split(",")) <= allow_comms):
            continue
        gw_flows[(dst, dport, proto, w)] += 1

for k, n in gw_flows.items():
    dst, dport, proto, w = k
    find("leak", "Klartext im fremden Netz", f"{proto} → {dst}:{dport} ({n} Pakete), Prozess: {w}")
for q, dst, w in gw_dns:
    if allow_dns or (w != "?" and set(x.strip() for x in w.split(",")) <= allow_comms):
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
for m in macs:
    first = int(m.split(":")[0], 16)
    fp["MAC"].add(f"{m} ({'zufällig/lokal' if first & 2 else 'Hersteller-MAC'})")
if strict_fp:
    for k in ("DHCP-Hostname (Opt. 12)", "DHCP-FQDN (Opt. 81)", "DHCPv6-FQDN",
              "IPv6 aus MAC abgeleitet (EUI-64)", "mDNS-Antwort (eigener Name)", "LLMNR-Anfrage"):
        for v in sorted(fp.get(k, ())):
            find("leak", "Fingerabdruck", f"{k}: {v}")
    for v in sorted(fp.get("MAC", ())):
        if "Hersteller" in v:
            find("leak", "Fingerabdruck", f"echte MAC sichtbar: {v}")

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
