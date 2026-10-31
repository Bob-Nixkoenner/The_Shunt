# The Shunt – Gateway-Modus (Linux)

**Status:** Konzept; Stufe 1 (ohne Tor-Route, ohne eigenen DNS-Filter für Clients) im Branch `gateway-mode`

## 1. Ziel
Der Rechner leitet den Verkehr anderer Geräte, VMs und Container (LAN-Seite: Bridge oder Interface, z. B. `virbr1`, `br-lab`, USB-Ethernet) durch The Shunt. Die Clients haben denselben Schutz wie der Rechner selbst (Whonix-Prinzip: ein gekapertes Gerät kennt die echte IP nicht). Linux zuerst.

Abgrenzung zu #48: dort folgt weitergeleiteter Verkehr (Docker, libvirt-NAT, Namespaces) **automatisch dem Standardweg**, ohne Konfiguration, ohne eigene Regeln für Clients. Der Gateway-Modus ist dagegen **bewusst eingeschaltet**, benennt die Client-Interfaces und gibt jeder Client-Gruppe eine eigene Route. Verkehr von Interfaces, die in einer Gruppe stehen, geht nie nach #48 (Standardweg), sondern nach der Gruppe. Alles andere bleibt unverändert (#48-Logik unberührt).

## 2. Konfiguration
```toml
[gateway]
enabled = true
ipv6 = "block"            # block (Standard) | pass (Stufe 2)

[[gateway.group]]
name = "vms"
interfaces = ["virbr1"]   # Bridge/Interface auf der Client-Seite
route = "tunnel:vps"      # tunnel:x | direct | block | link:wifi|ethernet|mobile (Tor: Stufe 2)
```
- Mehrere Gruppen, jedes Interface nur in einer Gruppe. Interface darf noch nicht existieren (VM-Bridge kommt später); Regeln greifen per Name.
- Die Interfaces dürfen nicht der Uplink, ein Tunnel oder `lo` sein (Prüfung).
- Subnetze/DHCP gehören der Bridge, nicht dem Shunt.

## 3. Verhalten (nft, Tabelle `shunt`)
- **Route pro Gruppe:** in `mark_in` (prerouting) bekommt jede neue Verbindung von einem Gruppen-Interface die Marke der Gruppenroute (vor der Standardweg-Regel aus #48, die wegen der gesetzten Marke nicht mehr greift). Policy-Routing/Kill-Switch sind die der Route (Tunnel-Tabelle mit „unreachable“-Default, `leak_guard` im postrouting).
- **Kill-Switch auch für Clients:** Tunnel weg = Tabelle unreachable = Client-Pakete fallen; `leak_guard` verwirft alles, was nicht über die Tunnel-Schnittstelle geht; zusätzlich `gw_fwd`: Verkehr von einem Gruppen-Interface muss die Marke seiner Route tragen, sonst drop (kein Fallback auf direkt, auch nicht bei Fehlern in der Klassifizierung). `block`: drop in Forward (Lücke in #48: Standardweg `block` hatte für Weiterleitung keine Forward-Sperre, nur `output`; siehe Fund unten).
- **NAT:** Tunnel- und Link-Routen maskieren schon über die Marke (`nat_post`); für `direct`-Gruppen kommt `iifname {gw} oifname != {gw} masquerade` dazu.
- **Gruppen untereinander getrennt:** Forward zwischen Gruppen-Interfaces wird verworfen; neue Verbindungen *zu* Clients von außen (Uplink/Tunnel) ebenfalls (Eingangsschutz, Antworten laufen über conntrack).
- **Host schützen:** Von Gruppen-Interfaces erreichen Clients am Host nur DHCP (67), DNS (53), ICMP/ND; alles andere in `input` wird verworfen (kein SSH vom Gast zum Host).
- **DoT (853)** von Clients wird mit `dns.allow_dot=false` geblockt wie lokal.
- **IPv6:** Standard blocken (`gw_fwd`: `meta nfproto ipv6 drop` vom Gruppen-Interface; Clients sollen auf v4 fallen). `pass` später, nur für Gruppen, deren Tunnel v6 hat.
- **forwarding-Sysctl:** pro Interface (Gruppen + Uplinks + Tunnel), nie global `ip_forward` (wie bei Tailscale).
- **Panic:** `shunt_panic` hat `fwd_drop` (policy drop, Prio -300): Clients sofort tot. **tor-all / Notfall:** der Daemon baut beim Kompilieren (wie für den Standardweg und die Regeln) alle Gruppenrouten auf `block` um, solange tor-all aktiv ist; `gw_fwd` verwirft dann. Stufe 2 schickt sie stattdessen über Tor. **Boot-Lockdown:** `shunt_lockdown` kennt keine Konfiguration; Forwarding ist pro Interface erst nach shuntd an (Docker/libvirt setzen aber global `ip_forward`: Lücke bis shuntd läuft, Stufe 2 prüfen).
- **Daemon aus (`Stopped`):** Tunnel-Routen bleiben blockiert; Gruppen mit `direct` laufen weiter wie Direktverkehr des Hosts.

## 4. DNS für Clients
Stufe 1: Port 53 von Clients ist normaler Verkehr der Gruppenroute (geht durch den Tunnel zum Resolver, den der Client kennt). Kein Leck, aber ohne Shunt-Blocklisten. Der Client sollte per DHCP einen Resolver bekommen, der über den Tunnel erreichbar ist.
Stufe 2: Shunt-Resolver (`dnsproxy`) lauscht zusätzlich auf der Gateway-Adresse jeder Bridge; `nat prerouting` leitet Port 53 der Gruppe dorthin (Route und Filterstufe der Gruppe). Voraussetzung: Listener pro Interface-Adresse (heute nur loopback). Nicht neu bauen: dnsmasq der Bridge kann auf `127.0.0.1#Shunt-Port` weiterleiten.
DHCP: **nicht selbst bauen**. libvirt-dnsmasq, `dnsmasq`, systemd-networkd oder NetworkManager (`ipv4.method shared`) liefern Adresse und Resolver.

## 5. Tor (Stufe 2)
Tor-Routen brauchen einen transparenten Proxy, der auf der Gateway-Adresse lauscht (heute nur 127.0.0.1) und `REDIRECT` in `nat prerouting`; UDP wird abgewiesen (QUIC fällt auf TCP zurück). DNS über Tor wie beim Host. Bis dahin lehnt die Konfigurationsprüfung Tor als Gruppenroute mit klarer Meldung ab. `tor-all` blockiert Clients (siehe oben).

## 6. Konfig-Check (Befunde)
- Gateway an, aber Gruppe mit `direct` (Warnung: Clients ohne Schutz).
- Gateway an, Standardweg Tunnel, aber Gruppe `direct` (Info).
- Gruppe ohne Interface oder Interface = Uplink/Tunnel (Bad, die Validierung lehnt es ab).
- Kill-Switch des Daemons aus (Bad: Gateway ohne Kill-Switch).
- `ipv6 = "pass"` (Warnung, Stufe 2).

## 7. `shunt gateway status`
Listet Gruppen: Interface (da/fehlt), Route, Weg lebt (Tunnel verbunden?), Verbindungszähler aus conntrack nach Marke (Stufe 2), IPv6-Regel, forwarding aktiv. Auch in der UI als eine Status-Karte (Expert-Modus).

## 8. Offene Entscheidungen (Empfehlung zuerst)
1. **IPv6 für Clients:** blocken (Empfehlung; sonst Gefahr von Leck, wenn der Tunnel kein v6 hat).
2. **Standardroute einer Gruppe, wenn nichts steht:** `block` (Empfehlung), nicht Standardweg des Hosts.
3. **Tor für Clients (Whonix-Fall) kommt in Stufe 2** (Listener auf Bridge-Adresse). Bis dahin: Gruppe mit Tunnel, dessen Exit ein Tor-/Proxy-Server ist, oder Whonix-Gateway-VM hinter `tunnel`.
4. **DNS-Filter für Clients** (Stufe 2, Shunt-Resolver auf Bridge-Adresse). Empfehlung: ja, gleiche Listen wie Host.
5. **Gruppen untereinander trennen** (Empfehlung: ja, Standard).
6. **Gast → Host:** nur DHCP/DNS/ICMP (Empfehlung); Ausnahmen per Konfig später.
7. **Fund #48:** Standardweg `block` hat keine Forward-Sperre, weitergeleitete Pakete tragen Marke 0xfe, es gibt aber keine ip-Regel dafür (Main-Tabelle = Leck?). Der Gateway-Modus sperrt `block` in `gw_fwd`; soll die Sperre auch für den Standardweg (#48) kommen? Empfehlung: ja, eigener kleiner PR mit Test.

## 9. Lab-Tests (später, Lab-VMs, NICHT jetzt)
G01 Gast-VM an `virbr1` mit Gruppe `tunnel:x`: Austritts-IP = Tunnel-IP. G02 Tunnel abschießen: kein Paket direkt (Mitschnitt auf Uplink), nach Wiederkehr geht es wieder. G03 Gruppe `block`: nichts raus. G04 IPv6 vom Gast: kein Paket. G05 DNS (`dig` beim Gast): geht nur über die Route, Mitschnitt Uplink zeigt keine Port-53-Pakete. G06 Panic: Gast sofort tot, nach Panic-Ende wieder. G07 tor-all an: Gast tot. G08 Gast → Host: ssh/8088 zu, DHCP/DNS ok. G09 zwei Gruppen: kein Verkehr zwischen ihnen. G10 Umschalten Route im laufenden Betrieb (Tunnel A → B → direkt), laufende TCP-Verbindungen folgen nach `ForgetTCP`. G11 Daemon stoppen/neu starten: keine Lücke. G12 Docker-Container (#48) weiterhin Standardweg. G13 Bridge entsteht erst nach Start (VM startet später). G14 MTU/MSS (große Downloads im Gast). G15 UDP (QUIC) im Gast durch WG-Tunnel.

## 10. Stufen
1. Konzept, Konfig, nft (Routen, Kill-Switch, NAT, Trennung, v6-Block), `shunt gateway status`, Check, Integrationstest (Netns).
2. DNS-Resolver auf Bridge-Adresse + Filter, Tor-Route (transparenter Proxy auf Bridge-Adresse), tor-all schickt Clients über Tor.
3. IPv6 durchreichen, UI-Gruppenverwaltung, Verbindungszähler.
