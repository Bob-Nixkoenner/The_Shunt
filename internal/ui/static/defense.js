"use strict";
// Defense ("Abwehr", Opsec level): heat gauge, switches per feature, blocked
// addresses, live events and a small live window for hits on the decoys.
// Talks to /api/defense* (internal/defense/types.go has the shapes). Events
// stay on this machine: the page only shows them.

let defSt = null; // last defense.Status; null = the service has no defense (yet)
let defEvents = []; // newest last, at most 200
let defSince = 0;
let defPrimed = false; // the first fetch brings old events: no live window for those
let defMuteUntil = 0; // the live window was closed: quiet until then
let defLive = []; // what the live window shows
const DEF_LEVELS = ["quiet", "noticed", "hot", "attack"];

// supported: the service answers /v1/defense (the Opsec assistant asks this)
function defSupported() { return !!defSt; }

const defLevelText = () => ({ quiet: T("Quiet"), noticed: T("Noticed"), hot: T("Hot"), attack: T("Attack") });
const defClassText = () => ({ trusted: T("Trusted network"), public: T("Public network"), managed: T("Managed network") });
const defKindText = () => ({
  decoy_hit: T("Decoy port hit"), tarpit: T("Held in the tarpit"), cowrie: T("Login attempt on fake service"),
  scan: T("Port scan"), brute_force: T("Brute force"), reputation: T("Known bad address"), first_seen: T("New destination"),
  arp: T("ARP/NDP spoofing"), rogue_dhcp: T("Second DHCP server"), dns_hijack: T("DNS answers differ"), tls: T("Certificate changed"),
  beacon: T("Regular beacon traffic"), dns_tunnel: T("DNS tunnel"), evil_twin: T("Evil twin Wi-Fi"),
  dhcp_option: T("DHCP options"), rogue_ra: T("Rogue IPv6 router"), dns_rebind: T("DNS rebind"), new_iface: T("New network interface"), ban: T("Blocked"),
  unban: T("Block lifted"), manual: T("Blocked by you"), net_enter: T("Network joined"), observation: T("Observation"),
  exposed: T("Directly reachable from the internet"), outside: T("Outside check"),
});
// what each switch does: [name, one line]
// [name, what it watches, what on/off means for a beginner]
const defFeatText = () => ({
  decoy: [T("Decoy ports"), T("Fake services on common ports (not in trusted or managed networks)."), T("On: fake services on common ports catch snoopers. Off: no fake ports open.")],
  tarpit: [T("Tarpit"), T("Holds scanners in slow connections."), T("On: scanners get stuck in very slow connections. Off: they are turned away at once.")],
  cowrie: [T("Fake login"), T("A fake service records login attempts."), T("On: a fake login records what intruders type. Off: no fake login.")],
  scan: [T("Port scans"), T("Many ports from one source."), T("On: you learn when someone probes many ports. Off: scans go unnoticed.")],
  brute: [T("Brute force"), T("Many failed connections in a row."), T("On: many failed logins in a row are reported. Off: password guessing goes unnoticed.")],
  reputation: [T("Bad address lists"), T("Peers and destinations on lists of known attackers."), T("On: contact with known attackers is reported. Off: nothing is compared with the lists.")],
  first_seen: [T("New destinations"), T("An app contacts a destination for the first time (shown only, never blocks; each app learns for 10 minutes first)."), T("On: you see when an app talks to something new. Off: no such notes.")],
  arp: [T("ARP/NDP spoofing"), T("The gateway's hardware address changes."), T("On: warns when someone poses as your router. Off: such a takeover goes unnoticed.")],
  dhcp: [T("Rogue DHCP"), T("A second DHCP server answers."), T("On: warns when a stranger hands out network settings. Off: no warning.")],
  dns: [T("DNS tampering"), T("DNS answers differ or port 53 is diverted."), T("On: warns when name lookups are faked. Off: faked lookups go unnoticed.")],
  tls: [T("Certificate changes"), T("Checks the certificate issuer of a few public sites now and then (shown only)."), T("On: notices when secure connections are intercepted. Off: no such check.")],
  beacon: [T("Beacons"), T("An app connects to one destination at clockwork intervals (Linux only)."), T("On: reports apps that phone home like clockwork, as malware does. Off: no such check.")],
  dns_tunnel: [T("DNS tunnels"), T("Long, random names and many TXT queries."), T("On: notices data smuggled out in name lookups. Off: no such check.")],
  evil_twin: [T("Evil twin"), T("Same Wi-Fi name, different access point."), T("On: warns about a fake Wi-Fi with the same name. Off: no warning.")],
  dhcp_option: [T("DHCP options"), T("Routes from the network's DHCP reply that bypass the tunnel (shown only, never blocks)."), T("On: shows network settings that would steer traffic past the tunnel. Off: not shown.")],
  rogue_ra: [T("IPv6 routers"), T("A second or odd IPv6 router or DHCPv6 server (shown only, never blocks)."), T("On: shows a stranger acting as an IPv6 router. Off: not shown.")],
  dns_rebind: [T("DNS rebind"), T("A public name that resolves to a private address. Needs defense.rebind_protect; drops the answer only with Block."), T("On: notices websites that try to reach devices in your own network. Off: no such check.")],
  new_iface: [T("New interfaces"), T("A network interface appears that was not there at start, e.g. a USB adapter (Linux, shown only)."), T("On: shows a newly plugged-in network adapter. Off: not shown.")],
});
// the lists: [name, what is in it, how often, how long it counts, source link, terms link, restriction]
const DEF_SRC = {
  feodo: { url: "https://feodotracker.abuse.ch/blocklist/", terms: "https://abuse.ch/terms-of-use/" },
  sslbl: { url: "https://sslbl.abuse.ch/blacklist/", terms: "https://abuse.ch/terms-of-use/" },
  sslbl_ja3: { url: "https://sslbl.abuse.ch/blacklist/", terms: "https://abuse.ch/terms-of-use/" },
  et_compromised: { url: "https://rules.emergingthreats.net/blockrules/", terms: "https://rules.emergingthreats.net/open/suricata/BSD-License.txt", ask: true },
  spamhaus_drop: { url: "https://www.spamhaus.org/drop/", terms: "https://www.spamhaus.org/blocklists/drop-fair-use-policy/", ask: true },
};
const defSrcText = () => ({
  feodo: [T("abuse.ch Feodo Tracker"), T("Addresses of botnet command servers. Updated about every 5 minutes at the provider; this device fetches twice a day. Entries count 48 h after a download. Licence CC0.")],
  sslbl: [T("abuse.ch SSLBL (addresses)"), T("Addresses that host malware command servers seen by their TLS certificates. Fetched twice a day; entries count 48 h. Licence CC0.")],
  sslbl_ja3: [T("abuse.ch SSLBL (JA3)"), T("TLS fingerprints (JA3) of known malware clients; matched against what hits the decoy on port 443. Fetched twice a day; entries count 72 h. Licence CC0.")],
  et_compromised: [T("Emerging Threats compromised IPs"), T("Addresses of hosts known to be compromised. Updated daily at the provider; this device fetches twice a day; entries count 48 h. This list has known false alarms, so it only reports and never blocks. Note: the BSD licence of Emerging Threats is stated for its rule folder; for these IP lists the licence is not explicitly stated.")],
  spamhaus_drop: [T("Spamhaus DROP"), T("Network ranges run by criminals (IPv4 and IPv6). Updated daily. The terms of use grant no licence to build the list into an app, so it is not offered.")],
});
const BAIT = ["decoy_hit", "tarpit", "cowrie"];

function defTime(t) {
  const d = new Date(t);
  return isNaN(d) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function defLeft(ts) {
  const s = Math.round((new Date(ts) - Date.now()) / 1000);
  if (!(s > 0)) return "";
  return s >= 90 ? T("{n} min left", { n: Math.round(s / 60) }) : T("{n} s left", { n: s });
}

// the heat gauge: number, level name and a bar with the level borders
function defThermo(st, small) {
  const lv = DEF_LEVELS.includes(st.level) ? st.level : "quiet";
  const heat = Math.max(0, Math.min(100, st.heat | 0));
  return el("div", { class: "thermo heat-" + lv + (small ? " small" : ""), title: T("Heat 0–100: quiet below 25, noticed from 25, hot from 50, attack from 80") },
    el("div", { class: "head" }, el("span", { class: "num" }, heat), el("span", { class: "lvl" }, defLevelText()[lv]),
      small ? el("span", { class: "pill" }, defClassText()[st.class] || defClassText().public) : ""),
    el("div", { class: "track" }, el("div", { class: "fill", style: "width:" + Math.max(2, heat) + "%" }),
      ...[25, 50, 80].map((p) => el("div", { class: "tick", style: "left:" + p + "%" }))),
    small ? "" : el("div", { class: "scale" }, el("span", {}, "0"), el("span", {}, "25"), el("span", {}, "50"), el("span", {}, "80"), el("span", {}, "100")));
}

// defApp words the name of a connection's owner. "group:…" stands for a cgroup
// that several programs share (a login session, a Shunt route group): the
// service only learns the group there, not which program it was.
function defApp(a) {
  if (!a.startsWith("group:")) return a;
  const g = a.slice(6);
  return g === "login-session" ? T("A program of the login session") : T("A program of the group {g}", { g });
}

// defDetail turns the machine detail of the connection-based findings into a
// sentence (the service writes "key=value" pairs in English); anything else is shown as it is.
function defDetail(e) {
  const d = e.detail || "";
  const kv = {};
  d.split(" ").forEach((x) => { const i = x.indexOf("="); if (i > 0) kv[x.slice(0, i)] = x.slice(i + 1); });
  if (e.kind === "first_seen" && kv.app && kv.target) {
    return T("{app} contacted {target} for the first time", { app: defApp(kv.app), target: kv.target }) +
      (kv.more ? " " + T("(+{n} more not listed)", { n: kv.more }) : "");
  }
  if (e.kind === "beacon" && kv.app && kv.interval) {
    return T("{app} connects here about every {interval} (regularity {score})", { app: defApp(kv.app), interval: defInterval(kv.interval), score: kv.score || "?" });
  }
  if (e.kind === "dns_tunnel" && kv.domain) {
    return T("Unusual lookups under {domain}: long random names (score {score}, {n} queries in {w} s)", { domain: kv.domain, score: kv.score || "?", n: kv.queries || "?", w: parseInt(kv.window) || 60 });
  }
  if (e.kind === "tls" && kv.target) {
    if (d.includes("issuer chain differs")) return T("The certificate issuer of {target} differs from the one remembered earlier", { target: kv.target });
    if (d.includes("two ways")) return T("Two network paths to {target} show different certificate issuers", { target: kv.target });
    if (d.includes("not trusted")) return T("The certificate chain of {target} is not trusted by this system", { target: kv.target });
  }
  if (e.kind === "reputation" && kv.list) {
    const nm = (defSrcText()[kv.list] || [kv.list])[0];
    return kv.ja3 ? T("TLS fingerprint {ja3} is on the list {list}", { ja3: kv.ja3, list: nm }) : T("On the list {list}", { list: nm });
  }
  if (e.kind === "dhcp_option") {
    const cov = d.startsWith("covers-default");
    const routes = kv.routes ? kv.routes.split(" ")[0] : "";
    if (cov) return T("The DHCP reply sends routes that cover the default route ({routes}): traffic can bypass the VPN tunnel (TunnelVision pattern)", { routes: routes || "?" });
    if (kv.routes) return T("The DHCP reply contains classless routes ({routes}); they do not hide the default route", { routes: routes });
    if (kv.opts) return T("DHCP options offered: {opts}", { opts: kv.opts });
  }
  if (e.kind === "dns_rebind" && kv.domain) {
    return kv.action === "dropped" ? T("{domain} resolved to a {class} address; the answer was dropped", { domain: kv.domain, class: kv.class || "?" })
      : T("{domain} resolved to a {class} address (DNS rebind pattern)", { domain: kv.domain, class: kv.class || "?" });
  }
  if (e.kind === "new_iface" && kv.type) {
    const how = (kv.bus === "usb" ? T("USB") + " " : "") + kv.type;
    if (d.startsWith("default route")) return T("A new network interface ({how}) got the default route", { how });
    return T("A new network interface appeared ({how}); the USB hint is a guess from system files", { how });
  }
  if (kv.more && !kv.app && e.kind !== "outside") return T("{n} more of the same kind in a short time (folded into one line)", { n: kv.more });
  if (e.kind === "exposed" && kv.inbound) return defExposedText(kv.inbound, (kv.public || "").split(","));
  if (e.kind === "outside") return defOutsideText(d);
  let m;
  switch (e.kind) {
    case "rogue_ra":
      if (d.startsWith("a second router advertises itself as default router and names")) return T("A second IPv6 router appeared and also names DNS servers");
      if (d.startsWith("a second router")) return T("A second IPv6 router advertises itself as default router");
      if (d.startsWith("a second DHCPv6")) return T("A second DHCPv6 server answered on this network");
      if (d.startsWith("a router address is now")) return T("An IPv6 router address is now advertised from another hardware address (possible spoofing)");
      if (d.startsWith("a default router announced lifetime 0")) return T("An IPv6 router withdrew the default route (lifetime 0)");
      if (d.startsWith("a prefix was announced")) return T("A prefix was announced with lifetime 0 (removes addresses)");
      if (d.startsWith("DNS servers were announced")) return T("IPv6 DNS servers were announced with lifetime 0 (removes them)");
      if (d.startsWith("the announced DNS servers differ")) return T("The IPv6 DNS servers announced now differ from the first ones");
      if (d.startsWith("advertisement behind a fragment")) return T("A router advertisement came behind a fragment header (evades switch RA-Guard)");
      if ((m = /^flood: (\d+) router advertisements in (\d+)s$/.exec(d))) return T("{n} router advertisements in {s} s", { n: m[1], s: m[2] });
      break;
    case "tarpit":
      if ((m = /^held (\d+)s$/.exec(d))) return T("Held in the tarpit for {n} s", { n: m[1] });
      break;
    case "decoy_hit":
      if (d === "tcp connect") return T("Connected to a decoy port");
      break;
    case "cowrie":
      if ((m = /^telnet login user=(\S*) len=(\d+) h=\w+$/.exec(d))) return T("Tried to log in on the fake telnet service as {user} (password of {n} characters)", { user: m[1], n: m[2] });
      if ((m = /^ssh client (.*)$/.exec(d))) return T("Connected to the fake SSH service, client: {client}", { client: m[1] });
      break;
    case "scan":
      if ((m = /^mode=many_ports .*: (\d+)/.exec(d))) return T("Probed {n} different ports in a short time", { n: m[1] });
      if ((m = /^mode=failed_ports .*: (\d+)/.exec(d))) return T("Tried {n} ports that refused or did not answer", { n: m[1] });
      break;
    case "brute_force":
      if ((m = /^mode=few_ports failed attempts in window: (\d+) on (\d+) ports/.exec(d))) return T("{n} failed connection attempts on {p} ports in a short time", { n: m[1], p: m[2] });
      break;
    case "arp":
      if (d.startsWith("the gateway's hardware address changed")) return T("The hardware address of the gateway changed (possible ARP/NDP spoofing)");
      break;
    case "rogue_dhcp":
      if (d.startsWith("a second DHCP server")) return T("A second DHCP server answered on this network");
      break;
    case "dns_hijack":
      if (d.startsWith("the network's resolver answers differently")) return T("The network's resolver answers differently from the reference for a fixed name");
      if (d.startsWith("port 53 to a public resolver is answered with other data inside the tunnel")) return T("Port 53 to a public resolver is answered with other data inside the tunnel");
      if (d.startsWith("port 53 to a public resolver")) return T("Port 53 to a public resolver is answered with other data (diverted)");
      break;
    case "evil_twin":
      if (d.startsWith("a known Wi-Fi name appears")) return T("A known Wi-Fi name appears with a different gateway (possible evil twin)");
      break;
    case "observation":
      if (d.startsWith("captive portal")) return T("Captive portal: the network wants a login before it is open");
      if ((m = /^ja3=(\w+)$/.exec(d))) return T("TLS fingerprint of a visitor: {ja3}", { ja3: m[1] });
      break;
    case "ban":
      if ((m = /^reason=(\w+)$/.exec(d))) return T("Blocked because of: {reason}", { reason: defKindText()[m[1]] || m[1] });
      break;
    case "unban":
      if (d === "expired") return T("The block ran out");
      if (d === "manual") return T("The block was lifted by hand");
      break;
    case "net_enter":
      if ((m = /^class=(\w+)$/.exec(d))) return T("Joined a network, treated as: {class}", { class: defClassText()[m[1]] || m[1] });
      break;
  }
  return d;
}

// the warning for a device with a public address; stronger when nothing filters
function defExposedText(inbound, fams) {
  const f = fams.filter(Boolean).map((x) => x === "v6" ? "IPv6" : "IPv4").join(" + ") || "IPv4";
  if (inbound === "open" || inbound === "off") {
    return T("This device has a public address ({fam}) and is reachable directly from the internet. Nothing blocks incoming connections ({mode}): every program that listens can be attacked. Switch on “Incoming connections” (closed) under Configure → Privacy and protection.", { fam: f, mode: inbound === "off" ? T("protection off") : T("open") });
  }
  return T("This device has a public address ({fam}) and is reachable directly from the internet. Incoming connections are limited ({mode}); check from outside to be sure.", { fam: f, mode: inbound });
}
// "open v4=22,80 v6=none" in words
function defOutsideText(d) {
  const parts = d.replace(/^open /, "").split(" ").filter(Boolean).map((x) => {
    const [fam, v] = x.split("=");
    const nm = fam === "v6" ? "IPv6" : "IPv4";
    return v === "none" ? T("{fam}: nothing answers", { fam: nm }) : v === "error" ? T("{fam}: check failed", { fam: nm }) : T("{fam}: ports {ports} answer", { fam: nm, ports: v });
  });
  return parts.join(" · ");
}
// red plaque, on the tile and in the tab
function defExposedBadge() {
  const x = defSt && defSt.exposed;
  if (!defSt || !defSt.enabled || !x || !(x.v4 || x.v6)) return null;
  const strong = x.inbound === "open" || x.inbound === "off";
  return el("div", { class: "banner bad", role: "alert", style: "margin:8px 0" },
    el("b", {}, "⚠ " + T("Directly reachable from the internet")), " ",
    defExposedText(x.inbound || "off", [x.v4 ? "v4" : "", x.v6 ? "v6" : ""]),
    );
}

// defInterval shows a Go duration ("1m0s", "45s", "1h0m0s") as "1 min" / "45 s".
function defInterval(v) {
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$/.exec(v);
  if (!m || !v) return v;
  const sec = (+m[1] || 0) * 3600 + (+m[2] || 0) * 60 + (+m[3] || 0);
  if (sec >= 3600 && sec % 3600 === 0) return T("{n} h", { n: sec / 3600 });
  if (sec >= 60 && sec % 60 === 0) return T("{n} min", { n: sec / 60 });
  if (sec >= 60) return T("{n} min", { n: Math.floor(sec / 60) }) + " " + T("{n} s", { n: Math.round(sec % 60) });
  return T("{n} s", { n: Math.round(sec) });
}

function defEventRow(e, compact) {
  const kind = defKindText()[e.kind] || e.kind;
  const where = [e.src, e.port ? (e.proto || "") + (e.port ? ":" + e.port : "") : ""].filter(Boolean).join(" ");
  return el("div", { class: "ev s" + (e.severity | 0) },
    el("span", { class: "t" }, defTime(e.time)), el("span", { class: "dot" }),
    el("span", { class: "x" }, el("b", {}, kind),
      e.src ? el("span", { class: "mono" }, " ", el("button", { class: "srclink", type: "button", title: T("Show everything from this source"), onclick: () => defOpenSource(e.src) }, e.src), e.port ? " " + (e.proto || "") + ":" + e.port : "")
        : where ? el("span", { class: "mono" }, " " + where) : "",
      e.detail && !compact ? el("div", { class: "muted" }, defDetail(e)) : ""));
}

function renderDefense() {
  const sec = $("#sec-defense");
  const on = defSt && defSt.enabled;
  sec.hidden = !defSt;
  if (!defSt) {
    $("#def-thermo").replaceChildren(el("div", { class: "muted" }, T("The service has no defense module yet.")));
    $("#def-feats").replaceChildren(); $("#def-bans").replaceChildren(); $("#def-events").replaceChildren();
    $("#def-class").replaceChildren(); $("#def-notes").textContent = ""; $("#def-exposed").replaceChildren();
    $("#def-on").disabled = true; $("#def-unban-all").hidden = true;
    return;
  }
  $("#def-on").disabled = false;
  $("#def-on").checked = !!defSt.enabled;
  $("#def-class").replaceChildren(el("span", { class: "pill " + (defSt.class === "trusted" ? "ok" : defSt.class === "managed" ? "" : "warn"), title: T("Set by the network profile; an unknown network counts as public") },
    defClassText()[defSt.class] || defClassText().public));
  const notes = [];
  if (!on) notes.push(T("Defense is off: nothing is watched, no decoys run."));
  else if (defSt.class === "trusted") notes.push(T("Trusted network: no decoys, quiet warnings only."));
  else if (defSt.class === "managed") notes.push(T("Managed network: watching only, no decoys."));
  else if ((defSt.decoys || []).length) notes.push(T("Decoys listen on: {ports}", { ports: defSt.decoys.join(", ") }));
  if (defSt.unsupported) notes.push(defSt.unsupported);
  // the switches, lists and blocks exist only where the defense runs
  // (Linux): elsewhere they are not shown at all, the note above says why
  const none = typeof onWindows === "function" && onWindows();
  for (const id of ["#def-feats", "#def-sources", "#def-bans"]) { const sec = $(id).closest("section"); if (sec) sec.hidden = none; }
  const exp = defSt.exposed && (defSt.exposed.v4 || defSt.exposed.v6);
  if (on && exp && !(defSt.config && defSt.config.decoys_when_exposed)) notes.push(T("Decoys stay off here: with a public address they would be real attack surface."));
  $("#def-notes").textContent = notes.join(" ");
  const badge = defExposedBadge();
  $("#def-exposed").replaceChildren(...(badge ? [badge] : []), ...(on && exp ? [defDecoyChoice()] : []));
  renderOutside();
  // heat
  $("#def-thermo").replaceChildren(defThermo(defSt, false));
  // switches
  const feats = (defSt.config && defSt.config.features) || {};
  const txt = defFeatText();
  $("#def-feats").replaceChildren(...Object.keys(txt).map((k) => {
    const f = feats[k] || { watch: false, block: false };
    const watch = el("input", { type: "checkbox", "aria-label": T("Watch") + ": " + txt[k][0], onchange: () => defSetFeature(k, { watch: watch.checked, block: watch.checked && f.block }) });
    const block = el("input", { type: "checkbox", "aria-label": T("Block") + ": " + txt[k][0], onchange: () => defSetFeature(k, { watch: f.watch, block: block.checked }) });
    watch.checked = !!f.watch; block.checked = !!f.block && !!f.watch; block.disabled = !f.watch || !on;
    watch.disabled = !on;
    return el("tr", {}, el("td", {}, el("b", {}, txt[k][0]), el("div", { class: "d" }, txt[k][1]), el("div", { class: "d onoff" }, txt[k][2]), k === "dhcp" ? defProbeChoice(on, "dhcp_probe", "Active DHCP check") : k === "dns" ? defProbeChoice(on, "dns_probe", "Active DNS check") : k === "scan" ? defBanChoice(on, f) : ""), el("td", { class: "sw" }, watch), el("td", { class: "sw" }, block));
  }));
  renderDefSources(on);
  // bans
  const bans = defSt.bans || [];
  $("#def-unban-all").hidden = !bans.length;
  $("#def-bans").replaceChildren(...(bans.length ? bans.map((b) => el("tr", {},
    el("td", { class: "mono" }, b.src.includes("/") ? el("span", { title: T("A whole range, blocked because many addresses in it attacked") }, b.src) : el("button", { class: "srclink", type: "button", title: T("Show everything from this source"), onclick: () => defOpenSource(b.src) }, b.src)),
    el("td", {}, defKindText()[b.reason] || b.reason, " ", el("span", { class: "muted" }, defLeft(b.expires))),
    el("td", { style: "text-align:right" }, el("button", { onclick: () => defUnban(b.src) }, "Unblock"), " ", el("button", { onclick: () => defAllow(b.src) }, T("Always allow")))))
    : [el("tr", {}, el("td", { class: "muted" }, "No address is blocked."))]));
  // events
  const shown = defEvents.slice(-100).reverse();
  $("#def-evsum").textContent = defEvents.length ? T("{n} shown", { n: shown.length }) : "";
  $("#def-events").replaceChildren(...(shown.length ? shown.map((e) => defEventRow(e)) : [el("div", { class: "muted" }, "Nothing seen yet.")]));
  renderDefTile();
}

function defAge(ts) {
  const s = Math.round((Date.now() - new Date(ts)) / 1000);
  if (!(s >= 0)) return "";
  return s < 5400 ? T("{n} min ago", { n: Math.max(1, Math.round(s / 60)) }) : s < 172800 ? T("{n} h ago", { n: Math.round(s / 3600) }) : T("{n} days ago", { n: Math.round(s / 86400) });
}
function renderDefSources(on) {
  const txt = defSrcText(), cfg = defSt.config || {};
  const info = {};
  (defSt.sources || []).forEach((x) => { info[x.name] = x; });
  // a list the terms keep out of the app (Spamhaus DROP, "unavailable") is not
  // shown: a box that can never be ticked only confuses
  const names = ["feodo", "sslbl", "sslbl_ja3", "et_compromised", "spamhaus_drop"].filter((n) => !(info[n] || {}).unavailable);
  $("#def-sources").replaceChildren(...names.map((n) => {
    const i = info[n] || { name: n, on: false };
    const m = DEF_SRC[n], dead = !!i.unavailable;
    const box = el("input", { type: "checkbox", "aria-label": txt[n][0], onchange: () => defSetSource(n, box.checked, m.ask) });
    box.checked = !!i.on && !dead; box.disabled = !on || dead;
    let st;
    if (dead) st = T("Terms require a separate agreement.");
    else if (!i.on) st = T("Off: nothing is downloaded.");
    else if (i.error && !i.updated) st = T("Error: {error}", { error: i.error }) + " · " + T("Expired");
    else if (!i.updated) st = T("Not downloaded yet.");
    else st = T("Updated {when}", { when: defAge(i.updated) }) + " · " + Tn(i.entries | 0, "{n} entry", "{n} entries") + (i.expired ? " · " + T("Expired") : "") + (i.error ? " · " + T("Error: {error}", { error: i.error }) : "");
    return el("div", { class: "srccard" + (i.on ? "" : " off") },
      el("div", { class: "hd" }, el("b", {}, txt[n][0]),
        i.on && !dead ? el("span", { class: "pill " + (i.quality ? "ok" : "warn"), title: T("Only high quality lists may block") }, i.quality ? T("may block") : T("reports only")) : "",
        el("a", { href: m.url, target: "_blank", rel: "noopener" }, T("Source")),
        el("a", { href: m.terms, target: "_blank", rel: "noopener" }, T("Terms")), box),
      el("div", { class: "d" }, txt[n][1]),
      el("div", { class: "st" }, st),
      dead ? "" : el("div", { class: "st" }, T("Your device downloads this list directly from the provider; Shunt ships no data.")));
  }));
}
async function defSetSource(n, onNow, ask1) {
  const cfg = JSON.parse(JSON.stringify(defSt.config));
  if (onNow && ask1 && !(cfg.reputation_sources || []).includes(n) &&
    !(await ask(n === "et_compromised"
      ? T("This list is run by Emerging Threats. Its BSD licence is stated for the rule folder; for the IP lists the licence is not explicitly stated. Your device would download it directly from the provider. Switch it on?")
      : T("This list has restrictions. Switch it on?"), { ok: T("Switch on") }))) return renderDefense();
  if (n === "feodo" || n === "sslbl") {
    cfg.reputation_off = (cfg.reputation_off || []).filter((x) => x !== n);
    if (!onNow) cfg.reputation_off.push(n);
  } else {
    cfg.reputation_sources = (cfg.reputation_sources || []).filter((x) => x !== n);
    if (onNow) cfg.reputation_sources.push(n);
  }
  defSend(cfg);
}
// allow an address for good (it lands on the never-list and is never blocked)
async function defAllow(src) {
  if (!(await ask(T("Always allow {src}? It is added to the never-block list and any block on it is lifted.", { src }), { ok: T("Allow") }))) return;
  const cfg = JSON.parse(JSON.stringify(defSt.config));
  cfg.never = cfg.never || [];
  if (!cfg.never.includes(src)) cfg.never.push(src);
  await defSend(cfg);
  await defUnban(src);
}

function defDecoyChoice() {
  const box = el("input", { type: "checkbox", onchange: () => {
    const cfg = JSON.parse(JSON.stringify(defSt.config));
    cfg.decoys_when_exposed = box.checked;
    defSend(cfg);
  } });
  box.checked = !!(defSt.config && defSt.config.decoys_when_exposed);
  return el("label", { class: "row muted", style: "margin:4px 0" }, box, " ", T("Run the decoys anyway (not recommended with a public address)"));
}

// the outside check: your own server connects back and lists answering ports
function renderOutside() {
  const o = (defSt.config && defSt.config.outside_scan) || {};
  const x = defSt.exposed || {};
  const exp = !!(x.v4 || x.v6);
  const act = document.activeElement;
  if (act !== $("#out-host") && act !== $("#out-token")) { $("#out-host").value = o.host || ""; $("#out-token").value = o.token || ""; }
  $("#out-on").checked = !!o.enabled;
  $("#out-run").disabled = !(o.enabled && o.host && exp) || defOutBusy;
  $("#out-msg").textContent = !exp ? T("This device has no public address: there is nothing to check from outside.") : !o.enabled || !o.host ? T("Enter your server and allow the check first.") : "";
  const r = defSt.outside;
  $("#out-res").replaceChildren(...(r ? [el("div", {}, T("Last check {when}", { when: defAge(r.time) })),
    ...(r.checks || []).map((c) => el("div", { class: c.error ? "" : (c.open || []).length ? "banner bad" : "", style: c.error ? "color:var(--bad)" : "" },
      el("b", {}, c.family === "v6" ? "IPv6: " : "IPv4: "),
      c.error ? c.error : (c.open || []).length ? T("answering from the internet: {ports}", { ports: c.open.join(", ") }) : T("no port answers from the internet")))] : []));
}
let defOutBusy = false;
$("#out-save").addEventListener("click", () => {
  const cfg = JSON.parse(JSON.stringify(defSt.config));
  cfg.outside_scan = { enabled: $("#out-on").checked, host: $("#out-host").value.trim(), token: $("#out-token").value };
  defSend(cfg);
});
$("#out-run").addEventListener("click", async () => {
  if (!(await ask(T("Your own server will now connect to this device's public address and try a list of ports. Only do this with a server you run yourself. Continue?"), { ok: T("Check") }))) return;
  defOutBusy = true; renderOutside(); $("#out-msg").textContent = T("Checking … this can take a minute.");
  try { await api("POST", "/api/defense/outside-scan", {}); } catch (e) { toast(T("Nothing was checked: {error}", { error: e.message })); }
  defOutBusy = false;
  await loadDefense();
});

// the tile on the overview: gauge and the last five events
function renderDefTile() {
  const sum = $("#def-sum");
  if (!defSt) { $("#def-tile").replaceChildren(); sum.textContent = ""; return; }
  if (!defSt.enabled) {
    sum.textContent = T("off");
    $("#def-tile").replaceChildren(el("div", { class: "muted" }, T("Defense is off: nothing is watched, no decoys run.")));
    return;
  }
  // "new destination" notes are plentiful and harmless: counted, not listed here
  const last = defEvents.filter((e) => e.kind !== "first_seen").slice(-5).reverse();
  const fsN = (defSt.counts || {}).first_seen | 0;
  const bans = (defSt.bans || []).length;
  sum.textContent = bans ? Tn(bans, "{n} address blocked", "{n} addresses blocked") : "";
  const tb = defExposedBadge();
  $("#def-tile").replaceChildren(...(tb ? [tb] : []), el("div", { class: "deftile" },
    el("div", {}, defThermo(defSt, true)),
    el("div", { class: "evlist", style: "max-height:none" }, ...(last.length ? last.map((e) => defEventRow(e, true)) : [el("div", { class: "muted" }, "Nothing seen yet.")]),
      fsN ? el("div", { class: "muted" }, Tn(fsN, "{n} new destination noted in this network", "{n} new destinations noted in this network")) : "")));
}

// live window: hits on decoys, tarpit and the fake login, as they happen
function defPopupMode() { return lvGet("shunt-def-popup") || "auto"; }
function defLiveFeed(fresh) {
  const mode = defPopupMode();
  const hits = fresh.filter((e) => BAIT.includes(e.kind));
  if (mode === "never" || !defSt) return;
  if (hits.length) defLive = defLive.concat(hits).slice(-20);
  const allowed = mode === "always" || DEF_LEVELS.indexOf(defSt.level) >= DEF_LEVELS.indexOf("hot");
  const box = $("#def-live");
  if (hits.length && allowed && Date.now() > defMuteUntil) box.hidden = false;
  if (box.hidden) return;
  $("#def-live-title").textContent = T("Live: someone is knocking") + " · " + defLevelText()[defSt.level];
  $("#def-live-list").replaceChildren(...defLive.slice().reverse().map((e) => defEventRow(e)));
}
$("#def-live-close").addEventListener("click", () => { $("#def-live").hidden = true; defLive = []; defMuteUntil = Date.now() + 5 * 60 * 1000; });

// defBanChoice: a scan is blocked only after the source made a real
// connection to a decoy, because the sender address of single packets can be
// forged (config ban_unverified, default off = wait). Only matters while
// blocking of scans is on.
function defBanChoice(on, f) {
  const box = el("input", { type: "checkbox", onchange: () => {
    const cfg = JSON.parse(JSON.stringify(defSt.config));
    cfg.ban_unverified = box.checked;
    defSend(cfg);
  } });
  box.checked = !!(defSt.config && defSt.config.ban_unverified);
  box.disabled = !on || !f.watch || !f.block;
  return el("label", { class: "d defprobe" }, box, " ",
    T("Block at once, without waiting for a real connection (not recommended: sender addresses can be forged)"));
}

// defProbeChoice: the active DHCP probe sends a request into the network, so
// it has its own choice (auto = public networks only, never in quiet mode)
function defProbeChoice(on, key, label) {
  const cur = (defSt.config && defSt.config[key]) || "auto";
  const sel = el("select", { "aria-label": T(label), onchange: () => {
    const cfg = JSON.parse(JSON.stringify(defSt.config));
    cfg[key] = sel.value;
    defSend(cfg);
  } }, ...[["auto", T("Automatic")], ["on", T("On")], ["off", T("Off")]].map(([v, t]) => el("option", { value: v }, t)));
  sel.value = cur; sel.disabled = !on;
  return el("div", { class: "d defprobe" }, T(label), ": ", sel, " ",
    T("sends a request into the network, so by default only in public networks"));
}

async function defSend(cfg) {
  try { await api("POST", "/api/defense/config", cfg); } catch (e) { toast(T("Nothing was changed: {error}", { error: e.message })); }
  await loadDefense();
}
async function defSetFeature(name, f) {
  if (f.block && !(defSt.config.features[name] || {}).block &&
    !(await ask(T("Block the sources this switch finds? A block can also hit a harmless device on the network. Blocks end by themselves; you can lift them here."), { ok: T("Block") }))) return renderDefense();
  const cfg = JSON.parse(JSON.stringify(defSt.config));
  cfg.features = cfg.features || {};
  cfg.features[name] = f;
  defSend(cfg);
}
async function defUnban(src) {
  try { await api("POST", "/api/defense/unban", { src }); } catch (e) { toast(e.message); }
  loadDefense();
}

async function loadDefense() {
  try { defSt = await api("GET", "/api/defense"); } catch { defSt = null; }
  if (defSt) {
    defSt.bans = defSt.bans || []; defSt.decoys = defSt.decoys || [];
    defSt.config = defSt.config || { enabled: defSt.enabled, features: {} };
  }
  renderDefense();
}

async function pollDefense() {
  if (document.hidden || level() !== "opsec") return;
  await loadDefense();
  if (!defSt) return;
  try {
    const r = await api("GET", "/api/defense/events?since=" + defSince);
    if (r.last_seq < defSince) { defEvents = []; defSince = 0; defPrimed = false; return; } // the service restarted
    defSince = r.last_seq;
    if (r.events.length) {
      defEvents = defEvents.concat(r.events).slice(-200);
      renderDefense();
    }
    if (defPrimed) defLiveFeed(r.events);
    defPrimed = true;
  } catch { /* the next round tries again */ }
}

$("#def-on").addEventListener("change", () => {
  const cfg = JSON.parse(JSON.stringify(defSt.config));
  cfg.enabled = $("#def-on").checked;
  defSend(cfg);
});
$("#def-unban-all").addEventListener("click", async () => {
  if (await ask(T("Lift all blocks?"), { ok: T("Unblock all") })) defUnban("");
});
$("#def-popup").value = defPopupMode();
$("#def-popup").addEventListener("change", (e) => lvSet("shunt-def-popup", e.target.value));
$("#def-open").addEventListener("click", () => setTab("defense"));
setInterval(pollDefense, 2000);
setTimeout(pollDefense, 400);

// Pivot: everything one source did (the events the service still keeps)
let defSrcCur = "";
const SRC_BUCKETS = 24;
function defSrcSummary(evs) {
  const kinds = {}, ports = new Set();
  for (const e of evs) {
    kinds[e.kind] = (kinds[e.kind] || 0) + 1;
    if (e.port) ports.add((e.proto || "tcp") + "/" + e.port);
  }
  const t0 = new Date(evs[0].time).getTime(), t1 = new Date(evs[evs.length - 1].time).getTime();
  const span = Math.max(1, t1 - t0), tl = new Array(SRC_BUCKETS).fill(null).map(() => ({ n: 0, sev: 0 }));
  for (const e of evs) {
    const i = Math.min(SRC_BUCKETS - 1, Math.floor(((new Date(e.time).getTime() - t0) / span) * SRC_BUCKETS));
    tl[i].n++; tl[i].sev = Math.max(tl[i].sev, e.severity | 0);
  }
  return { kinds, ports: [...ports].sort((a, b) => parseInt(a.split("/")[1]) - parseInt(b.split("/")[1])), tl, t0, t1 };
}
function defRenderSource(src, evs) {
  $("#def-src-title").textContent = src;
  const ban = ((defSt && defSt.bans) || []).find((b) => b.src === src);
  const btn = ban
    ? el("button", { onclick: async () => { await defUnban(src); defOpenSource(src); } }, T("Unblock"))
    : el("button", { class: "primary", onclick: () => defBan(src) }, T("Block"));
  const allow = el("button", { onclick: async () => { await defAllow(src); defOpenSource(src); } }, T("Always allow"));
  const parts = [el("div", { class: "row" }, ban ? el("span", { class: "pill bad" }, T("Blocked")) : el("span", { class: "pill" }, T("Not blocked")),
    ban ? el("span", { class: "muted" }, defLeft(ban.expires)) : "", el("span", { class: "spacer" }), allow, btn)];
  if (!evs.length) {
    parts.push(el("div", { class: "muted" }, T("No events from this source are kept any more.")));
  } else {
    const s = defSrcSummary(evs), peak = Math.max(...s.tl.map((b) => b.n));
    parts.push(el("div", { class: "muted" }, T("First seen {a}, last seen {b}, {n} events", { a: defTime(s.t0), b: defTime(s.t1), n: evs.length })));
    parts.push(el("div", { class: "chips" }, ...Object.keys(s.kinds).map((k) => el("span", { class: "pill" }, (defKindText()[k] || k) + " × " + s.kinds[k]))));
    if (s.ports.length) parts.push(el("div", {}, el("span", { class: "muted" }, T("Ports") + ": "), el("span", { class: "mono" }, s.ports.join(", "))));
    parts.push(el("div", { class: "tl", "aria-label": T("Timeline") }, ...s.tl.map((b) => el("i", { class: "s" + b.sev, style: "height:" + (b.n ? Math.max(8, Math.round((b.n / peak) * 100)) : 0) + "%" }))));
    parts.push(el("div", { class: "evlist" }, ...evs.slice().reverse().map((e) => defEventRow(e))));
  }
  if (typeof evSourceBox === "function") parts.push(evSourceBox(src));
  $("#def-src-body").replaceChildren(...parts);
}
async function defOpenSource(src) {
  defSrcCur = src;
  $("#def-src").hidden = false;
  try {
    const r = await api("GET", "/api/defense/events?src=" + encodeURIComponent(src));
    if (defSrcCur === src) defRenderSource(src, r.events || []);
  } catch (e) { $("#def-src-body").replaceChildren(el("div", { class: "muted" }, e.message)); }
}
async function defBan(src) {
  if (!(await ask(T("Block {src}? A block can also hit a harmless device. It ends by itself; you can lift it here.", { src }), { ok: T("Block") }))) return;
  try { await api("POST", "/api/defense/ban", { src }); } catch (e) { toast(T("Nothing was changed: {error}", { error: e.message })); }
  await loadDefense();
  defOpenSource(src);
}
function defCloseSource() { $("#def-src").hidden = true; defSrcCur = ""; }
$("#def-src-close").addEventListener("click", defCloseSource);
$("#def-src").addEventListener("click", (e) => { if (e.target.id === "def-src") defCloseSource(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#def-src").hidden) defCloseSource(); });

// Network reports (one per network, kept by the service)
let defReports = [];
const defPropText = () => ({ yes: T("yes"), none_seen: T("none seen so far"), unknown: T("unknown") });
function defRenderReports() {
  const box = $("#def-reports");
  if (!defReports.length) { box.replaceChildren(el("div", { class: "muted" }, T("No network report yet."))); return; }
  const kinds = defKindText(), pr = defPropText();
  const day = (t) => { const d = new Date(t); return isNaN(d) ? "" : d.toLocaleString([], { dateStyle: "short", timeStyle: "short" }); };
  box.replaceChildren(...defReports.map((r) => {
    const counts = Object.keys(r.counts || {}).filter((k) => r.counts[k] && k !== "net_enter").sort((a, b) => r.counts[b] - r.counts[a]);
    const srcs = Object.entries(r.sources || {}).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const lv = DEF_LEVELS.includes(LevelOf(r.peak_heat)) ? LevelOf(r.peak_heat) : "quiet";
    return el("div", { class: "repcard" },
      el("div", { class: "hd" }, el("b", { class: "mono" }, r.key.slice(0, 8)), el("span", { class: "pill" }, defClassText()[r.class] || defClassText().public),
        r.key === defRepCur ? el("span", { class: "pill ok" }, T("now")) : "", el("span", { class: "spacer" }),
        el("span", { class: "pill heat-" + lv, title: T("Highest heat") }, T("Peak {n}", { n: r.peak_heat | 0 }))),
      el("div", { class: "muted" }, T("First seen {a}, last seen {b}", { a: day(r.first_seen), b: day(r.last_seen) })),
      el("div", { class: "chips" }, ...(counts.length ? counts.map((k) => el("span", { class: "pill" }, (kinds[k] || k) + " × " + r.counts[k])) : [el("span", { class: "muted" }, T("Nothing seen yet."))])),
      el("div", {}, el("span", { class: "muted" }, T("DNS redirected") + ": "), pr[r.dns_redirect] || pr.unknown, "  ·  ",
        el("span", { class: "muted" }, T("Login page (captive)") + ": "), pr[r.captive] || pr.unknown, "  ·  ",
        el("span", { class: "muted" }, T("Isolation between devices") + ": "), pr[r.isolation] || pr.unknown),
      srcs.length ? el("div", {}, el("span", { class: "muted" }, T("Sources") + ": "), el("span", { class: "mono" }, srcs.map(([k, n]) => k + " (" + n + ")").join(", "))) : "");
  }));
}
function LevelOf(h) { h |= 0; return h >= 80 ? "attack" : h >= 50 ? "hot" : h >= 25 ? "noticed" : "quiet"; }
let defRepCur = "";
async function loadDefReports() {
  try {
    const r = await api("GET", "/api/defense/reports");
    defReports = r.reports || []; defRepCur = r.current || "";
  } catch { defReports = []; }
  defRenderReports();
}
$("#def-rep-export").addEventListener("click", async () => {
  try {
    const r = await api("GET", "/api/defense/reports?export=1");
    const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" })), download: "shunt-network-report.json" });
    document.body.appendChild(a); a.click(); a.remove();
  } catch (e) { toast(e.message); }
});
setInterval(() => { if (!document.hidden && level() === "opsec" && defSt) loadDefReports(); }, 15000);
setTimeout(() => { if (level() === "opsec") loadDefReports(); }, 900);
