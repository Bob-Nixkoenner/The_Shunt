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
  beacon: T("Regular beacon traffic"), dns_tunnel: T("DNS tunnel"), evil_twin: T("Evil twin Wi-Fi"), ban: T("Blocked"),
  unban: T("Block lifted"), net_enter: T("Network joined"), observation: T("Observation"),
});
// what each switch does: [name, one line]
const defFeatText = () => ({
  decoy: [T("Decoy ports"), T("Fake services on common ports (not in trusted or managed networks).")],
  tarpit: [T("Tarpit"), T("Holds scanners in slow connections.")],
  cowrie: [T("Fake login"), T("A fake service records login attempts.")],
  scan: [T("Port scans"), T("Many ports from one source.")],
  brute: [T("Brute force"), T("Many failed connections in a row.")],
  reputation: [T("Bad address lists"), T("Peers and destinations on lists of known attackers.")],
  first_seen: [T("New destinations"), T("An app contacts an address for the first time.")],
  arp: [T("ARP/NDP spoofing"), T("The gateway's hardware address changes.")],
  dhcp: [T("Rogue DHCP"), T("A second DHCP server answers.")],
  dns: [T("DNS tampering"), T("DNS answers differ or port 53 is diverted.")],
  tls: [T("Certificate changes"), T("The certificate of a known target changes.")],
  beacon: [T("Beacons"), T("Traffic at regular intervals.")],
  dns_tunnel: [T("DNS tunnels"), T("Long, random names and many TXT queries.")],
  evil_twin: [T("Evil twin"), T("Same Wi-Fi name, different access point.")],
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

function defEventRow(e, compact) {
  const kind = defKindText()[e.kind] || e.kind;
  const where = [e.src, e.port ? (e.proto || "") + (e.port ? ":" + e.port : "") : ""].filter(Boolean).join(" ");
  return el("div", { class: "ev s" + (e.severity | 0) },
    el("span", { class: "t" }, defTime(e.time)), el("span", { class: "dot" }),
    el("span", { class: "x" }, el("b", {}, kind), where ? el("span", { class: "mono" }, " " + where) : "",
      e.detail && !compact ? el("div", { class: "muted" }, e.detail) : ""));
}

function renderDefense() {
  const sec = $("#sec-defense");
  const on = defSt && defSt.enabled;
  sec.hidden = !defSt;
  if (!defSt) {
    $("#def-thermo").replaceChildren(el("div", { class: "muted" }, T("The service has no defense module yet.")));
    $("#def-feats").replaceChildren(); $("#def-bans").replaceChildren(); $("#def-events").replaceChildren();
    $("#def-class").replaceChildren(); $("#def-notes").textContent = "";
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
  $("#def-notes").textContent = notes.join(" ");
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
    return el("tr", {}, el("td", {}, el("b", {}, txt[k][0]), el("div", { class: "d" }, txt[k][1])), el("td", { class: "sw" }, watch), el("td", { class: "sw" }, block));
  }));
  // bans
  const bans = defSt.bans || [];
  $("#def-unban-all").hidden = !bans.length;
  $("#def-bans").replaceChildren(...(bans.length ? bans.map((b) => el("tr", {},
    el("td", { class: "mono" }, b.src),
    el("td", {}, defKindText()[b.reason] || b.reason, " ", el("span", { class: "muted" }, defLeft(b.expires))),
    el("td", { style: "text-align:right" }, el("button", { onclick: () => defUnban(b.src) }, "Unblock"))))
    : [el("tr", {}, el("td", { class: "muted" }, "No address is blocked."))]));
  // events
  const shown = defEvents.slice(-100).reverse();
  $("#def-evsum").textContent = defEvents.length ? T("{n} shown", { n: shown.length }) : "";
  $("#def-events").replaceChildren(...(shown.length ? shown.map((e) => defEventRow(e)) : [el("div", { class: "muted" }, "Nothing seen yet.")]));
  renderDefTile();
}

// the tile on the overview: gauge and the last five events
function renderDefTile() {
  const sum = $("#def-sum");
  if (!defSt) { $("#def-tile").replaceChildren(); sum.textContent = ""; return; }
  if (!defSt.enabled) {
    sum.textContent = T("off");
    $("#def-tile").replaceChildren(el("div", { class: "muted" }, T("Defense is off: nothing is watched, no decoys run.")));
    return;
  }
  const last = defEvents.slice(-5).reverse();
  const bans = (defSt.bans || []).length;
  sum.textContent = bans ? Tn(bans, "{n} address blocked", "{n} addresses blocked") : "";
  $("#def-tile").replaceChildren(el("div", { class: "deftile" },
    el("div", {}, defThermo(defSt, true)),
    el("div", { class: "evlist", style: "max-height:none" }, ...(last.length ? last.map((e) => defEventRow(e, true)) : [el("div", { class: "muted" }, "Nothing seen yet.")]))));
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
