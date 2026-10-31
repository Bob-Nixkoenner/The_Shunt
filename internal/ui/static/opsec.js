"use strict";
// Opsec assistant. Switching to Opsec lists the strict settings it stands
// for, each with a switch (on by default); nothing changes until the user
// confirms. What it changed is remembered (ui-state "shunt-opsec-undo"), and
// switching away from Opsec offers to put those settings back.
//
// Item fields: sets = config fields [path, value] written when on (os: where
// the service has them), ui = a page setting [key, value], builtin = systems
// where it is always on anyway, na = not available yet anywhere.

const OPSEC_ITEMS = [
  { id: "killswitch", text: "Kill switch on",
    help: "Traffic that bypasses the tunnels is blocked, also while the service is stopped.",
    os: ["windows"], sets: [[["daemon", "kill_switch"], true]],
    builtin: { linux: "Always on under Linux: apps of a tunnel that is down are blocked, never sent past it." } },
  { id: "bootlock", text: "Network blocked at boot until The Shunt runs",
    help: "Programs that start before The Shunt cannot send their first packets in clear text.",
    os: ["linux"], sets: [[["daemon", "boot_lockdown"], "on"]],
    builtin: { windows: "Part of the kill switch on Windows: it stays in place at boot." } },
  { id: "stealth", text: "Disguise in foreign networks: new MAC address on every connection, no host name in DHCP",
    help: "Networks you join see neither your device's real address nor its name. Applies from the next connection; at home a network profile can say otherwise.",
    os: ["linux"], sets: [[["daemon", "mac"], "random"], [["daemon", "dhcp_hostname"], "none"]] },
  { id: "captive", text: "No check for Wi-Fi login pages",
    help: "The check asks a test address directly over the network you are in, on purpose (a login page sits in front of every tunnel). Without it you open login pages yourself: tray → “Wi-Fi login page…”.",
    os: ["linux"], sets: [[["daemon", "captive_check"], false]],
    builtin: { windows: "The Shunt makes no such check on Windows." } },
  { id: "inbound", text: "Incoming connections closed",
    help: "Nothing new reaches this computer from the network or through a tunnel; answers to your own connections pass. Network profiles you trust can open single ports.",
    os: ["linux", "windows"], sets: [[["inbound", "enabled"], true]] },
  { id: "clock", text: "Clock check through the tunnel",
    help: "A wrong clock makes tunnel handshakes and certificates fail. The time is asked from web servers through your default route.",
    os: ["windows"], sets: [[["daemon", "clock_check"], true]],
    builtin: { linux: "Always on under Linux." } },
  { id: "tcpts", text: "TCP timestamps off",
    help: "Timestamps tell others on a foreign network how long this computer has been running, which helps to recognise it again. Tunnel traffic is not affected.",
    os: ["linux"], sets: [[["daemon", "tcp_timestamps"], "off"]] },
  { id: "icmpts", text: "No answers to ICMP timestamp requests", na: true,
    help: "They reveal the clock of this computer to others on the network." },
  { id: "strict", text: "Stricter security check",
    help: "Every warning shows as a banner on the overview instead of a quiet note, e.g. an OpenVPN file without tls-crypt, DNS that can go past the tunnel, or everything else going direct.",
    ui: ["shunt-opsec-strict", "1"] },
  { id: "history", text: "Keep no speed test history",
    help: "The last measurements are deleted and new ones are not stored.",
    ui: ["shunt-no-history", "1"] },
  { id: "stats", text: "Keep no traffic statistics", na: true,
    help: "The service counts traffic per tunnel and blocked names on this computer (nothing is sent anywhere)." },
];

const opsecOS = () => (typeof onWindows === "function" && onWindows() ? "windows" : "linux");
const cfgGet = (m, path) => path.reduce((o, k) => (o == null ? undefined : o[k]), m);
function cfgPut(m, path, v) {
  let o = m;
  for (const k of path.slice(0, -1)) o = o[k] = o[k] || {};
  const last = path[path.length - 1];
  if (v === null || v === undefined) delete o[last]; else o[last] = v;
}
// state of an item on this system: "set" (can be switched), "builtin", "na"
function opsecState(it) {
  if (it.na) return "na";
  if (it.ui) return "set";
  if (it.os.includes(opsecOS())) return "set";
  return it.builtin && it.builtin[opsecOS()] ? "builtin" : "na";
}
function opsecIsOn(it) {
  if (it.ui) return lvGet(it.ui[0]) === it.ui[1];
  return !!model && it.sets.every(([p, v]) => cfgGet(model, p) === v);
}

function opsecUndo() { try { return JSON.parse(lvGet("shunt-opsec-undo") || "{}") || {}; } catch (e) { return {}; } }

// lvDialog shows the list; resolves to "ok", "keep" or null (cancelled)
function lvDialog(o) {
  return new Promise((resolve) => {
    const m = $("#lvmodal");
    $("#lv-title").textContent = o.title;
    $("#lv-intro").textContent = o.intro;
    $("#lv-items").replaceChildren(...o.rows);
    $("#lv-note").replaceChildren(...o.note);
    $("#lv-ok").textContent = o.ok;
    $("#lv-keep").hidden = !o.keep;
    $("#lv-keep").textContent = o.keep || "";
    m.hidden = false;
    $("#lv-ok").focus();
    const done = (v) => { m.hidden = true; m.onclick = m.onkeydown = null; resolve(v); };
    $("#lv-ok").onclick = () => done("ok");
    $("#lv-keep").onclick = () => done("keep");
    $("#lv-cancel").onclick = () => done(null);
    m.onclick = (e) => { if (e.target === m) done(null); };
    m.onkeydown = (e) => { if (e.key === "Escape") done(null); };
  });
}

function lvRow(it, box, note) {
  return el("label", { class: "lvitem" + (box.disabled ? " na" : "") }, box, el("b", {}, T(it.text)), el("span", { class: "muted" }, note));
}

// saveModel writes the edited config like "Save & apply"; false on failure
async function opsecSave() {
  let err = "";
  const ok = await checkOrSave(true, { config: model }, (t, cls) => { if (cls === "err") err = t; });
  await loadConfig();
  refresh();
  if (!ok) toast(T("Nothing was changed: {error}", { error: err }));
  return ok;
}

// opsecSwitch runs the assistant for a switch from level `from` to `to`;
// false = stay where you are.
async function opsecSwitch(from, to) {
  if ((to === "opsec") === (from === "opsec")) return true;
  if (!model) await loadConfig();
  if (!model) { toast(T("The service is not reachable: the level stays as it is.")); return false; }
  if ($("#savebar").classList.contains("dirty")) { toast(T("Save or discard your other changes first")); return false; }
  return to === "opsec" ? opsecOn() : opsecOff();
}

async function opsecOn() {
  const boxes = {};
  const rows = OPSEC_ITEMS.map((it) => {
    const st = opsecState(it);
    const on = opsecIsOn(it);
    const box = el("input", { type: "checkbox" });
    box.checked = st !== "na";
    box.disabled = st !== "set";
    if (st === "set" && !on) boxes[it.id] = box;
    const note = st === "na" ? (it.na ? T("Not available yet.") : T("Not available on this system.")) + " " + T(it.help)
      : st === "builtin" ? T(it.builtin[opsecOS()])
      : on ? T("Already set.") + " " + T(it.help) : T(it.help);
    if (st === "set" && on) box.disabled = true;
    return lvRow(it, box, note);
  });
  const note = [el("div", {}, el("b", {}, T("Opsec is no guarantee.")), " ",
    T("These settings close common leaks of this computer; they do not make you anonymous. Your VPN provider still sees your traffic, and websites still recognise you by logins, cookies and your browser."))];
  if ((model.daemon.default_route || "direct") === "direct") note.push(el("div", { style: "color:var(--warn);margin-top:6px" },
    T("Everything else goes direct, past every tunnel. Opsec does not change that for you: choose a tunnel under “Everything else goes”.")));
  const r = await lvDialog({ title: T("What Opsec sets"), intro: T("Each switch is one setting. Nothing changes before you confirm; switching back to Pro or Simple offers to undo it."),
    rows, note, ok: T("Switch to Opsec") });
  if (r !== "ok") return false;
  const recs = {};
  let cfgChanged = false;
  for (const it of OPSEC_ITEMS) {
    const box = boxes[it.id];
    if (!box || !box.checked) continue;
    if (it.ui) recs[it.id] = { ui: [it.ui[0], lvGet(it.ui[0]) || null] };
    else {
      recs[it.id] = { cfg: it.sets.map(([p]) => [p, cfgGet(model, p) ?? null]) };
      for (const [p, v] of it.sets) cfgPut(model, p, v);
      cfgChanged = true;
    }
  }
  if (cfgChanged && !(await opsecSave())) return false; // nothing changed, the level stays
  for (const it of OPSEC_ITEMS) if (recs[it.id] && it.ui) lvSet(it.ui[0], it.ui[1]);
  // an earlier, kept Opsec change keeps its value from before that time
  const undo = opsecUndo();
  for (const [id, rec] of Object.entries(recs)) if (!undo[id]) undo[id] = rec;
  lvSet("shunt-opsec-undo", JSON.stringify(undo));
  if (recs.history) api("DELETE", "/api/speedtest/history").catch(() => {});
  return true;
}

async function opsecOff() {
  const undo = opsecUndo();
  const items = OPSEC_ITEMS.filter((it) => undo[it.id]);
  if (!items.length) return true;
  const boxes = {};
  const rows = items.map((it) => {
    const box = el("input", { type: "checkbox", checked: "" });
    boxes[it.id] = box;
    return lvRow(it, box, T("Set by Opsec. Ticked: back to how it was before."));
  });
  const r = await lvDialog({ title: T("Undo the Opsec settings?"), intro: T("Opsec changed these settings. Ticked ones go back to how they were before; the others stay as they are."),
    rows, note: [], ok: T("Undo ticked ones"), keep: T("Keep all") });
  if (r === null) return false;
  if (r === "keep") { lvSet("shunt-opsec-undo", "{}"); return true; }
  let cfgChanged = false;
  for (const it of items) {
    if (!boxes[it.id].checked) continue;
    const rec = undo[it.id];
    if (rec.ui) { if (rec.ui[1] === null) lvDel(rec.ui[0]); else lvSet(rec.ui[0], rec.ui[1]); }
    if (rec.cfg) { for (const [p, v] of rec.cfg) cfgPut(model, p, v); cfgChanged = true; }
  }
  if (cfgChanged && !(await opsecSave())) return false;
  lvSet("shunt-opsec-undo", "{}");
  return true;
}
