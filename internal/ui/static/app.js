"use strict";
// The Shunt UI. No frameworks, no external requests.

const $ = (s) => document.querySelector(s);
let status = null;
let apps = [];
let ffProfiles = [];

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) e.append(k instanceof Node ? k : document.createTextNode(String(k ?? "")));
  return e;
}

function routeTag(r) {
  const cls = r.startsWith("tunnel:") ? "tunnel" : r.startsWith("link:") ? "link" : r;
  return el("span", { class: "route " + cls }, r || "–");
}

async function api(method, path, body) {
  const opt = { method, headers: { "X-Shunt": "1" } };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3200);
}

// ask shows a dialog in the page. Resolves to true / the entered text, or
// null when cancelled (Escape, Cancel, click outside).
function ask(msg, opts = {}) {
  return new Promise((resolve) => {
    const m = $("#modal"), inp = $("#modal-input"), ok = $("#modal-ok");
    $("#modal-msg").textContent = msg;
    inp.hidden = opts.input === undefined;
    inp.value = opts.input || "";
    ok.textContent = opts.ok || "OK";
    ok.className = opts.danger ? "danger" : "primary";
    m.hidden = false;
    (inp.hidden ? ok : inp).focus();
    const done = (v) => {
      m.hidden = true;
      m.onclick = ok.onclick = $("#modal-cancel").onclick = m.onkeydown = null;
      resolve(v);
    };
    ok.onclick = () => done(inp.hidden ? true : inp.value);
    $("#modal-cancel").onclick = () => done(null);
    m.onclick = (e) => { if (e.target === m) done(null); };
    m.onkeydown = (e) => {
      if (e.key === "Escape") done(null);
      if (e.key === "Enter") ok.click();
    };
  });
}

function bytes(n) {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}

function ago(ts) {
  if (!ts || ts.startsWith("0001")) return "never";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(ts)) / 1000));
  if (s < 90) return s + "s ago";
  if (s < 5400) return Math.round(s / 60) + " min ago";
  return Math.round(s / 3600) + " h ago";
}

function render() {
  const st = status;
  const win = !!st && st.platform === "windows";
  document.body.classList.toggle("windows", win);
  if (win && !document.body.dataset.winText) { // Linux paths in the static text
    document.body.dataset.winText = "1";
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n; (n = w.nextNode());) n.nodeValue = n.nodeValue.replace("/etc/shunt/shunt.toml", "C:\\ProgramData\\Shunt\\shunt.toml");
  }
  const state = $("#state");
  if (!st) { state.className = "pill bad"; state.textContent = "shuntd not reachable"; return; }

  const down = st.tunnels.filter((t) => !t.disabled).filter((t) => !t.up || !t.peers || t.peers.every((p) => !p.last_handshake || p.last_handshake.startsWith("0001")));
  if (st.panic) { state.className = "pill bad"; state.textContent = "PANIC – everything blocked"; }
  else if (st.pass_left) { state.className = "pill bad"; state.textContent = "PASS – unprotected"; }
  else if (st.captive === "portal") { state.className = "pill warn"; state.textContent = "Wi-Fi login needed – tunnels wait for it"; }
  else if (st.pending) { state.className = "pill warn"; state.textContent = st.pending + " app(s) waiting for a route"; }
  else if (down.length) { state.className = "pill warn"; state.textContent = down.length + " tunnel(s) without connection – their apps are blocked"; }
  else if (st.dns_failing && Object.keys(st.dns_failing).length) { state.className = "pill warn"; state.textContent = "DNS not working: " + Object.keys(st.dns_failing).sort().join(", "); }
  else { state.className = "pill ok"; state.textContent = "protected"; }
  $("#defroute").replaceChildren("default route ", routeTag(st.default_route), ...(st.network ? [el("span", { class: "muted" }, " (network “" + st.network + "”)")] : []));

  const pass = $("#pass");
  pass.textContent = st.pass_left ? "End pass (" + Math.floor(st.pass_left / 60) + ":" + String(st.pass_left % 60).padStart(2, "0") + ")" : "Pass 5 min";
  pass.classList.toggle("on", !!st.pass_left);
  const panic = $("#panic");
  panic.textContent = st.panic ? "Release panic" : "PANIC";
  panic.classList.toggle("on", st.panic);

  $("#banners").replaceChildren(...(st.warnings || []).map((w) => el("div", { class: "banner" }, "⚠ ", w)),
    ...(st.panic ? [el("div", { class: "banner bad" }, "Panic mode is on: all traffic except loopback is dropped.")] : []),
    ...(st.pass_left && !st.panic ? [el("div", { class: "banner bad" }, "Pass: everything goes direct – past tunnels, blocks and the DNS filter – for another " +
      Math.ceil(st.pass_left / 60) + " min. Connections opened meanwhile are cut when it ends.")] : []));

  $("#tunnels").replaceChildren(...(st.tunnels.length ? st.tunnels.map((t) => {
    const p = (t.peers || [])[0] || {};
    const hs = p.last_handshake && !p.last_handshake.startsWith("0001");
    const ovpn = t.driver === "openvpn" || t.driver === "tailscale";
    return el("div", { class: "card " + (t.up && hs ? "up" : "down") },
      el("div", { class: "name" }, t.name, t.disabled ? el("span", { class: "pill" }, "off") : el("span", { class: "pill " + (t.up && hs ? "ok" : "bad") }, t.up ? (hs ? "up" : ovpn ? "connecting" : "no handshake") : "down")),
      el("div", { class: "kv" },
        el("span", {}, "interface"), el("span", { class: "mono" }, t.iface + (t.driver ? " · " + t.driver : "")),
        el("span", {}, "endpoint"), el("span", { class: "mono" }, p.endpoint || "–"),
        ...(t.via ? [el("span", {}, "multi-hop"), el("span", {}, "through " + t.via)] : []),
        el("span", {}, ovpn ? "connected" : "handshake"), el("span", {}, ago(p.last_handshake)),
        el("span", {}, "traffic"), el("span", {}, "↓ " + bytes(p.rx_bytes || 0) + "  ↑ " + bytes(p.tx_bytes || 0)),
        ...(st.traffic && st.traffic[t.name] ? [el("span", {}, "this month"), el("span", {},
          "↓ " + bytes(st.traffic[t.name].month.rx) + "  ↑ " + bytes(st.traffic[t.name].month.tx) +
          "  (total ↓ " + bytes(st.traffic[t.name].total.rx) + "  ↑ " + bytes(st.traffic[t.name].total.tx) + ")")] : []),
        ...(t.up && t.health && t.health.state !== "unknown" ? [el("span", {}, "health"), el("span", {},
          el("span", { class: "pill verdict " + ({ ok: "ok", idle: "", stale: "warn", down: "bad" }[t.health.state] || "") },
            { ok: "ok", idle: "idle", stale: "no answers", down: "down" }[t.health.state] || t.health.state),
          t.health.latency_ms ? " " + t.health.latency_ms + " ms" : "",
          t.health.loss > 0 ? " · " + Math.round(t.health.loss * 100) + " % lost" : "")] : []),
        ...(t.error ? [el("span", {}, "error"), el("span", { style: "color:var(--bad)" }, t.error)] : [])));
  }) : [el("div", { class: "muted" }, "No tunnels configured – import one under Configure.")]),
    ...(st.traffic && st.traffic.total && st.traffic.total.total.rx + st.traffic.total.total.tx > 0 ? [el("div", { class: "muted", style: "grid-column:1/-1" },
      "All tunnels: this month ↓ " + bytes(st.traffic.total.month.rx) + " ↑ " + bytes(st.traffic.total.month.tx) +
      " · last month ↓ " + bytes(st.traffic.total.last_month.rx) + " ↑ " + bytes(st.traffic.total.last_month.tx) +
      " · total ↓ " + bytes(st.traffic.total.total.rx) + " ↑ " + bytes(st.traffic.total.total.tx))] : []));

  // Selects are rebuilt only when the routes change: rebuilding closes a
  // dropdown the user has open.
  const routesKey = st.routes.join(",");
  const routesChanged = routesKey !== render.routesKey;
  render.routesKey = routesKey;
  if (routesChanged) {
    const sel = $("#runroute");
    const cur = sel.value;
    sel.replaceChildren(...st.routes.map((r) => el("option", { value: r }, r)));
    sel.value = cur && st.routes.includes(cur) ? cur : (st.routes.find((r) => r.startsWith("tunnel:")) || "direct");
  }

  $("#groups").replaceChildren(...st.groups.filter((g) => g.procs > 0 || !g.name.startsWith("via:")).map((g) =>
    el("tr", {},
      el("td", {}, g.name.replace(/^via:/, "started via ").replace(/^app:/, "app rule: ")),
      el("td", {}, routeTag(g.route)),
      el("td", {}, g.apps && g.apps.length ? g.apps.map((a) => el("span", { class: "chip" }, a)) : el("span", { class: "muted" }, "–")))));
  if (!$("#groups").children.length) $("#groups").append(el("tr", {}, el("td", { colspan: 3, class: "muted" }, "Nothing running in a route yet – start an app above. Everything else takes the default route.")));

  $("#rules").replaceChildren(...st.rules.map((r, i) => {
    const [name, route] = r.split(" -> ");
    return el("tr", {}, el("td", { class: "muted" }, i + 1 + "."), el("td", {}, name), el("td", {}, routeTag(route)));
  }), el("tr", {}, el("td", { class: "muted" }, st.rules.length + 1 + "."), el("td", { class: "muted" }, "everything else"), el("td", {}, routeTag(st.default_route))));

  $("#dns").replaceChildren(...Object.entries(st.dns || {}).sort().map(([r, ups]) =>
    el("tr", {}, el("td", {}, routeTag(r)), el("td", { class: "mono" }, ups.join(", ")))));

  if (routesChanged) { renderApps(); renderLaunchers(); }
}

function renderApps() {
  if (!status) return;
  const f = $("#appfilter").value.toLowerCase();
  const routes = ["", ...status.routes];
  // Default: apps that use the network or are already routed; the rest
  // (hundreds of tools on Kali) only on request or when searching.
  const all = $("#allapps").checked || f !== "";
  const shown = apps.filter((a) => !a.clone && (all || a.online || a.route) && (!f || (a.name + a.id).toLowerCase().includes(f)));
  shown.sort((x, y) => (y.route ? 1 : 0) - (x.route ? 1 : 0));
  $("#appcount").textContent = "(" + apps.length + ")";
  $("#apps").replaceChildren(...shown.map((a) => {
    const s = el("select", {
      onchange: async (e) => {
        try {
          await api("POST", "/api/apps", { id: a.id, route: e.target.value });
          a.route = e.target.value;
          toast(a.name + (a.route ? " now starts via " + a.route : " restored to its original entry") + " – close all its windows and start it again");
          warnRunning(a);
        } catch (err) { toast(err.message); e.target.value = a.route || ""; }
      },
    }, ...routes.map((r) => el("option", { value: r }, r || "system default")));
    s.value = a.route || "";
    return el("tr", {}, el("td", {}, a.name, " ", el("span", { class: "muted mono" }, a.id)), el("td", {}, s));
  }));
}

// processName guesses the process name of a menu app: "brave-browser" ->
// "brave", "org.mozilla.firefox" -> "firefox", "firefox-esr" -> "firefox".
function processName(id) {
  const last = id.split(".").pop().toLowerCase();
  return last.split("-")[0] || last;
}

// warnRunning: a browser that already runs keeps its route – new windows
// open in the old process. Say so instead of letting the user wonder.
async function warnRunning(a) {
  const want = a.route || status.default_route;
  let ps = [];
  try { ps = await api("GET", "/api/procs?name=" + encodeURIComponent(processName(a.id))); } catch { return; }
  const wrong = ps.filter((p) => p.route.replace(/ \(default\)$/, "") !== want);
  if (!wrong.length) return;
  const routes = [...new Set(wrong.map((p) => p.route))].join(", ");
  await ask(a.name + " is still running (" + wrong.length + " processes in " + routes + ").\n\nNew windows open in that old process and keep its route. Quit it completely – also from the tray or background mode (Brave/Chrome: Settings → System → “Continue running background apps” off) – then start it again.\n\nCheck with: shunt which " + processName(a.id), { ok: "Got it" });
}

function routeSelect(value, onchange, withDefault) {
  const routes = (withDefault ? [""] : []).concat(status ? status.routes : []);
  const s = el("select", { onchange }, ...routes.map((r) => el("option", { value: r }, r || "system default")));
  s.value = value;
  return s;
}

const firefoxApp = () => (apps.find((a) => /^(firefox-esr|firefox|org\.mozilla\.firefox)$/.test(a.id)) || {}).id;

function renderLaunchers() {
  if (!status) return;
  const launchers = apps.filter((a) => a.clone);
  $("#launchers").replaceChildren(...launchers.map((a) => el("tr", {},
    el("td", {}, a.name, " ", el("span", { class: "muted mono" }, a.clone + " " + (a.args || ""))),
    el("td", {}, routeSelect(a.route, async (e) => {
      try { await api("POST", "/api/apps", { id: a.id, route: e.target.value }); a.route = e.target.value; toast(a.name + " now via " + a.route); }
      catch (err) { toast(err.message); e.target.value = a.route; }
    })),
    el("td", {}, el("span", { class: "muted lstate", "data-id": a.id }, "…")),
    el("td", {}, el("button", { onclick: () => startLauncher(a) }, "Start")),
    el("td", {}, el("button", { onclick: async () => {
      try { await api("POST", "/api/apps", { id: a.id, route: "" }); toast(a.name + " removed"); await loadApps(); }
      catch (err) { toast(err.message); }
    } }, "Remove")))));

  updateLauncherState();

  const ff = firefoxApp();
  const have = new Set(launchers.map((a) => a.args));
  // launchers made before profiles were started by folder used -P <name>
  const todo = ff ? ffProfiles.filter((p) => !have.has(profileArgs(p)) && !have.has(legacyProfileArgs(p.name))) : [];
  $("#ffprofiles").replaceChildren(...(todo.length ? [el("div", { class: "row", style: "margin-bottom:10px" },
    el("span", { class: "muted" }, "Firefox profiles found:"),
    ...todo.map((p) => {
      const sel = routeSelect(status.routes.find((r) => r.startsWith("tunnel:")) || "direct");
      return el("span", { class: "chip", style: "padding:4px 8px;display:inline-flex;gap:6px;align-items:center", title: p.path }, p.name, sel,
        el("button", { onclick: () => createLauncher(ff, "Firefox " + p.name, profileArgs(p), sel.value) }, "+ launcher"));
    }))] : []));

  const lapp = $("#lapp");
  const cur = lapp.value;
  lapp.replaceChildren(...apps.filter((a) => !a.clone && (a.online || a.id === cur)).map((a) => el("option", { value: a.id }, a.name)));
  lapp.value = cur || ff || (lapp.options[0] && lapp.options[0].value) || "";
  const lroute = $("#lroute");
  const curRoute = lroute.value;
  lroute.replaceChildren(...status.routes.map((r) => el("option", { value: r }, r)));
  lroute.value = curRoute || status.routes.find((r) => r.startsWith("tunnel:")) || "direct";
}

// The command of a launcher: what its Exec line runs after "run --via ROUTE --",
// without the desktop field codes (%u, %F, ...).
function launcherCmd(a) {
  const words = (a.exec || "").match(/"(?:[^"\\]|\\.)*"|\S+/g) || [];
  const i = words.indexOf("--");
  return words.slice(i + 1).filter((w) => !/^%[a-zA-Z%]$/.test(w)).join(" ");
}
const launcherProg = (a) => (launcherCmd(a).split(/\s+/)[0] || "").replace(/^"|"$/g, "").split("/").pop();

async function startLauncher(a) {
  const cmd = launcherCmd(a);
  if (!cmd) return toast("Cannot read the command of " + a.name);
  try {
    const p = await api("GET", "/api/procs?name=" + encodeURIComponent(launcherProg(a)));
    const other = (p || []).find((x) => x.route && x.route !== a.route);
    if (other && !(await ask(a.name + ": " + launcherProg(a) + " already runs via " + other.route + " (PID " + other.pid +
      "). A second start usually joins that running copy and then keeps ITS route, not " + a.route + ". Start anyway?", { ok: "Start anyway" }))) return;
    await api("POST", "/api/run", { route: a.route, cmd });
    toast(a.name + " started via " + a.route);
  } catch (e) { toast(e.message); }
  setTimeout(updateLauncherState, 1500);
}

// "running via X" next to every launcher, and a warning when the program
// runs with another route than the launcher's (e.g. started from the normal
// menu entry or as the default browser, without the wrapper).
async function updateLauncherState() {
  const cells = document.querySelectorAll(".lstate");
  for (const c of cells) {
    const a = apps.find((x) => x.id === c.dataset.id);
    if (!a) continue;
    let ps = [];
    try { ps = (await api("GET", "/api/procs?name=" + encodeURIComponent(launcherProg(a)))) || []; } catch { continue; }
    const wrong = ps.filter((x) => x.route && x.route !== a.route);
    c.className = "lstate " + (wrong.length ? "bad" : ps.length ? "ok" : "muted");
    c.textContent = !ps.length ? "not running" : wrong.length
      ? "running via " + wrong[0].route + " – not " + a.route + "!"
      : "running via " + a.route;
  }
}

// By folder, not -P <name>: profiles of Firefox's newer profile manager are
// not in profiles.ini, and names differ between machines anyway.
function profileArgs(p) { return '--new-instance --profile "' + p.path.replace(/(["\\`$])/g, "\\$1") + '"'; }
function legacyProfileArgs(n) { return "--new-instance -P " + (/\s/.test(n) ? '"' + n + '"' : n); }

async function createLauncher(app, name, args, route) {
  try {
    await api("POST", "/api/launchers", { app, name, args, route });
    toast("Menu entry \u201c" + name + "\u201d created (" + route + ")");
    await loadApps();
  } catch (e) { toast(e.message); }
}

$("#lcreate").addEventListener("click", () => {
  const name = $("#lname").value.trim();
  if (!name) { toast("Give the launcher a menu name"); return; }
  createLauncher($("#lapp").value, name, $("#largs").value.trim(), $("#lroute").value).then(() => { $("#lname").value = ""; $("#largs").value = ""; });
});

async function loadApps() {
  try { apps = await api("GET", "/api/apps"); } catch { apps = []; }
  renderApps();
  renderLaunchers();
}

async function refresh() {
  try { status = await api("GET", "/api/status"); } catch { status = null; }
  render();
  if (document.querySelector(".lstate")) updateLauncherState();
  checkCaptive(status);
  checkPending(status);
  if (typeof model !== "undefined" && model) updateNetNow(); // Configure page
}

$("#pass").addEventListener("click", async () => {
  const on = !(status && status.pass_left);
  if (on && !(await ask("Let everything through for 5 minutes – your real IP, no tunnels, no blocks, no DNS filter?", { ok: "Pass 5 min", danger: true }))) return;
  try { await api("POST", "/api/pass", { minutes: on ? 5 : 0 }); toast(on ? "Pass for 5 minutes" : "Pass ended"); } catch (e) { toast(e.message); }
  refresh();
});

$("#panic").addEventListener("click", async () => {
  const on = !(status && status.panic);
  if (on && !(await ask("Drop ALL traffic now (except loopback)?", { ok: "PANIC", danger: true }))) return toast("Panic mode not switched on");
  try { await api("POST", "/api/panic", { on }); toast(on ? "Panic mode on" : "Panic mode off"); } catch (e) { toast(e.message); }
  refresh();
});

$("#restart").addEventListener("click", async () => {
  if (!(await ask("Restart the service? Tunnels reconnect; apps in a tunnel are blocked for a few seconds.", { ok: "Restart" }))) return;
  try { await api("POST", "/api/restart"); toast("Service restarts…"); } catch (e) { toast("Restart failed: " + e.message); }
  setTimeout(refresh, 3000);
});

$("#reload").addEventListener("click", async () => {
  try { await api("POST", "/api/reload"); toast("Configuration reloaded"); } catch (e) { toast("Reload failed: " + e.message); }
  refresh();
});

async function runApp() {
  const cmd = $("#cmd").value.trim();
  if (!cmd) return;
  const route = $("#runroute").value;
  try { await api("POST", "/api/run", { route, cmd }); toast("Started via " + route); $("#cmd").value = ""; } catch (e) { toast(e.message); }
  setTimeout(refresh, 800);
}
$("#run").addEventListener("click", runApp);
$("#cmd").addEventListener("keydown", (e) => { if (e.key === "Enter") runApp(); });

$("#leak").addEventListener("click", async () => {
  const b = $("#leak");
  b.disabled = true;
  b.textContent = "Testing…";
  $("#leakres").replaceChildren(el("span", { class: "muted" }, "Probing every route, this takes a few seconds…"));
  try {
    const res = await api("POST", "/api/leaktest");
    // one compact row per route: route + verdict, then IP and resolver
    // (long IPv6 resolvers wrap inside their cell instead of widening it)
    $("#leakres").replaceChildren(el("div", { class: "leaklist" }, ...res.map((r) => el("div", { class: "leakrow " + r.verdict },
      el("div", { class: "leakhead" }, routeTag(r.route), el("span", { class: "pill verdict " + r.verdict }, r.verdict.toUpperCase())),
      r.verdict === "blocked" && !r.result.ip ? el("div", { class: "muted" }, r.note || "nothing gets out") : el("div", { class: "leakkv" },
        el("span", {}, "public IP"), el("span", { class: "mono" }, r.result.ip || "–"),
        el("span", {}, "DNS seen as"), el("span", { class: "mono" }, r.result.resolver || "–")),
      r.note && !(r.verdict === "blocked" && !r.result.ip) ? el("div", { class: "muted leaknote" }, r.note) : ""))));
  } catch (e) { $("#leakres").textContent = "Leak test failed: " + e.message; }
  b.disabled = false;
  b.textContent = "Run again";
});

$("#appfilter").addEventListener("input", renderApps);
$("#allapps").addEventListener("change", renderApps);

(async () => {
  await refresh();
  try { ffProfiles = await api("GET", "/api/firefox-profiles"); } catch { ffProfiles = []; }
  await loadApps();
  setInterval(refresh, 2000);
})();

// --- updates ---------------------------------------------------------------
let upd = null;
async function loadUpdate() {
  try { upd = await api("GET", "/api/update"); } catch { return; }
  // the service was updated but this app still runs the old version
  const stale = status && status.version && upd.app && status.version !== upd.app && upd.app !== "dev";
  $("#updbar").hidden = !upd.available && !stale;
  $("#upd-cmd").hidden = $("#upd-copy").hidden = !upd.available;
  if (stale && !upd.available) {
    $("#updbar").firstElementChild.textContent = "Updated to " + status.version;
    $("#upd-ver").textContent = "– this window still runs " + upd.app + ".";
    $("#updbar").children[2].textContent = "Restart the app: tray → “Restart service and app”.";
  } else if (upd.available) {
    $("#updbar").firstElementChild.textContent = "Update available";
    $("#updbar").children[2].textContent = "Run this in a terminal:";
    $("#upd-cmd").textContent = upd.command;
    $("#upd-ver").textContent = "(installed " + (status && status.version || upd.current) + ")";
  }
  const cb = $("#c-updrel");
  if (cb) {
    cb.checked = upd.releases;
    $("#c-updpre").checked = upd.prereleases;
    $("#c-updinfo").textContent = upd.disabled ? "off – no requests to GitHub" :
      "installed " + upd.current + (upd.checked && !upd.checked.startsWith("0001") ? " · last check " + ago(upd.checked) : "") +
      (upd.error ? " · last check failed: " + upd.error : upd.available ? " · update available" : upd.checked && !upd.checked.startsWith("0001") ? " · up to date" : "");
  }
}
$("#upd-copy").addEventListener("click", async () => {
  const cmd = $("#upd-cmd").textContent;
  try {
    await navigator.clipboard.writeText(cmd);
    toast("Copied – paste it into a terminal (Ctrl+Shift+V)");
  } catch {
    // no clipboard API: select the text so Ctrl+C works
    const r = document.createRange();
    r.selectNodeContents($("#upd-cmd"));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
    toast("Selected – press Ctrl+C, then paste it into a terminal");
  }
});
for (const [id, key] of [["#c-updrel", "releases"], ["#c-updpre", "prereleases"]]) {
  $(id).addEventListener("change", async (e) => {
    try { await api("POST", "/api/update", { [key]: e.target.checked }); } catch (err) { toast(err.message); }
    loadUpdate();
  });
}
loadUpdate();
setInterval(loadUpdate, 60 * 1000);

// --- Wi-Fi login page (captive portal) ---------------------------------------
// Asked once per network: the tunnels can't connect before you log in.
let captiveAsked = "";
async function checkCaptive(st) {
  if (!st || st.captive !== "portal") { if (st && st.captive === "online") captiveAsked = ""; return; }
  const key = JSON.stringify(st.net_info || {});
  if (captiveAsked === key || !$("#modal").hidden) return;
  captiveAsked = key;
  const ssid = st.net_info && st.net_info.ssid ? "“" + st.net_info.ssid + "”" : "This network";
  const go = await ask(ssid + " wants you to log in on a web page first – until then no VPN can connect (apps in a tunnel stay blocked, nothing leaks).\n\nOpen the login page in a throwaway browser that goes past the tunnels? Close it when you are online; the tunnels connect by themselves.", { ok: "Open login page" });
  if (!go) return toast("OK – later: tray → “Wi-Fi login page…” or `shunt captive`");
  try { await api("POST", "/api/captive"); toast("Login browser starting…"); } catch (e) { toast(e.message); }
}

// --- app firewall: programs waiting for a route ------------------------------
let fwCurrent = null;
const fwLater = new Set();
async function checkPending(st) {
  if (!st || !st.pending) { if (fwCurrent) closeFw(); return; }
  let list = [];
  try { list = await api("GET", "/api/pending"); } catch { return; }
  if (fwCurrent && !list.some((p) => p.id === fwCurrent.id)) closeFw(); // decided elsewhere / timed out
  if (fwCurrent || !$("#modal").hidden) return;
  const p = list.find((x) => !fwLater.has(x.id));
  if (p) showFw(p, st);
}
function showFw(p, st) {
  fwCurrent = p;
  $("#fw-title").textContent = p.name;
  $("#fw-key").textContent = p.key + (p.procs > 1 ? " · " + p.procs + " processes" : "");
  const routes = st.routes.filter((r) => r !== "block");
  $("#fw-routes").replaceChildren(
    ...routes.map((r) => el("button", { class: r === st.default_route ? "primary" : "", onclick: () => decideFw(r) }, r === "direct" ? "direct (real IP)" : r.replace(/^tunnel:/, "tunnel ") )),
    el("button", { class: "danger", onclick: () => decideFw("block") }, "block"));
  $("#fw-remember").checked = true;
  $("#fwmodal").hidden = false;
  tickFw();
}
function tickFw() {
  if (!fwCurrent) return;
  const d = fwCurrent.deadline && !fwCurrent.deadline.startsWith("0001") ? new Date(fwCurrent.deadline) : null;
  $("#fw-count").textContent = d
    ? "No answer: default route (" + (status ? status.default_route : "") + ") in " + Math.max(0, Math.round((d - Date.now()) / 1000)) + " s"
    : "Blocked until you decide.";
  setTimeout(tickFw, 1000);
}
function closeFw() { fwCurrent = null; $("#fwmodal").hidden = true; }
async function decideFw(route) {
  const p = fwCurrent;
  if (!p) return;
  closeFw();
  try {
    await api("POST", "/api/pending/" + encodeURIComponent(p.id), { route, remember: $("#fw-remember").checked });
    toast(p.name + " → " + route + ($("#fw-remember").checked ? " (remembered)" : ""));
  } catch (e) { toast(e.message); }
}
$("#fw-later").addEventListener("click", () => { if (fwCurrent) fwLater.add(fwCurrent.id); closeFw(); });
