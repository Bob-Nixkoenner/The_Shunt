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

// The Windows window shows no external pages: links to other sites are
// opened by the app in the default browser.
document.addEventListener("click", (e) => {
  const a = e.target.closest && e.target.closest("a[href]");
  if (!a || a.protocol !== "https:" || a.host === location.host) return;
  if (!status || status.platform !== "windows") return;
  e.preventDefault();
  api("POST", "/api/open-url", { url: a.href }).catch((err) => toast(err.message));
});

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
        ...(t.error ? [el("span", {}, "error"), el("span", { style: "color:var(--bad)" }, t.error)] : [])),
      ...(typeof sparkline === "function" && hist && hist.tunnels && hist.tunnels[t.name] ? [sparkline(hist.tunnels[t.name])] : []));
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

  // The overview shows your first rules only (all of them are under Configure);
  // the built-in ones (captive, via:...) are not rules you made.
  const SHOWN_RULES = 4;
  const mine = st.rules.map((r, i) => [i + 1, ...r.split(" -> ")]).filter(([, name]) => name !== "captive" && !name.startsWith("via:"));
  $("#rules").replaceChildren(...mine.slice(0, SHOWN_RULES).map(([n, name, route]) =>
    el("tr", {}, el("td", { class: "muted" }, n + "."), el("td", {}, name), el("td", {}, routeTag(route)))),
    el("tr", {}, el("td", { class: "muted" }, "→"), el("td", { class: "muted" }, "everything else"), el("td", {}, routeTag(st.default_route))));
  $("#rules-more").replaceChildren(...(mine.length > SHOWN_RULES ? [mine.length - SHOWN_RULES + " more rules – ", el("a", { href: "#", onclick: (e) => { e.preventDefault(); setTab("config"); } }, "show all under Configure")] : []));

  $("#dns").replaceChildren(...Object.entries(st.dns || {}).sort().map(([r, ups]) =>
    el("tr", {}, el("td", {}, routeTag(r)), el("td", { class: "mono" }, ups.join(", ")))));

  if (routesChanged) { renderApps(); renderLaunchers(); }
}

function renderApps() {
  if (!status) return;
  const f = $("#appfilter").value.toLowerCase();
  // Default: apps that use the network or are already routed; the rest
  // (hundreds of tools on Kali) only on request or when searching.
  const all = $("#allapps").checked || f !== "";
  const routes = ["", ...status.routes];
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
    // a route that no longer exists (tunnel removed) stays visible instead of an empty box
    if (a.route && !routes.includes(a.route)) s.append(el("option", { value: a.route }, a.route + " (gone)"));
    s.value = a.route || "";
    return el("tr", {}, el("td", {}, a.name, " ", el("span", { class: "muted mono" }, a.id)), el("td", {}, s), el("td", { class: "linux-only" }, appFilterSelect(a)));
  }));
}

// --- DNS filter level per app ---------------------------------------------
// A level for one app is a [[rule]] with the app's process name, a
// dns_filter and no route (the app keeps the route it has otherwise).
const LEVEL_OPTS = [["", "as everything else"], ["off", "off"], ["low", "low"], ["normal", "normal"], ["paranoid", "paranoid"]];
let appRules = []; // [[rule]]s of the config in effect

async function loadAppRules() {
  try { appRules = ((await api("GET", "/api/config")).config.rule) || []; } catch { appRules = []; }
}
const isLevelRule = (r, proc) => r.dns_filter && !r.route && !(r.cidr || []).length && !(r.port || []).length && !(r.domain || []).length &&
  !(r.group || []).length && (r.app || []).length === 1 && r.app[0] === proc;
const appLevel = (a) => (appRules.find((r) => isLevelRule(r, processName(a.id))) || {}).dns_filter || "";

function appFilterSelect(a) {
  const s = el("select", { title: "DNS filter for " + a.name + ", whatever route it takes", onchange: async (e) => {
    try {
      // fresh copy of the config: never overwrite what changed meanwhile
      const v = await api("GET", "/api/config");
      const c = v.config, proc = processName(a.id), level = e.target.value;
      c.rule = c.rule || [];
      const i = c.rule.findIndex((r) => isLevelRule(r, proc));
      if (!level && i >= 0) c.rule.splice(i, 1);
      else if (level && i >= 0) c.rule[i].dns_filter = level;
      else if (level) c.rule.push({ name: "DNS filter: " + proc, app: [proc], dns_filter: level });
      await api("PUT", "/api/config", { config: c, version: v.version });
      appRules = c.rule;
      toast(a.name + (level ? ": DNS filter " + level : ": DNS filter as everything else"));
    } catch (err) { toast(err.message); s.value = appLevel(a); }
  } }, ...LEVEL_OPTS.map(([v, l]) => el("option", { value: v }, l)));
  s.value = appLevel(a);
  return s;
}

// processName guesses the process name of a menu app: "brave-browser" ->
// "brave", "org.mozilla.firefox" -> "firefox", "firefox-esr" -> "firefox".
function processName(id) {
  if (/\.exe$/i.test(id)) return id.slice(0, -4).toLowerCase(); // Windows: "firefox.exe"
  const last = id.split(".").pop().toLowerCase();
  return last.split(/[-_]/)[0] || last;
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

// Chromium family (the server names the browser): one process per data folder, so a launcher with
// its own route needs a folder of its own
const isChromium = (id) => !!(apps.find((a) => a.id === id) || {}).chromium;
const chromiumApp = () => (apps.find((a) => !a.clone && a.chromium) || {}).id;
const slug = (n) => n.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const firefoxApp = () => (apps.find((a) => /^(firefox-esr|firefox|org\.mozilla\.firefox|firefox_firefox|firefox\.exe)$/.test(a.id)) || {}).id;
const onWindows = () => !!status && status.platform === "windows";
const menuWord = () => onWindows() ? "Start menu entry" : "Menu entry";

// open/closed state of the browser groups survives a re-render
const openBrowsers = new Set(JSON.parse((() => { try { return localStorage.getItem("shunt-open-browsers") || "[]"; } catch { return "[]"; } })()));
function rememberOpen() { try { localStorage.setItem("shunt-open-browsers", JSON.stringify([...openBrowsers])); } catch {} }

const isSnap = (app) => /\/snap\/bin\//.test(app.exec || "");

function launcherRow(a) {
  return el("tr", {},
    el("td", {}, a.name, " ", el("span", { class: "muted mono" }, (a.args || ""))),
    el("td", {}, routeSelect(a.route, async (e) => {
      try { await api("POST", "/api/apps", { id: a.id, route: e.target.value }); a.route = e.target.value; toast(a.name + " now via " + a.route); }
      catch (err) { toast(err.message); e.target.value = a.route; }
    })),
    el("td", {}, el("span", { class: "muted lstate", "data-id": a.id }, "…")),
    el("td", {}, el("button", { onclick: () => startLauncher(a) }, "Start")),
    el("td", {}, el("button", { onclick: async () => {
      try { await api("POST", "/api/apps", { id: a.id, route: "" }); toast(a.name + " removed"); await loadApps(); }
      catch (err) { toast(err.message); }
    } }, "Remove")));
}

function renderLaunchers() {
  if (!status) return;
  const launchers = apps.filter((a) => a.clone);
  const ff = firefoxApp();
  // one foldable group per browser: its profiles (without a launcher yet) and its launchers
  const groups = [];
  if (ff) groups.push({ key: "firefox", app: apps.find((a) => a.id === ff), label: "Firefox" });
  for (const a of apps.filter((x) => !x.clone && x.chromium)) groups.push({ key: a.chromium, app: a, label: a.name });
  const keyOf = (l) => (l.clone && firefoxApp() === l.clone) ? "firefox" : ((apps.find((a) => a.id === l.clone) || {}).chromium || "other");
  for (const l of launchers) if (!groups.some((g) => g.key === keyOf(l))) groups.push({ key: keyOf(l), app: null, label: keyOf(l) === "other" ? "Other apps" : keyOf(l) });
  $("#sec-launchers").hidden = !groups.length;

  const sel0 = () => routeSelect(status.routes.find((r) => r.startsWith("tunnel:")) || "direct");
  $("#browsers").replaceChildren(...groups.map((g) => {
    const mine = launchers.filter((l) => keyOf(l) === g.key);
    const chips = [];
    if (g.key === "firefox") {
      const have = new Set(launchers.map((a) => a.args));
      // launchers made before profiles were started by folder used -P <name>
      for (const p of ffProfiles.filter((p) => !have.has(profileArgs(p)) && !have.has(legacyProfileArgs(p.name)))) {
        const sel = sel0();
        chips.push(el("span", { class: "chip", style: "padding:4px 8px;display:inline-flex;gap:6px;align-items:center", title: p.path }, p.name, sel,
          el("button", { onclick: () => createLauncher(ff, "Firefox " + p.name, profileArgs(p), sel.value) }, "+ launcher")));
      }
    } else if (g.app && onWindows()) {
      // Windows: an existing profile cannot be shared with a launcher (desktop.ErrSharedProfile)
    } else if (g.app) {
      // an existing profile gets a data folder of its own (a link to the profile) and a launcher
      for (const p of crProfiles.filter((p) => p.browser === g.key)) {
        const lname = g.app.name + " " + p.name;
        const done = launchers.some((l) => l.name === lname);
        const sel = sel0();
        chips.push(el("span", { class: "chip", style: "padding:4px 8px;display:inline-flex;gap:6px;align-items:center", title: p.root + "/" + p.dir }, p.name,
          ...(done ? [el("span", { class: "muted" }, "has a launcher")] : [sel,
            el("button", { onclick: () => createProfileLauncher(g.app.id, lname, p, sel.value) }, "+ launcher")])));
      }
    }
    const note = g.app && isSnap(g.app) ? el("div", { class: "hint", style: "margin:6px 0" },
      "Snap version: it starts in two steps, so the first window can take a moment longer, and routing it is best effort, not guaranteed. The .deb or Flatpak version of the browser is more reliable.")
      : g.app && g.key !== "firefox" && onWindows() ? el("div", { class: "hint", style: "margin:6px 0" },
      "Existing profiles of " + g.label + " cannot get a launcher of their own on Windows: the browser binds logins and saved passwords to its data folder and would delete them. Use a launcher with a new profile folder (below, arguments empty) and log in there once, or give the whole browser a route under Programs.") : "";
    const det = el("details", { class: "inner browser", ontoggle: (e) => { if (e.target.open) openBrowsers.add(g.key); else openBrowsers.delete(g.key); rememberOpen(); } },
      el("summary", {}, el("b", {}, g.label), " ", el("span", { class: "muted" }, mine.length + (mine.length === 1 ? " launcher" : " launchers") + (chips.length ? " · " + chips.length + " profile" + (chips.length === 1 ? "" : "s") + " found" : ""))),
      note,
      chips.length ? el("div", { class: "row", style: "margin:8px 0;flex-wrap:wrap" }, el("span", { class: "muted" }, "Profiles found:"), ...chips) : "",
      mine.length ? el("table", {}, el("tbody", {}, ...mine.map(launcherRow))) : "");
    if (openBrowsers.has(g.key)) det.open = true;
    return det;
  }));

  updateLauncherState();

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
function launcherProg(a) {
  const c = launcherCmd(a);
  const first = c.startsWith('"') ? c.slice(1, c.indexOf('"', 1) > 0 ? c.indexOf('"', 1) : undefined) : (c.split(/\s+/)[0] || "");
  return first.split(/[\\/]/).pop();
}

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
function profileArgs(p) {
  if (onWindows()) return '--new-instance --profile "' + p.path + '"'; // Windows command line: backslashes stay
  return '--new-instance --profile "' + p.path.replace(/(["\\`$])/g, "\\$1") + '"';
}
function legacyProfileArgs(n) { return "--new-instance -P " + (/\s/.test(n) ? '"' + n + '"' : n); }

let crProfiles = [];
async function createProfileLauncher(app, name, profile, route) {
  try {
    await api("POST", "/api/profile-launchers", { app, name, route, profile });
    toast(menuWord() + " \u201c" + name + "\u201d created (" + route + "). Close the browser's own window of this profile first: one profile, one process.");
    await loadApps();
  } catch (e) { toast(e.message); }
}

async function createLauncher(app, name, args, route) {
  try {
    await api("POST", "/api/launchers", { app, name, args, route });
    toast(menuWord() + " \u201c" + name + "\u201d created (" + route + ")");
    await loadApps();
  } catch (e) { toast(e.message); }
}

$("#lcreate").addEventListener("click", () => {
  const name = $("#lname").value.trim();
  if (!name) { toast("Give the launcher a menu name"); return; }
  const app = $("#lapp").value;
  let args = $("#largs").value.trim();
  if (!args && isChromium(app)) args = onWindows() // {home}: filled in by the app
    ? '--user-data-dir="{home}\\ShuntProfiles\\' + (slug(name) || "profile") + '"'
    : '--user-data-dir="{home}/.local/share/shunt/profiles/' + (slug(name) || "profile") + '"';
  createLauncher(app, name, args, $("#lroute").value).then(() => { $("#lname").value = ""; $("#largs").value = ""; });
});

async function loadApps() {
  try { apps = await api("GET", "/api/apps"); } catch { apps = []; }
  await loadAppRules();
  renderApps();
  renderLaunchers();
}

async function refresh() {
  try { status = await api("GET", "/api/status"); } catch { status = null; }
  if (status) { status.tunnels = status.tunnels || []; status.routes = status.routes || []; } // Go sends null for "none yet"
  render();
  if (document.querySelector(".lstate")) updateLauncherState();
  checkCaptive(status);
  watchTunnels(status);
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

// runLeak probes every route. auto: started by a tunnel change, not by a click.
let leakBusy = false;
async function runLeak(auto) {
  if (leakBusy) return;
  leakBusy = true;
  const b = $("#leak");
  b.disabled = true;
  b.textContent = "Testing…";
  $("#leakres").replaceChildren(el("span", { class: "muted" }, auto ? "A tunnel changed – probing every route…" : "Probing every route, this takes a few seconds…"));
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
    showLeakPill(res);
  } catch (e) { $("#leakres").textContent = "Leak test failed: " + e.message; }
  b.disabled = false;
  b.textContent = "Run again";
  leakBusy = false;
}
$("#leak").addEventListener("click", () => runLeak(false));

// the verdict of the last test, always visible in the header
function showLeakPill(res) {
  const p = $("#leakpill");
  const leaks = res.filter((r) => r.verdict === "leak").length;
  const odd = res.filter((r) => r.verdict === "warn" || r.verdict === "error").length;
  p.hidden = false;
  p.className = "pill " + (leaks ? "bad" : odd ? "warn" : "ok");
  p.textContent = leaks ? "leak test: " + leaks + " LEAK" : odd ? "leak test: check" : "leak test: ok";
  p.title = "Last leak test " + new Date().toLocaleTimeString() + " – click for details";
}
$("#leakpill").addEventListener("click", () => { setTab("overview"); $("#leakres").scrollIntoView({ block: "center" }); });

// Tunnel comes up or goes down: test again a few seconds later (unless switched off).
let upKey = null, autoLeakTimer = null;
function watchTunnels(st) {
  if (!st) return;
  const key = st.tunnels.filter((t) => t.up && (t.peers || []).some((p) => p.last_handshake && !p.last_handshake.startsWith("0001")) ||
    (t.up && (t.driver === "openvpn" || t.driver === "tailscale"))).map((t) => t.name).sort().join(",");
  if (upKey !== null && key !== upKey) {
    clearTimeout(autoLeakTimer);
    autoLeakTimer = setTimeout(() => { if ($("#leak-auto").checked && !st.panic && !st.pass_left) runLeak(true); }, 5000);
  }
  upKey = key;
}
try { $("#leak-auto").checked = localStorage.getItem("shunt-leak-auto") !== "0"; } catch (e) { /* private window */ }
$("#leak-auto").addEventListener("change", (e) => { try { localStorage.setItem("shunt-leak-auto", e.target.checked ? "1" : "0"); } catch (err) { /* private window */ } });

$("#appfilter").addEventListener("input", renderApps);
$("#allapps").addEventListener("change", renderApps);

(async () => {
  await refresh();
  try { ffProfiles = await api("GET", "/api/firefox-profiles"); } catch { ffProfiles = []; }
  try { crProfiles = await api("GET", "/api/chromium-profiles"); } catch { crProfiles = []; }
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
  $("#upd-cmd").hidden = $("#upd-copy").hidden = !upd.available || upd.can_apply;
  $("#upd-now").hidden = !upd.can_apply;
  if (!upd.available || Date.now() - updInstalling > 30 * 60 * 1000) updInstalling = 0;
  $("#upd-now").disabled = !!updInstalling;
  $("#upd-now").textContent = updInstalling ? "Installing…" : "Install update";
  if (updInstalling) $("#updbar").hidden = false;
  if (stale && !upd.available) {
    $("#updbar").firstElementChild.textContent = "Updated to " + status.version;
    $("#upd-ver").textContent = "– this window still runs " + upd.app + ".";
    $("#updbar").children[2].textContent = "Restart the app: tray → “Restart service and app”.";
  } else if (upd.available) {
    $("#updbar").firstElementChild.textContent = "Update available";
    $("#updbar").children[2].textContent = upd.can_apply ? "Checked against the release signature, then installed:" : "Run this in a terminal:";
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
let updInstalling = 0; // time the install was started; the bar goes away by itself when it worked
let updTimer = 0;
// Shows how far the installer got: step n of m, what runs now, and why it
// failed. Polls while it runs, so it also resumes after the app restarted.
async function pollUpdate() {
  clearTimeout(updTimer);
  const step = $("#upd-step"), prog = $("#upd-prog");
  let p;
  try { p = await api("GET", "/api/update/progress"); } catch {
    // the app itself restarts at the end of an update: keep asking
    if (updInstalling) { step.hidden = false; step.className = "muted"; step.textContent = "waiting for the app…"; updTimer = setTimeout(pollUpdate, 2000); }
    return;
  }
  if (p.state === "running") {
    if (!updInstalling) updInstalling = Date.now();
    prog.hidden = step.hidden = false;
    prog.value = p.step;
    step.className = "muted";
    step.textContent = (p.step ? p.step + "/" + p.total + " " : "") + (p.text || "starting…") +
      (p.quiet ? " – no news for 5 min, still running? Log: " + p.log : "");
    $("#upd-now").textContent = "Installing… " + (p.step || 0) + "/" + p.total;
    $("#upd-now").disabled = true;
    $("#updbar").hidden = false;
    updTimer = setTimeout(pollUpdate, 2000);
    return;
  }
  prog.hidden = true;
  if (p.state === "failed" && updInstalling) {
    updInstalling = 0;
    step.hidden = false;
    step.className = "bad";
    step.textContent = "Update failed: " + p.error + " – log: " + p.log;
  } else if (p.state === "done" && updInstalling) {
    updInstalling = 0;
    step.hidden = false;
    step.className = "muted";
    step.textContent = "Installed. Restart the app: tray → “Restart service and app”.";
  } else if (!updInstalling) {
    step.hidden = true;
  }
  loadUpdate();
}
$("#upd-now").addEventListener("click", async () => {
  updInstalling = Date.now();
  $("#upd-step").hidden = true;
  loadUpdate();
  try {
    await api("POST", "/api/update/apply");
    toast("Update started – confirm the password / admin prompt when it appears. This takes a minute.");
    pollUpdate();
  } catch (err) {
    updInstalling = 0;
    toast(err.message);
    loadUpdate();
  }
});
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
pollUpdate();
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
