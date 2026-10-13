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
  const cls = r.startsWith("tunnel:") ? "tunnel" : r;
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
  const state = $("#state");
  if (!st) { state.className = "pill bad"; state.textContent = "shuntd not reachable"; return; }

  const down = st.tunnels.filter((t) => !t.up || !t.peers || t.peers.every((p) => !p.last_handshake || p.last_handshake.startsWith("0001")));
  if (st.panic) { state.className = "pill bad"; state.textContent = "PANIC – everything blocked"; }
  else if (st.captive === "portal") { state.className = "pill warn"; state.textContent = "Wi-Fi login needed – tunnels wait for it"; }
  else if (down.length) { state.className = "pill warn"; state.textContent = down.length + " tunnel(s) without connection – their apps are blocked"; }
  else if (st.dns_failing && Object.keys(st.dns_failing).length) { state.className = "pill warn"; state.textContent = "DNS not working: " + Object.keys(st.dns_failing).sort().join(", "); }
  else { state.className = "pill ok"; state.textContent = "protected"; }
  $("#defroute").replaceChildren("default route ", routeTag(st.default_route), ...(st.network ? [el("span", { class: "muted" }, " (network “" + st.network + "”)")] : []));

  const panic = $("#panic");
  panic.textContent = st.panic ? "Release panic" : "PANIC";
  panic.classList.toggle("on", st.panic);

  $("#banners").replaceChildren(...(st.warnings || []).map((w) => el("div", { class: "banner" }, "⚠ ", w)),
    ...(st.panic ? [el("div", { class: "banner bad" }, "Panic mode is on: all traffic except loopback is dropped.")] : []));

  $("#tunnels").replaceChildren(...(st.tunnels.length ? st.tunnels.map((t) => {
    const p = (t.peers || [])[0] || {};
    const hs = p.last_handshake && !p.last_handshake.startsWith("0001");
    const ovpn = t.driver === "openvpn";
    return el("div", { class: "card " + (t.up && hs ? "up" : "down") },
      el("div", { class: "name" }, t.name, el("span", { class: "pill " + (t.up && hs ? "ok" : "bad") }, t.up ? (hs ? "up" : ovpn ? "connecting" : "no handshake") : "down")),
      el("div", { class: "kv" },
        el("span", {}, "interface"), el("span", { class: "mono" }, t.iface + (t.driver ? " · " + t.driver : "")),
        el("span", {}, "endpoint"), el("span", { class: "mono" }, p.endpoint || "–"),
        ...(t.via ? [el("span", {}, "multi-hop"), el("span", {}, "through " + t.via)] : []),
        el("span", {}, ovpn ? "connected" : "handshake"), el("span", {}, ago(p.last_handshake)),
        el("span", {}, "traffic"), el("span", {}, "↓ " + bytes(p.rx_bytes || 0) + "  ↑ " + bytes(p.tx_bytes || 0)),
        ...(t.error ? [el("span", {}, "error"), el("span", { style: "color:var(--bad)" }, t.error)] : [])));
  }) : [el("div", { class: "muted" }, "No tunnels configured – import one under Configure.")]));

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
    el("td", {}, el("button", { onclick: async () => {
      try { await api("POST", "/api/apps", { id: a.id, route: "" }); toast(a.name + " removed"); await loadApps(); }
      catch (err) { toast(err.message); }
    } }, "Remove")))));

  const ff = firefoxApp();
  const have = new Set(launchers.map((a) => a.args));
  const todo = ff ? ffProfiles.filter((p) => !have.has(profileArgs(p))) : [];
  $("#ffprofiles").replaceChildren(...(todo.length ? [el("div", { class: "row", style: "margin-bottom:10px" },
    el("span", { class: "muted" }, "Firefox profiles found:"),
    ...todo.map((p) => {
      const sel = routeSelect(status.routes.find((r) => r.startsWith("tunnel:")) || "direct");
      return el("span", { class: "chip", style: "padding:4px 8px;display:inline-flex;gap:6px;align-items:center" }, p, sel,
        el("button", { onclick: () => createLauncher(ff, "Firefox " + p, profileArgs(p), sel.value) }, "+ launcher"));
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

function profileArgs(p) { return "--new-instance -P " + (/\s/.test(p) ? '"' + p + '"' : p); }

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
  checkCaptive(status);
  if (typeof model !== "undefined" && model) updateNetNow(); // Configure page
}

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
    $("#leakres").replaceChildren(el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Route"), el("th", {}, "Public IP"), el("th", {}, "DNS resolver"), el("th", {}, "Result"))),
      el("tbody", {}, ...res.map((r) => el("tr", {},
        el("td", {}, routeTag(r.route)),
        el("td", { class: "mono" }, r.result.ip || "–"),
        el("td", { class: "mono" }, r.result.resolver || "–"),
        el("td", {}, el("span", { class: "verdict " + r.verdict }, r.verdict.toUpperCase()), r.note ? el("div", { class: "muted" }, r.note) : ""))))));
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
  $("#updbar").hidden = !upd.available;
  if (upd.available) {
    $("#upd-cmd").textContent = upd.command;
    $("#upd-ver").textContent = "(installed " + upd.current + ")";
  }
  const cb = $("#c-updcheck");
  if (cb) {
    cb.checked = !upd.disabled;
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
$("#c-updcheck").addEventListener("change", async (e) => {
  try { await api("POST", "/api/update", { enabled: e.target.checked }); } catch (err) { toast(err.message); }
  loadUpdate();
});
loadUpdate();
setInterval(loadUpdate, 10 * 60 * 1000);

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
