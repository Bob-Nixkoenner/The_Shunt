"use strict";
// The Shunt UI. No frameworks, no external requests.

const $ = (s) => document.querySelector(s);
let status = null;
let apps = [];

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
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
  else if (down.length) { state.className = "pill warn"; state.textContent = down.length + " tunnel(s) without handshake – their apps are blocked"; }
  else { state.className = "pill ok"; state.textContent = "protected"; }
  $("#defroute").replaceChildren("default route ", routeTag(st.default_route));

  const panic = $("#panic");
  panic.textContent = st.panic ? "Release panic" : "PANIC";
  panic.classList.toggle("on", st.panic);

  $("#banners").replaceChildren(...(st.warnings || []).map((w) => el("div", { class: "banner" }, "⚠ ", w)),
    ...(st.panic ? [el("div", { class: "banner bad" }, "Panic mode is on: all traffic except loopback is dropped.")] : []));

  $("#tunnels").replaceChildren(...(st.tunnels.length ? st.tunnels.map((t) => {
    const p = (t.peers || [])[0] || {};
    const hs = p.last_handshake && !p.last_handshake.startsWith("0001");
    return el("div", { class: "card " + (t.up && hs ? "up" : "down") },
      el("div", { class: "name" }, t.name, el("span", { class: "pill " + (t.up && hs ? "ok" : "bad") }, t.up ? (hs ? "up" : "no handshake") : "down")),
      el("div", { class: "kv" },
        el("span", {}, "interface"), el("span", { class: "mono" }, t.iface + (t.driver ? " · " + t.driver : "")),
        el("span", {}, "endpoint"), el("span", { class: "mono" }, p.endpoint || "–"),
        el("span", {}, "handshake"), el("span", {}, ago(p.last_handshake)),
        el("span", {}, "traffic"), el("span", {}, "↓ " + bytes(p.rx_bytes || 0) + "  ↑ " + bytes(p.tx_bytes || 0)),
        ...(t.error ? [el("span", {}, "error"), el("span", { style: "color:var(--bad)" }, t.error)] : [])));
  }) : [el("div", { class: "muted" }, "No tunnels configured – add one in /etc/shunt/shunt.toml.")]));

  const sel = $("#runroute");
  const cur = sel.value;
  sel.replaceChildren(...st.routes.map((r) => el("option", { value: r }, r)));
  sel.value = cur && st.routes.includes(cur) ? cur : (st.routes.find((r) => r.startsWith("tunnel:")) || "direct");

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

  renderApps();
}

function renderApps() {
  if (!status) return;
  const f = $("#appfilter").value.toLowerCase();
  const routes = ["", ...status.routes];
  $("#apps").replaceChildren(...apps.filter((a) => !f || (a.name + a.id).toLowerCase().includes(f)).map((a) => {
    const s = el("select", {
      onchange: async (e) => {
        try {
          await api("POST", "/api/apps", { id: a.id, route: e.target.value });
          a.route = e.target.value;
          toast(a.name + (a.route ? " now starts via " + a.route : " restored to its original entry"));
        } catch (err) { toast(err.message); e.target.value = a.route || ""; }
      },
    }, ...routes.map((r) => el("option", { value: r }, r || "system default")));
    s.value = a.route || "";
    return el("tr", {}, el("td", {}, a.name, " ", el("span", { class: "muted mono" }, a.id)), el("td", {}, s));
  }));
}

async function refresh() {
  try { status = await api("GET", "/api/status"); } catch { status = null; }
  render();
}

$("#panic").addEventListener("click", async () => {
  const on = !(status && status.panic);
  if (on && !confirm("Drop ALL traffic now (except loopback)?")) return;
  try { await api("POST", "/api/panic", { on }); toast(on ? "Panic mode on" : "Panic mode off"); } catch (e) { toast(e.message); }
  refresh();
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

(async () => {
  await refresh();
  try { apps = await api("GET", "/api/apps"); } catch { apps = []; }
  renderApps();
  setInterval(refresh, 2000);
})();
