"use strict";
// Configure page: edits a copy of the daemon's config; nothing is written
// before the daemon has checked it (same checks as `shuntd check`).

let cfgView = null; // last config from the daemon (raw text, parsed, tunnel info)
let model = null; // working copy being edited
let editIdx = -1; // rule being edited (-1 = new)

const splitList = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
const joinList = (a) => (a || []).join(", ");

// "config" and "filter" share the config page (and its save bar): the
// filter sections are marked .pf.
function setTab(t) {
  $("#page-overview").hidden = t !== "overview";
  $("#page-apps").hidden = t !== "apps";
  $("#page-config").hidden = t === "overview" || t === "apps";
  for (const s of document.querySelectorAll("#page-config > section")) s.hidden = s.classList.contains("pf") !== (t === "filter");
  for (const n of ["overview", "apps", "config", "filter"]) $("#tab-" + n).classList.toggle("active", t === n);
  if ((t === "config" || t === "filter") && !model) loadConfig();
  try { history.replaceState(null, "", t === "overview" ? location.pathname : "#" + t); } catch (e) { /* file: or sandbox */ }
  if (t === "apps") loadApps(); // installed programs and the config may have changed since the last visit
}
$("#tab-overview").addEventListener("click", () => setTab("overview"));
$("#tab-apps").addEventListener("click", () => setTab("apps"));
$("#tab-config").addEventListener("click", () => setTab("config"));
$("#tab-filter").addEventListener("click", () => setTab("filter"));

function cmsg(text, cls) {
  const m = $("#c-msg");
  m.className = "msg " + (cls || "muted");
  m.textContent = text;
}

function markDirty() {
  $("#savebar").classList.add("dirty");
  cmsg("Unsaved changes – press “Save & apply” (or “Check” first).", "warn");
}

async function loadConfig() {
  try {
    cfgView = await api("GET", "/api/config");
  } catch (e) {
    cmsg("Cannot load the config: " + e.message, "err");
    return;
  }
  model = structuredClone(cfgView.config);
  model.tunnel = model.tunnel || {};
  model.rule = model.rule || [];
  model.group = model.group || {};
  model.dns = model.dns || {};
  model.dns.upstream = model.dns.upstream || {};
  $("#savebar").classList.remove("dirty");
  cmsg("Changes are checked before anything is written; the previous file is kept as shunt.toml.bak.");
  $("#raw").value = cfgView.raw;
  renderConfig();
  renderFilter();
}

// link routes: out over one kind of connection only (blocked without it)
const LINKS = [["link:wifi", "Wi-Fi"], ["link:ethernet", "cable"], ["link:mobile", "mobile"]];
const modelRoutes = () => ["direct", "block", ...Object.keys(model.tunnel).sort().map((n) => "tunnel:" + n), ...LINKS.map((l) => l[0])];

function fill(sel, options, value) {
  const s = $(sel);
  s.replaceChildren(...options.map((o) => (Array.isArray(o) ? el("option", { value: o[0] }, o[1]) : el("option", { value: o }, o))));
  s.value = value;
}

// DNS filter level select for a tunnel, network or rule object o
const FILTER_OPTS = [["", "as everything else"], ["off", "off"], ["low", "low"], ["normal", "normal"], ["paranoid", "paranoid"]];
function filterSel(o) {
  const f = el("select", { onchange: (e) => { o.dns_filter = e.target.value || undefined; markDirty(); if (typeof renderFilter === "function") renderFilter(); } },
    ...FILTER_OPTS.map(([v, l]) => el("option", { value: v }, l)));
  f.value = o.dns_filter || "";
  return f;
}

function upstreamUsers(name) {
  const users = [];
  if (model.dns.direct === name) users.push("direct DNS");
  for (const [t, v] of Object.entries(model.tunnel)) if (v.dns === name) users.push("tunnel " + t);
  return users;
}

function renderConfig() {
  const ups = Object.keys(model.dns.upstream).sort();
  fill("#c-default", modelRoutes(), model.daemon.default_route || "direct");
  $("#c-killswitch").checked = !!model.daemon.kill_switch;
  defaultHint();
  fillVia();
  renderNetworks();
  renderFirewall();
  fill("#c-direct", [["", "system resolvers (from resolv.conf)"], ...ups.map((u) => [u, u + " – " + model.dns.upstream[u].addr])], model.dns.direct || "");
  $("#c-blockdoh").checked = !model.dns.allow_doh;
  $("#c-blockdot").checked = !model.dns.allow_dot;

  $("#c-upstreams").replaceChildren(...(ups.length ? ups.map((u) => {
    const v = model.dns.upstream[u];
    const users = upstreamUsers(u);
    return el("tr", {},
      el("td", {}, el("b", {}, u)),
      el("td", { class: "mono" }, v.addr, v.tls_name ? el("span", { class: "muted" }, " (" + v.tls_name + ")") : ""),
      el("td", { class: "muted" }, users.join(", ")),
      el("td", {}, el("button", { class: "iconbtn", title: users.length ? "in use" : "remove", disabled: users.length ? "" : null, onclick: () => { delete model.dns.upstream[u]; markDirty(); renderConfig(); } }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "None yet – direct traffic uses the system resolvers, tunnels the DNS= of their WireGuard file."))]));

  const info = Object.fromEntries((cfgView.tunnels || []).map((t) => [t.name, t]));
  const names = Object.keys(model.tunnel).sort();
  $("#c-tunnels").replaceChildren(...(names.length ? names.map((n) => {
    const t = model.tunnel[n];
    const i = info[n] || {};
    const fromFile = i.type === "openvpn" ? "DNS pushed by the server" : "DNS from its file" + (i.dns && i.dns.length ? " (" + i.dns.join(", ") + ")" : " (none!)");
    const dnsSel = el("select", { onchange: (e) => { t.dns = e.target.value || undefined; markDirty(); } },
      el("option", { value: "" }, fromFile),
      ...ups.map((u) => el("option", { value: u }, u)));
    dnsSel.value = t.dns || "";
    // multi-hop: a tunnel may run through any other tunnel (not through
    // itself or one that already runs through it)
    const loops = (m) => { for (let c = m, k = 0; c && k < 20; k++) { if (c === n) return true; c = ((model.tunnel[c] || {}).via || "").replace(/^tunnel:/, ""); } return false; };
    const viaSel = el("select", { title: "multi-hop", onchange: (e) => { t.via = e.target.value || undefined; markDirty(); renderConfig(); } },
      el("option", { value: "" }, "direct to its server"),
      ...names.filter((m) => !loops(m)).map((m) => el("option", { value: "tunnel:" + m }, "via " + m)),
      ...LINKS.map(([v, l]) => el("option", { value: v }, "over " + l + " only")));
    viaSel.value = t.via || "";
    return el("tr", {},
      el("td", {}, routeTag("tunnel:" + n), el("div", { class: "muted" }, i.type === "openvpn" ? "OpenVPN" : "WireGuard")),
      el("td", { class: "mono" }, (i.endpoint || "–") + "  ", el("span", { class: "muted" }, joinList(i.addresses))),
      el("td", {}, viaSel, el("label", { class: "row muted", style: "font-size:12px;margin-top:6px", title: "Apps in this tunnel still reach printers, NAS and the router of the network you are in (private addresses only)" },
        el("input", { type: "checkbox", checked: t.allow_lan ? "" : null, onchange: (e) => { t.allow_lan = e.target.checked || undefined; markDirty(); } }), "local network direct"),
      el("label", { class: "row muted", style: "font-size:12px;margin-top:6px", title: "Keep the tunnel but don't connect it. Apps that would use it are blocked." },
        el("input", { type: "checkbox", checked: t.disabled ? null : "", onchange: (e) => { t.disabled = !e.target.checked || undefined; markDirty(); } }), "switched on")),
      el("td", {}, dnsSel, el("div", { class: "row", style: "margin-top:6px" }, el("span", { class: "muted", style: "font-size:12px" }, "DNS filter "), filterSel(t))),
      el("td", {}, el("button", { class: "iconbtn", title: "delete tunnel", onclick: () => deleteTunnel(n) }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No tunnels yet – add a WireGuard, OpenVPN, Tailscale or Headscale tunnel under “Add a tunnel” below."))]));

  $("#c-rules").replaceChildren(...(model.rule.length ? model.rule.map((r, i) => {
    const sel = [];
    if (r.app) sel.push("apps: " + joinList(r.app) + (r.args ? " [" + joinList(r.args) + "]" : ""));
    if (r.domain) sel.push("domains: " + joinList(r.domain));
    if (r.cidr) sel.push("IPs: " + joinList(r.cidr));
    if (r.port) sel.push("ports: " + joinList(r.port));
    if (r.group) sel.push("groups: " + joinList(r.group));
    if (r.network) sel.push("only on: " + joinList(r.network));
    if (r.override_explicit) sel.push("also for apps started in a route");
    if (r.dns_filter) sel.push("DNS filter: " + r.dns_filter);
    const move = (d) => { const j = i + d; [model.rule[i], model.rule[j]] = [model.rule[j], model.rule[i]]; markDirty(); renderConfig(); };
    return el("tr", {},
      el("td", { class: "muted" }, i + 1 + "."),
      el("td", {}, el("b", {}, r.name || "(unnamed)"), el("div", {}, ...sel.map((x) => el("span", { class: "chip" }, x)))),
      el("td", {}, r.route ? routeTag(r.route) : el("span", { class: "muted" }, "route unchanged")),
      el("td", { style: "white-space:nowrap" },
        el("button", { class: "iconbtn", title: "up", onclick: () => i > 0 && move(-1) }, "↑"), " ",
        el("button", { class: "iconbtn", title: "down", onclick: () => i < model.rule.length - 1 && move(1) }, "↓"), " ",
        el("button", { class: "iconbtn", title: "edit", onclick: () => openRule(i) }, "✎"), " ",
        el("button", { class: "iconbtn", title: "delete", onclick: () => { model.rule.splice(i, 1); markDirty(); renderConfig(); } }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No rules – apps follow the route they were started with, everything else the default."))]));
}

$("#c-killswitch").addEventListener("change", (e) => { model.daemon.kill_switch = e.target.checked; markDirty(); });
$("#c-default").addEventListener("change", (e) => { model.daemon.default_route = e.target.value; markDirty(); defaultHint(); });
function defaultHint() {
  const d = model.daemon.default_route || "direct";
  $("#c-default-hint").textContent = d === "direct" && Object.keys(model.tunnel).length
    ? "Everything without a rule goes past the VPN with your real IP – only apps you start through a tunnel are protected." : "";
}
$("#c-direct").addEventListener("change", (e) => { model.dns.direct = e.target.value || undefined; markDirty(); renderConfig(); });
$("#c-blockdoh").addEventListener("change", (e) => { model.dns.allow_doh = !e.target.checked; markDirty(); });
$("#c-blockdot").addEventListener("change", (e) => { model.dns.allow_dot = !e.target.checked; markDirty(); });

$("#u-add").addEventListener("click", () => {
  const name = $("#u-name").value.trim();
  const addr = $("#u-addr").value.trim();
  const tls = $("#u-tls").value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(name)) return toast("Name: letters, digits, - and _");
  if (!addr) return toast("Address missing");
  if (/^(tls|https):/.test(addr) && !tls) return toast("tls:// and https:// need the TLS name of the server");
  model.dns.upstream[name] = tls ? { addr, tls_name: tls } : { addr };
  ["#u-name", "#u-addr", "#u-tls"].forEach((s) => ($(s).value = ""));
  markDirty();
  renderConfig();
});

function openRule(i) {
  editIdx = i;
  const r = i >= 0 ? model.rule[i] : { route: modelRoutes().find((x) => x.startsWith("tunnel:")) || "direct" };
  $("#r-name").value = r.name || "";
  fill("#r-route", [["", "unchanged – only set the DNS filter"], ...modelRoutes()], r.route || "");
  fill("#r-filter", FILTER_OPTS, r.dns_filter || "");
  $("#r-app").value = joinList(r.app);
  $("#r-args").value = joinList(r.args);
  $("#r-domain").value = joinList(r.domain);
  $("#r-cidr").value = joinList(r.cidr);
  $("#r-port").value = joinList(r.port);
  $("#r-group").value = joinList(r.group);
  const nets = (model.network || []).map((n) => n.name);
  $("#r-network").replaceChildren(...(nets.length ? nets.map((n) => el("label", { class: "row", style: "color:var(--text)" },
    el("input", { type: "checkbox", value: n, checked: (r.network || []).includes(n) ? "" : null }), n)) :
    [el("span", { class: "muted" }, "everywhere (no network profiles yet – see Networks)")]));
  $("#r-override").checked = !!r.override_explicit;
  $("#r-editor").hidden = false;
  $("#r-name").focus();
}
$("#r-new").addEventListener("click", () => openRule(-1));
$("#r-cancel").addEventListener("click", () => { $("#r-editor").hidden = true; });
$("#r-ok").addEventListener("click", () => {
  const r = { name: $("#r-name").value.trim() };
  if ($("#r-route").value) r.route = $("#r-route").value;
  if ($("#r-filter").value) r.dns_filter = $("#r-filter").value;
  for (const [k, id] of [["app", "#r-app"], ["args", "#r-args"], ["domain", "#r-domain"], ["cidr", "#r-cidr"], ["port", "#r-port"], ["group", "#r-group"]]) {
    const v = splitList($(id).value);
    if (v.length) r[k] = v;
  }
  const nets = [...document.querySelectorAll("#r-network input:checked")].map((x) => x.value);
  if (nets.length) r.network = nets;
  if ($("#r-override").checked) r.override_explicit = true;
  if (!r.app && !r.domain && !r.cidr && !r.port && !r.group) return toast("A rule needs at least one of apps, domains, IP ranges, ports or groups");
  if (r.args && !r.app) return toast("Arguments only work together with apps");
  if (r.dns_filter && !r.app && !r.group) return toast("A DNS filter level needs apps or groups");
  if (!r.route && !r.dns_filter) return toast("Choose a route or a DNS filter level");
  if (!r.route && (r.domain || r.cidr || r.port)) return toast("Without a route the rule only sets the DNS filter: no domains, IPs or ports");
  for (const g of r.group || []) model.group[g] = model.group[g] || {};
  if (editIdx >= 0) model.rule[editIdx] = r;
  else model.rule.push(r);
  $("#r-editor").hidden = true;
  markDirty();
  renderConfig();
});

async function checkOrSave(save, body, msgFn) {
  body.version = cfgView && cfgView.version;
  try {
    const res = await api(save ? "PUT" : "POST", save ? "/api/config" : "/api/config/check", body);
    if (!res.ok) { msgFn(res.error, "err"); return false; }
    const w = (res.warnings || []).length ? " Warnings: " + res.warnings.join(" · ") : "";
    msgFn((save ? "Saved and applied." : "Looks good – nothing written yet.") + w, w ? "warn" : "ok");
    return true;
  } catch (e) {
    msgFn(e.message, "err");
    if (/changed meanwhile/.test(e.message) && await ask("The config file was changed outside this editor since you opened it.\nLoad the current version? (your unsaved changes here are lost – nothing was overwritten)", { ok: "Load current" })) {
      await loadConfig();
      msgFn("Loaded the current config – please make your change again.", "warn");
    }
    return false;
  }
}

$("#c-check").addEventListener("click", () => checkOrSave(false, { config: model }, cmsg));
$("#c-save").addEventListener("click", async () => {
  if (await checkOrSave(true, { config: model }, cmsg)) {
    const m = $("#c-msg").textContent;
    await loadConfig();
    cmsg(m, "ok");
    refresh();
  }
});
$("#c-revert").addEventListener("click", loadConfig);

const rawMsg = (text, cls) => { const m = $("#raw-msg"); m.className = "msg " + cls; m.textContent = text; };
$("#raw-toggle").addEventListener("click", () => {
  const box = $("#raw-box");
  box.hidden = !box.hidden;
  $("#raw-toggle").textContent = box.hidden ? "Show" : "Hide";
});
$("#raw-check").addEventListener("click", () => checkOrSave(false, { raw: $("#raw").value }, rawMsg));
$("#raw-save").addEventListener("click", async () => {
  if (await checkOrSave(true, { raw: $("#raw").value }, rawMsg)) { await loadConfig(); refresh(); }
});

// --- tunnel import ------------------------------------------------------
function confType(t) {
  if (t.includes("[Interface]")) return "wireguard";
  if (/^\s*remote\s+\S/m.test(t)) return "openvpn";
  if (/^\s*auth_key\s*=/m.test(t)) return "tailscale";
  return "";
}
function needsLogin(t) {
  // auth-user-pass without its own inline block
  return /^\s*auth-user-pass\s*$/m.test(t) && !/<auth-user-pass>/i.test(t);
}
function updateImportForm() {
  const t = $("#t-conf").value;
  const type = confType(t);
  $("#t-type").textContent = type === "wireguard" ? "WireGuard config" : type === "openvpn" ? "OpenVPN config" + (needsLogin(t) ? " – needs a login" : "") : t.trim() ? "not a WireGuard or OpenVPN config?" : "";
  $("#t-auth").hidden = !(type === "openvpn" && needsLogin(t));
}
// same rules as `shunt import`: "Mullvad-DE_fra 001.conf" -> "mullvad-de"
function nameFromFile(n) {
  let s = n.toLowerCase().replace(/\.(conf|ovpn|ts)$/, "").replace(/[-_ .]+/g, "-").replace(/[^a-z0-9-]/g, "").replace(/^-+/, "");
  return s.slice(0, 10).replace(/-+$/, "") || "tunnel";
}
function takeFile(f) {
  if (!f) return;
  if (f.size > 256 * 1024) return toast("That file is too big for a VPN config");
  f.text().then((t) => {
    $("#t-conf").value = t;
    if (!$("#t-name").value) $("#t-name").value = nameFromFile(f.name);
    updateImportForm();
    if (!confType(t)) toast(f.name + " doesn't look like a WireGuard, OpenVPN or Tailscale/Headscale config");
  }).catch((e) => toast("Cannot read " + f.name + ": " + e.message + " (root-only files: sudo shunt import FILE)"));
}
function fillVia() {
  const tunnels = Object.keys(model.tunnel || {}).sort();
  const cur = $("#t-via").value;
  fill("#t-via", [["", "directly to the server"], ...tunnels.map((n) => ["tunnel:" + n, "through tunnel " + n + " (multi-hop)"]),
    ...LINKS.map(([v, l]) => [v, "over " + l + " only"])], cur);
}
$("#t-conf").addEventListener("input", updateImportForm);
$("#t-file").addEventListener("change", (e) => { takeFile(e.target.files[0]); e.target.value = ""; });
const drop = $("#t-drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); takeFile(e.dataTransfer.files[0]); });
// a file dropped next to the drop zone must not replace the page
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => e.preventDefault());

$("#t-import").addEventListener("click", async () => {
  const name = $("#t-name").value.trim();
  const conf = $("#t-conf").value;
  const type = confType(conf);
  if (!/^[a-z0-9][a-z0-9-]{0,9}$/.test(name)) return toast("Tunnel name: 1–10 characters a-z 0-9 -");
  if (!type) return toast("Paste or drop a WireGuard (.conf), OpenVPN (.ovpn) or Tailscale/Headscale (.ts) config first");
  if (model.tunnel && model.tunnel[name]) return toast("There is a tunnel " + name + " already – pick another name");
  const req = { name, conf, via: $("#t-via").value || undefined };
  if (type === "openvpn" && needsLogin(conf)) {
    req.username = $("#t-user").value.trim();
    req.password = $("#t-pass").value;
    if (!req.username || !req.password) return toast("This OpenVPN server wants a username and password");
  }
  if ($("#savebar").classList.contains("dirty") && !(await ask("Importing reloads the config; your unsaved form changes are discarded. Continue?", { ok: "Import" }))) return toast("Import cancelled");
  try {
    const res = await api("POST", "/api/tunnels", req);
    toast("Tunnel " + name + " imported" + ((res.warnings || []).length ? " – " + res.warnings.join(" · ") : ""));
    for (const id of ["#t-name", "#t-conf", "#t-user", "#t-pass"]) $(id).value = "";
    $("#t-via").value = "";
    updateImportForm();
    await loadConfig();
    refresh();
  } catch (e) { toast("Import failed: " + e.message); }
});

$("#ts-add").addEventListener("click", async () => {
  const name = $("#ts-name").value.trim();
  const v = (id) => $(id).value.trim();
  if (!/^[a-z0-9][a-z0-9-]{0,9}$/.test(name)) return toast("Tunnel name: 1–10 characters a-z 0-9 -");
  if (model.tunnel && model.tunnel[name]) return toast("There is a tunnel " + name + " already – pick another name");
  if (!v("#ts-key")) return toast("An auth key is needed");
  if ([v("#ts-server"), v("#ts-key"), v("#ts-host"), v("#ts-exit")].some((x) => /[\r\n]/.test(x))) return toast("No line breaks, please");
  const conf = ["login_server = " + v("#ts-server"), "auth_key = " + v("#ts-key"),
    ...(v("#ts-host") ? ["hostname = " + v("#ts-host")] : []), ...(v("#ts-exit") ? ["exit_node = " + v("#ts-exit")] : [])].join("\n") + "\n";
  if ($("#savebar").classList.contains("dirty") && !(await ask("Adding reloads the config; your unsaved form changes are discarded. Continue?", { ok: "Add" }))) return toast("Cancelled");
  try {
    const res = await api("POST", "/api/tunnels", { name, conf, driver: "tailscale" });
    toast("Tunnel " + name + " added" + ((res.warnings || []).length ? " – " + res.warnings.join(" · ") : ""));
    for (const id of ["#ts-name", "#ts-server", "#ts-key", "#ts-host", "#ts-exit"]) $(id).value = "";
    await loadConfig();
    refresh();
  } catch (e) { toast("Adding failed: " + e.message); }
});

async function deleteTunnel(n) {
  if ($("#savebar").classList.contains("dirty")) return toast("Save or discard your other changes first");
  if (!(await ask("Delete tunnel " + n + " and its config file?", { ok: "Delete", danger: true }))) return;
  try {
    await api("DELETE", "/api/tunnels/" + encodeURIComponent(n));
    toast("Tunnel " + n + " deleted");
    await loadConfig();
    refresh();
  } catch (e) { toast(e.message); }
}

// --- network profiles ---------------------------------------------------
function netNow() { return (status && status.net_info) || {}; }
function updateNetNow() {
  const now = netNow();
  $("#n-now").textContent = now.iface
    ? "Now: " + now.iface + (now.ssid ? " · Wi-Fi “" + now.ssid + "”" : "") + (now.gateway_mac ? " · router " + now.gateway_mac : " · router MAC unknown") +
      (status && status.network ? " → profile “" + status.network + "” active" : " → no profile: “Everything else goes” applies")
    : "Not connected to a network right now.";
}
function renderNetworks() {
  updateNetNow();
  const nets = model.network || [];
  $("#c-networks").replaceChildren(...(nets.length ? nets.map((n, i) => {
    const route = el("select", { onchange: (e) => { n.default_route = e.target.value; markDirty(); } }, ...modelRoutes().map((r) => el("option", { value: r }, r)));
    route.value = n.default_route;
    const crit = [];
    if (n.ssid) crit.push("Wi-Fi: " + joinList(n.ssid));
    if (n.gateway_mac) crit.push("router: " + joinList(n.gateway_mac));
    const weak = n.ssid && !n.gateway_mac && n.default_route !== "block" && n.default_route !== model.daemon.default_route;
    return el("tr", {},
      el("td", {}, el("b", {}, n.name)),
      el("td", {}, ...crit.map((x) => el("span", { class: "chip" }, x)),
        weak ? el("div", { style: "color:var(--warn)" }, "Wi-Fi names are easy to fake: add the router MAC") : ""),
      el("td", {}, el("span", { class: "muted" }, "everything else goes "), route,
        el("div", { class: "row", style: "margin-top:6px" }, el("span", { class: "muted" }, "app firewall "), (() => {
          const f = el("select", { onchange: (e) => { n.firewall = e.target.value || undefined; markDirty(); } },
            el("option", { value: "" }, "as set below"), el("option", { value: "off" }, "off"), el("option", { value: "ask" }, "ask"), el("option", { value: "block" }, "block"));
          f.value = n.firewall || "";
          return f;
        })()),
        el("div", { class: "row", style: "margin-top:6px" }, el("span", { class: "muted", title: "DNS for direct and Wi-Fi/cable routes on this network" }, "DNS direct "), (() => {
          const d = el("select", { onchange: (e) => { n.dns_direct = e.target.value || undefined; markDirty(); } },
            el("option", { value: "" }, "as set in DNS"), el("option", { value: "system" }, "the network's own"),
            ...Object.keys((model.dns || {}).upstream || {}).sort().map((u) => el("option", { value: u }, u)));
          d.value = n.dns_direct || "";
          return d;
        })()),
        el("div", { class: "row", style: "margin-top:6px" }, el("span", { class: "muted", title: "DNS filter for direct and Wi-Fi/cable routes on this network (tunnels keep their own)" }, "DNS filter "), filterSel(n))),
      el("td", {}, el("button", { class: "iconbtn", title: "remove", onclick: () => { nets.splice(i, 1); markDirty(); renderConfig(); } }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No profiles – e.g. at home everything direct, everywhere else through a tunnel."))]));
}
$("#n-add").addEventListener("click", async () => {
  const now = netNow();
  if (!now.ssid && !now.gateway_mac) return toast("The current network can't be recognised (no Wi-Fi name, router MAC unknown)");
  const name = ((await ask("Name for this network", { input: now.ssid || "home", ok: "Add" })) || "").trim();
  if (!name) return;
  model.network = model.network || [];
  if (model.network.some((n) => n.name === name)) return toast("There is a network called " + name + " already");
  const n = { name, default_route: "direct" };
  if (now.ssid) n.ssid = [now.ssid];
  if (now.gateway_mac) n.gateway_mac = [now.gateway_mac];
  model.network.push(n);
  markDirty();
  renderConfig();
});

// Follow changes made elsewhere (editor, `shunt import`, another window)
// while nothing is being edited here.
setInterval(async () => {
  if (!model || $("#page-config").hidden || $("#savebar").classList.contains("dirty")) return;
  try {
    const v = await api("GET", "/api/config");
    if (v.version !== cfgView.version) await loadConfig();
  } catch { /* daemon away: the status pill says so */ }
}, 5000);

// --- app firewall ------------------------------------------------------------
function fwModel() { model.firewall = model.firewall || { mode: "off" }; return model.firewall; }
function renderFirewall() {
  const f = model.firewall || {};
  $("#c-fwmode").value = f.mode || "off";
  $("#c-fwtimeout").value = f.timeout || 30;
  $("#c-fwterm").checked = !!f.ask_terminal;
  $("#c-fwtimeout").disabled = (f.mode || "off") !== "ask";
  loadFwApps();
}
async function loadFwApps() {
  let rs = [];
  try { rs = await api("GET", "/api/firewall/apps"); } catch { /* daemon away */ }
  $("#c-fwapps").replaceChildren(...(rs.length ? rs.map((r) => el("tr", {},
    el("td", {}, el("b", {}, r.name), el("div", { class: "muted mono", style: "font-size:12px" }, r.key)),
    el("td", {}, routeTag(r.route || (status ? status.default_route : "default"))),
    el("td", {}, el("button", { class: "iconbtn", title: "forget – asked again next start", onclick: async () => {
      try { await api("DELETE", "/api/firewall/apps?key=" + encodeURIComponent(r.key)); toast(r.name + " forgotten"); loadFwApps(); } catch (e) { toast(e.message); }
    } }, "✕")))) : [el("tr", {}, el("td", { class: "muted" }, "None yet – answers with “remember” show up here."))]));
}
$("#c-fwmode").addEventListener("change", (e) => { fwModel().mode = e.target.value; markDirty(); renderFirewall(); });
$("#c-fwtimeout").addEventListener("change", (e) => { fwModel().timeout = Math.max(5, +e.target.value || 30); markDirty(); });
$("#c-fwterm").addEventListener("change", (e) => { fwModel().ask_terminal = e.target.checked || undefined; markDirty(); });
function fwPreset(mode, defaultToTunnel) {
  fwModel().mode = mode;
  if (defaultToTunnel) {
    const t = Object.keys(model.tunnel).sort()[0];
    if (t) model.daemon.default_route = "tunnel:" + t;
  }
  markDirty();
  renderConfig();
  toast("Preset set – press “Save & apply”");
}
$("#fw-p-paranoid").addEventListener("click", () => fwPreset("block", true));
$("#fw-p-normal").addEventListener("click", () => fwPreset("ask", false));
$("#fw-p-off").addEventListener("click", () => fwPreset("off", false));

// "Add a tunnel": switch between the file import and the Tailscale/Headscale form
for (const [t, other] of [["file", "ts"], ["ts", "file"]]) {
  $("#addtab-" + t).addEventListener("click", () => {
    $("#add-" + t).hidden = false;
    $("#add-" + other).hidden = true;
    $("#addtab-" + t).classList.add("active");
    $("#addtab-" + other).classList.remove("active");
  });
}

// a reload (or a link with #apps) opens the same tab again
{
  const t = location.hash.slice(1);
  if (["apps", "config", "filter"].includes(t)) setTab(t);
}
