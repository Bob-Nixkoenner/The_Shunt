"use strict";
// Configure page: edits a copy of the daemon's config; nothing is written
// before the daemon has checked it (same checks as `shuntd check`).

let cfgView = null; // last config from the daemon (raw text, parsed, tunnel info)
let model = null; // working copy being edited
let editIdx = -1; // rule being edited (-1 = new)

const splitList = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
const joinList = (a) => (a || []).join(", ");

// One page per tab. The tabs that edit the config share one copy of it and
// one save bar, which moves along to the page that is shown.
const TABS = ["overview", "vpn", "apps", "dns", "ports", "speed", "config", "view"];
const CFG_TABS = ["vpn", "apps", "dns", "ports", "config"];
let curTab = "overview";
function setTab(t) {
  if (t === "filter") t = "dns"; // old links
  if (!TABS.includes(t) || $("#tab-" + t).offsetParent === null) t = "overview"; // e.g. Ports in Normal view
  curTab = t;
  for (const n of TABS) {
    $("#page-" + n).hidden = t !== n;
    $("#tab-" + n).classList.toggle("active", t === n);
  }
  // the app firewall (Linux only) is the config part of the Apps page
  const bar = $("#savebar");
  bar.hidden = !CFG_TABS.includes(t) || (t === "apps" && document.body.classList.contains("windows"));
  if (!bar.hidden) $("#page-" + t).append(bar);
  if (CFG_TABS.includes(t) && !model) loadConfig();
  // "#/dns", not "#dns": a reload would scroll to the element with id="dns"
  try { history.replaceState(null, "", t === "overview" ? location.pathname : "#/" + t); } catch (e) { /* file: or sandbox */ }
  if (t === "apps") loadApps(); // installed programs and the config may have changed since the last visit
  if (typeof viewChanged === "function") viewChanged();
}
const cfgShown = () => CFG_TABS.includes(curTab);
for (const n of TABS) $("#tab-" + n).addEventListener("click", () => setTab(n));

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
    cmsg(T("Cannot load the config: {error}", { error: e.message }), "err");
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
  if (model.dns.direct === name) users.push(T("direct DNS"));
  for (const [t, v] of Object.entries(model.tunnel)) if (v.dns === name) users.push(T("tunnel {name}", { name: t }));
  return users;
}

function renderConfig() {
  const ups = Object.keys(model.dns.upstream).sort();
  fill("#c-default", modelRoutes(), model.daemon.default_route || "direct");
  $("#c-killswitch").checked = model.daemon.kill_switch !== false; // unset = on
  defaultHint();
  fillVia();
  renderNetworks();
  renderFirewall();
  fill("#c-direct", [["", "system resolvers (from resolv.conf)"], ...ups.map((u) => [u, u + " – " + model.dns.upstream[u].addr])], model.dns.direct || "");
  $("#c-blockdoh").checked = !model.dns.allow_doh;
  $("#c-blockdot").checked = !model.dns.allow_dot;
  $("#c-hostname").value = model.daemon.dhcp_hostname || "";
  $("#c-mac").value = model.daemon.mac || "";
  $("#c-bootlock").value = model.daemon.boot_lockdown === "auto" ? "" : model.daemon.boot_lockdown || "";
  $("#c-inbound").checked = !!(model.inbound && model.inbound.enabled);
  $("#c-inallow").value = ((model.inbound && model.inbound.allow) || []).join(" ");

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
    const fromFile = i.type === "openvpn" ? T("DNS pushed by the server") : i.dns && i.dns.length ? T("DNS from its file ({list})", { list: i.dns.join(", ") }) : T("DNS from its file (none!)");
    const dnsSel = el("select", { onchange: (e) => { t.dns = e.target.value || undefined; markDirty(); } },
      el("option", { value: "" }, fromFile),
      ...ups.map((u) => el("option", { value: u }, u)));
    dnsSel.value = t.dns || "";
    // multi-hop: a tunnel may run through any other tunnel (not through
    // itself or one that already runs through it)
    const loops = (m) => { for (let c = m, k = 0; c && k < 20; k++) { if (c === n) return true; c = ((model.tunnel[c] || {}).via || "").replace(/^tunnel:/, ""); } return false; };
    const viaSel = el("select", { title: "multi-hop", class: "expert", onchange: (e) => { t.via = e.target.value || undefined; markDirty(); renderConfig(); } },
      el("option", { value: "" }, "direct to its server"),
      ...names.filter((m) => !loops(m)).map((m) => el("option", { value: "tunnel:" + m }, T("via {tunnel}", { tunnel: m }))),
      ...LINKS.map(([v, l]) => el("option", { value: v }, T("over {link} only", { link: T(l) }))));
    viaSel.value = t.via || "";
    return el("tr", {},
      el("td", {}, routeTag("tunnel:" + n), el("div", { class: "muted" }, i.type === "openvpn" ? "OpenVPN" : "WireGuard")),
      el("td", { class: "mono" }, (i.endpoint || "–") + "  ", el("span", { class: "muted" }, joinList(i.addresses))),
      el("td", {}, viaSel, el("label", { class: "row muted", style: "font-size:12px;margin-top:6px", title: "Apps in this tunnel still reach printers, NAS and the router of the network you are in (private addresses only)" },
        el("input", { type: "checkbox", checked: t.allow_lan ? "" : null, onchange: (e) => { t.allow_lan = e.target.checked || undefined; markDirty(); } }), "local network direct"),
      el("label", { class: "row muted", style: "font-size:12px;margin-top:6px", title: "Keep the tunnel but don't connect it. Apps that would use it are blocked." },
        el("input", { type: "checkbox", checked: t.disabled ? null : "", onchange: (e) => { t.disabled = !e.target.checked || undefined; markDirty(); } }), "switched on")),
      el("td", {}, dnsSel, el("div", { class: "row", style: "margin-top:6px" }, el("span", { class: "muted", style: "font-size:12px" }, "DNS filter "), filterSel(t)),
        el("div", { class: "row linux-only", style: "margin-top:6px" }, el("span", { class: "muted", style: "font-size:12px", title: "Incoming connections through this tunnel, on every network (when switched on above). LAN = e.g. a tunnel home." }, "incoming "), (() => {
          const s = el("select", { onchange: (e) => { t.inbound = e.target.value || undefined; markDirty(); } },
            el("option", { value: "" }, "closed"), el("option", { value: "lan" }, "LAN: allowed ports"), el("option", { value: "open" }, "open (no filter)"));
          s.value = t.inbound === "closed" ? "" : t.inbound || "";
          return s;
        })())),
      el("td", {}, el("button", { class: "iconbtn", title: "delete tunnel", onclick: () => deleteTunnel(n) }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No tunnels yet – add a WireGuard, OpenVPN, Tailscale or Headscale tunnel under “Add a tunnel” below."))]));

  $("#c-rules").replaceChildren(...(model.rule.length ? model.rule.map((r, i) => {
    const sel = [];
    if (r.app) sel.push(T("apps: {list}", { list: joinList(r.app) + (r.args ? " [" + joinList(r.args) + "]" : "") }));
    if (r.domain) sel.push(T("domains: {list}", { list: joinList(r.domain) }));
    if (r.cidr) sel.push(T("IPs: {list}", { list: joinList(r.cidr) }));
    if (r.port) sel.push(T("ports: {list}", { list: joinList(r.port) }));
    if (r.group) sel.push(T("groups: {list}", { list: joinList(r.group) }));
    if (r.network) sel.push(T("only on: {list}", { list: joinList(r.network) }));
    if (r.override_explicit) sel.push("also for apps started in a route");
    if (r.dns_filter) sel.push(T("DNS filter: {level}", { level: T(r.dns_filter) }));
    // a rule that matches addresses/domains/ports does not reach programs that were started in a
    // route on purpose (launcher, shunt run --via): they keep their route unless the rule says otherwise
    const skipped = r.route && !r.override_explicit && !r.app && !r.group && !r.dns_filter && typeof apps !== "undefined"
      ? apps.filter((a) => a.route && a.route !== r.route && (a.clone || a.route.startsWith("tunnel:"))).map((a) => a.name + " (" + a.route + ")") : [];
    // an app rule catches the program only after it started: menu entries that start it
    // outside the rule's route (#6: first DNS query/connection go the old way) can start
    // it in the route instead. Entries started in a route of their own are left alone by
    // the rule (unless override_explicit), so they are not listed.
    const early = r.app && r.route && r.route !== "direct" && !r.args && typeof apps !== "undefined"
      ? apps.filter((a) => !a.clone && a.route !== r.route && (!a.route || r.override_explicit) && r.app.some((sel) => menuStarts(a.exec, sel, a.chromium))) : [];
    const move = (d) => { const j = i + d; [model.rule[i], model.rule[j]] = [model.rule[j], model.rule[i]]; markDirty(); renderConfig(); };
    return el("tr", {},
      el("td", { class: "muted" }, i + 1 + "."),
      el("td", {}, el("b", {}, r.name || "(unnamed)"), el("div", {}, ...sel.map((x) => el("span", { class: "chip" }, x))),
        skipped.length ? el("div", { class: "muted", style: "font-size:12px;margin-top:4px;color:var(--warn)" },
          T("does not apply to: {list} – they keep the route they were started with. ", { list: skipped.slice(0, 3).join(", ") + (skipped.length > 3 ? " …" : "") }),
          el("a", { href: "#", onclick: (e) => { e.preventDefault(); r.override_explicit = true; markDirty(); renderConfig(); } }, "apply to them too")) : "",
        early.length ? el("div", { class: "muted linux-only", style: "font-size:12px;margin-top:4px;color:var(--warn)" },
          T("from the menu, {list} starts outside the route for a moment (its first connection can go the old way). ", { list: early.map((a) => a.name).join(", ") }),
          el("a", { href: "#", onclick: async (e) => {
            e.preventDefault();
            try {
              for (const a of early) await api("POST", "/api/apps", { id: a.id, route: r.route });
              toast(Tn(early.length, "{list} now starts via {route}", "{list} now start via {route}", { list: early.map((a) => a.name).join(", "), route: r.route }));
            } catch (err) { toast(String(err.message || err)); }
            await loadApps(); renderConfig();
          } }, "start in the route from the menu")) : ""),
      el("td", {}, r.route ? routeTag(r.route) : el("span", { class: "muted" }, "route unchanged")),
      el("td", { style: "white-space:nowrap" },
        el("button", { class: "iconbtn", title: "up", onclick: () => i > 0 && move(-1) }, "↑"), " ",
        el("button", { class: "iconbtn", title: "down", onclick: () => i < model.rule.length - 1 && move(1) }, "↓"), " ",
        el("button", { class: "iconbtn", title: "edit", onclick: () => openRule(i) }, "✎"), " ",
        el("button", { class: "iconbtn", title: "delete", onclick: () => { model.rule.splice(i, 1); markDirty(); renderConfig(); } }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No rules – apps follow the route they were started with, everything else the default."))]));
  renderPorts();
  if (typeof viewChanged === "function") viewChanged();
}

function renderPorts() {
  const rs = model.rule.map((r, i) => [r, i]).filter(([r]) => r.port);
  $("#p-rules").replaceChildren(...(rs.length ? rs.map(([r, i]) => el("tr", {},
    el("td", { class: "muted" }, i + 1 + "."),
    el("td", {}, el("b", {}, r.name || "(unnamed)"), el("div", {}, ...r.port.map((x) => el("span", { class: "chip mono" }, x)),
      ...(r.app ? [el("span", { class: "chip" }, T("apps: {list}", { list: joinList(r.app) }))] : []), ...(r.cidr ? [el("span", { class: "chip" }, T("IPs: {list}", { list: joinList(r.cidr) }))] : []))),
    el("td", {}, routeTag(r.route)),
    el("td", {}, el("button", { class: "iconbtn", title: "edit", onclick: () => editRuleFromPorts(i) }, "✎")))) :
    [el("tr", {}, el("td", { class: "muted" }, "No port rules – e.g. send SSH (tcp/22) or a game's UDP ports through a tunnel."))]));
}
function editRuleFromPorts(i) {
  setTab("config");
  openRule(i);
  if (i < 0) $("#r-port").focus();
  $("#r-editor").scrollIntoView({ block: "center" });
}
$("#p-new").addEventListener("click", () => editRuleFromPorts(-1));

$("#c-killswitch").addEventListener("change", (e) => { model.daemon.kill_switch = e.target.checked; markDirty(); });
$("#c-hostname").addEventListener("change", (e) => { model.daemon.dhcp_hostname = e.target.value || undefined; markDirty(); });
$("#c-mac").addEventListener("change", (e) => { model.daemon.mac = e.target.value || undefined; markDirty(); });
$("#c-bootlock").addEventListener("change", (e) => { model.daemon.boot_lockdown = e.target.value || undefined; markDirty(); });
$("#c-default").addEventListener("change", (e) => { model.daemon.default_route = e.target.value; markDirty(); defaultHint(); });
function defaultHint() {
  const d = model.daemon.default_route || "direct";
  $("#c-default-hint").textContent = d === "direct" && Object.keys(model.tunnel).length
    ? "Everything without a rule goes past the VPN with your real IP – only apps you start through a tunnel are protected." : "";
}
$("#c-direct").addEventListener("change", (e) => { model.dns.direct = e.target.value || undefined; markDirty(); renderConfig(); });
$("#c-blockdoh").addEventListener("change", (e) => { model.dns.allow_doh = !e.target.checked; markDirty(); });
$("#c-blockdot").addEventListener("change", (e) => { model.dns.allow_dot = !e.target.checked; markDirty(); });
$("#c-inbound").addEventListener("change", (e) => { model.inbound = model.inbound || {}; model.inbound.enabled = e.target.checked; markDirty(); });
$("#c-inallow").addEventListener("input", (e) => {
  model.inbound = model.inbound || {};
  model.inbound.allow = e.target.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  if (!model.inbound.allow.length) delete model.inbound.allow;
  markDirty();
});

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
    const w = (res.warnings || []).length ? " " + T("Warnings: {list}", { list: res.warnings.join(" · ") }) : "";
    msgFn(T(save ? "Saved and applied." : "Looks good – nothing written yet.") + w, w ? "warn" : "ok");
    return true;
  } catch (e) {
    msgFn(e.message, "err");
    if (/changed meanwhile/.test(e.message) && await ask(T("The config file was changed outside this editor since you opened it.\nLoad the current version? (your unsaved changes here are lost – nothing was overwritten)"), { ok: "Load current" })) {
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
  $("#t-type").textContent = type === "wireguard" ? T("WireGuard config") : type === "openvpn" ? T(needsLogin(t) ? "OpenVPN config – needs a login" : "OpenVPN config") : t.trim() ? T("not a WireGuard or OpenVPN config?") : "";
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
    if (!confType(t)) toast(T("{name} doesn't look like a WireGuard, OpenVPN or Tailscale/Headscale config", { name: f.name }));
  }).catch((e) => toast(T("Cannot read {name}: {error} (root-only files: sudo shunt import FILE)", { name: f.name, error: e.message })));
}
function fillVia() {
  const tunnels = Object.keys(model.tunnel || {}).sort();
  const cur = $("#t-via").value;
  fill("#t-via", [["", "directly to the server"], ...tunnels.map((n) => ["tunnel:" + n, T("through tunnel {name} (multi-hop)", { name: n })]),
    ...LINKS.map(([v, l]) => [v, T("over {link} only", { link: T(l) })])], cur);
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
  if (model.tunnel && model.tunnel[name]) return toast(T("There is a tunnel {name} already – pick another name", { name }));
  const req = { name, conf, via: $("#t-via").value || undefined };
  if (type === "openvpn" && needsLogin(conf)) {
    req.username = $("#t-user").value.trim();
    req.password = $("#t-pass").value;
    if (!req.username || !req.password) return toast("This OpenVPN server wants a username and password");
  }
  if ($("#savebar").classList.contains("dirty") && !(await ask("Importing reloads the config; your unsaved form changes are discarded. Continue?", { ok: "Import" }))) return toast("Import cancelled");
  try {
    const res = await api("POST", "/api/tunnels", req);
    toast((res.warnings || []).length ? T("Tunnel {name} imported – {warnings}", { name, warnings: res.warnings.join(" · ") }) : T("Tunnel {name} imported", { name }));
    for (const id of ["#t-name", "#t-conf", "#t-user", "#t-pass"]) $(id).value = "";
    $("#t-via").value = "";
    updateImportForm();
    await loadConfig();
    refresh();
  } catch (e) { toast(T("Import failed: {error}", { error: e.message })); }
});

$("#ts-add").addEventListener("click", async () => {
  const name = $("#ts-name").value.trim();
  const v = (id) => $(id).value.trim();
  if (!/^[a-z0-9][a-z0-9-]{0,9}$/.test(name)) return toast("Tunnel name: 1–10 characters a-z 0-9 -");
  if (model.tunnel && model.tunnel[name]) return toast(T("There is a tunnel {name} already – pick another name", { name }));
  if (!v("#ts-key")) return toast("An auth key is needed");
  if ([v("#ts-server"), v("#ts-key"), v("#ts-host"), v("#ts-exit")].some((x) => /[\r\n]/.test(x))) return toast("No line breaks, please");
  const conf = ["login_server = " + v("#ts-server"), "auth_key = " + v("#ts-key"),
    ...(v("#ts-host") ? ["hostname = " + v("#ts-host")] : []), ...(v("#ts-exit") ? ["exit_node = " + v("#ts-exit")] : [])].join("\n") + "\n";
  if ($("#savebar").classList.contains("dirty") && !(await ask("Adding reloads the config; your unsaved form changes are discarded. Continue?", { ok: "Add" }))) return toast("Cancelled");
  try {
    const res = await api("POST", "/api/tunnels", { name, conf, driver: "tailscale" });
    toast((res.warnings || []).length ? T("Tunnel {name} added – {warnings}", { name, warnings: res.warnings.join(" · ") }) : T("Tunnel {name} added", { name }));
    for (const id of ["#ts-name", "#ts-server", "#ts-key", "#ts-host", "#ts-exit"]) $(id).value = "";
    await loadConfig();
    refresh();
  } catch (e) { toast(T("Adding failed: {error}", { error: e.message })); }
});

async function deleteTunnel(n) {
  if ($("#savebar").classList.contains("dirty")) return toast("Save or discard your other changes first");
  if (!(await ask(T("Delete tunnel {name} and its config file?", { name: n }), { ok: "Delete", danger: true }))) return;
  try {
    await api("DELETE", "/api/tunnels/" + encodeURIComponent(n));
    toast(T("Tunnel {name} deleted", { name: n }));
    await loadConfig();
    refresh();
  } catch (e) { toast(e.message); }
}

// --- network profiles ---------------------------------------------------
function netNow() { return (status && status.net_info) || {}; }
function updateNetNow() {
  const now = netNow();
  $("#n-now").textContent = now.iface
    ? T("Now: {iface}", { iface: now.iface }) + (now.ssid ? T(" · Wi-Fi “{ssid}”", { ssid: now.ssid }) : "") + (now.gateway_mac ? T(" · router {mac}", { mac: now.gateway_mac }) : T(" · router MAC unknown")) +
      (status && status.network ? T(" → profile “{name}” active", { name: status.network }) : T(" → no profile: “Everything else goes” applies"))
    : T("Not connected to a network right now.");
}
// field: a labelled select in a profile card; the left bar marks what the
// profile sets itself, so the few overrides stand out from "as set above"
function netField(text, title, options, get, set, o = {}) {
  const s = el("select", {}, ...options.map(([v, t]) => el("option", { value: v }, t)));
  s.value = get();
  const mark = (v) => o.mark !== false && !!v;
  const l = el("label", { title, class: (o.linux ? "linux-only " : "") + (mark(s.value) ? "set" : "") }, text, s);
  s.addEventListener("change", () => { set(s.value); l.classList.toggle("set", mark(s.value)); markDirty(); });
  return l;
}

function renderNetworks() {
  updateNetNow();
  const nets = model.network || [];
  const ups = Object.keys((model.dns || {}).upstream || {}).sort();
  $("#c-networks").replaceChildren(...(nets.length ? nets.map((n, i) => {
    const crit = [];
    if (n.ssid) crit.push(T("Wi-Fi: {list}", { list: joinList(n.ssid) }));
    if (n.gateway_mac) crit.push(T("router: {list}", { list: joinList(n.gateway_mac) }));
    const weak = n.ssid && !n.gateway_mac && n.default_route !== "block" && n.default_route !== model.daemon.default_route;
    const General = "as set above";
    const fs = filterSel(n);
    return el("div", { class: "netcard" },
      el("div", { class: "nethead" }, el("b", {}, n.name), ...crit.map((x) => el("span", { class: "chip" }, x)),
        weak ? el("span", { style: "color:var(--warn);font-size:12px" }, "Wi-Fi names are easy to fake: add the router MAC") : "",
        el("span", { class: "spacer" }),
        el("button", { class: "iconbtn", title: "remove this profile", onclick: () => { nets.splice(i, 1); markDirty(); renderConfig(); } }, "✕")),
      el("div", { class: "netgrid" },
        netField("everything else goes", "Route for apps without a rule on this network", modelRoutes().map((r) => [r, r]),
          () => n.default_route, (v) => { n.default_route = v; }, { mark: false }),
        netField("app firewall", "What happens to programs without a rule on this network",
          [["", "as set below"], ["off", "off"], ["ask", "ask"], ["block", "block"]], () => n.firewall || "", (v) => { n.firewall = v || undefined; }),
        netField("DNS direct", "DNS for direct and Wi-Fi/cable routes on this network",
          [["", "as set in DNS"], ["system", "the network's own"], ...ups.map((u) => [u, u])], () => n.dns_direct || "", (v) => { n.dns_direct = v || undefined; }),
        (() => {
          const l = el("label", { title: "DNS filter for direct and Wi-Fi/cable routes on this network (tunnels keep their own)", class: n.dns_filter ? "set" : "" }, "DNS filter", fs);
          fs.addEventListener("change", () => l.classList.toggle("set", !!fs.value));
          return l;
        })(),
        netField("host name in DHCP", "Host name in DHCP on this network (when set above)",
          [["", General], ["none", "don't send"], ["send", "send"]], () => n.dhcp_hostname || "", (v) => { n.dhcp_hostname = v || undefined; }, { linux: true }),
        netField("MAC address", "MAC address on this network (when set above); applies from the next connection",
          [["", General], ["random", "new each time"], ["stable", "own per network"], ["permanent", "the real one"]], () => n.mac || "", (v) => { n.mac = v || undefined; }, { linux: true }),
        netField("incoming connections", "Incoming connections on this network (when switched on above)",
          [["", "closed"], ["lan", "LAN: allowed ports"], ["open", "open (no filter)"]], () => (n.inbound === "closed" ? "" : n.inbound || ""), (v) => { n.inbound = v || undefined; }, { linux: true })));
  }) : [el("div", { class: "muted" }, "No profiles – e.g. at home everything direct, everywhere else through a tunnel.")]));
}
$("#n-add").addEventListener("click", async () => {
  const now = netNow();
  if (!now.ssid && !now.gateway_mac) return toast("The current network can't be recognised (no Wi-Fi name, router MAC unknown)");
  const name = ((await ask("Name for this network", { input: now.ssid || "home", ok: "Add" })) || "").trim();
  if (!name) return;
  model.network = model.network || [];
  if (model.network.some((n) => n.name === name)) return toast(T("There is a network called {name} already", { name }));
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
  if (!model || !cfgShown() || $("#savebar").classList.contains("dirty")) return;
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
      try { await api("DELETE", "/api/firewall/apps?key=" + encodeURIComponent(r.key)); toast(T("{name} forgotten", { name: r.name })); loadFwApps(); } catch (e) { toast(e.message); }
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


// menuStarts: does a menu entry's Exec line start the program an app selector names
// ("firefox" process name, "exe:/path", "flatpak:<id>"), as appwatch matches it?
// Chromium browsers start through a wrapper script (brave-browser-stable): their process name
const CHROMIUM_COMM = { chrome: ["chrome"], chromium: ["chromium", "chromium-browse"], brave: ["brave"],
  vivaldi: ["vivaldi-bin"], opera: ["opera"], "opera-gx": ["opera"], edge: ["msedge"] };
function menuStarts(exec, sel, chromium) {
  if (chromium && (CHROMIUM_COMM[chromium] || []).includes(sel)) return true;
  let t = (exec || "").match(/"[^"]*"|\S+/g) || [];
  t = t.map((x) => x.replace(/^"|"$/g, ""));
  const base = (x) => x.split("/").pop();
  // an entry The Shunt manages already: "shunt run --via R -- prog …"
  if (t.length && base(t[0]) === "shunt" && t.includes("--")) t = t.slice(t.indexOf("--") + 1);
  if (t[0] === "env" || base(t[0] || "") === "env") t = t.slice(1);
  while (t.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0])) t = t.slice(1);
  if (!t.length) return false;
  if (base(t[0]) === "flatpak" && t[1] === "run") {
    const id = t.slice(2).find((x) => !x.startsWith("-"));
    return sel === "flatpak:" + id;
  }
  if (sel.startsWith("exe:")) return t[0] === sel.slice(4);
  if (sel.startsWith("flatpak:")) return false;
  return base(t[0]) === sel;
}
