"use strict";
// Configure page: edits a copy of the daemon's config; nothing is written
// before the daemon has checked it (same checks as `shuntd check`).

let cfgView = null; // last config from the daemon (raw text, parsed, tunnel info)
let model = null; // working copy being edited
let editIdx = -1; // rule being edited (-1 = new)

const splitList = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
const joinList = (a) => (a || []).join(", ");

function setTab(t) {
  $("#page-overview").hidden = t !== "overview";
  $("#page-config").hidden = t !== "config";
  $("#tab-overview").classList.toggle("active", t === "overview");
  $("#tab-config").classList.toggle("active", t === "config");
  if (t === "config" && !model) loadConfig();
}
$("#tab-overview").addEventListener("click", () => setTab("overview"));
$("#tab-config").addEventListener("click", () => setTab("config"));

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
}

const modelRoutes = () => ["direct", "block", ...Object.keys(model.tunnel).sort().map((n) => "tunnel:" + n)];

function fill(sel, options, value) {
  const s = $(sel);
  s.replaceChildren(...options.map((o) => (Array.isArray(o) ? el("option", { value: o[0] }, o[1]) : el("option", { value: o }, o))));
  s.value = value;
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
    const dnsSel = el("select", { onchange: (e) => { t.dns = e.target.value || undefined; markDirty(); } },
      el("option", { value: "" }, "DNS from its file" + (i.dns && i.dns.length ? " (" + i.dns.join(", ") + ")" : " (none!)")),
      ...ups.map((u) => el("option", { value: u }, u)));
    dnsSel.value = t.dns || "";
    return el("tr", {},
      el("td", {}, routeTag("tunnel:" + n)),
      el("td", { class: "mono" }, (i.endpoint || "–") + "  ", el("span", { class: "muted" }, joinList(i.addresses))),
      el("td", {}, dnsSel),
      el("td", {}, el("button", { class: "iconbtn", title: "delete tunnel", onclick: () => deleteTunnel(n) }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No tunnels yet – import a WireGuard config below."))]));

  $("#c-rules").replaceChildren(...(model.rule.length ? model.rule.map((r, i) => {
    const sel = [];
    if (r.app) sel.push("apps: " + joinList(r.app) + (r.args ? " [" + joinList(r.args) + "]" : ""));
    if (r.domain) sel.push("domains: " + joinList(r.domain));
    if (r.cidr) sel.push("IPs: " + joinList(r.cidr));
    if (r.port) sel.push("ports: " + joinList(r.port));
    if (r.group) sel.push("groups: " + joinList(r.group));
    const move = (d) => { const j = i + d; [model.rule[i], model.rule[j]] = [model.rule[j], model.rule[i]]; markDirty(); renderConfig(); };
    return el("tr", {},
      el("td", { class: "muted" }, i + 1 + "."),
      el("td", {}, el("b", {}, r.name || "(unnamed)"), el("div", {}, ...sel.map((x) => el("span", { class: "chip" }, x)))),
      el("td", {}, routeTag(r.route)),
      el("td", { style: "white-space:nowrap" },
        el("button", { class: "iconbtn", title: "up", onclick: () => i > 0 && move(-1) }, "↑"), " ",
        el("button", { class: "iconbtn", title: "down", onclick: () => i < model.rule.length - 1 && move(1) }, "↓"), " ",
        el("button", { class: "iconbtn", title: "edit", onclick: () => openRule(i) }, "✎"), " ",
        el("button", { class: "iconbtn", title: "delete", onclick: () => { model.rule.splice(i, 1); markDirty(); renderConfig(); } }, "✕")));
  }) : [el("tr", {}, el("td", { class: "muted" }, "No rules – apps follow the route they were started with, everything else the default."))]));
}

$("#c-default").addEventListener("change", (e) => { model.daemon.default_route = e.target.value; markDirty(); });
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
  fill("#r-route", modelRoutes(), r.route);
  $("#r-app").value = joinList(r.app);
  $("#r-args").value = joinList(r.args);
  $("#r-domain").value = joinList(r.domain);
  $("#r-cidr").value = joinList(r.cidr);
  $("#r-port").value = joinList(r.port);
  $("#r-group").value = joinList(r.group);
  $("#r-editor").hidden = false;
  $("#r-name").focus();
}
$("#r-new").addEventListener("click", () => openRule(-1));
$("#r-cancel").addEventListener("click", () => { $("#r-editor").hidden = true; });
$("#r-ok").addEventListener("click", () => {
  const r = { name: $("#r-name").value.trim(), route: $("#r-route").value };
  for (const [k, id] of [["app", "#r-app"], ["args", "#r-args"], ["domain", "#r-domain"], ["cidr", "#r-cidr"], ["port", "#r-port"], ["group", "#r-group"]]) {
    const v = splitList($(id).value);
    if (v.length) r[k] = v;
  }
  if (!r.app && !r.domain && !r.cidr && !r.port && !r.group) return toast("A rule needs at least one of apps, domains, IP ranges, ports or groups");
  if (r.args && !r.app) return toast("Arguments only work together with apps");
  for (const g of r.group || []) model.group[g] = model.group[g] || {};
  if (editIdx >= 0) model.rule[editIdx] = r;
  else model.rule.push(r);
  $("#r-editor").hidden = true;
  markDirty();
  renderConfig();
});

async function checkOrSave(save, body, msgFn) {
  try {
    const res = await api(save ? "PUT" : "POST", save ? "/api/config" : "/api/config/check", body);
    if (!res.ok) { msgFn(res.error, "err"); return false; }
    const w = (res.warnings || []).length ? " Warnings: " + res.warnings.join(" · ") : "";
    msgFn((save ? "Saved and applied." : "Looks good – nothing written yet.") + w, w ? "warn" : "ok");
    return true;
  } catch (e) {
    msgFn(e.message, "err");
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
function takeFile(f) {
  if (!f) return;
  if (f.size > 64 * 1024) return toast("That file is too big for a WireGuard config");
  f.text().then((t) => {
    $("#t-conf").value = t;
    if (!$("#t-name").value) $("#t-name").value = f.name.replace(/\.conf$/, "").toLowerCase().replace(/[^a-z0-9-]/g, "").slice(0, 10);
  });
}
$("#t-file").addEventListener("change", (e) => takeFile(e.target.files[0]));
const drop = $("#t-drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); takeFile(e.dataTransfer.files[0]); });

$("#t-import").addEventListener("click", async () => {
  const name = $("#t-name").value.trim();
  const conf = $("#t-conf").value;
  if (!/^[a-z0-9][a-z0-9-]{0,9}$/.test(name)) return toast("Tunnel name: 1–10 characters a-z 0-9 -");
  if (!conf.includes("[Interface]")) return toast("Paste or drop a WireGuard config first");
  if ($("#savebar").classList.contains("dirty") && !confirm("Importing reloads the config; your unsaved form changes are discarded. Continue?")) return;
  try {
    const res = await api("POST", "/api/tunnels", { name, conf });
    toast("Tunnel " + name + " imported" + ((res.warnings || []).length ? " – " + res.warnings.join(" · ") : ""));
    $("#t-name").value = "";
    $("#t-conf").value = "";
    await loadConfig();
    refresh();
  } catch (e) { toast("Import failed: " + e.message); }
});

async function deleteTunnel(n) {
  if ($("#savebar").classList.contains("dirty")) return toast("Save or discard your other changes first");
  if (!confirm("Delete tunnel " + n + " and its WireGuard file?")) return;
  try {
    await api("DELETE", "/api/tunnels/" + encodeURIComponent(n));
    toast("Tunnel " + n + " deleted");
    await loadConfig();
    refresh();
  } catch (e) { toast(e.message); }
}
