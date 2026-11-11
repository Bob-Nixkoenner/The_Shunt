"use strict";
// Evidence ("Beweise", Defense tab): a local, tamper-evident record of
// attacks, cases to keep, export for the police or a lawyer, and the abuse
// contact of an address. Talks to /api/defense/evidence*. Nothing here sends
// anything by itself: export and abuse lookup run only on a button press.

let evSt = null; // last GET /api/defense/evidence

function evSize(b) {
  b = b | 0;
  return b < 1024 ? b + " B" : b < 1048576 ? (b / 1024).toFixed(0) + " KB" : (b / 1048576).toFixed(1) + " MB";
}

function evConfig() {
  const cfg = JSON.parse(JSON.stringify((defSt && defSt.config) || {}));
  cfg.evidence = Object.assign({}, cfg.evidence || {});
  return cfg;
}

function renderEvidence() {
  const sec = $("#sec-evidence");
  if (!sec) return;
  sec.hidden = !defSt;
  if (!defSt || !evSt) return;
  const on = !!evSt.enabled, st = evSt.status || {};
  const pill = $("#ev-state");
  pill.className = "pill " + (!on ? "" : st.chain_ok ? "ok" : "bad");
  pill.textContent = !on ? T("Off") : st.chain_ok ? T("Chain intact") + " ✓" : T("Chain broken") + " ✗";
  $("#ev-on").checked = on; $("#ev-on").disabled = !defSt.enabled && !on;
  $("#ev-cap").checked = !!evSt.capture; $("#ev-cap").disabled = !on || !evSt.capture_supported;
  $("#ev-cap-note").textContent = evSt.capture_supported ? "" : T("Not available on this system: only the event log and the export.");
  if (document.activeElement !== $("#ev-days")) $("#ev-days").value = (evSt.config && evSt.config.retention_days) || 90;
  const lines = [];
  if (!on && !(st.lines > 0)) lines.push([T("Evidence is off: nothing is written."), "muted"]);
  else {
    lines.push([T("{lines} log lines in {files} files, {size}", { lines: st.lines | 0, files: st.files | 0, size: evSize(st.bytes) }), "muted"]);
    if (st.pcap_bytes) lines.push([T("Capture files: {size}", { size: evSize(st.pcap_bytes) }), "muted"]);
    if (!st.chain_ok && st.first_bad) lines.push([T("First broken line: {where}", { where: st.first_bad }), "bad"]);
    if (!on) lines.push([T("Evidence is off: old data is kept until you delete it or the retention time ends."), "muted"]);
  }
  $("#ev-status").replaceChildren(...lines.map(([l, c]) => el("div", { class: c }, l)));
  const cases = evSt.cases || [];
  $("#ev-cases").replaceChildren(...(cases.length ? cases.map((c) => el("div", { class: "row", style: "flex-wrap:wrap;gap:6px 10px;margin:4px 0" },
    el("b", {}, c.name), c.src ? el("button", { class: "srclink mono", type: "button", title: T("Show everything from this source"), onclick: () => defOpenSource(c.src) }, c.src) : "",
    el("span", { class: "pill " + (c.pinned ? "ok" : "") }, c.pinned ? T("kept") : T("not kept")),
    el("span", { class: "spacer" }),
    el("button", { onclick: () => evExport({ case_id: c.id }) }, T("Export")),
    el("button", { onclick: () => evCase({ action: c.pinned ? "unpin" : "pin", id: c.id }) }, c.pinned ? T("Stop keeping") : T("Keep")),
    el("button", { onclick: async () => { if (await ask(T("Delete this case? The log lines stay until the retention time ends."), { ok: T("Delete") })) evCase({ action: "delete", id: c.id }); } }, T("Delete"))))
    : [el("div", { class: "muted" }, T("No cases yet. Open an address in the event list and press “Save as case”."))]));
}

async function loadEvidence() {
  try { evSt = await api("GET", "/api/defense/evidence"); } catch { evSt = null; }
  renderEvidence();
}

async function evCase(body) {
  try { await api("POST", "/api/defense/evidence/case", body); } catch (e) { toast(e.message); }
  await loadEvidence();
}

async function evSetConfig(mut) {
  const cfg = evConfig();
  mut(cfg.evidence);
  await defSend(cfg);
  await loadEvidence();
}

$("#ev-on").addEventListener("change", async () => {
  const want = $("#ev-on").checked;
  if (want && !(await ask(T("Keep a local log of attacks? It holds the addresses of other people (personal data) on this computer only, for {days} days, and nothing is sent anywhere without you. You can delete it at any time.", { days: (evSt && evSt.config && evSt.config.retention_days) || 90 }), { ok: T("Turn on") }))) { $("#ev-on").checked = false; return; }
  evSetConfig((e) => { e.enabled = want; });
});
$("#ev-cap").addEventListener("change", async () => {
  const want = $("#ev-cap").checked;
  if (want && !(await ask(T("Record unsolicited incoming packets (first packet, 128 bytes) and network control frames around an attack? Normal traffic is never recorded. Packets stay in memory and reach the disk only when an attack is seen."), { ok: T("Turn on") }))) { $("#ev-cap").checked = false; return; }
  evSetConfig((e) => { e.capture = want; });
});
$("#ev-save").addEventListener("click", () => {
  const n = parseInt($("#ev-days").value, 10);
  if (!(n >= 1 && n <= 3650)) { toast(T("Days: a number from 1 to 3650.")); return; }
  evSetConfig((e) => { e.retention_days = n; });
});
async function evPurge(all) {
  const msg = all
    ? T("Delete ALL evidence, also the cases you keep? This cannot be undone.")
    : T("Delete all evidence except the cases you keep? This cannot be undone.");
  if (!(await ask(msg, { ok: T("Delete") }))) return;
  try { await api("POST", "/api/defense/evidence/purge", { all }); toast(T("Deleted.")); } catch (e) { toast(e.message); }
  loadEvidence();
}
$("#ev-purge").addEventListener("click", () => evPurge(false));
$("#ev-purge-all").addEventListener("click", () => evPurge(true));

// export: the service writes the archive, the page saves a copy as a download
async function evExport(body) {
  toast(T("Making the archive …"));
  try {
    const r = await api("POST", "/api/defense/evidence/export", body);
    const name = String(r.path || "").split(/[\\/]/).pop();
    const d = await api("GET", "/api/defense/evidence/download?name=" + encodeURIComponent(name));
    const bin = atob(d.data || ""), bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const a = el("a", { href: URL.createObjectURL(new Blob([bytes], { type: "application/gzip" })), download: d.name });
    document.body.appendChild(a); a.click(); a.remove();
    toast(T("Exported {lines} log lines, {packets} packets. Check it with: shunt evidence verify {name}", { lines: r.lines | 0, packets: r.packets | 0, name: d.name }));
  } catch (e) { toast(e.message); }
}

// the box in the source detail dialog
function evSourceBox(src) {
  const out = el("div", { class: "hint" });
  const have = ((evSt && evSt.cases) || []).find((c) => c.src === src);
  const row = el("div", { class: "row", style: "flex-wrap:wrap;gap:6px" },
    have ? el("span", { class: "pill ok" }, T("Case: {name}", { name: have.name })) : el("button", { onclick: async () => {
      try { await api("POST", "/api/defense/evidence/case", { action: "create", name: src, src }); toast(T("Saved as a case.")); } catch (e) { toast(e.message); }
      await loadEvidence(); defOpenSource(src);
    } }, T("Save as case")),
    el("button", { onclick: () => evExport(have ? { case_id: have.id } : { src }) }, T("Export case")),
    el("button", { onclick: async () => {
      out.textContent = T("Looking up …");
      try {
        const r = await api("GET", "/api/defense/evidence/abuse?src=" + encodeURIComponent(src));
        const l = [];
        if (r.operator) l.push(T("Operator: {x}", { x: r.operator }));
        if (r.country) l.push(T("Country: {x}", { x: r.country }));
        if (r.network) l.push(T("Network: {x}", { x: r.network }));
        l.push(r.abuse_email ? T("Abuse e-mail: {x}", { x: r.abuse_email }) : T("No abuse e-mail found."));
        if (r.registry) l.push(T("Registry: {x}", { x: r.registry }) + (r.cached ? " (" + T("saved answer") + ")" : ""));
        out.replaceChildren(...l.map((x) => el("div", {}, x)));
      } catch (e) { out.textContent = e.message; }
    } }, T("Find abuse contact")));
  const note = el("div", { class: "muted" }, T("Nothing is sent to this address and it is never scanned. The lookup asks the registry that owns the address range, only now."));
  return el("div", { class: "evbox" }, el("div", { class: "muted" }, T("Evidence")), row, out, note);
}

setInterval(() => { if (!document.hidden && typeof level === "function" && level() === "opsec" && defSt) loadEvidence(); }, 10000);
setTimeout(() => { if (typeof level === "function" && level() === "opsec") loadEvidence(); }, 1000);
