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
  // packet capture exists only on Linux: elsewhere the box is not shown at all
  $("#ev-cap").closest("label").hidden = !evSt.capture_supported;
  $("#ev-cap-note").textContent = "";
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
// evExport asks for the network first: only its lines go into the archive,
// so no other place is given away by accident.
async function evExport(body) {
  const box = $("#ev-exp-box"), host = $("#ev-exp");
  let nets = [];
  try { nets = (await api("GET", "/api/defense/evidence/networks")).networks || []; } catch (e) { toast(e.message); return; }
  if (!nets.length) { toast(T("No evidence has been written yet.")); return; }
  const day = (s) => String(s || "").slice(0, 10);
  const classText = (c) => (typeof defClassText === "function" && defClassText()[c]) || c || "";
  const sel = el("select", {}, el("option", { value: "" }, T("Choose a network …")),
    ...nets.map((n) => el("option", { value: n.id }, n.id === "unknown"
      ? T("Earlier lines, network not known ({lines} lines)", { lines: n.lines })
      : T("Network {n}: {class}, last {day}, {lines} lines", { n: n.id, class: classText(n.class), day: day(n.last_utc), lines: n.lines }))));
  const anon = el("input", { type: "checkbox" });
  const list = el("div", { class: "hint" }, T("Choose a network to see what the package will hold."));
  const go = el("button", { class: "primary", disabled: true }, T("Export"));
  const close = () => { host.hidden = true; };
  const preview = async () => {
    go.disabled = true;
    if (!sel.value) { list.replaceChildren(T("Choose a network to see what the package will hold.")); return; }
    list.textContent = T("Looking up …");
    try {
      const p = await api("POST", "/api/defense/evidence/export", Object.assign({}, body, { net: sel.value, anonymize: anon.checked, preview: true }));
      const li = [
        T("{lines} log lines from {a} to {b}, only from the network you chose", { lines: p.lines | 0, a: day(p.first_utc), b: day(p.last_utc) }),
        T("{n} source addresses (the other side; they are the evidence)", { n: p.sources | 0 }),
        (p.chain_only | 0) ? T("{n} other lines only as hashes, no content (they prove the chain is unbroken)", { n: p.chain_only | 0 }) : "",
        (p.packets | 0) ? T("Packet capture with {n} packets (may hold hardware addresses of your computer)", { n: p.packets | 0 }) : (anon.checked ? T("No packet capture (left out on purpose)") : T("No packet capture")),
        anon.checked ? T("No program, system or build details in the manifest") : T("Program version, system type and build in the manifest"),
        T("No name or hardware address of any network; no data of other networks"),
      ].filter(Boolean);
      list.replaceChildren(el("div", { style: "margin-bottom:4px" }, T("The package will hold:")), el("ul", {}, ...li.map((t) => el("li", {}, t))),
        el("div", { class: "muted mono", style: "margin-top:6px" }, (p.files || []).join(", ")));
      go.disabled = false;
    } catch (e) { list.textContent = e.message; }
  };
  sel.onchange = preview; anon.onchange = preview;
  go.onclick = () => { close(); evExportRun(Object.assign({}, body, { net: sel.value, anonymize: anon.checked })); };
  box.replaceChildren(
    el("div", { style: "font-weight:700" }, T("Export evidence")),
    el("label", { class: "d" }, T("Network to export"), el("div", {}, sel)),
    el("label", { class: "row d", style: "gap:6px" }, anon, T("Make my own device details anonymous (no capture, no program or system details)")),
    list,
    el("div", { class: "row", style: "justify-content:flex-end" }, el("button", { onclick: close }, T("Cancel")), go));
  host.hidden = false;
}

async function evExportRun(body) {
  toast(T("Making the archive …"));
  try {
    const r = await api("POST", "/api/defense/evidence/export", body);
    const name = String(r.path || "").split(/[\\/]/).pop();
    // the desktop window cannot take a browser download: the app saves the file itself
    const sv = await api("POST", "/api/defense/evidence/save", { name });
    if (sv.cancelled) { toast(T("Not saved: the archive stays in the case folder of the service.")); return; }
    const box = $("#ev-exp-box"), host = $("#ev-exp");
    box.replaceChildren(
      el("div", { style: "font-weight:700" }, T("Evidence saved")),
      el("div", { class: "d" }, T("{lines} log lines, {packets} packets.", { lines: r.lines | 0, packets: r.packets | 0 })),
      el("div", { class: "mono", style: "margin:6px 0;word-break:break-all" }, sv.path),
      el("div", { class: "d" }, T("Check it with: shunt evidence verify {name}", { name: String(sv.path).split(/[\\/]/).pop() })),
      el("div", { class: "row", style: "justify-content:flex-end" }, el("button", { class: "primary", onclick: () => { host.hidden = true; } }, T("OK"))));
    host.hidden = false;
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
