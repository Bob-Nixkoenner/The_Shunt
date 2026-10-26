"use strict";
// View tab: Normal/Expert, the tab to open with. Normal hides the fine-tuning
// (elements marked .expert); hidden settings keep working, and a banner says
// how many of them are in use.

const viewGet = (k) => { try { return localStorage.getItem(k) || ""; } catch (e) { return ""; } };
const viewSet = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } };

function viewMode() { return viewGet("shunt-view-mode"); } // "" = not decided yet: show everything
function setViewMode(m) {
  viewSet("shunt-view-mode", m);
  applyViewMode();
}
function applyViewMode() {
  const m = viewMode();
  document.body.classList.toggle("normal", m === "normal");
  for (const b of document.querySelectorAll("#v-mode button")) b.classList.toggle("active", b.dataset.m === (m || "expert"));
  if (curTab === "ports" && m === "normal") setTab("overview");
  viewChanged();
}

// expertInUse lists the settings Normal hides that differ from a fresh install.
function expertInUse() {
  if (!model) return [];
  const out = [];
  const n = (k, one, many) => { if (k) out.push(Tn(k, one, many)); };
  n(model.rule.length, "{n} rule", "{n} rules");
  n(Object.keys(model.dns.upstream).length, "{n} own DNS server", "{n} own DNS servers");
  n(Object.values(model.tunnel).filter((t) => t.via).length, "{n} multi-hop tunnel", "{n} multi-hop tunnels");
  n((model.dns.allow_doh ? 1 : 0) + (model.dns.allow_dot ? 1 : 0), "{n} encrypted DNS allowed", "{n} encrypted DNS kinds allowed");
  n(model.daemon.dhcp_hostname ? 1 : 0, "{n} host name setting", "{n} host name settings");
  n(model.daemon.mac ? 1 : 0, "{n} MAC setting", "{n} MAC settings");
  n(apps.filter((a) => a.clone).length, "{n} launcher", "{n} launchers");
  return out;
}

function viewChanged() {
  const h = $("#expert-hint");
  const used = viewMode() === "normal" && curTab !== "overview" ? expertInUse() : [];
  h.hidden = !used.length;
  if (!used.length) return;
  h.replaceChildren(T("Expert settings in use: {list}. Hidden in Normal view, they keep working.", { list: used.join(", ") }),
    el("a", { href: "#", onclick: (e) => { e.preventDefault(); setViewMode("expert"); } }, "Show them"));
  $("#page-" + curTab).prepend(h);
}

for (const b of document.querySelectorAll("#v-mode button")) b.addEventListener("click", () => setViewMode(b.dataset.m));
$("#v-start").value = viewGet("shunt-start-tab") || "overview";
$("#v-start").addEventListener("change", (e) => viewSet("shunt-start-tab", e.target.value));

applyViewMode();
{
  // a reload (or a link with #apps) opens the same tab again, otherwise the chosen start tab
  const t = location.hash.replace(/^#\/?/, "") || viewGet("shunt-start-tab");
  if (t) setTab(t);
}
// First start of this version: a fresh install begins in Normal, a config
// that already uses expert settings in Expert.
if (!model) loadConfig().then(() => {
  if (!viewMode() && model) setViewMode(expertInUse().length ? "expert" : "normal");
  viewChanged();
});

// Language: automatic (the system's), or one of the languages on offer. The
// choice goes to the ui-state file, where the window, tray and CLI read it too.
(() => {
  const sel = $("#v-lang");
  const name = (code) => (i18n.langs.find((l) => l.code === code) || { name: "English" }).name;
  sel.replaceChildren(el("option", { value: "" }, T("Automatic ({language})", { language: name(i18n.auto) })),
    ...i18n.langs.map((l) => el("option", { value: l.code }, l.name)));
  sel.value = i18n.choice;
  sel.addEventListener("change", () => {
    try { if (sel.value) localStorage.setItem("shunt-lang", sel.value); else localStorage.removeItem("shunt-lang"); } catch (e) { /* private window */ }
    setTimeout(() => location.reload(), 900); // after state.js has sent it to the machine
  });
})();
