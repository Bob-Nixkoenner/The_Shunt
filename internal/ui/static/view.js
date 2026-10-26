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
  const n = (k, one, many) => { if (k) out.push(k + " " + (k === 1 ? one : many)); };
  n(model.rule.length, "rule", "rules");
  n(Object.keys(model.dns.upstream).length, "own DNS server", "own DNS servers");
  n(Object.values(model.tunnel).filter((t) => t.via).length, "multi-hop tunnel", "multi-hop tunnels");
  n((model.dns.allow_doh ? 1 : 0) + (model.dns.allow_dot ? 1 : 0), "encrypted DNS allowed", "encrypted DNS kinds allowed");
  n(model.daemon.dhcp_hostname ? 1 : 0, "host name setting", "host name settings");
  n(model.daemon.mac ? 1 : 0, "MAC setting", "MAC settings");
  n(apps.filter((a) => a.clone).length, "launcher", "launchers");
  return out;
}

function viewChanged() {
  const h = $("#expert-hint");
  const used = viewMode() === "normal" && curTab !== "overview" ? expertInUse() : [];
  h.hidden = !used.length;
  if (!used.length) return;
  h.replaceChildren("Expert settings in use: " + used.join(", ") + ". Hidden in Normal view, they keep working.",
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
