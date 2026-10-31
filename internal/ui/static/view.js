"use strict";
// View tab: the level (Simple/Pro/Opsec, see levels.js), the tab to open
// with, the language. Simple hides the fine-tuning; hidden settings keep
// working, and a banner says which of them are in use.

const viewGet = (k) => { try { return localStorage.getItem(k) || ""; } catch (e) { return ""; } };
const viewSet = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } };

// setLevel stores the level and redraws. Switching to or away from Opsec
// goes through the opsec assistant (opsec.js) first: it may change settings,
// and only with the user's consent.
function setLevel(l) {
  if (!levelOK(l)) return;
  lvSet("shunt-level", l);
  applyViewLevel();
}
async function chooseLevel(l) {
  const from = level();
  if (l === from && storedLevel()) return;
  if (l === "opsec" || from === "opsec") {
    if (!(await opsecSwitch(from, l))) return applyViewLevel(); // cancelled: buttons back as they were
  }
  setLevel(l);
}

// the routing card ("Everything else goes", kill switch on Windows): on the
// Configure tab, in Simple (no Configure tab) on the VPN tab
function placeRouting() {
  const sec = $("#sec-routing");
  const page = level() === "simple" ? $("#page-vpn") : $("#page-config");
  if (sec.parentElement !== page) page.prepend(sec);
}

function applyViewLevel() {
  const l = level();
  applyLevel();
  placeRouting();
  for (const b of document.querySelectorAll("#v-level button")) {
    b.classList.toggle("active", b.dataset.l === l);
    b.setAttribute("aria-pressed", String(b.dataset.l === l));
  }
  for (const h of document.querySelectorAll(".lvhelp")) h.hidden = h.dataset.for !== l;
  if ($("#tab-" + curTab).offsetParent === null) setTab("overview");
  if (status) render(); // parts drawn by the scripts (Tor card, banners)
  if (typeof renderChecks === "function" && status) renderChecks(status.findings || []);
  if (model) renderConfig();
  viewChanged();
}

// hiddenInUse lists the settings Simple hides that differ from a fresh install.
function hiddenInUse() {
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
  n((model.network || []).length, "{n} network profile", "{n} network profiles");
  n(model.inbound && model.inbound.enabled ? 1 : 0, "incoming protection on", "incoming protection on");
  n(Object.values(model.tunnel).filter((t) => t.driver === "tor" && t.bridges).length, "{n} Tor tunnel with bridges", "{n} Tor tunnels with bridges");
  return out;
}

function viewChanged() {
  const h = $("#lv-hint");
  const used = level() === "simple" && curTab !== "overview" && curTab !== "view" ? hiddenInUse() : [];
  h.hidden = !used.length;
  if (!used.length) return;
  h.replaceChildren(T("Settings hidden in Simple are in use: {list}. They keep working.", { list: used.join(", ") }),
    el("a", { href: "#", onclick: (e) => { e.preventDefault(); chooseLevel("pro"); } }, "Show them"));
  $("#page-" + curTab).prepend(h);
}

for (const b of document.querySelectorAll("#v-level button")) b.addEventListener("click", () => chooseLevel(b.dataset.l));
$("#v-start").value = viewGet("shunt-start-tab") || "overview";
$("#v-start").addEventListener("change", (e) => viewSet("shunt-start-tab", e.target.value));

// a level carried over from the old Normal/Expert view is stored under its new name
if (storedLevel() && lvGet("shunt-level") !== storedLevel()) lvSet("shunt-level", storedLevel());
applyViewLevel();
{
  // a reload (or a link with #apps) opens the same tab again, otherwise the chosen start tab
  const t = location.hash.replace(/^#\/?/, "") || viewGet("shunt-start-tab");
  if (t) setTab(t);
}
// First start: a fresh install begins in Simple, a config that already uses
// settings Simple hides in Pro.
if (!model) loadConfig().then(() => {
  if (!storedLevel() && model) setLevel(hiddenInUse().length ? "pro" : "simple");
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
