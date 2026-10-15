"use strict";
// DNS filter tab: blocklists per level, allowlist, what got blocked.
// Edits the same config model as the Configure page (same save bar).

// RPiList lists (https://github.com/RPiList/specials/tree/master/Blocklisten),
// approximate size in MB.
const RPILIST = [
  ["easylist", "ads and tracking – the starter list", 3.8],
  ["Phishing-Angriffe", "phishing", 4.2],
  ["malware", "malware", 14.9],
  ["notserious", "dubious shops and sites", 2.2],
  ["Fake-Science", "fake science", 0],
  ["crypto", "crypto scams and mining", 2.7],
  ["spam.mails", "spam senders", 4.4],
  ["proxies", "proxy and anonymiser services", 3.6],
  ["Win10Telemetry", "Windows telemetry", 0],
  ["MS-Office-Telemetry", "MS Office telemetry", 0],
  ["samsung", "Samsung telemetry", 0],
  ["lg-tv", "LG TV telemetry", 0],
  ["Streaming", "streaming sites", 0.5],
  ["SupportingRussia", "companies supporting Russia", 0],
  ["Corona-Blocklist", "corona fakes", 7.5],
  ["DatingSites", "dating sites", 7.3],
  ["gambling", "gambling", 40],
  ["child-protection", "child protection", 5.9],
  ["DomainSquatting1", "domain squatting 1", 32.9],
  ["DomainSquatting2", "domain squatting 2", 18.8],
  ["DomainSquatting3", "domain squatting 3", 0],
  ["DomainSquatting4", "domain squatting 4", 0],
  ["Overblock", "aggressive, breaks sites", 0],
  ...[1, 2, 3, 4, 5, 6].map((i) => ["pornblock" + i, "adult content " + i, i === 6 ? 7.2 : 33]),
];
const LEVELS = ["low", "normal", "paranoid"];

// the working copy's [dns_filter], created from the settings in effect
function fm() {
  if (!model.dns_filter) model.dns_filter = structuredClone(cfgView.dns_filter);
  for (const l of LEVELS) model.dns_filter[l] = model.dns_filter[l] || [];
  return model.dns_filter;
}
// read-only view (does not create the section)
const fview = () => model.dns_filter || cfgView.dns_filter || {};

function usedLevels() {
  const used = new Set([fview().default || "normal"]);
  for (const t of Object.values(model.tunnel || {})) used.add(t.dns_filter);
  for (const n of model.network || []) used.add(n.dns_filter);
  for (const r of model.rule || []) used.add(r.dns_filter);
  return used;
}

function renderFilter() {
  if (!model || !cfgView) return;
  const f = fview();
  const used = usedLevels();
  fill("#f-default", [["off", "off"], ...LEVELS.map((l) => [l, l + (used.has(l) || l === (f.default || "normal") ? "" : " (unused)")])], f.default || "normal");

  const known = new Set(RPILIST.map((x) => x[0]));
  const custom = [...new Set(LEVELS.flatMap((l) => f[l] || []))].filter((n) => !known.has(n));
  const rows = [...RPILIST, ...custom.map((u) => [u, "own list", null])];
  $("#f-lists").replaceChildren(...rows.map(([name, desc, mb]) => {
    const cells = LEVELS.map((l) => el("td", {}, el("input", {
      type: "checkbox", title: l + (used.has(l) ? "" : " – level not in use, nothing is downloaded"),
      checked: (f[l] || []).includes(name) ? "" : null,
      onchange: (e) => {
        const m = fm();
        m[l] = e.target.checked ? [...m[l], name] : m[l].filter((x) => x !== name);
        markDirty();
        renderFilter();
      },
    })));
    return el("tr", {},
      el("td", { class: name.startsWith("https://") ? "mono" : "" }, el("b", {}, name)),
      el("td", { class: "muted" }, desc + (mb ? " · " + mb + " MB" : ""), mb >= 30 ? el("span", { style: "color:var(--warn)" }, " – big") : ""),
      ...cells,
      el("td", {}, mb === null ? el("button", { class: "iconbtn", title: "remove", onclick: () => {
        const m = fm();
        for (const l of LEVELS) m[l] = m[l].filter((x) => x !== name);
        markDirty();
        renderFilter();
      } }, "✕") : ""));
  }));
  if (document.activeElement !== $("#f-allow")) $("#f-allow").value = (f.allow || []).join("\n");
  renderFilterStatus();
}

function ago(t) {
  if (!t || String(t).startsWith("0001")) return "never"; // Go's zero time
  const s = (Date.now() - new Date(t)) / 1000;
  if (s < 10) return "just now";
  if (s < 90) return Math.round(s) + " s ago";
  if (s < 5400) return Math.round(s / 60) + " min ago";
  if (s < 129600) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " days ago";
}

// the parts that come from the daemon's status
function renderFilterStatus() {
  const fs = status && status.dns_filter;
  if (!fs) {
    $("#f-now").replaceChildren(el("span", { class: "muted" }, status ? "DNS routing is off – the filter needs it." : "Daemon not reachable."));
    $("#f-stats").textContent = "";
    $("#f-loaded").replaceChildren();
    $("#f-recent").replaceChildren();
    return;
  }
  const lvl = (l) => el("span", { class: "chip" }, l || "off");
  $("#f-now").replaceChildren(el("div", { class: "muted", style: "margin-bottom:4px" }, "In effect now" + (status.network ? " (network “" + status.network + "”)" : "") + ":"),
    el("table", {}, el("tbody", {},
      ...Object.entries(fs.routes).map(([r, l]) => el("tr", {}, el("td", {}, routeTag(r)), el("td", {}, lvl(l)))),
      ...Object.entries(fs.rules || {}).map(([r, l]) => el("tr", {}, el("td", {}, "rule ", el("b", {}, r)), el("td", {}, lvl(l)))))));
  const st = fs.stats || {};
  const by = Object.entries(st.by_level || {}).map(([l, n]) => l + " " + n).join(" · ");
  $("#f-stats").textContent = (st.blocked || 0) + " queries blocked since the service started" + (by ? " (" + by + ")" : "");
  const lists = fs.lists || [];
  $("#f-loaded").replaceChildren(...(lists.length ? lists.map((l) => el("tr", {},
    el("td", {}, el("b", {}, l.name.replace(/^https:\/\//, "")), el("div", { class: "muted" }, (l.levels || []).join(", "))),
    el("td", {}, l.entries ? l.entries.toLocaleString() + " names" : el("span", { class: "muted" }, l.error ? "not loaded" : "loading…")),
    el("td", { class: "muted" }, "updated " + ago(l.updated)),
    el("td", { style: "color:var(--bad)" }, l.error || ""))) :
    [el("tr", {}, el("td", { class: "muted" }, "No list in use."))]));
  const recent = st.recent || [];
  $("#f-recent").replaceChildren(...(recent.length ? recent.map((b) => el("tr", {},
    el("td", { class: "mono" }, b.name),
    el("td", { class: "muted" }, b.level + " · " + b.list + " · " + b.route + " · " + ago(b.time)),
    el("td", {}, el("button", { title: "never block this name", onclick: () => allow(b.name) }, "Allow")))) :
    [el("tr", {}, el("td", { class: "muted" }, "Nothing blocked yet."))]));
}

function allow(name) {
  const m = fm();
  m.allow = m.allow || [];
  if (!m.allow.includes(name)) m.allow.push(name);
  markDirty();
  renderFilter();
  toast(name + " allowed – press “Save & apply”");
}

$("#f-default").addEventListener("change", (e) => { fm().default = e.target.value; markDirty(); renderFilter(); });
$("#f-allow").addEventListener("input", (e) => {
  const m = fm();
  m.allow = e.target.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  if (!m.allow.length) delete m.allow;
  markDirty();
});
$("#f-add").addEventListener("click", () => {
  const u = $("#f-custom").value.trim();
  if (!/^https:\/\/[^\s/]+\/\S*$/.test(u)) return toast("An https:// URL, please");
  const m = fm();
  if (!LEVELS.some((l) => m[l].includes(u))) m.paranoid.push(u);
  $("#f-custom").value = "";
  markDirty();
  renderFilter();
  toast("Added to paranoid – tick the other levels if you want it there too");
});
$("#f-refresh").addEventListener("click", async () => {
  try { await api("POST", "/api/dnsfilter/refresh"); toast("Downloading the lists again…"); } catch (e) { toast(e.message); }
});
setInterval(() => { if (!$("#page-config").hidden && model) renderFilterStatus(); }, 3000);
