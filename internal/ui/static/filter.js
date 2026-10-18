"use strict";
// DNS filter tab: blocklists per level, allowlists, what got blocked.
// Edits the same config model as the Configure page (same save bar).

// RPiList lists (https://github.com/RPiList/specials/blob/master/Blocklisten.md),
// grouped like on the RPiList page; approximate size in MB.
const RPILIST_GROUPS = [
  ["Ads", [
    ["easylist", "ads and tracking – the starter list", 3.8],
    ["spam.mails", "spam senders", 4.4],
  ]],
  ["Malware", [
    ["malware", "malware", 14.9],
  ]],
  ["Phishing and scam", [
    ["Phishing-Angriffe", "phishing", 4.2],
    ["crypto", "crypto scams and mining", 2.7],
    ["Fake-Science", "fake science", 0],
    ["Corona-Blocklist", "corona fakes", 7.5],
  ]],
  ["Fake shops and subscription traps", [
    ["notserious", "dubious shops and sites", 2.2],
    ["Streaming", "streaming sites", 0.5],
  ]],
  ["Domain squatting", [
    ["DomainSquatting1", "domain squatting 1", 32.9],
    ["DomainSquatting2", "domain squatting 2", 18.8],
    ["DomainSquatting3", "domain squatting 3", 0],
    ["DomainSquatting4", "domain squatting 4", 0],
  ]],
  ["Tracking and telemetry", [
    ["Win10Telemetry", "Windows telemetry", 0],
    ["MS-Office-Telemetry", "MS Office telemetry", 0],
  ]],
  ["Youth protection", [
    ["child-protection", "child protection", 5.9],
    ["gambling", "gambling", 40],
    ["DatingSites", "dating sites", 7.3],
    ["proxies", "proxy and anonymiser services", 3.6],
    ...[1, 2, 3, 4, 5, 6].map((i) => ["pornblock" + i, "adult content " + i, i === 6 ? 7.2 : 33]),
  ]],
  ["Other", [
    ["SupportingRussia", "companies supporting Russia", 0],
    ["Overblock", "aggressive, breaks sites", 0],
  ]],
];
// Offered lists: Windows' own telemetry lists only on Windows. (The RPiList phone and TV lists –
// Samsung, LG – are not offered at all: nothing on a PC asks for them. A list that is in the
// config but not offered shows up under "Other" and can be removed there.)
const WIN_ONLY = new Set(["Win10Telemetry", "MS-Office-Telemetry"]);
function offeredGroups() {
  const win = !!status && status.platform === "windows";
  return RPILIST_GROUPS.map(([cat, list]) => [cat, list.filter(([n]) => win || !WIN_ONLY.has(n))]).filter(([, list]) => list.length);
}
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

  const offered = offeredGroups();
  const known = new Set(offered.flatMap(([, l]) => l).map((x) => x[0]));
  const custom = [...new Set(LEVELS.flatMap((l) => f[l] || []))].filter((n) => !known.has(n));
  const groups = offered.map(([cat, list]) => cat === "Other" ? [cat, [...list, ...custom.map((u) => [u, "other list", null])]] : [cat, list]);
  const rows = groups.flatMap(([cat, list]) => [cat, ...list]);
  $("#f-lists").replaceChildren(...rows.map((row) => {
    if (typeof row === "string") return el("tr", { class: "grouprow" }, el("th", { colspan: 6, style: "text-align:left;padding-top:14px" }, row));
    const [name, desc, mb] = row;
    const cells = LEVELS.map((l, i) => el("td", {}, el("input", {
      type: "checkbox", title: l + (used.has(l) ? "" : " – level not in use, nothing is downloaded"),
      // a level has the lists of the levels below it
      checked: LEVELS.slice(0, i + 1).some((k) => (f[k] || []).includes(name)) ? "" : null,
      onchange: (e) => {
        const m = fm();
        // a level includes the ones below it, so the list is stored once, in the lowest level
        // that has it; unticking a level takes it out of this one and the lower ones
        for (const [j, k] of LEVELS.entries()) {
          if (e.target.checked && j !== i) m[k] = m[k].filter((x) => x !== name);
          if (!e.target.checked && j <= i) m[k] = m[k].filter((x) => x !== name);
        }
        if (e.target.checked) m[LEVELS[i]] = [...m[LEVELS[i]], name];
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
  if (document.activeElement !== $("#f-alists")) $("#f-alists").value = (f.allow_lists || []).join("\n");
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
// every https:// URL in a pasted text (Pi-hole adlist export, Markdown, a
// copied block); returns the URLs and how many other lines were left out
function pickUrls(text) {
  const urls = [];
  let skipped = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/https:\/\/[^\s<>"'`,)\]]+/);
    if (m && /^https:\/\/[^\s/]+\/\S*$/.test(m[0])) urls.push(m[0]);
    else skipped++;
  }
  return { urls: [...new Set(urls)], skipped };
}
$("#f-add").addEventListener("click", () => {
  const { urls, skipped } = pickUrls($("#f-paste").value);
  if (!urls.length) return toast("No https:// URL found");
  const lvl = $("#f-paste-level").value;
  const m = fm();
  const have = new Set(LEVELS.flatMap((l) => m[l]));
  let added = 0;
  const to = LEVELS.indexOf(lvl);
  for (const u of urls) {
    // stored once; a list that a lower level has already needs nothing
    if (LEVELS.slice(0, to + 1).some((k) => m[k].includes(u))) continue;
    for (const k of LEVELS.slice(to + 1)) m[k] = m[k].filter((x) => x !== u);
    m[lvl].push(u);
    if (!have.has(u)) added++;
  }
  $("#f-paste").value = "";
  $("#f-paste-info").textContent = urls.length + " lists read, " + added + " new" + (skipped ? ", " + skipped + " lines ignored (not https://)" : "") + " – put into “" + lvl + "” (the levels above include it)";
  markDirty();
  renderFilter();
});
// the same list under its short name and its full URL counts once
const FILTER_SRC = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/";
const listKey = (n) => ((n.startsWith("https://") ? n : (fview().source || FILTER_SRC).replace(/\/$/, "") + "/" + encodeURIComponent(n)).replace(/\/$/, "")).toLowerCase();
$("#f-tidy").addEventListener("click", () => {
  const m = fm();
  const seen = new Set();
  let removed = 0;
  for (const l of LEVELS) {
    m[l] = m[l].filter((n) => { const k = listKey(n); if (seen.has(k)) { removed++; return false; } seen.add(k); return true; });
  }
  $("#f-paste-info").textContent = removed ? removed + " redundant entries removed" : "nothing to tidy";
  if (removed) { markDirty(); renderFilter(); }
});
$("#f-alists").addEventListener("input", (e) => {
  const m = fm();
  m.allow_lists = pickUrls(e.target.value).urls;
  if (!m.allow_lists.length) delete m.allow_lists;
  markDirty();
});
$("#f-refresh").addEventListener("click", async () => {
  try { await api("POST", "/api/dnsfilter/refresh"); toast("Downloading the lists again…"); } catch (e) { toast(e.message); }
});
setInterval(() => { if (!$("#page-config").hidden && model) renderFilterStatus(); }, 3000);
