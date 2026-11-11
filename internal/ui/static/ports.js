// "Open ports" on the overview and "DNS blocks per app" on the Apps tab.
let listening = null;

async function loadPorts() {
  try { listening = await api("GET", "/api/listening"); } catch { listening = null; }
  renderPorts();
}

function renderPorts() {
  const sec = $("#sec-ports");
  if (!status) { sec.hidden = true; return; }
  sec.hidden = false;
  if (status.platform === "windows") { // no port list here (nor on Android): say so, and point to the outside check
    $("#ports").replaceChildren(el("tr", {}, el("td", { class: "muted" }, T("This platform gives no list of open ports. Use “Check from outside” in the Defense tab to see what really answers."))));
    $("#ports-sum").textContent = ""; $("#ports-notes").replaceChildren();
    return;
  }
  const l = listening;
  if (!l) { $("#ports").replaceChildren(el("tr", {}, el("td", { class: "muted" }, "Daemon not reachable."))); return; }
  if (l.error) { $("#ports").replaceChildren(el("tr", {}, el("td", { style: "color:var(--bad)" }, l.error))); return; }
  const all = $("#ports-all").checked;
  const ports = l.ports || []; // none listening: the service may send null
  const shown = ports.filter((p) => all || p.reach !== "localhost");
  const exposed = ports.filter((p) => p.exposed && !p.blocked);
  const pub = ports.filter((p) => p.public);
  // the heading stays visible when the section is folded: warn there too
  const sum = $("#ports-sum");
  sum.textContent = T("{n} reachable from the network · {m} only from this machine", { n: exposed.length, m: ports.filter((p) => p.reach === "localhost").length });
  if (pub.length) sum.textContent += " · " + T("{n} reachable from the internet", { n: pub.length });
  sum.style.color = pub.length || (exposed.length && !l.network) ? "var(--bad)" : "";
  const reach = (p) => p.reach === "localhost" ? el("span", { class: "muted" }, "this machine") :
    p.reach === "all" ? "all interfaces" : (p.ifaces || []).join(", ") || p.addr;
  $("#ports").replaceChildren(...(shown.length ? shown.map((p) => el("tr", p.public ? { class: "pubport", style: "color:var(--bad)" } : {},
    el("td", { class: "mono" }, p.proto + " " + (p.addr.includes(":") ? "[" + p.addr + "]" : p.addr) + ":" + p.port),
    el("td", {}, el("b", {}, p.owner.name || "?"), p.owner.procs && p.owner.procs[0] !== p.owner.name && !p.owner.shared ? el("span", { class: "muted" }, " " + p.owner.procs.join(", ")) : ""),
    el("td", {}, reach(p)),
    el("td", {}, p.blocked ? el("span", { class: "pill ok", title: "The Shunt drops new connections from the network" }, "blocked") :
      p.lan_only ? el("span", { class: "pill warn", title: "only private addresses of this network" }, "LAN only") :
      p.public ? el("span", { class: "pill bad", title: T("Listens on every or a public address and nothing stops the internet") }, T("internet")) : "",
      p.exposed && !p.public ? el("span", { class: "pill " + (l.network ? "warn" : "bad") }, "network") : "",
      p.tunnel ? el("span", { class: "pill warn" }, "tunnel") : "")))
    : [el("tr", {}, el("td", { class: "muted" }, "Nothing listens beyond this machine."))]));
  const notes = [];
  if (pub.length) notes.push(el("div", { class: "banner bad", "data-lv": "inbound" }, T("⚠ {n} port(s) can be reached from the internet: this device has a public address or the incoming protection is open. Programs: {names}.", { n: pub.length, names: [...new Set(pub.map((p) => p.owner.name || "?"))].join(", ") })));
  else if ((l.public_v4 || l.public_v6) && exposed.length === 0 && l.inbound) notes.push(el("div", { class: "muted" }, T("This device has a public address; the incoming protection blocks the ports above.")));
  if (exposed.length && !l.network && !l.inbound) notes.push(el("div", { class: "banner bad", "data-lv": "inbound" }, T("⚠ Unknown network: {n} port(s) can be reached by everyone on it. Switch on “Incoming connections” under Configure → Privacy and protection to block them.", { n: exposed.length })));
  if (l.inbound) notes.push(el("div", { class: "muted", "data-lv": "inbound" }, (l.network ? T("Incoming protection: {mode} (network “{network}”), tunnels closed.", { mode: l.inbound, network: l.network }) : T("Incoming protection: {mode} (unknown network), tunnels closed.", { mode: l.inbound }))));
  if (l.firewalls && l.firewalls.length) notes.push(el("div", { class: "muted" }, T("Other firewalls active: {list} – they may already block some of these.", { list: l.firewalls.join(", ") })));
  $("#ports-notes").replaceChildren(...notes);
}

function renderAppBlocks() {
  const st = status && status.dns_filter && status.dns_filter.stats;
  const by = (st && st.by_app) || {};
  const rows = Object.entries(by).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const max = rows.length ? rows[0][1] : 1;
  $("#appblocks").replaceChildren(...(rows.length ? rows.map(([n, c]) => el("tr", {},
    el("td", {}, n || el("span", { class: "muted" }, "unknown")),
    el("td", { style: "width:50%" }, el("div", { class: "bar", style: "width:" + Math.max(2, Math.round(100 * c / max)) + "%" })),
    el("td", { class: "mono", style: "text-align:right" }, c.toLocaleString())))
    : [el("tr", {}, el("td", { class: "muted" }, st ? "Nothing blocked yet." : "The DNS filter is off."))]));
}

$("#ports-all").addEventListener("change", renderPorts);
setInterval(() => { if (!document.hidden && !$("#page-ports").hidden) loadPorts(); }, 10000);
setInterval(() => { if (!document.hidden && !$("#page-apps").hidden) renderAppBlocks(); }, 3000);
setTimeout(() => { loadPorts(); renderAppBlocks(); }, 500);
