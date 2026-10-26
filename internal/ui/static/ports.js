// "Open ports" on the overview and "DNS blocks per app" on the Apps tab.
let listening = null;

async function loadPorts() {
  try { listening = await api("GET", "/api/listening"); } catch { listening = null; }
  renderPorts();
}

function renderPorts() {
  const sec = $("#sec-ports");
  if (!status || status.platform === "windows") { sec.hidden = true; return; }
  sec.hidden = false;
  const l = listening;
  if (!l) { $("#ports").replaceChildren(el("tr", {}, el("td", { class: "muted" }, "Daemon not reachable."))); return; }
  if (l.error) { $("#ports").replaceChildren(el("tr", {}, el("td", { style: "color:var(--bad)" }, l.error))); return; }
  const all = $("#ports-all").checked;
  const shown = l.ports.filter((p) => all || p.reach !== "localhost");
  const exposed = l.ports.filter((p) => p.exposed && !p.blocked);
  // the heading stays visible when the section is folded: warn there too
  const sum = $("#ports-sum");
  sum.textContent = exposed.length + " reachable from the network · " + l.ports.filter((p) => p.reach === "localhost").length + " only from this machine";
  sum.style.color = exposed.length && !l.network ? "var(--bad)" : "";
  const reach = (p) => p.reach === "localhost" ? el("span", { class: "muted" }, "this machine") :
    p.reach === "all" ? "all interfaces" : (p.ifaces || []).join(", ") || p.addr;
  $("#ports").replaceChildren(...(shown.length ? shown.map((p) => el("tr", {},
    el("td", { class: "mono" }, p.proto + " " + (p.addr.includes(":") ? "[" + p.addr + "]" : p.addr) + ":" + p.port),
    el("td", {}, el("b", {}, p.owner.name || "?"), p.owner.procs && p.owner.procs[0] !== p.owner.name && !p.owner.shared ? el("span", { class: "muted" }, " " + p.owner.procs.join(", ")) : ""),
    el("td", {}, reach(p)),
    el("td", {}, p.blocked ? el("span", { class: "pill ok", title: "The Shunt drops new connections from the network" }, "blocked") :
      p.lan_only ? el("span", { class: "pill warn", title: "only private addresses of this network" }, "LAN only") :
      p.exposed ? el("span", { class: "pill " + (l.network ? "warn" : "bad") }, "network") : "",
      p.tunnel ? el("span", { class: "pill warn" }, "tunnel") : "")))
    : [el("tr", {}, el("td", { class: "muted" }, "Nothing listens beyond this machine."))]));
  const notes = [];
  if (exposed.length && !l.network && !l.inbound) notes.push(el("div", { class: "banner bad" }, "⚠ Unknown network: " + exposed.length + " port(s) can be reached by everyone on it. Switch on “Incoming connections” under Configure → General to block them."));
  if (l.inbound) notes.push(el("div", { class: "muted" }, "Incoming protection: " + l.inbound + (l.network ? " (network “" + l.network + "”)" : " (unknown network)") + ", tunnels closed."));
  if (l.firewalls && l.firewalls.length) notes.push(el("div", { class: "muted" }, "Other firewalls active: " + l.firewalls.join(", ") + " – they may already block some of these."));
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
