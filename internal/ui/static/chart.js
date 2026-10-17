"use strict";
// Traffic and DNS-block graphs on the overview, and the small history line
// on every tunnel card. Data: GET /api/history?range=1h|24h|7d|30d (kept by
// the daemon in 5-minute slots). Plain SVG, no libraries.

var hist = null; // last answer; var: app.js may call sparkline() before this file ran
var histRange = "24h";
try { histRange = localStorage.getItem("shunt-range") || "24h"; } catch (e) { /* private window */ }
var histMissing = false; // the daemon has no history (yet)

const SVGNS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs = {}, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  e.append(...kids);
  return e;
}

// "M0,10L5,8…" for values scaled to 0..max over a W x H box
function linePath(vals, W, H, max) {
  const n = vals.length;
  return vals.map((v, i) => (i ? "L" : "M") + (n > 1 ? (i * W / (n - 1)).toFixed(1) : 0) + "," + (H - (max ? v / max * H : 0)).toFixed(1)).join("");
}

function sparkline(vals) {
  if (!vals || vals.length < 2) return "";
  const max = Math.max(...vals);
  const line = linePath(vals, 100, 24, max);
  return svgEl("svg", { class: "spark", viewBox: "0 -1 100 26", preserveAspectRatio: "none", role: "img", "aria-label": "traffic of the last " + histRange },
    svgEl("path", { class: "a", d: line + "L100,24L0,24Z" }), svgEl("path", { d: line }));
}

function fmtTime(sec, long) {
  const d = new Date(sec * 1000);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return long || histRange === "1h" || histRange === "24h" ? (histRange === "24h" || long ? d.toLocaleDateString([], { weekday: "short" }) + " " : "") + t : d.toLocaleDateString([], { day: "numeric", month: "short" });
}

function rate(b, step) { return bytes(Math.round(b / step)) + "/s"; }

function drawTraffic(h) {
  const W = 1000, H = 100, n = h.points.length;
  const down = h.points.map((p) => p.rx), up = h.points.map((p) => p.tx);
  const max = Math.max(1, ...down, ...up);
  const box = $("#t-chart");
  const cursor = svgEl("line", { class: "cursor", y1: 0, y2: H, x1: 0, x2: 0, visibility: "hidden" });
  box.replaceChildren(
    svgEl("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none" },
      ...[0.25, 0.5, 0.75].map((f) => svgEl("line", { class: "grid", x1: 0, x2: W, y1: H * f, y2: H * f })),
      svgEl("path", { class: "a-up", d: linePath(up, W, H, max) + "L" + W + "," + H + "L0," + H + "Z" }),
      svgEl("path", { class: "a-down", d: linePath(down, W, H, max) + "L" + W + "," + H + "L0," + H + "Z" }),
      svgEl("path", { class: "l-up", d: linePath(up, W, H, max) }),
      svgEl("path", { class: "l-down", d: linePath(down, W, H, max) }),
      cursor),
    el("span", { class: "ymax" }, rate(max, h.step)));
  return cursor;
}

function drawBlocks(h) {
  const W = 1000, H = 40, n = h.points.length;
  const vals = h.points.map((p) => p.dns);
  const max = Math.max(1, ...vals);
  const bw = W / n;
  const cursor = svgEl("line", { class: "cursor", y1: 0, y2: H, x1: 0, x2: 0, visibility: "hidden" });
  $("#t-dnschart").replaceChildren(
    svgEl("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none" },
      ...vals.map((v, i) => v ? svgEl("rect", { class: "bar", x: (i * bw + bw * 0.12).toFixed(1), width: (bw * 0.76).toFixed(1), y: (H - v / max * H).toFixed(1), height: (v / max * H).toFixed(1) }) : ""),
      cursor),
    ...(vals.some((v) => v) ? [el("span", { class: "ymax" }, max + " blocked")] : []));
  return cursor;
}

function kpi(cls, value, label) {
  return el("div", { class: "kpi " + cls }, el("b", {}, value), el("span", {}, label));
}

function renderTraffic() {
  const sec = $("#traffic");
  sec.hidden = histMissing;
  if (histMissing || !hist) return;
  const h = hist, step = h.step;
  const filterOn = !!(status && status.dns_filter);
  const names = { "1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" };
  $("#t-kpis").replaceChildren(
    kpi("down", "↓ " + bytes(h.rx), "downloaded, " + names[h.range]),
    kpi("up", "↑ " + bytes(h.tx), "uploaded, " + names[h.range]),
    kpi("dns", filterOn || h.dns_month ? String(h.dns_today) : "–", filterOn ? "names blocked today" : "names blocked today (DNS filter off)"),
    kpi("dns", filterOn || h.dns_month ? String(h.dns_month) : "–", "names blocked this month"));
  const c1 = drawTraffic(h), c2 = drawBlocks(h);
  $("#t-from").textContent = fmtTime(h.from);
  const hover = $("#t-hover");
  const n = h.points.length;
  const move = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
    const i = Math.min(n - 1, Math.floor(f * n));
    const p = h.points[i];
    const x = (i + 0.5) / n * 1000;
    for (const c of [c1, c2]) { c.setAttribute("x1", x); c.setAttribute("x2", x); c.setAttribute("visibility", "visible"); }
    hover.textContent = fmtTime(p.t, true) + "  ·  ↓ " + rate(p.rx, step) + "  ↑ " + rate(p.tx, step) + "  ·  " + p.dns + " blocked";
  };
  const leave = () => { for (const c of [c1, c2]) c.setAttribute("visibility", "hidden"); hover.textContent = ""; };
  for (const id of ["#t-chart", "#t-dnschart"]) { $(id).onmousemove = move; $(id).onmouseleave = leave; }
  for (const b of document.querySelectorAll("#t-range button")) b.classList.toggle("active", b.dataset.r === histRange);
}

async function loadHistory() {
  try {
    hist = await api("GET", "/api/history?range=" + histRange);
    histMissing = false;
  } catch (e) {
    // an older daemon (or one without history) answers 404/502: hide the graph
    if (!hist) histMissing = true;
  }
  renderTraffic();
  if (status) render();
}

for (const b of document.querySelectorAll("#t-range button")) {
  b.addEventListener("click", () => {
    histRange = b.dataset.r;
    try { localStorage.setItem("shunt-range", histRange); } catch (e) { /* private window */ }
    loadHistory();
  });
}
loadHistory();
setInterval(() => { if (!document.hidden && !$("#page-overview").hidden) loadHistory(); }, 15000);
