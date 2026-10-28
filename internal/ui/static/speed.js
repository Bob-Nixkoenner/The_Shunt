"use strict";
// Speedtest tab: pick routes, start, watch the progress, read the result.
// The measurement runs in the service (inside each route), this page only
// starts it and polls.
const SPEED_MB_PER_STEP = 25; // download and upload each, per route and round
let speedTimer = null, speedLast = null, speedInfoOpen = false;

function speedRoutes() {
  const st = typeof status !== "undefined" ? status : null;
  return ((st && st.routes) || []).filter((r) => r !== "block");
}

function isTorRoute(r) {
  const st = typeof status !== "undefined" ? status : null;
  const t = st && r.startsWith("tunnel:") ? (st.tunnels || []).find((x) => "tunnel:" + x.name === r) : null;
  return !!(t && t.bootstrap !== undefined && t.bootstrap !== null);
}

function renderSpeedRoutes() {
  const box = $("#sp-routes");
  const routes = speedRoutes();
  const key = routes.join(",");
  if (box.dataset.key === key) return;
  const had = new Set([...box.querySelectorAll("input:checked")].map((i) => i.value));
  const first = !box.dataset.key;
  box.dataset.key = key;
  box.replaceChildren(...routes.map((r) => el("label", { class: "row" + (isTorRoute(r) ? " expert" : ""), style: "gap:5px;color:var(--text)" },
    el("input", { type: "checkbox", value: r, ...(first || had.has(r) ? { checked: "" } : {}), onchange: speedEstimate }), routeTag(r))));
  speedEstimate();
}

function speedChosen() { return [...$("#sp-routes").querySelectorAll("input:checked")].map((i) => i.value); }

function speedEstimate() {
  const n = speedChosen().length, rounds = +$("#sp-rounds").value;
  const ndt = $("#sp-prov").value === "ndt7";
  const mb = ndt ? n * rounds * 2 * 120 : n * rounds * 2 * SPEED_MB_PER_STEP;
  $("#sp-est").textContent = n ? T("about {mb} MB of data", { mb: mb }) : "";
  $("#sp-ndt-note").hidden = !(ndt || speedInfoOpen);
  $("#sp-mobile").hidden = !speedChosen().some((r) => r === "link:mobile");
  $("#sp-start").disabled = !n;
}

function num1(x) { return x > 0 ? (x >= 100 ? Math.round(x) : x.toFixed(1)) : "–"; }

function renderSpeedResult(rep) {
  $("#sp-result-sec").hidden = !rep;
  if (!rep) return;
  const maxDown = Math.max(1, ...rep.routes.map((r) => r.down_mbit || 0));
  const maxUp = Math.max(1, ...rep.routes.map((r) => r.up_mbit || 0));
  const bar = (v, max) => el("div", { class: "spbar" }, el("div", { class: "spfill", style: "width:" + Math.round(100 * (v || 0) / max) + "%" }),
    el("span", { class: "spnum" }, v > 0 ? num1(v) + " Mbit/s" : "–"));
  $("#sp-result").replaceChildren(...rep.routes.map((r) => el("tr", {},
    el("td", {}, routeTag(r.route), r.fastest ? el("span", { class: "pill ok" }, "fastest") : "", r.slowest ? el("span", { class: "pill warn" }, "slowest") : ""),
    el("td", {}, r.state === "failed" ? el("span", { class: "pill bad", title: r.error || "" }, "failed") : r.latency_ms > 0 ? num1(r.latency_ms) + " ms" : "–"),
    el("td", {}, r.jitter_ms > 0 ? num1(r.jitter_ms) + " ms" : "–"),
    el("td", {}, bar(r.down_mbit, maxDown), r.down_max > r.down_min ? el("div", { class: "muted" }, num1(r.down_min) + "–" + num1(r.down_max)) : ""),
    el("td", {}, bar(r.up_mbit, maxUp), r.up_max > r.up_min ? el("div", { class: "muted" }, num1(r.up_min) + "–" + num1(r.up_max)) : ""),
    el("td", { class: "mono" }, r.ip ? r.ip + (r.loc ? " (" + r.loc + ")" : "") : "–", r.state === "partial" ? el("div", { class: "muted", title: r.error || "" }, "some steps failed") : ""))));
  $("#sp-seed").textContent = T("Rounds: {n} · order seed {seed} (the same seed repeats the order)", { n: rep.rounds, seed: rep.seed });
}

function speedState(s) {
  speedLast = s;
  $("#sp-start").hidden = s.running;
  $("#sp-cancel").hidden = !s.running;
  for (const i of $("#sp-routes").querySelectorAll("input")) i.disabled = s.running;
  $("#sp-prog").textContent = s.running ? T("Measuring… step {done} of {total}", { done: s.done, total: s.total }) : "";
  const m = $("#sp-msg");
  m.className = "msg " + (s.error ? (s.error === "cancelled" ? "muted" : "err") : "");
  m.textContent = s.error ? (s.error === "cancelled" ? T("Cancelled.") : s.error) : "";
  renderSpeedResult(s.report);
  clearTimeout(speedTimer);
  if (s.running) speedTimer = setTimeout(pollSpeed, 1000);
}

async function pollSpeed() {
  try { speedState(await api("GET", "/api/speedtest")); } catch (e) { $("#sp-msg").textContent = e.message; }
}

$("#sp-start").addEventListener("click", async () => {
  const routes = speedChosen();
  if (!routes.length) return;
  try {
    speedState(await api("POST", "/api/speedtest", { routes, provider: $("#sp-prov").value, rounds: +$("#sp-rounds").value }));
  } catch (e) { $("#sp-msg").className = "msg err"; $("#sp-msg").textContent = e.message; }
});
$("#sp-cancel").addEventListener("click", async () => { try { speedState(await api("DELETE", "/api/speedtest")); } catch (e) { /* gone */ } });
$("#sp-all").addEventListener("click", () => { for (const i of $("#sp-routes").querySelectorAll("input:not(:disabled)")) i.checked = true; speedEstimate(); });
$("#sp-none").addEventListener("click", () => { for (const i of $("#sp-routes").querySelectorAll("input:not(:disabled)")) i.checked = false; speedEstimate(); });
$("#sp-prov").addEventListener("change", speedEstimate);
$("#sp-rounds").addEventListener("change", speedEstimate);
$("#tab-speed").addEventListener("click", () => { renderSpeedRoutes(); pollSpeed(); });
setInterval(() => { if (!document.hidden && !$("#page-speed").hidden) renderSpeedRoutes(); }, 2000);
// the Windows service has no speed test yet
setInterval(() => { const w = typeof status !== "undefined" && status && status.platform === "windows"; $("#tab-speed").hidden = !!w; }, 2000);
$("#sp-info").addEventListener("click", () => { speedInfoOpen = !speedInfoOpen; speedEstimate(); });
