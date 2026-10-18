"use strict";
// Keeps the page's own preferences (keys "shunt-…" in localStorage: folded
// sections, theme, graph range) on the machine as well, so they survive a
// restart even when the address of the page changes (shunt ui picks a new port).
(() => {
  let ls;
  try { ls = window.localStorage; ls.getItem("x"); } catch (e) { return; }
  const set = Storage.prototype.setItem, del = Storage.prototype.removeItem;
  let pending = {}, timer = null;
  const send = (body) => fetch("api/ui-state", { method: "PUT", headers: { "X-Shunt": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) }).catch(() => {});
  const push = (k, v) => {
    if (!k.startsWith("shunt-")) return;
    pending[k] = v;
    clearTimeout(timer);
    timer = setTimeout(() => { const b = pending; pending = {}; send(b); }, 400);
  };
  Storage.prototype.setItem = function (k, v) { set.call(this, k, v); if (this === ls) push(String(k), String(v)); };
  Storage.prototype.removeItem = function (k) { del.call(this, k); if (this === ls) push(String(k), null); };
  fetch("api/ui-state").then((r) => (r.ok ? r.json() : {})).then((srv) => {
    let changed = false;
    for (const [k, v] of Object.entries(srv)) {
      if (ls.getItem(k) !== v) { set.call(ls, k, v); changed = true; }
    }
    // a page that has settings the machine does not know yet seeds it
    const seed = {};
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (k.startsWith("shunt-") && !(k in srv)) seed[k] = ls.getItem(k);
    }
    if (Object.keys(seed).length) send(seed);
    if (changed) location.reload(); // apply the stored state once; the next load finds no difference
  }).catch(() => {});
})();
