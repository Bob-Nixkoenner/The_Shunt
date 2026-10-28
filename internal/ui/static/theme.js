"use strict";
// Light/dark: follows the system unless chosen under View → Look.
// Loaded in <head> so the page does not flash in the wrong theme.
(() => {
  const root = document.documentElement;
  const get = () => { try { return localStorage.getItem("shunt-theme") || ""; } catch (e) { return ""; } };
  const apply = (t) => { if (t === "light" || t === "dark") root.dataset.theme = t; else delete root.dataset.theme; };
  apply(get());
  addEventListener("DOMContentLoaded", () => {
    const sel = document.getElementById("c-theme");
    if (!sel) return;
    sel.value = get();
    sel.addEventListener("change", () => {
      try { sel.value ? localStorage.setItem("shunt-theme", sel.value) : localStorage.removeItem("shunt-theme"); } catch (e) { /* private window */ }
      apply(sel.value);
    });
  });
})();
