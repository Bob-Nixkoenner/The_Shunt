"use strict";
// Foldable sections ([data-fold]) and lists that show at most N rows and
// scroll beyond that ([data-rows="N"]). Fold state is remembered per browser.

function foldKey(sec) {
  const h = sec.querySelector("h2");
  return "shunt-fold:" + (sec.closest("main") || {}).id + ":" + (h ? h.firstChild.textContent.trim() : "");
}
function foldGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function foldSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } }

function fitRows(box) {
  const n = +box.dataset.rows;
  const items = box.querySelectorAll("tbody tr, .leaklist > *");
  if (box.offsetParent === null || items.length <= n) {
    box.style.maxHeight = "";
    box.style.overflowY = "";
    return;
  }
  const last = items[n - 1].getBoundingClientRect().bottom;
  const top = box.getBoundingClientRect().top;
  box.style.maxHeight = Math.ceil(last - top + box.scrollTop + 2) + "px";
  box.style.overflowY = "auto";
}
let fitQueued = false;
function fitAll() {
  if (fitQueued) return;
  fitQueued = true;
  requestAnimationFrame(() => {
    fitQueued = false;
    document.querySelectorAll("[data-rows]").forEach(fitRows);
  });
}

document.querySelectorAll("section[data-fold]").forEach((sec) => {
  const h = sec.querySelector("h2");
  const key = foldKey(sec);
  const btn = document.createElement("button");
  btn.className = "fold";
  btn.type = "button";
  h.classList.add("foldable");
  h.prepend(btn);
  const set = (folded) => {
    sec.classList.toggle("folded", folded);
    btn.title = btn.ariaLabel = folded ? "Unfold" : "Fold";
    btn.setAttribute("aria-expanded", String(!folded));
  };
  // data-fold="closed": folded until you open it once
  const saved = foldGet(key);
  set(saved === null ? sec.dataset.fold === "closed" : saved === "1");
  // the arrow and empty heading space fold; buttons, fields and links in the heading keep their job
  h.addEventListener("click", (e) => {
    if (e.target.closest("button:not(.fold), input, select, label, a")) return;
    const folded = !sec.classList.contains("folded");
    set(folded);
    foldSet(key, folded ? "1" : "0");
    fitAll();
  });
});

document.querySelectorAll("[data-rows]").forEach((box) => {
  new MutationObserver(fitAll).observe(box, { childList: true, subtree: true });
});
document.querySelectorAll("nav.tabs button").forEach((b) => b.addEventListener("click", () => setTimeout(fitAll, 0)));
window.addEventListener("resize", fitAll);
fitAll();
