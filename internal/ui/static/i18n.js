"use strict";
// Language of the page. i18n-data.js (made by the server, loaded first) says
// which language, and brings the translations: the English text is the key.
//
//   T("Everything else goes")                     text from code
//   T("{n} apps", { n: 3 })                       with values
//   Tn(n, "{n} rule", "{n} rules")                one / many
//
// Plain texts need no call at all: text nodes, title, placeholder and
// aria-label that equal a key are translated as they appear in the page, also
// those made later by the scripts. A paragraph with markup inside gets
// data-i18n="html" (the key is its inner HTML); data-i18n="skip" keeps a part
// of the page as it is (names of apps, tunnels, ...).
(() => {
  const D = window.SHUNT_I18N || { lang: "en", langs: [{ code: "en", name: "English" }], dict: {} };
  const dict = D.dict || {};
  const fill = (s, v) => (v ? s.replace(/\{(\w+)\}/g, (m, k) => (k in v ? v[k] : m)) : s);
  window.T = (s, v) => fill(dict[s] || s, v);
  window.Tn = (n, one, many, v) => T(n === 1 ? one : many, Object.assign({ n }, v));
  window.i18n = { lang: D.lang, choice: D.choice || "", auto: D.auto || "en", langs: D.langs };
  document.documentElement.lang = D.lang === "xx" ? "en" : D.lang;
  if (!Object.keys(dict).length) return; // English: nothing to translate

  const squash = (s) => s.replace(/\s+/g, " ").trim();
  const SKIP = "SCRIPT,STYLE,TEXTAREA,PRE";
  const ATTRS = ["title", "placeholder", "aria-label"];

  // What was written into a node by us: the observer sees our own change
  // and must not translate it again (a German text that equals an English
  // key, or a text that stays the same, would loop for ever).
  const written = new WeakMap(), writtenAttr = new WeakMap(), htmlDone = new WeakSet();
  function text(node) {
    const v = node.nodeValue;
    if (written.get(node) === v) return;
    const key = squash(v);
    if (!key || !(key in dict)) return;
    const lead = v.match(/^\s*/)[0], trail = v.match(/\s*$/)[0];
    const nv = lead + dict[key] + trail;
    written.set(node, nv);
    if (nv !== v) node.nodeValue = nv;
  }
  function attrs(el) {
    if (!el.getAttribute) return;
    let w = writtenAttr.get(el);
    for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (!v || (w && w[a] === v) || !dict[squash(v)]) continue;
      const nv = dict[squash(v)];
      if (!w) writtenAttr.set(el, (w = {}));
      w[a] = nv;
      if (nv !== v) el.setAttribute(a, nv);
    }
  }
  function walk(n) {
    if (n.nodeType === 3) return text(n);
    if (n.nodeType !== 1) return;
    const mode = n.getAttribute("data-i18n");
    if (mode === "skip") return;
    attrs(n); // also a textarea's placeholder; its content is the user's own
    if (SKIP.includes(n.tagName)) return;
    if (mode === "html") {
      if (htmlDone.has(n)) return;
      const key = squash(n.innerHTML);
      htmlDone.add(n);
      if (dict[key] && dict[key] !== n.innerHTML) n.innerHTML = dict[key];
      return;
    }
    for (const c of Array.from(n.childNodes)) walk(c);
  }

  const obs = new MutationObserver((muts) => {
    for (const m of muts) {
      if (m.type === "characterData") { if (!m.target.parentElement || m.target.parentElement.closest('[data-i18n="skip"]') === null) text(m.target); }
      else if (m.type === "attributes") { if (m.target.closest('[data-i18n="skip"]') === null) attrs(m.target); }
      else for (const n of m.addedNodes) if (!(n.parentElement && n.parentElement.closest('[data-i18n="skip"]'))) walk(n);
    }
  });
  const start = () => {
    walk(document.documentElement);
    document.title = dict[document.title] || document.title;
    obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
