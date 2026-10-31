"use strict";
// Levels: what the page shows. "simple" for people who just want the VPN to
// work, "pro" shows everything, "opsec" shows everything too, with a violet
// accent, a band in the header and a set of strict settings the user
// confirmed once (opsec.js). The level only hides things: hidden settings
// keep working.
//
// LEVEL_TABLE is the one place that says which part shows in which level.
// Elements name their part with data-lv="key" (in index.html, or as an
// attribute of el() in the scripts); a key missing from the table shows
// everywhere. Scripts ask shows("key") for parts they draw themselves.

const UI_LEVELS = ["simple", "pro", "opsec"];
const LV_ALL = ["simple", "pro", "opsec"], LV_PRO = ["pro", "opsec"];

const LEVEL_TABLE = {
  // tabs: Simple has Overview, VPN, Apps, DNS (and View, where the level is chosen)
  "tab.ports": LV_PRO,
  "tab.speed": LV_PRO,
  "tab.config": LV_PRO,
  // Tor: existing Tor tunnels stay as a plain card; adding one, bridges,
  // new identity and the emergency switch are Pro (the switch stays visible
  // while it is on, see app.js)
  "tor.add": LV_PRO,
  "tor.bridges": LV_PRO,
  "tor.newnym": LV_PRO,
  "tor.emergency": LV_PRO,
  // tunnels
  "tunnel.multihop": LV_PRO,
  "tunnel.advanced": LV_PRO,
  "ts.advanced": LV_PRO,
  // apps: Simple keeps the route per app (the simple choice of rules)
  "apps.groups": LV_PRO,
  "apps.launchers": LV_PRO,
  "apps.fwtuning": LV_PRO,
  "apps.fwdecisions": LV_PRO,
  // DNS
  "dns.lists": LV_PRO,
  "dns.encrypted": LV_PRO,
  "dns.servers": LV_PRO,
  // Configure (the whole tab is Pro; Simple gets the routing card on the VPN tab)
  "privacy.stealth": LV_PRO,
  "config.rules": LV_PRO,
  "config.raw": LV_PRO,
  // incoming protection ([inbound]): global switch, allowed ports, per tunnel,
  // per network profile, notes on the Ports tab, the question on a new network
  "inbound": LV_PRO,
  // security check: Simple shows only what is really bad (red banners)
  "checks.notes": LV_PRO,
  // opsec only
  "opsec.band": ["opsec"],
};

function levelOK(l) { return UI_LEVELS.includes(l); }

// levelFrom: the level stored, or the one the old Normal/Expert view mode
// becomes ("" = not decided yet). The service does the same with the
// ui-state file (uistate.go).
function levelFrom(level, viewMode) {
  if (levelOK(level)) return level;
  if (viewMode === "normal") return "simple";
  if (viewMode === "expert") return "pro";
  return "";
}

function lvGet(k) { try { return localStorage.getItem(k) || ""; } catch (e) { return ""; } }
function lvSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } }
function lvDel(k) { try { localStorage.removeItem(k); } catch (e) { /* private window */ } }

// storedLevel: "" until the user (or the first start) decided
function storedLevel() { return levelFrom(lvGet("shunt-level"), lvGet("shunt-view-mode")); }
function level() { return storedLevel() || "simple"; }
function shows(key, lv) {
  const l = LEVEL_TABLE[key];
  return !l || l.includes(lv || level());
}

// applyLevel marks every part of the page the current level hides; called
// again for parts drawn later (el() does it for its own elements).
function applyLevel(root) {
  const lv = level();
  for (const l of UI_LEVELS) document.body.classList.toggle("lv-" + l, l === lv);
  for (const e of (root || document).querySelectorAll("[data-lv]")) e.classList.toggle("lv-off", !shows(e.dataset.lv, lv));
}
