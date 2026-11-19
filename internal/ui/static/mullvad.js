"use strict";
// Mullvad module (Configure > Add a tunnel > Mullvad): log in, pick an exit.
let mvCountries = [];

function mvFill(sel, rows, keep) {
  const s = $(sel);
  s.replaceChildren(...rows.map(([v, l]) => el("option", { value: v }, l)));
  if (keep && rows.some(([v]) => v === keep)) s.value = keep;
}

function mvPickLists() {
  const cc = $("#mv-country").value;
  const c = mvCountries.find((x) => x.code === cc);
  mvFill("#mv-city", [["", T("any city")], ...(c ? c.cities.map((x) => [x.code, x.name + " (" + x.servers + ")"]) : [])], $("#mv-city").value);
  mvServers();
}

function mvServers() {
  // single servers are only listed when a city is chosen; the host name is the code
  const city = $("#mv-city").value;
  const rows = [["", T("any server")]];
  const c = mvCountries.find((x) => x.code === $("#mv-country").value);
  const ci = c && c.cities.find((x) => x.code === city);
  if (ci) for (const h of ci.hosts || []) rows.push([h, h]);
  mvFill("#mv-server", rows, $("#mv-server").value);
}

async function mvRefresh() {
  let st;
  try { st = await api("GET", "/api/mullvad"); } catch (e) { return; }
  $("#mv-main").hidden = !st.logged_in;
  const accts = st.accounts || [];
  $("#mv-accounts").replaceChildren(...accts.map((a) => el("div", { class: "row", style: "margin-top:10px" },
    el("b", {}, a.name), el("span", { class: "muted" }, T("Account {account}, device {device}", { account: a.account, device: a.device })),
    el("span", { class: "spacer" }),
    el("button", { type: "button", onclick: () => mvLogout(a.name) }, T("Log out")))));
  mvFill("#mv-acct", accts.map((a) => [a.name, a.name]), $("#mv-acct").value);
  $("#mv-acct").hidden = accts.length < 2;
  if (!st.logged_in) return;
  const tb = $("#mv-exits");
  tb.replaceChildren(...(st.exits || []).map((x) => el("tr", {},
    el("td", {}, x.tunnel), el("td", {}, accts.length > 1 ? x.account : ""), el("td", {}, x.country + ", " + x.city), el("td", { class: "mono" }, x.hostname),
    el("td", {}, el("button", { class: "iconbtn", title: T("use this name for the next exit"), onclick: () => { $("#mv-name").value = x.tunnel; $("#mv-acct").value = x.account; } }, "↻")))));
  if (!mvCountries.length) {
    try {
      mvCountries = await api("GET", "/api/mullvad/relays");
      mvFill("#mv-country", [["", T("any country")], ...mvCountries.map((c) => [c.code, c.name + " (" + c.servers + ")"])], "");
      mvPickLists();
    } catch (e) { toast(e.message); }
  }
}

async function mvLogout(name) {
  if (!(await ask(T("Log out of Mullvad? The Mullvad tunnels are removed and the device is deleted at Mullvad.")))) return;
  try {
    await api("POST", "/api/mullvad/logout", { name });
    toast(T("Logged out of Mullvad"));
    await mvRefresh();
    reloadConfig();
  } catch (e) { toast(e.message); }
}

$("#mv-country").addEventListener("change", mvPickLists);
$("#mv-city").addEventListener("change", mvServers);

$("#mv-login-btn").addEventListener("click", async () => {
  const account = $("#mv-account").value;
  try {
    await api("POST", "/api/mullvad/login", { name: $("#mv-acct-name").value.trim(), account });
    $("#mv-account").value = "";
    $("#mv-acct-name").value = "";
    toast(T("Logged in to Mullvad"));
    await mvRefresh();
  } catch (e) { toast(e.message); }
});

$("#mv-connect").addEventListener("click", async () => {
  const name = $("#mv-name").value.trim();
  if (!/^[a-z0-9][a-z0-9-]{0,9}$/.test(name)) return toast(T("Tunnel name: 1–10 characters a-z 0-9 -"));
  const req = { tunnel: name, account: $("#mv-acct").value || undefined, country: $("#mv-country").value, city: $("#mv-city").value, hostname: $("#mv-server").value, via: $("#mv-via").value || undefined };
  try {
    await api("POST", "/api/mullvad/connect", req);
    toast(T("Tunnel {name} is on its new Mullvad exit", { name }));
    await mvRefresh();
    reloadConfig();
  } catch (e) { toast(e.message); }
});

$("#addtab-mv").addEventListener("click", mvRefresh);
