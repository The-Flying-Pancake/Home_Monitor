/* Services on the network and planned work, in the browser:
 *   Settings, Pi-hole and Settings, UniFi (pihole.py, unifi.py): switch, steps, connection form
 *   Settings, Maintenance windows (maintenance.py), and the device page's Maintenance button
 *   device page: the DNS tab (Pi-hole), Wi-Fi devices on the Wireless tab (UniFi), and the
 *   "Filling up" forecasts on the Storage tab (forecast.py)
 * Relies on app.js helpers (api, escapeHtml, showToast, confirmDialog, can, lastDetail, activeDeviceId,
 * fillTable, drawDefinition, formatAgo, formatDuration, taxo).
 */

// --- Settings: Pi-hole and UniFi ---------------------------------------------

const LAN = {
  pihole: { p: "ph", name: "Pi-hole", api: "/api/pihole", cfg: null,
    fields: { url: "ph-url", secret: "ph-secret", fingerprint: "ph-fp", test_name: "ph-test-name" },
    off: "Reads Pi-hole's own web API with an app password. Nothing is fetched while it is off.",
    on: c => c.configured ? `On: figures every minute on ${c.device_name || "the Pi-hole's device page"}, DNS tab.` : "On: connect it below." },
  unifi: { p: "uf", name: "UniFi", api: "/api/unifi", cfg: null,
    fields: { url: "uf-url", username: "uf-user", site: "uf-site", secret: "uf-secret", fingerprint: "uf-fp" },
    off: "Logs in to the UniFi Network application with a local view-only account. Nothing is fetched while it is off.",
    on: c => c.configured ? "On: Wi-Fi devices on each access point's Wireless tab, names in the Inventory." : "On: connect it below." },
};

function lanSay(kind, text, cls = "") {
  const m = document.getElementById(`${LAN[kind].p}-msg`);
  m.textContent = text;
  m.className = `form-help ${cls}`;
}

async function loadLanSettings(kind) {
  const L = LAN[kind];
  try {
    L.cfg = await api(`${L.api}/config`);
  } catch (err) {
    lanSay(kind, err.message, "text-err");
    return;
  }
  if (kind === "pihole") {
    const devs = (lastFleet ? lastFleet[0] : null) || (await api("/api/devices").catch(() => ({ devices: [] }))).devices || [];
    document.getElementById("ph-device").innerHTML = `<option value="">The device with the Pi-hole's address</option>` +
      devs.map(d => `<option value="${d.id}">${escapeHtml(d.hostname)} (${escapeHtml(d.ip_address)})</option>`).join("");
    const hit = devs.find(d => d.id === L.cfg.device_id);
    L.cfg.device_name = hit ? hit.hostname : "";
  }
  renderLanSettings(kind, true);
}

function renderLanSettings(kind, fill) {
  const L = LAN[kind], c = L.cfg || {};
  const sel = document.getElementById(`${L.p}-enabled`);
  sel.value = c.enabled ? "on" : "off";
  sel.disabled = !can("settings.system");
  document.getElementById(`${L.p}-config`).classList.toggle("hidden", !c.enabled);
  let help = c.enabled ? L.on(c) : L.off;
  if (c.enabled && c.last && c.last.error) help += ` Last attempt: ${c.last.error}`;
  else if (c.enabled && c.last && c.last.at) help += ` Last read ${formatAgo(c.last.at)}${c.last.clients != null ? `: ${c.last.clients} devices, ${c.last.aps} access points` : ""}.`;
  document.getElementById(`${L.p}-enabled-help`).textContent = help;
  document.getElementById(`btn-${L.p}-disconnect`).classList.toggle("hidden", !c.configured);
  if (!fill) return;
  for (const [k, id] of Object.entries(L.fields)) {
    if (k === "secret") continue;
    document.getElementById(id).value = c[k] || "";
  }
  const secret = document.getElementById(L.fields.secret);
  secret.value = "";
  secret.placeholder = c.secret_set ? "Stored and hidden: leave empty to keep" : "";
  if (kind === "pihole") document.getElementById("ph-device").value = c.device_id ? String(c.device_id) : "";
  if (kind === "unifi") api("/api/wifi").then(w => { document.getElementById("uf-never").value = (w.never || []).join(", "); }).catch(() => {});
}

function lanPayload(kind) {
  const L = LAN[kind];
  const body = {};
  for (const [k, id] of Object.entries(L.fields)) body[k] = document.getElementById(id).value.trim();
  if (kind === "pihole") {
    const v = document.getElementById("ph-device").value;
    body.device_id = v ? Number(v) : null;
  }
  return body;
}

function initLanSettings(kind) {
  const L = LAN[kind];
  document.getElementById(`${L.p}-enabled`).addEventListener("change", async ev => {
    const on = ev.target.value === "on";
    try {
      L.cfg = Object.assign(L.cfg || {}, (await api(`${L.api}/config`, { method: "PUT", body: { enabled: on } })).config);
      renderLanSettings(kind, false);
      lanSay(kind, on ? "" : "Switched off. The connection is kept for when you switch it back on; Disconnect removes it.");
    } catch (err) {
      ev.target.value = on ? "off" : "on";
      lanSay(kind, err.message, "text-err");
    }
  });
  document.getElementById(`btn-${L.p}-fetchfp`).addEventListener("click", async () => {
    lanSay(kind, "Fetching...");
    try {
      const r = await api(`${L.api}/fingerprint`, { method: "POST", body: { url: document.getElementById(L.fields.url).value.trim() } });
      document.getElementById(L.fields.fingerprint).value = r.fingerprint;
      lanSay(kind, "Compare it with the one your browser shows for that page before you save.");
    } catch (err) {
      lanSay(kind, err.message, "text-err");
    }
  });
  document.getElementById(`btn-${L.p}-test`).addEventListener("click", async ev => {
    const b = ev.currentTarget;
    b.disabled = true;
    lanSay(kind, "Testing...");
    try {
      const r = (await api(`${L.api}/test`, { method: "POST", body: lanPayload(kind) })).result;
      lanSay(kind, kind === "pihole"
        ? `Connected to Pi-hole ${r.version}: ${r.queries != null ? Number(r.queries).toLocaleString() + " queries today, " : ""}${r.blocked_pct != null ? r.blocked_pct.toFixed(1) + "% blocked, " : ""}blocking ${r.blocking ? "on" : "off"}. DNS test: ${r.dns.ok ? `answered in ${r.dns.ms} ms` : r.dns.error}.`
        : `Connected${r.unifi_os ? " (UniFi OS)" : ""}: ${r.clients} devices, ${r.wifi} on Wi-Fi, ${r.aps} access points.`, "text-ok");
    } catch (err) {
      lanSay(kind, err.message, "text-err");
    } finally {
      b.disabled = false;
    }
  });
  document.getElementById(`${L.p}-config`).addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      L.cfg = Object.assign(L.cfg || {}, (await api(`${L.api}/config`, { method: "PUT", body: lanPayload(kind) })).config);
      await loadLanSettings(kind);
      lanSay(kind, "Saved. The first figures arrive within a minute.", "text-ok");
    } catch (err) {
      lanSay(kind, err.message, "text-err");
    }
  });
  document.getElementById(`btn-${L.p}-disconnect`).addEventListener("click", async () => {
    if (!(await confirmDialog({ title: `Disconnect ${L.name}?`, message: "The stored address and password are removed. Figures already recorded stay in the history.",
      confirmLabel: "Disconnect", danger: true }))) return;
    try {
      L.cfg = (await api(`${L.api}/config`, { method: "PUT", body: { disconnect: true } })).config;
      renderLanSettings(kind, true);
    } catch (err) {
      lanSay(kind, err.message, "text-err");
    }
  });
}

// --- Maintenance windows -----------------------------------------------------

let maintData = { windows: [] };

const fmtWhen = ts => new Date(ts * 1000).toLocaleString(undefined, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function maintCovers(w) {
  if (w.scope === "all") return "Every device";
  if (w.scope === "device") {
    const d = (lastFleet ? lastFleet[0] : []).find(x => String(x.id) === w.target);
    return d ? d.hostname : `Device ${w.target}`;
  }
  if (w.scope === "group") return `Group ${(taxo.groups.find(g => g.id === w.target) || { name: w.target }).name}`;
  return `Tag ${w.target}`;
}

async function loadMaintenance() {
  try {
    maintData = await api("/api/maintenance");
    if (!lastFleet) await loadDevices().catch(() => null);
  } catch (err) {
    document.getElementById("maint-msg").textContent = err.message;
    return;
  }
  document.getElementById("maint-body").innerHTML = maintData.windows.length ? maintData.windows.map(w => `<tr>
      <td class="text-cell">${escapeHtml(maintCovers(w))}</td><td>${escapeHtml(fmtWhen(w.start))}</td><td>${escapeHtml(fmtWhen(w.end))}</td>
      <td class="text-cell">${escapeHtml(w.note || "")}</td>
      <td><span class="status-pill ${w.state === "active" ? "status-warn" : w.state === "scheduled" ? "status-ok" : "status-unknown"}">${escapeHtml(w.state)}</span></td>
      <td class="actions-cell">${w.state !== "ended" ? `<button type="button" class="btn btn-small" data-perm="problems.ack" data-maint-end="${w.id}">${w.state === "active" ? "End now" : "Cancel"}</button>` : ""}</td></tr>`).join("")
    : `<tr><td colspan="6" class="empty-cell">No maintenance windows.</td></tr>`;
  maintTargets();
}

function maintTargets() {
  const scope = document.getElementById("maint-scope").value;
  const sel = document.getElementById("maint-target");
  document.getElementById("maint-target-wrap").classList.toggle("hidden", scope === "all");
  const opts = scope === "device" ? (lastFleet ? lastFleet[0] : []).map(d => [String(d.id), d.hostname])
    : scope === "group" ? taxo.groups.filter(g => g.devices).map(g => [g.id, g.name])
    : scope === "tag" ? taxo.tags.map(t => [t.name, t.name]) : [];
  sel.innerHTML = opts.map(([v, l]) => `<option value="${escapeHtml(v)}">${escapeHtml(l)}</option>`).join("")
    || `<option value="">${scope === "tag" ? "No tags yet" : "Nothing to choose"}</option>`;
}

async function addMaintenance(body) {
  const r = await api("/api/maintenance", { method: "POST", body });
  maintData.windows = r.windows;
  return r.window;
}

/** Device page, Maintenance: a window for this device, starting now. */
async function deviceMaintenance() {
  const d = lastDetail && lastDetail.device;
  if (!d) return;
  if (lastDetail.maintenance) {
    if (!(await confirmDialog({ title: `End maintenance on ${d.hostname}?`, message: "Alerts for it are sent again from now.", confirmLabel: "End now" }))) return;
    try {
      await api(`/api/maintenance/${lastDetail.maintenance.id}/end`, { method: "POST" });
      loadDeviceDetail(d.id, true);
    } catch (err) {
      showToast(err.message, "error");
    }
    return;
  }
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Maintenance on ${escapeHtml(d.hostname)}</span></div>
    <div class="modal-body">
      <div class="dialog-message">From now, its problems are still shown but no messages are sent, and downtime counts as planned. Devices behind it on the map are not covered: use Settings, Maintenance windows for a group or tag.</div>
      <div class="form-row">
        <div class="form-group"><label for="dm-minutes">For</label><select id="dm-minutes">
          <option value="30">30 minutes</option><option value="60" selected>1 hour</option><option value="120">2 hours</option><option value="240">4 hours</option><option value="1440">1 day</option></select></div>
        <div class="form-group"><label for="dm-note">Note (optional)</label><input type="text" id="dm-note" maxlength="200"></div>
      </div>
      <div class="form-error hidden" data-err></div>
    </div>
    <div class="modal-footer"><button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Start</button></div>
  </form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  form.querySelector("[data-x]").addEventListener("click", () => back.remove());
  back.addEventListener("keydown", ev => { if (ev.key === "Escape") back.remove(); });
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      await addMaintenance({ scope: "device", target: String(d.id), minutes: Number(form.querySelector("#dm-minutes").value),
        note: form.querySelector("#dm-note").value });
      back.remove();
      loadDeviceDetail(d.id, true);
    } catch (err) {
      const e = form.querySelector("[data-err]");
      e.textContent = err.message;
      e.classList.remove("hidden");
    }
  });
  form.querySelector("#dm-minutes").focus();
}

/** The notice under a device's header while it is in a window. */
function renderMaintNote(data) {
  const box = document.getElementById("detail-maint");
  const w = data.maintenance;
  box.classList.toggle("hidden", !w);
  document.getElementById("btn-detail-maint").textContent = w ? "End maintenance" : "Maintenance";
  if (!w) return;
  box.textContent = `In maintenance until ${fmtWhen(w.end)}${w.note ? `: ${w.note}` : ""}. Problems are shown but no messages are sent; downtime counts as planned.`;
}

function initMaintenance() {
  document.getElementById("maint-scope").addEventListener("change", maintTargets);
  document.getElementById("maint-when").addEventListener("change", ev =>
    document.getElementById("maint-start-wrap").classList.toggle("hidden", ev.target.value !== "at"));
  document.getElementById("maint-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const msg = document.getElementById("maint-msg");
    const scope = document.getElementById("maint-scope").value;
    const at = document.getElementById("maint-when").value === "at" ? document.getElementById("maint-start").value : "";
    if (document.getElementById("maint-when").value === "at" && !at) { msg.textContent = "Choose when it starts."; msg.className = "form-help text-err"; return; }
    try {
      await addMaintenance({ scope, target: scope === "all" ? "" : document.getElementById("maint-target").value,
        start: at ? Math.floor(new Date(at).getTime() / 1000) : null, minutes: Number(document.getElementById("maint-minutes").value),
        note: document.getElementById("maint-note").value });
      msg.textContent = "Added.";
      msg.className = "form-help text-ok";
      document.getElementById("maint-note").value = "";
      loadMaintenance();
    } catch (err) {
      msg.textContent = err.message;
      msg.className = "form-help text-err";
    }
  });
  document.getElementById("maint-body").addEventListener("click", async ev => {
    const b = ev.target.closest("[data-maint-end]");
    if (!b) return;
    try {
      await api(`/api/maintenance/${b.dataset.maintEnd}/end`, { method: "POST" });
      loadMaintenance();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
  document.getElementById("btn-detail-maint").addEventListener("click", deviceMaintenance);
}

// --- Device page: forecasts, Wi-Fi devices, DNS --------------------------------

function renderForecasts(detail) {
  const rows = (detail && detail.forecasts) || [];
  document.getElementById("forecast-panel").classList.toggle("hidden", !rows.length);
  fillTable("forecast-body", rows.map(f => `<tr>
      <td class="text-cell"><strong>${escapeHtml(f.label)}</strong></td>
      <td>${f.now.toFixed(1)}%</td>
      <td>${f.per_day > 0 ? "+" : ""}${f.per_day.toFixed(2)} points</td>
      <td data-sort="${f.days ?? 99999}">${f.days == null ? '<span class="dim">not filling</span>'
        : f.days > 730 ? `<span class="dim">over ${Math.floor(f.days / 365)} years</span>`
        : `<span class="${f.days <= 14 ? "text-err" : f.days <= 60 ? "text-warn" : ""}">about ${f.days < 1 ? "a day" : Math.round(f.days) + " days"}</span> <span class="dim">(${new Date(f.full_on * 1000).toLocaleDateString()})</span>`}</td></tr>`).join(""), "", 4);
}

function signalClass(dbm) {
  return dbm == null ? "" : dbm >= -60 ? "text-ok" : dbm >= -70 ? "" : dbm >= -78 ? "text-warn" : "text-err";
}

function renderWifiClients(data) {
  const rows = data.wifi_clients || [];
  document.getElementById("wifi-clients-panel").classList.toggle("hidden", !rows.length);
  if (!rows.length) return;
  document.getElementById("wifi-clients-note").textContent = `${rows.length} from UniFi, weakest first`;
  fillTable("wifi-clients-body", rows.map(c => `<tr>
      <td class="text-cell"><strong>${escapeHtml(c.name || c.mac)}</strong><div class="dim">${escapeHtml([c.ip, c.vendor].filter(Boolean).join(" · "))}</div></td>
      <td data-sort="${c.signal ?? -999}" class="${signalClass(c.signal)}">${c.signal != null ? `${c.signal} dBm` : "-"}</td>
      <td>${escapeHtml(c.band || "-")}</td><td>${c.channel != null ? escapeHtml(String(c.channel)) : "-"}</td>
      <td data-sort="${c.tx_mbps ?? 0}">${c.tx_mbps != null ? `${c.tx_mbps} / ${c.rx_mbps ?? "-"} Mbps` : "-"}</td>
      <td>${c.retries != null ? Number(c.retries).toLocaleString() : "-"}</td><td>${c.roams ?? "-"}</td>
      <td data-sort="${c.experience ?? -1}">${c.experience != null ? `${Math.round(c.experience)}%` : "-"}</td>
      <td data-sort="${c.uptime ?? 0}">${c.uptime != null ? escapeHtml(formatDuration(c.uptime)) : "-"}</td></tr>`).join(""), "", 9);
}

let dnsDrawn = 0;

async function loadDns(isRefresh) {
  let data;
  try {
    data = await api(`/api/devices/${activeDeviceId}/dns`);
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  fillTable("dns-up-body", data.upstreams.map(u => `<tr><td class="text-cell">${escapeHtml(u.name || "-")}</td><td>${escapeHtml(u.ip || "-")}</td>
      <td>${u.count != null ? Number(u.count).toLocaleString() : u.share_pct != null ? `${u.share_pct}%` : "-"}</td>
      <td>${u.response_ms != null ? `${u.response_ms} ms` : "-"}</td></tr>`).join(""), "No upstreams reported yet.", 4);
  fillTable("dns-blocked-body", data.blocked.map(b => `<tr><td class="text-cell">${escapeHtml(b.domain)}</td><td>${Number(b.count).toLocaleString()}</td></tr>`).join(""),
    "Nothing blocked yet today.", 2);
  if (isRefresh && Date.now() - dnsDrawn < 60000) return;
  dnsDrawn = Date.now();
  const defs = [
    { id: "dns.ms", title: "DNS answer time", series: [["dns.ms", "Answer"]], fmt: "ms" },
    { id: "pihole.queries", title: "Queries today", series: [["pihole.queries", "Queries"], ["pihole.blocked", "Blocked"]], fmt: "int" },
    { id: "pihole.blocked_pct", title: "Share blocked", series: [["pihole.blocked_pct", "Blocked"]], fmt: "pct", max: 100 },
  ];
  const box = document.getElementById("dns-charts");
  box.innerHTML = defs.map((g, i) => `<div class="chart-card" data-title="${escapeHtml(g.title)}"><div class="chart-title"><span>${escapeHtml(g.title)}</span><span class="dim">24h</span></div>
    <div class="chart-host" data-dns-chart="${i}"></div></div>`).join("");
  await Promise.all(defs.map((g, i) => drawDefinition(box.querySelector(`[data-dns-chart="${i}"]`), activeDeviceId, g, 24)));
}

// --- Wi-Fi page (UniFi) --------------------------------------------------------

let wifiData = { aps: [], clients: [] };

async function loadWifi() {
  try {
    wifiData = await api("/api/wifi");
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  const sel = document.getElementById("wifi-ap");
  const keep = sel.value;
  sel.innerHTML = `<option value="">All access points</option>` + wifiData.aps.map(a => `<option value="${a.device_id}">${escapeHtml(a.name)}</option>`).join("");
  sel.value = wifiData.aps.some(a => String(a.device_id) === keep) ? keep : "";
  const last = wifiData.last || {};
  document.getElementById("wifi-when").textContent = last.error ? `UniFi: ${last.error}` : last.at ? `Read ${formatAgo(last.at)}` : "";
  document.getElementById("wifi-aps").innerHTML = wifiData.aps.map(a => `<button type="button" class="wifi-ap${sel.value === String(a.device_id) ? " on" : ""}" data-wifi-ap="${a.device_id}">
      <h4><span>${escapeHtml(a.name)}</span><a class="dim" href="#/device/${a.device_id}/wireless">open</a></h4>
      <div class="wifi-ap-figs"><span><b>${Number(a.clients)}</b>devices</span><span><b class="${a.weak ? "text-warn" : ""}">${Number(a.weak)}</b>weak</span>
        <span><b>${a.experience != null ? a.experience + "%" : "-"}</b>experience</span></div>
      <div class="dim wifi-ap-bands">${escapeHtml(Object.entries(a.bands).map(([b, n]) => `${b} ${n}`).join(" · "))}</div></button>`).join("")
    || `<div class="dim">No access point has Wi-Fi devices yet: UniFi is read once a minute, and only monitored access points are shown.</div>`;
  renderWifi();
}

function renderWifi() {
  const q = document.getElementById("wifi-q").value.trim().toLowerCase();
  const ap = document.getElementById("wifi-ap").value, band = document.getElementById("wifi-band").value;
  const weakOnly = document.getElementById("wifi-weak-only").checked;
  const rows = wifiData.clients.filter(c => (!ap || String(c.ap_id) === ap) && (!band || c.band === band)
    && (!weakOnly || (c.signal != null && c.signal < wifiData.weak_dbm))
    && (!q || [c.name, c.mac, c.ip, c.vendor, c.ap_name].some(v => String(v || "").toLowerCase().includes(q))))
    .sort((a, b) => (a.signal ?? 0) - (b.signal ?? 0));
  document.getElementById("wifi-count").textContent = `${rows.length} of ${wifiData.clients.length} devices, weak below ${wifiData.weak_dbm} dBm`;
  document.querySelectorAll("[data-wifi-ap]").forEach(b => b.classList.toggle("on", b.dataset.wifiAp === ap));
  fillTable("wifi-body", rows.map(c => `<tr>
      <td class="text-cell"><strong>${escapeHtml(c.name || c.mac)}</strong>${c.alert === "off" ? ' <span class="dim" title="Inventory, Edit: its weak signal is never reported">not reported</span>'
        : c.alert ? ` <span class="dim" title="Inventory, Edit: its weak signal is reported below its own line">own line ${escapeHtml(String(c.alert))} dBm</span>` : ""}<div class="dim">${escapeHtml([c.ip, c.vendor, c.ssid].filter(Boolean).join(" · "))}</div></td>
      <td class="text-cell"><a href="#/device/${c.ap_id}/wireless">${escapeHtml(c.ap_name)}</a></td>
      <td data-sort="${c.signal ?? -999}" class="${signalClass(c.signal)}">${c.signal != null ? `${c.signal} dBm` : "-"}</td>
      <td>${escapeHtml(c.band || "-")}${c.channel ? ` <span class="dim">ch ${escapeHtml(String(c.channel))}</span>` : ""}</td>
      <td data-sort="${c.tx_mbps ?? 0}">${c.tx_mbps != null ? `${c.tx_mbps} / ${c.rx_mbps ?? "-"} Mbps` : "-"}</td>
      <td>${c.retries != null ? Number(c.retries).toLocaleString() : "-"}</td><td>${c.roams ?? "-"}</td>
      <td data-sort="${c.experience ?? -1}">${c.experience != null ? `${Math.round(c.experience)}%` : "-"}</td>
      <td data-sort="${c.uptime ?? 0}">${c.uptime != null ? escapeHtml(formatDuration(c.uptime)) : "-"}</td>
      <td class="actions-cell">${c.blocked ? `<span class="dim" title="${escapeHtml(c.blocked)}">held back</span>`
        : `<button type="button" class="btn btn-small" data-perm="devices.manage" data-wifi-reconnect="${escapeHtml(c.mac)}">Reconnect</button>`}</td></tr>`).join(""),
    wifiData.clients.length ? "Nothing matches." : "No Wi-Fi devices yet.", 10);
}

function initWifiPage() {
  ["wifi-q", "wifi-ap", "wifi-band", "wifi-weak-only"].forEach(id => document.getElementById(id).addEventListener(id === "wifi-q" ? "input" : "change", renderWifi));
  document.getElementById("wifi-filters").addEventListener("submit", ev => ev.preventDefault());
  document.getElementById("btn-wifi-refresh").addEventListener("click", loadWifi);
  document.getElementById("wifi-aps").addEventListener("click", ev => {
    const b = ev.target.closest("[data-wifi-ap]");
    if (!b || ev.target.closest("a")) return;
    const sel = document.getElementById("wifi-ap");
    sel.value = sel.value === b.dataset.wifiAp ? "" : b.dataset.wifiAp;
    renderWifi();
  });
  document.getElementById("wifi-body").addEventListener("click", async ev => {
    const b = ev.target.closest("[data-wifi-reconnect]");
    if (!b) return;
    const c = wifiData.clients.find(x => x.mac === b.dataset.wifiReconnect);
    if (!(await confirmDialog({ title: `Reconnect ${c.name || c.mac}?`, confirmLabel: "Reconnect",
      message: `It is dropped from ${c.ap_name} and joins again within a few seconds, ideally to the nearest access point. A call or download on it is interrupted.` }))) return;
    b.disabled = true;
    try {
      await api("/api/wifi/reconnect", { method: "POST", body: { mac: c.mac } });
      showToast(`Reconnecting ${c.name || c.mac}. The list updates within a minute.`, "success");
      setTimeout(loadWifi, 1500);
    } catch (err) {
      showToast(err.message, "error");
      b.disabled = false;
    }
  });
  document.getElementById("btn-uf-never").addEventListener("click", async () => {
    try {
      const r = await api("/api/unifi/never", { method: "PUT", body: { never: document.getElementById("uf-never").value } });
      document.getElementById("uf-never").value = r.never.join(", ");
      lanSay("unifi", "Never-reconnect list saved.", "text-ok");
    } catch (err) {
      lanSay("unifi", err.message, "text-err");
    }
  });
}

// --- Pi-hole page -----------------------------------------------------------------

let phData = null;

async function loadPiholePage() {
  try {
    phData = await api("/api/pihole");
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  const m = k => (phData.metrics[k] || {}).value;
  const kpis = document.getElementById("ph-kpis");
  if (!phData.device) {
    kpis.innerHTML = `<div class="panel-note-bar">No monitored device has the Pi-hole's address. Add it on the Devices page (Ping is enough), or choose it in Settings, Pi-hole.</div>`;
    return;
  }
  const blocking = m("pihole.blocking"), paused = m("pihole.paused") === 1;
  const left = m("pihole.pause_left");
  const state = blocking === 1 ? "Blocking on" : paused ? `Paused${left ? `, about ${Math.max(1, Math.round(left / 60))} min left` : ""}` : blocking === 0 ? "Blocking OFF" : "";
  document.getElementById("ph-state").textContent = state;
  document.getElementById("btn-ph-resume").classList.toggle("hidden", blocking !== 0);
  document.querySelectorAll("[data-ph-pause]").forEach(b => b.classList.toggle("hidden", blocking === 0));
  const num = v => v == null ? "-" : Math.round(v).toLocaleString();
  kpis.innerHTML = [
    kpiCard("Blocking", blocking === 1 ? "ON" : paused ? "PAUSED" : blocking === 0 ? "OFF" : "-", phData.device.hostname,
      blocking === 1 ? "text-ok" : "text-warn"),
    kpiCard("Queries today", num(m("pihole.queries")), `${num(m("pihole.clients"))} active clients`),
    kpiCard("Blocked today", num(m("pihole.blocked")), m("pihole.blocked_pct") != null ? `${m("pihole.blocked_pct").toFixed(1)}% of queries` : ""),
    kpiCard("DNS answer time", m("dns.ok") === 0 ? "NO ANSWER" : m("dns.ms") != null ? `${m("dns.ms").toFixed(0)} ms` : "-",
      "test lookup every minute", m("dns.ok") === 0 ? "text-err" : ""),
    kpiCard("Blocklists", num(m("pihole.domains")), m("pihole.gravity_days") != null ? `updated ${m("pihole.gravity_days").toFixed(0)} days ago` : ""),
  ].join("");
  fillTable("ph-up-body", phData.upstreams.map(u => `<tr><td class="text-cell">${escapeHtml(u.name || "-")}</td><td>${escapeHtml(u.ip || "-")}</td>
      <td>${u.count != null ? Number(u.count).toLocaleString() : u.share_pct != null ? `${u.share_pct}%` : "-"}</td>
      <td>${u.response_ms != null ? `${u.response_ms} ms` : "-"}</td></tr>`).join(""), "No upstreams reported yet.", 4);
  fillTable("ph-blocked-body", phData.blocked.map(b => `<tr><td class="text-cell">${escapeHtml(b.domain)}</td><td>${Number(b.count).toLocaleString()}</td></tr>`).join(""),
    "Nothing blocked yet today.", 2);
  const defs = [
    { id: "dns.ms", title: "DNS answer time", series: [["dns.ms", "Answer"]], fmt: "ms" },
    { id: "pihole.queries", title: "Queries today", series: [["pihole.queries", "Queries"], ["pihole.blocked", "Blocked"]], fmt: "int" },
    { id: "pihole.blocked_pct", title: "Share blocked", series: [["pihole.blocked_pct", "Blocked"]], fmt: "pct", max: 100 },
  ];
  const box = document.getElementById("ph-charts");
  box.innerHTML = defs.map((g, i) => `<div class="chart-card" data-title="Pi-hole ${escapeHtml(g.title)}"><div class="chart-title"><span>${escapeHtml(g.title)}</span><span class="dim">24h</span></div>
    <div class="chart-host" data-ph-chart="${i}"></div></div>`).join("");
  await Promise.all(defs.map((g, i) => drawDefinition(box.querySelector(`[data-ph-chart="${i}"]`), phData.device.id, g, 24)));
}

async function piholeBlocking(body, label) {
  try {
    phData = (await api("/api/pihole/blocking", { method: "POST", body })).pihole;
    showToast(label, "success");
    loadPiholePage();
  } catch (err) {
    showToast(err.message, "error");
  }
}

function initPiholePage() {
  document.getElementById("ph-actions").addEventListener("click", async ev => {
    const b = ev.target.closest("[data-ph-pause]");
    if (!b) return;
    const minutes = Number(b.dataset.phPause);
    if (!(await confirmDialog({ title: `Pause blocking for ${minutes} minutes?`, confirmLabel: "Pause",
      message: "Every device using the Pi-hole sees ads and trackers until blocking comes back on by itself. No alert is raised for a pause." }))) return;
    piholeBlocking({ enabled: false, minutes }, `Blocking paused for ${minutes} minutes`);
  });
  document.getElementById("btn-ph-resume").addEventListener("click", () => piholeBlocking({ enabled: true }, "Blocking is back on"));
}

document.addEventListener("DOMContentLoaded", () => {
  initWifiPage();
  initPiholePage();
  initLanSettings("pihole");
  initLanSettings("unifi");
  initMaintenance();
});
