/* Proxmox dashboard: nodes, guests, storage, backups and failed tasks from the Proxmox API.
 *
 * Switched on and connected under Settings, Proxmox (users with system settings permission;
 * the token secret is write-only). Off, the menu entry is hidden and nothing is fetched.
 * Data is cached on the server for 30 s and refreshed here every 30 s while the page is open.
 * Clicking a node or guest opens its history (CPU, memory, network, disk I/O) from Proxmox's
 * own RRD data for the last hour, day, week or month.
 */

let pveData = null;
let pveTimer = null;
let pveFilter = "";
let pveStatus = "all";
let pveOpen = null;             // {kind, node, vmid, title}: the row whose history is shown
let pveTimeframe = "hour";
const pveHistoryCache = {};     // "kind/node/vmid/timeframe" -> {at, points}

const PVE_TIMEFRAMES = [["hour", "Hour", 1], ["day", "Day", 24], ["week", "Week", 168], ["month", "Month", 720]];

const pvePct = (used, max) => (isNum(used) && isNum(max) && max > 0 ? (100 * used) / max : null);

/** Percentage bar with "used of total" below. Without a percentage: an empty meter (aligned with the
 * others) and, when known, the size alone below it (a VM's disk, a stopped guest's memory). */
function pveMeter(used, max, fmt = formatBytes, sizeOnly = null) {
  const p = pvePct(used, max);
  if (p === null) return emptyMeter() + (isNum(sizeOnly) && sizeOnly ? `<div class="dim pve-sub">${escapeHtml(fmt(sizeOnly))}</div>` : "");
  return `${barHtml(p, `${p.toFixed(0)}%`)}<div class="dim pve-sub">${escapeHtml(fmt(used))} of ${escapeHtml(fmt(max))}</div>`;
}

function pveStatusPill(s) {
  const cls = s === "running" || s === "online" || s === "available" ? "status-ok" : s === "stopped" ? "status-unknown" : "status-err";
  return `<span class="status-pill ${cls}">${escapeHtml(s || "unknown")}</span>`;
}

function pveDeviceLink(name, deviceId) {
  return deviceId ? `<a class="device-link" href="#/device/${Number(deviceId)}">${escapeHtml(name)}</a>` : `<strong>${escapeHtml(name)}</strong>`;
}

function pveTaskStatus(t) {
  if (!t.end) return `<span class="status-pill status-warn">running</span>`;
  return t.status === "OK" ? `<span class="status-pill status-ok">OK</span>` : `<span class="status-pill status-err" title="${escapeHtml(t.status || "")}">failed</span>`;
}

// --- Menu entry ---

/** Shows the Proxmox menu entry only when the feature is switched on and connected. */
async function refreshFeatures() {
  try {
    const f = await api("/api/features");
    document.getElementById("nav-proxmox").classList.toggle("hidden", !f.proxmox);
    document.getElementById("nav-inventory").classList.toggle("hidden", !f.inventory);
    document.getElementById("nav-wifi").classList.toggle("hidden", !f.wifi);
    document.getElementById("nav-pihole").classList.toggle("hidden", !f.pihole);
    // After the What's changed window, if it is open, so the two never stack.
    if (f.tls_prompt && typeof askHttps === "function") (window.changesDone || Promise.resolve()).then(askHttps);
    return f;
  } catch (err) {
    return {};
  }
}

// --- Page ---

/** Monitor (not yet a monitored device, address known) and, with the action token, start / shut down / reboot. */
function pveGuestButtons(g, actions) {
  if (g.template) return "";
  const key = `${g.node}/${g.vmid}`;
  let out = !g.device_id && (g.ips || []).length ? `<button type="button" class="btn btn-small" data-perm="devices.manage" data-pve-monitor="${escapeHtml(key)}">Monitor</button>` : "";
  if (actions && can("devices.manage")) {
    const b = (a, l) => `<button type="button" class="btn btn-small" data-pve-action="${escapeHtml(a)}" data-pve-guest="${escapeHtml(key)}">${escapeHtml(l)}</button>`;
    const more = g.status === "running" ? `${b("reboot", "Reboot")} ${b("shutdown", "Shut down")}` : b("start", "Start");
    out += (out ? " " : "") + more;
  }
  return out;
}

async function loadProxmox(force = false) {
  const body = document.getElementById("pve-body");
  try {
    pveData = await api(`/api/proxmox${force ? "?refresh=1" : ""}`);
  } catch (err) {
    body.innerHTML = `<div class="panel-note-bar warn">${escapeHtml(err.message)}</div>`;
    return;
  }
  renderProxmox();
  clearInterval(pveTimer);
  if (pveData.configured) {
    pveTimer = setInterval(() => {
      if (document.getElementById("view-proxmox").classList.contains("hidden")) { clearInterval(pveTimer); return; }
      api("/api/proxmox").then(d => { pveData = d; renderProxmox(); }).catch(() => {});
    }, 30000);
  }
}

const pveRowKey = (kind, node, vmid) => `${kind}/${node}/${vmid ?? ""}`;
const pveIsOpen = (kind, node, vmid) => pveOpen && pveRowKey(pveOpen.kind, pveOpen.node, pveOpen.vmid) === pveRowKey(kind, node, vmid);

/** The expandable history row under a node or guest. */
function pveHistoryRow(colspan) {
  return `<tr class="detail-row pve-history-row"><td colspan="${escapeHtml(colspan)}">
    <div class="pve-history-head"><strong>${escapeHtml(pveOpen.title)}</strong>
      <span class="seg">${PVE_TIMEFRAMES.map(([id, label]) =>
        `<button type="button" class="btn btn-small${id === pveTimeframe ? " active" : ""}" data-pve-tf="${escapeHtml(id)}">${escapeHtml(label)}</button>`).join("")}</span>
      <span class="dim">From Proxmox's own history (averages).</span></div>
    <div class="pve-charts">
      <div class="chart-card"><div class="chart-title">CPU</div><div class="chart-host" data-pve-chart="cpu"></div></div>
      <div class="chart-card"><div class="chart-title">Memory</div><div class="chart-host" data-pve-chart="mem"></div></div>
      <div class="chart-card"><div class="chart-title">Network</div><div class="chart-host" data-pve-chart="net"></div></div>
      <div class="chart-card"><div class="chart-title">Disk I/O</div><div class="chart-host" data-pve-chart="disk"></div></div>
    </div></td></tr>`;
}

async function drawPveHistory() {
  if (!pveOpen) return;
  const { kind, node, vmid } = pveOpen;
  const key = `${pveRowKey(kind, node, vmid)}/${pveTimeframe}`;
  const hosts = document.querySelectorAll("[data-pve-chart]");
  let points;
  try {
    const cached = pveHistoryCache[key];
    if (cached && Date.now() - cached.at < 60000) points = cached.points;
    else {
      const q = new URLSearchParams({ node, type: kind, timeframe: pveTimeframe });
      if (vmid !== null && vmid !== undefined) q.set("vmid", vmid);
      points = (await api(`/api/proxmox/rrd?${q}`)).points;
      pveHistoryCache[key] = { at: Date.now(), points };
    }
  } catch (err) {
    hosts.forEach(h => { h.innerHTML = `<div class="chart-empty">${escapeHtml(err.message)}</div>`; });
    return;
  }
  const hours = PVE_TIMEFRAMES.find(t => t[0] === pveTimeframe)[2];
  const series = (label, f) => ({ key: label, label, points: points.filter(p => isNum(f(p))).map(p => ({ timestamp: p.t, value: f(p) })) });
  const draw = (name, list, opts) => {
    const host = document.querySelector(`[data-pve-chart="${name}"]`);
    if (host) lineChart(host, list, Object.assign({ hours }, opts));
  };
  draw("cpu", [series("CPU", p => (isNum(p.cpu) ? p.cpu * 100 : null))], { fmt: FMT.pct, max: 100 });
  draw("mem", [series("Used", p => p.mem)].concat(points.some(p => isNum(p.maxmem)) ? [series("Total", p => p.maxmem)] : []), { fmt: v => formatBytes(v) });
  draw("net", [series("In", p => (isNum(p.netin) ? p.netin * 8 : null)), series("Out", p => (isNum(p.netout) ? p.netout * 8 : null))], { fmt: formatBps });
  draw("disk", [series("Read", p => p.diskread), series("Write", p => p.diskwrite)], { fmt: FMT.Bps });
}

function renderProxmox() {
  const d = pveData;
  const body = document.getElementById("pve-body");
  const updated = document.getElementById("pve-updated");
  if (!d.configured) {
    body.innerHTML = `<div class="panel-note-bar">Proxmox is switched off or not connected.${can("settings.system") ? ` <a href="#/settings/proxmox">Settings, Proxmox</a>` : " A user with system settings permission can switch it on under Settings, Proxmox."}</div>`;
    updated.textContent = "";
    return;
  }
  if (d.error) {
    body.innerHTML = `<div class="panel-note-bar warn">${escapeHtml(d.error)}${can("settings.system") ? ` <a href="#/settings/proxmox">Check the connection</a>` : ""}</div>`;
    updated.textContent = "";
    return;
  }
  updated.textContent = `Proxmox VE ${d.version || ""}, updated ${formatAgo(d.fetched_at)}`;
  const guests = d.guests.filter(g => !g.template);
  const running = guests.filter(g => g.status === "running").length;
  const nodesUp = d.nodes.filter(n => n.status === "online").length;
  const stTotal = d.storage.reduce((a, s) => a + (s.maxdisk || 0), 0), stUsed = d.storage.reduce((a, s) => a + (s.disk || 0), 0);
  const failedBackups = d.backups.filter(t => t.end && t.status !== "OK").length;
  const tile = (n, l, cls = "") => `<div class="stat ${escapeHtml(cls)}"><div class="stat-num">${escapeHtml(n)}</div><div class="stat-label">${escapeHtml(l)}</div></div>`;
  const q = pveFilter.toLowerCase();
  const shownGuests = d.guests.filter(g => (pveStatus === "all" || g.status === pveStatus) &&
    (!q || `${g.vmid} ${g.name} ${g.node} ${(g.tags || []).join(" ")}`.toLowerCase().includes(q)));
  const caret = open => `<span class="pve-caret" aria-hidden="true">${open ? "▾" : "▸"}</span>`;

  const nodeRow = n => {
    const open = pveIsOpen("node", n.node, null);
    return `<tr class="clickable-row" data-pve-open="node" data-node="${escapeHtml(n.node)}" title="Show history">
        <td class="text-cell">${caret(open)}${pveDeviceLink(n.node, n.device_id)}${n.cpu_model ? `<div class="dim pve-sub">${escapeHtml(n.cpu_model)}</div>` : ""}</td>
        <td>${pveStatusPill(n.status)}</td>
        <td class="bar-cell">${barHtml(isNum(n.cpu) ? n.cpu * 100 : null)}<div class="dim pve-sub">${escapeHtml(n.maxcpu ? `${n.maxcpu} CPUs` : "")}</div></td>
        <td class="bar-cell">${pveMeter(n.mem, n.maxmem)}</td>
        <td class="bar-cell">${pveMeter(n.disk, n.maxdisk)}</td>
        <td>${escapeHtml((n.loadavg || []).join("  ") || "-")}</td>
        <td>${isNum(n.uptime) ? escapeHtml(formatDuration(n.uptime)) : "-"}</td>
        <td class="dim" title="${escapeHtml(n.pveversion || "")}">${escapeHtml(((n.pveversion || "").match(/pve-manager\/([\d.]+)/) || [])[1] || n.pveversion || "")}</td></tr>${open ? pveHistoryRow(8) : ""}`;
  };
  const guestRow = g => {
    const open = pveIsOpen(g.type, g.node, g.vmid);
    return `<tr class="clickable-row${g.template ? " dim" : ""}" data-pve-open="${escapeHtml(g.type)}" data-node="${escapeHtml(g.node)}" data-vmid="${Number(g.vmid)}" title="Show history">
        <td>${caret(open)}${Number(g.vmid)}</td>
        <td class="text-cell">${pveDeviceLink(g.name || `#${g.vmid}`, g.device_id)}${g.template ? ' <span class="ack-tag">template</span>' : ""}</td>
        <td>${g.type === "lxc" ? "Container" : "VM"}</td>
        <td>${escapeHtml(g.node)}</td>
        <td>${pveStatusPill(g.status)}</td>
        <td class="bar-cell">${barHtml(g.status === "running" && isNum(g.cpu) ? g.cpu * 100 : null)}<div class="dim pve-sub">${escapeHtml(g.maxcpu ? `${g.maxcpu} cores` : "")}</div></td>
        <td class="bar-cell">${g.status === "running" ? pveMeter(g.mem, g.maxmem, formatBytes, g.maxmem) : pveMeter(null, null, formatBytes, g.maxmem)}</td>
        <td class="bar-cell"${g.type === "qemu" ? ' title="Proxmox sees only the size given to a VM disk, not how full it is (that needs the guest agent inside the VM)."' : ""}>${g.type === "lxc" && g.maxdisk ? pveMeter(g.disk, g.maxdisk) : pveMeter(null, null, formatBytes, g.maxdisk)}</td>
        <td>${g.status === "running" && isNum(g.uptime) ? escapeHtml(formatDuration(g.uptime)) : "-"}</td>
        <td class="text-cell">${(g.tags || []).map(t => `<span class="ack-tag">${escapeHtml(t)}</span>`).join(" ")}</td>
        <td class="actions-cell">${pveGuestButtons(g, d.actions)}</td></tr>${open ? pveHistoryRow(11) : ""}`;
  };

  body.innerHTML = `
    <div class="stat-row pve-tiles">
      ${tile(`${nodesUp} / ${d.nodes.length}`, "Nodes online", nodesUp < d.nodes.length ? "stat-bad" : "stat-ok")}
      ${tile(`${running} / ${guests.length}`, "Guests running")}
      ${tile(stTotal ? `${((100 * stUsed) / stTotal).toFixed(0)}%` : "-", "Storage used")}
      ${tile(String(failedBackups), "Failed backups (recent)", failedBackups ? "stat-bad" : "")}
      ${tile(String(d.failed_tasks.length), "Failed tasks (recent)", d.failed_tasks.length ? "stat-warn" : "")}
    </div>
    ${!d.actions && can("settings.system") ? `<div class="panel-note-bar">Start, shut down and reboot guests from here, and take snapshots before updates in a workflow:
      add a token that may make changes in <a href="#/settings/proxmox">Settings, Proxmox, Actions</a>. The token in use only reads.</div>` : ""}
    <div class="panel"><div class="panel-header-bar">Nodes <span class="dim pve-hint">Click a row for its history</span></div>
      <table><thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Root disk</th><th>Load</th><th>Uptime</th><th>Version</th></tr></thead>
      <tbody>${d.nodes.map(nodeRow).join("") || `<tr><td colspan="8" class="empty-cell">No nodes.</td></tr>`}</tbody></table></div>
    <div class="panel"><div class="panel-header-bar pve-guest-head">Virtual machines and containers
        <span class="pve-guest-tools">
          <input type="search" id="pve-filter" class="filter-input" placeholder="Filter by name, ID, node or tag..." value="${escapeHtml(pveFilter)}">
          <select id="pve-status"><option value="all">All</option><option value="running">Running</option><option value="stopped">Stopped</option></select>
        </span></div>
      <table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th><th>Uptime</th><th>Tags</th><th></th></tr></thead>
      <tbody>${shownGuests.map(guestRow).join("")
        || `<tr><td colspan="11" class="empty-cell">${d.guests.length ? "No guests match." : "No guests."}</td></tr>`}</tbody></table></div>
    <div class="grid-2">
      <div class="panel"><div class="panel-header-bar">Storage</div>
        <table><thead><tr><th>Storage</th><th>Node</th><th>Type</th><th>Status</th><th>Used</th></tr></thead>
        <tbody>${d.storage.map(s => `<tr><td class="text-cell"><strong>${escapeHtml(s.storage)}</strong>${s.shared ? ' <span class="ack-tag">shared</span>' : ""}</td>
          <td>${escapeHtml(s.node)}</td><td>${escapeHtml(s.type || "")}</td><td>${pveStatusPill(s.status)}</td>
          <td class="bar-cell">${pveMeter(s.disk, s.maxdisk)}</td></tr>`).join("") || `<tr><td colspan="5" class="empty-cell">No storage.</td></tr>`}</tbody></table></div>
      <div class="panel"><div class="panel-header-bar">Recent backups</div>
        <table><thead><tr><th>Started</th><th>Guest</th><th>Node</th><th>Status</th><th>Took</th></tr></thead>
        <tbody>${d.backups.map(t => `<tr><td>${escapeHtml(formatTime(t.start))}</td><td>${escapeHtml(t.id || "all")}</td><td>${escapeHtml(t.node)}</td>
          <td>${pveTaskStatus(t)}</td><td>${t.end ? escapeHtml(formatDuration(t.end - t.start)) : "-"}</td></tr>`).join("")
          || `<tr><td colspan="5" class="empty-cell">No backup tasks in the recent task list.</td></tr>`}</tbody></table></div>
    </div>
    ${d.failed_tasks.length ? `<div class="panel"><div class="panel-header-bar">Failed tasks</div>
      <table><thead><tr><th>When</th><th>Task</th><th>Target</th><th>Node</th><th>User</th><th>Result</th></tr></thead>
      <tbody>${d.failed_tasks.map(t => `<tr><td>${escapeHtml(formatTime(t.start))}</td><td>${escapeHtml(t.type)}</td><td>${escapeHtml(t.id || "")}</td>
        <td>${escapeHtml(t.node)}</td><td>${escapeHtml(t.user || "")}</td><td class="text-cell">${escapeHtml(t.status || "")}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
  document.getElementById("pve-status").value = pveStatus;
  drawPveHistory();
}

// --- Settings, Proxmox ---

let pveConfig = null;

async function loadPveSettings() {
  try {
    pveConfig = await api("/api/proxmox/config");
  } catch (err) {
    pveSay(err.message, "text-err");
    return;
  }
  renderPveSettings(true);
}

function pveSay(text, kind = "") {
  const msg = document.getElementById("pve-config-msg");
  msg.textContent = text;
  msg.className = `form-help ${kind}`;
}

/** The switch, and the connection form under it only while it is on. */
function renderPveSettings(fill) {
  const c = pveConfig || {};
  const sel = document.getElementById("pve-enabled");
  sel.value = c.enabled ? "on" : "off";
  sel.disabled = !can("settings.system");
  document.getElementById("pve-config").classList.toggle("hidden", !c.enabled);
  document.getElementById("pve-enabled-help").textContent = !c.enabled
    ? "Connects with a read-only API token. Nothing is fetched while it is off."
    : c.configured ? "On: Proxmox has its own page in the menu." : "On: connect it below. The page appears in the menu once the connection is saved.";
  document.getElementById("btn-pve-disconnect").classList.toggle("hidden", !c.configured);
  if (!fill) return;
  document.getElementById("pve-url").value = c.url || "";
  document.getElementById("pve-token").value = c.token_id || "";
  document.getElementById("pve-secret").value = "";
  document.getElementById("pve-secret").placeholder = c.secret_set ? "Stored and hidden: leave empty to keep" : "The token secret Proxmox showed once";
  document.getElementById("pve-fp").value = c.fingerprint || "";
  document.getElementById("pve-act-token").value = c.action_token_id || "";
  document.getElementById("pve-act-secret").value = "";
  document.getElementById("pve-act-secret").placeholder = c.action_secret_set ? "Stored and hidden: leave empty to keep" : "";
  document.getElementById("btn-pve-act-remove").classList.toggle("hidden", !c.action_token_id);
}

function pveFormPayload() {
  return {
    url: document.getElementById("pve-url").value.trim(),
    token_id: document.getElementById("pve-token").value.trim(),
    secret: document.getElementById("pve-secret").value.trim(),
    fingerprint: document.getElementById("pve-fp").value.trim(),
  };
}

async function pveSaved(r) {
  pveConfig = r.config;
  renderPveSettings(true);
  await refreshFeatures();
}

async function savePveActionToken(remove) {
  try {
    const body = remove ? { remove: true } : { token_id: document.getElementById("pve-act-token").value.trim(),
      secret: document.getElementById("pve-act-secret").value.trim() };
    const r = await api("/api/proxmox/actions", { method: "PUT", body });
    pveSay(remove ? "Action token removed: the Proxmox page only reads again." : r.actions ? "Action token saved: Start, Shut down and Reboot appear on the Proxmox page." : "Saved.", "text-ok");
    await loadPveSettings();
  } catch (err) {
    pveSay(err.message, "text-err");
  }
}

function initProxmox() {
  document.getElementById("btn-pve-act-save").addEventListener("click", () => savePveActionToken(false));
  document.getElementById("btn-pve-act-remove").addEventListener("click", () => savePveActionToken(true));
  document.getElementById("btn-pve-refresh").addEventListener("click", () => loadProxmox(true));
  document.getElementById("pve-enabled").addEventListener("change", async ev => {
    const on = ev.target.value === "on";
    try {
      await pveSaved(await api("/api/proxmox/config", { method: "PUT", body: { enabled: on } }));
      pveSay(on ? "" : "Switched off. The connection is kept for when you switch it back on; Disconnect removes it.", "");
    } catch (err) {
      ev.target.value = on ? "off" : "on";
      pveSay(err.message, "text-err");
    }
  });
  document.getElementById("btn-pve-fetchfp").addEventListener("click", async ev => {
    ev.target.disabled = true;
    try {
      const r = await api("/api/proxmox/fingerprint", { method: "POST", body: { url: document.getElementById("pve-url").value.trim() } });
      document.getElementById("pve-fp").value = r.fingerprint;
      pveSay(`The host presented ${r.fingerprint}. Compare it with the Proxmox GUI (the node, System, Certificates, pve-ssl.pem) before saving.`, "text-warn");
    } catch (err) { pveSay(err.message, "text-err"); } finally { ev.target.disabled = false; }
  });
  document.getElementById("btn-pve-test").addEventListener("click", async ev => {
    ev.target.disabled = true;
    try {
      const r = await api("/api/proxmox/test", { method: "POST", body: pveFormPayload() });
      pveSay(`Connected: Proxmox VE ${r.version}. The token sees ${r.nodes} node${r.nodes === 1 ? "" : "s"}, ${r.guests} VMs and containers, ${r.storage} storage.`, "text-ok");
    } catch (err) { pveSay(err.message, "text-err"); } finally { ev.target.disabled = false; }
  });
  document.getElementById("pve-config").addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      await pveSaved(await api("/api/proxmox/config", { method: "PUT", body: pveFormPayload() }));
      pveSay("Saved. Proxmox is in the menu.", "text-ok");
    } catch (err) { pveSay(err.message, "text-err"); }
  });
  document.getElementById("btn-pve-disconnect").addEventListener("click", async () => {
    if (!(await confirmDialog({ title: "Disconnect Proxmox?", message: "The address, token and pinned certificate are removed from the monitor and the page leaves the menu. The token itself stays in Proxmox until you delete it there.",
      confirmLabel: "Disconnect", danger: true }))) return;
    try {
      await pveSaved(await api("/api/proxmox/config", { method: "PUT", body: { disconnect: true } }));
      pveSay("Disconnected.", "");
    } catch (err) { pveSay(err.message, "text-err"); }
  });

  const body = document.getElementById("pve-body");
  body.addEventListener("input", ev => {
    if (ev.target.id !== "pve-filter") return;
    pveFilter = ev.target.value;
    const pos = ev.target.selectionStart;
    renderProxmox();
    const el = document.getElementById("pve-filter");
    el.focus();
    el.setSelectionRange(pos, pos);
  });
  body.addEventListener("change", ev => {
    if (ev.target.id === "pve-status") { pveStatus = ev.target.value; renderProxmox(); }
  });
  body.addEventListener("click", async ev => {
    const mon = ev.target.closest("[data-pve-monitor]");
    if (mon) {
      const g = pveData.guests.find(x => `${x.node}/${x.vmid}` === mon.dataset.pveMonitor);
      openAddPrefilled((g.ips || [])[0], g.name, `From Proxmox: <strong>${escapeHtml(g.name || `#${g.vmid}`)}</strong>, `
        + `${g.type === "lxc" ? "container" : "VM"} ${Number(g.vmid)} on ${escapeHtml(g.node)}.`);
      return;
    }
    const act = ev.target.closest("[data-pve-action]");
    if (act) {
      const g = pveData.guests.find(x => `${x.node}/${x.vmid}` === act.dataset.pveGuest);
      const what = { start: "Start", shutdown: "Shut down", reboot: "Reboot" }[act.dataset.pveAction];
      if (!(await confirmDialog({ title: `${what} ${g.name || `#${g.vmid}`}?`, confirmLabel: what, danger: act.dataset.pveAction !== "start",
        message: act.dataset.pveAction === "start" ? "Proxmox starts the guest." : "Proxmox asks the guest to shut down cleanly"
          + (act.dataset.pveAction === "reboot" ? " and start again." : ". It stays off until someone starts it.") }))) return;
      act.disabled = true;
      try {
        await api("/api/proxmox/guest", { method: "POST", body: { node: g.node, type: g.type, vmid: g.vmid, action: act.dataset.pveAction } });
        showToast(`${what}: sent to Proxmox. The list updates within half a minute.`, "success");
        setTimeout(() => loadProxmox(true), 4000);
      } catch (err) {
        showToast(err.message, "error");
        act.disabled = false;
      }
      return;
    }
    const tf = ev.target.closest("[data-pve-tf]");
    if (tf) { pveTimeframe = tf.dataset.pveTf; renderProxmox(); return; }
    // Links inside a row (to the monitored device) keep working; the rest of the row opens its history.
    if (ev.target.closest("a, button, input, select")) return;
    const row = ev.target.closest("tr[data-pve-open]");
    if (!row) return;
    const kind = row.dataset.pveOpen, node = row.dataset.node;
    const vmid = row.dataset.vmid ? Number(row.dataset.vmid) : null;
    if (pveIsOpen(kind, node, vmid)) pveOpen = null;
    else {
      const g = vmid === null ? null : pveData.guests.find(x => x.vmid === vmid && x.node === node);
      pveOpen = { kind, node, vmid, title: g ? `${g.name || `#${vmid}`} (${vmid})` : `Node ${node}` };
    }
    renderProxmox();
  });
}

document.addEventListener("DOMContentLoaded", initProxmox);
