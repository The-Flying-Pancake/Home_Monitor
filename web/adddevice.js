/* Add to monitoring: the "Scan the network" side of the Add window.
 *
 * Three kinds of target (the cards at the top): Ping, Device statistics (SNMP) and Service.
 * Ping and SNMP scan for hosts (ping and SNMP on every address); each host found can be added
 * as an SNMP device (with the template it was detected as) or as ping only, and a host without
 * SNMP starts as ping only. Service scans look for open TCP ports: the common services, a list
 * or ranges, or all 65,535 (slow; the hosts that are up are found first, open ports show as they
 * are found, and Stop keeps what was found). Everything ticked is added in one request
 * (POST /api/devices/bulk-add). The single-address form is app.js (setDeviceFormKind).
 */

let addScan = { job: null, timer: null, results: [], service: false };
let scanPortMode = "common";

const addKind = () => document.getElementById("modal-add-device").dataset.kind || "device";

const HOW_HELP = {
  ping: ["Pings it on every check: up or down, response time, availability.", "Finds every address that answers ping; add them as ping only, or with SNMP where they have it."],
  device: ["Asks the device over SNMP what it is and what it has.", "Pings every address and asks each one over SNMP what it is."],
  service: ["Watches one TCP port or web page.", "Looks for open ports on every address; each one found can become its own check."],
};

function syncAddHelp() {
  const scan = document.getElementById("modal-add-device").classList.contains("scan-mode");
  document.getElementById("add-how-help").textContent = HOW_HELP[addKind()][scan ? 1 : 0];
}

function addScanMode(on) {
  const modal = document.getElementById("modal-add-device");
  modal.classList.toggle("scan-mode", on);
  document.querySelectorAll("#add-how [data-how]").forEach(b => {
    const active = (b.dataset.how === "scan") === on;
    b.classList.toggle("active", active);
    b.setAttribute("aria-checked", String(active));
  });
  modal.querySelectorAll(".single-only").forEach(el => el.classList.toggle("hidden", on));
  modal.querySelectorAll(".scan-only").forEach(el => el.classList.toggle("hidden", !on));
  document.getElementById("add-scan").classList.toggle("hidden", !on);
  syncAddHelp();
  if (on) {
    const subnets = document.getElementById("scan-subnets");
    if (!subnets.value.trim()) {
      api("/api/setup/status").then(st => { if (st.default_subnet && !subnets.value.trim()) subnets.value = st.default_subnet; }).catch(() => {});
    }
  }
}

function addScanService() {
  return addKind() === "service";
}

function setScanPortMode(mode) {
  scanPortMode = mode;
  document.querySelectorAll("#scan-port-mode [data-port-mode]").forEach(b => {
    b.classList.toggle("active", b.dataset.portMode === mode);
    b.setAttribute("aria-checked", String(b.dataset.portMode === mode));
  });
  document.getElementById("scan-ports").classList.toggle("hidden", mode !== "custom");
  document.getElementById("scan-port-warn").classList.toggle("hidden", mode !== "all");
  document.getElementById("scan-port-help").textContent = {
    common: "About 80 ports that web interfaces, remote access, file sharing, databases, home automation and media servers use. Takes seconds.",
    custom: "Single ports and ranges, for example 22,80,443,8000-8100.",
    all: "Every port from 1 to 65535.",
  }[mode];
}

function resetAddScan() {
  if (addScan.timer) clearTimeout(addScan.timer);
  addScan = { job: null, timer: null, results: [], service: false };
  hide(document.getElementById("scan-results"));
  hide(document.getElementById("scan-progress"));
  hide(document.getElementById("btn-scan-stop"));
  document.getElementById("btn-scan-start").disabled = false;
}

async function startAddScan() {
  const service = addScanService();
  const subnets = document.getElementById("scan-subnets").value.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
  const body = { subnets };
  if (service) {
    body.ports = scanPortMode === "custom" ? document.getElementById("scan-ports").value.trim() : scanPortMode;
    if (!body.ports) { showToast("Enter the ports to look for, for example 80,443,8000-8100", "error"); return; }
    if (scanPortMode === "all" && !(await confirmDialog({ title: "Scan all 65,535 ports?",
      message: "This tries every port of every host that is up and can take a long time: about a minute per host on a quiet network, much longer with firewalls. Open ports show as they are found, and Stop keeps what was found.",
      confirmLabel: "Start the full scan" }))) return;
  } else {
    body.community = document.getElementById("scan-community").value.trim();
  }
  const btn = document.getElementById("btn-scan-start");
  btn.disabled = true;
  try {
    const r = await api("/api/devices/scan", { method: "POST", body });
    addScan = { job: r.id, timer: null, results: [], service };
    show(document.getElementById("scan-progress"));
    show(document.getElementById("btn-scan-stop"));
    hide(document.getElementById("scan-results"));
    document.getElementById("scan-status").textContent = `Scanning ${r.total} addresses...`;
    pollAddScan();
  } catch (err) {
    showToast(err.message, "error");
    btn.disabled = false;
  }
}

function scanStatusText(v) {
  const found = addScan.service ? `${v.results.reduce((a, r) => a + (r.open_ports || []).length, 0)} open ports on ${v.results.length} hosts`
    : `${v.results.length} found`;
  if (v.finished) return `${v.stopped ? "Stopped" : "Done"} after ${formatDuration(v.seconds)}: ${found} on ${v.subnet}`;
  if (v.phase === "live") return `Finding the hosts that are up (ping and common ports)... ${found}`;
  const eta = isNum(v.eta_seconds) && v.eta_seconds > 5 ? `, about ${formatDuration(v.eta_seconds)} left` : "";
  if (addScan.service) {
    const hosts = isNum(v.live_hosts) ? `${v.live_hosts} hosts up, ` : "";
    return `Scanning: ${hosts}${v.done.toLocaleString()} of ${v.total.toLocaleString()} connections tried, ${found}${eta}`;
  }
  return `Scanning... ${v.done} of ${v.total} addresses, ${found}`;
}

async function pollAddScan() {
  if (!addScan.job) return;
  try {
    const v = await api(`/api/devices/scan/${addScan.job}`);
    const pctDone = v.phase === "live" ? 3 : v.total ? Math.round(v.done * 100 / v.total) : 100;
    document.getElementById("scan-bar").style.width = `${v.finished ? 100 : pctDone}%`;
    document.getElementById("scan-status").textContent = scanStatusText(v);
    addScan.results = v.results;
    renderAddScan();
    if (!v.finished) addScan.timer = setTimeout(pollAddScan, 1000);
    else {
      document.getElementById("btn-scan-start").disabled = false;
      hide(document.getElementById("btn-scan-stop"));
    }
  } catch (err) {
    showToast(err.message, "error");
    document.getElementById("btn-scan-start").disabled = false;
  }
}

/** One row per host (devices) or per host and open port (services). Already monitored rows are shown, not ticked. */
function addScanRows() {
  if (!addScan.service) return addScan.results.map(r => ({ key: r.ip, ip: r.ip, port: 0, r, monitored: r.monitored }));
  return addScan.results.flatMap(r => (r.open_ports || []).map(p => ({
    key: `${r.ip}:${p}`, ip: r.ip, port: p, r, monitored: (r.monitored_ports || []).includes(p) })));
}

/** The template choice for a host found by a device scan: ping only first, then the SNMP templates. */
function monitorAsOptions(r) {
  const snmpOnes = profileOptionsHtml.replace(/<option value="(ping_only|service_check)">[^<]*<\/option>/g, "");
  return `<option value="${PING_PROFILE}">Ping only</option>${r.snmp ? `<optgroup label="SNMP template">${snmpOnes}</optgroup>`
    : `<optgroup label="SNMP (it did not answer SNMP)">${snmpOnes}</optgroup>`}`;
}

function renderAddScan() {
  const box = document.getElementById("scan-results");
  const rows = addScanRows();
  show(box);
  if (!rows.length) {
    box.innerHTML = `<div class="dim scan-empty">${addScan.service ? "No open ports found yet." : "No hosts found yet."}</div>`;
    updateAddScanButton();
    return;
  }
  const prev = {};
  box.querySelectorAll("[data-scan-key]").forEach(cb => {
    const tr = cb.closest("tr");
    prev[cb.dataset.scanKey] = { on: cb.checked, name: tr.querySelector("[data-scan-name]").value,
      profile: (tr.querySelector("[data-scan-profile]") || {}).value };
  });
  const pingKind = addKind() === "ping";
  box.innerHTML = `<div class="scan-bar-actions">
      <button type="button" class="btn btn-small" data-scan-all="1">Tick all new</button>
      ${addScan.service ? "" : `<button type="button" class="btn btn-small" data-scan-all="snmp">Tick those with SNMP</button>`}
      <button type="button" class="btn btn-small" data-scan-all="0">Clear</button>
    </div>
    <table class="scan-table"><thead><tr><th></th><th>Address</th>${addScan.service ? "<th>Port</th>" : "<th>Monitor as</th>"}<th>Name</th><th>Found</th></tr></thead><tbody>
    ${rows.map(x => {
      const p = prev[x.key];
      const name = p ? p.name : (addScan.service ? `${x.r.name || x.ip} ${PORT_NAMES[x.port] || x.port}` : (x.r.name || x.ip));
      const found = addScan.service ? (x.r.ping ? "ping, port open" : "port open")
        : [x.r.ping ? "ping" : "", x.r.snmp ? "SNMP" : ""].filter(Boolean).join(", ");
      return `<tr class="${x.monitored ? "dim" : ""}">
        <td><input type="checkbox" data-scan-key="${escapeHtml(x.key)}" data-has-snmp="${x.r.snmp ? 1 : 0}" ${x.monitored ? "disabled" : p && p.on ? "checked" : ""} aria-label="Add ${escapeHtml(x.key)}"></td>
        <td>${escapeHtml(x.ip)}</td>
        ${addScan.service ? `<td>${Number(x.port)}${PORT_NAMES[x.port] ? ` <span class="dim">${escapeHtml(PORT_NAMES[x.port])}</span>` : ""}</td>`
          : `<td><select data-scan-profile="${escapeHtml(x.key)}">${monitorAsOptions(x.r)}</select></td>`}
        <td><input type="text" data-scan-name="${escapeHtml(x.key)}" maxlength="128" value="${escapeHtml(name)}"></td>
        <td class="dim">${x.monitored ? "already monitored" : escapeHtml(found)}</td>
      </tr>`;
    }).join("")}</tbody></table>`;
  if (!addScan.service) {
    rows.forEach(x => {
      const sel = box.querySelector(`[data-scan-profile="${CSS.escape(x.key)}"]`);
      if (!sel) return;
      const p = prev[x.key];
      // Ping card: every host starts as ping only. SNMP card: the detected template, ping only without SNMP.
      sel.value = p && p.profile ? p.profile : pingKind || !x.r.snmp ? PING_PROFILE : (x.r.profile_id || "generic_device");
    });
  }
  updateAddScanButton();
}

// Common service names, to suggest a readable check name.
const PORT_NAMES = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "web", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
  389: "LDAP", 443: "web (HTTPS)", 445: "SMB", 548: "AFP", 554: "RTSP", 631: "printing", 873: "rsync", 993: "IMAPS", 1194: "OpenVPN",
  1433: "SQL Server", 1883: "MQTT", 2049: "NFS", 3000: "web 3000", 3306: "MySQL", 3389: "Remote Desktop", 5000: "web 5000",
  5001: "web 5001", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes", 7878: "web 7878", 8006: "Proxmox",
  8080: "web 8080", 8096: "Jellyfin", 8123: "Home Assistant", 8384: "Syncthing", 8443: "web 8443", 8989: "Sonarr",
  9000: "web 9000", 9090: "web 9090", 9100: "printer", 9443: "web 9443", 9696: "Prowlarr", 11434: "Ollama",
  25565: "Minecraft", 27017: "MongoDB", 32400: "Plex", 51413: "Transmission" };

function updateAddScanButton() {
  const n = document.querySelectorAll("#scan-results [data-scan-key]:checked").length;
  const btn = document.getElementById("btn-scan-add");
  btn.disabled = !n;
  btn.textContent = n ? `Add ${n} selected` : "Add selected";
}

async function addScanSelected() {
  const service = addScan.service;
  const devices = [...document.querySelectorAll("#scan-results [data-scan-key]:checked")].map(cb => {
    const key = cb.dataset.scanKey;
    const row = cb.closest("tr");
    const [ip, port] = service ? key.split(":") : [key, 0];
    return {
      ip_address: ip, hostname: row.querySelector("[data-scan-name]").value.trim() || key,
      profile_id: service ? SERVICE_PROFILE : row.querySelector("[data-scan-profile]").value,
      service_port: service ? Number(port) : undefined,
    };
  });
  if (!devices.length) return;
  const btn = document.getElementById("btn-scan-add");
  btn.disabled = true;
  try {
    const body = { devices };
    if (!service && document.getElementById("scan-community").value.trim()) body.community = document.getElementById("scan-community").value.trim();
    const r = await api("/api/devices/bulk-add", { method: "POST", body });
    showToast(`Added ${r.added.length}${r.skipped.length ? `, ${r.skipped.length} already monitored` : ""}. First checks started.`, "success");
    hide(document.getElementById("modal-add-device"));
    loadDevices();
  } catch (err) {
    showToast(`Could not add: ${err.message}`, "error");
    btn.disabled = false;
  }
}

function initAddDeviceScan() {
  const modal = document.getElementById("modal-add-device");
  document.getElementById("add-how").addEventListener("click", ev => {
    const b = ev.target.closest("[data-how]");
    if (b) addScanMode(b.dataset.how === "scan");
  });
  document.getElementById("scan-port-mode").addEventListener("click", ev => {
    const b = ev.target.closest("[data-port-mode]");
    if (b) setScanPortMode(b.dataset.portMode);
  });
  document.getElementById("btn-scan-start").addEventListener("click", startAddScan);
  document.getElementById("btn-scan-add").addEventListener("click", addScanSelected);
  document.getElementById("btn-scan-stop").addEventListener("click", async () => {
    if (!addScan.job) return;
    try { await api(`/api/devices/scan/${addScan.job}`, { method: "DELETE" }); } catch (err) { showToast(err.message, "error"); }
  });
  document.getElementById("scan-results").addEventListener("change", updateAddScanButton);
  document.getElementById("scan-results").addEventListener("click", ev => {
    const all = ev.target.closest("[data-scan-all]");
    if (!all) return;
    document.querySelectorAll("#scan-results [data-scan-key]:not(:disabled)").forEach(cb => {
      cb.checked = all.dataset.scanAll === "1" || (all.dataset.scanAll === "snmp" && cb.dataset.hasSnmp === "1");
      // Ticking those with SNMP also sets them to their detected template.
      if (all.dataset.scanAll === "snmp" && cb.checked) {
        const r = addScan.results.find(x => x.ip === cb.dataset.scanKey);
        const sel = cb.closest("tr").querySelector("[data-scan-profile]");
        if (r && sel) sel.value = r.profile_id || "generic_device";
      }
    });
    updateAddScanButton();
  });
  // Switching kind clears an earlier scan when its results are of the other sort (hosts or ports).
  document.getElementById("add-kind").addEventListener("click", ev => {
    const b = ev.target.closest("[data-kind]");
    if (!b) return;
    if ((b.dataset.kind === "service") !== addScan.service || !addScan.job) resetAddScan();
    else renderAddScan();
    syncAddHelp();
  });
  // Every time the window opens it starts with one SNMP device by address.
  document.getElementById("btn-open-add").addEventListener("click", () => {
    resetAddScan();
    setScanPortMode("common");
    addScanMode(false);
  });
  // Address and name fields of the single form hide in scan mode (CSS: .scan-mode .single-field).
  modal.querySelectorAll(".modal-body > .form-row-addr, .modal-body > .form-group, .modal-body > .form-row, .modal-body > .probe-box, .modal-body > .checkbox-label")
    .forEach(el => el.classList.add("single-field"));
}

document.addEventListener("DOMContentLoaded", initAddDeviceScan);
