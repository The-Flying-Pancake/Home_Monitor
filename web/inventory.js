/* Inventory page (inventory.py): every hardware address seen on the network, new ones first.
 * The administrator's name, note, location and purchase date are edited in a window; "known" ends the
 * "new" mark. Relies on app.js helpers (api, escapeHtml, showToast, confirmDialog, can, fillTable,
 * formatAgo).
 */

let invData = { rows: [] };

/** The API path for one address. Dashes, not colons: an encoded colon (%3A) matched no route, so
 * Edit, Known and Forget failed with "Endpoint not found". */
function invPath(mac) {
  return `/api/inventory/${String(mac).replace(/:/g, "-")}`;
}

async function loadInventory() {
  try {
    invData = await api("/api/inventory");
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  const learn = document.getElementById("inv-learning");
  learn.classList.toggle("hidden", !invData.learning_until);
  if (invData.learning_until) {
    learn.textContent = `Learning the network until ${new Date(invData.learning_until * 1000).toLocaleString()}: what is seen until then is recorded quietly as known. After that a new device is announced (event, bell and Telegram).`;
  }
  renderInventory();
}

function invMatches(r, q, show, now) {
  // Quiet devices (marked quiet, or on a quiet network) only show when asked for.
  if (show === "quiet" ? !r.hushed : show !== "all" && r.hushed) return false;
  if (show === "new" && r.known) return false;
  if (show === "unmonitored" && r.device_id) return false;
  if (show === "wifi" && r.via !== "wifi") return false;
  if (show === "cable" && r.via !== "cable") return false;
  if (show === "gone" && now - r.last_seen < 30 * 86400) return false;
  if (!q) return true;
  return [r.name, r.seen_name, r.device_name, r.mac, r.ip, r.vendor, r.note, r.location, r.where_seen, r.ssid]
    .some(v => String(v || "").toLowerCase().includes(q));
}

function renderInventory() {
  const q = document.getElementById("inv-q").value.trim().toLowerCase();
  const show = document.getElementById("inv-show").value;
  const rows = invData.rows.filter(r => invMatches(r, q, show, invData.now));
  const fresh = invData.rows.filter(r => !r.known && !r.hushed).length;
  const hushed = invData.rows.filter(r => r.hushed).length;
  document.getElementById("inv-count").textContent = `${rows.length} of ${invData.rows.length}${fresh ? `, ${fresh} new` : ""}`
    + (hushed && show !== "quiet" && show !== "all" ? `, ${hushed} quiet not shown` : "");
  document.getElementById("btn-inv-known").classList.toggle("hidden", !fresh || !can("devices.manage"));
  fillTable("inventory-body", rows.map(r => {
    const title = r.name || r.device_name || r.seen_name || "";
    const sub = [r.name && r.seen_name && r.seen_name !== r.name ? `reports itself as ${r.seen_name}` : "", r.location, r.note,
      r.wifi_alert === "off" ? "weak Wi-Fi not reported" : r.wifi_alert !== "" ? `weak Wi-Fi below ${r.wifi_alert} dBm` : ""].filter(Boolean).join(" · ");
    const pill = r.hushed ? `<span class="status-pill status-unknown" title="${escapeHtml(r.quiet_net ? `On the quiet network ${r.ssid}` : "Marked quiet")}: kept, never announced">quiet</span> `
      : r.known ? "" : '<span class="status-pill status-warn">new</span> ';
    return `<tr class="${r.known || r.hushed ? "" : "inv-new"}">
      <td class="text-cell">${pill}<strong>${escapeHtml(title || "Unnamed")}</strong>
        ${r.device_id ? `<a class="dim" href="#/device/${escapeHtml(r.device_id)}">monitored</a>` : ""}${sub ? `<div class="dim inv-sub">${escapeHtml(sub)}</div>` : ""}</td>
      <td class="mono-cell">${escapeHtml(r.mac)}${r.private ? ' <span class="dim" title="A private (randomised) address: phones and laptops use these to hide their real one">private</span>' : ""}</td>
      <td class="mono-cell">${escapeHtml(r.ip || "-")}</td>
      <td class="text-cell">${escapeHtml(r.where_seen || "-")}</td>
      <td class="text-cell">${r.ssid ? escapeHtml(r.ssid) : '<span class="dim">-</span>'}</td>
      <td class="text-cell">${escapeHtml(r.vendor || "-")}</td>
      <td data-sort="${escapeHtml(r.first_seen)}" class="dim">${escapeHtml(formatAgo(r.first_seen))}</td>
      <td data-sort="${escapeHtml(r.last_seen)}" class="dim">${escapeHtml(formatAgo(r.last_seen))}</td>
      <td class="actions-cell">${!r.known && !r.hushed ? `<button type="button" class="btn btn-small" data-perm="devices.manage" data-inv-known="${escapeHtml(r.mac)}" title="Known: no longer new (works while it is offline too)">Known</button> ` : ""}${!r.device_id && r.ip ? `<button type="button" class="btn btn-small" data-perm="devices.manage" data-inv-monitor="${escapeHtml(r.mac)}">Monitor</button> ` : ""}<button type="button" class="btn btn-small" data-perm="devices.manage" data-inv-edit="${escapeHtml(r.mac)}">Edit</button></td>
    </tr>`;
  }).join(""), invData.rows.length ? "Nothing matches." : "Nothing seen yet: the inventory fills as the switches and the gateway are polled.", 9);
}

function editInventory(mac) {
  const r = invData.rows.find(x => x.mac === mac);
  if (!r) return;
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog inv-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>${escapeHtml(r.name || r.seen_name || r.mac)}</span></div>
    <div class="modal-body">
      <table class="kv-table"><tbody>
        <tr><td>MAC address</td><td>${escapeHtml(r.mac)}${r.private ? " (private, randomised)" : ""}</td></tr>
        <tr><td>IP address</td><td>${escapeHtml(r.ip || "-")}</td></tr>
        <tr><td>Connected</td><td>${escapeHtml(r.where_seen || "-")}</td></tr>
        ${r.ssid ? `<tr><td>Wi-Fi network</td><td>${escapeHtml(r.ssid)}${r.quiet_net ? " (a quiet network)" : ""}</td></tr>` : ""}
        <tr><td>Maker</td><td>${escapeHtml(r.vendor || "-")}</td></tr>
        <tr><td>Reports itself as</td><td>${escapeHtml(r.seen_name || "-")}</td></tr>
        <tr><td>First seen</td><td>${escapeHtml(new Date(r.first_seen * 1000).toLocaleString())}</td></tr>
      </tbody></table>
      <div class="form-row">
        <div class="form-group"><label for="inv-name">Name</label><input type="text" id="inv-name" maxlength="60" value="${escapeHtml(r.name)}" placeholder="${escapeHtml(r.seen_name || "Kitchen speaker")}"></div>
        <div class="form-group"><label for="inv-location">Location</label><input type="text" id="inv-location" maxlength="60" value="${escapeHtml(r.location)}"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label for="inv-purchased">Bought on</label><input type="date" id="inv-purchased" value="${escapeHtml(r.purchased)}"></div>
        <div class="form-group"><label class="checkbox-label"><input type="checkbox" id="inv-known"${r.known ? " checked" : ""}> Known (not new)</label>
          <label class="checkbox-label" title="Kept and kept up to date, but never announced or counted as new, and hidden from the list unless you ask"><input type="checkbox" id="inv-quiet"${r.quiet ? " checked" : ""}> Quiet${r.quiet_net ? " (its network is quiet anyway)" : ""}</label></div>
      </div>
      ${invWifiAlertHtml(r)}
      <div class="form-group"><label for="inv-note">Note</label><textarea id="inv-note" rows="3" maxlength="500">${escapeHtml(r.note)}</textarea></div>
      <div class="form-error hidden" data-err></div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn btn-danger" data-forget title="Remove it from the inventory; it is added again (as new) if it shows up">Forget</button>
      <span class="topbar-spacer"></span>
      <button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Save</button>
    </div></form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  invWifiAlertWire(form);
  const fail = err => { const e = form.querySelector("[data-err]"); e.textContent = err.message; e.classList.remove("hidden"); };
  form.querySelector("[data-x]").addEventListener("click", () => back.remove());
  back.addEventListener("keydown", ev => { if (ev.key === "Escape") back.remove(); });
  form.querySelector("[data-forget]").addEventListener("click", async () => {
    if (!(await confirmDialog({ title: "Forget this address?", message: "If it is seen again it comes back as a new device.", confirmLabel: "Forget", danger: true }))) return;
    try {
      await api(invPath(r.mac), { method: "DELETE" });
      back.remove();
      loadInventory();
    } catch (err) { fail(err); }
  });
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      await api(invPath(r.mac), { method: "PUT", body: {
        name: form.querySelector("#inv-name").value, location: form.querySelector("#inv-location").value,
        purchased: form.querySelector("#inv-purchased").value, note: form.querySelector("#inv-note").value,
        known: form.querySelector("#inv-known").checked, quiet: form.querySelector("#inv-quiet").checked, ...invWifiAlertValue(form) } });
      back.remove();
      loadInventory();
    } catch (err) { fail(err); }
  });
  form.querySelector("#inv-name").focus();
}

/** Weak Wi-Fi signal, per device: as usual, only below a line of its own, or never. Shown for
 * Wi-Fi devices (and any that already have a rule); the line input only with "its own line". */
function invWifiAlertHtml(r) {
  if (r.via !== "wifi" && r.wifi_alert === "") return "";
  const usual = invData.weak_dbm ?? -75;
  const mode = r.wifi_alert === "off" ? "off" : r.wifi_alert === "" ? "" : "line";
  const line = mode === "line" ? r.wifi_alert : Math.max(-95, usual - 10);
  return `<div class="form-group inv-wifi-alert">
    <label for="inv-wifi-alert">Weak Wi-Fi signal</label>
    <div class="form-row">
      <select id="inv-wifi-alert">
        <option value=""${mode === "" ? " selected" : ""}>Report it as usual (below ${escapeHtml(usual)} dBm)</option>
        <option value="line"${mode === "line" ? " selected" : ""}>Report it only below a line of its own</option>
        <option value="off"${mode === "off" ? " selected" : ""}>Never report it</option>
      </select>
      <span class="inv-wifi-line${mode === "line" ? "" : " hidden"}"><input type="number" id="inv-wifi-line" min="-95" max="-40" step="1" value="${escapeHtml(line)}"> dBm</span>
    </div>
    <div class="dim form-hint">For a device that is always weak: the access point's weak-signal problem (and its Telegram message) leaves it out, or waits for its own line. It still shows on the Wi-Fi page.</div>
  </div>`;
}

function invWifiAlertWire(form) {
  const sel = form.querySelector("#inv-wifi-alert");
  if (sel) sel.addEventListener("change", () => form.querySelector(".inv-wifi-line").classList.toggle("hidden", sel.value !== "line"));
}

function invWifiAlertValue(form) {
  const sel = form.querySelector("#inv-wifi-alert");
  if (!sel) return {};
  return { wifi_alert: sel.value === "line" ? form.querySelector("#inv-wifi-line").value : sel.value };
}

/** Monitor: the Add window with what the inventory knows filled in. What it is (ping, SNMP, a
 * service) is not known yet, so it starts on Ping, which suits anything, and the user chooses;
 * Test shows what answers before anything is added. */
function monitorFromInventory(mac) {
  const r = invData.rows.find(x => x.mac === mac);
  if (!r || !r.ip) return;
  const what = [r.vendor && `made by ${r.vendor}`, r.where_seen && `on ${r.where_seen}`].filter(Boolean).join(", ");
  openAddPrefilled(r.ip, r.name || r.seen_name || "",
    `From the Inventory: <strong>${escapeHtml(r.name || r.seen_name || r.mac)}</strong>${what ? `, ${escapeHtml(what)}` : ""}.`);
}

/** Add a device by MAC, as known: for something that is offline now, or not seen yet. */
function addInventoryDevice() {
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog inv-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Add a device</span></div>
    <div class="modal-body">
      <p class="dim">It goes in as known, so it is never announced as new when it shows up. It does not need to be online.</p>
      <div class="form-row">
        <div class="form-group"><label for="inv-add-mac">MAC address</label><input type="text" id="inv-add-mac" maxlength="17" placeholder="aa:bb:cc:dd:ee:ff" required></div>
        <div class="form-group"><label for="inv-add-name">Name</label><input type="text" id="inv-add-name" maxlength="60" placeholder="Kitchen speaker"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label for="inv-add-location">Location</label><input type="text" id="inv-add-location" maxlength="60"></div>
        <div class="form-group"><label class="checkbox-label"><input type="checkbox" id="inv-add-quiet"> Quiet (kept, never announced)</label></div>
      </div>
      <div class="form-group"><label for="inv-add-note">Note</label><textarea id="inv-add-note" rows="2" maxlength="500"></textarea></div>
      <div class="form-error hidden" data-err></div>
    </div>
    <div class="modal-footer"><span class="topbar-spacer"></span>
      <button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Add</button></div></form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  form.querySelector("[data-x]").addEventListener("click", () => back.remove());
  back.addEventListener("keydown", ev => { if (ev.key === "Escape") back.remove(); });
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      await api("/api/inventory", { method: "POST", body: { mac: form.querySelector("#inv-add-mac").value, name: form.querySelector("#inv-add-name").value,
        location: form.querySelector("#inv-add-location").value, note: form.querySelector("#inv-add-note").value,
        quiet: form.querySelector("#inv-add-quiet").checked } });
      back.remove();
      showToast("Added, as known", "success");
      loadInventory();
    } catch (err) {
      const e = form.querySelector("[data-err]"); e.textContent = err.message; e.classList.remove("hidden");
    }
  });
  form.querySelector("#inv-add-mac").focus();
}

/** Quiet Wi-Fi networks: their devices are kept but never announced or counted as new. */
function editQuietNetworks() {
  const nets = (invData.ssids || []).map(s => s.ssid);
  (invData.quiet_ssids || []).forEach(q => { if (!nets.some(n => n.toLowerCase() === q.toLowerCase())) nets.push(q); });
  const quiet = new Set((invData.quiet_ssids || []).map(q => q.toLowerCase()));
  const count = s => Number((invData.ssids || []).find(x => x.ssid === s)?.count || 0);
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog inv-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Quiet Wi-Fi networks</span></div>
    <div class="modal-body">
      <p class="dim">Devices on a quiet network, a tenant's or a guest network for example, are still recorded and kept up to date, but never announced, never counted as new and hidden from the list (choose "Quiet only" to see them). Nothing is deleted.</p>
      <div class="inv-nets">${nets.length ? nets.map(n => `<label class="checkbox-label"><input type="checkbox" data-net="${escapeHtml(n)}"${quiet.has(n.toLowerCase()) ? " checked" : ""}> ${escapeHtml(n)} <span class="dim">${count(n)} device${count(n) === 1 ? "" : "s"}</span></label>`).join("")
        : '<p class="dim">No Wi-Fi networks seen yet (they come from UniFi). Type one below.</p>'}</div>
      <div class="form-group"><label for="inv-net-add">Another network, by name</label><input type="text" id="inv-net-add" maxlength="32" placeholder="Tenant-WiFi"></div>
      <div class="form-error hidden" data-err></div>
    </div>
    <div class="modal-footer"><span class="topbar-spacer"></span>
      <button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Save</button></div></form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  form.querySelector("[data-x]").addEventListener("click", () => back.remove());
  back.addEventListener("keydown", ev => { if (ev.key === "Escape") back.remove(); });
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    const ssids = [...form.querySelectorAll("[data-net]:checked")].map(c => c.dataset.net);
    const extra = form.querySelector("#inv-net-add").value.trim();
    if (extra) ssids.push(extra);
    try {
      await api("/api/inventory/quiet-ssids", { method: "PUT", body: { ssids } });
      back.remove();
      showToast(ssids.length ? `Quiet: ${ssids.join(", ")}` : "No quiet networks", "success");
      loadInventory();
    } catch (err) {
      const e = form.querySelector("[data-err]"); e.textContent = err.message; e.classList.remove("hidden");
    }
  });
}

function initInventory() {
  document.getElementById("inv-q").addEventListener("input", renderInventory);
  document.getElementById("inv-show").addEventListener("change", renderInventory);
  document.getElementById("inv-filters").addEventListener("submit", ev => ev.preventDefault());
  document.getElementById("inventory-body").addEventListener("click", ev => {
    const b = ev.target.closest("[data-inv-edit]");
    if (b) editInventory(b.dataset.invEdit);
    const m = ev.target.closest("[data-inv-monitor]");
    if (m) monitorFromInventory(m.dataset.invMonitor);
    const k = ev.target.closest("[data-inv-known]");
    if (k) {
      k.disabled = true;
      api(invPath(k.dataset.invKnown), { method: "PUT", body: { known: true } })
        .then(loadInventory).catch(err => { k.disabled = false; showToast(err.message, "error"); });
    }
  });
  document.getElementById("btn-inv-add").addEventListener("click", addInventoryDevice);
  document.getElementById("btn-inv-quiet-nets").addEventListener("click", editQuietNetworks);
  document.getElementById("btn-inv-known").addEventListener("click", async () => {
    try {
      const r = await api("/api/inventory/known", { method: "POST" });
      showToast(`${r.changed} marked known`, "success");
      loadInventory();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

document.addEventListener("DOMContentLoaded", initInventory);
