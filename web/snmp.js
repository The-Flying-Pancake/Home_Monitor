/* Custom SNMP tab on the device page: custom values (extra OIDs) and the SNMP walk browser.
 *
 * A template may not read every value a device publishes (for
 * example a switch with no CPU or memory). Its vendor still answers under
 * its enterprise OID; the walk browser lists what is there, and "Use" turns
 * a row into a polled value for this device or for every device on its
 * template. MIB files only name these numbers; the numbers are used as is.
 * Each numeric value gets a graph here (and on the Graphs tab), can be put on
 * the Overview, can open a problem at a threshold and can start a workflow
 * (Automation, "A measurement goes above or below a value").
 * Relies on app.js helpers (api, escapeHtml, showToast, confirmDialog, lastDetail, can,
 * drawDefinition, overviewDefs, devicePortsForGraphs, loadDeviceDetail).
 */

const COID_KIND_HELP = {
  gauge: "The value as the device reports it (temperature, percent, count)",
  counter: "A total that only grows (bytes, packets): shown as a rate per second",
  timeticks: "Hundredths of a second (uptimes): shown in seconds",
  string: "Text: shown here only, no graph",
};
const COID_KIND_WORDS = { gauge: "value", counter: "rate per second", timeticks: "seconds", string: "text" };
let coidData = null;
let coidDrawn = 0;

async function loadCustomOids(detail, isRefresh = false) {
  const d = detail && detail.device;
  if (!d) return;
  try {
    coidData = await api(`/api/custom-oids?device=${Number(d.id)}`);
  } catch (err) {
    document.getElementById("custom-oids-body").innerHTML = `<div class="text-err">${escapeHtml(err.message)}</div>`;
    return;
  }
  const walkOid = document.getElementById("walk-oid");
  if (!walkOid.value) walkOid.value = coidData.enterprise || "1.3.6.1.4.1";
  // A refresh every few seconds updates the readings; the graphs are drawn again once a minute.
  if (isRefresh && Date.now() - coidDrawn < 60000) { updateCoidReadings(detail); return; }
  coidDrawn = Date.now();
  const onOverview = overviewDefs(detail, await devicePortsForGraphs()).map(g => g.id);
  const defs = coidData.definitions;
  document.getElementById("custom-oids-note").innerHTML = defs.length
    ? "Polled with the device. Numbers are graphed here and on the Graphs tab, can go on the Overview, and can start a workflow: Automation, <em>A measurement goes above or below a value</em>."
    : "Values this device's template does not read, added by their OID. Browse below to see what the device answers, then press Use on a row.";
  document.getElementById("custom-oids-body").innerHTML = defs.map(c => {
    const key = `custom.${c.id}`;
    const where = c.scope === "template" ? `every ${escapeHtml(c.target)} device` : "this device only";
    const alertText = c.alert_op ? `Problem (${escapeHtml(c.alert_severity)}) when ${escapeHtml(c.alert_op)} ${escapeHtml(String(c.alert_value))}${c.unit ? " " + escapeHtml(c.unit) : ""}` : "No problem threshold";
    const numeric = c.kind !== "string";
    return `<div class="coid-card" data-coid="${Number(c.id)}">
      <div class="coid-head">
        <div><strong>${escapeHtml(c.label)}</strong><div class="dim coid-oid">${escapeHtml(c.oid)}</div></div>
        <div class="coid-now" data-coid-now="${Number(c.id)}"></div>
      </div>
      <div class="coid-meta dim">${escapeHtml(COID_KIND_WORDS[c.kind] || c.kind)}${c.scale !== 1 ? `, times ${escapeHtml(String(c.scale))}` : ""} &middot; polled for ${where} &middot; ${alertText}</div>
      ${numeric ? `<div class="chart-host coid-chart" data-coid-chart="${Number(c.id)}"></div>` : ""}
      <div class="coid-actions">
        ${numeric ? `<button type="button" class="btn btn-small chart-pin${onOverview.includes(key) ? " on" : ""}" data-perm="devices.manage"
          data-overview-pin="${escapeHtml(key)}" aria-pressed="${onOverview.includes(key)}">${onOverview.includes(key) ? "On overview" : "Add to overview"}</button>` : ""}
        <span class="topbar-spacer"></span>
        <button type="button" class="btn btn-small btn-danger" data-perm="devices.manage" data-coid-del="${Number(c.id)}">Remove</button>
      </div>
    </div>`;
  }).join("");
  updateCoidReadings(detail);
  await Promise.all(defs.filter(c => c.kind !== "string").map(c =>
    drawDefinition(document.querySelector(`[data-coid-chart="${Number(c.id)}"]`), d.id,
      { id: `custom.${c.id}`, title: c.label, series: [[`custom.${c.id}`, c.label]], fmt: "dec2" }, 24)));
}

function updateCoidReadings(detail) {
  const latest = Object.fromEntries((detail.latest_metrics || []).map(m => [m.metric_key, m.value]));
  const strings = Object.fromEntries((coidData.strings || []).map(s => [s.oid, s.value]));
  for (const c of coidData.definitions) {
    const el = document.querySelector(`[data-coid-now="${Number(c.id)}"]`);
    if (!el) continue;
    const v = c.kind === "string" ? strings[c.oid] : latest[`custom.${c.id}`];
    el.innerHTML = v === undefined || v === null ? '<span class="dim">no answer yet</span>'
      : escapeHtml(c.kind === "string" ? v : `${Number(v).toLocaleString()}${c.unit ? " " + c.unit : ""}${c.kind === "counter" ? "/s" : ""}`);
  }
}

function coidEditor(prefill) {
  const d = lastDetail.device;
  const p = Object.assign({ oid: "", label: "", unit: "", kind: "gauge", scale: 1 }, prefill || {});
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal coid-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Add a custom value</span><button type="button" class="btn" data-x aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <div class="form-group"><label for="coid-oid">OID</label>
        <input type="text" id="coid-oid" spellcheck="false" value="${escapeHtml(p.oid)}" placeholder="1.3.6.1.4.1.4413.1.1.1.1.4.9.0">
        <div class="form-help">The numeric object identifier. A MIB file maps names such as cpuUtilization to these numbers.</div></div>
      ${p.sample !== undefined ? `<div class="form-help">The device answered <strong>${escapeHtml(String(p.sample))}</strong> just now.</div>` : ""}
      <div class="form-row">
        <div class="form-group"><label for="coid-label">Name</label><input type="text" id="coid-label" maxlength="60" value="${escapeHtml(p.label)}" placeholder="CPU usage"></div>
        <div class="form-group"><label for="coid-unit">Unit (optional)</label><input type="text" id="coid-unit" maxlength="16" value="${escapeHtml(p.unit)}" placeholder="%"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label for="coid-kind">Type</label>
          <select id="coid-kind">${Object.keys(COID_KIND_HELP).map(k => `<option value="${escapeHtml(k)}" ${k === p.kind ? "selected" : ""}>${escapeHtml(k)}</option>`).join("")}</select>
          <div class="form-help" id="coid-kind-help"></div></div>
        <div class="form-group coid-num"><label for="coid-scale">Multiply by</label><input type="number" id="coid-scale" step="any" value="${escapeHtml(p.scale)}">
          <div class="form-help">0.1 when the device reports tenths (235 = 23.5 C).</div></div>
      </div>
      <div class="form-group"><label for="coid-scope">Poll it for</label>
        <select id="coid-scope"><option value="device">This device only (${escapeHtml(d.hostname)})</option>
          <option value="template">Every device on the ${escapeHtml(d.profile_id)} template</option></select></div>
      <div class="form-group coid-num"><label class="check-label"><input type="checkbox" id="coid-alert"> Open a problem when it crosses a threshold</label></div>
      <div class="form-row three coid-alert-row hidden">
        <div class="form-group"><label for="coid-op">When</label><select id="coid-op"><option value="above">Above</option><option value="below">Below</option></select></div>
        <div class="form-group"><label for="coid-value">Value</label><input type="number" id="coid-value" step="any"></div>
        <div class="form-group"><label for="coid-sev">Severity</label><select id="coid-sev">${["info", "warning", "high", "critical"].map(s => `<option ${s === "warning" ? "selected" : ""}>${escapeHtml(s)}</option>`).join("")}</select></div>
      </div>
      <div class="form-error hidden" id="coid-error"></div>
    </div>
    <div class="modal-footer"><button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Add</button></div>
  </form>`;
  document.body.appendChild(back);
  const box = back.querySelector("form");
  const sync = () => {
    const kind = box.querySelector("#coid-kind").value;
    box.querySelector("#coid-kind-help").textContent = COID_KIND_HELP[kind];
    box.querySelectorAll(".coid-num").forEach(el => el.classList.toggle("hidden", kind === "string"));
    box.querySelector(".coid-alert-row").classList.toggle("hidden", kind === "string" || !box.querySelector("#coid-alert").checked);
  };
  sync();
  box.addEventListener("change", sync);
  box.querySelectorAll("[data-x]").forEach(b => b.addEventListener("click", () => back.remove()));
  box.addEventListener("submit", async ev => {
    ev.preventDefault();
    const scope = box.querySelector("#coid-scope").value;
    const body = {
      scope, target: scope === "device" ? String(d.id) : d.profile_id,
      oid: box.querySelector("#coid-oid").value.trim(), label: box.querySelector("#coid-label").value.trim(),
      unit: box.querySelector("#coid-unit").value.trim(), kind: box.querySelector("#coid-kind").value,
      scale: box.querySelector("#coid-scale").value,
    };
    if (box.querySelector("#coid-alert").checked && body.kind !== "string") {
      Object.assign(body, { alert_op: box.querySelector("#coid-op").value, alert_value: box.querySelector("#coid-value").value,
        alert_severity: box.querySelector("#coid-sev").value });
    }
    try {
      await api("/api/custom-oids", { method: "POST", body });
      back.remove();
      showToast(`Added ${body.label}. It is read at the next poll.`, "success");
      coidDrawn = 0;
      loadDeviceDetail(d.id, true);
    } catch (err) {
      const e = box.querySelector("#coid-error");
      e.textContent = err.message;
      e.classList.remove("hidden");
    }
  });
  (p.oid ? box.querySelector("#coid-label") : box.querySelector("#coid-oid")).focus();
}

let walkRows = [];

function drawWalk() {
  const q = document.getElementById("walk-filter").value.trim().toLowerCase();
  const shown = walkRows.filter(r => !q || r.oid.includes(q) || String(r.value).toLowerCase().includes(q));
  document.getElementById("walk-results").innerHTML = shown.length ? `<table class="walk-table"><thead><tr><th>OID</th><th>Type</th><th>Value</th><th></th></tr></thead><tbody>${
    shown.map(r => `<tr><td class="coid-oid">${escapeHtml(r.oid)}</td><td class="dim">${escapeHtml(r.type)}</td>
      <td class="text-cell">${escapeHtml(String(r.value))}</td>
      <td><button type="button" class="btn btn-small" data-perm="devices.manage" data-walk-use="${walkRows.indexOf(r)}">Use</button></td></tr>`).join("")
  }</tbody></table>` : `<div class="dim">${walkRows.length ? "No rows match the filter." : "Nothing answered under this OID."}</div>`;
}

function initSnmpTools() {
  document.getElementById("btn-coid-add").addEventListener("click", () => lastDetail && coidEditor());
  // Browse: reveals the walk in the tab and starts at the vendor's subtree.
  document.getElementById("btn-snmp-walk").addEventListener("click", () => {
    const box = document.getElementById("snmp-walk-inline");
    box.classList.toggle("hidden");
    document.getElementById("btn-snmp-walk").textContent = box.classList.contains("hidden") ? "Browse" : "Hide";
    if (!box.classList.contains("hidden") && !walkRows.length) document.getElementById("walk-form").requestSubmit();
  });
  document.getElementById("walk-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    if (!lastDetail) return;
    const out = document.getElementById("walk-results");
    out.innerHTML = `<div class="dim">Walking...</div>`;
    try {
      const r = await api(`/api/devices/${Number(lastDetail.device.id)}/snmp-walk?oid=${encodeURIComponent(document.getElementById("walk-oid").value.trim())}`);
      walkRows = r.rows;
      drawWalk();
      if (r.truncated) showToast("Showing the first 500 rows: walk a deeper OID for the rest.", "info");
    } catch (err) {
      out.innerHTML = `<div class="text-err">${escapeHtml(err.message)}</div>`;
    }
  });
  document.getElementById("walk-filter").addEventListener("input", drawWalk);
  document.getElementById("walk-results").addEventListener("click", ev => {
    const b = ev.target.closest("[data-walk-use]");
    if (!b) return;
    const r = walkRows[Number(b.dataset.walkUse)];
    coidEditor({ oid: r.oid, kind: r.type === "number" ? "gauge" : "string", sample: r.value });
  });
  document.getElementById("custom-oids-body").addEventListener("click", async ev => {
    const b = ev.target.closest("[data-coid-del]");
    if (!b) return;
    const c = coidData.definitions.find(x => x.id === Number(b.dataset.coidDel));
    if (!(await confirmDialog({ title: `Remove ${c.label}?`, message: c.scope === "template"
      ? `It stops being polled on every ${c.target} device and its history is no longer shown.`
      : "It stops being polled and its history is no longer shown.", confirmLabel: "Remove", danger: true }))) return;
    try {
      await api(`/api/custom-oids/${c.id}`, { method: "DELETE" });
      coidDrawn = 0;
      loadDeviceDetail(lastDetail.device.id, true);
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

// A new device page starts with the walk folded away and its own starting OID.
window.addEventListener("hashchange", () => {
  if (!/^#\/device\/\d+/.test(location.hash)) return;
  const id = (location.hash.match(/^#\/device\/(\d+)/) || [])[1];
  if (lastDetail && String(lastDetail.device.id) === id) return;
  walkRows = [];
  coidDrawn = 0;
  const oid = document.getElementById("walk-oid");
  if (oid) oid.value = "";
  const box = document.getElementById("snmp-walk-inline");
  if (box) { box.classList.add("hidden"); document.getElementById("btn-snmp-walk").textContent = "Browse"; }
  const res = document.getElementById("walk-results");
  if (res) res.innerHTML = `<div class="dim">Press Walk to list what the device answers.</div>`;
});

document.addEventListener("DOMContentLoaded", initSnmpTools);
