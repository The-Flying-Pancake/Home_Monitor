/* Alert rules editor (Settings, Alert rules card).
 *
 * Lists every rule that can open a problem with its effective values at the
 * chosen scope: all devices, one template or one device. Values inherited
 * from a level above are shown dimmed; changing one creates an override at
 * this scope, Reset removes this scope's overrides for the row. Changes are
 * held until Save, like the rest of Settings. Telegram columns appear only
 * while Telegram is on, and a switched-off rule shows nothing else.
 * Relies on helpers from app.js (api, escapeHtml, showToast, cachedSettings).
 */

const AR_SOURCE = { default: "built-in default", global: "all devices", template: "the template", device: "this device" };
/** "From ..." for a value's source; a tag source reads "tag:<name>". */
const arSourceText = src => (src && src.startsWith("tag:") ? `the tag ${src.slice(4)}` : AR_SOURCE[src] || "default");
const AR_FIELDS = ["enabled", "severity", "threshold", "for_minutes", "telegram", "resolved", "sound"];
const AR_TELEGRAM = { default: "By severity", always: "Always", never: "Never" };
// Sound on the phone. "By schedule" follows the silent window in Notifications.
const AR_SOUND = { default: "By schedule", always: "Always ring", silent: "Always silent" };

let arData = null;
let arPending = {};           // "rule|field" -> new value (null = inherit)
let arScope = { scope: "global", target: "" };

function alertRulesPanel() {
  return `<div class="alert-rules" id="alert-rules">
    <div class="ar-toolbar">
      <label for="ar-scope">Apply to</label>
      <select id="ar-scope">
        <option value="overview">Overview: everything set anywhere</option>
        <option value="global">All devices</option>
        <option value="template">One template</option>
        <option value="tag">One tag</option>
        <option value="device">One device</option>
      </select>
      <select id="ar-target" class="hidden"></select>
      <span class="ar-spacer"></span>
      <span class="dim" id="ar-dirty"></span>
      <button class="btn hidden" type="button" id="ar-discard">Discard</button>
      <button class="btn btn-primary hidden" type="button" id="ar-save">Save rules</button>
    </div>
    <div class="form-help" id="ar-help"></div>
    <div id="ar-overview" class="hidden"></div>
    <div class="ar-table-wrap" id="ar-table-wrap">
      <table class="ar-table">
        <thead><tr><th>Rule</th><th>On</th><th>Threshold</th><th>Wait</th><th>Severity</th>
          <th class="ar-tg">Telegram</th><th class="ar-tg">Resolved message</th><th class="ar-tg">Sound</th><th></th></tr></thead>
        <tbody id="ar-body"><tr><td colspan="9" class="dim">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>`;
}

async function loadAlertRules(scope = arScope.scope, target = arScope.target) {
  if (scope === "overview") return loadAlertOverview();
  // Recorded before the fetch, so a Settings re-render meanwhile asks for this scope too.
  arScope = { scope, target };
  try {
    arData = await api(`/api/alert-rules?scope=${encodeURIComponent(scope)}&target=${encodeURIComponent(target)}`);
  } catch (err) {
    showToast(`Could not load alert rules: ${err.message}`, "error");
    return;
  }
  arScope = { scope, target };
  arPending = {};
  renderAlertRules();
}

function arValue(rule, field) {
  const k = `${rule.id}|${field}`;
  if (k in arPending) return arPending[k] === null ? arInherited(rule, field) : arPending[k];
  return rule.effective[field];
}

/** What the field would be without this scope's override (shown after Reset). */
function arInherited(rule, field) {
  return rule.inherited[field];
}

function arIsHere(rule, field) {
  const k = `${rule.id}|${field}`;
  if (k in arPending) return arPending[k] !== null;
  return field in rule.here;
}

const AR_FIELD_LABEL = { enabled: "On", severity: "Severity", threshold: "Threshold", for_minutes: "Wait", telegram: "Telegram", resolved: "Resolved message", sound: "Sound" };
const AR_SCOPE_LABEL = { global: "All devices", template: "Template", tag: "Tag", device: "Device" };
let arOverview = null;

function arShowMode(overview) {
  document.getElementById("ar-overview").classList.toggle("hidden", !overview);
  document.getElementById("ar-table-wrap").classList.toggle("hidden", overview);
  if (overview) {
    document.getElementById("ar-target").classList.add("hidden");
    for (const id of ["ar-save", "ar-discard"]) document.getElementById(id).classList.add("hidden");
    document.getElementById("ar-dirty").textContent = "";
  }
}

function arFieldText(field, value, unit) {
  if (field === "enabled") return value ? "on" : "off";
  if (field === "threshold") return `${value}${unit ? " " + unit : ""}`;
  if (field === "for_minutes") return `${value} min`;
  if (field === "telegram") return AR_TELEGRAM[value] || value;
  if (field === "resolved") return value === "on" ? "send" : "do not send";
  if (field === "sound") return AR_SOUND[value] || value;
  return value === "" ? "as reported" : String(value);
}

/** One place to see every value that differs from the defaults: all devices, each template, each device. */
async function loadAlertOverview() {
  try {
    arOverview = await api("/api/alert-rules?scope=overview");
  } catch (err) {
    showToast(`Could not load the overview: ${err.message}`, "error");
    return;
  }
  arScope = { scope: "overview", target: "" };
  arPending = {};
  document.getElementById("ar-scope").value = "overview";
  document.getElementById("ar-help").textContent = "Every alert rule value changed from its default, and where it is set. Reset removes that change, so the value comes from the level above again (a device from its template, a template from all devices). Open edits it in place.";
  arShowMode(true);
  const groups = arOverview.groups;
  const canEdit = can("settings.alerts");
  document.getElementById("ar-overview").innerHTML = !groups.length
    ? `<div class="ok-state">Nothing changed: every device uses the built-in defaults.</div>`
    : groups.map((g, gi) => `<div class="ar-ov-group">
        <div class="ar-ov-head">
          <span class="status-pill status-unknown">${escapeHtml(AR_SCOPE_LABEL[g.scope] || g.scope)}</span>
          <strong>${escapeHtml(g.name)}</strong>
          <span class="dim">${g.items.length} change${g.items.length === 1 ? "" : "s"}</span>
          <span class="ar-spacer"></span>
          <button type="button" class="btn btn-small" data-ov-open="${gi}">Open</button>
          ${canEdit ? `<button type="button" class="btn btn-small" data-ov-reset-group="${gi}">Reset all</button>` : ""}
        </div>
        <table class="ar-table"><tbody>${g.items.map((it, ii) => `<tr class="${it.field === "enabled" && !it.value ? "ar-off" : ""}">
          <td class="text-cell"><strong>${escapeHtml(it.label)}</strong> <span class="dim">${escapeHtml(it.group)}</span></td>
          <td>${escapeHtml(AR_FIELD_LABEL[it.field] || it.field)}</td>
          <td><strong>${escapeHtml(arFieldText(it.field, it.value, it.unit))}</strong>
            <span class="dim">(default ${escapeHtml(arFieldText(it.field, it.default, it.unit))})</span></td>
          <td class="ar-ov-actions">${canEdit ? `<button type="button" class="btn btn-small" data-ov-reset="${gi}:${ii}">Reset</button>` : ""}</td>
        </tr>`).join("")}</tbody></table>
      </div>`).join("");
}

async function arOverviewReset(group, items) {
  const what = items.length === 1 ? `${items[0].label} (${AR_FIELD_LABEL[items[0].field]})` : `${items.length} changes`;
  const ok = await confirmDialog({
    title: "Reset to inherited values?",
    message: `${what} on ${group.name} goes back to the value from the level above.`,
    confirmLabel: "Reset",
  });
  if (!ok) return;
  try {
    await api("/api/alert-rules", { method: "PUT", body: { scope: group.scope, target: group.target,
      changes: items.map(i => ({ rule_id: i.rule_id, field: i.field, value: null })) } });
    showToast("Reset", "success");
    loadAlertOverview();
  } catch (err) {
    showToast(`Could not reset: ${err.message}`, "error");
  }
}

function renderAlertRules() {
  if (!arData) return;
  arShowMode(false);
  const scopeSel = document.getElementById("ar-scope");
  const targetSel = document.getElementById("ar-target");
  scopeSel.value = arScope.scope;
  if (arScope.scope === "global") {
    targetSel.classList.add("hidden");
  } else {
    const opts = arScope.scope === "template"
      ? arData.templates.map(t => [t.id, `${t.name}${t.devices ? ` (${t.devices} device${t.devices > 1 ? "s" : ""})` : ""}`])
      : arScope.scope === "tag" ? (arData.tags || []).map(t => [t.name, t.name])
      : arData.devices.map(d => [String(d.id), `${d.hostname} (${d.profile_id})`]);
    targetSel.innerHTML = opts.map(([v, l]) => `<option value="${escapeHtml(v)}" ${v === arScope.target ? "selected" : ""}>${escapeHtml(l)}</option>`).join("");
    targetSel.classList.remove("hidden");
  }
  document.getElementById("ar-help").textContent = {
    global: "Defaults for every device. Templates, tags and single devices can override any value.",
    template: "Overrides for every device using this template.",
    tag: "Overrides for every device with this tag, whatever its template. Tags sit between the template and the device: a device's own setting still wins, and when two of its tags set the same thing, the one lower in the tag list (Settings, Groups and tags) wins.",
    device: `Overrides for this device only.${(arData.device_tags || []).length ? ` Its tags: ${arData.device_tags.join(", ")}.` : ""}`,
  }[arScope.scope] + " Faded values are inherited (hover to see from where); outlined values are set here. Wait: the condition must last this many minutes before a problem opens (0 = at once).";

  const telegramOn = cachedSettings.telegram_enabled === "on";
  document.querySelectorAll("#alert-rules .ar-tg").forEach(th => th.classList.toggle("hidden", !telegramOn));
  const sevOptions = (rule, value) => (rule.as_reported ? [["", "As reported"]] : []).concat(arData.severities.map(s => [s, s]))
    .map(([v, l]) => `<option value="${escapeHtml(v)}" ${v === value ? "selected" : ""}>${escapeHtml(l)}</option>`).join("");
  const cell = (rule, field, html) => {
    const cls = arIsHere(rule, field) ? "ar-here" : "ar-inherited";
    const from = arIsHere(rule, field) ? "Set here" : `From ${arSourceText(rule.source[field])}`;
    return `<td class="${cls}" title="${escapeHtml(from)}">${html}</td>`;
  };
  const attrs = (rule, field) => `data-ar-rule="${escapeHtml(rule.id)}" data-ar-field="${escapeHtml(field)}"`;

  let group = null;
  const rows = [];
  for (const r of arData.rules) {
    if (r.group !== group) {
      group = r.group;
      rows.push(`<tr class="ar-group"><td colspan="9">${escapeHtml(group)}</td></tr>`);
    }
    const on = arValue(r, "enabled");
    const changed = Object.keys(arPending).some(k => k.startsWith(`${r.id}|`));
    const hasHere = AR_FIELDS.some(f => arIsHere(r, f));
    const sev = arValue(r, "severity");
    rows.push(`<tr class="${on ? "" : "ar-off"} ${changed ? "ar-changed" : ""}">
      <td class="text-cell"><strong>${escapeHtml(r.label)}</strong>${r.help ? `<div class="dim ar-rule-help">${escapeHtml(r.help)}</div>` : ""}</td>
      ${cell(r, "enabled", `<input type="checkbox" ${attrs(r, "enabled")} ${on ? "checked" : ""}>`)}
      ${on ? (r.has_threshold
        ? cell(r, "threshold", `<input type="number" class="ar-num" ${attrs(r, "threshold")} value="${escapeHtml(arValue(r, "threshold"))}" min="${escapeHtml(r.min)}" max="${escapeHtml(r.max)}" step="any"> <span class="unit">${escapeHtml(r.unit)}</span>`)
        : `<td class="dim">-</td>`) : `<td></td>`}
      ${on ? cell(r, "for_minutes", `<input type="number" class="ar-num" ${attrs(r, "for_minutes")} value="${escapeHtml(arValue(r, "for_minutes"))}" min="0" max="1440" step="1"> <span class="unit">min</span>`) : `<td></td>`}
      ${on ? cell(r, "severity", `<select ${attrs(r, "severity")} class="ar-sev ar-sev-${escapeHtml(sev || "reported")}">${sevOptions(r, sev)}</select>`) : `<td class="dim">Off</td>`}
      ${telegramOn ? (on ? cell(r, "telegram", `<select ${attrs(r, "telegram")}>${Object.entries(AR_TELEGRAM).map(([v, l]) =>
        `<option value="${escapeHtml(v)}" ${v === arValue(r, "telegram") ? "selected" : ""}>${escapeHtml(l)}</option>`).join("")}</select>`) : `<td></td>`) : ""}
      ${telegramOn ? (on && arValue(r, "telegram") !== "never" ? cell(r, "resolved", `<select ${attrs(r, "resolved")}>${["on", "off"].map(v =>
        `<option value="${escapeHtml(v)}" ${v === arValue(r, "resolved") ? "selected" : ""}>${v === "on" ? "Send" : "Do not send"}</option>`).join("")}</select>`) : `<td></td>`) : ""}
      ${telegramOn ? (on && arValue(r, "telegram") !== "never" ? cell(r, "sound", `<select ${attrs(r, "sound")}>${Object.entries(AR_SOUND).map(([v, l]) =>
        `<option value="${escapeHtml(v)}" ${v === (arValue(r, "sound") || "default") ? "selected" : ""}>${escapeHtml(l)}</option>`).join("")}</select>`) : `<td></td>`) : ""}
      <td>${hasHere ? `<button class="btn btn-small" type="button" data-ar-reset="${escapeHtml(r.id)}"
        title="Remove the values set here so this row inherits again">Reset</button>` : ""}</td>
    </tr>`);
  }
  document.getElementById("ar-body").innerHTML = rows.join("") || `<tr><td colspan="9" class="dim">No rules.</td></tr>`;
  arUpdateDirty();
}

function arUpdateDirty() {
  const n = Object.keys(arPending).length;
  document.getElementById("ar-dirty").textContent = n ? `${n} unsaved change${n > 1 ? "s" : ""}` : "";
  document.getElementById("ar-save").classList.toggle("hidden", !n);
  document.getElementById("ar-discard").classList.toggle("hidden", !n);
}

function arSetPending(rule, field, value) {
  const k = `${rule.id}|${field}`;
  const original = rule.effective[field];
  const wasHere = field in rule.here;
  if (value === null) {
    if (wasHere) arPending[k] = null; else delete arPending[k];
  } else if (value === original) {
    // Back to the stored value: nothing to save.
    delete arPending[k];
  } else {
    arPending[k] = value;
  }
}

function arConfirmDiscard() {
  return confirmDialog({ title: "Discard alert rule changes?", message: "The unsaved changes in this table are lost.",
    confirmLabel: "Discard", danger: true, arm: false });
}

function initAlertRules() {
  // Unsaved rule edits survive moving between Settings sections; anything else asks first.
  registerUnsavedGuard(target => {
    const n = Object.keys(arPending).length;
    if (!n || (target && target.startsWith("#/settings") && !target.startsWith("#/settings/alerts/"))) return "";
    return `${n} alert rule change${n === 1 ? "" : "s"}`;
  });
  window.addEventListener("discardunsaved", () => { arPending = {}; });
  const root = document.getElementById("settings-sections");
  root.addEventListener("change", async (ev) => {
    if (ev.target.id === "ar-scope") {
      if (Object.keys(arPending).length && !(await arConfirmDiscard())) {
        ev.target.value = arScope.scope;
        return;
      }
      const scope = ev.target.value;
      if (scope === "overview") { loadAlertOverview(); return; }
      if (!arData) { await loadAlertRules("global", ""); if (scope === "global") return; }
      if (scope === "tag" && !(arData.tags || []).length) {
        showToast("No tags yet: add them in Settings, Groups and tags, or on a device in Edit.", "info");
        ev.target.value = arScope.scope;
        return;
      }
      const target = scope === "template" ? (arData.templates[0] || {}).id || ""
        : scope === "tag" ? arData.tags[0].name
        : scope === "device" ? String((arData.devices[0] || {}).id || "") : "";
      loadAlertRules(scope, target);
      return;
    }
    if (ev.target.id === "ar-target") {
      if (Object.keys(arPending).length && !(await arConfirmDiscard())) {
        ev.target.value = arScope.target;
        return;
      }
      loadAlertRules(arScope.scope, ev.target.value);
      return;
    }
    const el = ev.target.closest("[data-ar-field]");
    if (!el) return;
    const rule = arData.rules.find(r => r.id === el.dataset.arRule);
    const field = el.dataset.arField;
    let value;
    if (field === "enabled") value = el.checked;
    else if (field === "threshold") value = el.value === "" ? null : Number(el.value);
    else if (field === "for_minutes") value = el.value === "" ? null : parseInt(el.value, 10);
    else value = el.value;
    if (value !== null && (field === "threshold" || field === "for_minutes") && !isFinite(value)) return;
    arSetPending(rule, field, value);
    renderAlertRules();
  });
  root.addEventListener("click", async (ev) => {
    const ovOpen = ev.target.closest("[data-ov-open]");
    if (ovOpen) {
      const g = arOverview.groups[Number(ovOpen.dataset.ovOpen)];
      loadAlertRules(g.scope, g.target);
      return;
    }
    const ovOne = ev.target.closest("[data-ov-reset]");
    const ovAll = ev.target.closest("[data-ov-reset-group]");
    if (ovOne || ovAll) {
      const [gi, ii] = (ovOne ? ovOne.dataset.ovReset : ovAll.dataset.ovResetGroup).split(":").map(Number);
      const group = arOverview.groups[gi];
      arOverviewReset(group, ovOne ? [group.items[ii]] : group.items);
      return;
    }
    const reset = ev.target.closest("[data-ar-reset]");
    if (reset) {
      const rule = arData.rules.find(r => r.id === reset.dataset.arReset);
      for (const f of AR_FIELDS) {
        delete arPending[`${rule.id}|${f}`];
        if (f in rule.here) arPending[`${rule.id}|${f}`] = null;
      }
      renderAlertRules();
      return;
    }
    if (ev.target.id === "ar-discard") {
      arPending = {};
      renderAlertRules();
      return;
    }
    if (ev.target.id === "ar-save") {
      const changes = Object.entries(arPending).map(([k, value]) => {
        const [rule_id, field] = k.split("|");
        return { rule_id, field, value };
      });
      ev.target.disabled = true;
      try {
        arData = await api("/api/alert-rules", { method: "PUT", body: { scope: arScope.scope, target: arScope.target, changes } });
        arPending = {};
        renderAlertRules();
        showToast(`Saved ${changes.length} alert rule change${changes.length > 1 ? "s" : ""}`, "success");
      } catch (err) {
        showToast(`Could not save: ${err.message}`, "error");
      } finally {
        ev.target.disabled = false;
      }
    }
  });
}

/** Settings, Notifications, Changed alerts: every place an alert was changed from its default, so
 *  nothing set months ago has to be remembered. Each line links to where it is changed. */
async function loadChangedAlerts() {
  const box = document.getElementById("notify-changed");
  if (!box) return;
  let d;
  try {
    d = await api("/api/alerts/changed");
  } catch (err) {
    box.innerHTML = `<div class="form-error">Could not load the changed alerts: ${escapeHtml(err.message)}</div>`;
    return;
  }
  const wifiRule = r => r === "off" ? "never reported" : `reported below ${r} dBm`;
  const section = (title, link, linkText, help, lines) => !lines.length ? "" : `<div class="chg-section">
      <div class="chg-head"><strong>${escapeHtml(title)}</strong><span class="ar-spacer"></span>
        <a class="btn btn-small" href="${escapeHtml(link)}">${escapeHtml(linkText)}</a></div>
      ${help ? `<div class="form-help">${escapeHtml(help)}</div>` : ""}
      <ul class="chg-list">${lines.join("")}</ul></div>`;
  const li = (name, detail, link) => `<li>${link ? `<a href="${escapeHtml(link)}">${escapeHtml(name)}</a>` : `<strong>${escapeHtml(name)}</strong>`}${detail ? ` <span class="dim">${escapeHtml(detail)}</span>` : ""}</li>`;
  const rules = (d.rules || []).map(g => li(`${AR_SCOPE_LABEL[g.scope] || g.scope}: ${g.name}`,
    g.changes.map(c => `${c.label}, ${(AR_FIELD_LABEL[c.field] || c.field).toLowerCase()} ${arFieldText(c.field, c.value, c.unit)} (default ${arFieldText(c.field, c.default, c.unit)})`).join("; "),
    g.link));
  const maint = (d.maintenance || []).map(w => li(w.what,
    `${w.state === "active" ? "on now, until" : `from ${formatTime(w.start)} until`} ${formatTime(w.end)}${w.note ? `: ${w.note}` : ""}`));
  const inv = d.inventory;
  const nets = inv ? [
    ...inv.quiet_networks.map(n => li(n, "quiet: new devices are not announced")),
    ...inv.network_wifi.map(n => li(n.name, `weak Wi-Fi ${wifiRule(n.rule)}`)),
  ] : [];
  const devs = inv ? [
    ...inv.quiet_devices.map(n => li(n, "quiet: never announced")),
    ...inv.device_wifi.map(x => li(x.name, `weak Wi-Fi ${wifiRule(x.rule)}`)),
  ] : [];
  const html = section("Alert rules", "#/settings/alerts/overview", "Open alert rules", "Values changed from the defaults, for all devices, a template, a tag or one device.", rules)
    + section("Maintenance windows", "#/settings/maintenance", "Open maintenance", "While a window is on, its devices raise no problems and send no messages.", maint)
    + section("Wi-Fi networks", "#/inventory", "Open inventory", "Set in Inventory, Wi-Fi networks.", nets)
    + section("Devices in the inventory", "#/inventory", "Open inventory", "Set in each device's Edit window in the Inventory.", devs);
  box.innerHTML = `<p class="form-help">Everything that makes alerts behave differently from the defaults, wherever it was set.</p>`
    + (html || `<div class="ok-state">Nothing changed: every alert works as it came.</div>`);
}
