/* Reports: ready-made templates the user adjusts in the customizer, then previews, downloads as PDF
 * or CSV, or saves to run on a schedule (reports.py does the work; this page only asks and shows).
 * #/reports opens the page; a saved report's files are kept on the monitor and listed under it. */

let reportsData = null;            // GET /api/reports
let reportSpec = null;             // the spec being edited
let reportEditing = null;          // id of the saved report being changed, or null for a new one
let reportPreview = null;          // the last preview, to draw again

const REPORT_PERIODS = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days" };
const REPORT_RIGHT = new Set(["num", "pct", "ms", "bytes", "duration", "mbps", "dbm"]);
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function reportTemplate(id) {
  return (reportsData.templates || []).find(t => t.id === id) || reportsData.templates[0];
}

function newReportSpec(templateId) {
  const t = reportTemplate(templateId);
  return { template: t.id, period: "7d", filter: { group: "", tag: "", device: 0 }, columns: [...t.default],
    sort: { column: t.sort, desc: t.desc }, limit: 0, title: "" };
}

async function loadReports(keep = false) {
  try {
    reportsData = await api("/api/reports");
  } catch (err) {
    document.getElementById("rep-templates").innerHTML = `<div class="form-error">${escapeHtml(err.message)}</div>`;
    return;
  }
  if (!keep || !reportSpec) { reportSpec = newReportSpec(reportsData.templates[0].id); reportEditing = null; }
  renderReportTemplates();
  renderReportSaved();
  renderReportCustomizer();
}

function renderReportTemplates() {
  document.getElementById("rep-templates").innerHTML = reportsData.templates.map(t => `
    <button type="button" class="rep-template ${t.id === reportSpec.template ? "active" : ""}" data-rep-template="${escapeHtml(t.id)}">
      <span class="rep-template-title">${escapeHtml(t.title)}</span>
      <span class="rep-template-text">${escapeHtml(t.description)}</span></button>`).join("");
}

function reportSize(n) {
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`;
}

function renderReportSaved() {
  const box = document.getElementById("rep-saved");
  const saved = reportsData.saved || [];
  if (!saved.length) {
    box.innerHTML = `<div class="dim rep-empty">Nothing saved yet. Set up a report on the right and press Save to keep it or run it on a schedule.</div>`;
    return;
  }
  box.innerHTML = saved.map(r => {
    const runs = (r.runs || []).slice(0, 5).map(run => `<li>
        <span>${escapeHtml(formatTime(run.made_at))}</span>
        ${run.error ? `<span class="text-warn">${escapeHtml(run.error)}</span>`
          : `<span class="dim">${escapeHtml(run.total)} row${run.total === 1 ? "" : "s"}</span>
             ${run.has_pdf ? `<a href="/api/reports/runs/${escapeHtml(run.id)}.pdf">PDF</a> <span class="dim">${escapeHtml(reportSize(run.pdf_size || 0))}</span>` : ""}
             ${run.has_csv ? `<a href="/api/reports/runs/${escapeHtml(run.id)}.csv">CSV</a>` : ""}`}</li>`).join("");
    return `<div class="rep-saved-item ${reportEditing === r.id ? "active" : ""}">
      <div class="rep-saved-head"><strong>${escapeHtml(r.name)}</strong>
        <span class="dim">${escapeHtml(r.schedule_text)}${r.telegram ? ", to Telegram" : ""}</span></div>
      <div class="rep-saved-actions">
        <button type="button" class="btn btn-small" data-rep-open="${escapeHtml(r.id)}">Open</button>
        ${reportsData.can_save ? `<button type="button" class="btn btn-small" data-rep-run="${escapeHtml(r.id)}">Run now</button>
        <button type="button" class="btn btn-small btn-danger" data-rep-delete="${escapeHtml(r.id)}">Delete</button>` : ""}
      </div>
      ${runs ? `<ul class="rep-runs">${runs}</ul>` : `<div class="dim rep-runs-none">No files yet.</div>`}
    </div>`;
  }).join("");
}

function renderReportCustomizer() {
  const t = reportTemplate(reportSpec.template);
  const s = reportSpec;
  document.getElementById("rep-title").value = s.title;
  document.getElementById("rep-title").placeholder = t.title;
  document.getElementById("rep-heading").textContent = reportEditing ? `Saved report: ${(reportsData.saved.find(r => r.id === reportEditing) || {}).name || ""}` : t.title;
  document.getElementById("rep-period-group").classList.toggle("hidden", !t.period);
  document.getElementById("rep-period").innerHTML = reportsData.periods.map(p =>
    `<option value="${escapeHtml(p)}" ${p === s.period ? "selected" : ""}>${escapeHtml(REPORT_PERIODS[p] || p)}</option>`).join("");
  const covers = s.filter.device ? "device" : s.filter.group ? "group" : s.filter.tag ? "tag" : "";
  document.getElementById("rep-covers").value = covers;
  const which = document.getElementById("rep-which");
  which.classList.toggle("hidden", !covers);
  const opts = covers === "group" ? reportsData.groups.map(g => [g.id, g.name])
    : covers === "tag" ? reportsData.tags.map(n => [n, n])
    : covers === "device" ? reportsData.devices.map(d => [String(d.id), `${d.name} (${d.ip})`]) : [];
  const current = covers === "device" ? String(s.filter.device) : covers === "group" ? s.filter.group : s.filter.tag;
  which.innerHTML = opts.map(([v, l]) => `<option value="${escapeHtml(v)}" ${v === current ? "selected" : ""}>${escapeHtml(l)}</option>`).join("");
  // Columns: the chosen ones in their order first (with arrows), then the others to tick.
  const byKey = Object.fromEntries(t.columns.map(c => [c.key, c]));
  const chosen = s.columns.filter(k => byKey[k]);
  const rest = t.columns.filter(c => !chosen.includes(c.key));
  document.getElementById("rep-columns").innerHTML = chosen.map((k, i) => `<li class="rep-col on">
      <label><input type="checkbox" data-rep-col="${escapeHtml(k)}" checked> ${escapeHtml(byKey[k].label)}</label>
      <span class="rep-col-move"><button type="button" class="btn btn-small" data-rep-up="${i}" ${i ? "" : "disabled"} title="Move left" aria-label="Move ${escapeHtml(byKey[k].label)} left">&uarr;</button><button type="button" class="btn btn-small" data-rep-down="${i}" ${i < chosen.length - 1 ? "" : "disabled"} title="Move right" aria-label="Move ${escapeHtml(byKey[k].label)} right">&darr;</button></span></li>`).join("")
    + rest.map(c => `<li class="rep-col"><label><input type="checkbox" data-rep-col="${escapeHtml(c.key)}"> ${escapeHtml(c.label)}</label></li>`).join("");
  document.getElementById("rep-sort").innerHTML = t.columns.map(c =>
    `<option value="${escapeHtml(c.key)}" ${c.key === s.sort.column ? "selected" : ""}>${escapeHtml(c.label)}</option>`).join("");
  document.getElementById("rep-desc").value = s.sort.desc ? "1" : "0";
  document.getElementById("rep-limit").value = s.limit || "";
  document.getElementById("btn-rep-save").classList.toggle("hidden", !reportsData.can_save);
  document.getElementById("btn-rep-save").textContent = reportEditing ? "Save changes" : "Save...";
  document.getElementById("btn-rep-new").classList.toggle("hidden", !reportEditing);
  renderReportTemplates();
}

function readReportCustomizer() {
  const s = reportSpec;
  s.title = document.getElementById("rep-title").value.trim();
  s.period = document.getElementById("rep-period").value || s.period;
  const covers = document.getElementById("rep-covers").value;
  const v = document.getElementById("rep-which").value;
  s.filter = { group: covers === "group" ? v : "", tag: covers === "tag" ? v : "", device: covers === "device" ? parseInt(v, 10) || 0 : 0 };
  s.sort = { column: document.getElementById("rep-sort").value, desc: document.getElementById("rep-desc").value === "1" };
  s.limit = parseInt(document.getElementById("rep-limit").value, 10) || 0;
  return s;
}

function formatReportCell(type, v) {
  if (v === null || v === undefined || v === "") return "";
  if (typeof v !== "number") return String(v);
  if (type === "pct") return v >= 99.95 && v < 100 ? `${v.toFixed(2)}%` : `${v.toFixed(1)}%`;
  if (type === "ms") return v >= 10 ? `${Math.round(v)} ms` : `${v.toFixed(1)} ms`;
  if (type === "time") return v > 0 ? formatTime(v) : "";
  if (type === "bytes") return formatBytes(v);
  if (type === "duration") return formatDuration(v);
  if (type === "mbps") return `${Math.round(v)} Mbps`;
  if (type === "dbm") return `${Math.round(v)} dBm`;
  return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2);
}

function reportBarChart(c) {
  const max = Math.max(...c.bars.map(b => Number(b[1]) || 0), c.unit === "%" ? 100 : 0, 1);
  return `<div class="rep-chart"><div class="rep-chart-title">${escapeHtml(c.title)}</div>
    ${c.bars.map(([label, value]) => `<div class="rep-bar-row"><span class="rep-bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
      <span class="rep-bar-track"><span class="rep-bar" style="width:${Math.max(0, Math.min(100, (Number(value) || 0) / max * 100)).toFixed(1)}%"></span></span>
      <span class="rep-bar-value">${escapeHtml(c.unit === "%" ? `${Number(value).toFixed(1)}%` : Number(value).toLocaleString())}</span></div>`).join("")}</div>`;
}

function reportLineChart(c) {
  const all = c.series.flatMap(s => s.points.filter(p => p[1] !== null));
  if (!all.length) return "";
  const t0 = Math.min(...all.map(p => p[0])), t1 = Math.max(...all.map(p => p[0]));
  const top = c.unit === "%" ? 100 : Math.max(...all.map(p => p[1]), 1);
  const W = 600, H = 160;
  const x = t => t1 === t0 ? 0 : (t - t0) / (t1 - t0) * W;
  const y = v => H - v / top * H;
  const paths = c.series.map((s, i) => {
    let d = "", pen = false;
    s.points.forEach(([t, v]) => {
      if (v === null) { pen = false; return; }
      d += `${pen ? "L" : "M"}${x(t).toFixed(1)},${y(v).toFixed(1)}`;
      pen = true;
    });
    return `<path d="${d}" class="rep-line rep-line-${i % 4}"></path>`;
  }).join("");
  return `<div class="rep-chart"><div class="rep-chart-title">${escapeHtml(c.title)}
      ${c.series.map((s, i) => `<span class="rep-legend rep-line-${i % 4}">${escapeHtml(s.name)}</span>`).join("")}</div>
    <svg class="rep-line-chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(c.title)}">
      <line x1="0" y1="${H / 2}" x2="${W}" y2="${H / 2}" class="rep-grid"></line>${paths}</svg>
    <div class="rep-axis dim"><span>${escapeHtml(formatTime(t0))}</span><span>${escapeHtml(formatTime(t1))}</span></div></div>`;
}

function renderReportPreview() {
  const box = document.getElementById("rep-preview");
  const r = reportPreview;
  if (!r) { box.innerHTML = ""; return; }
  const cols = r.columns;
  const shown = r.rows.length < r.total ? `<div class="panel-note-bar">The preview shows the first ${escapeHtml(r.rows.length)} rows; the files hold all ${escapeHtml(r.total)}.</div>` : "";
  box.innerHTML = `<div class="rep-preview-head"><div class="rep-preview-title">${escapeHtml(r.title)}</div><div class="dim">${escapeHtml(r.subtitle)}</div></div>
    ${r.charts.length ? `<div class="rep-charts">${r.charts.map(c => c.kind === "line" ? reportLineChart(c) : reportBarChart(c)).join("")}</div>` : ""}
    ${shown}
    <div class="panel rep-table-wrap"><table class="rep-table"><thead><tr>${cols.map(c => `<th class="${REPORT_RIGHT.has(c.type) ? "num" : ""}">${escapeHtml(c.label)}</th>`).join("")}</tr></thead>
      <tbody>${r.rows.length ? r.rows.map(row => `<tr>${row.map((v, i) => `<td class="${REPORT_RIGHT.has(cols[i].type) ? "num" : "text-cell"}">${escapeHtml(formatReportCell(cols[i].type, v))}</td>`).join("")}</tr>`).join("")
        : `<tr><td colspan="${cols.length}" class="dim">Nothing to show for this choice.</td></tr>`}</tbody></table></div>`;
}

async function runReportPreview() {
  const spec = readReportCustomizer();
  const btn = document.getElementById("btn-rep-run");
  btn.disabled = true;
  document.getElementById("rep-preview").innerHTML = `<div class="dim">Making the report...</div>`;
  try {
    reportPreview = await api("/api/reports/run", { method: "POST", body: { spec } });
    renderReportPreview();
  } catch (err) {
    document.getElementById("rep-preview").innerHTML = `<div class="form-error">${escapeHtml(err.message)}</div>`;
  } finally {
    btn.disabled = false;
  }
}

async function downloadReport(format) {
  const spec = readReportCustomizer();
  try {
    const res = await fetch("/api/reports/download", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ spec, format }), credentials: "same-origin" });
    if (!res.ok) {
      let msg = `Request failed (HTTP ${res.status})`;
      try { msg = (await res.json()).error || msg; } catch (e) { /* not JSON */ }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const name = ((res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/) || [])[1] || `report.${format}`;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) {
    showToast(`Could not download the report: ${err.message}`, "error");
  }
}

/* Save: a name, when it runs (by hand, daily, weekly or monthly at a time), which files and Telegram. */
function openReportSave() {
  const spec = readReportCustomizer();
  const t = reportTemplate(spec.template);
  const existing = reportEditing ? reportsData.saved.find(r => r.id === reportEditing) : null;
  const sched = existing ? existing.schedule : { kind: "manual" };
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog rep-save" role="dialog" aria-modal="true" aria-labelledby="rep-save-title">
    <div class="modal-header"><span id="rep-save-title">${existing ? "Save changes to the report" : "Save the report"}</span></div>
    <div class="modal-body">
      <div class="form-group"><label for="rep-save-name">Name</label>
        <input type="text" id="rep-save-name" maxlength="80" value="${escapeHtml(existing ? existing.name : spec.title || t.title)}" required></div>
      <div class="form-row">
        <div class="form-group"><label for="rep-save-when">Runs</label>
          <select id="rep-save-when"><option value="manual">By hand</option><option value="daily">Every day</option>
            <option value="weekly">Every week</option><option value="monthly">Every month</option></select></div>
        <div class="form-group" id="rep-save-time-group"><label for="rep-save-time">At</label><input type="time" id="rep-save-time" value="${escapeHtml(sched.time || "07:00")}"></div>
      </div>
      <div class="form-group hidden" id="rep-save-days-group"><span class="form-label">On</span>
        <div class="rep-days">${WEEKDAYS.map((d, i) => `<label class="checkbox-label"><input type="checkbox" data-rep-day="${i + 1 === 7 ? 0 : i + 1}" ${(sched.weekdays || [1]).includes(i + 1 === 7 ? 0 : i + 1) ? "checked" : ""}> ${escapeHtml(d.slice(0, 3))}</label>`).join("")}</div></div>
      <div class="form-group hidden" id="rep-save-day-group"><label for="rep-save-day">Day of the month</label>
        <input type="number" id="rep-save-day" min="1" max="28" value="${escapeHtml(sched.day || 1)}"></div>
      <div class="form-group"><label for="rep-save-formats">Files to keep</label>
        <select id="rep-save-formats"><option value="pdf">PDF</option><option value="csv">CSV (for a spreadsheet)</option><option value="both">PDF and CSV</option></select>
        <div class="form-help">The monitor keeps the newest ${10} runs of each report under Saved reports.</div></div>
      ${reportsData.telegram ? `<label class="checkbox-label"><input type="checkbox" id="rep-save-telegram" ${existing && existing.telegram ? "checked" : ""}> Also send the files to Telegram</label>` : ""}
      <div class="form-error hidden" id="rep-save-error"></div>
    </div>
    <div class="modal-footer"><span class="topbar-spacer"></span>
      <button type="button" class="btn" data-rep-cancel>Cancel</button><button type="submit" class="btn btn-primary">Save</button></div></form>`;
  document.body.appendChild(back);
  const $ = sel => back.querySelector(sel);
  $("#rep-save-when").value = sched.kind || "manual";
  $("#rep-save-formats").value = existing ? existing.formats : "pdf";
  const sync = () => {
    const k = $("#rep-save-when").value;
    $("#rep-save-time-group").classList.toggle("hidden", k === "manual");
    $("#rep-save-days-group").classList.toggle("hidden", k !== "weekly");
    $("#rep-save-day-group").classList.toggle("hidden", k !== "monthly");
  };
  sync();
  $("#rep-save-when").addEventListener("change", sync);
  const close = () => { document.removeEventListener("keydown", onKey, true); back.remove(); };
  const onKey = ev => { if (ev.key === "Escape") { ev.preventDefault(); close(); } };
  document.addEventListener("keydown", onKey, true);
  $("[data-rep-cancel]").addEventListener("click", close);
  $("#rep-save-name").focus();
  back.querySelector("form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const kind = $("#rep-save-when").value;
    const schedule = kind === "manual" ? { kind } : { kind, time: $("#rep-save-time").value || "07:00",
      ...(kind === "weekly" ? { weekdays: [...back.querySelectorAll("[data-rep-day]:checked")].map(x => parseInt(x.dataset.repDay, 10)) } : {}),
      ...(kind === "monthly" ? { day: parseInt($("#rep-save-day").value, 10) || 1 } : {}) };
    const body = { name: $("#rep-save-name").value.trim(), spec, schedule, formats: $("#rep-save-formats").value,
      telegram: !!($("#rep-save-telegram") && $("#rep-save-telegram").checked) };
    try {
      if (existing) await api(`/api/reports/${existing.id}`, { method: "PUT", body });
      else reportEditing = (await api("/api/reports", { method: "POST", body })).id;
      close();
      showToast(`Report ${body.name} saved.`, "success");
      await loadReports(true);
    } catch (err) {
      const e = $("#rep-save-error");
      e.textContent = err.message;
      e.classList.remove("hidden");
    }
  });
}

function initReports() {
  const page = document.getElementById("view-reports");
  if (!page) return;
  page.addEventListener("click", async ev => {
    const tpl = ev.target.closest("[data-rep-template]");
    if (tpl) {
      reportSpec = newReportSpec(tpl.dataset.repTemplate);
      reportEditing = null;
      reportPreview = null;
      renderReportCustomizer();
      renderReportSaved();
      renderReportPreview();
      return;
    }
    const open = ev.target.closest("[data-rep-open]");
    if (open) {
      const r = reportsData.saved.find(x => x.id === Number(open.dataset.repOpen));
      reportSpec = JSON.parse(JSON.stringify(r.spec));
      reportEditing = r.id;
      renderReportCustomizer();
      renderReportSaved();
      runReportPreview();
      return;
    }
    const run = ev.target.closest("[data-rep-run]");
    if (run) {
      run.disabled = true;
      try {
        const r = await api(`/api/reports/${run.dataset.repRun}/run`, { method: "POST", body: {} });
        showToast(r.error ? `The report did not run: ${r.error}` : `Report made: ${r.total} row${r.total === 1 ? "" : "s"}.`, r.error ? "error" : "success");
        await loadReports(true);
      } catch (err) { showToast(err.message, "error"); run.disabled = false; }
      return;
    }
    const del = ev.target.closest("[data-rep-delete]");
    if (del) {
      const r = reportsData.saved.find(x => x.id === Number(del.dataset.repDelete));
      if (!(await confirmDialog({ title: "Delete the report?", message: `${r.name} and its kept files are deleted. Its schedule stops.`, confirmLabel: "Delete", danger: true }))) return;
      try {
        await api(`/api/reports/${r.id}`, { method: "DELETE" });
        if (reportEditing === r.id) reportEditing = null;
        await loadReports(true);
      } catch (err) { showToast(err.message, "error"); }
      return;
    }
    const up = ev.target.closest("[data-rep-up]"), down = ev.target.closest("[data-rep-down]");
    if (up || down) {
      readReportCustomizer();
      const i = Number((up || down).dataset[up ? "repUp" : "repDown"]);
      const j = up ? i - 1 : i + 1;
      const cols = reportSpec.columns;
      [cols[i], cols[j]] = [cols[j], cols[i]];
      renderReportCustomizer();
    }
  });
  page.addEventListener("change", ev => {
    const col = ev.target.closest("[data-rep-col]");
    if (col) {
      readReportCustomizer();
      const key = col.dataset.repCol;
      reportSpec.columns = col.checked ? [...reportSpec.columns, key] : reportSpec.columns.filter(k => k !== key);
      if (!reportSpec.columns.length) reportSpec.columns = [key];
      renderReportCustomizer();
      return;
    }
    if (ev.target.id === "rep-covers") {
      const covers = ev.target.value;
      readReportCustomizer();
      const first = covers === "group" ? (reportsData.groups[0] || {}).id : covers === "tag" ? reportsData.tags[0]
        : covers === "device" ? (reportsData.devices[0] || {}).id : "";
      reportSpec.filter = { group: covers === "group" ? first || "" : "", tag: covers === "tag" ? first || "" : "", device: covers === "device" ? first || 0 : 0 };
      renderReportCustomizer();
    }
  });
  document.getElementById("btn-rep-run").addEventListener("click", runReportPreview);
  document.getElementById("btn-rep-pdf").addEventListener("click", () => downloadReport("pdf"));
  document.getElementById("btn-rep-csv").addEventListener("click", () => downloadReport("csv"));
  document.getElementById("btn-rep-save").addEventListener("click", openReportSave);
  document.getElementById("btn-rep-new").addEventListener("click", () => {
    reportSpec = newReportSpec(reportSpec.template);
    reportEditing = null;
    reportPreview = null;
    renderReportCustomizer();
    renderReportSaved();
    renderReportPreview();
  });
}

document.addEventListener("DOMContentLoaded", initReports);
