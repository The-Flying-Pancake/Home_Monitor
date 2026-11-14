/* Reports: ready-made templates the user adjusts in the customizer, then previews, downloads as PDF
 * or CSV, or saves to run on a schedule (reports.py does the work; this page only asks and shows).
 * #/reports opens the page; a saved report's files are kept on the monitor and listed under it. */

let reportsData = null;            // GET /api/reports
let reportSpec = null;             // the spec being edited
let reportEditing = null;          // id of the saved report being changed, or null for a new one
let reportPreview = null;          // the last preview, to draw again
let reportWidth = 0;               // the width the preview was drawn at (drawn again when it changes)

const REPORT_PERIODS = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days" };
const REPORT_RIGHT = new Set(["num", "pct", "ms", "bytes", "duration", "mbps", "dbm", "bps"]);
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function reportTemplate(id) {
  return (reportsData.templates || []).find(t => t.id === id) || reportsData.templates[0];
}

function newReportSpec(templateId) {
  const t = reportTemplate(templateId);
  // A one-device template starts on the first device; the others cover every device.
  const first = t.one_device && reportsData.devices.length ? reportsData.devices[0].id : 0;
  return { template: t.id, period: t.default_period || "7d", filter: { group: "", tag: "", device: first }, columns: [...t.default],
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
  if (type === "mbps") return v >= 1000 ? `${v / 1000} Gbps` : `${Math.round(v)} Mbps`;
  if (type === "bps") return formatBps(v);
  if (type === "dbm") return `${Math.round(v)} dBm`;
  return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2);
}

/* --- The report layout: header band, key figures, summary, charts, tables, footer ---------------
 * The same layout as the PDF (pdfdoc.py). Charts are drawn here as inline SVG or plain HTML at the
 * width they get, so text stays its real size; the preview is drawn again when that width changes.
 * Colours come from reports.css: green, amber and red only for status, blue, teal and purple for
 * ordinary series, grey for no data. */

const REP_TONES = ["good", "warn", "bad", "info", "none"];

/** A tone name safe for a class (anything unknown is grey). */
function repTone(t) { return REP_TONES.includes(t) ? t : "none"; }

/** A number for an SVG attribute. */
function rn(v) { return Number(v).toFixed(1); }

/** Readable number: 1234, 12.5, 0.75. */
function repNum(v) {
  const a = Math.abs(v);
  if (Number.isInteger(v)) return String(Number(v));
  return String(Number(v.toFixed(a >= 100 ? 0 : a >= 10 ? 1 : 2)));
}

/** A value with its unit, short enough for an axis or the end of a bar (as pdfdoc.format_value). */
function repFmt(v, unit) {
  if (v === null || v === undefined) return "";
  if (unit === "bps" || unit === "B") {
    const names = unit === "bps" ? ["bps", "Kbps", "Mbps", "Gbps", "Tbps"] : ["B", "KB", "MB", "GB", "TB", "PB"];
    const base = unit === "bps" ? 1000 : 1024;
    let i = 0, x = Math.abs(v);
    while (x >= base && i < names.length - 1) { x /= base; i++; }
    return `${v < 0 ? "-" : ""}${repNum(Number(x.toFixed(i === 0 || x >= 100 ? 0 : 1)))} ${names[i]}`;
  }
  if (unit === "%") return `${repNum(v)}%`;
  if (unit === "ms" || unit === "min" || unit === "d" || unit === "h") return `${repNum(v)} ${unit}`;
  return unit ? `${repNum(v)} ${unit}` : repNum(v);
}

function repNiceTicks(low, high, count) {
  if (high <= low) high = low + 1;
  const rough = (high - low) / count;
  const power = Math.pow(10, Math.floor(Math.log10(rough)));
  const step = [1, 2, 5, 10].map(m => m * power).find(s => s >= rough);
  const out = [];
  for (let v = Math.floor(low / step) * step; v <= high + step * 0.001; v += step) out.push(Number(v.toFixed(10)));
  if (out[out.length - 1] < high) out.push(Number((out[out.length - 1] + step).toFixed(10)));
  return out;
}

/** Ticks from exactly low to high for a zoomed axis (as pdfdoc.exact_ticks). */
function repExactTicks(low, high) {
  const span = high - low;
  for (const n of [5, 4, 2]) {
    const step = span / n;
    if (Math.abs(step * 100 - Math.round(step * 100)) < 1e-6) return Array.from({ length: n + 1 }, (_, k) => Number((low + k * step).toFixed(6)));
  }
  return [low, high];
}

const REP_TIME_STEPS = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 1209600, 2592000];

function repTimeTicks(t0, t1, count) {
  const span = Math.max(t1 - t0, 1);
  const step = REP_TIME_STEPS.find(s => span / s <= count) || REP_TIME_STEPS[REP_TIME_STEPS.length - 1];
  const off = -new Date(t0 * 1000).getTimezoneOffset() * 60;
  const out = [];
  for (let t = Math.ceil((t0 + off) / step) * step - off; t <= t1; t += step) out.push(t);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const label = t => {
    const d = new Date(t * 1000);
    const hm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    if (step < 86400) return span <= 86400 ? hm : `${d.getDate()} ${months[d.getMonth()]} ${hm}`;
    return `${d.getDate()} ${months[d.getMonth()]}`;
  };
  return out.map(t => [t, label(t)]);
}

/** Thresholds to draw, and those far above the data that are only named (as pdfdoc.split_marks). */
function repSplitMarks(marks, top, yMax) {
  const all = marks || [];
  if (yMax !== null && yMax !== undefined) return [all, []];
  const near = all.filter(m => isNum(m.value) && m.value <= Math.max(top, 0) * 2);
  return [near, all.filter(m => !near.includes(m))];
}

function repLegend(items) {
  if (!items.length) return "";
  return `<div class="rep-legend-row">${items.map(([name, cls, dashed]) =>
    `<span class="rep-key"><span class="rep-swatch ${escapeHtml(cls)} ${dashed ? "dashed" : ""}"></span>${escapeHtml(name)}</span>`).join("")}</div>`;
}

/** Room for the value labels left of the plot. */
function repPadL(ticks, unit) { return Math.max(...ticks.map(v => repFmt(v, unit).length)) * 6.2 + 8; }

/** The y axis: grid lines and labels, the plot starting at padL. */
function repYAxis(ticks, unit, y, W, padL) {
  const labels = ticks.map(v => repFmt(v, unit));
  return ticks.map((v, i) => `<line class="rep-gridline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(v))}" y2="${rn(y(v))}"></line>
    <text class="rep-tick" x="${rn(padL - 5)}" y="${rn(y(v) + 3.5)}" text-anchor="end">${escapeHtml(labels[i])}</text>`).join("");
}

function repTimeAxis(t0, t1, x, yBase, W) {
  const ticks = repTimeTicks(t0, t1, Math.max(2, Math.floor(W / 110)));
  return ticks.map(([t, label]) => `<line class="rep-axisline" x1="${rn(x(t))}" x2="${rn(x(t))}" y1="${rn(yBase)}" y2="${rn(yBase + 4)}"></line>
    <text class="rep-tick" x="${rn(x(t))}" y="${rn(yBase + 15)}" text-anchor="middle">${escapeHtml(label)}</text>`).join("");
}

/** A path through points; a null value breaks the line. */
function repPath(points, x, y) {
  let d = "", pen = false;
  for (const [t, v] of points) {
    if (v === null || v === undefined) { pen = false; continue; }
    d += `${pen ? "L" : "M"}${rn(x(t))},${rn(y(v))}`;
    pen = true;
  }
  return d;
}

function repSeriesCls(s, i) { return s.tone ? `rt-${repTone(s.tone)}` : `rs-${i % 3}`; }

function repLineChart(c, W, H) {
  const series = (c.series || []).map(s => ({ ...s, points: (s.points || []).filter(p => p[0] !== null) }));
  const values = series.flatMap(s => s.points.map(p => p[1]).filter(isNum));
  if (!values.length) return "";
  const times = series.flatMap(s => s.points.filter(p => isNum(p[1])).map(p => p[0]));
  const [marks, far] = repSplitMarks(c.thresholds, Math.max(...values), isNum(c.y_max) ? c.y_max : c.unit === "%" ? 100 : null);
  let low = isNum(c.y_min) ? c.y_min : Math.min(0, ...values);
  let high = isNum(c.y_max) ? c.y_max : Math.max(...values, ...marks.map(m => m.value));
  if (!isNum(c.y_max) && c.unit === "%" && high <= 100) high = 100;
  const ticks = repNiceTicks(low, high, 4);
  low = ticks[0]; high = ticks[ticks.length - 1];
  const top = 8, base = H - 22;
  const y = v => base - (Math.max(low, Math.min(high, v)) - low) / ((high - low) || 1) * (base - top);
  const padL = repPadL(ticks, c.unit);
  const axis = repYAxis(ticks, c.unit, y, W, padL);
  let t0 = c.start || Math.min(...times), t1 = c.end || Math.max(...times);
  if (t1 <= t0) { t0 -= 1800; t1 += 1800; }
  const x = t => padL + (t - t0) / (t1 - t0) * (W - 4 - padL);
  const bands = (c.bands || []).map(b => `<rect class="rep-band rt-${escapeHtml(repTone(b.tone))}" x="${rn(padL)}" width="${rn(W - 4 - padL)}" y="${rn(y(b.to))}" height="${rn(Math.max(0, y(b.from) - y(b.to)))}"></rect>`).join("");
  const lines = marks.map(m => `<line class="rep-mark rt-${escapeHtml(repTone(m.tone))}" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(m.value))}" y2="${rn(y(m.value))}"></line>`).join("");
  const paths = series.map((s, i) => `<path class="rep-line ${escapeHtml(repSeriesCls(s, i))}" d="${escapeHtml(repPath(s.points, x, y))}"><title>${escapeHtml(s.name)}</title></path>`).join("");
  const legend = (series.length > 1 ? series.map((s, i) => [s.name, repSeriesCls(s, i), false]) : [])
    .concat(marks.filter(m => m.label).map(m => [m.label, `rt-${repTone(m.tone)}`, true]))
    .concat(far.filter(m => m.label).map(m => [`${m.label}, above the chart`, `rt-${repTone(m.tone)}`, true]));
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${bands}${axis}
    <line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(base)}" y2="${rn(base)}"></line>${repTimeAxis(t0, t1, x, base, W)}${lines}${paths}</svg>${repLegend(legend)}`;
}

function repMirrorChart(c, W, H) {
  const ins = (c.in || []).filter(p => p[0] !== null), outs = (c.out || []).filter(p => p[0] !== null);
  const values = ins.concat(outs).map(p => p[1]).filter(isNum).map(Math.abs);
  if (!values.length) return "";
  const times = ins.concat(outs).filter(p => isNum(p[1])).map(p => p[0]);
  const ticks = repNiceTicks(0, Math.max(...values, c.line || 0) || 1, 2);
  const top = ticks[ticks.length - 1];
  const upper = 6, base = H - 22, mid = (upper + base) / 2, half = (base - upper) / 2;
  const labels = ticks.map(v => repFmt(v, c.unit));
  const padL = Math.max(...labels.map(s => s.length)) * 6.2 + 8;
  let t0 = c.start || Math.min(...times), t1 = c.end || Math.max(...times);
  if (t1 <= t0) { t0 -= 1800; t1 += 1800; }
  const x = t => padL + (t - t0) / (t1 - t0) * (W - 4 - padL);
  const grid = ticks.map((v, i) => (v === 0 ? [1] : [1, -1]).map(sign => {
    const yy = mid - sign * v / top * half;
    return `<line class="rep-gridline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(yy)}" y2="${rn(yy)}"></line>
      <text class="rep-tick" x="${rn(padL - 5)}" y="${rn(yy + 3.5)}" text-anchor="end">${escapeHtml(labels[i])}</text>`;
  }).join("")).join("");
  const area = (pts, sign, cls) => {
    let d = "", run = [];
    const flush = () => {
      if (run.length) d += `M${rn(x(run[0][0]))},${rn(mid)}` + run.map(([t, v]) => `L${rn(x(t))},${rn(mid - sign * Math.min(Math.abs(v), top) / top * half)}`).join("") + `L${rn(x(run[run.length - 1][0]))},${rn(mid)}Z`;
      run = [];
    };
    for (const p of pts) { if (isNum(p[1])) run.push(p); else flush(); }
    flush();
    const yv = v => mid - sign * Math.min(Math.abs(v), top) / top * half;
    return `<path class="rep-area ${escapeHtml(cls)}" d="${escapeHtml(d)}"></path><path class="rep-line ${escapeHtml(cls)}" d="${escapeHtml(repPath(pts, x, yv))}"></path>`;
  };
  const speed = isNum(c.line) ? [1, -1].map(sign => `<line class="rep-mark rt-none" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(mid - sign * Math.min(c.line, top) / top * half)}" y2="${rn(mid - sign * Math.min(c.line, top) / top * half)}"></line>`).join("") : "";
  const legend = [[c.in_label || "In", "rs-0", false], [c.out_label || "Out", "rs-1", false]].concat(isNum(c.line) && c.line_label ? [[c.line_label, "rt-none", true]] : []);
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${grid}${area(ins, 1, "rs-0")}${area(outs, -1, "rs-1")}${speed}
    <line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(mid)}" y2="${rn(mid)}"></line>${repTimeAxis(t0, t1, x, base, W)}</svg>${repLegend(legend)}`;
}

function repColumnsChart(c, W, H) {
  const labels = c.labels || [];
  const series = (c.series || []).filter(s => (s.values || []).length);
  if (!labels.length || !series.length) return "";
  const stacked = c.stacked !== false;
  const totals = labels.map((_, i) => stacked ? series.reduce((a, s) => a + Math.max(0, s.values[i] || 0), 0) : Math.max(...series.map(s => s.values[i] || 0)));
  let target = c.target || null;
  if (target && !isNum(c.y_max) && repSplitMarks([target], Math.max(...totals), null)[1].length) target = { ...target, value: null, label: target.label ? `${target.label}, above the chart` : "" };
  let low = c.y_min || 0;
  let high = isNum(c.y_max) ? c.y_max : Math.max(...totals, target && isNum(target.value) ? target.value : 0) || 1;
  let ticks = c.y_min && isNum(c.y_max) ? repExactTicks(low, high) : repNiceTicks(low, high, 4);
  if (c.whole) { ticks = ticks.filter(v => Number.isInteger(v)); if (ticks.length < 2) ticks = [0, 1]; }
  low = ticks[0]; high = ticks[ticks.length - 1];
  const top = 8, base = H - 22;
  const y = v => base - (Math.max(low, Math.min(high, v)) - low) / ((high - low) || 1) * (base - top);
  const padL = repPadL(ticks, c.unit);
  const axis = repYAxis(ticks, c.unit, y, W, padL);
  const slot = (W - 4 - padL) / labels.length, bw = Math.max(1, slot * 0.72);
  const tones = c.bar_tones || [];
  const bars = labels.map((label, i) => {
    let floor = low;
    return series.map((s, si) => {
      const v = s.values[i];
      if (!isNum(v)) return "";
      const cls = series.length === 1 && tones[i] ? `rt-${repTone(tones[i])}` : repSeriesCls(s, si);
      const topV = stacked ? floor + Math.max(0, v) : v;
      const r = `<rect class="rep-colbar ${escapeHtml(cls)}" x="${rn(padL + i * slot + (slot - bw) / 2)}" y="${rn(y(topV))}" width="${rn(bw)}" height="${rn(Math.max(0, y(floor) - y(topV)))}"><title>${escapeHtml(label)}: ${escapeHtml(repFmt(v, c.unit))}${series.length > 1 ? ` ${escapeHtml(s.name)}` : ""}</title></rect>`;
      if (stacked) floor = topV;
      return r;
    }).join("");
  }).join("");
  const every = Math.max(1, Math.ceil(Math.max(...labels.map(l => String(l).length)) * 6 / Math.max(slot - 2, 1)));
  const xl = labels.map((label, i) => i % every ? "" : `<text class="rep-tick" x="${rn(padL + i * slot + slot / 2)}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(label)}</text>`).join("");
  const line = target && isNum(target.value) ? `<line class="rep-mark rt-${escapeHtml(repTone(target.tone))}" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(target.value))}" y2="${rn(y(target.value))}"></line>` : "";
  const legend = (series.length > 1 ? series.map((s, i) => [s.name, repSeriesCls(s, i), false]) : [])
    .concat(target && target.label ? [[target.label, `rt-${repTone(target.tone)}`, true]] : []);
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${axis}${bars}
    <line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(base)}" y2="${rn(base)}"></line>${line}${xl}</svg>${repLegend(legend)}`;
}

function repBarChart(c) {
  const bars = (c.bars || []).filter(b => isNum(b[1]));
  if (!bars.length) return "";
  const max = c.max || Math.max(...bars.map(b => b[1]), c.unit === "%" ? 100 : 0, 1);
  const marks = (c.thresholds || []).map(m => `<span class="rep-hmark rt-${escapeHtml(repTone(m.tone))}" style="left:${Math.min(100, m.value / max * 100).toFixed(1)}%"></span>`).join("");
  return `<div class="rep-hbars">${bars.map(([label, value, tone]) => `<div class="rep-hbar-row"><span class="rep-hbar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
      <span class="rep-hbar-track"><span class="rep-hbar ${tone ? `rt-${escapeHtml(repTone(tone))}` : "rs-0"}" style="width:${Math.max(0.5, Math.min(100, Math.max(0, value) / max * 100)).toFixed(1)}%"></span>${marks}</span>
      <span class="rep-hbar-value">${escapeHtml(repFmt(value, c.unit))}</span></div>`).join("")}</div>
    ${repLegend((c.thresholds || []).filter(m => m.label).map(m => [m.label, `rt-${repTone(m.tone)}`, true]))}`;
}

function repDonutChart(c) {
  const segs = (c.segments || []).filter(s => isNum(s.value) && s.value > 0);
  const total = segs.reduce((a, s) => a + s.value, 0);
  if (!total) return "";
  const R = 62, r = 40, C = 70;
  let angle = -Math.PI / 2;
  const arcs = segs.map((s, i) => {
    const sweep = s.value / total * Math.PI * 2;
    const a2 = angle + Math.min(sweep, Math.PI * 2 - 0.0001);
    const large = sweep > Math.PI ? 1 : 0;
    const p = (rad, a) => `${rn(C + rad * Math.cos(a))},${rn(C + rad * Math.sin(a))}`;
    const d = `M${p(R, angle)}A${R},${R} 0 ${large} 1 ${p(R, a2)}L${p(r, a2)}A${r},${r} 0 ${large} 0 ${p(r, angle)}Z`;
    angle += sweep;
    return `<path class="rep-seg ${escapeHtml(repSeriesCls(s, i))}" d="${escapeHtml(d)}"><title>${escapeHtml(s.label)}: ${escapeHtml(repNum(s.value))}</title></path>`;
  }).join("");
  return `<div class="rep-donut"><svg class="rep-donut-svg" viewBox="0 0 140 140" role="img" aria-label="${escapeHtml(c.title)}">${arcs}
      <text class="rep-donut-total" x="70" y="72" text-anchor="middle">${escapeHtml(repNum(isNum(c.total) ? c.total : total))}</text>
      <text class="rep-tick" x="70" y="88" text-anchor="middle">${escapeHtml(c.total_label || "")}</text></svg>
    <ul class="rep-donut-keys">${segs.map((s, i) => `<li><span class="rep-swatch ${escapeHtml(repSeriesCls(s, i))}"></span><strong>${escapeHtml(repNum(s.value))}</strong> ${escapeHtml(s.label)}
      <span class="dim">${escapeHtml(Math.round(s.value / total * 100))}%</span></li>`).join("")}</ul></div>`;
}

function repStrips(c) {
  const rows = c.rows || [];
  if (!rows.length) return "";
  return `<div class="rep-strips">${rows.map(row => `<div class="rep-strip-row"><span class="rep-strip-name" title="${escapeHtml(row.name)}">${escapeHtml(row.name)}</span>
      <span class="rep-strip">${(row.cells || []).map(cell => `<span class="rep-cell rt-${escapeHtml(repTone(cell[1]))}" title="${escapeHtml(isNum(cell[0]) ? `${cell[0].toFixed(2)}%` : "No checks")}"></span>`).join("")}</span>
      <span class="rep-strip-value">${escapeHtml(row.value_text)}</span></div>`).join("")}
    <div class="rep-strip-axis dim"><span>${escapeHtml(c.start_text)}</span><span>${escapeHtml(c.end_text)}</span></div></div>`;
}

function repHeatmap(c) {
  const grid = c.values || [];
  const top = c.max || 1;
  const hours = Array.from({ length: 24 }, (_, h) => h);
  return `<div class="rep-heat">${grid.map((row, w) => `<span class="rep-heat-day">${escapeHtml((c.rows || [])[w] || "")}</span>${row.map((v, h) =>
      `<span class="rep-heat-cell ${isNum(v) ? "" : "empty"}" style="--level:${isNum(v) ? Math.round(8 + 92 * Math.max(0, Math.min(1, v / top))) : 0}%" title="${escapeHtml(`${(c.rows || [])[w] || ""} ${String(h).padStart(2, "0")}:00 ${isNum(v) ? repFmt(v, c.unit) : "No data"}`)}"></span>`).join("")}`).join("")}
    <span></span>${hours.map(h => `<span class="rep-heat-hour">${h % 3 ? "" : escapeHtml(String(h).padStart(2, "0"))}</span>`).join("")}</div>
    <div class="rep-heat-scale dim">Low <span class="rep-heat-ramp"></span> High (${escapeHtml(repFmt(top, c.unit))})</div>`;
}

function repGrid(c) {
  return `<div class="rep-tiles">${(c.tiles || []).map(t => `<div class="rep-tile rt-${escapeHtml(repTone(t.tone))}" title="${escapeHtml(t.sub)}">
      <span class="rep-tile-name">${escapeHtml(t.label)}</span><span class="rep-tile-sub">${escapeHtml(t.sub)}</span></div>`).join("")}</div>`;
}

function repChart(c, W, full) {
  const H = full ? 230 : 190;
  const body = c.kind === "line" ? repLineChart(c, W, H) : c.kind === "mirror" ? repMirrorChart(c, W, H)
    : c.kind === "columns" ? repColumnsChart(c, W, H) : c.kind === "bar" ? repBarChart(c) : c.kind === "donut" ? repDonutChart(c)
    : c.kind === "strips" ? repStrips(c) : c.kind === "heatmap" ? repHeatmap(c) : c.kind === "grid" ? repGrid(c) : "";
  return `<figure class="rep-chart ${full ? "rep-chart-main" : ""}" data-kind="${escapeHtml(c.kind)}">
    <figcaption><span class="rep-chart-title">${escapeHtml(c.title)}</span>${c.note ? `<span class="rep-chart-note">${escapeHtml(c.note)}</span>` : ""}</figcaption>
    ${body || `<div class="dim rep-nodata">No data</div>`}</figure>`;
}

function repSpark(values) {
  const vals = (values || []).filter(isNum);
  if (vals.length < 2) return "";
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const step = 60 / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => [i, v]);
  return `<svg class="rep-spark" viewBox="0 0 60 16" role="img" aria-label="Trend"><path class="rep-line rs-0" d="${escapeHtml(repPath(pts, i => i * step, v => 14 - (v - lo) / ((hi - lo) || 1) * 12))}"></path></svg>`;
}

function repCell(col, v, tones) {
  if (col.type === "pill") return v === null || v === undefined || v === "" ? "" : `<span class="rep-pill rt-${escapeHtml(repTone(tones[v]))}">${escapeHtml(v)}</span>`;
  if (col.type === "spark") return repSpark(v);
  return escapeHtml(formatReportCell(col.type, v));
}

function repTable(cols, rows, tones, empty) {
  return `<div class="rep-table-wrap"><table class="rep-table"><thead><tr>${cols.map(c => `<th class="${REPORT_RIGHT.has(c.type) ? "num" : ""}">${escapeHtml(c.label)}</th>`).join("")}</tr></thead>
    <tbody>${rows.length ? rows.map(row => `<tr>${row.map((v, i) => `<td class="${REPORT_RIGHT.has(cols[i].type) ? "num" : cols[i].type === "pill" || cols[i].type === "spark" ? "pill-cell" : "text-cell"}">${repCell(cols[i], v, tones)}</td>`).join("")}</tr>`).join("")
      : `<tr><td colspan="${escapeHtml(cols.length)}" class="dim">${escapeHtml(empty)}</td></tr>`}</tbody></table></div>`;
}

function repKpi(k) {
  return `<div class="rep-kpi rt-${escapeHtml(repTone(k.tone))}"><span class="rep-kpi-label">${escapeHtml(k.label)}</span>
    <span class="rep-kpi-value">${escapeHtml(k.value)}</span>${k.sub ? `<span class="rep-kpi-sub">${escapeHtml(k.sub)}</span>` : ""}
    ${k.note ? `<span class="rep-kpi-note ${k.trend === "good" ? "up-good" : k.trend === "bad" ? "up-bad" : ""}">${escapeHtml(k.note)}</span>` : ""}</div>`;
}

function renderReportPreview() {
  const box = document.getElementById("rep-preview");
  const r = reportPreview;
  if (!r) { box.innerHTML = ""; return; }
  const width = Math.max(280, box.clientWidth || 600);
  const inner = width - 28;                     // inside the report's padding and border
  const two = width >= 700;                     // as the container query in reports.css
  const half = two ? (inner - 16) / 2 : inner;
  reportWidth = width;
  const shown = r.rows.length < r.total ? `<div class="panel-note-bar">The preview shows the first ${escapeHtml(r.rows.length)} rows; the files hold all ${escapeHtml(r.total)}.</div>` : "";
  box.innerHTML = `<article class="rep-doc">
    <header class="rep-head"><h2 class="rep-head-title">${escapeHtml(r.title)}</h2><p class="rep-head-purpose">${escapeHtml(r.purpose)}</p>
      <dl class="rep-facts">${(r.facts || []).map(f => `<div class="rep-fact"><dt>${escapeHtml(f[0])}</dt><dd>${escapeHtml(f[1])}</dd></div>`).join("")}</dl></header>
    ${(r.kpis || []).length ? `<section class="rep-kpis" aria-label="Key figures">${r.kpis.map(repKpi).join("")}</section>` : ""}
    ${r.summary ? `<section class="rep-summary"><h3 class="rep-section-title">Summary</h3><p>${escapeHtml(r.summary)}</p></section>` : ""}
    ${r.main ? repChart(r.main, inner, true) : ""}
    ${(r.charts || []).length ? `<div class="rep-chartgrid">${r.charts.map(c => repChart(c, half, false)).join("")}</div>` : ""}
    <section class="rep-section"><h3 class="rep-section-title">${escapeHtml(r.table_title || "Details")} <span class="dim">${escapeHtml(r.total)} row${r.total === 1 ? "" : "s"}</span></h3>
      ${shown}${repTable(r.columns, r.rows, r.tones || {}, "Nothing to show for this choice.")}</section>
    ${(r.tables || []).map(t => `<section class="rep-section"><h3 class="rep-section-title">${escapeHtml(t.title)}</h3>${t.note ? `<p class="rep-section-note dim">${escapeHtml(t.note)}</p>` : ""}
      ${repTable(t.columns, t.rows, r.tones || {}, "Nothing to show.")}</section>`).join("")}
    <footer class="rep-foot">${escapeHtml(r.footer || "")}</footer></article>`;
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

// Charts are drawn at the width they get: draw the preview again when that width changes.
let reportResizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(reportResizeTimer);
  reportResizeTimer = setTimeout(() => {
    const box = document.getElementById("rep-preview");
    if (reportPreview && box && box.clientWidth && Math.abs(box.clientWidth - reportWidth) > 30) renderReportPreview();
  }, 200);
});
