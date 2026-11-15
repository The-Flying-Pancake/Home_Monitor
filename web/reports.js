/* Reports: templates in groups, a "What do you want to know?" picker and a builder for reports made
 * from scratch. A report is a header and a list of blocks (key figures, charts, tables, text, device
 * details, two side by side); templates and custom reports are drawn by the same code here and in the
 * PDF (reports.py does the work; this page only asks and shows).
 * #/reports opens the page; a saved report's files are kept on the monitor and listed under it. */

let reportsData = null;            // GET /api/reports
let reportSpec = null;             // the spec being edited (a template's, or a custom one with blocks)
let reportEditing = null;          // id of the saved report being changed, or null for a new one
let reportPreview = null;          // the last preview, to draw again
let reportWidth = 0;               // the width the preview was drawn at (drawn again when it changes)
let reportOpen = null;             // the builder block being edited: "3", or "3.left" inside a side by side row
let reportQuestion = "";           // the picker's question

const REPORT_PERIODS = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days" };
const REPORT_RIGHT = new Set(["num", "pct", "ms", "bytes", "duration", "mbps", "dbm", "bps"]);
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const BLOCK_NAMES = { kpi_row: "Key figures", chart: "Chart", table: "Table", text: "Text", key_value: "Device details",
  two_column: "Side by side", part: "Ready-made" };

function reportTemplate(id) {
  return (reportsData.templates || []).find(t => t.id === id) || reportsData.templates[0];
}

function reportCatalog() { return reportsData.catalog || { sources: [], charts: {}, kpis: [], tables: [], questions: [], groups: [] }; }

function newReportSpec(templateId) {
  const t = reportTemplate(templateId);
  // A one-device template starts on the first device; the others cover every device.
  const first = t.one_device && reportsData.devices.length ? reportsData.devices[0].id : 0;
  const spec = { template: t.id, period: t.default_period || "7d", filter: { group: "", tag: "", device: first }, columns: [...t.default],
    sort: { column: t.sort, desc: t.desc }, limit: 0, title: "" };
  if (t.focus === "outage") spec.focus = { outage: 0 };
  return spec;
}

/** A custom report: blank, or a copy of a template's blocks (Start from this template). */
function newCustomSpec(fromTemplate) {
  const t = fromTemplate ? reportTemplate(fromTemplate) : null;
  const base = reportSpec || {};
  const blocks = t ? JSON.parse(JSON.stringify(t.blocks)) : [];
  if (t) {
    // The template's own column choice, sort and limit go with its first table.
    const first = blocks.find(b => b.type === "table" || (b.type === "part" && b.part === "table"));
    if (first && base.template === t.id) Object.assign(first, { columns: [...base.columns], sort: { ...base.sort }, limit: base.limit || first.limit || 0 });
  }
  return { template: "custom", based_on: t ? t.id : "", title: t ? (base.title || t.title) : "", subtitle: t ? t.description : "",
    audience: t ? t.audience : "", period: base.period || (t && t.default_period) || "7d",
    filter: base.filter ? { ...base.filter } : { group: "", tag: "", device: 0 }, blocks };
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

/* --- Templates in groups, with the picker on top --------------------------------------------- */

function renderReportTemplates() {
  const cat = reportCatalog();
  const q = cat.questions.find(x => x.id === reportQuestion);
  const names = Object.fromEntries(reportsData.templates.map(t => [t.id, t.title]));
  const suggest = q ? `<div class="rep-suggest">
      ${q.gap ? `<p class="rep-suggest-gap dim">${escapeHtml(q.gap)}</p>` : ""}
      <span class="rep-suggest-head">Templates</span>
      <div class="rep-suggest-row">${q.templates.filter(id => names[id]).map(id => `<button type="button" class="btn btn-small" data-rep-template="${escapeHtml(id)}">${escapeHtml(names[id])}</button>`).join("")}</div>
      <span class="rep-suggest-head">Charts for a report of your own</span>
      <div class="rep-suggest-row">${q.charts.map(ch => `<button type="button" class="btn btn-small" data-rep-suggest="${escapeHtml(`${ch.source}|${ch.view}|${ch.chart}`)}">${escapeHtml(repChartName(ch))}</button>`).join("")}</div>
    </div>` : "";
  const groups = cat.groups.map(g => {
    const items = reportsData.templates.filter(t => t.group === g.id);
    if (!items.length) return "";
    return `<section class="rep-group"><h3 class="rep-group-title">${escapeHtml(g.title)}</h3><p class="rep-group-about">${escapeHtml(g.about)}</p>
      ${items.map(t => `<button type="button" class="rep-template ${t.id === reportSpec.template ? "active" : ""}" data-rep-template="${escapeHtml(t.id)}">
        <span class="rep-template-title">${escapeHtml(t.title)}</span>
        <span class="rep-template-text">${escapeHtml(t.description)}</span>
        ${t.audience ? `<span class="rep-template-for">For ${escapeHtml(t.audience.charAt(0).toLowerCase() + t.audience.slice(1))}</span>` : ""}</button>`).join("")}</section>`;
  }).join("");
  document.getElementById("rep-templates").innerHTML = `<div class="rep-pick">
      <button type="button" class="btn btn-primary btn-small rep-blank ${reportSpec.template === "custom" ? "active" : ""}" id="btn-rep-blank">New custom report</button>
      <label class="rep-pick-label" for="rep-question">What do you want to know?</label>
      <select id="rep-question"><option value="">Choose a question</option>${cat.questions.map(x => `<option value="${escapeHtml(x.id)}" ${x.id === reportQuestion ? "selected" : ""}>${escapeHtml(x.text)}</option>`).join("")}</select>
      ${suggest}</div>${groups}`;
}

function repChartName(ch) {
  const cat = reportCatalog();
  const s = cat.sources.find(x => x.id === ch.source);
  const v = s ? s.views.find(x => x.id === ch.view) : null;
  const c = cat.charts[ch.chart] || { label: ch.chart };
  return `${s ? s.label : ch.source}${v ? `, ${v.label.toLowerCase()}` : ""}: ${c.label.toLowerCase()}`;
}

function reportSize(n) {
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`;
}

function renderReportSaved() {
  const box = document.getElementById("rep-saved");
  const saved = reportsData.saved || [];
  if (!saved.length) {
    box.innerHTML = `<div class="dim rep-empty">Nothing saved yet. Set up a report and press Save to keep it or run it on a schedule.</div>`;
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
        <span class="dim">${r.spec && r.spec.template === "custom" ? "Custom report, " : ""}${escapeHtml(r.schedule_text)}${r.telegram ? ", to Telegram" : ""}</span></div>
      <div class="rep-saved-actions">
        <button type="button" class="btn btn-small" data-rep-open="${escapeHtml(r.id)}">Open</button>
        ${reportsData.can_save ? `<button type="button" class="btn btn-small" data-rep-run="${escapeHtml(r.id)}">Run now</button>
        <button type="button" class="btn btn-small btn-danger" data-rep-delete="${escapeHtml(r.id)}">Delete</button>` : ""}
      </div>
      ${runs ? `<ul class="rep-runs">${runs}</ul>` : `<div class="dim rep-runs-none">No files yet.</div>`}
    </div>`;
  }).join("");
}

/* --- The customizer (a template) and the builder (a custom report) ----------------------------- */

/** Elements this page adds to the panel (index.html holds the template customizer only). */
function reportExtras() {
  const panel = document.querySelector("#view-reports .rep-custom");
  if (!document.getElementById("btn-rep-copy")) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.id = "btn-rep-copy";
    btn.className = "btn btn-small";
    btn.textContent = "Start from this template";
    btn.title = "Copy this template into the builder to add, remove, reorder and change its blocks";
    document.getElementById("btn-rep-new").before(btn);
  }
  if (!document.getElementById("rep-builder")) {
    const outage = document.createElement("div");
    outage.className = "form-group hidden";
    outage.id = "rep-outage-group";
    const builder = document.createElement("div");
    builder.id = "rep-builder";
    builder.className = "rep-builder hidden";
    panel.querySelector(".rep-actions").before(outage, builder);
  }
}

function renderReportCustomizer() {
  reportExtras();
  const s = reportSpec;
  const custom = s.template === "custom";
  const t = custom ? null : reportTemplate(s.template);
  const columnsGroup = document.getElementById("rep-columns").closest(".form-group");
  const sortRow = document.getElementById("rep-sort").closest(".form-row");
  columnsGroup.classList.toggle("hidden", custom);
  sortRow.classList.toggle("hidden", custom);
  document.getElementById("rep-builder").classList.toggle("hidden", !custom);
  document.getElementById("btn-rep-copy").classList.toggle("hidden", custom);
  document.getElementById("rep-title").value = s.title || "";
  document.getElementById("rep-title").placeholder = custom ? "My report" : t.title;
  const saved = reportEditing ? reportsData.saved.find(r => r.id === reportEditing) : null;
  document.getElementById("rep-heading").textContent = saved ? `Saved report: ${saved.name}` : custom ? (s.based_on ? `Custom report, from ${reportTemplate(s.based_on).title}` : "New custom report") : t.title;
  document.getElementById("rep-period-group").classList.toggle("hidden", !custom && !t.period);
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
  // The outage review asks which outage (the longest of your devices' last 90 days).
  const outage = document.getElementById("rep-outage-group");
  const showOutage = !custom && t.focus === "outage";
  outage.classList.toggle("hidden", !showOutage);
  if (showOutage) {
    const chosen = (s.focus || {}).outage || 0;
    outage.innerHTML = `<label for="rep-outage">Outage</label><select id="rep-outage"><option value="0">The longest in the period</option>
      ${(reportsData.outages || []).map(o => `<option value="${escapeHtml(o.id)}" ${o.id === chosen ? "selected" : ""}>${escapeHtml(`${o.device}, ${formatTime(o.started)}, ${formatDuration(o.seconds)}`)}</option>`).join("")}</select>`;
  }
  if (!custom) {
    // Columns: the chosen ones in their order first (with arrows), then the others to tick.
    const byKey = Object.fromEntries(t.columns.map(c => [c.key, c]));
    const chosen = s.columns.filter(k => byKey[k]);
    const rest = t.columns.filter(c => !chosen.includes(c.key));
    document.getElementById("rep-columns").innerHTML = chosen.map((k, i) => `<li class="rep-col on">
        <label><input type="checkbox" data-rep-col="${escapeHtml(k)}" checked> ${escapeHtml(byKey[k].label)}</label>
        <span class="rep-col-move"><button type="button" class="btn btn-small" data-rep-up="${i}" ${i ? "" : "disabled"} title="Move left" aria-label="Move ${escapeHtml(byKey[k].label)} left">&uarr;</button><button type="button" class="btn btn-small" data-rep-down="${i}" ${i < chosen.length - 1 ? "" : "disabled"} title="Move right" aria-label="Move ${escapeHtml(byKey[k].label)} right">&darr;</button></span></li>`).join("")
      + rest.map(c => `<li class="rep-col"><label><input type="checkbox" data-rep-col="${escapeHtml(c.key)}"> ${escapeHtml(c.label)}</label></li>`).join("");
    columnsGroup.classList.toggle("hidden", !t.columns.length);
    document.getElementById("rep-sort").innerHTML = t.columns.map(c =>
      `<option value="${escapeHtml(c.key)}" ${c.key === s.sort.column ? "selected" : ""}>${escapeHtml(c.label)}</option>`).join("");
    document.getElementById("rep-desc").value = s.sort.desc ? "1" : "0";
    document.getElementById("rep-limit").value = s.limit || "";
  } else {
    renderReportBuilder();
  }
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
  if (s.template === "custom") {
    const sub = document.getElementById("rep-b-subtitle"), aud = document.getElementById("rep-b-audience");
    if (sub) s.subtitle = sub.value.trim();
    if (aud) s.audience = aud.value.trim();
    return s;
  }
  s.sort = { column: document.getElementById("rep-sort").value, desc: document.getElementById("rep-desc").value === "1" };
  s.limit = parseInt(document.getElementById("rep-limit").value, 10) || 0;
  const outage = document.getElementById("rep-outage");
  if (outage && reportTemplate(s.template).focus === "outage") s.focus = { outage: parseInt(outage.value, 10) || 0 };
  return s;
}

/* --- The builder --------------------------------------------------------------------------------
 * Each block is a card: what it shows in a line, buttons to move it, change it or take it out. The
 * open card shows its settings. A chart asks what you want to know, or which data; then it offers
 * only the charts that suit that data's shape. Every setting is checked again by the monitor. */

function repSource(id) { return reportCatalog().sources.find(s => s.id === id); }
function repView(b) { const s = repSource(b.source); return s ? s.views.find(v => v.id === b.view) : null; }
function repTableDef(id) { return reportCatalog().tables.find(t => t.id === id); }

function repBlockAt(path) {
  const [i, side] = String(path).split(".");
  const b = reportSpec.blocks[Number(i)];
  return side ? (b ? b[side] : null) : b;
}

function repDefaultBlock(type) {
  const cat = reportCatalog();
  if (type === "chart") return repChartBlock("availability", "time", "columns");
  if (type === "kpi_row") return { type, title: "", tiles: [{ metric: "availability", compare: "previous" }, { metric: "ping", compare: "previous" }, { metric: "problems", compare: "previous" }] };
  if (type === "table") { const t = cat.tables[0]; return { type, title: "", entity: t.id, columns: [...t.default], sort: { column: t.sort, desc: t.desc }, limit: 0 }; }
  if (type === "text") return { type, title: "Notes", text: "" };
  if (type === "key_value") return { type, title: "Device details" };
  return { type: "two_column", left: repChartBlock("availability", "per", "bar"), right: { type: "text", title: "Notes", text: "" } };
}

function repChartBlock(source, view, chart) {
  const b = { type: "chart", title: "", note: "", source, view, chart, scope: { kind: "all" }, period: "", threshold: { mode: "inherit" } };
  const v = repView(b);
  if (v) {
    if (v.aggs.length) b.agg = v.aggs[0];
    if (v.splits.length) b.split = v.splits[0];
    if (v.top) b.top = v.top;
  }
  return b;
}

function repBlockLine(b) {
  if (!b) return "Empty";
  const cat = reportCatalog();
  if (b.type === "chart") return repChartName(b) + (b.title ? `, titled ${b.title}` : "");
  if (b.type === "kpi_row") return (b.tiles || []).map(t => t.label || (cat.kpis.find(k => k.id === t.metric) || {}).label || t.metric).join(", ");
  if (b.type === "table") return (repTableDef(b.entity) || {}).label || b.entity;
  if (b.type === "text") return b.auto ? `${b.title || "Text"}, written from the data` : `${b.title || "Text"}${b.text ? `: ${b.text.slice(0, 60)}${b.text.length > 60 ? "..." : ""}` : ""}`;
  if (b.type === "key_value") return b.title || "Device details";
  if (b.type === "part") {
    const t = reportTemplate(b.template);
    return `${t.title}: ${(t.parts || {})[b.part] || b.part}`;
  }
  return "";
}

function repSelect(path, field, options, value, label) {
  const id = `rb-${String(path).replace(".", "-")}-${field}`;
  return `<div class="form-group"><label for="${escapeHtml(id)}">${escapeHtml(label)}</label><select id="${escapeHtml(id)}" data-bp="${escapeHtml(path)}" data-bf="${escapeHtml(field)}">
    ${options.map(([v, l]) => `<option value="${escapeHtml(v)}" ${String(v) === String(value) ? "selected" : ""}>${escapeHtml(l)}</option>`).join("")}</select></div>`;
}

function repInput(path, field, value, label, kind, extra) {
  const id = `rb-${String(path).replace(".", "-")}-${field}`;
  return `<div class="form-group"><label for="${escapeHtml(id)}">${escapeHtml(label)}</label><input id="${escapeHtml(id)}" type="${kind === "number" ? "number" : "text"}"
    ${kind === "number" ? "step=\"any\"" : "maxlength=\"120\""} data-bp="${escapeHtml(path)}" data-bf="${escapeHtml(field)}" value="${escapeHtml(value === undefined || value === null ? "" : value)}" placeholder="${escapeHtml(extra || "")}"></div>`;
}

function repScopeFields(path, b) {
  const sc = b.scope || { kind: "all" };
  const kinds = [["all", "Every device the report covers"], ["group", "One group"], ["tag", "Devices with a tag"], ["devices", "Chosen devices"]];
  let which = "";
  if (sc.kind === "group") which = repSelect(path, "scope_group", reportsData.groups.map(g => [g.id, g.name]), sc.group, "Which group");
  else if (sc.kind === "tag") which = repSelect(path, "scope_tag", reportsData.tags.map(n => [n, n]), sc.tag, "Which tag");
  else if (sc.kind === "devices") {
    const chosen = new Set(sc.devices || []);
    which = `<div class="form-group rep-b-devices"><span class="form-label">Which devices</span><div class="rep-b-checks">${reportsData.devices.map(d =>
      `<label class="checkbox-label"><input type="checkbox" data-bp="${escapeHtml(path)}" data-bf="scope_device" value="${escapeHtml(d.id)}" ${chosen.has(d.id) ? "checked" : ""}> ${escapeHtml(d.name)}</label>`).join("")}</div></div>`;
  }
  return `<div class="form-row">${repSelect(path, "scope_kind", kinds, sc.kind, "Devices")}${which}</div>`;
}

function repPeriodField(path, b) {
  return repSelect(path, "period", [["", "The report's period"]].concat(reportsData.periods.map(p => [p, REPORT_PERIODS[p] || p])), b.period || "", "Period");
}

function repChartEditor(path, b) {
  const cat = reportCatalog();
  const q = cat.questions.find(x => x.id === b._q);
  const sources = q ? cat.sources.filter(s => q.charts.some(c => c.source === s.id)) : cat.sources;
  const s = repSource(b.source) || cat.sources[0];
  const v = repView(b) || s.views[0];
  const charts = v.charts.map(id => [id, `${cat.charts[id].label}${cat.charts[id].n ? ` (chart ${cat.charts[id].n})` : ""}`]);
  const th = b.threshold || { mode: "inherit" };
  const limits = v.limits ? `<div class="form-row">${repSelect(path, "th_mode", [["inherit", "The monitor's own"], ["override", "Set for this report"]], th.mode, v.limits === "target" ? "Target" : "Limits")}
      ${th.mode === "override" ? (v.limits === "target" ? repInput(path, "th_target", th.target, "Target value", "number")
        : repInput(path, "th_warn", th.warn, "Amber from", "number") + repInput(path, "th_bad", th.bad, "Red from", "number")) : ""}</div>` : "";
  return `<div class="form-row">${repSelect(path, "_q", [["", "Any question"]].concat(cat.questions.map(x => [x.id, x.text])), b._q || "", "What do you want to know?")}</div>
    ${q ? `<div class="rep-suggest-row">${q.charts.map(ch => `<button type="button" class="btn btn-small" data-b-pick="${escapeHtml(`${path}|${ch.source}|${ch.view}|${ch.chart}`)}">${escapeHtml(repChartName(ch))}</button>`).join("")}</div>
      ${q.gap ? `<p class="dim rep-b-hint">${escapeHtml(q.gap)}</p>` : ""}` : ""}
    <div class="form-row">${repSelect(path, "source", sources.map(x => [x.id, x.label]), s.id, "Data")}${repSelect(path, "view", s.views.map(x => [x.id, x.label]), v.id, "Show it")}</div>
    <p class="dim rep-b-hint">${escapeHtml(s.about)} Shape: ${escapeHtml(((cat.shapes || {})[v.shape] || v.shape).toLowerCase())}, so only the charts that suit it are offered.</p>
    <div class="form-row">${repSelect(path, "chart", charts, b.chart, "Chart")}
      ${v.aggs.length ? repSelect(path, "agg", v.aggs.map(a => [a, cat.aggs[a] || a]), b.agg, "Figure") : ""}
      ${v.splits.length ? repSelect(path, "split", v.splits.map(x => [x, cat.splits[x] || x]), b.split, "Split") : ""}
      ${v.top ? repInput(path, "top", b.top || v.top, "How many", "number") : ""}</div>
    ${repScopeFields(path, b)}
    <div class="form-row">${repPeriodField(path, b)}</div>
    ${limits}
    <div class="form-row">${repInput(path, "title", b.title, "Title", "text", "From the data")}${repInput(path, "note", b.note, "How to read it", "text", "From the data")}</div>`;
}

function repKpiEditor(path, b) {
  const cat = reportCatalog();
  const tiles = b.tiles || [];
  return `<ol class="rep-b-tiles">${tiles.map((t, i) => {
    const m = cat.kpis.find(k => k.id === t.metric) || cat.kpis[0];
    const tp = `${path}:${i}`;
    const compares = (m.now ? [] : [["previous", "The period before"]]).concat([["target", "A target"], ["none", "Nothing"]]);
    return `<li class="rep-b-tile"><div class="form-row">${repSelect(tp, "metric", cat.kpis.map(k => [k.id, k.label]), t.metric, `Figure ${i + 1}`)}
        ${m.aggs.length ? repSelect(tp, "agg", m.aggs.map(a => [a, cat.aggs[a] || a]), t.agg || m.aggs[0], "Which") : ""}
        ${repSelect(tp, "compare", compares, t.compare || (m.now ? "none" : "previous"), "Compared with")}
        ${(t.compare || "") === "target" ? repInput(tp, "target", isNum(t.target) ? t.target : m.target, "Target", "number") : ""}
        ${repSelect(tp, "better", [["", "As the figure says"], ["up", "Higher is better"], ["down", "Lower is better"]], t.better || "", "Better when")}
        ${repInput(tp, "label", t.label, "Label", "text", m.label)}</div>
        <button type="button" class="btn btn-small" data-b-tile-del="${escapeHtml(tp)}">Take this figure out</button></li>`;
  }).join("")}</ol>
    ${tiles.length < 6 ? `<button type="button" class="btn btn-small" data-b-tile-add="${escapeHtml(path)}">Add a figure</button>` : `<span class="dim">Six figures at most.</span>`}
    ${repScopeFields(path, b)}<div class="form-row">${repPeriodField(path, b)}</div>`;
}

function repTableEditor(path, b) {
  const cat = reportCatalog();
  const t = repTableDef(b.entity) || cat.tables[0];
  const chosen = new Set(b.columns || t.default);
  const statuses = Object.entries(t.status || {});
  const sparks = Object.entries(t.sparks || {});
  return `<div class="form-row">${repSelect(path, "entity", cat.tables.map(x => [x.id, x.label]), t.id, "Rows")}
      ${b.entity === "group" ? repSelect(path, "split", [["auto", "Groups, or devices with one group"], ["group", "Groups"], ["device", "Devices"]], b.split || "auto", "One row per") : ""}</div>
    <div class="form-group"><span class="form-label">Columns</span><div class="rep-b-checks">${t.columns.map(c =>
      `<label class="checkbox-label"><input type="checkbox" data-bp="${escapeHtml(path)}" data-bf="column" value="${escapeHtml(c.key)}" ${chosen.has(c.key) ? "checked" : ""}> ${escapeHtml(c.label)}</label>`).join("")}</div></div>
    <div class="form-row">${statuses.length ? repSelect(path, "status", statuses, b.status || statuses[0][0], "Status column shows") : ""}
      ${sparks.length ? repSelect(path, "spark", sparks, b.spark || sparks[0][0], "Trend column shows") : ""}</div>
    <div class="form-row">${repSelect(path, "sort_column", [["", "As listed"]].concat(t.columns.filter(c => c.type !== "spark").map(c => [c.key, c.label])), (b.sort || {}).column || "", "Sort by")}
      ${repSelect(path, "sort_desc", [["0", "Lowest first, A to Z"], ["1", "Highest first, Z to A"]], (b.sort || {}).desc ? "1" : "0", "Order")}
      ${repInput(path, "limit", b.limit || "", "Only the first", "number", "All rows")}</div>
    ${repScopeFields(path, b)}<div class="form-row">${repPeriodField(path, b)}</div>
    <div class="form-row">${repInput(path, "title", b.title, "Title", "text", t.label)}${repInput(path, "note", b.note, "Note", "text", "")}</div>`;
}

function repTextEditor(path, b) {
  const cat = reportCatalog();
  const id = `rb-${String(path).replace(".", "-")}-text`;
  return `<div class="form-row">${repInput(path, "title", b.title, "Title", "text", "Notes")}
      ${repSelect(path, "auto", [["", "Your own words"]].concat(Object.entries(cat.auto || {}).map(([k, l]) => [k, `Written from the data: ${l.toLowerCase()}`])), b.auto || "", "What it says")}</div>
    ${b.auto ? `<p class="dim rep-b-hint">The monitor writes this from the data each time the report runs.</p>`
      : `<div class="form-group"><label for="${escapeHtml(id)}">Words <span class="dim">(kept with the saved report; a new line starts a new paragraph)</span></label>
      <textarea id="${escapeHtml(id)}" rows="5" maxlength="4000" data-bp="${escapeHtml(path)}" data-bf="text">${escapeHtml(b.text || "")}</textarea></div>`}`;
}

function repKvEditor(path, b) {
  const sc = b.scope || { kind: "all" };
  const current = sc.kind === "devices" && (sc.devices || []).length ? String(sc.devices[0]) : "";
  return `<div class="form-row">${repInput(path, "title", b.title, "Title", "text", "Device details")}
    ${repSelect(path, "kv_device", [["", "The first device the report covers"]].concat(reportsData.devices.map(d => [String(d.id), d.name])), current, "Which device")}</div>`;
}

function repEditor(path, b) {
  if (!b) return "";
  if (b.type === "chart") return repChartEditor(path, b);
  if (b.type === "kpi_row") return repKpiEditor(path, b);
  if (b.type === "table") return repTableEditor(path, b);
  if (b.type === "text") return repTextEditor(path, b);
  if (b.type === "key_value") return repKvEditor(path, b);
  if (b.type === "part") return `<p class="dim rep-b-hint">A ready-made block from ${escapeHtml(reportTemplate(b.template).title)}: it shows what that template shows here. Move it or take it out; for your own settings add a chart or a table instead.</p>
    <div class="form-row">${repInput(path, "title", b.title, "Title", "text", "From the template")}</div>`;
  return "";
}

function repCard(path, b, last, first) {
  const open = reportOpen === String(path);
  const side = String(path).includes(".");
  const name = b ? BLOCK_NAMES[b.type] || b.type : "Empty";
  const moves = side ? "" : `<button type="button" class="btn btn-small" data-b-move="${escapeHtml(`${path}|-1`)}" ${first ? "disabled" : ""} aria-label="Move up" title="Move up">&uarr;</button>
      <button type="button" class="btn btn-small" data-b-move="${escapeHtml(`${path}|1`)}" ${last ? "disabled" : ""} aria-label="Move down" title="Move down">&darr;</button>`;
  const sideType = side ? repSelect(path, "side_type", [["chart", "Chart"], ["text", "Text"], ["key_value", "Device details"], ["", "Nothing"]], b ? b.type : "", "This side holds") : "";
  return `<div class="rep-b-card ${open ? "open" : ""}">
    <div class="rep-b-head"><span class="rep-b-type">${escapeHtml(name)}</span><span class="rep-b-line">${escapeHtml(repBlockLine(b))}</span>
      <span class="rep-b-actions">${moves}${b ? `<button type="button" class="btn btn-small" data-b-open="${escapeHtml(path)}">${open ? "Done" : "Change"}</button>` : ""}
      ${side ? "" : `<button type="button" class="btn btn-small btn-danger" data-b-del="${escapeHtml(path)}" aria-label="Take this block out" title="Take this block out">&times;</button>`}</span></div>
    ${open || side ? `<div class="rep-b-body">${sideType}${open ? repEditor(path, b) : ""}</div>` : ""}</div>`;
}

function renderReportBuilder() {
  const box = document.getElementById("rep-builder");
  const s = reportSpec;
  const blocks = s.blocks || [];
  const limit = (reportCatalog().limits || {}).blocks || 30;
  const cards = blocks.map((b, i) => {
    const first = i === 0, last = i === blocks.length - 1;
    if (b.type !== "two_column") return repCard(String(i), b, last, first);
    const open = reportOpen && reportOpen.startsWith(`${i}.`);
    return `<div class="rep-b-card rep-b-two ${open ? "open" : ""}">
      <div class="rep-b-head"><span class="rep-b-type">${escapeHtml(BLOCK_NAMES.two_column)}</span><span class="rep-b-line">${escapeHtml(`${repBlockLine(b.left)} | ${repBlockLine(b.right)}`)}</span>
        <span class="rep-b-actions"><button type="button" class="btn btn-small" data-b-move="${escapeHtml(`${i}|-1`)}" ${first ? "disabled" : ""} aria-label="Move up" title="Move up">&uarr;</button>
        <button type="button" class="btn btn-small" data-b-move="${escapeHtml(`${i}|1`)}" ${last ? "disabled" : ""} aria-label="Move down" title="Move down">&darr;</button>
        <button type="button" class="btn btn-small btn-danger" data-b-del="${escapeHtml(i)}" aria-label="Take this block out" title="Take this block out">&times;</button></span></div>
      <div class="rep-b-sides">${repCard(`${i}.left`, b.left, true, true)}${repCard(`${i}.right`, b.right, true, true)}</div></div>`;
  }).join("");
  box.innerHTML = `<div class="form-row">
      <div class="form-group"><label for="rep-b-subtitle">What it is for</label><input type="text" id="rep-b-subtitle" maxlength="200" value="${escapeHtml(s.subtitle || "")}" placeholder="One line under the title"></div>
      <div class="form-group"><label for="rep-b-audience">Audience</label><input type="text" id="rep-b-audience" maxlength="80" value="${escapeHtml(s.audience || "")}" placeholder="Who reads it"></div></div>
    <div class="rep-b-list">${cards || `<div class="dim rep-empty">No blocks yet. Add key figures, a chart, a table or some text below, or pick a question on the left.</div>`}</div>
    ${blocks.length < limit ? `<div class="rep-b-add"><span class="form-label">Add</span>${Object.entries(BLOCK_NAMES).filter(([k]) => k !== "part").map(([k, l]) =>
      `<button type="button" class="btn btn-small" data-b-add="${escapeHtml(k)}">${escapeHtml(l)}</button>`).join("")}</div>` : `<div class="dim">A report holds at most ${escapeHtml(limit)} blocks.</div>`}`;
}

/** A builder setting changed: field on the block at path (a tile's path is "block:tile"). */
function repSetField(el) {
  const path = el.dataset.bp, field = el.dataset.bf;
  const [blockPath, tileIndex] = path.split(":");
  const b = repBlockAt(blockPath);
  if (field === "side_type") {
    const [i, side] = blockPath.split(".");
    const kind = el.value;
    reportSpec.blocks[Number(i)][side] = kind ? (kind === "chart" ? repChartBlock("availability", "per", "bar") : repDefaultBlock(kind)) : null;
    reportOpen = kind ? blockPath : null;
    return;
  }
  if (!b) return;
  const num = v => { const n = parseFloat(v); return isFinite(n) ? n : undefined; };
  if (tileIndex !== undefined) {
    const t = b.tiles[Number(tileIndex)];
    if (field === "target") t.target = num(el.value);
    else if (field === "metric") { b.tiles[Number(tileIndex)] = { metric: el.value }; }
    else t[field] = el.value;
    return;
  }
  const v = el.value;
  if (field === "_q") { b._q = v; return; }
  if (field === "source") { Object.assign(b, repChartBlock(v, repSource(v).views[0].id, repSource(v).views[0].charts[0]), { title: b.title, note: b.note, _q: b._q }); return; }
  if (field === "view") { const view = repSource(b.source).views.find(x => x.id === v); Object.assign(b, repChartBlock(b.source, v, view.charts[0]), { title: b.title, note: b.note, _q: b._q }); return; }
  if (field === "scope_kind") { b.scope = v === "group" ? { kind: v, group: (reportsData.groups[0] || {}).id || "" } : v === "tag" ? { kind: v, tag: reportsData.tags[0] || "" } : v === "devices" ? { kind: v, devices: [] } : { kind: "all" }; return; }
  if (field === "scope_group") { b.scope = { kind: "group", group: v }; return; }
  if (field === "scope_tag") { b.scope = { kind: "tag", tag: v }; return; }
  if (field === "scope_device") {
    const ids = new Set((b.scope && b.scope.devices) || []);
    const id = parseInt(v, 10);
    if (el.checked) ids.add(id); else ids.delete(id);
    b.scope = { kind: "devices", devices: [...ids] };
    return;
  }
  if (field === "kv_device") { b.scope = v ? { kind: "devices", devices: [parseInt(v, 10)] } : { kind: "all" }; return; }
  if (field === "th_mode") { b.threshold = { mode: v }; return; }
  if (field.startsWith("th_")) { b.threshold = { ...(b.threshold || { mode: "override" }), [field.slice(3)]: num(v) }; return; }
  if (field === "column") {
    const def = repTableDef(b.entity);
    const set = new Set(b.columns || def.default);
    if (el.checked) set.add(v); else set.delete(v);
    b.columns = def.columns.map(c => c.key).filter(k => set.has(k));
    if (!b.columns.length) b.columns = [v];
    return;
  }
  if (field === "entity") { const def = repTableDef(v); Object.assign(b, { entity: v, columns: [...def.default], sort: { column: def.sort, desc: def.desc }, status: "", spark: "" }); return; }
  if (field === "sort_column") { b.sort = { ...(b.sort || {}), column: v }; return; }
  if (field === "sort_desc") { b.sort = { ...(b.sort || {}), desc: v === "1" }; return; }
  if (field === "top" || field === "limit") { b[field] = parseInt(v, 10) || 0; return; }
  if (field === "auto") { b.auto = v; return; }
  b[field] = v;
}

/** The spec as sent: the builder's own notes (the chosen question) left out. */
function repSpecForServer() {
  const s = readReportCustomizer();
  if (s.template !== "custom") return s;
  return JSON.parse(JSON.stringify(s, (k, v) => (k === "_q" ? undefined : v)));
}

function repAddChart(source, view, chart) {
  if (reportSpec.template !== "custom") {
    reportSpec = newCustomSpec("");
    reportEditing = null;
    reportPreview = null;
  }
  reportSpec.blocks.push(repChartBlock(source, view, chart));
  reportOpen = String(reportSpec.blocks.length - 1);
  renderReportCustomizer();
  renderReportSaved();
  renderReportPreview();
}

function formatReportCell(type, v) {
  if (v === null || v === undefined || v === "") return "";
  if (typeof v !== "number") return String(v);
  if (type === "pct") return (v >= 99.95 && v < 100) || (v > 0 && v < 1) ? `${v.toFixed(2)}%` : `${v.toFixed(1)}%`;
  if (type === "ms") return v >= 10 ? `${Math.round(v)} ms` : `${v.toFixed(1)} ms`;
  if (type === "time") return v > 0 ? formatTime(v) : "";
  if (type === "bytes") return formatBytes(v);
  if (type === "duration") return formatDuration(v);
  if (type === "mbps") return v >= 1000 ? `${v / 1000} Gbps` : `${Math.round(v)} Mbps`;
  if (type === "bps") return formatBps(v);
  if (type === "dbm") return `${Math.round(v)} dBm`;
  return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2);
}

/* --- The report layout: header band, then the blocks in order, then the footer -----------------
 * The same layout as the PDF (pdfdoc.py). Charts are drawn here as inline SVG or plain HTML at the
 * width they get, so text stays its real size; the preview is drawn again when that width changes.
 * Colours come from reports.css: green, amber and red only for status, blue, teal, purple and orange
 * for ordinary series, grey for no data. */

const REP_TONES = ["good", "warn", "bad", "info", "none"];

/** A tone name safe for a class (anything unknown is grey). */
function repTone(t) { return REP_TONES.includes(t) ? t : "none"; }

/** A tone or a series ("s3") as a class. */
function repToneCls(t, i) {
  if (REP_TONES.includes(t)) return `rt-${t}`;
  const m = /^s(\d)$/.exec(String(t || ""));
  return `rs-${m ? Number(m[1]) % 6 : (i || 0) % 3}`;
}

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
  const all = (marks || []).filter(m => m && isNum(m.value));
  if (yMax !== null && yMax !== undefined) return [all, []];
  const near = all.filter(m => m.value <= Math.max(top, 0) * 2);
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

/** A filled band between two values per point (lo and hi indexes); a missing value breaks it. */
function repBandPath(rows, loI, hiI, x, y) {
  let d = "", run = [];
  const flush = () => {
    if (run.length) d += `M${run.map(r => `${rn(x(r[0]))},${rn(y(r[loI]))}`).join("L")}L${run.slice().reverse().map(r => `${rn(x(r[0]))},${rn(y(r[hiI]))}`).join("L")}Z`;
    run = [];
  };
  for (const r of rows) { if (isNum(r[loI]) && isNum(r[hiI])) run.push(r); else flush(); }
  flush();
  return d;
}

/** A ring segment in screen angles (radians, clockwise from the right), for gauges and the clock. */
function repWedge(cx, cy, r1, r2, t1, t2) {
  const large = t2 - t1 > Math.PI ? 1 : 0;
  const p = (r, t) => `${rn(cx + r * Math.cos(t))},${rn(cy + r * Math.sin(t))}`;
  return `M${p(r2, t1)}A${rn(r2)},${rn(r2)} 0 ${large} 1 ${p(r2, t2)}L${p(r1, t2)}A${rn(r1)},${rn(r1)} 0 ${large} 0 ${p(r1, t1)}Z`;
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
  const dots = (c.dots || []).map(([t, v]) => `<circle class="rep-dot rt-bad" cx="${rn(x(t))}" cy="${rn(y(v))}" r="2.6"></circle>`).join("");
  const legend = (series.length > 1 ? series.map((s, i) => [s.name, repSeriesCls(s, i), false]) : [])
    .concat(marks.filter(m => m.label).map(m => [m.label, `rt-${repTone(m.tone)}`, true]))
    .concat(far.filter(m => m.label).map(m => [`${m.label}, above the chart`, `rt-${repTone(m.tone)}`, true]));
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${bands}${axis}
    <line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(base)}" y2="${rn(base)}"></line>${repTimeAxis(t0, t1, x, base, W)}${lines}${paths}${dots}</svg>${repLegend(legend)}`;
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
  const grouped = !!c.grouped && !stacked;
  const totals = labels.map((_, i) => stacked ? series.reduce((a, s) => a + Math.max(0, s.values[i] || 0), 0) : Math.max(...series.map(s => s.values[i] || 0)));
  let target = c.target && isNum(c.target.value) ? c.target : null;
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
      const each = grouped ? bw / series.length : bw;
      const bx = padL + i * slot + (slot - bw) / 2 + (grouped ? si * each : 0);
      const topV = stacked ? floor + Math.max(0, v) : v;
      const r = `<rect class="rep-colbar ${escapeHtml(cls)}" x="${rn(bx)}" y="${rn(y(topV))}" width="${rn(Math.max(0.6, each - (grouped ? 1 : 0)))}" height="${rn(Math.max(0, y(stacked ? floor : low) - y(topV)))}"><title>${escapeHtml(label)}: ${escapeHtml(repFmt(v, c.unit))}${series.length > 1 ? ` ${escapeHtml(s.name)}` : ""}</title></rect>`;
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
  const marks = (c.thresholds || []).filter(m => isNum(m.value)).map(m => `<span class="rep-hmark rt-${escapeHtml(repTone(m.tone))}" style="left:${Math.min(100, m.value / max * 100).toFixed(1)}%"></span>`).join("");
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
  if (!grid.some(row => row.some(isNum))) return "";
  const top = c.max || 1;
  const hours = Array.from({ length: 24 }, (_, h) => h);
  return `<div class="rep-heat">${grid.map((row, w) => `<span class="rep-heat-day">${escapeHtml((c.rows || [])[w] || "")}</span>${row.map((v, h) =>
      `<span class="rep-heat-cell ${isNum(v) ? "" : "empty"}" style="--level:${isNum(v) ? Math.round(8 + 92 * Math.max(0, Math.min(1, v / top))) : 0}%" title="${escapeHtml(`${(c.rows || [])[w] || ""} ${String(h).padStart(2, "0")}:00 ${isNum(v) ? repFmt(v, c.unit) : "No data"}`)}"></span>`).join("")}`).join("")}
    <span></span>${hours.map(h => `<span class="rep-heat-hour">${h % 3 ? "" : escapeHtml(String(h).padStart(2, "0"))}</span>`).join("")}</div>
    <div class="rep-heat-scale dim">Low <span class="rep-heat-ramp"></span> High (${escapeHtml(repFmt(top, c.unit))})</div>`;
}

function repGrid(c) {
  const tiles = c.tiles || [];
  if (!tiles.length) return "";
  return `<div class="rep-tiles">${tiles.map(t => `<div class="rep-tile rt-${escapeHtml(repTone(t.tone))}" title="${escapeHtml(t.sub)}">
      <span class="rep-tile-name">${escapeHtml(t.label)}</span><span class="rep-tile-sub">${escapeHtml(t.sub)}</span></div>`).join("")}</div>
    ${repLegend((c.counts || []).map(([label, tone, n]) => [`${label} ${n}`, `rt-${repTone(tone)}`, false]))}`;
}

/* At a glance: gauges, headline numbers with a sparkline, sparkline tables, bullets ------------- */

function repGauges(c) {
  const gs = c.gauges || [];
  if (!gs.length) return "";
  return `<div class="rep-gauges">${gs.map(g => {
    const top = isNum(g.max) && g.max > 0 ? g.max : 100;
    const warn = isNum(g.warn) ? g.warn : top, bad = isNum(g.bad) ? g.bad : top;
    const ang = v => -Math.PI * (1 - Math.max(0, Math.min(1, v / top)));
    const arc = (a, b, cls) => `<path class="rep-arc ${escapeHtml(cls)}" d="${escapeHtml(repWedge(60, 60, 38, 54, a, b))}"></path>`;
    const has = isNum(g.value);
    const needle = has ? `<line class="rep-needle" x1="60" y1="60" x2="${rn(60 + 50 * Math.cos(ang(g.value)))}" y2="${rn(60 + 50 * Math.sin(ang(g.value)))}"></line><circle class="rep-needle-hub" cx="60" cy="60" r="3"></circle>` : "";
    const arcs = has ? arc(-Math.PI, ang(warn), "rt-good") + arc(ang(warn), ang(bad), "rt-warn") + arc(ang(bad), 0, "rt-bad") : arc(-Math.PI, 0, "rt-none");
    return `<figure class="rep-gauge"><svg viewBox="0 0 120 66" role="img" aria-label="${escapeHtml(`${g.label}: ${g.text}`)}">${arcs}${needle}</svg>
      <strong class="rep-gauge-value">${escapeHtml(g.text || "No data")}</strong><span class="rep-gauge-label">${escapeHtml(g.label)}</span></figure>`;
  }).join("")}</div>`;
}

function repSparkSvg(values, cls, dots, better) {
  const vals = (values || []).map((v, i) => [i, v]).filter(p => isNum(p[1]));
  if (vals.length < 2) return `<svg class="rep-spark" viewBox="0 0 100 18" role="img" aria-label="No trend"><line class="rep-gridline" x1="0" x2="100" y1="9" y2="9"></line></svg>`;
  const lo = Math.min(...vals.map(p => p[1])), hi = Math.max(...vals.map(p => p[1]));
  const n = Math.max((values || []).length - 1, 1);
  const x = i => i / n * 96 + 2, y = v => 16 - (v - lo) / ((hi - lo) || 1) * 14;
  const pts = (values || []).map((v, i) => [i, v]);
  let marks = "";
  if (dots) {
    const iMin = vals.reduce((a, p) => p[1] < a[1] ? p : a)[0], iMax = vals.reduce((a, p) => p[1] > a[1] ? p : a)[0];
    const last = vals[vals.length - 1];
    const lowGood = better !== "up";
    marks = `<circle class="rep-dot ${lowGood ? "rt-good" : "rt-bad"}" cx="${rn(x(iMin))}" cy="${rn(y(values[iMin]))}" r="2"></circle>
      <circle class="rep-dot ${lowGood ? "rt-bad" : "rt-good"}" cx="${rn(x(iMax))}" cy="${rn(y(values[iMax]))}" r="2"></circle>
      <circle class="rep-dot rs-5" cx="${rn(x(last[0]))}" cy="${rn(y(last[1]))}" r="2"></circle>`;
  }
  return `<svg class="rep-spark" viewBox="0 0 100 18" preserveAspectRatio="none" role="img" aria-label="Trend"><path class="rep-line ${escapeHtml(cls)}" d="${escapeHtml(repPath(pts, x, y))}"></path>${marks}</svg>`;
}

function repHeadline(c) {
  const items = c.items || [];
  if (!items.length) return "";
  return `<div class="rep-headlines">${items.map(it => `<div class="rep-headline"><span class="rep-headline-value">${escapeHtml(it.value_text || "-")}</span>
      <span class="rep-headline-label">${escapeHtml(it.label)}</span>${repSparkSvg(it.values, "rs-0", true, it.better)}</div>`).join("")}</div>`;
}

function repSparkTable(c) {
  const rows = c.rows || [];
  if (!rows.length) return "";
  const head = c.header || ["", "", "", ""];
  return `<div class="rep-sparktable"><div class="rep-st-row rep-st-head"><span>${escapeHtml(head[0] || "")}</span><span>${escapeHtml(head[1] || "")}</span><span>${escapeHtml(head[2] || "")}</span><span></span></div>
    ${rows.map(r => `<div class="rep-st-row"><span class="rep-st-name" title="${escapeHtml(r.name)}">${escapeHtml(r.name)}</span>
      ${repSparkSvg(r.values, r.tone === "warn" || r.tone === "bad" ? `rt-${repTone(r.tone)}` : "rs-0", false, "down")}
      <strong class="rep-st-now rt-${escapeHtml(repTone(r.tone))}">${escapeHtml(r.now)}</strong><span class="rep-st-dot rt-${escapeHtml(repTone(r.tone))}" title="${escapeHtml(r.tone)}"></span></div>`).join("")}</div>`;
}

function repBullet(c, W) {
  const rows = c.rows || [];
  if (!rows.length) return "";
  const lo = isNum(c.min) ? c.min : 0, hi = isNum(c.max) ? c.max : 100;
  const bands = c.bands || [lo, lo, hi];
  const labelW = Math.min(Math.max(...rows.map(r => String(r[0]).length)) * 6.4 + 10, W * 0.32);
  const valueW = 70, x0 = labelW, x1 = W - valueW;
  const sx = v => x0 + (Math.max(lo, Math.min(hi, v)) - lo) / ((hi - lo) || 1) * (x1 - x0);
  const H = rows.length * 22 + 22;
  const edges = [lo, bands[1], bands[2], hi];
  const body = rows.map(([label, value, text], i) => {
    const yy = i * 22 + 4;
    return `<text class="rep-tick rep-ink" x="${rn(x0 - 6)}" y="${rn(yy + 11)}" text-anchor="end">${escapeHtml(label)}</text>
      ${[0, 1, 2].map(k => `<rect class="rep-shade rep-shade-${Number(k)}" x="${rn(sx(edges[k]))}" y="${rn(yy)}" width="${rn(Math.max(0, sx(edges[k + 1]) - sx(edges[k])))}" height="15"></rect>`).join("")}
      ${isNum(value) ? `<rect class="rep-bullet-bar" x="${rn(x0)}" y="${rn(yy + 5)}" width="${rn(Math.max(1, sx(value) - x0))}" height="5"></rect>` : ""}
      ${isNum(c.target) ? `<line class="rep-tickmark rt-bad" x1="${rn(sx(c.target))}" x2="${rn(sx(c.target))}" y1="${rn(yy - 2)}" y2="${rn(yy + 17)}"></line>` : ""}
      <text class="rep-tick" x="${rn(x1 + 6)}" y="${rn(yy + 11)}">${escapeHtml(text)}</text>`;
  }).join("");
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${body}
    <text class="rep-tick" x="${rn(x0)}" y="${rn(H - 4)}">${escapeHtml(repFmt(lo, c.unit))}</text><text class="rep-tick" x="${rn(x1)}" y="${rn(H - 4)}" text-anchor="end">${escapeHtml(repFmt(hi, c.unit))}</text>
    ${isNum(c.target) && c.target_label ? `<text class="rep-tick rt-bad rep-tone-text" x="${rn(sx(c.target))}" y="${rn(H - 4)}" text-anchor="middle">${escapeHtml(c.target_label)}</text>` : ""}</svg>`;
}

/* Comparison: lollipop, diverging, dumbbell, butterfly, 100% stacked, treemap ------------------- */

function repLollipop(c, W, H) {
  const items = (c.items || []).filter(it => isNum(it[1]));
  if (!items.length) return "";
  const marks = (c.thresholds || []).filter(m => isNum(m.value));
  const ticks = repNiceTicks(0, isNum(c.max) ? c.max : Math.max(...items.map(it => it[1]), ...marks.map(m => m.value), 0) || 1, 4);
  const high = ticks[ticks.length - 1], top = 8, base = H - 22;
  const y = v => base - Math.max(0, Math.min(high, v)) / (high || 1) * (base - top);
  const padL = repPadL(ticks, c.unit);
  const slot = (W - 4 - padL) / items.length;
  const every = Math.max(1, Math.ceil(Math.max(...items.map(it => String(it[0]).length)) * 6 / Math.max(slot - 2, 1)));
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repYAxis(ticks, c.unit, y, W, padL)}
    ${marks.map(m => `<line class="rep-mark rt-${escapeHtml(repTone(m.tone))}" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(m.value))}" y2="${rn(y(m.value))}"></line>`).join("")}
    ${items.map(([label, value, tone], i) => {
      const cx = padL + slot * (i + 0.5);
      const cls = tone ? `rt-${repTone(tone)}` : "rs-0";
      return `<line class="rep-stem ${escapeHtml(cls)}" x1="${rn(cx)}" x2="${rn(cx)}" y1="${rn(base)}" y2="${rn(y(value))}"></line><circle class="rep-dot ${escapeHtml(cls)}" cx="${rn(cx)}" cy="${rn(y(value))}" r="4"><title>${escapeHtml(label)}: ${escapeHtml(repFmt(value, c.unit))}</title></circle>
        ${i % every ? "" : `<text class="rep-tick" x="${rn(cx)}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(String(label).length > 14 ? `${String(label).slice(0, 13)}...` : label)}</text>`}`;
    }).join("")}<line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(base)}" y2="${rn(base)}"></line></svg>
    ${repLegend(marks.filter(m => m.label).map(m => [m.label, `rt-${repTone(m.tone)}`, true]))}`;
}

function repDiverging(c, W) {
  const rows = (c.rows || []).filter(r => isNum(r[1]));
  if (!rows.length) return "";
  const labelW = Math.min(Math.max(...rows.map(r => String(r[0]).length)) * 6.4 + 10, W * 0.3);
  const x0 = labelW, x1 = W - 4, mid = (x0 + x1) / 2;
  const span = Math.max(...rows.map(r => Math.abs(r[1]))) || 1;
  const half = (x1 - x0) / 2 - 80;
  const H = rows.length * 20 + 26;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    ${rows.map(([label, d, text], i) => {
      const yy = i * 20 + 4, len = Math.abs(d) / span * half, worse = d > 0;
      return `<text class="rep-tick rep-ink" x="${rn(x0 - 6)}" y="${rn(yy + 11)}" text-anchor="end">${escapeHtml(label)}</text>
        <rect class="rep-colbar ${worse ? "rt-bad" : "rt-good"}" x="${rn(worse ? mid : mid - len)}" y="${rn(yy + 2)}" width="${rn(Math.max(1, len))}" height="12"></rect>
        <text class="rep-tick" x="${rn(worse ? mid + len + 4 : mid - len - 4)}" y="${rn(yy + 12)}" text-anchor="${worse ? "start" : "end"}">${escapeHtml(text)}</text>`;
    }).join("")}
    <line class="rep-zero" x1="${rn(mid)}" x2="${rn(mid)}" y1="0" y2="${rn(H - 18)}"></line>
    <text class="rep-tick rt-good rep-tone-text" x="${rn(x0)}" y="${rn(H - 4)}">&lt; ${escapeHtml(c.left_text || "Better")}</text>
    <text class="rep-tick rt-bad rep-tone-text" x="${rn(x1)}" y="${rn(H - 4)}" text-anchor="end">${escapeHtml(c.right_text || "Worse")} &gt;</text></svg>`;
}

function repDumbbell(c, W) {
  const rows = (c.rows || []).filter(r => isNum(r[1]) || isNum(r[2]));
  if (!rows.length) return "";
  const vals = rows.flatMap(r => [r[1], r[2]]).filter(isNum);
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const pad = (hi - lo) * 0.1 || Math.abs(hi) * 0.05 || 1;
  const ticks = repNiceTicks(lo >= 0 ? Math.max(0, lo - pad) : lo - pad, hi + pad, 4);
  const labelW = Math.min(Math.max(...rows.map(r => String(r[0]).length)) * 6.4 + 10, W * 0.32);
  const x0 = labelW, x1 = W - 8;
  const sx = v => x0 + (v - ticks[0]) / ((ticks[ticks.length - 1] - ticks[0]) || 1) * (x1 - x0);
  const H = rows.length * 20 + 22;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    ${ticks.map(t => `<line class="rep-gridline" x1="${rn(sx(t))}" x2="${rn(sx(t))}" y1="0" y2="${rn(H - 18)}"></line><text class="rep-tick" x="${rn(sx(t))}" y="${rn(H - 4)}" text-anchor="middle">${escapeHtml(repFmt(t, c.unit))}</text>`).join("")}
    ${rows.map(([label, a, b], i) => {
      const yy = i * 20 + 10;
      return `<text class="rep-tick rep-ink" x="${rn(x0 - 6)}" y="${rn(yy + 4)}" text-anchor="end">${escapeHtml(label)}</text>
        ${isNum(a) && isNum(b) ? `<line class="rep-dumb" x1="${rn(sx(a))}" x2="${rn(sx(b))}" y1="${rn(yy)}" y2="${rn(yy)}"></line>` : ""}
        ${isNum(a) ? `<circle class="rep-dot rs-4" cx="${rn(sx(a))}" cy="${rn(yy)}" r="4.5"><title>${escapeHtml(`${c.before_label}: ${repFmt(a, c.unit)}`)}</title></circle>` : ""}
        ${isNum(b) ? `<circle class="rep-dot rs-0" cx="${rn(sx(b))}" cy="${rn(yy)}" r="4.5"><title>${escapeHtml(`${c.after_label}: ${repFmt(b, c.unit)}`)}</title></circle>` : ""}`;
    }).join("")}</svg>${repLegend([[c.before_label || "Before", "rs-4", false], [c.after_label || "After", "rs-0", false]])}`;
}

function repButterfly(c, W) {
  const rows = c.rows || [];
  if (!rows.length) return "";
  const labelW = Math.min(Math.max(...rows.map(r => String(r[0]).length)) * 6.4 + 10, W * 0.28);
  const x0 = labelW, x1 = W - 2, mid = (x0 + x1) / 2, half = (x1 - mid) - 64;
  const top = Math.max(...rows.flatMap(r => [r[1] || 0, r[2] || 0])) || 1;
  const H = rows.length * 20 + 22;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    <text class="rep-tick rs-0 rep-tone-text" x="${rn(mid - 6)}" y="12" text-anchor="end">&lt; ${escapeHtml(c.left_label || "In")}</text>
    <text class="rep-tick rs-1 rep-tone-text" x="${rn(mid + 6)}" y="12">${escapeHtml(c.right_label || "Out")} &gt;</text>
    ${rows.map(([label, l, r], i) => {
      const yy = i * 20 + 20, lw = (l || 0) / top * half, rw = (r || 0) / top * half;
      return `<text class="rep-tick rep-ink" x="${rn(x0 - 6)}" y="${rn(yy + 10)}" text-anchor="end">${escapeHtml(label)}</text>
        <rect class="rep-colbar rs-0" x="${rn(mid - lw)}" y="${rn(yy)}" width="${rn(Math.max(0.6, lw))}" height="13"></rect>
        <rect class="rep-colbar rs-1" x="${rn(mid)}" y="${rn(yy)}" width="${rn(Math.max(0.6, rw))}" height="13"></rect>
        <text class="rep-tick" x="${rn(mid - lw - 4)}" y="${rn(yy + 10)}" text-anchor="end">${escapeHtml(repFmt(l, c.unit))}</text>
        <text class="rep-tick" x="${rn(mid + rw + 4)}" y="${rn(yy + 10)}">${escapeHtml(repFmt(r, c.unit))}</text>`;
    }).join("")}<line class="rep-zero" x1="${rn(mid)}" x2="${rn(mid)}" y1="16" y2="${rn(H)}"></line></svg>`;
}

function repStack100(c) {
  const rows = (c.rows || []).filter(r => (r.values || []).reduce((a, v) => a + v, 0) > 0);
  const parts = c.parts || [];
  if (!rows.length) return "";
  const cls = (p, i) => p.tone ? `rt-${repTone(p.tone)}` : `rep-blue-${Math.min(i, 2)}`;
  return `${repLegend(parts.map((p, i) => [p.name, cls(p, i), false]))}<div class="rep-stack100">${rows.map(r => {
    const total = r.values.reduce((a, v) => a + v, 0);
    return `<div class="rep-s100-row"><span class="rep-hbar-label" title="${escapeHtml(r.label)}">${escapeHtml(r.label)}</span><span class="rep-s100-bar">${r.values.map((v, i) => v ? `<span class="rep-s100-seg ${escapeHtml(cls(parts[i] || {}, i))}" style="width:${(v / total * 100).toFixed(2)}%" title="${escapeHtml(`${(parts[i] || {}).name}: ${v} of ${total}`)}">${v / total >= 0.12 ? escapeHtml(`${Math.round(v / total * 100)}%`) : ""}</span>` : "").join("")}</span></div>`;
  }).join("")}</div>`;
}

function repTreemap(c) {
  const items = c.items || [];
  if (!items.length) return "";
  return `<div class="rep-treemap">${items.map((it, i) => `<div class="rep-tm ${it.tone ? `rt-${escapeHtml(repTone(it.tone))}` : `rs-${escapeHtml(i % 3)}`}" style="left:${rn(it.x * 100)}%;top:${rn(it.y * 100)}%;width:${rn(it.w * 100)}%;height:${rn(it.h * 100)}%" title="${escapeHtml(`${it.label}: ${it.text}`)}">
      ${it.w * it.h > 0.012 ? `<span class="rep-tm-label">${escapeHtml(it.label)}</span><span class="rep-tm-value">${escapeHtml(it.text)}</span>` : ""}</div>`).join("")}</div>`;
}

/* Composition: waterfall and Pareto --------------------------------------------------------------- */

function repWaterfall(c, W, H) {
  const steps = c.steps || [];
  if (!steps.length) return "";
  let run = 0;
  const spans = steps.map(([label, v, kind]) => {
    if (kind === "start") { run = v; return [label, 0, v, "rs-5", v]; }
    if (kind === "minus") { const s = [label, run - v, run, "rt-bad", v]; run -= v; return s; }
    return [label, Math.min(0, v), Math.max(0, v), v >= 0 ? "rt-good" : "rt-bad", v];
  });
  const ticks = repNiceTicks(Math.min(0, ...spans.map(s => s[1])), Math.max(...spans.map(s => s[2])) || 1, 4);
  const lo = ticks[0], hi = ticks[ticks.length - 1], top = 14, base = H - 22;
  const y = v => base - (v - lo) / ((hi - lo) || 1) * (base - top);
  const padL = repPadL(ticks, c.unit);
  const slot = (W - 4 - padL) / spans.length;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repYAxis(ticks, c.unit, y, W, padL)}
    ${spans.map(([label, a, b, cls, v], i) => {
      const bx = padL + i * slot + slot * 0.15;
      return `<rect class="rep-colbar ${escapeHtml(cls)}" x="${rn(bx)}" y="${rn(y(b))}" width="${rn(slot * 0.7)}" height="${rn(Math.max(1, y(a) - y(b)))}"><title>${escapeHtml(`${label}: ${repFmt(v, c.unit)}`)}</title></rect>
        <text class="rep-tick" x="${rn(bx + slot * 0.35)}" y="${rn(y(b) - 3)}" text-anchor="middle">${escapeHtml(repFmt(v, c.unit))}</text>
        <text class="rep-tick" x="${rn(bx + slot * 0.35)}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(String(label).length > Math.max(4, slot / 6.5) ? `${String(label).slice(0, Math.max(3, Math.floor(slot / 6.5) - 2))}...` : label)}</text>`;
    }).join("")}<line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(0))}" y2="${rn(y(0))}"></line></svg>`;
}

function repPareto(c, W, H) {
  const bars = c.bars || [];
  if (!bars.length) return "";
  const cum = c.cumulative || [];
  let ticks = repNiceTicks(0, Math.max(...bars.map(b => b[1])) || 1, 4).filter(v => Number.isInteger(v));
  if (ticks.length < 2) ticks = [0, 1];
  const high = ticks[ticks.length - 1], top = 8, base = H - 22, right = W - 34;
  const y = v => base - v / (high || 1) * (base - top);
  const yp = p => base - p / 100 * (base - top);
  const padL = repPadL(ticks, "");
  const slot = (right - padL) / bars.length;
  const line = cum.map((p, i) => `${i ? "L" : "M"}${rn(padL + slot * (i + 0.5))},${rn(yp(p))}`).join("");
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repYAxis(ticks, "", y, right + 4, padL)}
    ${bars.map(([label, n], i) => `<rect class="rep-colbar rs-0" x="${rn(padL + i * slot + slot * 0.15)}" y="${rn(y(n))}" width="${rn(slot * 0.7)}" height="${rn(Math.max(0.5, base - y(n)))}"><title>${escapeHtml(`${label}: ${n}`)}</title></rect>
      <text class="rep-tick" x="${rn(padL + slot * (i + 0.5))}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(String(label).length > slot / 6.5 ? `${String(label).slice(0, Math.max(3, Math.floor(slot / 6.5) - 2))}...` : label)}</text>`).join("")}
    ${[0, 50, 100].map(p => `<text class="rep-tick" x="${rn(right + 4)}" y="${rn(yp(p) + 3.5)}">${escapeHtml(p)}%</text>`).join("")}
    <line class="rep-mark rt-none rep-dotted" x1="${rn(padL)}" x2="${rn(right)}" y1="${rn(yp(80))}" y2="${rn(yp(80))}"></line>
    <path class="rep-line rs-3" d="${escapeHtml(line)}"></path>${cum.map((p, i) => `<circle class="rep-dot rs-3" cx="${rn(padL + slot * (i + 0.5))}" cy="${rn(yp(p))}" r="2.5"></circle>`).join("")}
    <line class="rep-axisline" x1="${rn(padL)}" x2="${rn(right)}" y1="${rn(base)}" y2="${rn(base)}"></line></svg>
    ${repLegend([["Count", "rs-0", false], ["Running total (right axis)", "rs-3", false], ["80%", "rt-none", true]])}`;
}

/* Distribution: histogram, box plot, CDF ---------------------------------------------------------- */

function repHistogram(c, W, H) {
  const bins = c.bins || [];
  if (!bins.length) return "";
  let ticks = repNiceTicks(0, Math.max(...bins.map(b => b[2])) || 1, 4).filter(v => Number.isInteger(v));
  if (ticks.length < 2) ticks = [0, 1];
  const high = ticks[ticks.length - 1], top = 30, base = H - 22;
  const y = v => base - v / (high || 1) * (base - top);
  const padL = repPadL(ticks, "");
  const lo = bins[0][0], hi = bins[bins.length - 1][1];
  const x = v => padL + (v - lo) / ((hi - lo) || 1) * (W - 4 - padL);
  const xt = repNiceTicks(lo, hi, 5).filter(v => v >= lo && v <= hi);
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repYAxis(ticks, "", y, W, padL)}
    ${bins.map(([a, b, n]) => n ? `<rect class="rep-colbar rs-0 rep-soft" x="${rn(x(a) + 0.3)}" y="${rn(y(n))}" width="${rn(Math.max(0.5, x(b) - x(a) - 0.6))}" height="${rn(base - y(n))}"><title>${escapeHtml(`${repFmt(a, c.unit)} to ${repFmt(b, c.unit)}: ${n}`)}</title></rect>` : "").join("")}
    ${xt.map(t => `<text class="rep-tick" x="${rn(x(t))}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(repFmt(t, c.unit))}</text>`).join("")}
    ${(c.marks || []).filter(m => isNum(m.value)).map((m, k) => `<line class="rep-mark ${escapeHtml(repToneCls(m.tone))}" x1="${rn(x(Math.max(lo, Math.min(hi, m.value))))}" x2="${rn(x(Math.max(lo, Math.min(hi, m.value))))}" y1="${rn(base)}" y2="${rn(6 + k * 8)}"></line>
      <text class="rep-tick rep-tone-text ${escapeHtml(repToneCls(m.tone))}" x="${rn(x(Math.max(lo, Math.min(hi, m.value))) + 3)}" y="${rn(12 + k * 8)}">${escapeHtml(m.label)}</text>`).join("")}
    <line class="rep-axisline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(base)}" y2="${rn(base)}"></line></svg>`;
}

function repBox(c, W) {
  const rows = c.rows || [];
  if (!rows.length) return "";
  const high = Math.max(...rows.map(r => r.hi), ...rows.flatMap(r => r.outliers || []), isNum(c.target) ? c.target : 0) || 1;
  const ticks = repNiceTicks(0, high, 5);
  const labelW = Math.min(Math.max(...rows.map(r => String(r.label).length)) * 6.4 + 10, W * 0.3);
  const x0 = labelW, x1 = W - 8;
  const sx = v => x0 + v / (ticks[ticks.length - 1] || 1) * (x1 - x0);
  const H = rows.length * 22 + 22;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    ${ticks.map(t => `<line class="rep-gridline" x1="${rn(sx(t))}" x2="${rn(sx(t))}" y1="0" y2="${rn(H - 18)}"></line><text class="rep-tick" x="${rn(sx(t))}" y="${rn(H - 4)}" text-anchor="middle">${escapeHtml(repFmt(t, c.unit))}</text>`).join("")}
    ${isNum(c.target) ? `<line class="rep-mark rt-warn" x1="${rn(sx(c.target))}" x2="${rn(sx(c.target))}" y1="0" y2="${rn(H - 18)}"></line>` : ""}
    ${rows.map((r, i) => {
      const m = i * 22 + 11;
      return `<text class="rep-tick rep-ink" x="${rn(x0 - 6)}" y="${rn(m + 4)}" text-anchor="end">${escapeHtml(r.label)}</text>
        <line class="rep-whisker" x1="${rn(sx(r.lo))}" x2="${rn(sx(r.hi))}" y1="${rn(m)}" y2="${rn(m)}"></line>
        <line class="rep-whisker" x1="${rn(sx(r.lo))}" x2="${rn(sx(r.lo))}" y1="${rn(m - 4)}" y2="${rn(m + 4)}"></line><line class="rep-whisker" x1="${rn(sx(r.hi))}" x2="${rn(sx(r.hi))}" y1="${rn(m - 4)}" y2="${rn(m + 4)}"></line>
        <rect class="rep-boxrect" x="${rn(sx(r.q1))}" y="${rn(m - 7)}" width="${rn(Math.max(1, sx(r.q3) - sx(r.q1)))}" height="14"><title>${escapeHtml(`${r.label}: median ${repFmt(r.med, c.unit)}, middle half ${repFmt(r.q1, c.unit)} to ${repFmt(r.q3, c.unit)}, ${r.n} answers`)}</title></rect>
        <line class="rep-median" x1="${rn(sx(r.med))}" x2="${rn(sx(r.med))}" y1="${rn(m - 7)}" y2="${rn(m + 7)}"></line>
        ${(r.outliers || []).map(o => `<circle class="rep-outlier" cx="${rn(sx(o))}" cy="${rn(m)}" r="1.6"></circle>`).join("")}`;
    }).join("")}</svg>${isNum(c.target) && c.target_label ? repLegend([[c.target_label, "rt-warn", true]]) : ""}`;
}

function repCdf(c, W, H) {
  const series = (c.series || []).filter(s => (s.points || []).length);
  if (!series.length) return "";
  const xt = repNiceTicks(0, Math.max(...series.flatMap(s => s.points.map(p => p[0]))) || 1, 5);
  const padL = 40, top = 8, base = H - 22;
  const x = v => padL + v / (xt[xt.length - 1] || 1) * (W - 4 - padL);
  const y = f => base - f * (base - top);
  const mark = isNum(c.mark) ? c.mark : 0.95;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    ${[0, 0.25, 0.5, 0.75, 1].map(f => `<line class="rep-gridline" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(f))}" y2="${rn(y(f))}"></line><text class="rep-tick" x="${rn(padL - 5)}" y="${rn(y(f) + 3.5)}" text-anchor="end">${escapeHtml(Math.round(f * 100))}%</text>`).join("")}
    ${xt.map(t => `<line class="rep-gridline" x1="${rn(x(t))}" x2="${rn(x(t))}" y1="${rn(top)}" y2="${rn(base)}"></line><text class="rep-tick" x="${rn(x(t))}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(repFmt(t, c.unit))}</text>`).join("")}
    <line class="rep-mark rt-none rep-dotted" x1="${rn(padL)}" x2="${rn(W - 4)}" y1="${rn(y(mark))}" y2="${rn(y(mark))}"></line>
    <text class="rep-tick" x="${rn(W - 8)}" y="${rn(y(mark) + 13)}" text-anchor="end">${escapeHtml(Math.round(mark * 100))}% of answers</text>
    ${series.map((s, i) => `<path class="rep-line rs-${escapeHtml(i % 4)}" d="${escapeHtml(repPath(s.points, x, y))}"><title>${escapeHtml(s.name)}</title></path>`).join("")}</svg>
    ${repLegend(series.map((s, i) => [s.name, `rs-${i % 4}`, false]))}`;
}

/* Over time: percentile band, against the usual, step, small multiples, forecast ----------------- */

function repTimeFrame(c, W, H, low, high) {
  const ticks = repNiceTicks(low, high, 4);
  const lo = ticks[0], hi = ticks[ticks.length - 1], top = 8, base = H - 22;
  const y = v => base - (Math.max(lo, Math.min(hi, v)) - lo) / ((hi - lo) || 1) * (base - top);
  const padL = repPadL(ticks, c.unit);
  const t0 = c.start, t1 = c.end > c.start ? c.end : c.start + 1;
  const x = t => padL + (t - t0) / (t1 - t0) * (W - 4 - padL);
  return { x, y, ticks, padL, base, top, t0, t1 };
}

/** The axes of a time frame (repTimeFrame): value labels on the left, times along the bottom. */
function repFrameAxis(f, unit, W) {
  return `${repYAxis(f.ticks, unit, f.y, W, f.padL)}<line class="rep-axisline" x1="${rn(f.padL)}" x2="${rn(W - 4)}" y1="${rn(f.base)}" y2="${rn(f.base)}"></line>${repTimeAxis(f.t0, f.t1, f.x, f.base, W)}`;
}

function repBand(c, W, H) {
  const pts = c.points || [];
  const vals = pts.flatMap(p => p.slice(1)).filter(isNum);
  if (!vals.length) return "";
  const [marks] = repSplitMarks(c.thresholds, Math.max(...vals), null);
  const f = repTimeFrame({ ...c, start: c.start || pts[0][0], end: c.end || pts[pts.length - 1][0] }, W, H, 0, Math.max(...vals, ...marks.map(m => m.value)));
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repFrameAxis(f, c.unit, W)}
    <path class="rep-area rs-0 rep-band-outer" d="${escapeHtml(repBandPath(pts, 1, 5, f.x, f.y))}"></path>
    <path class="rep-area rs-0 rep-band-inner" d="${escapeHtml(repBandPath(pts, 2, 4, f.x, f.y))}"></path>
    <path class="rep-line rs-5" d="${escapeHtml(repPath(pts.map(p => [p[0], p[3]]), f.x, f.y))}"></path>
    ${marks.map(m => `<line class="rep-mark rt-${escapeHtml(repTone(m.tone))}" x1="${rn(f.padL)}" x2="${rn(W - 4)}" y1="${rn(f.y(m.value))}" y2="${rn(f.y(m.value))}"></line>`).join("")}</svg>
    ${repLegend([["5th to 95th", "rs-0 rep-swatch-light", false], ["25th to 75th", "rs-0 rep-swatch-mid", false], ["Median", "rs-5", false]].concat(marks.filter(m => m.label).map(m => [m.label, `rt-${repTone(m.tone)}`, true])))}`;
}

function repBaseline(c, W, H) {
  const pts = c.points || [], band = c.band || [];
  const vals = pts.map(p => p[1]).concat(band.flatMap(b => [b[1], b[2]])).filter(isNum);
  if (!vals.length) return "";
  const f = repTimeFrame(c, W, H, 0, Math.max(...vals));
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repFrameAxis(f, c.unit, W)}
    <path class="rep-area rt-none" d="${escapeHtml(repBandPath(band, 1, 2, f.x, f.y))}"></path>
    <path class="rep-line rs-0" d="${escapeHtml(repPath(pts, f.x, f.y))}"></path>
    ${(c.anomalies || []).map(([t, v]) => `<circle class="rep-dot rt-bad" cx="${rn(f.x(t))}" cy="${rn(f.y(v))}" r="2.8"></circle>`).join("")}</svg>
    ${repLegend([["Usual range", "rt-none", false], ["Actual", "rs-0", false], ["Out of the usual", "rt-bad", false]])}`;
}

function repStep(c, W, H) {
  const pts = (c.points || []).slice().sort((a, b) => a[0] - b[0]);
  if (!pts.length) return "";
  const high = Math.max(...pts.map(p => p[1]), isNum(c.expected) ? c.expected : 0) + 1;
  const f = repTimeFrame({ ...c, start: c.start || pts[0][0], end: c.end || pts[pts.length - 1][0] }, W, H, 0, high);
  let d = "";
  pts.forEach(([t, v], i) => { d += i ? `L${rn(f.x(t))},${rn(f.y(pts[i - 1][1]))}L${rn(f.x(t))},${rn(f.y(v))}` : `M${rn(f.x(t))},${rn(f.y(v))}`; });
  const fill = `${d}L${rn(f.x(pts[pts.length - 1][0]))},${rn(f.base)}L${rn(f.x(pts[0][0]))},${rn(f.base)}Z`;
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repFrameAxis(f, c.unit, W)}
    <path class="rep-area rs-0" d="${escapeHtml(fill)}"></path><path class="rep-line rs-0" d="${escapeHtml(d)}"></path>
    ${isNum(c.expected) ? `<line class="rep-mark rt-none rep-dotted" x1="${rn(f.padL)}" x2="${rn(W - 4)}" y1="${rn(f.y(c.expected))}" y2="${rn(f.y(c.expected))}"></line>` : ""}</svg>
    ${repLegend([["Answering", "rs-0", false]].concat(isNum(c.expected) ? [[c.expected_label || "Expected", "rt-none", true]] : []))}`;
}

function repMultiples(c) {
  const panels = c.panels || [];
  if (!panels.length) return "";
  const top = isNum(c.y_max) && c.y_max > 0 ? c.y_max : 100;
  const t0 = c.start, t1 = c.end > c.start ? c.end : c.start + 1;
  const x = t => (t - t0) / (t1 - t0) * 120, y = v => 40 - Math.max(0, Math.min(top, v)) / top * 38;
  const th = c.threshold && isNum(c.threshold.value) ? c.threshold.value : null;
  return `<div class="rep-multiples">${panels.map(p => {
    const has = (p.points || []).some(q => isNum(q[1]));
    return `<div class="rep-multiple"><span class="rep-multiple-name" title="${escapeHtml(p.name)}">${escapeHtml(p.name)}</span>
      ${has ? `<svg viewBox="0 0 120 42" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(p.name)}">${th !== null ? `<line class="rep-mark rt-none rep-dotted" x1="0" x2="120" y1="${rn(y(th))}" y2="${rn(y(th))}"></line>` : ""}
        <path class="rep-line ${p.bad ? "rt-bad" : "rs-0"}" d="${escapeHtml(repPath(p.points, x, y))}"></path></svg>` : `<span class="dim rep-multiple-none">No data</span>`}</div>`;
  }).join("")}</div><div class="dim rep-multiple-scale">Every panel 0 to ${escapeHtml(repFmt(top, c.unit))}</div>`;
}

function repForecast(c, W, H) {
  const obs = c.observed || [];
  if (!obs.length) return "";
  const proj = c.projection || [], cone = c.cone || [];
  const vals = obs.map(p => p[1]).concat(proj.map(p => p[1]), cone.map(p => p[2])).filter(isNum);
  const high = c.unit === "%" ? 100 : Math.max(...vals, isNum(c.limit) ? c.limit : 0);
  const f = repTimeFrame({ ...c, start: c.start || obs[0][0], end: c.end || obs[obs.length - 1][0] }, W, H, 0, high);
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${repFrameAxis(f, c.unit, W)}
    ${cone.length ? `<path class="rep-area rs-0 rep-band-outer" d="${escapeHtml(repBandPath(cone, 1, 2, f.x, f.y))}"></path>` : ""}
    <path class="rep-line rs-0" d="${escapeHtml(repPath(obs, f.x, f.y))}"></path>
    ${proj.length ? `<path class="rep-line rs-0 rep-dashed" d="${escapeHtml(repPath(proj, f.x, f.y))}"></path>` : ""}
    ${isNum(c.limit) ? `<line class="rep-mark rt-bad" x1="${rn(f.padL)}" x2="${rn(W - 4)}" y1="${rn(f.y(c.limit))}" y2="${rn(f.y(c.limit))}"></line>` : ""}
    ${isNum(c.full_at) ? `<line class="rep-mark rt-none rep-dotted" x1="${rn(f.x(c.full_at))}" x2="${rn(f.x(c.full_at))}" y1="${rn(f.top)}" y2="${rn(f.base)}"></line>
      <text class="rep-tick rep-ink" x="${rn(f.x(c.full_at) - 4)}" y="${rn(f.top + 12)}" text-anchor="end">${escapeHtml(c.full_text || "")}</text>` : ""}</svg>
    ${repLegend([["Daily peak", "rs-0", false], ["Trend", "rs-0", true], ["About 90% confidence", "rs-0 rep-swatch-light", false]].concat(isNum(c.limit) ? [[c.limit_label || "Limit", "rt-bad", true]] : []))}`;
}

/* Time patterns: calendar, outage timeline, clock, event timeline ------------------------------- */

function repCalendar(c) {
  const cells = c.cells || [];
  if (!cells.length) return "";
  const weeks = Math.max(...cells.map(x => x[0])) + 1;
  const byPos = new Map(cells.map(x => [`${x[0]}:${x[1]}`, x]));
  const months = new Map((c.months || []).map(([w, l]) => [w, l]));
  return `<div class="rep-cal" style="--weeks:${Number(weeks)}"><span></span>${Array.from({ length: weeks }, (_, w) => `<span class="rep-cal-month">${escapeHtml(months.get(w) || "")}</span>`).join("")}
    ${["Mon", "", "Wed", "", "Fri", "", "Sun"].map((d, day) => `<span class="rep-cal-day">${escapeHtml(d)}</span>${Array.from({ length: weeks }, (_, w) => {
      const cell = byPos.get(`${w}:${day}`);
      return cell ? `<span class="rep-cal-cell rt-${escapeHtml(repTone(cell[3]))} ${cell[4] ? "soft" : ""}" title="${escapeHtml(cell[5])}"></span>` : `<span class="rep-cal-cell blank"></span>`;
    }).join("")}`).join("")}</div>
    ${repLegend((c.legend || []).map(([label, tone, soft]) => [label, `rt-${repTone(tone)}${soft ? " rep-swatch-soft" : ""}`, false]))}`;
}

function repGantt(c, W) {
  const rows = c.rows || [];
  if (!rows.length || !c.start || !c.end) return "";
  const labelW = Math.min(Math.max(...rows.map(r => String(r.name).length)) * 6.4 + 10, W * 0.28);
  const x0 = labelW, x1 = W - 2;
  const x = t => x0 + (t - c.start) / ((c.end - c.start) || 1) * (x1 - x0);
  const H = rows.length * 18 + 24;
  const marks = (c.marks || []).filter(m => m[0] >= c.start && m[0] <= c.end);
  const every = Math.max(1, Math.ceil(marks.length / Math.max(1, (x1 - x0) / 60)));
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    <defs><pattern id="rep-hatch" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="5" height="5" class="rep-hatch-bg"></rect><line x1="0" y1="0" x2="0" y2="5" class="rep-hatch-line"></line></pattern></defs>
    ${marks.map((m, i) => `<line class="rep-gridline" x1="${rn(x(m[0]))}" x2="${rn(x(m[0]))}" y1="0" y2="${rn(H - 18)}"></line>${i % every ? "" : `<text class="rep-tick" x="${rn(x(m[0]) + 2)}" y="${rn(H - 4)}">${escapeHtml(m[1])}</text>`}`).join("")}
    ${rows.map((r, i) => {
      const yy = i * 18 + 2;
      return `<text class="rep-tick rep-ink" x="${rn(x0 - 6)}" y="${rn(yy + 10)}" text-anchor="end">${escapeHtml(r.name)}</text><rect class="rep-track" x="${rn(x0)}" y="${rn(yy)}" width="${rn(x1 - x0)}" height="13"></rect>
        ${(r.spans || []).map(([a, b, tone, text]) => `<rect class="${tone === "maint" ? "rep-maint" : `rep-colbar rt-${escapeHtml(repTone(tone))}`}" x="${rn(x(a))}" y="${rn(yy)}" width="${rn(Math.max(2, x(b) - x(a)))}" height="13"><title>${escapeHtml(text)}</title></rect>`).join("")}`;
    }).join("")}</svg>${repLegend([["Down", "rt-bad", false], ["Maintenance", "rep-swatch-maint", false]])}`;
}

function repClock(c) {
  const vals = c.values || [];
  const known = vals.filter(isNum);
  if (!known.length || !known.some(v => v)) return "";
  const top = Math.max(...known) || 1, R = 78, r0 = 20, C = 100;
  const wedges = vals.map((v, h) => {
    if (!isNum(v) || !v) return "";
    const t = -Math.PI / 2 + h / 24 * Math.PI * 2;
    const cls = isNum(c.bad) && v >= c.bad ? "rt-bad" : isNum(c.warn) && v >= c.warn ? "rt-warn" : "rs-0";
    return `<path class="rep-colbar ${cls}" d="${escapeHtml(repWedge(C, C, r0, r0 + (R - r0) * v / top, t - 0.11, t + 0.11))}"><title>${escapeHtml(`${String(h).padStart(2, "0")}:00 ${repFmt(v, c.unit)}`)}</title></path>`;
  }).join("");
  const labels = [[0, "00h"], [6, "06h"], [12, "12h"], [18, "18h"]].map(([h, l]) => {
    const t = -Math.PI / 2 + h / 24 * Math.PI * 2;
    return `<text class="rep-tick" x="${rn(C + (R + 12) * Math.cos(t))}" y="${rn(C + (R + 12) * Math.sin(t) + 3.5)}" text-anchor="middle">${escapeHtml(l)}</text>`;
  }).join("");
  return `<svg class="rep-clock" viewBox="0 0 200 200" role="img" aria-label="${escapeHtml(c.title)}"><circle class="rep-ring" cx="100" cy="100" r="${rn(R)}"></circle><circle class="rep-ring" cx="100" cy="100" r="${rn(r0)}"></circle>${wedges}${labels}</svg>`;
}

function repTimeline(c, W) {
  const events = c.events || [];
  if (!c.start || !c.end || (!events.length && !c.impact)) return "";
  const H = 170, mid = 80;
  const x = t => 6 + (t - c.start) / ((c.end - c.start) || 1) * (W - 12);
  const impact = c.impact ? `<rect class="rep-impact" x="${rn(x(c.impact[0]))}" y="6" width="${rn(Math.max(2, x(c.impact[1]) - x(c.impact[0])))}" height="${rn(H - 36)}"></rect>
    <text class="rep-tick rt-bad rep-tone-text" x="${rn(x(c.impact[0]) + 4)}" y="18">${escapeHtml(c.impact[2])}</text>` : "";
  const chars = Math.max(12, Math.floor(W / Math.max(4, Math.min(events.length, 8)) / 6));
  const marks = events.map(([t, label, tone], i) => {
    const up = i % 2 === 0, lane = Math.floor(i / 2) % 3;
    const ly = mid + (up ? -1 : 1) * (18 + lane * 15);
    const text = String(label).length > chars ? `${String(label).slice(0, chars - 3)}...` : String(label);
    const ex = x(t);
    const anchor = ex < W * 0.15 ? "start" : ex > W * 0.85 ? "end" : "middle";
    return `<line class="rep-stem rt-none" x1="${rn(ex)}" x2="${rn(ex)}" y1="${rn(mid)}" y2="${rn(ly)}"></line><circle class="rep-dot rt-${escapeHtml(repTone(tone))}" cx="${rn(ex)}" cy="${rn(mid)}" r="4"><title>${escapeHtml(label)}</title></circle>
      <text class="rep-tick rep-ink rep-tl-label" x="${rn(ex)}" y="${rn(ly + (up ? -2 : 9))}" text-anchor="${anchor}">${escapeHtml(text)}<title>${escapeHtml(label)}</title></text>`;
  }).join("");
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${impact}
    <line class="rep-zero" x1="6" x2="${rn(W - 6)}" y1="${rn(mid)}" y2="${rn(mid)}"></line>${marks}${repTimeAxis(c.start, c.end, x, H - 28, W)}</svg>`;
}

/* Relationship: scatter, radar, map ----------------------------------------------------------------- */

function repScatter(c, W) {
  const pts = c.points || [];
  if (!pts.length) return "";
  const top = isNum(c.max) ? c.max : 100;
  const H = Math.min(260, Math.max(180, W * 0.6));
  const padL = 34, base = H - 30, upper = 16;
  const x = v => padL + Math.max(0, Math.min(top, v)) / top * (W - 8 - padL);
  const y = v => base - Math.max(0, Math.min(top, v)) / top * (base - upper);
  const ticks = repNiceTicks(0, top, 4);
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">
    ${ticks.map(t => `<line class="rep-gridline" x1="${rn(x(t))}" x2="${rn(x(t))}" y1="${rn(upper)}" y2="${rn(base)}"></line><line class="rep-gridline" x1="${rn(padL)}" x2="${rn(W - 8)}" y1="${rn(y(t))}" y2="${rn(y(t))}"></line>
      <text class="rep-tick" x="${rn(x(t))}" y="${rn(base + 14)}" text-anchor="middle">${escapeHtml(repNum(t))}</text><text class="rep-tick" x="${rn(padL - 5)}" y="${rn(y(t) + 3.5)}" text-anchor="end">${escapeHtml(repNum(t))}</text>`).join("")}
    ${isNum(c.x_line) ? `<line class="rep-mark rt-none rep-dotted" x1="${rn(x(c.x_line))}" x2="${rn(x(c.x_line))}" y1="${rn(upper)}" y2="${rn(base)}"></line>` : ""}
    ${isNum(c.y_line) ? `<line class="rep-mark rt-none rep-dotted" x1="${rn(padL)}" x2="${rn(W - 8)}" y1="${rn(y(c.y_line))}" y2="${rn(y(c.y_line))}"></line>` : ""}
    ${pts.map(([label, vx, vy, tone, named]) => `<circle class="rep-dot rt-${escapeHtml(repTone(tone))}" cx="${rn(x(vx))}" cy="${rn(y(vy))}" r="4"><title>${escapeHtml(`${label}: ${vx}% and ${vy}%`)}</title></circle>
      ${named ? `<text class="rep-tick rep-ink" x="${rn(x(vx) + 6)}" y="${rn(y(vy) - 4)}">${escapeHtml(label)}</text>` : ""}`).join("")}
    <text class="rep-tick" x="${rn((padL + W) / 2)}" y="${rn(H - 2)}" text-anchor="middle">${escapeHtml(c.x_label || "")}</text>
    <text class="rep-tick" x="${rn(padL)}" y="10">${escapeHtml(c.y_label || "")}</text></svg>`;
}

function repRadar(c, W) {
  const axes = c.axes || [];
  const series = (c.series || []).filter(s => (s.values || []).some(isNum));
  if (axes.length < 3 || !series.length) return "";
  const H = 250, cx = W / 2, cy = H / 2 + 4, R = Math.min(W / 2 - 70, H / 2 - 24);
  const n = axes.length;
  const ang = i => -Math.PI / 2 + i * 2 * Math.PI / n;
  const pt = (i, v) => `${rn(cx + R * v / 100 * Math.cos(ang(i)))},${rn(cy + R * v / 100 * Math.sin(ang(i)))}`;
  const rings = [25, 50, 75, 100].map(r => `<polygon class="rep-ring" points="${escapeHtml(axes.map((_, i) => pt(i, r)).join(" "))}"></polygon>`).join("");
  const spokes = axes.map((name, i) => {
    const cos = Math.cos(ang(i));
    return `<line class="rep-gridline" x1="${rn(cx)}" y1="${rn(cy)}" x2="${rn(cx + R * cos)}" y2="${rn(cy + R * Math.sin(ang(i)))}"></line>
      <text class="rep-tick" x="${rn(cx + (R + 10) * cos)}" y="${rn(cy + (R + 10) * Math.sin(ang(i)) + 3.5)}" text-anchor="${Math.abs(cos) < 0.3 ? "middle" : cos > 0 ? "start" : "end"}">${escapeHtml(name)}</text>`;
  }).join("");
  const shapes = series.map((s, k) => `<polygon class="rep-radar ${k ? "rs-4" : "rs-0"}" points="${escapeHtml(s.values.map((v, i) => isNum(v) ? pt(i, v) : "").filter(Boolean).join(" "))}"><title>${escapeHtml(`${s.name}: ${axes.map((a, i) => `${a} ${isNum(s.values[i]) ? Math.round(s.values[i]) : "no data"}`).join(", ")}`)}</title></polygon>`).join("");
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${rings}${spokes}${shapes}</svg>
    ${repLegend(series.map((s, k) => [s.name, k ? "rs-4" : "rs-0", false]))}`;
}

function repTopology(c, W) {
  const nodes = c.nodes || [];
  if (!nodes.length) return "";
  const H = 260;
  const pos = new Map(nodes.map(n => [n.key, [24 + n.x * (W - 48), 14 + n.y * (H - 34)]]));
  const links = (c.links || []).filter(l => pos.has(l.a) && pos.has(l.b)).map(l => {
    const [ax, ay] = pos.get(l.a), [bx, by] = pos.get(l.b);
    return `<line class="rep-link ${l.tone === "warn" || l.tone === "bad" ? `rt-${escapeHtml(repTone(l.tone))} hot` : ""} ${l.dashed ? "down" : ""}" x1="${rn(ax)}" y1="${rn(ay)}" x2="${rn(bx)}" y2="${rn(by)}"><title>${escapeHtml(isNum(l.util) ? `${l.util}% used` : "Use not known")}</title></line>`;
  }).join("");
  const dots = nodes.map(n => {
    const [nx, ny] = pos.get(n.key);
    return `<circle class="rep-node rt-${escapeHtml(repTone(n.tone))}" cx="${rn(nx)}" cy="${rn(ny)}" r="${n.core ? 8 : 6}"><title>${escapeHtml(n.label)}</title></circle>
      <text class="rep-tick rep-ink" x="${rn(nx)}" y="${rn(n.alt ? ny - 11 : ny + 18)}" text-anchor="middle">${escapeHtml(String(n.label).length > 14 ? `${String(n.label).slice(0, 13)}...` : n.label)}</text>`;
  }).join("");
  return `<svg class="rep-svg" viewBox="0 0 ${rn(W)} ${rn(H)}" role="img" aria-label="${escapeHtml(c.title)}">${links}${dots}</svg>
    ${repLegend([["Up", "rt-good", false], ["Problem", "rt-warn", false], ["Down", "rt-bad", false], ["Link over 70% or 90%", "rt-warn", true]])}`;
}

/** One chart with its heading and reading note. An empty one shows its "No data" state. */
function repChart(c, W, full) {
  const H = full ? 230 : 190;
  const k = c.kind;
  const body = k === "line" ? repLineChart(c, W, H) : k === "mirror" ? repMirrorChart(c, W, H)
    : k === "columns" ? repColumnsChart(c, W, H) : k === "bar" ? repBarChart(c) : k === "donut" ? repDonutChart(c)
    : k === "strips" ? repStrips(c) : k === "heatmap" ? repHeatmap(c) : k === "grid" ? repGrid(c)
    : k === "gauge" ? repGauges(c) : k === "headline" ? repHeadline(c) : k === "sparktable" ? repSparkTable(c)
    : k === "bullet" ? repBullet(c, W) : k === "lollipop" ? repLollipop(c, W, H) : k === "diverging" ? repDiverging(c, W)
    : k === "dumbbell" ? repDumbbell(c, W) : k === "butterfly" ? repButterfly(c, W) : k === "stack100" ? repStack100(c)
    : k === "treemap" ? repTreemap(c) : k === "waterfall" ? repWaterfall(c, W, H) : k === "pareto" ? repPareto(c, W, H)
    : k === "histogram" ? repHistogram(c, W, H) : k === "box" ? repBox(c, W) : k === "cdf" ? repCdf(c, W, H)
    : k === "band" ? repBand(c, W, H) : k === "baseline" ? repBaseline(c, W, H) : k === "step" ? repStep(c, W, H)
    : k === "multiples" ? repMultiples(c) : k === "forecast" ? repForecast(c, W, H) : k === "calendar" ? repCalendar(c)
    : k === "gantt" ? repGantt(c, W) : k === "clock" ? repClock(c) : k === "timeline" ? repTimeline(c, W)
    : k === "scatter" ? repScatter(c, W) : k === "radar" ? repRadar(c, W) : k === "topology" ? repTopology(c, W) : "";
  return `<figure class="rep-chart ${full ? "rep-chart-main" : ""}" data-kind="${escapeHtml(k)}">
    <figcaption><span class="rep-chart-title">${escapeHtml(c.title)}</span>${c.note ? `<span class="rep-chart-note">${escapeHtml(c.note)}</span>` : ""}</figcaption>
    ${body || `<div class="dim rep-nodata">${escapeHtml(c.empty_text || "No data for this period.")}</div>`}</figure>`;
}

function repSpark(values) {
  const vals = (values || []).filter(isNum);
  if (vals.length < 2) return "";
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const step = 60 / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => [i, v]);
  return `<svg class="rep-spark rep-spark-cell" viewBox="0 0 60 16" role="img" aria-label="Trend"><path class="rep-line rs-0" d="${escapeHtml(repPath(pts, i => i * step, v => 14 - (v - lo) / ((hi - lo) || 1) * 12))}"></path></svg>`;
}

function repCell(col, v, tones) {
  if (col.type === "pill") return v === null || v === undefined || v === "" ? "" : `<span class="rep-pill rt-${escapeHtml(repTone(tones[v]))}">${escapeHtml(v)}</span>`;
  if (col.type === "spark") return repSpark(v);
  return escapeHtml(formatReportCell(col.type, v));
}

function repTable(cols, rows, tones, empty) {
  if (!rows.length) return `<p class="rep-empty-line">${escapeHtml(empty)}</p>`;
  return `<div class="rep-table-wrap"><table class="rep-table"><thead><tr>${cols.map(c => `<th class="${REPORT_RIGHT.has(c.type) ? "num" : ""}">${escapeHtml(c.label)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(row => `<tr>${row.map((v, i) => `<td class="${REPORT_RIGHT.has(cols[i].type) ? "num" : cols[i].type === "pill" || cols[i].type === "spark" ? "pill-cell" : "text-cell"}">${repCell(cols[i], v, tones)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function repKpi(k) {
  return `<div class="rep-kpi rt-${escapeHtml(repTone(k.tone))}"><span class="rep-kpi-label">${escapeHtml(k.label)}</span>
    <span class="rep-kpi-value">${escapeHtml(k.value)}</span>${k.sub ? `<span class="rep-kpi-sub">${escapeHtml(k.sub)}</span>` : ""}
    ${k.note ? `<span class="rep-kpi-note ${k.trend === "good" ? "up-good" : k.trend === "bad" ? "up-bad" : ""}">${escapeHtml(k.note)}</span>` : ""}</div>`;
}

/** A block that may sit on one side of a row: a chart, a text box or device details (no recursion). */
function repSide(b, W, full, tones) {
  if (b.type === "chart") return repChart(b.chart, W, full);
  if (b.type === "text") {
    const paras = String(b.text || "").split("\n").filter(p => p.trim()).map(p => `<p>${escapeHtml(p)}</p>`).join("");
    return b.box ? `<section class="rep-textbox">${b.title ? `<h3 class="rep-section-title">${escapeHtml(b.title)}</h3>` : ""}${paras}</section>`
      : `<section class="rep-summary"><h3 class="rep-section-title">${escapeHtml(b.title || "Summary")}</h3>${paras}</section>`;
  }
  if (b.type === "key_value") return `<section class="rep-kv"><h3 class="rep-section-title">${escapeHtml(b.title || "Device details")}</h3>
    <dl>${(b.pairs || []).map(([k, v]) => `<div class="rep-kv-row"><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`).join("")}</dl></section>`;
  if (b.type === "kpi_row") return `<section class="rep-kpis" aria-label="Key figures">${(b.tiles || []).map(repKpi).join("")}</section>`;
  if (b.type === "table") {
    const kept = isNum(b.count) ? b.count : b.total;
    const shown = b.main && b.rows.length < kept ? `<div class="panel-note-bar">The preview shows the first ${escapeHtml(b.rows.length)} rows; the files hold all ${escapeHtml(kept)}.</div>` : "";
    const count = `${b.total} row${b.total === 1 ? "" : "s"}${kept < b.total ? `, the first ${kept} shown` : ""}`;
    return `<section class="rep-section"><h3 class="rep-section-title">${escapeHtml(b.title || "Details")}${b.main ? ` <span class="dim">${escapeHtml(count)}</span>` : ""}</h3>
      ${b.note ? `<p class="rep-section-note dim">${escapeHtml(b.note)}</p>` : ""}${shown}${repTable(b.columns, b.rows, tones, b.empty || "Nothing to show.")}</section>`;
  }
  return "";
}

function repBlock(b, inner, half, tones) {
  if (b.type === "two_column") return `<div class="rep-chartgrid">${repSide(b.left, half, false, tones)}${repSide(b.right, half, false, tones)}</div>`;
  return repSide(b, inner, true, tones);
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
  const tones = r.tones || {};
  box.innerHTML = `<article class="rep-doc">
    <header class="rep-head"><h2 class="rep-head-title">${escapeHtml(r.title)}</h2><p class="rep-head-purpose">${escapeHtml(r.purpose)}</p>
      <dl class="rep-facts">${(r.facts || []).map(f => `<div class="rep-fact"><dt>${escapeHtml(f[0])}</dt><dd>${escapeHtml(f[1])}</dd></div>`).join("")}</dl></header>
    ${(r.blocks || []).map(b => repBlock(b, inner, half, tones)).join("")}
    <footer class="rep-foot">${escapeHtml(r.footer || "")}</footer></article>`;
}

async function runReportPreview() {
  const spec = repSpecForServer();
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
  const spec = repSpecForServer();
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
  const spec = repSpecForServer();
  const custom = spec.template === "custom";
  const t = custom ? null : reportTemplate(spec.template);
  const existing = reportEditing ? reportsData.saved.find(r => r.id === reportEditing) : null;
  const sched = existing ? existing.schedule : { kind: "manual" };
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog rep-save" role="dialog" aria-modal="true" aria-labelledby="rep-save-title">
    <div class="modal-header"><span id="rep-save-title">${existing ? "Save changes to the report" : "Save the report"}</span></div>
    <div class="modal-body">
      <div class="form-group"><label for="rep-save-name">Name</label>
        <input type="text" id="rep-save-name" maxlength="80" value="${escapeHtml(existing ? existing.name : spec.title || (custom ? "My report" : t.title))}" required></div>
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
        <div class="form-help">The monitor keeps the newest ${10} runs of each report under Saved reports.${custom ? " The CSV holds the report's first table." : ""}</div></div>
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

function repStartOver(spec) {
  reportSpec = spec;
  reportEditing = null;
  reportPreview = null;
  reportOpen = null;
  renderReportCustomizer();
  renderReportSaved();
  renderReportPreview();
}

function initReports() {
  const page = document.getElementById("view-reports");
  if (!page) return;
  page.addEventListener("click", async ev => {
    const tpl = ev.target.closest("[data-rep-template]");
    if (tpl) { repStartOver(newReportSpec(tpl.dataset.repTemplate)); return; }
    if (ev.target.closest("#btn-rep-blank")) { repStartOver(newCustomSpec("")); return; }
    if (ev.target.closest("#btn-rep-copy")) {
      readReportCustomizer();
      repStartOver(newCustomSpec(reportSpec.template));
      return;
    }
    const sug = ev.target.closest("[data-rep-suggest]");
    if (sug) { readReportCustomizer(); const [s, v, c] = sug.dataset.repSuggest.split("|"); repAddChart(s, v, c); return; }
    const open = ev.target.closest("[data-rep-open]");
    if (open) {
      const r = reportsData.saved.find(x => x.id === Number(open.dataset.repOpen));
      reportSpec = JSON.parse(JSON.stringify(r.spec));
      reportEditing = r.id;
      reportOpen = null;
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
      return;
    }
    // The builder.
    const add = ev.target.closest("[data-b-add]");
    if (add) {
      readReportCustomizer();
      reportSpec.blocks.push(repDefaultBlock(add.dataset.bAdd));
      const i = reportSpec.blocks.length - 1;
      reportOpen = reportSpec.blocks[i].type === "two_column" ? `${i}.left` : String(i);
      renderReportBuilder();
      return;
    }
    const move = ev.target.closest("[data-b-move]");
    if (move) {
      readReportCustomizer();
      const [i, d] = move.dataset.bMove.split("|").map(Number);
      const blocks = reportSpec.blocks;
      if (i + d < 0 || i + d >= blocks.length) return;
      [blocks[i], blocks[i + d]] = [blocks[i + d], blocks[i]];
      reportOpen = null;
      renderReportBuilder();
      return;
    }
    const delb = ev.target.closest("[data-b-del]");
    if (delb) {
      readReportCustomizer();
      reportSpec.blocks.splice(Number(delb.dataset.bDel), 1);
      reportOpen = null;
      renderReportBuilder();
      return;
    }
    const openb = ev.target.closest("[data-b-open]");
    if (openb) {
      readReportCustomizer();
      reportOpen = reportOpen === openb.dataset.bOpen ? null : openb.dataset.bOpen;
      renderReportBuilder();
      return;
    }
    const pick = ev.target.closest("[data-b-pick]");
    if (pick) {
      const [path, s, v, c] = pick.dataset.bPick.split("|");
      const b = repBlockAt(path);
      Object.assign(b, repChartBlock(s, v, c), { title: b.title, note: b.note, _q: b._q });
      renderReportBuilder();
      return;
    }
    const tileAdd = ev.target.closest("[data-b-tile-add]");
    if (tileAdd) { repBlockAt(tileAdd.dataset.bTileAdd).tiles.push({ metric: "outages", compare: "previous" }); renderReportBuilder(); return; }
    const tileDel = ev.target.closest("[data-b-tile-del]");
    if (tileDel) {
      const [path, i] = tileDel.dataset.bTileDel.split(":");
      const b = repBlockAt(path);
      if (b.tiles.length > 1) b.tiles.splice(Number(i), 1);
      renderReportBuilder();
    }
  });
  page.addEventListener("change", ev => {
    if (ev.target.id === "rep-question") {
      reportQuestion = ev.target.value;
      renderReportTemplates();
      return;
    }
    const field = ev.target.closest("[data-bf]");
    if (field) {
      readReportCustomizer();
      repSetField(field);
      if (field.dataset.bf !== "title" && field.dataset.bf !== "note" && field.dataset.bf !== "text" && field.dataset.bf !== "label") renderReportBuilder();
      return;
    }
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
    repStartOver(reportSpec.template === "custom" ? newCustomSpec("") : newReportSpec(reportSpec.template));
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
