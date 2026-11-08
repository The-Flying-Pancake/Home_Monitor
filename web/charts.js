/* Chart interactions: drag to zoom, reset, and an enlarged view in a window.
 *
 * drawChart (app.js) draws the SVG and calls chartAttach with the plot geometry. A drag across
 * the plot zooms into that time range; when the range is much shorter than what was fetched,
 * the history is fetched again for that window so the buckets get finer. "Reset zoom" returns
 * to the chart as it was. "Enlarge" opens the same graph in a large window with its own time
 * range and compare switch, where zoom works too.
 * host._chart = {series, opts} (lineChart); host._source = {deviceId, g, hours, compare}
 * (drawDefinition), present when the chart can be fetched again.
 */

const CHART_RANGES = [[1, "1h"], [6, "6h"], [24, "24h"], [168, "7d"], [720, "30d"]];
const ZOOM_MIN_PX = 6;

function chartAttach(host, svg, geo) {
  const plotLeft = geo.padL, plotRight = geo.W - geo.padR;
  const toT = px => geo.start + ((px - plotLeft) / (plotRight - plotLeft)) * (geo.end - geo.start);
  const svgX = ev => {
    const r = svg.getBoundingClientRect();
    return ((ev.clientX - r.left) / r.width) * geo.W;
  };
  let drag = null;
  svg.addEventListener("mousedown", ev => {
    if (ev.button !== 0) return;
    const x = svgX(ev);
    if (x < plotLeft || x > plotRight) return;
    ev.preventDefault();
    const sel = svgEl("rect", { x, y: geo.padT, width: 0, height: geo.H - geo.padT - geo.padB, class: "chart-zoom-sel" });
    svg.appendChild(sel);
    drag = { x0: x, sel };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  });
  const move = ev => {
    if (!drag) return;
    const x = Math.max(plotLeft, Math.min(plotRight, svgX(ev)));
    drag.x1 = x;
    drag.sel.setAttribute("x", Math.min(drag.x0, x));
    drag.sel.setAttribute("width", Math.abs(x - drag.x0));
  };
  const up = () => {
    if (!drag) return;
    const d = drag;
    drag = null;
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", up);
    d.sel.remove();
    if (d.x1 === undefined || Math.abs(d.x1 - d.x0) < ZOOM_MIN_PX) return;
    chartZoom(host, toT(Math.min(d.x0, d.x1)), toT(Math.max(d.x0, d.x1)));
  };
  const tools = document.createElement("div");
  tools.className = "chart-tools";
  const zoomed = !!(host._chart && host._chart.opts.zoom);
  const inModal = !!host.closest(".chart-modal");
  tools.innerHTML = (zoomed ? `<button type="button" class="btn btn-small" data-chart-reset>Reset zoom</button>` : "") +
    (!inModal ? `<button type="button" class="btn btn-small chart-enlarge" data-chart-enlarge title="Open this graph in a larger window" aria-label="Enlarge graph">⤢</button>` : "");
  if (zoomed) tools.classList.add("zoomed");
  tools.addEventListener("mousedown", ev => ev.stopPropagation());
  tools.addEventListener("click", ev => {
    if (ev.target.closest("[data-chart-reset]")) chartResetZoom(host);
    else if (ev.target.closest("[data-chart-enlarge]")) openChartModal(host);
  });
  if (tools.innerHTML) host.appendChild(tools);
}

/** A zoom window with no data still needs its way back. */
function chartAttachEmpty(host) {
  const tools = document.createElement("div");
  tools.className = "chart-tools zoomed";
  tools.innerHTML = `<button type="button" class="btn btn-small" data-chart-reset>Reset zoom</button>`;
  tools.addEventListener("click", () => chartResetZoom(host));
  host.appendChild(tools);
}

async function chartZoom(host, t0, t1) {
  if (!host._chart) return;
  if (!host._chartBase) host._chartBase = { series: host._chart.series, opts: host._chart.opts };
  const opts = { ...host._chart.opts, zoom: [t0, t1] };
  const src = host._source;
  const fetchedSpan = (host._chartBase.opts.hours || 24) * 3600;
  // Finer buckets for a short window: fetch that window again (the server keeps about 300 points per range).
  if (src && t1 - t0 < fetchedSpan / 3) {
    try {
      const keys = src.g.series.map(s => s[0]);
      const q = `keys=${keys.join(",")}&hours=${src.hours}&start=${Math.floor(t0)}&end=${Math.ceil(t1)}` +
        (src.compare ? `&compare=1&shift=${src.hours * 3600}` : "");
      const hist = await api(`/api/devices/${src.deviceId}/history?${q}`);
      const series = src.g.series.map(([k, label]) => ({ key: k, label, points: hist.series[k] || [] }));
      if (src.compare && hist.previous) {
        src.g.series.forEach(([k, label], i) => series.push({ label: `${label} (previous)`, points: hist.previous[k] || [], dashed: true, color: i }));
      }
      lineChart(host, series, opts);
      return;
    } catch (err) { /* fall back to the data already drawn */ }
  }
  lineChart(host, host._chart.series, opts);
}

function chartResetZoom(host) {
  const base = host._chartBase;
  host._chartBase = null;
  if (base) lineChart(host, base.series, base.opts);
}

function chartTitleOf(host) {
  const card = host.closest(".chart-card");
  if (card && card.dataset.title) return card.dataset.title;
  const widget = host.closest(".widget");
  const head = widget && widget.querySelector(".widget-head span, .widget-head");
  return head ? head.textContent.trim().split("\n")[0] : "Graph";
}

/** The graph in a large window: own range and compare when it can be fetched again, zoom always. */
function openChartModal(host) {
  const src = host._source;
  const title = chartTitleOf(host);
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  let hours = src ? src.hours : (host._chart ? host._chart.opts.hours : 24);
  let compare = src ? !!src.compare : false;
  back.innerHTML = `<div class="modal chart-modal" role="dialog" aria-modal="true" aria-label="${escapeHtml(title)}">
    <div class="modal-header"><span>${escapeHtml(title)}</span>
      <button type="button" class="btn" data-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      ${src ? `<div class="toolbar">
        <span class="dim">Range:</span>
        <div class="seg">${CHART_RANGES.map(([h, l]) => `<button type="button" class="btn${h === hours ? " active" : ""}" data-hours="${h}">${l}</button>`).join("")}</div>
        <label class="checkbox-label inline"><input type="checkbox" data-compare ${compare ? "checked" : ""}> Compare with the previous period</label>
        <span class="dim">Drag across the graph to zoom in.</span>
      </div>` : `<div class="toolbar"><span class="dim">Drag across the graph to zoom in.</span></div>`}
      <div class="chart-host chart-fill chart-modal-host"></div>
    </div>
  </div>`;
  document.body.appendChild(back);
  const target = back.querySelector(".chart-modal-host");
  // Series switched off on the small graph start off in the large one (and can be switched there).
  target._hidden = new Set(host._hidden || []);
  const draw = () => {
    target._chartBase = null;
    if (src) drawDefinition(target, src.deviceId, src.g, hours, compare);
    else if (host._chart) lineChart(target, host._chart.series, { ...host._chart.opts, zoom: undefined });
  };
  const close = () => {
    document.removeEventListener("keydown", onKey, true);
    window.removeEventListener("hashchange", close);
    back.remove();
    hide(document.getElementById("chart-tooltip"));
  };
  // Another page means this graph no longer belongs on screen.
  window.addEventListener("hashchange", close);
  const onKey = ev => { if (ev.key === "Escape" && !document.querySelector(".dialog")) { ev.stopPropagation(); close(); } };
  document.addEventListener("keydown", onKey, true);
  back.addEventListener("mousedown", ev => { if (ev.target === back) close(); });
  back.querySelector("[data-close]").addEventListener("click", close);
  back.querySelectorAll("[data-hours]").forEach(b => b.addEventListener("click", () => {
    hours = Number(b.dataset.hours);
    back.querySelectorAll("[data-hours]").forEach(x => x.classList.toggle("active", x === b));
    draw();
  }));
  const cmp = back.querySelector("[data-compare]");
  if (cmp) cmp.addEventListener("change", () => { compare = cmp.checked; draw(); });
  // Drawn after layout so the chart takes the window's size.
  requestAnimationFrame(draw);
}
