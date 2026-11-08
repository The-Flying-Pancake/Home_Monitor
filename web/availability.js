/* Availability: a status-page view of every device (in the style of Uptime Kuma) and the
 * availability card on each device's Overview.
 *
 * Data: /api/availability (every device the user may see: uptime % per window, the last checks)
 * and /api/availability/<id> (the incident list too). Uptime counts real checks only; time with
 * no checks shows grey ("no data"), never as up or down.
 *
 * Range (24 h, 7 d, 30 d, 90 d): one choice for the page and the device cards, remembered in the
 * browser. The bars, the uptime and the response average follow it; the server groups its hourly
 * counters into bars on this browser's clock (hours, quarter days, days).
 */

const AVAIL_BEATS = 60;
const AVAIL_RANGES = [["24h", "24 h", "24 hours ago"], ["7d", "7 d", "7 days ago"], ["30d", "30 d", "30 days ago"], ["90d", "90 d", "90 days ago"]];
const AVAIL_RANGE_STORE = "hm.availRange";
let availRange = "24h";     // the remembered choice is read in initAvailability (shell.js loads after this file)
let availData = null;
let availFilter = "all";
let availTimer = null;

function availClass(pct) {
  if (!isNum(pct)) return "none";
  return pct >= 99.5 ? "good" : pct >= 95 ? "fair" : "bad";
}

function availPct(pct) {
  if (!isNum(pct)) return "-";
  return pct >= 99.995 ? "100%" : `${pct.toFixed(pct >= 99 ? 2 : 1)}%`;
}

function availState(d) {
  if (d.down_since || d.status === "offline" || d.status === "degraded") return "down";
  if (!d.beats.length) return "pending";
  return "up";
}

// Same groups as the Devices page (groupOf in app.js; the server sends each device's group id).
const availGroup = d => groupOf(d);

/** The heartbeat bar: one stripe per check, newest on the right; missing checks fill the left in grey. */
function beatBar(beats, count = AVAIL_BEATS) {
  const pad = Math.max(0, count - beats.length);
  const stripes = [];
  for (let i = 0; i < pad; i++) stripes.push(`<span class="beat none" title="No data"></span>`);
  for (const b of beats.slice(-count)) {
    const when = new Date(b.t * 1000).toLocaleString();
    // Planned: down during a maintenance window (not counted against uptime).
    const tip = b.up ? `${when}: up${isNum(b.ms) ? `, ${b.ms.toFixed(1)} ms` : ""}` : b.planned ? `${when}: down, planned maintenance` : `${when}: down`;
    stripes.push(`<span class="beat ${b.up ? "up" : b.planned ? "planned" : "down"}" title="${escapeHtml(tip)}"></span>`);
  }
  return `<div class="beat-bar" aria-label="Last ${count} checks">${stripes.join("")}</div>`;
}

const availRangeLabel = key => (AVAIL_RANGES.find(r => r[0] === key) || AVAIL_RANGES[0])[1];
const availQuery = () => `range=${availRange}&tz=${-new Date().getTimezoneOffset()}`;

/** The range buttons; clicks on data-avail-range are handled in initAvailability. */
function availRangeSeg() {
  return `<span class="seg avail-range" role="group" aria-label="Range">${AVAIL_RANGES.map(([k, l]) =>
    `<button type="button" class="btn btn-small${k === availRange ? " active" : ""}" data-avail-range="${k}" aria-pressed="${k === availRange}">${l}</button>`).join("")}</span>`;
}

function setAvailRange(key) {
  if (!AVAIL_RANGES.some(r => r[0] === key) || key === availRange) return;
  availRange = key;
  storeSet(AVAIL_RANGE_STORE, key);
  if (!document.getElementById("view-availability").classList.contains("hidden")) loadAvailability();
  if (activeDeviceId) loadDeviceAvailability(activeDeviceId);
}

/** Uptime per bar over the chosen range: hours, quarter days or days; grey where nothing was checked. */
function rangeBar(r, compact = false) {
  const hours = r.bar_hours;
  const fmt = t => {
    const d = new Date(t * 1000);
    return hours >= 24 ? d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })
      : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };
  const until = t => new Date((t + hours * 3600) * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const spans = r.bars.map(([t, checks, ups, ms]) => {
    const pct = checks ? (100 * ups) / checks : null;
    const tip = `${fmt(t)}${hours < 24 ? ` to ${until(t)}` : ""}: `
      + (isNum(pct) ? `${availPct(pct)} up, ${checks} checks${isNum(ms) ? `, ${ms.toFixed(1)} ms` : ""}` : "no data");
    return `<span class="day ${availClass(pct)}" title="${escapeHtml(tip)}"></span>`;
  }).join("");
  return `<div class="avail-days${compact ? " compact" : ""}" aria-label="Uptime, ${escapeHtml(availRangeLabel(availRange))}">${spans}</div>`;
}

function availChip(label, pct) {
  return `<span class="avail-chip ${availClass(pct)}" title="Uptime, ${escapeHtml(label)}">${escapeHtml(availPct(pct))}<small>${escapeHtml(label)}</small></span>`;
}

function availAddress(d) {
  return d.service_port ? `${d.ip_address}:${d.service_port}` : d.ip_address;
}

async function loadAvailability() {
  document.getElementById("avail-range").innerHTML = availRangeSeg();
  try {
    availData = await api(`/api/availability?${availQuery()}`);
  } catch (err) {
    document.getElementById("avail-body").innerHTML = `<div class="panel-note-bar warn">${escapeHtml(err.message)}</div>`;
    return;
  }
  renderAvailability();
  clearInterval(availTimer);
  // Refreshed while the page is open; the timer stops itself once another page is shown.
  availTimer = setInterval(() => {
    if (document.getElementById("view-availability").classList.contains("hidden")) { clearInterval(availTimer); return; }
    api(`/api/availability?${availQuery()}`).then(d => { availData = d; renderAvailability(); }).catch(() => {});
  }, 30000);
}

function renderAvailability() {
  if (!availData) return;
  const q = document.getElementById("avail-search").value.trim().toLowerCase();
  const all = availData.devices;
  const counts = { up: 0, down: 0, pending: 0 };
  all.forEach(d => { counts[availState(d)]++; });
  const withData = all.filter(d => isNum(d.ranged.uptime));
  const overall = withData.length ? withData.reduce((a, d) => a + d.ranged.uptime, 0) / withData.length : null;
  const rangeLabel = availRangeLabel(availData.range);
  document.getElementById("avail-summary").innerHTML = [
    ["up", counts.up, "Up"], ["down", counts.down, "Down"], ["pending", counts.pending, "Waiting for checks"],
  ].map(([k, n, l]) => `<button type="button" class="stat avail-stat ${k}${availFilter === k ? " active-filter" : ""}" data-avail-filter="${k}">
      <div class="stat-num">${n}</div><div class="stat-label">${l}</div></button>`).join("") +
    `<div class="stat avail-stat"><div class="stat-num">${escapeHtml(availPct(overall))}</div><div class="stat-label">Average uptime, ${escapeHtml(rangeLabel)}</div></div>`;

  const group = document.getElementById("avail-filter-group").value, tag = document.getElementById("avail-filter-tag").value;
  const shown = all.filter(d => (availFilter === "all" || availState(d) === availFilter) && deviceMatches(d, group, tag) &&
    (!q || `${d.hostname} ${availAddress(d)}`.toLowerCase().includes(q)));
  const groups = new Map();
  for (const d of shown) {
    const [name, rank] = availGroup(d);
    if (!groups.has(name)) groups.set(name, { rank, items: [] });
    groups.get(name).items.push(d);
  }
  const order = [...groups.entries()].sort((a, b) => a[1].rank - b[1].rank || a[0].localeCompare(b[0]));
  const body = document.getElementById("avail-body");
  if (!shown.length) {
    body.innerHTML = `<div class="panel"><div class="empty-cell">${all.length ? "No devices match." : "No devices yet."}</div></div>`;
    return;
  }
  body.innerHTML = order.map(([name, g]) => `<div class="panel avail-group">
      <div class="panel-header-bar">${escapeHtml(name)} <span class="dim">${g.items.length}</span></div>
      ${g.items.sort((a, b) => a.hostname.localeCompare(b.hostname)).map(d => {
        const st = availState(d);
        const label = st === "up" ? "Up" : st === "down" ? "Down" : "Waiting";
        const since = st === "down" && d.down_since ? `down for ${formatDuration(Date.now() / 1000 - d.down_since)}` : "";
        return `<a class="avail-row" href="#/device/${Number(d.id)}">
          <span class="avail-status ${st}">${label}</span>
          <span class="avail-name"><strong>${escapeHtml(d.hostname)}</strong><span class="dim">${escapeHtml(availAddress(d))}${since ? `, ${escapeHtml(since)}` : ""}</span></span>
          ${rangeBar(d.ranged, true)}
          <span class="avail-chips">${availChip(rangeLabel, d.ranged.uptime)}</span>
          <span class="avail-ms" title="Average response time, ${escapeHtml(rangeLabel)}">${isNum(d.ranged.avg_ms) ? `${d.ranged.avg_ms.toFixed(d.ranged.avg_ms < 10 ? 1 : 0)} ms` : "-"}</span>
        </a>`;
      }).join("")}
    </div>`).join("");
}

function initAvailability() {
  const saved = storeGet(AVAIL_RANGE_STORE);
  if (AVAIL_RANGES.some(r => r[0] === saved)) availRange = saved;
  // Range buttons on the page and on the device card.
  document.addEventListener("click", ev => {
    const b = ev.target.closest("[data-avail-range]");
    if (b) setAvailRange(b.dataset.availRange);
  });
  document.getElementById("avail-search").addEventListener("input", renderAvailability);
  document.getElementById("avail-filter-group").addEventListener("change", renderAvailability);
  document.getElementById("avail-filter-tag").addEventListener("change", renderAvailability);
  document.getElementById("avail-summary").addEventListener("click", ev => {
    const b = ev.target.closest("[data-avail-filter]");
    if (!b) return;
    availFilter = availFilter === b.dataset.availFilter ? "all" : b.dataset.availFilter;
    document.getElementById("avail-filter-chip").classList.toggle("hidden", availFilter === "all");
    document.getElementById("avail-filter-chip").textContent = availFilter === "all" ? "" : { up: "Up", down: "Down", pending: "Waiting" }[availFilter];
    renderAvailability();
  });
  document.getElementById("avail-filter-chip").addEventListener("click", () => {
    availFilter = "all";
    document.getElementById("avail-filter-chip").classList.add("hidden");
    renderAvailability();
  });
}

// --- Device Overview: availability card ---

async function loadDeviceAvailability(deviceId) {
  const card = document.getElementById("detail-availability");
  if (!card) return;
  // Another device's card must not linger while this one loads.
  if (card.dataset.device !== String(deviceId)) card.classList.add("hidden");
  card.dataset.device = String(deviceId);
  let a;
  try {
    a = await api(`/api/availability/${deviceId}?${availQuery()}`);
  } catch (err) {
    card.classList.add("hidden");
    return;
  }
  if (deviceId !== activeDeviceId) return;
  if (!a.since && !a.beats.length) {
    card.innerHTML = `<div class="panel-header-bar">Availability</div><div class="panel-note-bar">Collecting: the first checks appear here within a minute.</div>`;
    card.classList.remove("hidden");
    return;
  }
  const r = a.ranged;
  const range = AVAIL_RANGES.find(x => x[0] === a.range) || AVAIL_RANGES[0];
  const from = r.bars.length ? r.bars[0][0] : 0;
  // Down periods that touch the chosen range.
  const inc = a.incidents.filter(i => !i.ended || i.ended >= from);
  const incRow = i => `<tr><td>${escapeHtml(formatTime(i.started))}</td><td>${i.ended ? escapeHtml(formatTime(i.ended)) : `<span class="status-pill status-err">Ongoing</span>`}</td>
    <td>${escapeHtml(formatDuration(i.seconds))}</td></tr>`;
  // The four uptime figures double as the range buttons.
  const chip = ([k, l]) => `<button type="button" class="avail-chip ${availClass(a.uptime[k])}${k === a.range ? " selected" : ""}" data-avail-range="${k}"
      title="Show the last ${escapeHtml(l)}" aria-pressed="${k === a.range}">${escapeHtml(availPct(a.uptime[k]))}<small>${escapeHtml(l)}</small></button>`;
  card.innerHTML = `<div class="panel-header-bar panel-header-row">Availability <span class="dim">since ${escapeHtml(formatTime(a.since || a.beats[0].t))}</span>
      <span class="topbar-spacer"></span>${availRangeSeg()}</div>
    <div class="avail-card">
      <div class="avail-chips wide">${AVAIL_RANGES.map(chip).join("")}</div>
      <div class="avail-resp"><div><div class="stat-num">${isNum(r.avg_ms) ? r.avg_ms.toFixed(1) + " ms" : "-"}</div><div class="stat-label">Average, ${escapeHtml(range[1])}</div></div>
        <div><div class="stat-num">${isNum(a.p95_ms) ? a.p95_ms.toFixed(1) + " ms" : "-"}</div><div class="stat-label">95th percentile, 24 h</div></div></div>
      <div class="avail-days-wrap">${rangeBar(r)}
        <div class="avail-days-axis dim"><span>${escapeHtml(range[2])}</span><span>Now</span></div></div>
      <div class="avail-beats-wrap"><div class="dim avail-beats-label">Last ${Math.min(a.beats.length, 90)} checks</div>${beatBar(a.beats, 90)}</div>
      ${inc.length ? `<details class="avail-incidents"${inc.some(i => !i.ended) ? " open" : ""}><summary>${inc.length} incident${inc.length === 1 ? "" : "s"} (down periods), last ${escapeHtml(range[1])}</summary>
        <table><thead><tr><th>Went down</th><th>Came back</th><th>Lasted</th></tr></thead><tbody>${inc.map(incRow).join("")}</tbody></table></details>`
        : `<div class="dim avail-noinc">No down periods in the last ${escapeHtml(range[1])}.</div>`}
    </div>`;
  card.classList.remove("hidden");
}

document.addEventListener("DOMContentLoaded", initAvailability);
