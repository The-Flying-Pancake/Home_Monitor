/* Workflows: list, drag and drop editor (canvas of steps and connections) and run viewer.
 *
 * Editor: a trigger node and step nodes on a pan and zoom canvas. Drag a step in from the
 * palette (or click it to add it after the selected step), drag a step to move it, and drag
 * from a step's right-hand dots to another step to connect them: green is followed when the
 * step succeeds, red when it fails. A step with no red connection stops the run when it fails.
 * The selected step's fields are edited in the right-hand panel; the trigger holds the schedule,
 * picked as a date and time (cron is generated on the server, see schedule.py).
 *
 * The run viewer draws the same graph and marks each step passed, failed or running.
 * Relies on app.js helpers (api, escapeHtml, showToast, show, hide, fillTable, formatTime,
 * formatDuration, confirmDialog, autoData, loadAutomation, openHostKeys), the templates in
 * wftemplates.js and the map data from /api/map (restart order).
 */

const WF_STATUS = { success: ["status-ok", "success"], partial: ["status-warn", "partial"], failed: ["status-err", "failed"],
  cancelled: ["status-unknown", "cancelled"], error: ["status-err", "error"], running: ["status-unknown", "running"],
  interrupted: ["status-warn", "interrupted"] };
const WF_KIND = {
  trigger: { title: "Trigger", badge: "START" },
  command: { title: "Run command", badge: "SSH" },
  wait: { title: "Wait", badge: "WAIT" },
  wait_ping: { title: "Wait for ping", badge: "PING" },
  wait_snmp: { title: "Wait for SNMP", badge: "SNMP" },
  telegram: { title: "Send Telegram", badge: "MSG" },
  wifi_reconnect: { title: "Reconnect weak Wi-Fi", badge: "WI-FI" },
  pve_snapshot: { title: "Snapshot a Proxmox guest", badge: "SNAP" },
  mute: { title: "Suppress notifications", badge: "QUIET" },
  unmute: { title: "Notifications back on", badge: "LOUD" },
};
let wfPveGuests = null;   // the Proxmox guests, for the snapshot step (loaded when the step is shown)
// "When something happens" conditions (schedule.py EVENT_TYPES).
const WF_EVENT_TYPES = [
  ["offline", "Goes offline"], ["online", "Comes back online"], ["snmp_down", "Answers ping, SNMP does not"],
  ["metric", "A measurement goes above or below a value"], ["watch", "A watched service or process stops"],
  ["problem", "A problem opens"],
];
const WF_STEP_PLACEHOLDERS = { workflow: "Workflow name", trigger: "What started it", status: "So far: all steps succeeded, or a step failed",
  steps: "One line per finished step with a tick or a cross", time: "Local time" };
// Index order is kept (data-pal); the palette draws them grouped by family. Each family has one colour, the same in the palette, on the canvas and in the run view
// (workflows.css, .wfb-f-*).
const WF_PALETTE = [
  { type: "command", fam: "do", title: "Run command", help: "SSH command on one or more hosts. Host actions are in its command templates." },
  { type: "wait", fam: "wait", title: "Wait", help: "Pause for a number of seconds" },
  { type: "wait_ping", fam: "wait", state: "down", title: "Wait until down", help: "Until a host stops answering ping" },
  { type: "wait_ping", fam: "wait", state: "up", title: "Wait until up", help: "Until a host answers ping again" },
  { type: "wait_snmp", fam: "wait", title: "Wait for SNMP", help: "Until a host's SNMP agent answers" },
  { type: "telegram", fam: "tell", title: "Send Telegram", help: "A message to the Telegram chat" },
  { type: "wifi_reconnect", fam: "do", title: "Reconnect weak Wi-Fi", help: "UniFi: devices on an access point below the weak-signal line rejoin" },
  { type: "pve_snapshot", fam: "do", title: "Snapshot a Proxmox guest", help: "Before an update: a snapshot to roll back to" },
  { type: "mute", fam: "tell", title: "Suppress notifications", help: "No Telegram for these devices while the run restarts them" },
  { type: "unmute", fam: "tell", title: "Notifications back on", help: "Ends the suppression early (it ends with the run anyway)" },
];
const WF_FAMILIES = [["do", "Do something"], ["wait", "Wait"], ["tell", "Tell and keep quiet"]];
let wfPalTab = "steps";
const WF_DAYS = [[1, "Mon"], [2, "Tue"], [3, "Wed"], [4, "Thu"], [5, "Fri"], [6, "Sat"], [0, "Sun"]];
const WF_DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const WF_MINUTE_STEPS = [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30];
const WF_HOUR_STEPS = [1, 2, 3, 4, 6, 8, 12];
const NODE_W = 210;
const NODE_H = 68;
const COL_W = 260;
const ROW_H = 110;

let wfList = null;
let wfMap = null;
let wfRunTimer = null;
// Editor state: draft workflow, its saved form (unsaved check), view transform, selection, right panel mode.
let wfb = null;

function wfPill(status) {
  const [cls, text] = WF_STATUS[status] || ["status-unknown", status || "never"];
  return `<span class="status-pill ${escapeHtml(cls)}">${escapeHtml(text)}</span>`;
}

function wfHosts() { return (autoData && autoData.devices) || []; }
function wfCreds() { return (autoData && autoData.credentials) || []; }
function wfNames() { return Object.fromEntries(wfHosts().map(d => [d.id, d.hostname])); }
/** A workflow with a command step logs in with a stored credential: that needs Use stored credentials. */
function wfCanRun(w) { return can("credentials.use") || !w.steps.some(s => s.type === "command"); }
/** The user a command step's credential logs in as, or "" when the credential is unknown. */
function wfRunsAs(credId) {
  const c = wfCreds().find(x => x.id === credId);
  return c ? c.username || "root" : "";
}

async function loadWorkflows() {
  // Workflows and their run logs need Run or Edit workflows (Manage devices alone also opens this page).
  if (!can("automation.run") && !can("automation.edit")) {
    fillTable("workflows-body", "", "Workflows need the Run workflows or Edit workflows permission.", 6);
    fillTable("wf-runs-body", "", "No workflow runs to show.", 5);
    return;
  }
  try {
    const [w, r] = await Promise.all([api("/api/workflows"), api("/api/workflows/runs")]);
    wfList = w;
    if (!autoData) await loadAutomation();
    renderWorkflows();
    fillTable("wf-runs-body", r.runs.map(x => `
      <tr class="clickable-row" data-wf-run="${Number(x.id)}">
        <td data-sort="${escapeHtml(x.started_at)}">${escapeHtml(formatTime(x.started_at))}</td>
        <td class="text-cell">${escapeHtml(x.name)}</td>
        <td class="dim">${escapeHtml(x.trigger)}</td>
        <td>${wfPill(x.status)}</td>
        <td data-sort="${x.finished_at ? x.finished_at - x.started_at : ""}">${x.finished_at ? formatDuration(x.finished_at - x.started_at) : "-"}</td>
      </tr>`).join(""), "No workflow runs yet.", 5);
  } catch (err) {
    showToast(`Could not load workflows: ${err.message}`, "error");
  }
}

function wfStepHosts(steps) {
  return [...new Set(steps.flatMap(s => s.device_ids || (s.device_id ? [s.device_id] : [])))];
}

function renderWorkflows() {
  const names = wfNames();
  fillTable("workflows-body", wfList.workflows.map(w => {
    const running = wfList.running[w.id];
    const sched = w.trigger_type === "manual" && w.schedule.kind !== "once" ? "Manual"
      : `${escapeHtml(w.schedule_text)}${w.is_active ? "" : ' <span class="dim">(disabled)</span>'}`;
    return `<tr>
      <td class="text-cell"><strong>${escapeHtml(w.name)}</strong><div class="dim task-cmd">${escapeHtml(w.description || "")}</div></td>
      <td>${w.steps.length}</td>
      <td class="text-cell">${wfStepHosts(w.steps).map(id => escapeHtml(names[id] || "?")).join(", ") || "-"}</td>
      <td class="text-cell">${sched}</td>
      <td>${running ? wfPill("running") : wfPill(w.last_status)}</td>
      <td class="actions-cell">
        ${running ? `<button class="btn" data-wf-open="${Number(running)}">View run</button>` : wfCanRun(w) ? `<button class="btn btn-primary" data-wf-start="${Number(w.id)}">Run now</button>` : ""}
        ${w.steps.some(s => s.type === "command") ? `<button class="btn" data-wf-keys="${Number(w.id)}">Host keys</button>` : ""}
        <button class="btn" data-wf-edit="${Number(w.id)}">Edit</button>
        <button class="btn btn-danger" data-wf-delete="${Number(w.id)}">Delete</button>
      </td>
    </tr>`;
  }).join(""), "No workflows yet. Click \"+ Add Workflow\".", 6);
}

async function wfLoadMap() {
  try {
    wfMap = await api("/api/map");
  } catch (err) {
    wfMap = null;
  }
}

/** Hops from the gateway on the network map; unknown hosts sort last. */
function wfDepth(deviceId) {
  if (!wfMap) return -1;
  let depth = 0;
  let node = `d:${deviceId}`;
  if (!(node in wfMap.parent)) return -1;
  while (wfMap.parent[node]) { node = wfMap.parent[node]; depth += 1; }
  return depth;
}

function wfCutsMonitor(deviceId) {
  if (!wfMap || !("monitor" in wfMap.parent)) return false;
  let node = "monitor";
  while (wfMap.parent[node]) {
    node = wfMap.parent[node];
    if (node === `d:${deviceId}`) return true;
  }
  return false;
}

// --- Schedules (mirror of schedule.describe on the server) ---

function wfScheduleText(s) {
  const kind = (s && s.kind) || "manual";
  if (kind === "manual") return "Manual only";
  if (kind === "once") return `Once on ${s.date || "?"} at ${s.time || "?"}${s.done ? " (done)" : ""}`;
  if (kind === "daily") return `Every day at ${s.time}`;
  if (kind === "weekly") {
    const d = (s.weekdays || []).slice().sort();
    if (!d.length) return "Every week: tick at least one day";
    if (d.join() === "1,2,3,4,5") return `Every weekday at ${s.time}`;
    if (d.join() === "0,6") return `Every Saturday and Sunday at ${s.time}`;
    if (d.length === 7) return `Every day at ${s.time}`;
    const names = d.map(i => WF_DAY_NAMES[i]);
    return `Every ${names.length === 1 ? names[0] : names.slice(0, -1).join(", ") + " and " + names[names.length - 1]} at ${s.time}`;
  }
  if (kind === "monthly") {
    const n = s.day, suf = n % 100 >= 10 && n % 100 <= 20 ? "th" : ({ 1: "st", 2: "nd", 3: "rd" }[n % 10] || "th");
    return `Monthly on the ${n}${suf} at ${s.time}`;
  }
  if (kind === "interval") return s.every === 1 ? `Every ${s.unit.slice(0, -1)}` : `Every ${s.every} ${s.unit}`;
  if (kind === "event") return wfEventText(s);
  return `Custom (cron ${s.cron})`;
}

/** Mirror of workflows.event_text on the server. */
function wfEventText(s) {
  const w = (s && s.when) || {};
  const dev = w.device_id ? (wfNames()[w.device_id] || `device #${w.device_id}`) : "a device (choose one)";
  const lasting = w.for_minutes ? ` for ${w.for_minutes} min` : "";
  if (w.type === "metric") return `When ${dev} ${w.metric || "?"} is ${w.op || "above"} ${w.value ?? "?"}${lasting}`;
  if (w.type === "watch") return `When ${dev} ${w.name ? `watched ${w.name}` : "a watched service or process"} stops`;
  if (w.type === "problem") return `When ${dev} has ${w.rule ? `a '${w.rule}' problem` : "a problem"} (${w.min_severity || "warning"} or worse)`;
  return `When ${dev} ${{ snmp_down: "answers ping but not SNMP", offline: "goes offline", online: "comes back online" }[w.type] || "?"}${lasting}`;
}

function wfTomorrow() {
  const d = new Date(Date.now() + 86400000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function wfScheduleDefaults(kind, old) {
  const time = (old && old.time) || "04:00";
  return { manual: { kind }, once: { kind, date: wfTomorrow(), time }, daily: { kind, time },
    weekly: { kind, weekdays: [0], time }, monthly: { kind, day: 1, time },
    interval: { kind, every: 15, unit: "minutes" }, cron: { kind, cron: (old && old.cron) || "0 4 * * 0" },
    event: { kind, when: { type: "offline", device_id: null, for_minutes: 5 }, cooldown_minutes: 30 } }[kind];
}

// --- Graph helpers ---

function wfNode(id) { return wfb.draft.graph.nodes.find(n => n.id === id); }
function wfTrigger(graph) { return graph.nodes.find(n => n.type === "trigger"); }

function wfNewId() {
  const used = new Set(wfb.draft.graph.nodes.map(n => n.id));
  let i = 1;
  while (used.has(`n${i}`)) i += 1;
  return `n${i}`;
}

function wfDefaultCred() {
  const used = wfb.draft.graph.nodes.find(n => n.type === "command" && n.credential_id);
  return used ? used.credential_id : (wfCreds()[0] || {}).id || null;
}

function newStep(type, extra = {}) {
  const base = { id: wfNewId(), type, label: "", retries: 0, x: 0, y: 0 };
  if (type === "command") return { ...base, command: "", device_ids: [], credential_id: wfDefaultCred(), timeout_s: 60, ssh_port: 22, expected_exit_code: 0, any_exit: false, ...extra };
  if (type === "wait") return { ...base, seconds: 30, ...extra };
  if (type === "telegram") return { ...base, text: "{workflow}: {status}\n{steps}", ...extra };
  if (type === "wifi_reconnect") return { ...base, device_id: null, ...extra };
  if (type === "pve_snapshot") return { ...base, node: "", guest_type: "", vmid: null, guest_name: "", timeout_s: 600, ...extra };
  if (type === "mute") return { ...base, scope: "hosts", device_ids: [], target: "", until_end: true, minutes: 120, grace_min: 5, ...extra };
  if (type === "unmute") return { ...base, grace_min: 0, ...extra };
  return { ...base, device_id: null, timeout_s: 300, ...(type === "wait_ping" ? { state: "up" } : {}), ...extra };
}

/** Steps reachable from a node; used to refuse a connection that would loop. */
function wfReaches(graph, from, target) {
  const seen = new Set();
  const stack = [from];
  while (stack.length) {
    const n = stack.pop();
    if (n === target) return true;
    if (seen.has(n)) continue;
    seen.add(n);
    graph.edges.filter(e => e.from === n).forEach(e => stack.push(e.to));
  }
  return false;
}

function wfConnect(from, to, kind) {
  const g = wfb.draft.graph;
  const a = wfNode(from), b = wfNode(to);
  if (!a || !b || from === to) return;
  if (b.type === "trigger") { showToast("Nothing can connect into the trigger", "error"); return; }
  if (wfReaches(g, to, from)) { showToast("That connection would make the workflow loop", "error"); return; }
  // One success and one failure path per step: a new connection replaces the old one of that kind.
  g.edges = g.edges.filter(e => !(e.from === from && e.kind === kind));
  g.edges.push({ from, to, kind });
  wfb.sel = null;
  wfDirtyRender();
}

/** The last step on the success path from the trigger (where new steps attach). */
function wfChainEnd() {
  const g = wfb.draft.graph;
  let cur = wfTrigger(g).id;
  const seen = new Set();
  for (;;) {
    const e = g.edges.find(x => x.from === cur && x.kind === "ok");
    if (!e || seen.has(e.to)) return cur;
    seen.add(e.to);
    cur = e.to;
  }
}

/** A free spot near (x, y): moves down a row until no node overlaps. */
function wfFreeSpot(x, y) {
  const busy = (px, py) => wfb.draft.graph.nodes.some(n => Math.abs(n.x - px) < NODE_W - 20 && Math.abs(n.y - py) < NODE_H + 10);
  while (busy(x, y)) y += ROW_H;
  return [x, y];
}

/** Adds a step after the selected step (or at the end of the success path), connected to it. */
function wfAddAfter(step) {
  const g = wfb.draft.graph;
  const anchorId = wfb.sel && wfb.sel.kind === "node" ? wfb.sel.id : wfChainEnd();
  const anchor = wfNode(anchorId);
  [step.x, step.y] = wfFreeSpot(anchor.x + COL_W, anchor.y);
  if ((step.type === "wait_ping" || step.type === "wait_snmp") && !step.device_id) {
    // A wait after a command usually watches that command's last host.
    step.device_id = anchor.device_ids ? anchor.device_ids[anchor.device_ids.length - 1] || null : anchor.device_id || null;
  }
  g.nodes.push(step);
  const old = g.edges.find(e => e.from === anchorId && e.kind === "ok");
  if (old) {
    // Insert between the anchor and what came after it.
    old.from = step.id;
  }
  g.edges.push({ from: anchorId, to: step.id, kind: "ok" });
  wfb.sel = { kind: "node", id: step.id };
  wfb.panel = "node";
  wfDirtyRender();
}

function wfDeleteSelection() {
  if (!wfb || !wfb.sel) return;
  const g = wfb.draft.graph;
  if (wfb.sel.kind === "edge") {
    g.edges.splice(wfb.sel.i, 1);
  } else {
    const n = wfNode(wfb.sel.id);
    if (!n || n.type === "trigger") return;
    // Keep the path joined: what led into this step now leads to what it led to on success.
    const into = g.edges.filter(e => e.to === n.id);
    const next = g.edges.find(e => e.from === n.id && e.kind === "ok");
    g.edges = g.edges.filter(e => e.from !== n.id && e.to !== n.id);
    if (next) into.forEach(e => { if (!wfReaches(g, next.to, e.from)) g.edges.push({ from: e.from, to: next.to, kind: e.kind }); });
    g.nodes = g.nodes.filter(x => x.id !== n.id);
  }
  wfb.sel = null;
  wfDirtyRender();
}

/** Layered layout: columns by longest path from the trigger, rows in path order. */
function wfArrange(graph) {
  const depth = {};
  const order = [];
  const visit = (id, d) => {
    if (depth[id] !== undefined && depth[id] >= d) return;
    depth[id] = d;
    if (!order.includes(id)) order.push(id);
    ["ok", "fail"].forEach(k => graph.edges.filter(e => e.from === id && e.kind === k).forEach(e => visit(e.to, d + 1)));
  };
  visit(wfTrigger(graph).id, 0);
  const rows = {};
  order.forEach(id => {
    const n = graph.nodes.find(x => x.id === id);
    const d = depth[id];
    rows[d] = (rows[d] || 0);
    n.x = 40 + d * COL_W;
    n.y = 60 + rows[d] * ROW_H;
    rows[d] += 1;
  });
  let loose = 0;
  graph.nodes.filter(n => depth[n.id] === undefined).forEach(n => { n.x = 40 + loose * COL_W; n.y = 60 + (Math.max(0, ...Object.values(rows)) + 1) * ROW_H; loose += 1; });
}

// --- Drawing (editor and run viewer) ---

function wfNodeSummary(n, names) {
  if (n.type === "trigger") return wfScheduleText(n.schedule);
  if (n.label) return n.label;
  if (n.type === "command") {
    const hosts = (n.device_ids || []).map(id => names[id] || "?");
    const cmd = (n.command || "").split("\n").filter(Boolean).pop() || "No command yet";
    const user = wfRunsAs(n.credential_id);
    return `${cmd.slice(0, 32)}${hosts.length ? ` on ${hosts.slice(0, 2).join(", ")}${hosts.length > 2 ? ` +${hosts.length - 2}` : ""}` : ", no host"}${user ? ` as ${user}` : ""}`;
  }
  if (n.type === "wait") return `${n.seconds} s`;
  if (n.type === "telegram") return `${n.silent ? "quietly: " : ""}${(n.text || "").split("\n")[0].slice(0, 40) || "No text yet"}`;
  if (n.type === "mute") return wfMuteWhat(n, names) + (n.until_end ? ", until the run ends" : `, ${n.minutes} min`);
  if (n.type === "unmute") return n.grace_min ? `in ${n.grace_min} min` : "now";
  const host = n.device_id ? names[n.device_id] || "?" : "choose a host";
  if (n.type === "wifi_reconnect") return n.device_id ? `weak devices on ${host}` : "choose an access point";
  if (n.type === "pve_snapshot") return n.vmid ? `${n.guest_name || "guest"} (${n.vmid})` : "choose a guest";
  if (n.type === "wait_ping") return `${host} ${n.state === "down" ? "stops answering" : "answers"}`;
  return `${host} answers SNMP`;
}

function wfMuteWhat(n, names) {
  if (n.scope === "all") return "everything";
  if (n.scope === "group") return `group ${(((typeof taxo !== "undefined" && taxo.groups) || []).find(g => g.id === n.target) || {}).name || n.target || "?"}`;
  if (n.scope === "tag") return `tag ${n.target || "?"}`;
  if (n.scope === "devices") {
    const hs = (n.device_ids || []).map(id => names[id] || "?");
    return hs.length ? hs.slice(0, 2).join(", ") + (hs.length > 2 ? ` +${hs.length - 2}` : "") : "choose devices";
  }
  return "this workflow's hosts";
}

function wfNodeTitle(n) {
  if (n.type === "wait_ping") return n.state === "down" ? "Wait until down" : "Wait until up";
  return WF_KIND[n.type].title;
}

function wfPortPos(n, port) {
  if (port === "in") return [n.x, n.y + NODE_H / 2];
  if (n.type === "trigger") return [n.x + NODE_W, n.y + NODE_H / 2];
  return [n.x + NODE_W, n.y + (port === "ok" ? NODE_H * 0.34 : NODE_H * 0.72)];
}

function wfCurve(x1, y1, x2, y2) {
  if (x2 < x1 - 40 && Math.abs(y2 - y1) > NODE_H) {
    // Backwards to another row: out to the right, along the gap between the rows, in from the left.
    const ym = (y1 + y2) / 2;
    return `M ${x1} ${y1} C ${x1 + 40} ${y1}, ${x1 + 40} ${ym}, ${x1} ${ym} L ${x2} ${ym} C ${x2 - 40} ${ym}, ${x2 - 40} ${y2}, ${x2} ${y2}`;
  }
  const dx = Math.max(50, Math.abs(x2 - x1) / 2);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function wfEnsureWorld(host) {
  let world = host.querySelector(".wfb-world");
  if (!world) {
    world = document.createElement("div");
    world.className = "wfb-world";
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "wfb-edges");
    const nodes = document.createElement("div");
    nodes.className = "wfb-nodes";
    world.append(svg, nodes);
    host.prepend(world);
  }
  return world;
}

/** Draws a graph into host. opts: view {x, y, k}, sel, status {nodeId: ok|failed|running}, readonly, tempEdge. */
function wfDraw(host, graph, opts) {
  const world = wfEnsureWorld(host);
  const names = wfNames();
  const v = opts.view;
  world.style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.k})`;
  const sel = opts.sel || {};
  const status = opts.status || {};
  const nodesBox = world.querySelector(".wfb-nodes");
  nodesBox.innerHTML = graph.nodes.map(n => {
    const st = status[n.id] ? ` st-${escapeHtml(status[n.id])}` : (opts.status && n.type !== "trigger" ? " st-skipped" : "");
    const isSel = sel.kind === "node" && sel.id === n.id ? " selected" : "";
    const ports = opts.readonly ? "" : `
      ${n.type === "trigger" ? "" : `<span class="wfb-port wfb-in" data-port-in="${escapeHtml(n.id)}"></span>`}
      <span class="wfb-port wfb-out-ok${n.type === "trigger" ? " wfb-out-mid" : ""}" data-port-out="${escapeHtml(n.id)}" data-kind="ok" title="Drag to the next step (on success)"></span>
      ${n.type === "trigger" ? "" : `<span class="wfb-port wfb-out-fail" data-port-out="${escapeHtml(n.id)}" data-kind="fail" title="Drag to the step to run if this one fails"></span>`}`;
    return `<div class="wfb-node wfb-t-${escapeHtml(n.type)}${isSel}${st}" data-node="${escapeHtml(n.id)}">
      <div class="wfb-node-head"><span class="wfb-badge">${WF_KIND[n.type].badge}</span><span class="wfb-node-title">${escapeHtml(wfNodeTitle(n))}</span>
        ${n.retries ? `<span class="wfb-retry" title="Retries">x${Number(n.retries) + 1}</span>` : ""}</div>
      <div class="wfb-node-sub">${escapeHtml(wfNodeSummary(n, names))}</div>${ports}
    </div>`;
  }).join("");
  nodesBox.querySelectorAll(".wfb-node").forEach(el => {
    const n = graph.nodes.find(x => x.id === el.dataset.node);
    el.style.left = `${n.x}px`;
    el.style.top = `${n.y}px`;
  });
  wfDrawEdges(world, graph, opts);
}

function wfDrawEdges(world, graph, opts) {
  const svg = world.querySelector(".wfb-edges");
  const sel = opts.sel || {};
  const byId = Object.fromEntries(graph.nodes.map(n => [n.id, n]));
  const status = opts.status || {};
  let html = "";
  graph.edges.forEach((e, i) => {
    const a = byId[e.from], b = byId[e.to];
    if (!a || !b) return;
    const [x1, y1] = wfPortPos(a, e.kind);
    const [x2, y2] = wfPortPos(b, "in");
    const d = wfCurve(x1, y1, x2, y2);
    // In the run viewer a connection is "taken" when both ends ran and the source ended the matching way.
    const taken = opts.status && status[e.from] && status[e.to] && ((e.kind === "ok") === (status[e.from] === "ok"));
    const cls = `wfb-edge wfb-edge-${e.kind}${sel.kind === "edge" && sel.i === i ? " selected" : ""}${opts.status ? (taken ? " taken" : " untaken") : ""}`;
    html += `<path class="${escapeHtml(cls)}" d="${escapeHtml(d)}"></path>`;
    if (!opts.readonly) html += `<path class="wfb-edge-hit" data-edge="${i}" d="${escapeHtml(d)}"><title>${e.kind === "ok" ? "On success" : "On failure"}: click, then Delete to remove</title></path>`;
    if (e.kind === "fail" && Math.abs(x2 - x1) > 120) html += `<text class="wfb-edge-label" x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 - 6}">on failure</text>`;
  });
  if (opts.tempEdge) html += `<path class="wfb-edge wfb-edge-${escapeHtml(opts.tempEdge.kind)} wfb-edge-temp" d="${escapeHtml(opts.tempEdge.d)}"></path>`;
  svg.innerHTML = html;
}

function wfFit(host, graph, view) {
  const r = host.getBoundingClientRect();
  if (!graph.nodes.length || !r.width) return;
  const xs = graph.nodes.map(n => n.x), ys = graph.nodes.map(n => n.y);
  const minX = Math.min(...xs) - 60, maxX = Math.max(...xs) + NODE_W + 60;
  const minY = Math.min(...ys) - 60, maxY = Math.max(...ys) + NODE_H + 60;
  view.k = Math.max(0.3, Math.min(1.1, r.width / (maxX - minX), r.height / (maxY - minY)));
  view.x = (r.width - (maxX - minX) * view.k) / 2 - minX * view.k;
  view.y = (r.height - (maxY - minY) * view.k) / 2 - minY * view.k;
}

// --- Editor ---

function wfRender() {
  wfDraw(document.getElementById("wfb-canvas"), wfb.draft.graph, { view: wfb.view, sel: wfb.sel, tempEdge: wfb.tempEdge });
}

function wfDirtyRender(panelToo = true) {
  wfRender();
  if (panelToo) wfRenderPanel();
  document.getElementById("wf-error").classList.add("hidden");
}

function wfSnapshot() {
  return JSON.stringify({ n: document.getElementById("wf-name").value, d: document.getElementById("wf-description").value,
    a: wfb.draft.is_active, g: wfb.draft.graph });
}

async function openWorkflowModal(wf) {
  if (!autoData) await loadAutomation();
  await wfLoadMap();
  const draft = wf ? JSON.parse(JSON.stringify({ id: wf.id, name: wf.name, description: wf.description || "", is_active: wf.is_active, graph: wf.graph }))
    : { id: null, name: "", description: "", is_active: true,
        graph: { nodes: [{ id: "trigger", type: "trigger", x: 40, y: 120, schedule: { kind: "manual" } }], edges: [] } };
  wfb = { draft, view: { x: 0, y: 0, k: 1 }, sel: null, panel: wf ? "node" : "templates", tempEdge: null };
  document.getElementById("wf-title").textContent = wf ? `Edit ${wf.name}` : "Add Workflow";
  document.getElementById("wf-name").value = draft.name;
  document.getElementById("wf-description").value = draft.description;
  document.getElementById("wf-error").classList.add("hidden");
  show(document.getElementById("modal-workflow"));
  wfFit(document.getElementById("wfb-canvas"), draft.graph, wfb.view);
  if (!wf) { wfb.view.k = 1; wfb.view.x = 20; wfb.view.y = 20; }
  wfb.initial = wfSnapshot();
  wfRender();
  wfRenderPanel();
  if (!wf) document.getElementById("wf-name").focus();
}

async function closeWorkflowModal() {
  if (wfb && wfSnapshot() !== wfb.initial &&
      !(await confirmDialog({ title: "Discard changes?", message: "This workflow has changes that are not saved.", confirmLabel: "Discard", danger: true }))) return;
  hide(document.getElementById("modal-workflow"));
  wfb = null;
}

function hostOptions(selected, filter) {
  return wfHosts().filter(d => !filter || filter(d)).map(d =>
    `<option value="${Number(d.id)}"${d.id === selected ? " selected" : ""}>${escapeHtml(d.hostname)} (${escapeHtml(d.ip_address)})</option>`).join("");
}

function credOptions(selected) {
  return wfCreds().map(c =>
    `<option value="${Number(c.id)}"${c.id === selected ? " selected" : ""}>${escapeHtml(c.name)}${c.username ? ` (${escapeHtml(c.username)})` : ""}</option>`).join("");
}

function wfPanelHelp() {
  const steps = wfb.draft.graph.nodes.length - 1;
  return `<div class="wfb-panel-title">Building a workflow</div>
    <ul class="wfb-help">
      <li>Drag a step from the left onto the canvas, or click it to add it after the selected step.</li>
      <li>Drag from a step's <span class="wfb-dot ok"></span> dot to the next step (on success) or from its <span class="wfb-dot fail"></span> dot to a step to run if it fails. Without a failure connection, a failed step stops the run.</li>
      <li>Click a step to edit it here. Delete removes the selected step or connection.</li>
      <li>Drag the background to move around, scroll to zoom.</li>
    </ul>
    ${steps ? "" : `<button type="button" class="btn btn-primary" data-panel="templates">Start from a template</button>`}
    <button type="button" class="btn" data-select="${escapeHtml(wfTrigger(wfb.draft.graph).id)}">Schedule (${escapeHtml(wfScheduleText(wfTrigger(wfb.draft.graph).schedule))})</button>`;
}

function wfPanelTrigger(n) {
  const s = n.schedule || { kind: "manual" };
  const kinds = [["manual", "Manual only"], ["once", "Once, on a date"], ["daily", "Every day"], ["weekly", "Every week"],
    ["monthly", "Every month"], ["interval", "Repeating, every few minutes or hours"], ["event", "When something happens"]];
  if (s.kind === "cron") kinds.push(["cron", "Custom (cron)"]);
  const time = `<div class="form-group"><label>Time</label><input type="time" data-s="time" value="${escapeHtml(s.time || "04:00")}"></div>`;
  let fields = "";
  if (s.kind === "once") {
    fields = `<div class="form-row"><div class="form-group"><label>Date</label><input type="date" data-s="date" value="${escapeHtml(s.date || "")}"></div>${time}</div>
      ${s.done ? `<div class="text-warn">This one-off run has happened. Pick a new date to run it again.</div>` : ""}`;
  } else if (s.kind === "daily") {
    fields = time;
  } else if (s.kind === "weekly") {
    fields = `<div class="form-group"><label>On</label><div class="wfb-days">${WF_DAYS.map(([d, name]) =>
      `<label class="wfb-day"><input type="checkbox" data-wd="${escapeHtml(d)}"${(s.weekdays || []).includes(d) ? " checked" : ""}> ${escapeHtml(name)}</label>`).join("")}</div></div>${time}`;
  } else if (s.kind === "monthly") {
    fields = `<div class="form-row"><div class="form-group"><label>Day of the month</label><select data-s="day" data-num="1">${
      Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}"${s.day === i + 1 ? " selected" : ""}>${i + 1}</option>`).join("")}</select></div>${time}</div>
      ${s.day > 28 ? `<div class="dim">Months without day ${Number(s.day)} are skipped.</div>` : ""}`;
  } else if (s.kind === "interval") {
    const steps = s.unit === "hours" ? WF_HOUR_STEPS : WF_MINUTE_STEPS;
    fields = `<div class="form-row"><div class="form-group"><label>Every</label><select data-s="every" data-num="1">${
      steps.map(v => `<option value="${escapeHtml(v)}"${s.every === v ? " selected" : ""}>${escapeHtml(v)}</option>`).join("")}</select></div>
      <div class="form-group"><label>Unit</label><select data-s="unit">
        <option value="minutes"${s.unit === "minutes" ? " selected" : ""}>minutes</option>
        <option value="hours"${s.unit === "hours" ? " selected" : ""}>hours</option></select></div></div>`;
  } else if (s.kind === "event") {
    fields = wfEventFields(s);
  } else if (s.kind === "cron") {
    fields = `<div class="form-group"><label>Cron expression</label><input type="text" data-s="cron" value="${escapeHtml(s.cron || "")}" spellcheck="false">
      <div class="form-help">Kept from an older workflow. Pick another option above to use the date and time picker.</div></div>`;
  }
  return `<div class="wfb-panel-title">Trigger</div>
    <div class="form-group"><label>When it runs</label><select data-s="kind">${kinds.map(([k, t]) =>
      `<option value="${escapeHtml(k)}"${s.kind === k ? " selected" : ""}>${escapeHtml(t)}</option>`).join("")}</select></div>
    ${fields}
    <div class="wfb-summary">${escapeHtml(wfScheduleText(s))}</div>
    ${s.kind === "manual" ? "" : `<label class="check-label"><input type="checkbox" data-wf-active${wfb.draft.is_active ? " checked" : ""}> Enabled (${s.kind === "event" ? "it starts on its own" : "scheduled runs happen"} only while this is ticked)</label>
      <div class="form-help">${s.kind === "event" ? "Checked about every half minute, after each problem check." : "Times are the monitor's own clock."} Run now from the list works whatever the trigger.</div>`}`;
}

/** Fields for "When something happens": the device, the condition and how long it must hold. */
function wfEventFields(s) {
  const w = s.when || {};
  const info = (wfb.devInfo || {})[w.device_id];
  if (w.device_id && !info) wfLoadDevInfo(w.device_id);
  const lasting = (label = "For at least (minutes, 0 = at once)") => `<div class="form-group"><label>${escapeHtml(label)}</label>
    <input type="number" min="0" max="1440" data-ev="for_minutes" data-num="1" value="${Number(w.for_minutes || 0)}"></div>`;
  let extra = "";
  if (w.type === "metric") {
    const metrics = info ? info.metrics : [];
    extra = `<div class="form-group"><label>Measurement</label>${info ? `<select data-ev="metric"><option value="">Choose...</option>${metrics.map(m =>
      `<option value="${escapeHtml(m.key)}"${m.key === w.metric ? " selected" : ""}>${escapeHtml(m.label)} (now ${escapeHtml(m.now)})</option>`).join("")}</select>`
      : `<div class="dim">${w.device_id ? "Loading the device's measurements..." : "Choose the device first."}</div>`}</div>
      <div class="form-row"><div class="form-group"><label>Is</label><select data-ev="op">
        <option value="above"${w.op !== "below" ? " selected" : ""}>above</option><option value="below"${w.op === "below" ? " selected" : ""}>below</option></select></div>
      <div class="form-group"><label>Value</label><input type="number" step="any" data-ev="value" data-float="1" value="${escapeHtml(String(w.value ?? ""))}"></div></div>
      ${lasting()}
      <div class="form-help">Wireless: client count per radio is available. Signal per client is not collected (the access points do not report it over SNMP), so roaming fixes per client are future work.</div>`;
  } else if (w.type === "snmp_down" || w.type === "offline") {
    extra = lasting();
  } else if (w.type === "watch") {
    const names = info ? info.watches : [];
    extra = `<div class="form-group"><label>Which one</label><select data-ev="name"><option value="">Any watched service or process</option>${names.map(n =>
      `<option value="${escapeHtml(n)}"${n === w.name ? " selected" : ""}>${escapeHtml(n)}</option>`).join("")}</select>
      ${info && !names.length ? `<div class="form-help">Nothing is watched on this device yet: tick Watch on its Processes tab.</div>` : ""}</div>`;
  } else if (w.type === "problem") {
    const rules = info ? info.rules : [];
    extra = `<div class="form-row"><div class="form-group"><label>Problem</label><select data-ev="rule"><option value="">Any problem</option>${rules.map(r =>
      `<option value="${escapeHtml(r.id)}"${r.id === w.rule ? " selected" : ""}>${escapeHtml(r.label)}</option>`).join("")}</select></div>
      <div class="form-group"><label>At least</label><select data-ev="min_severity">${["info", "warning", "high", "critical"].map(v =>
      `<option value="${escapeHtml(v)}"${(w.min_severity || "warning") === v ? " selected" : ""}>${escapeHtml(v)}</option>`).join("")}</select></div></div>`;
  }
  return `<div class="form-group"><label>Device to watch</label><select data-ev="device_id" data-num="1"><option value="">Choose a device...</option>${hostOptions(w.device_id)}</select></div>
    <div class="form-group"><label>What happens</label><select data-ev="type">${WF_EVENT_TYPES.map(([k, t]) =>
      `<option value="${escapeHtml(k)}"${w.type === k ? " selected" : ""}>${escapeHtml(t)}</option>`).join("")}</select></div>
    ${extra}
    <div class="form-group"><label>Then wait at least (minutes) before it can run again</label>
      <input type="number" min="1" max="1440" data-s="cooldown_minutes" data-num="1" value="${Number(s.cooldown_minutes || 30)}"></div>
    <div class="form-help">It runs once when this becomes true, and again only after it has cleared and come back.</div>`;
}

/** Measurements, alert rules and watched names of one device, for the event fields. */
async function wfLoadDevInfo(id) {
  wfb.devInfo = wfb.devInfo || {};
  if (wfb.devInfo[id] || (wfb.devLoading || {})[id]) return;
  wfb.devLoading = { ...(wfb.devLoading || {}), [id]: true };
  const info = { metrics: [], rules: [], watches: [] };
  try {
    const d = await api(`/api/devices/${Number(id)}`);
    info.metrics = (d.latest_metrics || []).filter(m => typeof m.value === "number").map(m => {
      // Custom SNMP values by the name given to them; the rest as the device page names them.
      const own = (d.metric_info || {})[m.metric_key];
      if (own && own.custom) return { key: m.metric_key, label: `${own.label}, custom`, now: `${Number(m.value).toLocaleString()}${own.unit ? " " + own.unit : ""}` };
      const [label, now] = typeof describeMetric === "function" ? describeMetric(m.metric_key, m.value) : [m.metric_key, String(m.value)];
      return { key: m.metric_key, label: own && own.label ? own.label : label, now };
    }).sort((a, b) => a.label.localeCompare(b.label));
    const r = await api(`/api/alert-rules?scope=device&target=${Number(id)}`).catch(() => ({ rules: [] }));
    info.rules = (r.rules || []).map(x => ({ id: x.id, label: x.label }));
    const pr = await api(`/api/devices/${Number(id)}/processes`).catch(() => ({ watches: [] }));
    info.watches = (pr.watches || []).map(x => x.name);
  } catch (err) { /* the fields say what is missing */ }
  // The builder may have been closed or reopened while this loaded: keep the result only if it is still open.
  if (!wfb) return;
  wfb.devInfo = wfb.devInfo || {};
  wfb.devInfo[id] = info;
  wfRenderPanel();
}

function wfTemplateOptions(n) {
  const hosts = (n.device_ids || []).map(id => wfHosts().find(d => d.id === id)).filter(Boolean);
  const fits = WF_COMMAND_TEMPLATES.filter(t => hosts.length && hosts.every(h => wfTemplateSuits(t, h)));
  const rest = WF_COMMAND_TEMPLATES.filter(t => !fits.includes(t));
  const opt = t => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)}</option>`;
  return `<option value="">Fill in from a template...</option>
    ${fits.length ? `<optgroup label="Suits these hosts">${fits.map(opt).join("")}</optgroup>` : ""}
    <optgroup label="${fits.length ? "Other templates" : "Templates"}">${rest.map(opt).join("")}</optgroup>`;
}

function wfPanelStep(n) {
  const names = wfNames();
  const warn = [];
  let body = "";
  if (n.type === "command") {
    const chips = n.device_ids.map((id, k) => `<span class="target-chip">${k + 1}. ${escapeHtml(names[id] || "?")}
      ${k > 0 ? `<button type="button" class="chip-btn" data-host-up="${k}" title="Earlier">&uarr;</button>` : ""}
      <button type="button" class="chip-btn" data-host-del="${k}" title="Remove">&times;</button></span>`).join(" ");
    n.device_ids.forEach(id => {
      if (wfCutsMonitor(id)) warn.push(`${names[id] || "A host"} is upstream of this monitor: while it restarts the monitor is offline too. Follow it with Wait until down and Wait until up so the run carries on once the network is back.`);
      const h = wfHosts().find(d => d.id === id);
      if (h && !h.host_key) warn.push(`${h.hostname}: SSH host key not approved yet. Use Host keys in the workflow list after saving.`);
    });
    const tpl = WF_COMMAND_TEMPLATES.find(t => t.command === n.command);
    body = `
      <div class="form-group"><label>Hosts, in order</label><div class="wf-hosts">${chips || '<span class="dim">None yet</span>'}</div>
        <select data-host-add><option value="">Add host...</option>${hostOptions(null, d => !n.device_ids.includes(d.id))}</select></div>
      <div class="form-group"><label>Command</label>
        ${n.device_ids.length ? `<select data-template>${wfTemplateOptions(n)}</select>` : ""}
        <textarea rows="5" spellcheck="false" data-f="command" placeholder="e.g. uptime">${escapeHtml(n.command)}</textarea>
        ${tpl && tpl.note ? `<div class="form-help">${escapeHtml(tpl.note)}</div>` : ""}</div>
      <div class="form-group"><label>Credential</label>${wfCreds().length ? `<select data-f="credential_id" data-num="1">${credOptions(n.credential_id)}</select>`
        : `<div class="text-warn">No stored credential yet. Add one under Credentials first.</div>`}
        ${wfRunsAs(n.credential_id) ? `<div class="form-help">Runs as ${escapeHtml(wfRunsAs(n.credential_id))} on these hosts, using the credential ${escapeHtml(wfCreds().find(x => x.id === n.credential_id).name)}.</div>` : ""}</div>
      <div class="form-row">
        <div class="form-group"><label>Timeout (s)</label><input type="number" min="5" max="3600" data-f="timeout_s" value="${Number(n.timeout_s)}"></div>
        <div class="form-group"><label>SSH port</label><input type="number" min="1" max="65535" data-f="ssh_port" value="${Number(n.ssh_port)}"></div>
      </div>
      <label class="check-label"><input type="checkbox" data-f="expect_disconnect"${n.expect_disconnect ? " checked" : ""}> This restarts the host: a dropped connection means it worked</label>
      <label class="check-label"><input type="checkbox" data-f="any_exit"${n.any_exit ? " checked" : ""}> Any exit code counts as success</label>
      ${n.any_exit ? "" : `<div class="form-group"><label>Expected exit code</label><input type="number" min="0" max="255" data-f="expected_exit_code" value="${Number(n.expected_exit_code)}"></div>`}
      ${n.credential_id && n.device_ids.length && can("credentials.use") ? `<div class="wfb-test"><button type="button" class="btn btn-small" data-test-login>Test login on ${escapeHtml(names[n.device_ids[0]] || "the first host")}</button>
        <span class="dim" id="wfb-test-result"></span></div>` : ""}`;
  } else if (n.type === "wait") {
    body = `<div class="form-group"><label>Seconds</label><input type="number" min="1" max="3600" data-f="seconds" value="${Number(n.seconds)}"></div>`;
  } else if (n.type === "telegram") {
    body = `<div class="form-group"><label>Message</label>
        <textarea rows="5" maxlength="1000" data-f="text">${escapeHtml(n.text || "")}</textarea>
        <button type="button" class="btn btn-small" data-tg-edit>Placeholders and emoji...</button></div>
      <label class="check-label"><input type="checkbox" data-f="silent"${n.silent ? " checked" : ""}> Send quietly (arrives without a sound)</label>
      <div class="form-help">Sent through the Telegram bot in Settings, Notifications. Queued if Telegram cannot be reached, so a restart that cuts the internet does not lose it.
        The text understands the message tricks: <code>{if status == "a step failed"}❌{else}✅{end}</code>.</div>`;
  } else if (n.type === "mute") {
    const groups = (typeof taxo !== "undefined" && taxo.groups) || [];
    const tags = (typeof taxo !== "undefined" && taxo.tags) || [];
    const chips = (n.device_ids || []).map((id, k) => `<span class="target-chip">${escapeHtml(names[id] || "?")}
      <button type="button" class="chip-btn" data-host-del="${k}" title="Remove">&times;</button></span>`).join(" ");
    body = `<div class="form-group"><label>Keep quiet</label><select data-f="scope">
        ${[["hosts", "This workflow's hosts"], ["devices", "Devices I pick"], ["group", "A group"], ["tag", "A tag"], ["all", "Everything"]]
          .filter(([v]) => v !== "all" || n.scope === "all" || !(currentUser && currentUser.scoped)).map(([v, l]) =>
          `<option value="${escapeHtml(v)}"${n.scope === v ? " selected" : ""}>${escapeHtml(l)}</option>`).join("")}</select></div>
      ${n.scope === "devices" ? `<div class="form-group"><label>Devices</label><div class="wf-hosts">${chips || '<span class="dim">None yet</span>'}</div>
        <select data-host-add><option value="">Add device...</option>${hostOptions(null, d => !(n.device_ids || []).includes(d.id))}</select></div>` : ""}
      ${n.scope === "group" ? `<div class="form-group"><label>Group</label><select data-f="target"><option value="">Choose a group...</option>${groups.map(g =>
        `<option value="${escapeHtml(g.id)}"${g.id === n.target ? " selected" : ""}>${escapeHtml(g.name)}</option>`).join("")}</select></div>` : ""}
      ${n.scope === "tag" ? `<div class="form-group"><label>Tag</label><select data-f="target"><option value="">Choose a tag...</option>${tags.map(t =>
        `<option value="${escapeHtml(t.name)}"${t.name === n.target ? " selected" : ""}>${escapeHtml(t.name)}</option>`).join("")}</select></div>` : ""}
      <label class="check-label"><input type="checkbox" data-f="until_end"${n.until_end ? " checked" : ""}> Until the run ends</label>
      <div class="form-row">
        ${n.until_end ? `<div class="form-group"><label>Then wait (min)</label><input type="number" min="0" max="120" data-f="grace_min" value="${Number(n.grace_min ?? 5)}"></div>` : ""}
        <div class="form-group"><label>${n.until_end ? "At most (min)" : "For (min)"}</label><input type="number" min="1" max="1440" data-f="minutes" value="${Number(n.minutes || 60)}"></div>
      </div>
      <div class="form-help">Opens a maintenance window: problems still show and are logged, but no Telegram message goes out and the downtime counts as planned in Availability.
        A device that comes back after the run still has the extra minutes, so its "back online" message stays quiet too. ${n.until_end ? "<em>At most</em> is a safety limit in case the run is stopped." : ""}</div>`;
  } else if (n.type === "unmute") {
    body = `<div class="form-group"><label>After (min)</label><input type="number" min="0" max="120" data-f="grace_min" value="${Number(n.grace_min || 0)}"></div>
      <div class="form-help">Ends what <em>Suppress notifications</em> started in this run. Not needed at the end of a workflow: the run ends it by itself.</div>`;
  } else if (n.type === "pve_snapshot") {
    if (wfPveGuests === null) {
      wfPveGuests = [];
      api("/api/proxmox").then(d => { wfPveGuests = (d.guests || []).filter(g => !g.template); wfRenderPanel(); }).catch(() => {});
    }
    const cur = `${n.node}|${n.guest_type}|${n.vmid}`;
    body = `<div class="form-group"><label>Guest</label><select data-pve-guest><option value="">Choose a VM or container...</option>${wfPveGuests.map(g =>
        `<option value="${escapeHtml(`${g.node}|${g.type}|${g.vmid}|${g.name || ""}`)}"${`${g.node}|${g.type}|${g.vmid}` === cur ? " selected" : ""}>${escapeHtml(`${g.name || "#" + g.vmid} (${g.vmid}, ${g.type === "lxc" ? "container" : "VM"} on ${g.node})`)}</option>`).join("")}</select></div>
      <div class="form-group"><label>Give up after (s)</label><input type="number" min="30" max="3600" data-f="timeout_s" value="${Number(n.timeout_s || 600)}"></div>
      <div class="form-help">Takes a snapshot named monitor-date-time and waits until Proxmox has it, so the next steps can update the guest safely. Roll back in Proxmox (the guest, Snapshots) if the update goes wrong. Needs the action token (Settings, Proxmox).</div>`;
  } else if (n.type === "wifi_reconnect") {
    body = `<div class="form-group"><label>Access point</label><select data-f="device_id" data-num="1"><option value="">Choose an access point...</option>${hostOptions(n.device_id)}</select></div>
      <div class="form-help">Every Wi-Fi device on it with a signal below the line in Alert rules, <em>Wi-Fi devices on weak signal</em>, is dropped so it joins again (UniFi, Settings). At most once an hour per device; the never-reconnect list (Settings, UniFi) is left alone. Pairs well with the trigger <em>A problem opens</em>, rule <em>Wi-Fi devices on weak signal</em>.</div>`;
  } else {
    body = `<div class="form-group"><label>Host</label><select data-f="device_id" data-num="1"><option value="">Choose a host...</option>${hostOptions(n.device_id)}</select></div>
      ${n.type === "wait_ping" ? `<div class="form-group"><label>Until it</label><select data-f="state">
        <option value="down"${n.state === "down" ? " selected" : ""}>stops answering</option>
        <option value="up"${n.state === "up" ? " selected" : ""}>answers</option></select></div>` : ""}
      <div class="form-group"><label>Give up after (s)</label><input type="number" min="10" max="3600" data-f="timeout_s" value="${Number(n.timeout_s)}"></div>`;
  }
  const g = wfb.draft.graph;
  const failTo = g.edges.find(e => e.from === n.id && e.kind === "fail");
  return `<div class="wfb-panel-title">${escapeHtml(wfNodeTitle(n))}</div>
    <div class="form-group"><label>Label (optional)</label><input type="text" data-f="label" maxlength="80" value="${escapeHtml(n.label || "")}"></div>
    ${body}
    <div class="form-group"><label>Retries when it fails</label><input type="number" min="0" max="10" data-f="retries" value="${Number(n.retries || 0)}"></div>
    <div class="form-help">${failTo ? `If it still fails: goes to ${escapeHtml(wfNodeTitle(wfNode(failTo.to)))} (red connection).` : "If it still fails: the run stops. Drag from the red dot to add a failure path."}</div>
    ${warn.map(w => `<div class="text-warn wf-warn">${escapeHtml(w)}</div>`).join("")}
    <div class="wfb-panel-actions"><button type="button" class="btn btn-danger" data-delete-sel>Delete step</button></div>`;
}

function wfPanelEdge(e) {
  const a = wfNode(e.from), b = wfNode(e.to);
  return `<div class="wfb-panel-title">Connection</div>
    <p>${escapeHtml(wfNodeTitle(a))} to ${escapeHtml(wfNodeTitle(b))}, followed when the first step ${e.kind === "ok" ? "succeeds" : "fails"}.</p>
    <div class="wfb-panel-actions"><button type="button" class="btn btn-danger" data-delete-sel>Delete connection</button></div>`;
}

/** Left column: Steps or Templates. Both add to the canvas; the right panel shows what is picked. */
function wfSyncPalette() {
  const palette = document.getElementById("wfb-palette");
  if (!palette || !palette.querySelector("[data-pal-tab]")) return;
  if (wfb && wfb.panel === "templates") wfPalTab = "templates";
  palette.querySelectorAll("[data-pal-tab]").forEach(b => {
    const on = b.dataset.palTab === wfPalTab;
    b.classList.toggle("active", on);
    b.setAttribute("aria-selected", String(on));
  });
  palette.querySelector("[data-pal-steps]").classList.toggle("hidden", wfPalTab !== "steps");
  palette.querySelector("[data-pal-tpls]").classList.toggle("hidden", wfPalTab !== "templates");
  palette.querySelectorAll("[data-tpl]").forEach(b => b.classList.toggle("selected", !!wfb && b.dataset.tpl === wfb.template));
}

function wfPanelTemplates() {
  const t = wfb.template && WF_FLOW_TEMPLATES.find(x => x.id === wfb.template);
  if (!t) {
    return `<div class="wfb-panel-title">Templates</div>
      <div class="form-help">Pick a template on the left. It adds ready-made steps after the selected step (or at the end); edit them afterwards like any other step.</div>
      <button type="button" class="btn" data-panel="node">Back</button>`;
  }
  if (t.needsGuests && wfPveGuests === null) {
    wfPveGuests = [];
    api("/api/proxmox").then(d => { wfPveGuests = (d.guests || []).filter(g => !g.template); wfRenderPanel(); }).catch(() => {});
  }
  const hosts = wfHosts().slice().sort((a, b) => (wfTemplateSuits(t, b) - wfTemplateSuits(t, a)) || (wfDepth(b.id) - wfDepth(a.id)));
  return `<div class="wfb-panel-title">${escapeHtml(t.name)}</div>
    <div class="form-help">${escapeHtml(t.help)}</div>
    <div class="form-group"><label>Hosts</label><div class="wf-seq-hosts">${hosts.map(d => `<label class="check-label">
      <input type="checkbox" data-tpl-host value="${Number(d.id)}"${wfTemplateSuits(t, d) && t.suits.length && hosts.filter(h => wfTemplateSuits(t, h)).length <= 6 ? "" : ""}>
      ${escapeHtml(d.hostname)} <span class="dim">${wfTemplateSuits(t, d) ? "suits, " : ""}${wfDepth(d.id) >= 0 ? `${wfDepth(d.id)} hops from the gateway` : "not on the map"}</span></label>`).join("")}</div></div>
    ${t.askCommand ? `<div class="form-group"><label>${escapeHtml(t.askLabel || "Restart command")}</label><input type="text" id="wfb-tpl-command" value="${escapeHtml(t.askDefault ?? "reboot")}"></div>` : ""}
    ${t.noCred ? "" : `<div class="form-group"><label>Credential</label>${wfCreds().length ? `<select id="wfb-tpl-cred">${credOptions(wfDefaultCred())}</select>`
      : `<div class="text-warn">No stored credential yet. Add one under Credentials first.</div>`}</div>`}
    ${t.quiet === undefined ? "" : `<label class="check-label"><input type="checkbox" id="wfb-tpl-quiet"${t.quiet ? " checked" : ""}> Suppress notifications for these hosts while it runs</label>`}
    <label class="check-label"><input type="checkbox" id="wfb-tpl-report"${t.report ? " checked" : ""}> Send a summary on Telegram at the end, quietly</label>
    <div class="wfb-panel-actions"><button type="button" class="btn btn-primary" data-tpl-add>Add these steps</button>
      <button type="button" class="btn" data-tpl-back>Back</button></div>`;
}

function wfRenderPanel() {
  wfSyncPalette();
  const panel = document.getElementById("wfb-panel");
  if (wfb.panel === "templates") { panel.innerHTML = wfPanelTemplates(); return; }
  const sel = wfb.sel;
  if (sel && sel.kind === "node" && wfNode(sel.id)) {
    const n = wfNode(sel.id);
    panel.innerHTML = n.type === "trigger" ? wfPanelTrigger(n) : wfPanelStep(n);
  } else if (sel && sel.kind === "edge" && wfb.draft.graph.edges[sel.i]) {
    panel.innerHTML = wfPanelEdge(wfb.draft.graph.edges[sel.i]);
  } else {
    panel.innerHTML = wfPanelHelp();
  }
}

/** Adds a whole-workflow template: one row of steps per host, rows joined end to start. */
function wfAddTemplate() {
  const t = WF_FLOW_TEMPLATES.find(x => x.id === wfb.template);
  let ids = Array.from(document.querySelectorAll("#wfb-panel [data-tpl-host]:checked")).map(b => parseInt(b.value, 10));
  const credEl = document.getElementById("wfb-tpl-cred");
  const cred = credEl ? parseInt(credEl.value, 10) : null;
  const cmdEl = document.getElementById("wfb-tpl-command");
  const command = cmdEl ? cmdEl.value.trim() : "";
  if (!ids.length || (!cred && !t.noCred) || (t.askCommand && !command)) {
    showToast("Choose hosts" + (t.noCred ? "" : " and a credential") + (t.askCommand ? ` and ${(t.askLabel || "a command").toLowerCase()}` : ""), "error");
    return;
  }
  if (t.id.startsWith("ha_") && !wfHa("disk_usage")) {
    showToast("The host actions list has not loaded yet (it needs permission to run automation). Try again in a moment.", "error");
    if (typeof haLoadCatalogue === "function") haLoadCatalogue();
    return;
  }
  const quiet = (document.getElementById("wfb-tpl-quiet") || {}).checked;
  const report = (document.getElementById("wfb-tpl-report") || {}).checked;
  // Furthest from the gateway first, so nothing restarts while a device it depends on is down.
  if (t.order === "restart") ids.sort((a, b) => wfDepth(b) - wfDepth(a));
  const g = wfb.draft.graph;
  let prev = wfb.sel && wfb.sel.kind === "node" ? wfb.sel.id : wfChainEnd();
  const after = g.edges.find(e => e.from === prev && e.kind === "ok");
  if (after) g.edges = g.edges.filter(e => e !== after);
  const start = wfNode(prev);
  const maxY = Math.max(...g.nodes.map(n => n.y));
  let row = 0;
  const place = (step, col) => {
    step.x = start.x + COL_W + col * COL_W;
    step.y = row === 0 ? start.y : maxY + row * ROW_H;
  };
  const link = (step, failNext) => {
    g.nodes.push(step);
    g.edges.push({ from: prev, to: step.id, kind: "ok" });
    if (failNext) g.edges.push({ from: prev, to: step.id, kind: "fail" });
  };
  const add = (step, col) => { place(step, col); link(step, false); prev = step.id; };
  if (quiet) { add(newStep("mute", { scope: "devices", device_ids: [...ids], until_end: true, minutes: 240, grace_min: 5 }), 0); row += 1; }
  if (t.single) {
    const step = newStep("command", { ...t.single(command), credential_id: cred, device_ids: ids });
    place(step, 0);
    link(step, false);
    prev = step.id;
    row += 1;
  } else {
    ids.forEach(id => {
      const host = wfHosts().find(d => d.id === id);
      let failNext = false;
      t.steps(host, command).forEach((spec, col) => {
        const { failNext: nextFails, ...fields } = spec;
        const step = newStep(spec.type, fields.type === "command" ? { ...fields, credential_id: cred, device_ids: [id] }
          : ["pve_snapshot", "telegram", "wait", "mute", "unmute"].includes(fields.type) ? fields : { ...fields, device_id: id });
        place(step, col);
        link(step, failNext);
        failNext = !!nextFails;
        prev = step.id;
      });
      row += 1;
    });
  }
  if (report) add(newStep("telegram", { text: "{if status == \"a step failed\"}❌{else}✅{end} {workflow}: {status}\n{steps}", silent: true }), 0);
  if (after) g.edges.push({ from: prev, to: after.to, kind: "ok" });
  wfb.panel = "node";
  wfb.template = null;
  wfb.sel = null;
  wfFit(document.getElementById("wfb-canvas"), g, wfb.view);
  wfDirtyRender();
}

async function saveWorkflow() {
  const d = wfb.draft;
  const body = { name: document.getElementById("wf-name").value.trim(), description: document.getElementById("wf-description").value.trim(),
    is_active: d.is_active, graph: d.graph };
  const err = document.getElementById("wf-error");
  try {
    if (d.id) await api(`/api/workflows/${Number(d.id)}`, { method: "PUT", body });
    else await api("/api/workflows", { method: "POST", body });
    hide(document.getElementById("modal-workflow"));
    showToast(`Saved ${body.name}`, "success");
    wfb = null;
    loadWorkflows();
  } catch (e) {
    err.textContent = `Not saved: ${e.message}`;
    err.classList.remove("hidden");
  }
}

function wfWorldPoint(ev) {
  const r = document.getElementById("wfb-canvas").getBoundingClientRect();
  return [(ev.clientX - r.left - wfb.view.x) / wfb.view.k, (ev.clientY - r.top - wfb.view.y) / wfb.view.k];
}

function wfZoom(factor, cx, cy) {
  const v = wfb.view;
  const k = Math.max(0.3, Math.min(2, v.k * factor));
  v.x = cx - (cx - v.x) * (k / v.k);
  v.y = cy - (cy - v.y) * (k / v.k);
  v.k = k;
  wfRender();
}

/** Pointer capture keeps a drag going outside the element; it throws for a pointer that is no longer down. */
function wfCapture(el, ev) {
  try { el.setPointerCapture(ev.pointerId); } catch (err) { /* drag still works while the pointer stays over el */ }
}

function initWorkflowCanvas() {
  const canvas = document.getElementById("wfb-canvas");
  let drag = null;
  canvas.addEventListener("pointerdown", (ev) => {
    if (!wfb || ev.button > 0 || ev.target.closest(".wfb-zoom")) return;
    const port = ev.target.closest("[data-port-out]");
    const nodeEl = ev.target.closest(".wfb-node");
    const edgeEl = ev.target.closest("[data-edge]");
    if (port) {
      drag = { mode: "link", from: port.dataset.portOut, kind: port.dataset.kind };
    } else if (nodeEl) {
      const n = wfNode(nodeEl.dataset.node);
      const [px, py] = wfWorldPoint(ev);
      drag = { mode: "node", id: n.id, dx: px - n.x, dy: py - n.y, moved: false };
      if (!(wfb.sel && wfb.sel.kind === "node" && wfb.sel.id === n.id)) {
        wfb.sel = { kind: "node", id: n.id };
        wfb.panel = "node";
        wfRender();
        wfRenderPanel();
      }
    } else if (edgeEl) {
      wfb.sel = { kind: "edge", i: Number(edgeEl.dataset.edge) };
      wfb.panel = "node";
      wfRender();
      wfRenderPanel();
      return;
    } else {
      drag = { mode: "pan", sx: ev.clientX, sy: ev.clientY, vx: wfb.view.x, vy: wfb.view.y, moved: false };
    }
    wfCapture(canvas, ev);
    ev.preventDefault();
  });
  canvas.addEventListener("pointermove", (ev) => {
    if (!drag || !wfb) return;
    if (drag.mode === "pan") {
      wfb.view.x = drag.vx + ev.clientX - drag.sx;
      wfb.view.y = drag.vy + ev.clientY - drag.sy;
      drag.moved = drag.moved || Math.abs(ev.clientX - drag.sx) + Math.abs(ev.clientY - drag.sy) > 3;
      wfEnsureWorld(canvas).style.transform = `translate(${wfb.view.x}px, ${wfb.view.y}px) scale(${wfb.view.k})`;
    } else if (drag.mode === "node") {
      const [px, py] = wfWorldPoint(ev);
      const n = wfNode(drag.id);
      n.x = Math.round((px - drag.dx) / 10) * 10;
      n.y = Math.round((py - drag.dy) / 10) * 10;
      drag.moved = true;
      const el = canvas.querySelector(`.wfb-node[data-node="${CSS.escape(n.id)}"]`);
      el.style.left = `${n.x}px`;
      el.style.top = `${n.y}px`;
      wfDrawEdges(wfEnsureWorld(canvas), wfb.draft.graph, { sel: wfb.sel });
    } else if (drag.mode === "link") {
      const a = wfNode(drag.from);
      const [x1, y1] = wfPortPos(a, drag.kind);
      const [x2, y2] = wfWorldPoint(ev);
      wfDrawEdges(wfEnsureWorld(canvas), wfb.draft.graph, { sel: wfb.sel, tempEdge: { kind: drag.kind, d: wfCurve(x1, y1, x2, y2) } });
    }
  });
  const end = (ev) => {
    if (!drag || !wfb) return;
    const d = drag;
    drag = null;
    if (d.mode === "link") {
      const over = document.elementFromPoint(ev.clientX, ev.clientY);
      const target = over && over.closest(".wfb-node");
      if (target && target.dataset.node !== d.from) wfConnect(d.from, target.dataset.node, d.kind);
      else wfRender();
    } else if (d.mode === "pan" && !d.moved && wfb.sel) {
      wfb.sel = null;
      wfb.panel = "node";
      wfRender();
      wfRenderPanel();
    }
  };
  canvas.addEventListener("pointerup", end);
  canvas.addEventListener("pointercancel", end);
  canvas.addEventListener("wheel", (ev) => {
    if (!wfb) return;
    ev.preventDefault();
    const r = canvas.getBoundingClientRect();
    wfZoom(ev.deltaY < 0 ? 1.1 : 1 / 1.1, ev.clientX - r.left, ev.clientY - r.top);
  }, { passive: false });
  document.getElementById("wfb-zoom").addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-zoom]");
    if (!b || !wfb) return;
    const r = canvas.getBoundingClientRect();
    if (b.dataset.zoom === "in") wfZoom(1.2, r.width / 2, r.height / 2);
    else if (b.dataset.zoom === "out") wfZoom(1 / 1.2, r.width / 2, r.height / 2);
    else if (b.dataset.zoom === "fit") { wfFit(canvas, wfb.draft.graph, wfb.view); wfRender(); }
    else if (b.dataset.zoom === "arrange") { wfArrange(wfb.draft.graph); wfFit(canvas, wfb.draft.graph, wfb.view); wfDirtyRender(false); }
  });

  // Palette: drag onto the canvas to place a step, or click to add it after the selected step.
  const palette = document.getElementById("wfb-palette");
  palette.innerHTML = `<div class="seg wfb-pal-tabs" role="tablist" aria-label="Add">
      <button type="button" class="btn" role="tab" data-pal-tab="steps">Steps</button><button type="button" class="btn" role="tab" data-pal-tab="templates">Templates</button></div>
    <div data-pal-steps class="wfb-pal-list">${WF_FAMILIES.map(([fam, label]) => `<div class="wfb-pal-group">${escapeHtml(label)}</div>` +
      WF_PALETTE.map((p, i) => p.fam !== fam ? "" : `
      <div class="wfb-pal-item wfb-t-${escapeHtml(p.type)}"${p.type === "command" ? ' data-perm="credentials.use"' : p.type === "pve_snapshot" ? " data-unscoped" : ""} data-pal="${i}" title="Drag onto the canvas, or click to add after the selected step">
        <span class="wfb-badge">${WF_KIND[p.type].badge}</span><span><strong>${escapeHtml(p.title)}</strong><span class="dim">${escapeHtml(p.help)}</span></span>
      </div>`).join("")).join("")}</div>
    <div data-pal-tpls class="wfb-pal-list hidden"><div class="form-help">Ready-made steps for one or more hosts. Pick one, then choose its hosts on the right.</div>
      ${WF_FLOW_TEMPLATES.map(x => `<button type="button" class="wfb-tpl" data-tpl="${escapeHtml(x.id)}">
        <strong>${escapeHtml(x.name)}</strong><span class="dim">${escapeHtml(x.help)}</span></button>`).join("")}</div>`;
  wfSyncPalette();
  let pal = null;
  palette.addEventListener("pointerdown", (ev) => {
    const item = ev.target.closest("[data-pal]");
    if (!item || !wfb) return;
    pal = { spec: WF_PALETTE[Number(item.dataset.pal)], sx: ev.clientX, sy: ev.clientY, ghost: null };
    wfCapture(palette, ev);
    ev.preventDefault();
  });
  palette.addEventListener("pointermove", (ev) => {
    if (!pal) return;
    if (!pal.ghost && Math.abs(ev.clientX - pal.sx) + Math.abs(ev.clientY - pal.sy) > 5) {
      pal.ghost = document.createElement("div");
      pal.ghost.className = `wfb-node wfb-ghost wfb-t-${pal.spec.type}`;
      pal.ghost.innerHTML = `<div class="wfb-node-head"><span class="wfb-badge">${WF_KIND[pal.spec.type].badge}</span><span class="wfb-node-title">${escapeHtml(pal.spec.title)}</span></div>`;
      document.body.appendChild(pal.ghost);
    }
    if (pal.ghost) {
      pal.ghost.style.left = `${ev.clientX - 30}px`;
      pal.ghost.style.top = `${ev.clientY - 20}px`;
    }
  });
  palette.addEventListener("pointerup", (ev) => {
    if (!pal) return;
    const p = pal;
    pal = null;
    const extra = p.spec.state ? { state: p.spec.state } : {};
    if (!p.ghost) { wfAddAfter(newStep(p.spec.type, extra)); return; }
    p.ghost.remove();
    const r = canvas.getBoundingClientRect();
    if (ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom) return;
    const step = newStep(p.spec.type, extra);
    const [px, py] = wfWorldPoint(ev);
    step.x = Math.round((px - 30) / 10) * 10;
    step.y = Math.round((py - 20) / 10) * 10;
    wfb.draft.graph.nodes.push(step);
    // Dropped steps connect to the end of the success path when that is free, as in most editors.
    const end = wfChainEnd();
    if (end !== step.id && !wfb.draft.graph.edges.some(e => e.from === end && e.kind === "ok")) wfb.draft.graph.edges.push({ from: end, to: step.id, kind: "ok" });
    wfb.sel = { kind: "node", id: step.id };
    wfb.panel = "node";
    wfDirtyRender();
  });

  // Side panel fields edit the selected node.
  const panel = document.getElementById("wfb-panel");
  const onField = (ev) => {
    if (!wfb) return;
    const el = ev.target;
    const n = wfb.sel && wfb.sel.kind === "node" ? wfNode(wfb.sel.id) : null;
    if (el.matches("[data-wf-active]")) { wfb.draft.is_active = el.checked; return; }
    if (!n) return;
    if (el.dataset.ev !== undefined) {
      const s = { ...(n.schedule || {}), when: { ...((n.schedule || {}).when || {}) } };
      const k = el.dataset.ev;
      const v = el.dataset.num ? (el.value === "" ? null : parseInt(el.value, 10)) : el.dataset.float ? (el.value === "" ? null : Number(el.value)) : el.value;
      if (k === "type") {
        s.when = { type: v, device_id: s.when.device_id, ...(v === "metric" ? { op: "above", for_minutes: 5 } : {}),
          ...(v === "offline" || v === "snmp_down" ? { for_minutes: 5 } : {}), ...(v === "problem" ? { min_severity: "warning", rule: "" } : {}) };
      } else s.when[k] = v;
      n.schedule = s;
      wfRender();
      if (ev.type === "change") wfRenderPanel();
      else panel.querySelector(".wfb-summary").textContent = wfScheduleText(s);
      return;
    }
    if (el.dataset.s !== undefined || el.dataset.wd !== undefined) {
      let s = { ...(n.schedule || { kind: "manual" }) };
      delete s.done;
      if (el.dataset.s === "kind") s = wfScheduleDefaults(el.value, s);
      else if (el.dataset.wd !== undefined) {
        const d = Number(el.dataset.wd);
        s.weekdays = el.checked ? [...new Set([...(s.weekdays || []), d])] : (s.weekdays || []).filter(x => x !== d);
      } else if (el.dataset.s === "unit") { s.unit = el.value; s.every = (el.value === "hours" ? WF_HOUR_STEPS : WF_MINUTE_STEPS)[0]; }
      else s[el.dataset.s] = el.dataset.num ? parseInt(el.value, 10) : el.value;
      n.schedule = s;
      wfRender();
      if (ev.type === "change") wfRenderPanel();
      else panel.querySelector(".wfb-summary").textContent = wfScheduleText(s);
      return;
    }
    const f = el.dataset.f;
    if (!f) return;
    if (el.type === "checkbox") n[f] = el.checked;
    else if (el.type === "number" || el.dataset.num) n[f] = el.value === "" ? null : parseInt(el.value, 10);
    else n[f] = el.value;
    wfRender();
    if (ev.type === "change" && ["any_exit", "device_id", "state", "credential_id", "scope", "until_end"].includes(f)) wfRenderPanel();
  };
  panel.addEventListener("input", onField);
  panel.addEventListener("change", async (ev) => {
    const n = wfb && wfb.sel && wfb.sel.kind === "node" ? wfNode(wfb.sel.id) : null;
    if (ev.target.matches("[data-pve-guest]") && n) {
      const [node, type, vmid, ...name] = ev.target.value.split("|");
      Object.assign(n, { node: node || "", guest_type: type || "", vmid: vmid ? Number(vmid) : null, guest_name: name.join("|") });
      wfDirtyRender();
      return;
    }
    if (ev.target.matches("[data-host-add]") && n && ev.target.value) {
      const id = parseInt(ev.target.value, 10);
      if (!n.device_ids.includes(id)) n.device_ids.push(id);
      wfDirtyRender();
      return;
    }
    if (ev.target.matches("[data-template]") && n && ev.target.value) {
      const t = WF_COMMAND_TEMPLATES.find(x => x.id === ev.target.value);
      ev.target.value = "";
      if (n.command && n.command !== t.command && !(await confirmDialog({ title: "Replace the command?", message: `Replace the current command with "${t.name}"?`, confirmLabel: "Replace" }))) return;
      Object.assign(n, { command: t.command, timeout_s: t.timeout_s || n.timeout_s, any_exit: !!t.any_exit, expect_disconnect: !!t.expect_disconnect });
      if (!n.label) n.label = t.name.split(": ").pop().replace(/^./, c => c.toUpperCase());
      wfDirtyRender();
      return;
    }
    onField(ev);
  });
  panel.addEventListener("click", (ev) => {
    const b = ev.target.closest("button");
    if (!b || !wfb) return;
    const n = wfb.sel && wfb.sel.kind === "node" ? wfNode(wfb.sel.id) : null;
    if (b.dataset.panel) { wfb.panel = b.dataset.panel; wfb.template = null; wfRenderPanel(); }
    else if (b.dataset.select) { wfb.sel = { kind: "node", id: b.dataset.select }; wfb.panel = "node"; wfDirtyRender(); }
    else if (b.dataset.tpl) { wfb.template = b.dataset.tpl; wfRenderPanel(); }
    else if (b.matches("[data-tpl-back]")) { wfb.template = null; wfb.panel = "node"; wfRenderPanel(); }
    else if (b.matches("[data-tpl-add]")) wfAddTemplate();
    else if (b.matches("[data-delete-sel]")) wfDeleteSelection();
    else if (n && b.matches("[data-tg-edit]")) {
      openTemplateEditor({ title: "Telegram message", value: n.text || "", placeholders: WF_STEP_PLACEHOLDERS, max: 1000,
        sample: { workflow: "Update Linux hosts", trigger: "manual", status: "all steps so far succeeded", steps: "✅ Update packages on media-server", time: "2026-11-01 09:30" },
        onSave: (text) => { n.text = text; wfDirtyRender(); } });
    } else if (n && b.matches("[data-test-login]")) {
      const out = document.getElementById("wfb-test-result");
      testCredential(n.credential_id, n.device_ids[0], n.ssh_port, out);
    }
    else if (n && (b.dataset.hostUp || b.dataset.hostDel)) {
      const k = Number(b.dataset.hostUp || b.dataset.hostDel);
      if (b.dataset.hostUp && k > 0) [n.device_ids[k - 1], n.device_ids[k]] = [n.device_ids[k], n.device_ids[k - 1]];
      if (b.dataset.hostDel) n.device_ids.splice(k, 1);
      wfDirtyRender();
    }
  });
  palette.addEventListener("click", (ev) => {
    const tab = ev.target.closest("[data-pal-tab]");
    if (tab) {
      wfPalTab = tab.dataset.palTab;
      if (wfb && wfPalTab === "steps" && wfb.panel === "templates") { wfb.panel = "node"; wfb.template = null; wfRenderPanel(); }
      wfSyncPalette();
      return;
    }
    const tpl = ev.target.closest("[data-tpl]");
    if (tpl && wfb) { wfb.panel = "templates"; wfb.template = tpl.dataset.tpl; wfRenderPanel(); }
  });
  document.addEventListener("keydown", (ev) => {
    if (!wfb || document.getElementById("modal-workflow").classList.contains("hidden")) return;
    if ((ev.target.closest && ev.target.closest("input, textarea, select")) || document.querySelector(".dialog-backdrop")) return;
    if (ev.key === "Delete" || ev.key === "Backspace") { ev.preventDefault(); wfDeleteSelection(); }
    else if (ev.key === "Escape" && wfb.sel) { ev.stopPropagation(); wfb.sel = null; wfRender(); wfRenderPanel(); }
  });
}

// --- Run viewer ---

async function openRun(runId) {
  clearInterval(wfRunTimer);
  const modal = document.getElementById("modal-wf-run");
  const host = document.getElementById("wf-run-graph");
  const view = { x: 0, y: 0, k: 1 };
  let fitted = false;
  const draw = async () => {
    let run;
    try {
      run = await api(`/api/workflow-runs/${Number(runId)}`);
    } catch (err) {
      clearInterval(wfRunTimer);
      return;
    }
    document.getElementById("wf-run-title").textContent = `${run.name}`;
    document.getElementById("wf-run-status").innerHTML = `${wfPill(run.status)} <span class="dim">started ${escapeHtml(formatTime(run.started_at))}, ${escapeHtml(run.trigger)}</span>`;
    const cancel = document.getElementById("btn-wf-cancel");
    cancel.classList.toggle("hidden", run.status !== "running");
    cancel.dataset.run = run.id;
    const wf = wfList && wfList.workflows.find(w => w.id === run.workflow_id);
    // Only runs logged by the graph engine name their node; older runs show the log alone.
    const status = {};
    run.log.forEach(e => {
      if (!e.node) return;
      if (e.status === "running") status[e.node] = "running";
      else if (e.status === "ok") { if (status[e.node] !== "failed") status[e.node] = "ok"; }
      else status[e.node] = "failed";
    });
    const graphOk = wf && run.log.some(e => e.node);
    host.classList.toggle("hidden", !graphOk);
    if (graphOk) {
      if (!fitted) { wfFit(host, wf.graph, view); fitted = true; }
      wfDraw(host, wf.graph, { view, status, readonly: true });
    }
    document.getElementById("wf-run-log").innerHTML = run.log.map(e => `
      <div class="wf-log-entry status-${escapeHtml(e.status)}" data-log-node="${escapeHtml(e.node || "")}">
        <div><span class="status-pill ${e.status === "ok" ? "status-ok" : e.status === "running" ? "status-unknown" : "status-err"}">${escapeHtml(e.status)}</span>
          <strong>${e.step ? Number(e.step) + ". " : ""}${escapeHtml(e.title)}</strong>${e.host ? ` <span class="dim">on ${escapeHtml(e.host)}</span>` : ""}
          <span class="dim">${e.finished ? `${Math.round(e.finished - e.started)} s` : "..."}</span></div>
        ${e.detail ? `<pre class="wf-log-detail">${escapeHtml(e.detail)}</pre>` : ""}
      </div>`).join("") || `<div class="dim">Starting...</div>`;
    if (run.status !== "running") {
      clearInterval(wfRunTimer);
      loadWorkflows();
    }
  };
  show(modal);
  await draw();
  wfRunTimer = setInterval(draw, 2000);
}

/** Missing host keys for a workflow's command steps: offers the approval dialog instead of a run that fails. */
function wfMissingKeys(w) {
  const cmd = w.steps.filter(s => s.type === "command");
  const ids = [...new Set(cmd.flatMap(s => s.device_ids))];
  return { ids, missing: ids.filter(id => !(wfHosts().find(d => d.id === id) || {}).host_key), port: cmd.length ? cmd[0].ssh_port : 22 };
}

function initWorkflows() {
  initWorkflowCanvas();
  document.getElementById("btn-add-workflow").addEventListener("click", () => openWorkflowModal(null));
  document.getElementById("btn-close-workflow").addEventListener("click", closeWorkflowModal);
  document.getElementById("btn-cancel-workflow").addEventListener("click", closeWorkflowModal);
  document.getElementById("btn-save-workflow").addEventListener("click", saveWorkflow);

  document.getElementById("workflows-body").addEventListener("click", async (ev) => {
    const b = ev.target.closest("button");
    if (!b) return;
    if (b.dataset.wfEdit) openWorkflowModal(wfList.workflows.find(w => w.id === +b.dataset.wfEdit));
    else if (b.dataset.wfKeys) {
      const k = wfMissingKeys(wfList.workflows.find(x => x.id === +b.dataset.wfKeys));
      openHostKeys({ device_ids: k.ids, ssh_port: k.port });
    }
    else if (b.dataset.wfOpen) openRun(+b.dataset.wfOpen);
    else if (b.dataset.wfDelete) {
      const w = wfList.workflows.find(x => x.id === +b.dataset.wfDelete);
      if (!(await confirmDialog({ title: "Delete workflow?", message: `Delete ${w.name} and its run history? This cannot be undone.`, confirmLabel: "Delete", danger: true }))) return;
      try { await api(`/api/workflows/${w.id}`, { method: "DELETE" }); loadWorkflows(); } catch (err) { showToast(err.message, "error"); }
    } else if (b.dataset.wfStart) {
      const w = wfList.workflows.find(x => x.id === +b.dataset.wfStart);
      const k = wfMissingKeys(w);
      if (k.missing.length) {
        const names = wfNames();
        if (!can("credentials.manage")) {
          showToast(`${w.name} connects over SSH to ${k.missing.map(id => names[id] || id).join(", ")}, whose host key is not approved yet. Someone with the Manage credentials permission needs to approve it.`, "error");
          return;
        }
        if (await confirmDialog({ title: "Host keys not approved", message: `${w.name} connects over SSH to ${k.missing.map(id => names[id] || id).join(", ")}, whose host key is not approved yet. Review and approve it first.`, confirmLabel: "Review host keys" })) {
          openHostKeys({ device_ids: k.missing, ssh_port: k.port });
        }
        return;
      }
      if (!(await confirmDialog({ title: "Run workflow now?", message: `${w.name} runs ${w.steps.length} step${w.steps.length === 1 ? "" : "s"} against real devices.`, confirmLabel: "Run now" }))) return;
      try {
        const res = await api(`/api/workflows/${w.id}/run`, { method: "POST" });
        loadWorkflows();
        openRun(res.run_id);
      } catch (err) {
        showToast(`Could not start: ${err.message}`, "error");
      }
    }
  });
  document.getElementById("wf-runs-body").addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-wf-run]");
    if (row) openRun(+row.dataset.wfRun);
  });
  document.getElementById("wf-run-graph").addEventListener("click", (ev) => {
    const n = ev.target.closest(".wfb-node");
    const entry = n && document.querySelector(`#wf-run-log [data-log-node="${CSS.escape(n.dataset.node)}"]`);
    if (entry) entry.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });
  document.getElementById("btn-close-wf-run").addEventListener("click", () => {
    clearInterval(wfRunTimer);
    hide(document.getElementById("modal-wf-run"));
  });
  document.getElementById("btn-wf-cancel").addEventListener("click", async (ev) => {
    if (!(await confirmDialog({ title: "Cancel this run?", message: "The current step is interrupted. A command already sent cannot be undone.", confirmLabel: "Cancel run", cancelLabel: "Keep running", danger: true }))) return;
    try { await api(`/api/workflow-runs/${Number(ev.target.dataset.run)}/cancel`, { method: "POST" }); } catch (err) { showToast(err.message, "error"); }
  });
}
