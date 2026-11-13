/**
 * Homelab Monitor & Automation - Air-gapped Client Application
 * Hash-based single-page routing, zero external dependencies.
 *
 * The server sends a strict Content-Security-Policy, so this file must not use
 * inline event handler attributes or inline style attributes. All handlers are
 * bound with addEventListener, dynamic sizes (bars, tooltips) are set through
 * the CSSOM, and every server-supplied string rendered via innerHTML passes
 * through escapeHtml.
 */

let cachedSettings = {};
let activeDeviceId = null;
let activeTab = "overview";
let probeVerified = false;
let graphHours = 24;
let lastDetail = null;
let lastGraphRender = 0;
let deviceFilter = null;
// Group and tag filters of the Devices page (taxonomy.js); empty shows all.
let devicesFilter = { group: "", tag: "" };
const expandedPorts = new Set();
let setupCompleted = null;
let justCreatedAdmin = false;   // set when the first account is created in this page: setup follows
const collapsedGroups = new Set();

document.addEventListener("DOMContentLoaded", () => {
  window.addEventListener("hashchange", () => routeGuarded());
  initSorting();
  initDeviceTable();
  initDetailPage();
  initModals();
  initSettingsAndAudit();
  initEventLog();
  initAuditLog();
  initDashboard();
  initLive();
  initCredentials();
  initHostKeys();
  initAuth();
  initMap();
  initWorkflows();
  initAlertRules();
  initSetup();
  ensureSession()
    .then(() => Promise.all([loadSettingValues(), loadProfiles(), refreshSetupNav()]))
    .then(([, , st]) => {
      // A fresh install opens setup instead of the dashboard until it has been completed once.
      // The address may still carry #/dashboard from an earlier visit to the same address
      // (browser autocomplete), so only another page chosen on purpose is left alone.
      setupCompleted = st ? st.completed : true;
      if (!setupCompleted && (justCreatedAdmin || ["", "#", "#/", "#/dashboard"].includes(window.location.hash))) {
        history.replaceState(null, "", "#/setup");
      }
      justCreatedAdmin = false;
      handleRouting();
    });

  // Background refresh every 15s without resetting the current view.
  setInterval(() => {
    const hash = window.location.hash || "#/dashboard";
    if (hash === "#/dashboard" || hash === "#/") { if (!dashEditing) refreshDashboard(); }
    else if (hash === "#/devices") loadDevices();
    else if (hash.startsWith("#/events") && eventsPage === 1) loadEvents();
    else if (hash.startsWith("#/device/") && activeDeviceId) loadDeviceDetail(activeDeviceId, true);
  }, 15000);
});

// --- Helpers ---

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }
const isNum = v => typeof v === "number" && isFinite(v);

/** fetch wrapper: JSON in and out, throws Error(message) on non-2xx or network failure. */
// --- Login session ---

let authPending = null;     // one login prompt shared by every request that hit 401
let confirmPending = null;  // one password confirmation shared by concurrent 403s
let setupTokenRequired = false;
let httpsLost = false;      // HTTPS failed and this is another computer: the server refuses logins

async function ensureSession() {
  const status = await fetch("/api/auth/status").then(r => r.json()).catch(() => ({ authenticated: false, configured: true }));
  if (status.authenticated) {
    setSignedIn(status.username, status.user);
    return;
  }
  setupTokenRequired = !!status.setup_token_required;
  loginRecovery = !!status.recovery;
  httpsLost = !!status.https_lost;
  await promptLogin(status.configured ? "login" : "setup");
}

function setSignedIn(username, user) {
  // The app is drawn only once a session exists: until then the page holds the login screen and nothing else.
  document.documentElement.dataset.auth = "in";
  document.getElementById("header-username").textContent = username || "";
  document.getElementById("password-username").value = username || "";
  document.getElementById("confirm-username").value = username || "";
  show(document.getElementById("header-user"));
  if (user) applyCurrentUser(user);
  else api("/api/auth/status").then(s => s.user && applyCurrentUser(s.user)).catch(() => {});
}

function promptLogin(mode) {
  if (authPending) return authPending;
  authPending = new Promise(resolve => {
    const screen = document.getElementById("auth-screen");
    const setup = mode === "setup";
    document.getElementById("auth-title").textContent = setup ? "Create the administrator account" : "Log in";
    document.getElementById("auth-submit").textContent = setup ? "Create account" : "Log in";
    document.getElementById("auth-setup-help").classList.toggle("hidden", !setup);
    document.getElementById("auth-confirm-group").classList.toggle("hidden", !setup);
    document.getElementById("auth-token-group").classList.toggle("hidden", !(setup && setupTokenRequired));
    document.getElementById("auth-password").autocomplete = setup ? "new-password" : "current-password";
    setLoginStep(null);
    document.getElementById("auth-forgot").classList.toggle("hidden", setup || !loginRecovery || httpsLost);
    // HTTPS lost: no form at all, so no password is typed into a page that would send it unprotected.
    if (httpsLost) {
      document.getElementById("auth-title").textContent = "HTTPS is not working";
      ["auth-setup-help", "auth-fields", "auth-submit"].forEach(id => hide(document.getElementById(id)));
    } else {
      show(document.getElementById("auth-submit"));
    }
    document.getElementById("auth-https-lost").classList.toggle("hidden", !httpsLost);
    hide(document.getElementById("auth-error"));
    screen.dataset.mode = mode;
    screen._resolve = resolve;
    document.documentElement.dataset.auth = "out";
    show(screen);
    document.getElementById(document.getElementById("auth-username").value ? "auth-password" : "auth-username").focus();
  }).finally(() => { authPending = null; });
  return authPending;
}

/** Login screen state: null = username and password; a challenge = waiting for the authenticator code. */
let loginChallenge = null;
let loginRecovery = false;
function setLoginStep(challenge) {
  loginChallenge = challenge;
  document.getElementById("auth-fields").classList.toggle("hidden", !!challenge);
  document.getElementById("auth-code-group").classList.toggle("hidden", !challenge);
  document.getElementById("auth-code").value = "";
  document.getElementById("auth-submit").textContent = challenge ? "Verify" : (document.getElementById("auth-screen").dataset.mode === "setup" ? "Create account" : "Log in");
  if (challenge) document.getElementById("auth-code").focus();
}

/**
 * Step-up: tier 2 asks for the password, tier 3 for the password and, with 2FA on, the code.
 * info is the server's 403 reply ({tier, mfa, suggest_2fa}). Resolves true once confirmed.
 */
let confirmTier = 2;
function promptConfirm(info = {}) {
  if (confirmPending) return confirmPending;
  confirmPending = new Promise(resolve => {
    const modal = document.getElementById("modal-confirm-password");
    modal._resolve = resolve;
    confirmTier = info.tier || 2;
    const mfa = !!info.mfa;
    document.getElementById("confirm-title").textContent = confirmTier >= 3 ? "Confirm with your password and code" : "Confirm your password";
    document.getElementById("confirm-help").textContent = confirmTier >= 3
      ? `This changes credentials, users or what is trusted. It stays confirmed for 15 minutes.`
      : `This can lose data or acts on devices. It stays confirmed for 10 minutes.`;
    document.getElementById("confirm-code-group").classList.toggle("hidden", !mfa);
    document.getElementById("confirm-suggest").classList.toggle("hidden", !info.suggest_2fa);
    document.getElementById("confirm-password").value = "";
    document.getElementById("confirm-code").value = "";
    hide(document.getElementById("confirm-error"));
    show(modal);
    document.getElementById("confirm-password").focus();
  }).finally(() => { confirmPending = null; });
  return confirmPending;
}

function initAuth() {
  document.getElementById("auth-min").textContent = "12";
  document.getElementById("auth-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const screen = document.getElementById("auth-screen");
    const setup = screen.dataset.mode === "setup";
    if (setup) justCreatedAdmin = true;
    const username = document.getElementById("auth-username").value.trim();
    const password = document.getElementById("auth-password").value;
    const err = document.getElementById("auth-error");
    if (setup && password !== document.getElementById("auth-password2").value) {
      err.textContent = "The passwords do not match.";
      show(err);
      return;
    }
    const button = document.getElementById("auth-submit");
    button.disabled = true;
    try {
      const url = loginChallenge ? "/api/auth/login/mfa" : setup ? "/api/auth/setup" : "/api/auth/login";
      const body = loginChallenge ? { challenge: loginChallenge, code: document.getElementById("auth-code").value.trim() }
        : setup ? { username, password, setup_token: document.getElementById("auth-token").value.trim() } : { username, password };
      const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        // An expired code step goes back to the password.
        if (loginChallenge && /expired/.test(data.error || "")) setLoginStep(null);
        throw new Error(data.error || `Request failed (HTTP ${res.status})`);
      }
      if (data.mfa_required) {
        hide(err);
        setLoginStep(data.challenge);
        return;
      }
      setLoginStep(null);
      document.getElementById("auth-password").value = "";
      document.getElementById("auth-password2").value = "";
      hide(screen);
      setSignedIn(data.username);
      if (screen._resolve) screen._resolve();
    } catch (e) {
      err.textContent = e.message;
      show(err);
    } finally {
      button.disabled = false;
    }
  });

  const confirmModal = document.getElementById("modal-confirm-password");
  const closeConfirm = (ok) => { hide(confirmModal); if (confirmModal._resolve) confirmModal._resolve(ok); confirmModal._resolve = null; };
  document.getElementById("btn-close-confirm").addEventListener("click", () => closeConfirm(false));
  document.getElementById("btn-cancel-confirm").addEventListener("click", () => closeConfirm(false));
  document.getElementById("confirm-password-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = document.getElementById("confirm-error");
    try {
      await api("/api/auth/confirm", { method: "POST", body: { password: document.getElementById("confirm-password").value,
        tier: confirmTier, code: document.getElementById("confirm-code").value.trim() } });
      document.getElementById("confirm-password").value = "";
      document.getElementById("confirm-code").value = "";
      closeConfirm(true);
    } catch (e) {
      err.textContent = e.message;
      show(err);
    }
  });

  document.getElementById("btn-logout").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch (e) { /* session already gone */ }
    hide(document.getElementById("header-user"));
    await promptLogin("login");
    handleRouting();
  });

  document.getElementById("password-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const current = document.getElementById("password-current");
    const next = document.getElementById("password-new");
    const next2 = document.getElementById("password-new2");
    if (next.value !== next2.value) {
      showToast("The new passwords do not match", "error");
      return;
    }
    try {
      await api("/api/auth/password", { method: "POST", body: { current: current.value, new: next.value } });
      current.value = next.value = next2.value = "";
      showToast("Password changed. Other browsers were logged out.", "success");
    } catch (e) {
      showToast(`Could not change password: ${e.message}`, "error");
    }
  });
}

async function api(path, options = {}, retried = false) {
  const opts = { method: options.method || "GET", headers: {} };
  if (options.body !== undefined || opts.method === "POST" || opts.method === "PUT") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(options.body ?? {});
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (err) {
    throw new Error("Cannot reach the local server");
  }
  let data = {};
  try {
    data = await res.json();
  } catch (err) {
    data = {};
  }
  if (!retried && res.status === 401 && (data.auth === "login" || data.auth === "setup")) {
    await promptLogin(data.auth);
    return api(path, options, true);
  }
  if (!retried && res.status === 403 && data.auth === "enrol") {
    await promptEnrol();
    return api(path, options, true);
  }
  if (!retried && res.status === 403 && data.auth === "confirm") {
    if (!(await promptConfirm(data))) throw new Error("Cancelled: not confirmed");
    return api(path, options, true);
  }
  // An action that could not be done is recorded on the server as an event; show it in the bell straight away.
  if (opts.method !== "GET" && typeof refreshBell === "function") setTimeout(refreshBell, 400);
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (HTTP ${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function formatDuration(totalSec) {
  totalSec = Math.floor(totalSec);
  const days = Math.floor(totalSec / 86400);
  const hours = Math.floor((totalSec % 86400) / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m ${totalSec % 60}s`;
}

function formatBytes(bytes) {
  if (!isNum(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let v = Math.abs(bytes);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${bytes < 0 ? "-" : ""}${v.toFixed(i === 0 ? 0 : v < 10 ? 2 : 1)} ${units[i]}`;
}

function formatKb(kb) { return formatBytes(kb * 1024); }

function formatBps(bps) {
  if (!isNum(bps)) return "-";
  const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let i = 0;
  let v = bps;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(i === 0 ? 0 : v < 10 ? 2 : 1)} ${units[i]}`;
}

function formatSpeed(mbps) {
  if (!isNum(mbps) || !mbps) return "-";
  return mbps >= 1000 ? `${mbps / 1000} Gbps` : `${Number(mbps)} Mbps`;
}

function formatAgo(ts) {
  if (!ts) return "Never";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

const pct = v => (isNum(v) ? `${v.toFixed(0)} %` : "-");

/** Value label beside a thin track, so the text never overlaps the fill. */
/** A meter with no reading: "-" where the value goes and an empty track, so the column stays aligned. */
function emptyMeter() {
  return `<div class="meter meter-empty"><span class="meter-val">-</span><span class="meter-track"></span></div>`;
}

function barHtml(percent, text, lowIsBad = false) {
  if (!isNum(percent)) return emptyMeter();
  const p = Math.max(0, Math.min(100, percent));
  // Fullness is bad for disks; emptiness is bad for supplies such as toner.
  const level = lowIsBad ? 100 - p : p;
  const cls = level >= 90 ? "bad" : level >= 70 ? "warn" : "";
  return `<div class="meter"><span class="meter-val">${escapeHtml(text ?? p.toFixed(0) + "%")}</span>` +
    `<span class="meter-track"><span class="meter-fill ${cls}" data-bar="${p.toFixed(1)}"></span></span></div>`;
}

const FMT = {
  ms: v => `${v.toFixed(1)} ms`,
  pct: v => `${v.toFixed(0)} %`,
  bps: v => formatBps(v),
  kb: v => formatKb(v),
  int: v => v.toFixed(0),
  dec2: v => v.toFixed(2),
  degc: v => `${v.toFixed(0)} °C`,
  Bps: v => `${formatBytes(v)}/s`,
};

function formatSince(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

/** Inline style attributes are blocked by the CSP, so bar widths are applied through the CSSOM. */
function applyBars(root) {
  root.querySelectorAll("[data-bar]").forEach(el => { el.style.width = `${el.dataset.bar}%`; });
}

const SEVERITY_RANK = { critical: 0, high: 1, warning: 2, info: 3 };
/** Unacknowledged problems that are worth attention (info-level ones are notes, not problems). */
const isOpenProblem = p => p.severity !== "info" && !p.acknowledged_at;

function ackButton(p) {
  const acked = !!p.acknowledged_at;
  return `<button class="btn btn-ack" data-perm="problems.ack" data-ack-device="${Number(p.device_id)}" data-ack-key="${escapeHtml(p.problem_key)}" ` +
    `data-ack="${acked ? 0 : 1}" title="${acked ? "Count this problem again" : "Stop counting this problem until it resolves"}">${acked ? "Unacknowledge" : "Acknowledge"}</button>`;
}

function ackLabel(p) {
  if (!p.acknowledged_at) return "";
  return ` <span class="ack-tag">acknowledged ${escapeHtml(formatSince(p.acknowledged_at))} ago${p.ack_note ? ": " + escapeHtml(p.ack_note) : ""}</span>`;
}

function severityPill(sev) {
  return `<span class="status-pill sev-pill-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
}

// --- In-app dialogs (replace the browser's confirm and prompt) ---

/**
 * Modal confirmation. Resolves true on confirm, false on cancel, Escape or a backdrop click.
 * opts: title, message (text), detail (optional monospace text), confirmLabel, cancelLabel, danger,
 * input ({label, value, placeholder, multiline}) to collect a value (then resolves the string, or null).
 */
const DANGER_ARM_MS = 1200;

function dialog(opts) {
  return new Promise(resolve => {
    const back = document.createElement("div");
    back.className = "modal-backdrop dialog-backdrop";
    const box = document.createElement("form");
    box.className = "modal dialog";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    const input = opts.input;
    const field = !input ? "" : input.multiline
      ? `<textarea class="dialog-input" rows="3" placeholder="${escapeHtml(input.placeholder || "")}">${escapeHtml(input.value || "")}</textarea>`
      : `<input type="text" class="dialog-input" value="${escapeHtml(input.value || "")}" placeholder="${escapeHtml(input.placeholder || "")}">`;
    box.innerHTML = `
      <div class="modal-header"><span>${escapeHtml(opts.title || "Are you sure?")}</span></div>
      <div class="modal-body">
        ${opts.message ? `<div class="dialog-message">${escapeHtml(opts.message)}</div>` : ""}
        ${opts.detail ? `<pre class="dialog-detail">${escapeHtml(opts.detail)}</pre>` : ""}
        ${input ? `<div class="form-group">${input.label ? `<label>${escapeHtml(input.label)}</label>` : ""}${field}</div>` : ""}
      </div>
      <div class="modal-footer">
        ${opts.alert ? "" : `<button type="button" class="btn" data-dialog="cancel">${escapeHtml(opts.cancelLabel || "Cancel")}</button>`}
        <button type="submit" class="btn ${opts.danger ? "btn-danger-solid" : "btn-primary"}">${escapeHtml(opts.confirmLabel || "OK")}</button>
      </div>`;
    back.appendChild(box);
    document.body.appendChild(back);
    const before = document.activeElement;
    const done = ok => {
      document.removeEventListener("keydown", onKey, true);
      back.remove();
      if (before && before.focus) before.focus();
      const el = box.querySelector(".dialog-input");
      resolve(input ? (ok ? el.value : null) : ok);
    };
    const onKey = ev => {
      if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); done(false); }
    };
    document.addEventListener("keydown", onKey, true);
    box.addEventListener("submit", ev => { ev.preventDefault(); done(true); });
    box.querySelector("[data-dialog=cancel]")?.addEventListener("click", () => done(false));
    back.addEventListener("mousedown", ev => { if (ev.target === back) done(false); });
    // Destructive choices arm after a short delay (red sweeping in from the right), so a
    // stray double click or Enter cannot confirm them. Reduced motion: same wait, no sweep.
    const submit = box.querySelector("[type=submit]");
    if (opts.danger && opts.arm !== false) {
      submit.disabled = true;
      submit.classList.add("arming");
      const arm = () => { submit.disabled = false; submit.classList.remove("arming"); submit.classList.add("armed"); };
      setTimeout(arm, DANGER_ARM_MS);
    }
    (box.querySelector(".dialog-input") || (opts.danger ? box.querySelector("[data-dialog=cancel]") : submit) || submit).focus();
  });
}

function confirmDialog(opts) { return dialog(opts); }
function promptDialog(opts) { return dialog({ ...opts, input: opts.input || {} }); }
function alertDialog(opts) { return dialog({ ...opts, alert: true }); }

// --- Toasts ---

function showToast(message, kind = "info", durationMs = 4000) {
  const stack = document.getElementById("toast-stack");
  const toast = document.createElement("div");
  toast.className = `toast toast-${kind}`;
  toast.setAttribute("role", kind === "error" ? "alert" : "status");

  const msg = document.createElement("span");
  msg.className = "toast-msg";
  msg.textContent = message;

  const close = document.createElement("button");
  close.className = "toast-close";
  close.setAttribute("aria-label", "Dismiss");
  close.textContent = "×";

  toast.append(msg, close);
  stack.appendChild(toast);
  while (stack.children.length > 5) stack.firstElementChild.remove();

  const dismiss = () => {
    toast.classList.add("leaving");
    setTimeout(() => toast.remove(), 200);
  };
  close.addEventListener("click", dismiss);
  setTimeout(dismiss, kind === "error" ? durationMs * 2 : durationMs);
}

// --- Sortable Tables ---
//
// Any <table class="sortable"> with an id sorts by clicking a header. Cells may
// carry data-sort with a raw value; otherwise the text is used. Columns marked
// data-type="num" compare numerically and "ip" compares by octet. Empty values
// always sort last. Rows with class detail-row stay attached to the row above.
// The chosen column and direction persist per table across re-renders.

const SORT_STORE = "monitor.sort.v1";
let sortState = {};
try { sortState = JSON.parse(localStorage.getItem(SORT_STORE) || "{}"); } catch (err) { sortState = {}; }

function initSorting() {
  document.addEventListener("click", (ev) => {
    const th = ev.target.closest("table.sortable thead th");
    if (!th || th.classList.contains("no-sort")) return;
    const table = th.closest("table");
    const col = Array.from(th.parentNode.children).indexOf(th);
    const cur = sortState[table.id];
    const dir = cur && cur.col === col && cur.dir === "asc" ? "desc" : "asc";
    sortState[table.id] = { col, dir };
    try { localStorage.setItem(SORT_STORE, JSON.stringify(sortState)); } catch (err) { /* storage unavailable */ }
    applySort(table);
  });
}

function sortKey(cell, type) {
  if (!cell) return null;
  const raw = cell.dataset.sort !== undefined ? cell.dataset.sort : cell.textContent.trim();
  if (raw === "" || raw === "-") return null;
  if (type === "num") {
    const n = parseFloat(raw);
    return isNaN(n) ? null : n;
  }
  if (type === "ip") {
    const parts = raw.split(".").map(Number);
    return parts.length === 4 && parts.every(n => !isNaN(n)) ? parts.reduce((a, b) => a * 256 + b, 0) : null;
  }
  return raw.toLowerCase();
}

function applySort(table) {
  const headers = table.tHead.rows[0].cells;
  Array.from(headers).forEach(h => h.classList.remove("sort-asc", "sort-desc"));
  const st = sortState[table.id];
  if (!st || !headers[st.col]) return;
  headers[st.col].classList.add(st.dir === "asc" ? "sort-asc" : "sort-desc");
  const type = headers[st.col].dataset.type || "text";

  const tbody = table.tBodies[0];
  // Group heading rows (class group-row) split the body into sections that are
  // sorted independently, so headings stay above their own rows.
  const sections = [{ head: null, items: [] }];
  for (const row of Array.from(tbody.rows)) {
    if (row.classList.contains("group-row")) sections.push({ head: row, items: [] });
    else {
      const items = sections[sections.length - 1].items;
      if (row.classList.contains("detail-row") && items.length) items[items.length - 1].push(row);
      else items.push([row]);
    }
  }

  const sign = st.dir === "asc" ? 1 : -1;
  const cmp = (a, b) => {
    const ka = sortKey(a[0].cells[st.col], type);
    const kb = sortKey(b[0].cells[st.col], type);
    if (ka === null && kb === null) return 0;
    if (ka === null) return 1;
    if (kb === null) return -1;
    return (ka < kb ? -1 : ka > kb ? 1 : 0) * sign;
  };
  for (const sec of sections) {
    if (sec.head) tbody.appendChild(sec.head);
    if (sec.items.length > 1 && sec.items[0][0].cells.length > 1) sec.items.sort(cmp);
    sec.items.forEach(g => g.forEach(r => tbody.appendChild(r)));
  }
}

// --- Collapsible Groups ---
//
// groupedRows renders rows under collapsible heading rows. Collapsed state is
// remembered per table and group name for the browser session.

const collapsedByTable = {};

function groupedRows(tableId, colspan, items, groupOf, rowHtml, summaryOf) {
  const groups = new Map();
  items.forEach(it => {
    const [name, rank] = groupOf(it);
    if (!groups.has(name)) groups.set(name, { rank, items: [] });
    groups.get(name).items.push(it);
  });
  const collapsed = collapsedByTable[tableId] || (collapsedByTable[tableId] = new Set());
  return Array.from(groups.entries()).sort((a, b) => a[1].rank - b[1].rank || a[0].localeCompare(b[0]))
    .map(([name, g]) => {
      const closed = collapsed.has(name);
      const summary = summaryOf ? summaryOf(g.items) : `${g.items.length}`;
      return `<tr class="group-row ${closed ? "collapsed" : ""}" data-group-table="${escapeHtml(tableId)}" data-group="${escapeHtml(name)}">` +
        `<td colspan="${escapeHtml(colspan)}">${escapeHtml(name)}<span class="dim">${escapeHtml(summary)}</span></td></tr>` +
        (closed ? "" : g.items.map(rowHtml).join(""));
    }).join("");
}

document.addEventListener("click", (ev) => {
  const head = ev.target.closest("tr.group-row[data-group-table]");
  if (!head) return;
  const set = collapsedByTable[head.dataset.groupTable] || (collapsedByTable[head.dataset.groupTable] = new Set());
  const name = head.dataset.group;
  if (set.has(name)) set.delete(name); else set.add(name);
  const rerender = GROUP_RERENDER[head.dataset.groupTable];
  if (rerender) rerender();
});
const GROUP_RERENDER = {};

/** Sets tbody HTML, then re-applies bars and the table's saved sort. */
function fillTable(tbodyId, html, emptyText, colspan) {
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = html || `<tr><td colspan="${escapeHtml(colspan)}" class="empty-cell">${escapeHtml(emptyText)}</td></tr>`;
  applyBars(tbody);
  const table = tbody.closest("table");
  if (table.classList.contains("sortable")) applySort(table);
}

// --- Routing ---

function handleRouting() {
  let hash = window.location.hash || "#/dashboard";
  // Until first-run setup is complete only the wizard is reachable (setup.js locks the menu).
  if (setupCompleted === false && !hash.startsWith("#/setup")) {
    history.replaceState(null, "", "#/setup");
    hash = "#/setup";
  }
  document.querySelectorAll(".view-panel").forEach(hide);
  document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
  // In Settings the left menu becomes the settings menu; Back returns to the page you came from.
  const inSettings = hash.startsWith("#/settings");
  document.getElementById("app-shell").classList.toggle("in-settings", inSettings);
  if (!inSettings && !hash.startsWith("#/setup")) document.getElementById("settings-back").setAttribute("href", hash);

  const nav = id => {
    const link = document.getElementById(id);
    if (link) link.classList.add("active");
    setPageTitle(titleForHash(hash));
  };
  const view = id => show(document.getElementById(id));
  window.scrollTo(0, 0);

  const detail = hash.match(/^#\/device\/(\d+)(?:\/(\w+))?$/);
  if (detail) {
    const id = parseInt(detail[1], 10);
    if (id !== activeDeviceId) expandedPorts.clear();
    activeDeviceId = id;
    activeTab = detail[2] || "overview";
    view("view-device-detail");
    nav("nav-devices");
    startLive(id);
    loadDeviceDetail(id);
    return;
  }

  activeDeviceId = null;
  stopLive();
  if (!hash.startsWith("#/settings")) settingsLoaded = false;
  if (hash.startsWith("#/settings")) {
    // #/settings/<section>; #/settings/alerts[/template/<id> | /tag/<name> | /device/<id> | /overview] opens the alert rules there.
    const m = hash.match(/^#\/settings\/alerts(?:\/(template|tag|device)\/([^/]+)|\/(overview))?$/);
    const sec = (hash.match(/^#\/settings\/(\w+)/) || [])[1];
    if (sec) settingsSection = sec;
    view("view-settings"); nav("nav-settings");
    if (m && m[3]) { settingsRoute = { scope: "overview", target: "", focus: true }; }
    else if (m && m[1]) { settingsRoute = { scope: m[1], target: decodeURIComponent(m[2]), focus: true }; }
    // Moving between sections keeps unsaved edits (every section is rendered, only one is shown).
    if (settingsLoaded) {
      showSettingsSection(settingsSection);
      if (settingsRoute.focus) { loadAlertRules(settingsRoute.scope, settingsRoute.target); settingsRoute = { scope: "global", target: "", focus: false }; }
    } else {
      loadSettings();
    }
  } else if (hash === "#/audit") {
    view("view-audit"); nav("nav-audit"); loadAuditLogs();
  } else if (hash.startsWith("#/events")) {
    view("view-events"); nav("nav-events"); loadEvents(true);
  } else if (hash === "#/setup" && setupCompleted === false) {
    // Setup is the first run only: once applied, an old link to it lands on the dashboard.
    view("view-setup"); setPageTitle("Setup"); openSetup(false);
  } else if (hash === "#/availability") {
    view("view-availability"); nav("nav-availability"); loadAvailability();
  } else if (hash.startsWith("#/guide")) {
    view("view-guide"); nav("nav-guide"); loadGuide((hash.match(/^#\/guide\/([\w-]+)/) || [])[1]);
  } else if (hash === "#/proxmox") {
    view("view-proxmox"); nav("nav-proxmox"); loadProxmox();
  } else if (hash === "#/wifi") {
    view("view-wifi"); nav("nav-wifi"); loadWifi();
  } else if (hash === "#/pihole") {
    view("view-pihole"); nav("nav-pihole"); loadPiholePage();
  } else if (hash === "#/inventory") {
    view("view-inventory"); nav("nav-inventory"); loadInventory();
  } else if (hash === "#/map") {
    view("view-map"); nav("nav-map"); loadMap();
  } else if (hash === "#/automation") {
    view("view-automation"); nav("nav-automation"); loadCredentials(); loadAutomation().then(loadHostActionRuns); loadWorkflows();
  } else if (hash.startsWith("#/devices")) {
    const f = hash.match(/^#\/devices\/(online|offline|problems|wireless)$/);
    deviceFilter = f ? f[1] : null;
    view("view-devices"); nav("nav-devices"); loadDevices();
  } else {
    view("view-dashboard"); nav("nav-dashboard"); loadDashboard();
  }
}

// --- Profiles ---

let profileOptionsHtml = "";
let profileNames = {};   // template id -> its readable name

async function loadProfiles() {
  try {
    const data = await api("/api/profiles");
    const options = (data.profiles || [])
      .map(p => `<option value="${escapeHtml(p.profile_id)}">${escapeHtml(p.name)}</option>`)
      .join("");
    profileOptionsHtml = options;
    profileNames = Object.fromEntries((data.profiles || []).map(p => [p.profile_id, p.name]));
    document.querySelectorAll(".profile-select").forEach(sel => { sel.innerHTML = options; });
  } catch (err) {
    showToast(`Could not load hardware profiles: ${err.message}`, "error");
  }
}

// --- Devices Overview ---

const STATUS_RANK = { offline: 0, degraded: 1, unknown: 2, online: 3 };

function statusClass(status) {
  if (status === "online") return "status-ok";
  if (status === "degraded") return "status-warn";
  if (status === "offline") return "status-err";
  return "status-unknown";
}

// Device groups: the server sends each device's group id (from its template's category, or the
// group chosen in Edit device). id -> [label, order]; mirrors DEVICE_GROUPS in server.py.
const DEVICE_GROUPS = {
  gateway: ["Gateways and routers", 10], switch: ["Switches", 20], wireless_ap: ["Access points", 30],
  nas: ["NAS and storage", 40], server: ["Servers and hypervisors", 50], workstation: ["Computers", 60],
  power: ["Power (UPS and PDU)", 65], printer: ["Printers", 68], service: ["Services (port checks)", 70],
  other: ["Other devices", 90],
};
const groupOf = d => DEVICE_GROUPS[d.group] || DEVICE_GROUPS.other;
// Info problems (a restart) leave Active problems after this long; warnings and worse stay until fixed.
const INFO_PROBLEM_SECONDS = 60;
const shownProblems = list => list.filter(p => p.severity !== "info" || Date.now() / 1000 - (p.since || 0) < INFO_PROBLEM_SECONDS);

/** Icon beside the status pill: the device's worst open problem, or a recent event (fades after 30 min). */
function attentionIcon(d) {
  const a = d.attention;
  if (!a) return "";
  const sev = a.severity === "critical" || a.severity === "high" ? "bad" : a.severity === "warning" ? "warn" : "info";
  const glyph = sev === "info" ? "i" : "!";
  const when = a.since ? ` (${formatAgo(a.since)})` : "";
  const href = `#/events?device=${Number(d.id)}`;
  return `<a class="attn attn-${sev}${a.acknowledged ? " attn-acked" : ""}" href="${href}" title="${escapeHtml(a.message + when)}" aria-label="${escapeHtml(a.message)}">${glyph}</a>`;
}

let lastFleet = null;
GROUP_RERENDER["tbl-devices"] = () => lastFleet && renderFleet(...lastFleet);

async function loadDevices() {
  try {
    const [devData, probData] = await Promise.all([api("/api/devices"), api("/api/problems")]);
    lastFleet = [devData.devices || [], probData.problems || []];
    renderFleet(...lastFleet);
  } catch (err) {
    console.error("Failed to load devices", err);
  }
}

const DEVICE_FILTERS = {
  online: ["Online", d => d.status === "online"],
  offline: ["Offline", d => d.status === "offline"],
  problems: ["With problems", (d, probIds) => probIds.has(d.id)],
  wireless: ["Access points", d => isNum(d.summary.clients)],
};

function statTile(n, label, cls, href, active) {
  return `<a class="stat clickable ${escapeHtml(cls)} ${active ? "active-filter" : ""}" href="${escapeHtml(href)}" title="Show ${escapeHtml(label.toLowerCase())}">` +
    `<div class="stat-num">${escapeHtml(n)}</div><div class="stat-label">${escapeHtml(label)}</div></a>`;
}

function renderFleet(allDevices, problems) {
  const online = allDevices.filter(d => d.status === "online").length;
  const offline = allDevices.filter(d => d.status === "offline").length;
  const actionable = problems.filter(isOpenProblem).length;
  const clients = allDevices.reduce((a, d) => a + (d.summary.clients || 0), 0);
  const f = deviceFilter;
  document.getElementById("fleet-stats").innerHTML = [
    statTile(allDevices.length, "Devices", "", "#/devices", !f),
    statTile(online, "Online", "stat-ok", "#/devices/online", f === "online"),
    statTile(offline, "Offline", offline ? "stat-bad" : "", "#/devices/offline", f === "offline"),
    statTile(actionable, "Problems", actionable ? "stat-warn" : "", "#/devices/problems", f === "problems"),
    statTile(clients, "Wireless clients", "", "#/devices/wireless", f === "wireless"),
  ].join("");

  const chip = document.getElementById("device-filter-chip");
  const probIds = new Set(problems.filter(isOpenProblem).map(p => p.device_id));
  let devices = allDevices;
  // Group and tag filters (the selects in the toolbar, or a link from Settings, Groups and tags).
  const fg = document.getElementById("devices-filter-group"), ft = document.getElementById("devices-filter-tag");
  if (fg.value !== devicesFilter.group) fg.value = devicesFilter.group;
  if (ft.value !== devicesFilter.tag) ft.value = devicesFilter.tag;
  if (devicesFilter.group || devicesFilter.tag) devices = devices.filter(d => deviceMatches(d, devicesFilter.group, devicesFilter.tag));
  if (f && DEVICE_FILTERS[f]) {
    devices = devices.filter(d => DEVICE_FILTERS[f][1](d, probIds));
    chip.textContent = `Filter: ${DEVICE_FILTERS[f][0]}`;
    show(chip);
  } else {
    hide(chip);
  }

  const panel = document.getElementById("problems-panel");
  const shown = shownProblems(problems);
  const listed = shown.filter(p => !p.acknowledged_at);
  const ackedList = shown.filter(p => p.acknowledged_at);
  const devById = Object.fromEntries(allDevices.map(d => [d.id, d]));
  // Acknowledged: seen to, still true. Kept apart from the problems that need someone.
  const ackedPanel = document.getElementById("acked-panel");
  if (ackedList.length) {
    show(ackedPanel);
    document.getElementById("acked-count").textContent = String(ackedList.length);
    fillTable("acked-body", ackedList.map(p => `
      <tr class="acked">
        <td data-sort="${Number(SEVERITY_RANK[p.severity] ?? 3)}">${severityPill(p.severity)}</td>
        <td class="text-cell"><a class="device-link" href="#/device/${Number(p.device_id)}">${escapeHtml(p.hostname)}</a></td>
        <td class="text-cell">${escapeHtml(p.message)} <span class="dim">for ${escapeHtml(formatSince(p.since))}</span>${ackLabel(p)} ${ackButton(p)}</td>
      </tr>`).join(""), "", 3);
  } else {
    hide(ackedPanel);
  }
  if (listed.length) {
    show(panel);
    fillTable("problems-body", listed.map(p => `
      <tr class="${p.acknowledged_at ? "acked" : ""}">
        <td data-sort="${Number(SEVERITY_RANK[p.severity] ?? 3)}">${severityPill(p.severity)}</td>
        <td class="text-cell"><a class="device-link" href="#/device/${Number(p.device_id)}">${escapeHtml(p.hostname)}</a></td>
        <td class="text-cell">${escapeHtml(p.message)} <span class="dim">for ${escapeHtml(formatSince(p.since))}</span>${ackLabel(p)} ${ackButton(p)}${haProblemButton(p, devById[p.device_id])}</td>
      </tr>`).join(""), "", 3);
  } else {
    hide(panel);
  }

  const deviceRow = d => {
    const id = Number(d.id);
    const inv = d.inventory || {};
    const s = d.summary || {};
    const ports = s.ports || {};
    const lastSeenAge = d.last_seen ? Math.floor(Date.now() / 1000 - d.last_seen) : "";
    return `
      <tr>
        <td data-sort="${Number(STATUS_RANK[d.status] ?? 2)}" class="status-cell"><span class="status-pill ${statusClass(d.status)}">${escapeHtml(String(d.status).toUpperCase())}</span>${attentionIcon(d)}</td>
        <td class="text-cell"><input type="checkbox" class="row-select" data-perm="devices.manage" data-select="${id}"${selectedDevices.has(id) ? " checked" : ""} aria-label="Select ${escapeHtml(d.hostname)}"><a href="#/device/${id}" class="device-link">${escapeHtml(d.hostname)}</a> ${tagBadge(id, d.tags, d.hostname)}</td>
        <td class="text-cell">${d.service_port ? `<span class="dim">TCP port</span> ${Number(d.service_port)}` : d.snmp === false ? `<span class="dim">Ping only</span>` : escapeHtml(inv.model || "-")}</td>
        <td>${escapeHtml(d.ip_address)}</td>
        <td>${escapeHtml(inv.firmware || "-")}</td>
        <td data-sort="${isNum(s.uptime_seconds) ? s.uptime_seconds : ""}">${isNum(s.uptime_seconds) ? formatDuration(s.uptime_seconds) : "-"}</td>
        <td data-sort="${isNum(d.last_ping_ms) ? d.last_ping_ms : ""}">${cellLink(id, "graphs", "Ping latency", isNum(d.last_ping_ms) ? d.last_ping_ms.toFixed(1) + " ms" : "")}</td>
        <td data-sort="${isNum(s.cpu_pct) ? s.cpu_pct : ""}" class="bar-cell">${isNum(s.cpu_pct) ? cellLink(id, "graphs", "CPU", barHtml(s.cpu_pct), true) : emptyMeter()}</td>
        <td data-sort="${isNum(s.mem_pct) ? s.mem_pct : ""}" class="bar-cell">${isNum(s.mem_pct) ? cellLink(id, "graphs", "Memory", barHtml(s.mem_pct), true) : emptyMeter()}</td>
        <td data-sort="${ports.total ? escapeHtml(ports.up) : ""}">${cellLink(id, "ports", "", ports.total ? `${ports.up} / ${ports.total}` : "")}</td>
        <td data-sort="${isNum(s.clients) ? s.clients : ""}">${cellLink(id, "wireless", "clients", isNum(s.clients) ? String(s.clients) : "")}</td>
        <td data-sort="${lastSeenAge}">${formatAgo(d.last_seen)}</td>
        <td class="actions-cell">
          <button class="btn" data-perm="devices.poll" data-action="poll" data-id="${id}">Poll</button>
          <button class="btn" data-perm="devices.manage" data-action="edit" data-id="${id}">Edit</button>
          <button class="btn btn-danger" data-perm="devices.manage" data-action="delete" data-id="${id}">Delete</button>
        </td>
      </tr>`;
  };
  const grouped = document.getElementById("devices-group").checked;
  const html = grouped
    ? groupedRows("tbl-devices", 13, devices, groupOf, deviceRow,
        items => `${items.length} device${items.length === 1 ? "" : "s"}, ${items.filter(x => x.status === "online").length} online`)
    : devices.map(deviceRow).join("");
  fillTable("device-table-body", html, f ? "No devices match this filter." : 'No devices configured yet. Click "+ Add Target" to add your first device.', 13);
  // Drop selections of devices that no longer exist, then show the bar only while something is ticked.
  const known = new Set(allDevices.map(d => d.id));
  for (const id of [...selectedDevices]) if (!known.has(id)) selectedDevices.delete(id);
  updateSelectionBar();
}

const selectedDevices = new Set();

/** A table value that opens the device at the tab (and graph or section) it comes from. html marks trusted markup. */
function cellLink(id, tab, focus, value, html = false) {
  if (!value) return "-";
  const what = focus && focus !== "clients" ? `the ${focus} graph` : `the ${tab} tab`;
  return `<a class="cell-link" href="#/device/${Number(id)}/${escapeHtml(tab)}"${focus ? ` data-focus="${escapeHtml(focus)}"` : ""} title="Open ${escapeHtml(what)}">${html ? value : escapeHtml(value)}</a>`;
}

// A link with data-focus scrolls the page it opens to that graph or section (consumed by the tab loaders).
document.addEventListener("click", ev => {
  const a = ev.target.closest("a[data-focus]");
  if (a) pendingFocus = a.dataset.focus;
});

function updateSelectionBar() {
  const n = selectedDevices.size;
  document.getElementById("device-selection").classList.toggle("hidden", n === 0);
  document.getElementById("device-selection-count").textContent = `${n} selected`;
  document.getElementById("btn-delete-selected").textContent = `Delete selected (${n})`;
}

function initAckButtons() {
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-ack-key]");
    if (!btn) return;
    ev.preventDefault();
    const acknowledged = btn.dataset.ack === "1";
    let note = "";
    if (acknowledged) {
      note = await promptDialog({ title: "Acknowledge this problem?",
        message: "It stays listed but stops counting (and stops reminders) until it resolves.",
        input: { label: "Note (optional)", placeholder: "e.g. Disk replacement ordered" }, confirmLabel: "Acknowledge" });
      if (note === null) return;
    }
    try {
      await api("/api/problems/ack", { method: "POST", body: {
        device_id: parseInt(btn.dataset.ackDevice, 10), problem_key: btn.dataset.ackKey, acknowledged, note: note.trim() } });
      showToast(acknowledged ? "Problem acknowledged." : "Acknowledgement removed.", "success");
      const hash = window.location.hash || "#/dashboard";
      if (hash.startsWith("#/device/")) loadDeviceDetail(activeDeviceId, true);
      else if (hash.startsWith("#/devices")) loadDevices();
      else refreshDashboard();
    } catch (err) {
      showToast(`Could not update problem: ${err.message}`, "error");
    }
  });
}

function initDeviceTable() {
  initAckButtons();
  const groupBox = document.getElementById("devices-group");
  try { groupBox.checked = localStorage.getItem("monitor.devgroup.v1") !== "off"; } catch (err) { /* storage unavailable */ }
  groupBox.addEventListener("change", () => {
    try { localStorage.setItem("monitor.devgroup.v1", groupBox.checked ? "on" : "off"); } catch (err) { /* storage unavailable */ }
    if (lastFleet) renderFleet(...lastFleet);
  });
  document.getElementById("device-filter-chip").addEventListener("click", () => { window.location.hash = "#/devices"; });
  document.getElementById("btn-poll-all").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    btn.textContent = "Polling...";
    try {
      const r = await api("/api/devices/poll-all", { method: "POST" });
      showToast(`Polling all ${r.queued} devices. The table refreshes as results arrive.`, "success");
      // Polls run in parallel on the server; refresh a few times while they complete.
      [3000, 8000, 15000].forEach(ms => setTimeout(loadDevices, ms));
    } catch (err) {
      showToast(`Poll all failed: ${err.message}`, "error");
    } finally {
      setTimeout(() => { btn.disabled = false; btn.textContent = "Poll all"; }, 8000);
    }
  });
  document.getElementById("device-table-body").addEventListener("change", (ev) => {
    const box = ev.target.closest("[data-select]");
    if (!box) return;
    const id = parseInt(box.dataset.select, 10);
    if (box.checked) selectedDevices.add(id); else selectedDevices.delete(id);
    updateSelectionBar();
  });
  document.getElementById("btn-select-all").addEventListener("click", () => {
    document.querySelectorAll("#device-table-body [data-select]").forEach(b => { b.checked = true; selectedDevices.add(parseInt(b.dataset.select, 10)); });
    updateSelectionBar();
  });
  document.getElementById("btn-select-clear").addEventListener("click", () => {
    selectedDevices.clear();
    document.querySelectorAll("#device-table-body [data-select]").forEach(b => { b.checked = false; });
    updateSelectionBar();
  });
  document.getElementById("btn-tag-selected").addEventListener("click", () => bulkTag(true));
  document.getElementById("btn-untag-selected").addEventListener("click", () => bulkTag(false));
  for (const [id, key] of [["devices-filter-group", "group"], ["devices-filter-tag", "tag"]]) {
    document.getElementById(id).addEventListener("change", ev => {
      devicesFilter[key] = ev.target.value;
      if (lastFleet) renderFleet(...lastFleet);
    });
  }
  document.getElementById("btn-delete-selected").addEventListener("click", async () => {
    const ids = [...selectedDevices];
    const names = (lastFleet ? lastFleet[0] : []).filter(d => selectedDevices.has(d.id)).map(d => d.hostname);
    if (!(await confirmDialog({ title: `Delete ${ids.length} device${ids.length === 1 ? "" : "s"}?`,
      message: "They stop being monitored and all their history is removed. This cannot be undone.",
      detail: names.join(", "), confirmLabel: "Delete", danger: true }))) return;
    try {
      const r = await api("/api/devices/bulk-delete", { method: "POST", body: { device_ids: ids } });
      selectedDevices.clear();
      showToast(`Deleted ${r.deleted.length} device${r.deleted.length === 1 ? "" : "s"}`, "success");
      loadDevices();
    } catch (err) {
      showToast(`Could not delete: ${err.message}`, "error");
    }
  });
  // One delegated listener survives the table being re-rendered every refresh.
  document.getElementById("device-table-body").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    const id = parseInt(btn.dataset.id, 10);
    if (btn.dataset.action === "poll") triggerDevicePoll(id, btn);
    else if (btn.dataset.action === "edit") openEditModal(id);
    else if (btn.dataset.action === "delete") deleteTarget(id);
    else if (btn.dataset.action === "tags") editDeviceTags(id);
  });
}

async function triggerDevicePoll(id, btn) {
  const originalText = btn.textContent;
  btn.textContent = "Polling...";
  btn.disabled = true;
  try {
    const data = await api(`/api/devices/${id}/poll`, { method: "POST" });
    const r = data.result;
    const ping = isNum(r.ping_ms) ? `${r.ping_ms.toFixed(1)} ms` : "no reply";
    const count = Object.keys(r.metrics || {}).length;
    const tables = (r.tables || []).join(", ");
    if (r.status === "online") {
      showToast(`Poll complete: online (${ping}), ${count} metrics${tables ? ", tables: " + tables : ""}`, "success");
    } else {
      showToast(`Poll complete: device is ${r.status} (${ping})`, "error");
    }
    if (activeDeviceId === id) loadDeviceDetail(id, true);
    else loadDevices();
  } catch (err) {
    showToast(`Poll failed: ${err.message}`, "error");
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

async function deleteTarget(id) {
  const name = (lastFleet ? lastFleet[0] : []).concat(lastDetail ? [lastDetail.device] : []).find(d => d && d.id === Number(id));
  if (!(await confirmDialog({ title: `Delete ${name ? name.hostname : "this device"}?`,
    message: "It stops being monitored and all its history is removed. This cannot be undone.",
    confirmLabel: "Delete", danger: true }))) return false;
  try {
    await api(`/api/devices/${id}`, { method: "DELETE" });
    showToast("Target removed.", "success");
    loadDevices();
    return true;
  } catch (err) {
    showToast(`Delete failed: ${err.message}`, "error");
    return false;
  }
}

// --- Metric Presentation ---

const METRIC_INFO = {
  icmp_ping_ms: ["Ping latency", v => `${v.toFixed(1)} ms`],
  tcp_connect_ms: ["Port connect time", v => `${v.toFixed(1)} ms`],
  tls_days_left: ["Certificate days left", v => v < 0 ? `expired ${Math.abs(v).toFixed(0)} days ago` : `${v.toFixed(0)} days`],
  "dns.ms": ["DNS answer time", v => `${v.toFixed(1)} ms`],
  "dns.ok": ["DNS answering", v => (v ? "yes" : "no")],
  "pihole.queries": ["Pi-hole queries today", v => Math.round(v).toLocaleString()],
  "pihole.blocked": ["Pi-hole blocked today", v => Math.round(v).toLocaleString()],
  "pihole.blocked_pct": ["Pi-hole share blocked", v => `${v.toFixed(1)}%`],
  "pihole.clients": ["Pi-hole active clients", v => String(Math.round(v))],
  "pihole.domains": ["Domains on the blocklists", v => Math.round(v).toLocaleString()],
  "pihole.blocking": ["Pi-hole blocking", v => (v ? "on" : "off")],
  "pihole.gravity_days": ["Blocklists updated", v => `${v.toFixed(0)} days ago`],
  "wifi.weak": ["Wi-Fi devices on weak signal", v => String(Math.round(v))],
  "wifi.experience": ["Wi-Fi experience (average)", v => `${v.toFixed(0)}%`],
  service_up: ["Service port", v => (v ? "answering" : "not answering")],
  uptime_seconds: ["Uptime", v => formatDuration(v)],
  cpu_load_1m: ["CPU load (1 min)", v => v.toFixed(2)],
  cpu_load_5m: ["CPU load (5 min)", v => v.toFixed(2)],
  cpu_load_15m: ["CPU load (15 min)", v => v.toFixed(2)],
  cpu_usage_pct: ["CPU usage", pct],
  cpu_core_max_pct: ["CPU busiest core", pct],
  cpu_idle_pct: ["CPU idle", pct],
  mem_used_pct: ["Memory used (excl. cache)", pct],
  mem_total_kb: ["Memory total", formatKb],
  mem_avail_kb: ["Memory free", formatKb],
  mem_buffer_kb: ["Memory buffers", formatKb],
  mem_cached_kb: ["Memory cached", formatKb],
  mem_total_mb: ["Memory total", v => formatKb(v * 1024)],
  mem_free_mb: ["Memory free", v => formatKb(v * 1024)],
  clients_total: ["Wireless clients", v => v.toFixed(0)],
  clients_2g: ["Clients 2.4 GHz", v => v.toFixed(0)],
  clients_5g: ["Clients 5 GHz", v => v.toFixed(0)],
  radio_2g_channel: ["Channel 2.4 GHz", v => v.toFixed(0)],
  radio_5g_channel: ["Channel 5 GHz", v => v.toFixed(0)],
  radio_2g_tx_power_dbm: ["Tx power 2.4 GHz", v => `${v.toFixed(0)} dBm`],
  radio_5g_tx_power_dbm: ["Tx power 5 GHz", v => `${v.toFixed(0)} dBm`],
  radio_2g_util_pct: ["Channel utilisation 2.4 GHz", pct],
  radio_5g_util_pct: ["Channel utilisation 5 GHz", pct],
  ports_up: ["Ports up", v => v.toFixed(0)],
  wan_status: ["WAN link", v => (v === 1 ? "Up" : "Down")],
  tcp_established: ["TCP connections (established)", v => v.toFixed(0)],
  mem_hr_size_units: ["Memory size (storage units)", v => v.toFixed(0)],
  mem_hr_used_units: ["Memory used (storage units)", v => v.toFixed(0)],
  cpu_temp_c: ["CPU temperature", v => `${v.toFixed(0)} °C`],
  system_temp_c: ["System temperature", v => `${v.toFixed(0)} °C`],
  fan_rpm: ["Fan speed", v => `${v.toFixed(0)} RPM`],
};

// Units a profile can give a metric ("unit" in the profile JSON).
const UNIT_FORMAT = {
  percent: pct, celsius: v => `${v.toFixed(0)} °C`, seconds: formatDuration, minutes: v => formatDuration(v * 60),
  volts: v => `${v.toFixed(1)} V`, amps: v => `${v.toFixed(1)} A`, watts: v => `${v.toFixed(0)} W`, hz: v => `${v.toFixed(1)} Hz`,
  decivolts: v => `${(v / 10).toFixed(1)} V`, dbm: v => `${v.toFixed(0)} dBm`, ports: v => v.toFixed(0),
  rpm: v => `${v.toFixed(0)} RPM`, KB: formatKb, MB: v => formatKb(v * 1024), bytes: formatBytes, count: v => v.toFixed(0),
};

/** Label and value text from the device's profile (lastDetail.metric_info), or null. */
function profileMetric(key, value) {
  const info = lastDetail && lastDetail.metric_info && lastDetail.metric_info[key];
  if (!info) return null;
  const words = info.values || {};
  const text = words[String(value)] ?? (UNIT_FORMAT[info.unit] ? UNIT_FORMAT[info.unit](value) : String(+value.toFixed(2)));
  return [info.label, text];
}

function describeMetric(key, value) {
  const fromProfile = profileMetric(key, value);
  if (fromProfile) return fromProfile;
  if (METRIC_INFO[key]) return [METRIC_INFO[key][0], METRIC_INFO[key][1](value)];
  if (key.endsWith("_octets")) return [key.replace(/_/g, " "), `${formatBytes(value)} total`];
  if (key.endsWith("_status")) return [key.replace(/_/g, " "), value === 1 ? "Up" : value === 2 ? "Down" : `State ${value}`];
  let m = /^disk\.(\d+)\.temp_c$/.exec(key);
  if (m) return [`Disk ${m[1]} temperature`, `${value.toFixed(0)} °C`];
  m = /^stor\.(\d+)\.used_pct$/.exec(key);
  if (m) return [`Storage ${m[1]} used`, pct(value)];
  m = /^vol\.(\d+)\.used_pct$/.exec(key);
  if (m) return [`Volume ${m[1]} used`, pct(value)];
  m = /^sensor\.(\w+)\.temp_c$/.exec(key);
  if (m) {
    const name = m[1].replace(/_/g, " ");
    return [`${name.charAt(0).toUpperCase()}${name.slice(1)} temperature`, `${value.toFixed(1)} °C`];
  }
  m = /^dio\.(\w+)\.(read|write)_Bps$/.exec(key);
  if (m) return [`${m[1]} ${m[2]}`, `${formatBytes(value)}/s`];
  m = /^if\.(\d+)\.(in|out)_peak_bps$/.exec(key);
  if (m) return [`Interface ${m[1]} ${m[2]} peak`, formatBps(value)];
  return [key, String(value)];
}

function formatChange(key, delta) {
  if (!isNum(delta) || delta === 0) return "";
  const arrow = delta > 0 ? "▲" : "▼";
  let text;
  if (key.endsWith("_octets")) text = formatBytes(Math.abs(delta));
  else if (key.endsWith("_kb")) text = formatKb(Math.abs(delta));
  else if (key === "uptime_seconds") text = formatDuration(Math.abs(delta));
  else text = Math.abs(delta) >= 100 ? Math.abs(delta).toFixed(0) : Math.abs(delta).toFixed(2);
  return `<span class="${delta > 0 ? "chg-up" : "chg-down"}">${arrow} ${escapeHtml(text)}</span>`;
}

// --- Device Detail Page ---

const TAB_SECTION = { ports: "interfaces", neighbours: ["fdb", "arp"], wireless: ["radios", "wifi_clients"], storage: ["storage", "disks", "volumes", "sensors", "diskio"],
  dns: "pihole_upstreams",
  health: "health", processes: ["processes", "services"], software: "software" };

function initDetailPage() {
  document.getElementById("detail-tabs").addEventListener("click", (ev) => {
    const tab = ev.target.closest("[data-tab]");
    if (!tab || !activeDeviceId) return;
    window.location.hash = `#/device/${activeDeviceId}/${tab.dataset.tab}`;
  });

  document.getElementById("btn-detail-poll").addEventListener("click", (ev) => {
    if (activeDeviceId) triggerDevicePoll(activeDeviceId, ev.currentTarget);
  });
  document.getElementById("btn-overview-graphs").addEventListener("click", () => lastDetail && chooseOverviewGraphs());
  document.getElementById("overview-charts").addEventListener("click", ev => {
    if (!ev.target.closest("[data-choose-graphs]")) return;
    ev.preventDefault();
    chooseOverviewGraphs();
  });
  // "Add to overview" on graph cards (Graphs tab, Custom SNMP tab).
  document.getElementById("view-device-detail").addEventListener("click", ev => {
    const b = ev.target.closest("[data-overview-pin]");
    if (b && lastDetail) toggleOverviewGraph(b.dataset.overviewPin, b);
  });
  document.getElementById("btn-detail-fixsnmp").addEventListener("click", () => {
    if (activeDeviceId) openFixSnmp(lastDetail.device);
  });
  document.getElementById("btn-detail-hostact").addEventListener("click", () => {
    if (activeDeviceId) openHostActions(activeDeviceId);
  });
  initFixSnmp();
  document.getElementById("btn-detail-alerts").addEventListener("click", () => {
    if (activeDeviceId) window.location.hash = `#/settings/alerts/device/${activeDeviceId}`;
  });
  document.getElementById("btn-detail-edit").addEventListener("click", () => {
    if (activeDeviceId) openEditModal(activeDeviceId);
  });
  document.getElementById("btn-detail-delete").addEventListener("click", async () => {
    if (activeDeviceId && await deleteTarget(activeDeviceId)) window.location.hash = "#/devices";
  });

  document.getElementById("ports-all").addEventListener("change", () => loadPorts());
  document.getElementById("ports-filter").addEventListener("input", () => loadPorts(true));
  document.getElementById("neighbours-filter").addEventListener("input", () => loadNeighbours(true));
  document.getElementById("processes-filter").addEventListener("input", () => renderProcesses());
  document.getElementById("software-filter").addEventListener("input", () => renderSoftware());
  document.querySelector('[data-panel="processes"]').addEventListener("change", async (ev) => {
    const box = ev.target.closest("input[data-watch-kind]");
    if (!box || !activeDeviceId) return;
    box.disabled = true;
    try {
      const res = await api(`/api/devices/${activeDeviceId}/watches`, {
        method: "POST", body: { kind: box.dataset.watchKind, name: box.dataset.watchName, watched: box.checked } });
      if (processData) processData.watches = res.watches;
      showToast(`${box.checked ? "Watching" : "Stopped watching"} ${box.dataset.watchName}`, "success");
    } catch (err) {
      box.checked = !box.checked;
      showToast(`Could not update watch: ${err.message}`, "error");
    }
    renderProcesses();
  });
  document.getElementById("detail-kpis").addEventListener("click", (ev) => {
    const card = ev.target.closest("[data-go]");
    if (card) goToDetail(card.dataset.go);
  });
  document.getElementById("ports-body").addEventListener("click", (ev) => {
    const group = ev.target.closest("tr.group-row");
    if (group) {
      const name = group.dataset.group;
      if (collapsedGroups.has(name)) collapsedGroups.delete(name);
      else collapsedGroups.add(name);
      loadPorts(true);
      return;
    }
    const row = ev.target.closest("tr.port-row");
    if (!row) return;
    const idx = row.dataset.ifindex;
    if (expandedPorts.has(idx)) expandedPorts.delete(idx);
    else expandedPorts.add(idx);
    loadPorts(true);
  });
  const compareBox = document.getElementById("graph-compare");
  try { compareBox.checked = localStorage.getItem("monitor.compare.v1") === "on"; } catch (err) { /* storage unavailable */ }
  compareBox.addEventListener("change", () => {
    try { localStorage.setItem("monitor.compare.v1", compareBox.checked ? "on" : "off"); } catch (err) { /* storage unavailable */ }
    renderGraphs();
  });
  document.getElementById("graph-range").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-hours]");
    if (!btn) return;
    graphHours = parseInt(btn.dataset.hours, 10);
    document.querySelectorAll("#graph-range .btn").forEach(b => b.classList.toggle("active", b === btn));
    renderGraphs();
  });
}

async function loadDeviceDetail(id, isRefresh = false) {
  let data;
  try {
    data = await api(`/api/devices/${id}`);
  } catch (err) {
    if (!isRefresh) showToast(`Could not load device: ${err.message}`, "error");
    return;
  }
  if (activeDeviceId !== id) return;
  lastDetail = data;
  const d = data.device;
  const inv = d.inventory || {};

  document.getElementById("detail-header-name").textContent = d.hostname;
  setPageTitle(d.hostname);
  // Fix SNMP is for SNMP devices: not for port checks or devices added as ping only.
  document.getElementById("btn-detail-fixsnmp").classList.toggle("hidden", !!d.service_port || d.snmp === false || (d.profile_id !== "linux_host" && d.snmp_status === "ok"));
  document.getElementById("btn-detail-fixsnmp").classList.toggle("btn-primary", d.snmp_status !== "ok" || data.problems.some(p => p.problem_key === "snmp_view"));
  document.getElementById("btn-detail-hostact").classList.toggle("hidden", !haEligible(d));
  document.getElementById("detail-header-sub").textContent =
    (d.service_port ? [`${d.ip_address}:${d.service_port}`, "port check"] : d.snmp === false ? [d.ip_address, "ping only"]
      : [d.ip_address, inv.model, inv.firmware]).filter(Boolean).join("  •  ");
  const pill = document.getElementById("detail-status");
  pill.className = `status-pill ${statusClass(d.status)}`;
  pill.textContent = String(d.status).toUpperCase();

  const probBox = document.getElementById("detail-problems");
  if (data.problems.length) {
    probBox.innerHTML = data.problems.map(p =>
      `<div class="problem sev-${escapeHtml(p.severity)} ${p.acknowledged_at ? "acked" : ""}"><span>${severityPill(p.severity)} ${escapeHtml(p.message)}` +
      ` <span class="dim">for ${escapeHtml(formatSince(p.since))}</span>${ackLabel(p)}</span><span>${haProblemButton(p, d)}${p.severity !== "info" ? ackButton(p) : ""}</span></div>`).join("");
    show(probBox);
  } else {
    hide(probBox);
  }

  if (typeof renderMaintNote === "function") renderMaintNote(data);

  // Tabs appear only when the device has data for them.
  const sections = new Set(data.sections);
  document.querySelectorAll("#detail-tabs [data-tab]").forEach(tab => {
    const need = TAB_SECTION[tab.dataset.tab];
    let visible = !need || (Array.isArray(need) ? need.some(n => sections.has(n)) : sections.has(need));
    // Custom SNMP: any device polled over SNMP (not ping-only devices or port checks).
    if (tab.dataset.tab === "snmp") visible = d.snmp !== false && !d.service_port;
    tab.classList.toggle("hidden", !visible);
    tab.classList.toggle("active", tab.dataset.tab === activeTab);
  });
  document.querySelectorAll("#view-device-detail [data-panel]").forEach(p => {
    p.classList.toggle("hidden", p.dataset.panel !== activeTab);
  });

  switch (activeTab) {
    case "ports": loadPorts(); break;
    case "neighbours": loadNeighbours(); break;
    case "wireless": loadWireless(); break;
    case "storage": loadStorage(); break;
    case "health": loadHealth(); break;
    case "processes": loadProcesses(); break;
    case "software": loadSoftware(); break;
    case "graphs":
      if (!isRefresh || Date.now() - lastGraphRender > 60000) renderGraphs();
      break;
    case "latest": renderLatest(data); break;
    case "dns": if (typeof loadDns === "function") loadDns(isRefresh); break;
    case "snmp": if (typeof loadCustomOids === "function") loadCustomOids(data, isRefresh); break;
    case "events": loadDeviceEvents(); break;
    default: renderOverview(data, isRefresh);
  }
}

/** KPI card; go names where a click leads (a tab, optionally "tab:focus"). */
function kpiCard(label, value, sub, valueClass = "", go = "") {
  const attrs = go ? ` clickable" data-go="${escapeHtml(go)}" tabindex="0" title="Open ${escapeHtml(go.split(":")[0])}` : "";
  return `
    <div class="summary-card${attrs}">
      <div class="summary-label">${escapeHtml(label)}</div>
      <div class="summary-val ${escapeHtml(valueClass)}">${escapeHtml(value)}</div>
      <div class="summary-sub">${escapeHtml(sub)}</div>
    </div>`;
}

/** Navigates within the device page: "graphs:CPU usage" opens Graphs and scrolls to that chart. */
function goToDetail(target) {
  const [tab, focus] = target.split(":");
  pendingFocus = focus || null;
  if (tab === "ports" && focus === "down") {
    document.getElementById("ports-filter").value = "down";
    pendingFocus = null;
  }
  window.location.hash = `#/device/${activeDeviceId}/${tab}`;
}
let pendingFocus = null;

function renderOverviewKpis(data, m) {
  const d = data.device;
  const cpu = isNum(m.cpu_usage_pct) ? m.cpu_usage_pct : isNum(m.cpu_idle_pct) ? 100 - m.cpu_idle_pct : data.cpu_pct;
  const ping = isNum(m.icmp_ping_ms) ? m.icmp_ping_ms : d.last_ping_ms;
  const cards = [
    kpiCard("Reachability", String(d.status).toUpperCase(), isNum(ping) ? `${ping.toFixed(1)} ms` : "No response",
      d.status === "online" ? "text-ok" : "text-err", "graphs:Ping latency"),
  ];
  if (d.service_port) {
    // Port checks: the port is the headline; there is no SNMP uptime.
    const up = m.service_up === 1;
    cards.push(kpiCard(`Port ${d.service_port}`, isNum(m.service_up) ? (up ? "ANSWERING" : "NOT ANSWERING") : "Not checked yet",
      up && isNum(m.tcp_connect_ms) ? `TCP connect ${m.tcp_connect_ms.toFixed(1)} ms` : "TCP connection", up ? "text-ok" : isNum(m.service_up) ? "text-err" : "",
      "graphs:Port"));
  } else {
    cards.push(kpiCard("Uptime", isNum(m.uptime_seconds) ? formatDuration(m.uptime_seconds) : "Unknown", "sysUpTime", "", "events"));
  }
  if (isNum(cpu)) cards.push(kpiCard("CPU", pct(cpu), isNum(m.cpu_load_1m) ? `Load ${m.cpu_load_1m.toFixed(2)}` : "", "", "graphs:CPU"));
  if (isNum(data.mem_pct)) cards.push(kpiCard("Memory Used", pct(data.mem_pct), `of ${formatKb(m.mem_total_kb)} (excl. cache)`, "", "graphs:Memory"));
  if (isNum(m.clients_total)) cards.push(kpiCard("Wireless Clients", String(m.clients_total), `2.4 GHz ${m.clients_2g ?? "-"}  /  5 GHz ${m.clients_5g ?? "-"}`, "", "wireless:clients"));
  if (data.ports.total) cards.push(kpiCard("Ports Up", `${data.ports.up} / ${data.ports.total}`, `${data.ports.down} down, ${data.ports.disabled} disabled`, "", data.ports.down ? "ports:down" : "ports"));
  const diskTemps = Object.keys(m).filter(k => /^disk\.\d+\.temp_c$/.test(k)).map(k => m[k]);
  if (isNum(m.system_temp_c) || diskTemps.length) {
    const hottest = diskTemps.length ? Math.max(...diskTemps) : null;
    cards.push(kpiCard("Temperature", isNum(m.system_temp_c) ? `${m.system_temp_c.toFixed(0)} °C` : "-",
      `${hottest !== null ? `Hottest disk ${hottest.toFixed(0)} °C` : "System"}${isNum(m.fan_rpm) ? `, fan ${m.fan_rpm.toFixed(0)} RPM` : ""}`, "", "graphs:Temperature"));
  }
  // Headline values a profile marks "kpi" (UPS battery, toner, firewall states).
  for (const [key, info] of Object.entries(data.metric_info || {})) {
    if (info.kpi && isNum(m[key])) cards.push(kpiCard(info.label, profileMetric(key, m[key])[1], info.group || "", "", "latest"));
  }
  document.getElementById("detail-kpis").innerHTML = cards.slice(0, 6).join("");
}

function renderOverview(data, isRefresh) {
  const d = data.device;
  const inv = d.inventory || {};
  const m = Object.fromEntries(data.latest_metrics.map(x => [x.metric_key, x.value]));
  renderOverviewKpis(data, Object.assign({}, m, liveLatest()));
  // Uptime card (availability.js); refreshed with the page, at most once a minute.
  if (typeof loadDeviceAvailability === "function" && (!isRefresh || Date.now() - (renderOverview.availAt || 0) > 60000)) {
    renderOverview.availAt = Date.now();
    loadDeviceAvailability(d.id);
  }

  const pollInterval = d.poll_interval || cachedSettings.default_poll_interval || 60;
  const sysRows = [
    ["System name", inv.sys_name],
    ["Hardware", inv.model],
    ["Firmware", inv.firmware],
    ["Serial number", inv.serial],
    ["Battery replaced", inv.battery_replaced],
    ["Description", inv.sys_descr],
    ["Object ID", inv.sys_object_id],
    ["Location", inv.sys_location],
    ["Contact", inv.sys_contact],
    ["IP address", d.ip_address],
    ["Template", profileNames[d.profile_id] || d.profile_id],
    d.service_port ? ["Check", `TCP connection to port ${d.service_port} and ICMP ping, every ${d.ping_interval || cachedSettings.default_ping_interval || 15} s`]
      : d.snmp === false ? ["Check", `ICMP ping every ${d.ping_interval || cachedSettings.default_ping_interval || 15} s (no SNMP)`]
      : ["SNMP", `${String(d.snmp_version).toUpperCase()} port ${d.snmp_port}`],
    d.service_port || d.snmp === false ? null : ["Polling", `SNMP every ${pollInterval}s, ping every ${d.ping_interval || cachedSettings.default_ping_interval || 15}s`],
    ["Last seen", formatAgo(d.last_seen)],
  ];
  document.getElementById("detail-system").innerHTML = sysRows
    .filter(r => r && r[1] !== undefined && r[1] !== null && r[1] !== "")
    .map(r => `<tr><td>${escapeHtml(r[0])}</td><td>${escapeHtml(r[1])}</td></tr>`).join("");

  const ps = data.ports;
  const stat = (n, label, cls = "") => `<div class="stat-inline ${escapeHtml(cls)}"><div class="stat-num">${escapeHtml(n)}</div><div class="stat-label">${escapeHtml(label)}</div></div>`;
  document.getElementById("detail-port-summary").innerHTML = ps.total
    ? [stat(ps.total, "Total"), stat(ps.up, "Up", "stat-ok"), stat(ps.down, "Down", ps.down ? "stat-bad" : ""), stat(ps.disabled, "Disabled")].join("")
    : `<span class="dim">No physical ports reported.</span>`;
  // A port check has no switch ports: the panel would only say so.
  document.getElementById("detail-port-summary").closest(".panel").classList.toggle("hidden", !!d.service_port || d.snmp === false);

  document.getElementById("detail-recent-events").innerHTML = data.events.length
    ? data.events.map(e => `<tr><td class="dim">${escapeHtml(formatAgo(e.timestamp))}</td><td>${severityPill(e.severity)}</td><td class="text-cell">${escapeHtml(e.message)}</td></tr>`).join("")
    : `<tr><td class="empty-cell">No events recorded yet.</td></tr>`;

  if (!isRefresh || Date.now() - lastGraphRender > 60000) {
    renderChartGrid("overview-charts", overviewDefs(data, null), 6);
  }
}

// --- Ports ---

let portsCache = null;

async function loadPorts(fromCache = false) {
  if (!fromCache || !portsCache) {
    try {
      portsCache = (await api(`/api/devices/${activeDeviceId}/ports`)).ports;
    } catch (err) {
      showToast(`Could not load ports: ${err.message}`, "error");
      return;
    }
  }
  const showAll = document.getElementById("ports-all").checked;
  const filter = document.getElementById("ports-filter").value.trim().toLowerCase();
  const live = liveRatesNow();
  const rows = portsCache.filter(r =>
    (showAll || r.kind === "port" || r.kind === "guest") &&
    (!filter || [r.label, r.alias, r.descr, r.mac, r.oper_text, r.ssid].some(v => String(v || "").toLowerCase().includes(filter))))
    .map(r => (live[r.if_index] ? Object.assign({}, r, live[r.if_index]) : r));

  const rowHtml = r => {
    const idx = escapeHtml(r.if_index);
    const disabled = r.admin === 2;
    const statusText = disabled ? "disabled" : r.oper_text;
    const statusCls = disabled ? "status-unknown" : r.oper === 1 ? "status-ok" : "status-err";
    const speedBps = (r.speed_mbps || 0) * 1e6;
    const util = speedBps && (isNum(r.in_bps) || isNum(r.out_bps)) ? 100 * Math.max(r.in_bps || 0, r.out_bps || 0) / speedBps : null;
    const errs = (r.in_errors || 0) + (r.out_errors || 0);
    const errDelta = (r.in_errors_delta || 0) + (r.out_errors_delta || 0);
    const disc = (r.in_discards || 0) + (r.out_discards || 0);
    const main = `
      <tr class="port-row" data-ifindex="${idx}">
        <td>${idx}</td>
        <td class="text-cell"><strong>${escapeHtml(r.label)}</strong></td>
        <td class="text-cell">${escapeHtml(r.alias && r.alias !== r.label ? r.alias : "")}</td>
        <td class="text-cell dim">${escapeHtml(r.kind)}</td>
        <td data-sort="${disabled ? 3 : r.oper === 1 ? 0 : 2}"><span class="status-pill ${statusCls}">${escapeHtml(statusText)}</span></td>
        <td data-sort="${escapeHtml(r.speed_mbps || "")}">${formatSpeed(r.speed_mbps)}</td>
        <td data-sort="${isNum(r.in_bps) ? r.in_bps : ""}">${formatBps(r.in_bps)}</td>
        <td data-sort="${isNum(r.out_bps) ? r.out_bps : ""}">${formatBps(r.out_bps)}</td>
        <td data-sort="${isNum(util) ? util : ""}" class="bar-cell">${barHtml(util, isNum(util) ? (util < 1 ? util.toFixed(2) : util.toFixed(0)) + " %" : null)}</td>
        <td data-sort="${isNum(r.in_octets) ? r.in_octets : ""}">${formatBytes(r.in_octets)}</td>
        <td data-sort="${isNum(r.out_octets) ? r.out_octets : ""}">${formatBytes(r.out_octets)}</td>
        <td data-sort="${escapeHtml(errs)}">${escapeHtml(errs.toLocaleString())}${errDelta > 0 ? `<span class="badge-delta">+${escapeHtml(errDelta)}</span>` : ""}</td>
        <td data-sort="${escapeHtml(disc)}">${escapeHtml(disc.toLocaleString())}</td>
        <td data-sort="${escapeHtml(r.mac_count || "")}">${escapeHtml(r.mac_count || "-")}</td>
        <td>${escapeHtml(r.mtu ?? "-")}</td>
        <td>${escapeHtml(r.mac || "-")}</td>
      </tr>`;
    if (!expandedPorts.has(String(r.if_index))) return main;
    return main + `<tr class="detail-row"><td colspan="16"><div class="chart-host" data-port-chart="${idx}"></div></td></tr>`;
  };

  let html;
  if (showAll) {
    // Grouped view: one heading row per group, rows sorted inside their group.
    const groups = new Map();
    rows.slice().sort((a, b) => (a.group_rank - b.group_rank) || (a.if_index - b.if_index))
      .forEach(r => { if (!groups.has(r.group)) groups.set(r.group, []); groups.get(r.group).push(r); });
    html = Array.from(groups.entries()).map(([name, members]) => {
      const up = members.filter(m => m.oper === 1).length;
      const collapsed = collapsedGroups.has(name);
      const head = `<tr class="group-row ${collapsed ? "collapsed" : ""}" data-group="${escapeHtml(name)}">` +
        `<td colspan="16">${escapeHtml(name)}<span class="dim">${members.length} interface${members.length === 1 ? "" : "s"}, ${up} up</span></td></tr>`;
      return head + (collapsed ? "" : members.map(rowHtml).join(""));
    }).join("");
  } else {
    html = rows.map(rowHtml).join("");
  }
  fillTable("ports-body", html, "No interfaces match.", 16);

  document.querySelectorAll("[data-port-chart]").forEach(async host => {
    const idx = host.dataset.portChart;
    const keys = [`if.${idx}.in_bps`, `if.${idx}.out_bps`];
    try {
      const cached = portHistoryCache[idx];
      const hist = cached && Date.now() - cached.at < 60000 ? cached.data
        : await api(`/api/devices/${activeDeviceId}/history?keys=${keys.map(encodeURIComponent).join(",")}&hours=24`);
      portHistoryCache[idx] = { at: cached && cached.data === hist ? cached.at : Date.now(), data: hist };
      host._source = { deviceId: activeDeviceId, g: { series: [[keys[0], "In"], [keys[1], "Out"]], fmt: "bps" }, hours: 24, compare: false };
      lineChart(host, [
        { key: keys[0], label: "In", points: hist.series[keys[0]] },
        { key: keys[1], label: "Out", points: hist.series[keys[1]] },
      ], { hours: 24, fmt: formatBps, deviceId: activeDeviceId });
    } catch (err) {
      host.innerHTML = `<div class="chart-empty">${escapeHtml(err.message)}</div>`;
    }
  });
}
let portHistoryCache = {};

// --- Neighbours ---

let neighboursCache = null;
GROUP_RERENDER["tbl-neighbours"] = () => loadNeighbours(true);

async function loadNeighbours(fromCache = false) {
  if (!fromCache || !neighboursCache) {
    try {
      neighboursCache = (await api(`/api/devices/${activeDeviceId}/neighbours`)).neighbours;
    } catch (err) {
      showToast(`Could not load neighbours: ${err.message}`, "error");
      return;
    }
  }
  const hasFdb = neighboursCache.some(n => n.source === "fdb");
  document.getElementById("neighbours-note").textContent = hasFdb
    ? "MAC addresses learned on each switch port. IPs come from the gateway ARP table."
    : "Hosts in this device's ARP table. 'Also seen on' shows the switch port each host is plugged into.";
  const filter = document.getElementById("neighbours-filter").value.trim().toLowerCase();
  const rows = neighboursCache.filter(n => !filter ||
    [n.mac, n.ip, n.port, n.device, n.seen_on].some(v => String(v || "").toLowerCase().includes(filter)));
  const neighbourRow = n => `
    <tr>
      <td>${escapeHtml(n.mac)}</td>
      <td>${escapeHtml(n.ip || "-")}</td>
      <td class="text-cell">${escapeHtml(n.device || "")}</td>
      <td>${escapeHtml(n.vlan ?? "-")}</td>
      <td class="text-cell" data-sort="${escapeHtml(String(n.if_index).padStart(6, "0"))}">${escapeHtml(n.port)}</td>
      <td class="text-cell dim">${escapeHtml(n.seen_on || "")}</td>
      <td class="dim">${escapeHtml(n.source.toUpperCase())}</td>
    </tr>`;
  fillTable("neighbours-body", groupedRows("tbl-neighbours", 7, rows,
    n => [n.port || "Unknown port", Number(n.if_index) || 0], neighbourRow,
    items => `${items.length} host${items.length === 1 ? "" : "s"}${items.some(i => i.device) ? ", includes " + items.filter(i => i.device).map(i => i.device).join(", ") : ""}`),
    "No neighbours match.", 7);
}

// --- Wireless ---

const BAND_NAME = { ng: "2.4 GHz", na: "5 GHz" };
GROUP_RERENDER["tbl-ssids"] = () => loadWireless();

async function loadWireless() {
  let data;
  try {
    data = await api(`/api/devices/${activeDeviceId}/wireless`);
  } catch (err) {
    showToast(`Could not load wireless data: ${err.message}`, "error");
    return;
  }
  const ssids = data.ssids || [];
  fillTable("radios-body", (data.radios || []).map(r => {
    const inBand = ssids.filter(s => s.band === r.band);
    const clients = inBand.reduce((a, s) => a + (s.clients || 0), 0);
    const first = inBand[0] || {};
    return `
      <tr>
        <td>${escapeHtml(r.name)}</td>
        <td class="text-cell">${escapeHtml(BAND_NAME[r.band] || r.band)}</td>
        <td>${escapeHtml(first.channel ?? "-")}</td>
        <td data-sort="${escapeHtml(first.tx_power_dbm ?? "")}">${isNum(first.tx_power_dbm) ? first.tx_power_dbm + " dBm" : "-"}</td>
        <td>${escapeHtml(clients)}</td>
        <td data-sort="${escapeHtml(r.util_pct ?? "")}" class="bar-cell">${barHtml(r.util_pct)}</td>
        <td data-sort="${escapeHtml(r.util_rx_pct ?? "")}">${pct(r.util_rx_pct)}</td>
        <td data-sort="${escapeHtml(r.util_tx_pct ?? "")}">${pct(r.util_tx_pct)}</td>
        <td data-sort="${escapeHtml(r.other_bss_pct ?? "")}">${pct(r.other_bss_pct)}</td>
        <td data-sort="${escapeHtml(r.rx_packets ?? "")}">${isNum(r.rx_packets) ? Number(r.rx_packets).toLocaleString() : "-"}</td>
        <td data-sort="${escapeHtml(r.tx_packets ?? "")}">${isNum(r.tx_packets) ? Number(r.tx_packets).toLocaleString() : "-"}</td>
      </tr>`;
  }).join(""), "No radios reported.", 11);

  const ssidRow = s => `
    <tr>
      <td class="text-cell"><strong>${escapeHtml(s.ssid)}</strong></td>
      <td class="text-cell">${escapeHtml(BAND_NAME[s.band] || s.band)}</td>
      <td>${escapeHtml(s.bssid)}</td>
      <td>${escapeHtml(s.channel ?? "-")}</td>
      <td>${escapeHtml(s.clients ?? "-")}</td>
      <td data-sort="${isNum(s.rx_bps) ? s.rx_bps : ""}">${formatBps(s.rx_bps)}</td>
      <td data-sort="${isNum(s.tx_bps) ? s.tx_bps : ""}">${formatBps(s.tx_bps)}</td>
      <td data-sort="${escapeHtml(s.rx_bytes ?? "")}">${formatBytes(s.rx_bytes)}</td>
      <td data-sort="${escapeHtml(s.tx_bytes ?? "")}">${formatBytes(s.tx_bytes)}</td>
      <td data-sort="${escapeHtml(s.tx_power_dbm ?? "")}">${isNum(s.tx_power_dbm) ? s.tx_power_dbm + " dBm" : "-"}</td>
      <td class="dim">${escapeHtml(s.name)}</td>
    </tr>`;
  fillTable("ssids-body", groupedRows("tbl-ssids", 11, ssids, x => [x.ssid || "(hidden)", 0], ssidRow,
    items => `${items.map(i => BAND_NAME[i.band] || i.band).join(" + ")}, ${items.reduce((a, i) => a + (i.clients || 0), 0)} clients`),
    "No SSIDs reported.", 11);
  // Per device, when UniFi is connected (lan.js).
  if (typeof renderWifiClients === "function") renderWifiClients(data);

  // Approximate client list: hosts learned on the switch port the AP is plugged into.
  const ph = data.port_hosts || { hosts: [] };
  const note = document.getElementById("clients-note");
  const clientCount = ssids.reduce((a, s) => a + (s.clients || 0), 0);
  note.classList.remove("warn");
  if (!ph.port) {
    note.textContent = "This access point was not found on a monitored switch port, so no client list can be built. UniFi APs do not report individual clients over SNMP.";
  } else {
    const shared = ph.hosts.length > clientCount + 2;
    note.textContent = `Hosts learned on ${ph.port}. UniFi APs report only client counts over SNMP, so this list comes from the switch MAC table joined to the gateway ARP table: no signal strength or band.` +
      (shared ? ` That port carries ${ph.hosts.length} hosts for ${clientCount} wireless clients, so it also has other devices behind it (for example a downstream switch) and this list includes them.` : "");
    if (shared) note.classList.add("warn");
  }
  fillTable("clients-body", ph.hosts.map(h => `
    <tr>
      <td>${escapeHtml(h.mac)}</td>
      <td>${escapeHtml(h.ip || "-")}</td>
      <td class="text-cell">${escapeHtml(h.device || "")}</td>
      <td>${escapeHtml(h.vlan ?? "-")}</td>
    </tr>`).join(""), "No hosts found.", 4);
  if (pendingFocus === "clients") {
    document.getElementById("clients-panel").scrollIntoView({ behavior: "smooth" });
    pendingFocus = null;
  }
}

// --- Storage ---

GROUP_RERENDER["tbl-storage"] = () => loadStorage();

// --- Fix SNMP (Linux hosts) ---

let fixSnmp = { device: null, sha: null };

async function openFixSnmp(device) {
  if (!autoData) await loadAutomation();
  fixSnmp = { device, sha: null };
  document.getElementById("fixsnmp-title").textContent = `Fix SNMP on ${device.hostname}`;
  const creds = (autoData && autoData.credentials) || [];
  document.getElementById("fixsnmp-cred").innerHTML = creds.map(c => `<option value="${Number(c.id)}">${escapeHtml(c.name)} (${escapeHtml(c.username || "root")})</option>`).join("");
  const hostKey = ((autoData && autoData.devices) || []).some(x => x.id === device.id && x.host_key);
  // No credential yet: the form would only show an empty list, so point to adding one instead.
  const none = !creds.length;
  // Without Use stored credentials only Copy as commands applies: no form, no Preview, no note.
  const useCred = can("credentials.use");
  document.getElementById("fixsnmp-nocred").classList.toggle("hidden", !none || !useCred);
  document.getElementById("fixsnmp-form").classList.toggle("hidden", none || !useCred);
  document.getElementById("btn-fixsnmp-preview").classList.toggle("hidden", none || !useCred);
  document.getElementById("fixsnmp-hostkey").classList.toggle("hidden", none || !useCred || !!hostKey);
  document.getElementById("fixsnmp-changes").innerHTML = "";
  for (const id of ["fixsnmp-file", "fixsnmp-script", "fixsnmp-result", "btn-fixsnmp-apply"]) hide(document.getElementById(id));
  // Copy as commands needs no credential: the steps can be pasted into the host by hand.
  show(document.getElementById("btn-fixsnmp-copy"));
  show(document.getElementById("modal-fixsnmp"));
}

/** True for an error that means SSH did not let the monitor in (refused, no answer, nothing listening, login refused). */
const isSshLoginFailure = msg => /could not log in over SSH|did not answer on the SSH port|nothing listens for SSH|refused the login|Permission denied|Connection refused|timed out/i.test(msg || "");

/** Fetches the SSH setup command for a host, copies it and returns it (null on failure). */
async function copySshSetup(deviceId, credentialId) {
  try {
    const r = await api(`/api/devices/${deviceId}/ssh-setup`, { method: "POST", body: { credential_id: credentialId || null } });
    // A password setup opens the host to password logins from this monitor: say so plainly before copying.
    if (r.kind !== "key" && !(await confirmDialog({
      title: "This turns on password login for root",
      message: `These commands let anyone connecting from this monitor's address (${r.monitor_ip}) log in to this host over SSH with a password, including as root. If this monitor were ever taken over, its address could be used to try passwords on this host. An SSH key credential avoids this.`,
      confirmLabel: "Copy the commands",
    }))) return null;
    try {
      await navigator.clipboard.writeText(r.script);
      showToast("Copied. Open the host's console as root (Proxmox: the guest's Console), paste and press Enter. Then try again here.", "success", 9000);
    } catch (e) {
      showToast("Select the command below and copy it (the browser blocked clipboard access).", "info");
    }
    return r.script;
  } catch (err) {
    showToast(`Could not build the command: ${err.message}`, "error");
    return null;
  }
}

function initFixSnmp() {
  const body = () => ({ credential_id: can("credentials.use") ? parseInt(document.getElementById("fixsnmp-cred").value, 10) || null : null,
    ssh_port: parseInt(document.getElementById("fixsnmp-port").value, 10) || 22 });
  document.getElementById("btn-close-fixsnmp").addEventListener("click", () => hide(document.getElementById("modal-fixsnmp")));
  document.getElementById("btn-fixsnmp-hostkey").addEventListener("click", async () => {
    await openHostKeys({ device_ids: [fixSnmp.device.id], ssh_port: body().ssh_port });
    hide(document.getElementById("fixsnmp-hostkey"));
  });
  document.getElementById("btn-fixsnmp-preview").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    try {
      const r = await api(`/api/devices/${fixSnmp.device.id}/fix-snmp`, { method: "POST", body: { ...body(), mode: "preview" } });
      fixSnmp.sha = r.sha;
      document.getElementById("fixsnmp-changes").innerHTML = r.unchanged ? "<li>Already configured: nothing to change.</li>"
        : r.changes.map(c => `<li>${escapeHtml(c)}</li>`).join("");
      // The whole new file as it will be written (no diff markers), community hidden.
      document.getElementById("fixsnmp-diff").textContent = r.content;
      document.getElementById("fixsnmp-file").classList.toggle("hidden", r.unchanged);
      hide(document.getElementById("fixsnmp-script"));
      document.getElementById("btn-fixsnmp-apply").classList.toggle("hidden", r.unchanged);
      document.getElementById("btn-fixsnmp-apply").disabled = false;
      show(document.getElementById("btn-fixsnmp-copy"));
      hide(document.getElementById("btn-fixsnmp-sshsetup"));
    } catch (err) {
      showToast(`Preview failed: ${err.message}`, "error");
      // Only when the SSH login itself failed: offer the command that sets SSH up on the host.
      document.getElementById("btn-fixsnmp-sshsetup").classList.toggle("hidden", !isSshLoginFailure(err.message));
    } finally {
      btn.disabled = false;
    }
  });
  document.getElementById("btn-fixsnmp-addcred").addEventListener("click", () => {
    hide(document.getElementById("modal-fixsnmp"));
    window.location.hash = "#/automation";
    // The Automation page loads its lists first; then the Add Credential window opens on top.
    setTimeout(() => openCredentialModal(null), 300);
  });
  document.getElementById("btn-fixsnmp-sshsetup").addEventListener("click", async () => {
    const out = await copySshSetup(fixSnmp.device.id, body().credential_id);
    if (out) {
      document.getElementById("fixsnmp-script-text").textContent = out;
      show(document.getElementById("fixsnmp-script"));
    }
  });
  document.getElementById("btn-fixsnmp-copy").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    try {
      const r = await api(`/api/devices/${fixSnmp.device.id}/fix-snmp`, { method: "POST", body: { ...body(), mode: "script" } });
      document.getElementById("fixsnmp-script-text").textContent = r.script;
      show(document.getElementById("fixsnmp-script"));
      try {
        await navigator.clipboard.writeText(r.script);
        showToast("Commands copied. Paste them into the host's shell.", "success");
      } catch (err) {
        showToast("Select the commands below and copy them (the browser blocked clipboard access).", "info");
      }
    } catch (err) {
      showToast(`Could not build the commands: ${err.message}`, "error");
    } finally {
      btn.disabled = false;
    }
  });
  document.getElementById("btn-fixsnmp-apply").addEventListener("click", async (ev) => {
    // Read before the await: the browser clears currentTarget once the click has been dispatched.
    const btn = ev.currentTarget;
    if (!(await confirmDialog({ title: `Apply on ${fixSnmp.device.hostname}?`,
      message: "Replaces snmpd.conf with the file shown (a backup is kept) and restarts snmpd.", confirmLabel: "Apply" }))) return;
    btn.disabled = true;
    const result = document.getElementById("fixsnmp-result");
    result.className = "dim";
    result.textContent = "Applying, restarting snmpd and checking the result...";
    show(result);
    try {
      const r = await api(`/api/devices/${fixSnmp.device.id}/fix-snmp`, { method: "POST", body: { ...body(), mode: "apply", expected_sha: fixSnmp.sha } });
      result.className = r.success ? "text-ok" : "text-warn";
      result.textContent = `${r.message} Backup: ${r.backup}`;
      showToast(r.success ? "SNMP fixed" : "Change rolled back", r.success ? "success" : "error");
      if (r.success) loadDeviceDetail(fixSnmp.device.id, true);
    } catch (err) {
      result.className = "text-err fixsnmp-error";
      result.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });
}

async function loadHealth() {
  let data;
  try {
    data = await api(`/api/devices/${activeDeviceId}/health`);
  } catch (err) {
    showToast(`Could not load health: ${err.message}`, "error");
    return;
  }
  const reading = h => {
    if (isNum(h.pct)) return [h.pct, barHtml(h.pct, `${h.pct.toFixed(0)} %`, true)];
    // Printer-MIB levels: -3 means some remains but the agent cannot measure it, -2 unknown.
    if (h.level === -3) return [-3, "Some remaining"];
    if (isNum(h.value)) return [h.value, escapeHtml(UNIT_FORMAT[h.unit] ? UNIT_FORMAT[h.unit](h.value) : String(h.value))];
    return ["", "-"];
  };
  fillTable("health-body", data.health.map(h => {
    const [sortVal, text] = reading(h);
    const cls = h.ok === false ? (["critical", "high"].includes(h.severity) ? "status-err" : "status-warn") : h.ok ? "status-ok" : "";
    const status = h.status ?? (h.ok === false ? "Low" : h.ok ? "OK" : "-");
    return `
      <tr>
        <td class="text-cell"><strong>${escapeHtml(h.name ?? "-")}</strong></td>
        <td>${escapeHtml(h.kind || "-")}</td>
        <td>${cls ? `<span class="status-pill ${cls}">${escapeHtml(status)}</span>` : escapeHtml(status)}</td>
        <td data-sort="${escapeHtml(sortVal)}" class="${isNum(h.pct) ? "bar-cell" : ""}">${text}</td>
      </tr>`;
  }).join(""), "No components reported.", 4);
}

let softwareData = null;

async function loadSoftware() {
  try {
    softwareData = await api(`/api/devices/${activeDeviceId}/software`);
  } catch (err) {
    showToast(`Could not load software: ${err.message}`, "error");
    return;
  }
  renderSoftware();
}

function renderSoftware() {
  if (!softwareData) return;
  const q = document.getElementById("software-filter").value.trim().toLowerCase();
  const rows = softwareData.software.filter(r => !q || `${r.name} ${r.version}`.toLowerCase().includes(q));
  const updated = softwareData.software.length ? Math.max(...softwareData.software.map(r => r.updated_at)) : 0;
  document.getElementById("software-note").textContent =
    `${softwareData.software.length} installed${updated ? `, checked ${formatSince(updated)} ago (hourly)` : ""}`;
  fillTable("software-changes-body", softwareData.events.map(e => `<tr>
      <td class="text-cell">${escapeHtml(new Date(e.timestamp * 1000).toLocaleString())}</td>
      <td class="text-cell">${escapeHtml(e.message)}</td>
    </tr>`).join(""), "No changes since monitoring began.", 2);
  document.getElementById("software-changes-panel").classList.toggle("hidden", !softwareData.events.length);
  fillTable("software-body", rows.map(r => `<tr>
      <td class="text-cell">${escapeHtml(r.name)}</td>
      <td class="text-cell">${escapeHtml(r.version || "-")}</td>
      <td>${escapeHtml(r.arch || "-")}</td>
    </tr>`).join(""), "No software matches.", 3);
}

let processData = null;

async function loadProcesses() {
  try {
    processData = await api(`/api/devices/${activeDeviceId}/processes`);
  } catch (err) {
    showToast(`Could not load processes: ${err.message}`, "error");
    return;
  }
  renderProcesses();
}

function renderProcesses() {
  if (!processData) return;
  const q = document.getElementById("processes-filter").value.trim().toLowerCase();
  const match = n => !q || n.toLowerCase().includes(q);
  const watched = new Set(processData.watches.map(w => `${w.kind}:${w.name}`));
  const box = (kind, name) => `<input type="checkbox" data-perm="devices.manage" data-watch-kind="${escapeHtml(kind)}" data-watch-name="${escapeHtml(name)}"${watched.has(`${kind}:${name}`) ? " checked" : ""} aria-label="Watch ${escapeHtml(name)}">`;
  const procs = new Map(processData.processes.map(p => [p.name, p]));
  const svcs = new Map(processData.services.map(x => [x.name, x]));

  fillTable("watches-body", processData.watches.map(w => {
    const row = (w.kind === "process" ? procs : svcs).get(w.name);
    const ok = row && (w.kind === "process" || row.state === "running");
    const state = !row ? "not running" : w.kind === "process" ? `running (${row.count})` : row.state;
    return `<tr>
      <td class="watch-cell">${box(w.kind, w.name)}</td>
      <td class="text-cell"><strong>${escapeHtml(w.name)}</strong></td>
      <td>${escapeHtml(w.kind)}</td>
      <td><span class="status-pill ${ok ? "status-ok" : "status-err"}">${escapeHtml(state)}</span></td>
    </tr>`;
  }).join(""), "Nothing watched yet.", 4);
  // The Watched panel appears once something is ticked (the toolbar hint explains how).
  document.getElementById("watches-panel").classList.toggle("hidden", !processData.watches.length);

  document.getElementById("services-panel").classList.toggle("hidden", !processData.services.length);
  fillTable("services-body", processData.services.filter(x => match(x.name)).map(x => `<tr>
      <td class="watch-cell">${box("service", x.name)}</td>
      <td class="text-cell">${escapeHtml(x.name)}</td>
      <td>${escapeHtml(x.state)}</td>
    </tr>`).join(""), "No services match.", 3);
  fillTable("processes-body", processData.processes.filter(p => match(p.name)).map(p => `<tr>
      <td class="watch-cell">${box("process", p.name)}</td>
      <td class="text-cell">${escapeHtml(p.name)}</td>
      <td data-sort="${escapeHtml(p.count)}">${escapeHtml(p.count)}</td>
    </tr>`).join(""), "No processes match.", 3);
}

async function loadStorage() {
  let data;
  try {
    data = await api(`/api/devices/${activeDeviceId}/storage`);
  } catch (err) {
    showToast(`Could not load storage: ${err.message}`, "error");
    return;
  }
  const storageRow = s => `
    <tr>
      <td class="text-cell"><strong>${escapeHtml(s.descr)}</strong></td>
      <td class="text-cell">${escapeHtml(s.kind)}</td>
      <td data-sort="${escapeHtml(s.size_bytes)}">${formatBytes(s.size_bytes)}</td>
      <td data-sort="${escapeHtml(s.used_bytes)}">${formatBytes(s.used_bytes)}</td>
      <td data-sort="${s.size_bytes - s.used_bytes}">${formatBytes(s.size_bytes - s.used_bytes)}</td>
      <td data-sort="${escapeHtml(s.used_pct)}" class="bar-cell">${barHtml(s.used_pct)}</td>
    </tr>`;
  const storageGroup = s => (["ram", "virtual"].includes(s.kind) || /memory|swap/i.test(s.descr))
    ? ["Memory and swap", 2] : ["Filesystems", 1];
  // On a NAS the Volumes and Disks tables are the useful view; the host list is
  // mostly internal mounts, so start it collapsed (once per page load).
  if ((data.volumes || []).length && !collapsedByTable["tbl-storage"]) {
    collapsedByTable["tbl-storage"] = new Set(["Filesystems", "Memory and swap"]);
  }
  fillTable("storage-body", groupedRows("tbl-storage", 6, data.storage, storageGroup, storageRow,
    items => `${items.length} entr${items.length === 1 ? "y" : "ies"}`), "No storage reported.", 6);
  document.getElementById("hrstorage-panel").classList.toggle("hidden", !data.storage.length && (data.disks.length || data.volumes.length));

  const vols = data.volumes || [];
  document.getElementById("volumes-panel").classList.toggle("hidden", !vols.length);
  fillTable("volumes-body", vols.map(v => {
    const ok = "ok" in v ? v.ok : String(v.status).toLowerCase() === "ready";
    return `
      <tr>
        <td class="text-cell"><strong>${escapeHtml(v.descr)}</strong></td>
        <td>${escapeHtml(v.filesystem || "-")}</td>
        <td><span class="status-pill ${ok ? "status-ok" : "status-err"}">${escapeHtml(v.status || "unknown")}</span></td>
        <td data-sort="${escapeHtml(v.size_bytes)}">${formatBytes(v.size_bytes)}</td>
        <td data-sort="${escapeHtml(v.used_bytes)}">${formatBytes(v.used_bytes)}</td>
        <td data-sort="${v.size_bytes - v.used_bytes}">${formatBytes(v.size_bytes - v.used_bytes)}</td>
        <td data-sort="${escapeHtml(v.used_pct ?? "")}" class="bar-cell">${barHtml(v.used_pct)}</td>
      </tr>`;
  }).join(""), "No volumes reported.", 7);

  const disks = data.disks || [];
  document.getElementById("disks-panel").classList.toggle("hidden", !disks.length);
  const diskLimit = data.limits.disk_temp ?? Infinity;
  fillTable("disks-body", disks.map(d => {
    const good = "ok" in d ? d.ok : String(d.smart).toUpperCase() === "GOOD";
    const hot = isNum(d.temp_c) && d.temp_c >= diskLimit;
    return `
      <tr>
        <td class="text-cell"><strong>${escapeHtml(d.name)}</strong></td>
        <td>${escapeHtml(d.model || "-")}</td>
        <td data-sort="${escapeHtml(d.size_bytes ?? "")}">${isNum(d.size_bytes) ? (d.size_bytes / 1e12).toFixed(2) + " TB" : "-"}</td>
        <td data-sort="${escapeHtml(d.temp_c ?? "")}" class="${hot ? "text-err" : ""}">${isNum(d.temp_c) ? d.temp_c + " °C" : "-"}</td>
        <td><span class="status-pill ${good ? "status-ok" : "status-err"}">${escapeHtml(d.smart || "unknown")}</span></td>
      </tr>`;
  }).join(""), "No disks reported.", 5);

  const sensors = data.sensors || [];
  document.getElementById("sensors-panel").classList.toggle("hidden", !sensors.length);
  const sensorLimit = data.limits.sensor_temp ?? Infinity;
  fillTable("sensors-body", sensors.map(t => `
    <tr>
      <td class="text-cell"><strong>${escapeHtml(t.name)}</strong></td>
      <td data-sort="${escapeHtml(t.temp_c)}" class="${t.temp_c >= sensorLimit ? "text-err" : ""}">${t.temp_c.toFixed(1)} °C</td>
    </tr>`).join(""), "No sensors reported.", 2);

  // "Full in N days" (forecast.py, lan.js).
  if (typeof renderForecasts === "function") renderForecasts(lastDetail);

  const dio = data.diskio || [];
  document.getElementById("diskio-panel").classList.toggle("hidden", !dio.length);
  const rate = v => isNum(v) ? `${formatBytes(v)}/s` : "-";
  fillTable("diskio-body", dio.map(d => `
    <tr>
      <td class="text-cell"><strong>${escapeHtml(d.name)}</strong></td>
      <td data-sort="${escapeHtml(d.read_Bps ?? "")}">${rate(d.read_Bps)}</td>
      <td data-sort="${escapeHtml(d.write_Bps ?? "")}">${rate(d.write_Bps)}</td>
      <td data-sort="${escapeHtml(d.read_bytes ?? "")}">${isNum(d.read_bytes) ? formatBytes(d.read_bytes) : "-"}</td>
      <td data-sort="${escapeHtml(d.written_bytes ?? "")}">${isNum(d.written_bytes) ? formatBytes(d.written_bytes) : "-"}</td>
    </tr>`).join(""), "No disk counters reported.", 5);
}

// --- Latest Data & Events ---

const PROFILE_GROUP_RANK = { Power: 3, "Hardware health": 4, Printing: 7, Firewall: 7 };

function metricCategory(x) {
  const k = x.metric_key;
  const info = lastDetail && lastDetail.metric_info && lastDetail.metric_info[k];
  if (info && info.group) return [info.group, PROFILE_GROUP_RANK[info.group] ?? 8];
  if (k === "icmp_ping_ms" || k === "uptime_seconds") return ["Reachability", 1];
  if (/^(cpu|mem)_/.test(k)) return ["CPU and memory", 2];
  if (/^(clients|radio)_/.test(k)) return ["Wireless", 3];
  if (/temp|fan/.test(k)) return ["Temperature and cooling", 4];
  if (/^(disk|vol|dio)\./.test(k)) return ["Disks and volumes", 5];
  if (/^(wan|ports|uplink|tcp)_/.test(k) || k.endsWith("_octets")) return ["Network", 6];
  return ["Other", 9];
}
GROUP_RERENDER["tbl-latest"] = () => lastDetail && renderLatest(lastDetail);

function renderLatest(data) {
  const latestRow = x => {
    const [label, valStr] = describeMetric(x.metric_key, x.value);
    const delta = isNum(x.prev_value) ? x.value - x.prev_value : null;
    const interval = x.prev_timestamp ? x.timestamp - x.prev_timestamp : null;
    return `
      <tr>
        <td class="text-cell" title="${escapeHtml(x.metric_key)}"><strong>${escapeHtml(label)}</strong></td>
        <td data-sort="${escapeHtml(String(x.value))}">${escapeHtml(valStr)}</td>
        <td data-sort="${isNum(delta) ? delta : ""}">${formatChange(x.metric_key, delta)}</td>
        <td data-sort="${escapeHtml(x.timestamp)}" class="dim">${escapeHtml(formatAgo(x.timestamp))}</td>
        <td data-sort="${interval ?? ""}" class="dim">${interval ? interval + "s" : "-"}</td>
      </tr>`;
  };
  fillTable("latest-body", groupedRows("tbl-latest", 5, data.latest_metrics, metricCategory, latestRow,
    items => `${items.length} metric${items.length === 1 ? "" : "s"}`), "No metrics polled yet.", 5);
}

function eventRows(events, withDevice) {
  return events.map(e => `
    <tr>
      <td data-sort="${escapeHtml(e.timestamp)}">${escapeHtml(formatTime(e.timestamp))}</td>
      ${withDevice ? `<td class="text-cell">${e.device_id
        ? `<a class="device-link" href="#/device/${Number(e.device_id)}">${escapeHtml(e.hostname)}</a>`
        : `<span class="dim">${e.actor ? escapeHtml(e.actor) : "System"}</span>`}</td>` : ""}
      <td data-sort="${Number(SEVERITY_RANK[e.severity] ?? 3)}">${severityPill(e.severity)}</td>
      <td class="text-cell dim">${escapeHtml(e.event_type)}</td>
      <td class="text-cell">${escapeHtml(e.message)}</td>
    </tr>`).join("");
}

async function loadDeviceEvents() {
  try {
    const data = await api(`/api/devices/${activeDeviceId}/events`);
    fillTable("device-events-body", eventRows(data.events, false), "No events recorded yet.", 4);
  } catch (err) {
    showToast(`Could not load events: ${err.message}`, "error");
  }
}

// Event log filters. #/events?device=3&severity=critical opens the log pre-filtered (links from elsewhere).
let eventsPage = 1;
let eventsDevicesLoaded = false;

function eventFilters() {
  const val = id => document.getElementById(id).value;
  const p = new URLSearchParams();
  if (val("ev-q").trim()) p.set("q", val("ev-q").trim());
  for (const [k, id] of [["device", "ev-device"], ["severity", "ev-severity"], ["type", "ev-type"], ["tag", "ev-tag"]]) if (val(id)) p.set(k, val(id));
  const range = val("ev-range");
  if (range === "custom") {
    // Dates are local midnights; "to" is inclusive, so the bound is the next midnight.
    if (val("ev-from")) p.set("from", Math.floor(new Date(val("ev-from") + "T00:00").getTime() / 1000));
    if (val("ev-to")) p.set("to", Math.floor(new Date(val("ev-to") + "T00:00").getTime() / 1000) + 86400);
  } else if (range) {
    p.set("from", Math.floor(Date.now() / 1000) - Number(range));
  }
  return p;
}

function pagerHtml(page, pages, total, perPage) {
  if (total === 0) return "";
  const first = (page - 1) * perPage + 1;
  const last = Math.min(total, page * perPage);
  const nums = new Set([1, pages, page - 2, page - 1, page, page + 1, page + 2].filter(n => n >= 1 && n <= pages));
  let prev = 0;
  const buttons = [];
  for (const n of [...nums].sort((a, b) => a - b)) {
    if (n - prev > 1) buttons.push(`<span class="pager-gap">...</span>`);
    buttons.push(`<button type="button" class="btn${n === page ? " active" : ""}" data-page="${escapeHtml(n)}"${n === page ? ' aria-current="page"' : ""}>${escapeHtml(n)}</button>`);
    prev = n;
  }
  return `<span class="dim">${first} to ${last} of ${Number(total).toLocaleString()}</span>
    <span class="pager-buttons">
      <button type="button" class="btn" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>Previous</button>
      ${buttons.join("")}
      <button type="button" class="btn" data-page="${Number(page) + 1}" ${page >= pages ? "disabled" : ""}>Next</button>
    </span>`;
}

async function loadEventDevices() {
  if (eventsDevicesLoaded) return;
  const data = await api("/api/devices");
  const sel = document.getElementById("ev-device");
  const keep = sel.value;
  sel.innerHTML = `<option value="">All devices</option>` + data.devices
    .map(d => `<option value="${Number(d.id)}">${escapeHtml(d.hostname)}</option>`).join("");
  sel.value = keep;
  eventsDevicesLoaded = true;
}

async function loadEvents(fromRoute = false) {
  try {
    if (fromRoute) {
      eventsPage = 1;
      await loadEventDevices();
      const q = new URLSearchParams((window.location.hash.split("?")[1]) || "");
      if (q.has("device")) document.getElementById("ev-device").value = q.get("device");
      if (q.has("severity")) document.getElementById("ev-severity").value = q.get("severity");
      if (q.has("type")) document.getElementById("ev-type").value = q.get("type");
    }
    const p = eventFilters();
    p.set("page", eventsPage);
    p.set("per_page", 50);
    const data = await api(`/api/events?${p}`);
    const types = document.getElementById("ev-type");
    const keep = types.value || new URLSearchParams((window.location.hash.split("?")[1]) || "").get("type") || "";
    types.innerHTML = `<option value="">All types</option>` + data.types
      .map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
    types.value = keep;
    const filtered = [...p.keys()].some(k => !["page", "per_page"].includes(k));
    fillTable("events-body", eventRows(data.events, true),
      filtered ? "No events match these filters." : "No events recorded yet.", 5);
    document.getElementById("events-pager").innerHTML = pagerHtml(data.page, data.pages, data.total, data.per_page);
    document.getElementById("ev-clear").classList.toggle("hidden", !filtered);
  } catch (err) {
    showToast(`Could not load events: ${err.message}`, "error");
  }
}

function initEventLog() {
  const form = document.getElementById("events-filters");
  let typing = null;
  const reload = () => { eventsPage = 1; loadEvents(); };
  form.addEventListener("submit", ev => { ev.preventDefault(); reload(); });
  form.addEventListener("change", ev => {
    if (ev.target.id === "ev-range") document.getElementById("ev-dates").classList.toggle("hidden", ev.target.value !== "custom");
    if (ev.target.id !== "ev-q") reload();
  });
  document.getElementById("ev-q").addEventListener("input", () => { clearTimeout(typing); typing = setTimeout(reload, 300); });
  document.getElementById("ev-clear").addEventListener("click", () => {
    form.reset();
    hide(document.getElementById("ev-dates"));
    if (window.location.hash.includes("?")) history.replaceState(null, "", "#/events");
    reload();
  });
  document.getElementById("events-pager").addEventListener("click", ev => {
    const b = ev.target.closest("[data-page]");
    if (!b || b.disabled) return;
    eventsPage = Number(b.dataset.page);
    loadEvents().then(() => document.getElementById("view-events").scrollIntoView({ block: "start" }));
  });
}

// --- Graphs ---

/**
 * Chooses which charts a device gets from the metrics it actually reports,
 * plus one traffic chart per active physical port when the port list is known.
 */
function graphDefinitions(detail, ports) {
  // Latest-only metrics (uptime, raw memory figures, counters) have no history to graph.
  const untracked = new Set(detail.untracked || []);
  const keys = new Set(detail.latest_metrics.map(m => m.metric_key).filter(k => !untracked.has(k)));
  const has = k => keys.has(k);
  const defs = [];
  // fmt is a key of FMT so definitions can be stored in dashboard tile config.
  const add = (title, series, fmt, opts = {}) => {
    const present = series.filter(([k]) => has(k) || k.startsWith("if."));
    // id: the first series' key, stable across renames (the Overview's chosen graphs are stored by it).
    if (present.length) defs.push({ id: present[0][0], title, series: present, fmt, ...opts });
  };

  add("Port connect time", [["tcp_connect_ms", "Connect"]], "ms", { overview: true });
  add("Ping latency", [["icmp_ping_ms", "RTT"]], "ms", { overview: true });
  // Pi-hole (pihole.py) and UniFi (unifi.py) figures, and certificates of website checks.
  add("DNS answer time", [["dns.ms", "Answer"]], "ms", { overview: true });
  add("DNS queries today", [["pihole.queries", "Queries"], ["pihole.blocked", "Blocked"]], "int");
  add("Share blocked", [["pihole.blocked_pct", "Blocked"]], "pct", { max: 100 });
  add("Weak Wi-Fi devices", [["wifi.weak", "Weak signal"]], "int", { step: true });
  add("Wi-Fi experience", [["wifi.experience", "Average"]], "pct", { max: 100 });
  add("Certificate days left", [["tls_days_left", "Days"]], "int");
  // Custom OIDs (customoids.py): one graph each, labelled as the administrator named them.
  for (const [k, info] of Object.entries(detail.metric_info || {})) {
    if (info.custom) add(info.label, [[k, info.label]], "dec2");
  }
  add("CPU usage", [["cpu_usage_pct", "CPU"]], "pct", { max: 100, overview: true });
  add("Load average", [["cpu_load_1m", "1 min"]], "dec2");
  add("Memory used", [["mem_used_pct", "Used"]], "pct", { max: 100 });
  add("Wireless clients", [["clients_2g", "2.4 GHz"], ["clients_5g", "5 GHz"]], "int", { overview: true });
  add("Channel utilisation", [["radio_2g_util_pct", "2.4 GHz"], ["radio_5g_util_pct", "5 GHz"]], "pct", { max: 100 });
  add("Ports up", [["ports_up", "Up"]], "int", { step: true });
  add("TCP connections", [["tcp_established", "Established"]], "int");
  add("Temperature", [["system_temp_c", "System"], ["cpu_temp_c", "CPU"]], "degc");
  add("Fan speed", [["fan_rpm", "Fan"]], "int");
  // NAS disk temperatures and volume usage arrive as indexed keys (disk.1.temp_c, vol.1.used_pct).
  const indexed = (re, label) => Array.from(keys).filter(k => re.test(k)).sort().map(k => [k, label(k.split(".")[1])]);
  add("Disk temperatures", indexed(/^disk\.\d+\.temp_c$/, n => `Disk ${n}`).slice(0, 4), "degc");
  add("Volume usage", indexed(/^vol\.\d+\.used_pct$/, n => `Volume ${n}`).slice(0, 4), "pct", { max: 100 });
  add("Host temperatures", indexed(/^sensor\.\w+\.temp_c$/, n => n.replace(/_/g, " ")).slice(0, 4), "degc", { overview: true });
  Array.from(new Set(Array.from(keys).filter(k => /^dio\./.test(k)).map(k => k.split(".")[1]))).sort().forEach(disk =>
    add(`Disk I/O ${disk}`, [[`dio.${disk}.read_Bps`, "Read"], [`dio.${disk}.write_Bps`, "Write"]], "Bps"));

  // Physical ports first, then Proxmox guest NICs (per-VM / per-container traffic).
  const trafficPorts = (ports || []).filter(p => (p.kind === "port" || p.kind === "guest") && p.oper === 1);
  // Busiest port first so the overview shows the uplink or WAN.
  trafficPorts.sort((a, b) => ((b.in_bps || 0) + (b.out_bps || 0)) - ((a.in_bps || 0) + (a.out_bps || 0)));
  trafficPorts.sort((a, b) => (a.kind === "guest") - (b.kind === "guest"));
  trafficPorts.forEach((p, i) => {
    const guest = p.kind === "guest" && /^(tap|veth)(\d+)i/.exec(p.label);
    const name = guest ? `guest ${guest[2]} (${guest[1] === "tap" ? "VM" : "container"})`
      : p.alias && p.alias !== p.label ? `${p.label} (${p.alias})` : p.label;
    const series = [[`if.${p.if_index}.in_bps`, "In"], [`if.${p.if_index}.out_bps`, "Out"]];
    if (p.wan) series.push([`if.${p.if_index}.in_peak_bps`, "In peak"], [`if.${p.if_index}.out_peak_bps`, "Out peak"]);
    defs.push({ id: series[0][0], title: `Traffic ${name}`, series, fmt: "bps", overview: i === 0 });
  });
  return defs;
}

/** Fetches history for one chart definition and draws it into host. compare overlays the previous period. */
async function drawDefinition(host, deviceId, g, hours, compare = false) {
  try {
    const keys = g.series.map(s => s[0]);
    const hist = await api(`/api/devices/${encodeURIComponent(deviceId)}/history?keys=${keys.map(encodeURIComponent).join(",")}&hours=${encodeURIComponent(hours)}${compare ? "&compare=1" : ""}`);
    const series = g.series.map(([k, label]) => ({ key: k, label, points: hist.series[k] || [] }));
    if (compare && hist.previous) {
      g.series.forEach(([k, label], i) => series.push({ label: `${label} (previous)`, points: hist.previous[k] || [], dashed: true, color: i }));
    }
    // Kept so the graph can be fetched again: zoomed (finer buckets) or enlarged (charts.js).
    host._source = { deviceId, g, hours, compare };
    host._chartBase = null;
    lineChart(host, series, { hours, fmt: FMT[g.fmt] || FMT.dec2, max: g.max, step: g.step, deviceId, compare });
  } catch (err) {
    host.innerHTML = `<div class="chart-empty">${escapeHtml(err.message)}</div>`;
  }
}

/** The Overview tab's graphs: the ones chosen for this device (in that order), or the default set. */
function overviewDefs(detail, ports) {
  const all = graphDefinitions(detail, ports);
  if (Array.isArray(detail.overview_graphs)) return detail.overview_graphs.map(id => all.find(g => g.id === id)).filter(Boolean);
  return all.filter(g => g.overview).slice(0, 4);
}

/** The port list, for traffic graphs; empty when the device has none. */
async function devicePortsForGraphs() {
  if (!lastDetail || !lastDetail.sections.includes("interfaces")) return [];
  try { return (await api(`/api/devices/${activeDeviceId}/ports`)).ports; } catch (err) { return []; }
}

async function saveOverviewGraphs(ids) {
  const r = await api(`/api/devices/${activeDeviceId}/overview`, { method: "PUT", body: { graphs: ids } });
  lastDetail.overview_graphs = r.overview_graphs;
  lastGraphRender = 0;
}

/** "On overview" on a graph (Graphs tab, Custom SNMP tab): adds it to the Overview or takes it off. */
async function toggleOverviewGraph(id, button) {
  const ports = await devicePortsForGraphs();
  const now = overviewDefs(lastDetail, ports).map(g => g.id);
  const next = now.includes(id) ? now.filter(x => x !== id) : now.concat(id);
  if (next.length > 12) { showToast("The Overview shows up to 12 graphs: take one off first.", "error"); return; }
  try {
    await saveOverviewGraphs(next);
    markOverviewButtons(next);
    showToast(now.includes(id) ? "Taken off the Overview." : "Added to the Overview.", "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

function markOverviewButtons(ids) {
  document.querySelectorAll("[data-overview-pin]").forEach(b => {
    const on = ids.includes(b.dataset.overviewPin);
    b.classList.toggle("on", on);
    b.setAttribute("aria-pressed", String(on));
    b.textContent = on ? "On overview" : "Add to overview";
  });
}

/** Overview, Choose graphs: every graph this device has, ticked when it is on the Overview. */
async function chooseOverviewGraphs() {
  const ports = await devicePortsForGraphs();
  const all = graphDefinitions(lastDetail, ports);
  const chosen = overviewDefs(lastDetail, ports).map(g => g.id);
  const order = chosen.concat(all.map(g => g.id).filter(id => !chosen.includes(id)));
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog overview-chooser" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Graphs on the Overview</span></div>
    <div class="modal-body">
      <div class="dialog-message">Tick the graphs to show on ${escapeHtml(lastDetail.device.hostname)}'s Overview, up to 12. The Graphs tab keeps showing all of them.</div>
      <div class="overview-pick">${order.map(id => all.find(g => g.id === id)).filter(Boolean).map(g =>
        `<label class="checkbox-label"><input type="checkbox" value="${escapeHtml(g.id)}"${chosen.includes(g.id) ? " checked" : ""}> ${escapeHtml(g.title)}</label>`).join("")
        || `<div class="dim">No graphs yet: they appear once the device has been polled.</div>`}</div>
      <div class="form-error hidden" data-err></div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn" data-default${Array.isArray(lastDetail.overview_graphs) ? "" : " disabled"}>Use the default</button>
      <span class="topbar-spacer"></span>
      <button type="button" class="btn" data-x>Cancel</button>
      <button type="submit" class="btn btn-primary">Save</button>
    </div></form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  const close = () => back.remove();
  const save = async ids => {
    try {
      await saveOverviewGraphs(ids);
      close();
      renderOverview(lastDetail, false);
    } catch (err) {
      const e = form.querySelector("[data-err]");
      e.textContent = err.message;
      e.classList.remove("hidden");
    }
  };
  form.querySelector("[data-x]").addEventListener("click", close);
  form.querySelector("[data-default]").addEventListener("click", () => save(null));
  back.addEventListener("keydown", ev => { if (ev.key === "Escape") close(); });
  form.addEventListener("submit", ev => {
    ev.preventDefault();
    const ids = [...form.querySelectorAll("input:checked")].map(i => i.value);
    if (ids.length > 12) {
      const e = form.querySelector("[data-err]");
      e.textContent = `${ids.length} ticked: the Overview shows up to 12.`;
      e.classList.remove("hidden");
      return;
    }
    save(ids);
  });
}

async function renderGraphs() {
  lastGraphRender = Date.now();
  let ports = [];
  if (lastDetail && lastDetail.sections.includes("interfaces")) {
    try { ports = (await api(`/api/devices/${activeDeviceId}/ports`)).ports; } catch (err) { ports = []; }
  }
  renderChartGrid("graph-grid", graphDefinitions(lastDetail, ports), graphHours);
}

async function renderChartGrid(containerId, defs, hours) {
  lastGraphRender = Date.now();
  // The overview needs the busiest port too, which lives in the ports section.
  if (containerId === "overview-charts" && lastDetail.sections.includes("interfaces")) {
    defs = overviewDefs(lastDetail, await devicePortsForGraphs());
  }
  const container = document.getElementById(containerId);
  // On the Graphs tab each graph can be put on the Overview or taken off it.
  // With the port list, so a traffic graph on the Overview shows as on.
  const onOverview = containerId === "graph-grid" ? overviewDefs(lastDetail, await devicePortsForGraphs()).map(g => g.id) : [];
  const pin = g => containerId !== "graph-grid" ? "" : `<button type="button" class="btn btn-small chart-pin${onOverview.includes(g.id) ? " on" : ""}"
      data-perm="devices.manage" data-overview-pin="${escapeHtml(g.id)}" aria-pressed="${onOverview.includes(g.id)}">${onOverview.includes(g.id) ? "On overview" : "Add to overview"}</button>`;
  const empty = containerId === "overview-charts" && Array.isArray(lastDetail.overview_graphs)
    ? `<div class="dim">No graphs chosen for the Overview. <a href="#" data-choose-graphs>Choose graphs</a></div>` : `<div class="dim">No graphable metrics yet.</div>`;
  container.innerHTML = defs.map((g, i) => `
    <div class="chart-card" data-title="${escapeHtml(g.title)}">
      <div class="chart-title"><span>${escapeHtml(g.title)}</span><span class="chart-title-end">${pin(g)}<span class="dim">${hours >= 24 ? Number(hours) / 24 + "d" : Number(hours) + "h"}</span></span></div>
      <div class="chart-host" data-chart="${i}"></div>
    </div>`).join("") || empty;

  const compare = containerId === "graph-grid" && document.getElementById("graph-compare").checked;
  await Promise.all(defs.map((g, i) => drawDefinition(container.querySelector(`[data-chart="${i}"]`), activeDeviceId, g, hours, compare)));
  if (pendingFocus && containerId === "graph-grid") {
    const card = Array.from(container.querySelectorAll(".chart-card")).find(c => c.dataset.title.startsWith(pendingFocus));
    if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
    pendingFocus = null;
  }
}

const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(name, attrs) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

/**
 * Draws a time-series line chart into host with axes, gaps for missing data and
 * a hover readout. series: [{key, label, points: [{timestamp, value}]}].
 * The history is kept on the host element so live mode can redraw it with
 * in-memory samples appended (see applyLiveToCharts).
 */
function lineChart(host, series, opts) {
  host._chart = { series, opts };
  drawChart(host, liveMergeSeries(series, opts), opts);
}

/** SVG path for [x, y] points as a uniform cubic B-spline ("basis"): fully rounded, no corners at all.
 * It runs inside the hull of the points, so it never rises above the highest reading or dips below
 * the lowest (the axes and the zero line hold). Only the ends pass exactly through their points; a
 * reading that stands alone above its neighbours is drawn softened, and the hover readout still
 * shows the exact values. */
function smoothPath(pts) {
  const f = v => v.toFixed(1);
  const n = pts.length;
  if (n < 3) return pts.map((p, i) => `${i ? "L" : "M"} ${f(p[0])} ${f(p[1])}`).join(" ");
  let d = `M ${f(pts[0][0])} ${f(pts[0][1])} L ${f((5 * pts[0][0] + pts[1][0]) / 6)} ${f((5 * pts[0][1] + pts[1][1]) / 6)}`;
  // One Bezier per span, from the B-spline's control points (the same construction as d3's curveBasis).
  const seg = (a, b, c) => ` C ${f((2 * a[0] + b[0]) / 3)} ${f((2 * a[1] + b[1]) / 3)} ${f((a[0] + 2 * b[0]) / 3)} ${f((a[1] + 2 * b[1]) / 3)}`
    + ` ${f((a[0] + 4 * b[0] + c[0]) / 6)} ${f((a[1] + 4 * b[1] + c[1]) / 6)}`;
  for (let i = 2; i < n; i++) d += seg(pts[i - 2], pts[i - 1], pts[i]);
  const last = pts[n - 1];
  d += seg(pts[n - 2], last, last) + ` L ${f(last[0])} ${f(last[1])}`;
  return d;
}

// Series switched off per graph title (see drawChart's legend).
const CHART_HIDDEN = {};

// Dense series are averaged over this many pixels for a round line (see drawChart).
const PX_PER_BUCKET = 5;

/** Step path: each value held until the next point. */
function stepPath(pts) {
  const f = v => v.toFixed(1);
  return pts.map((p, i) => i ? `L ${f(p[0])} ${f(pts[i - 1][1])} L ${f(p[0])} ${f(p[1])}` : `M ${f(p[0])} ${f(p[1])}`).join(" ");
}

function drawChart(host, series, opts) {
  host.innerHTML = "";
  // Zoomed (charts.js): only the chosen window is drawn and scaled.
  if (opts.zoom) {
    const [z0, z1] = opts.zoom;
    series = series.map(s => ({ ...s, points: s.points.filter(p => p.timestamp >= z0 && p.timestamp <= z1) }));
  }
  // Series switched off in the legend (host._hidden holds their labels) are left out of the drawing,
  // the scale and the hover readout. Colours follow each series' place in the full list, so switching
  // one off does not recolour the others.
  const baseLabel = s => s.label.replace(/ \(previous\)$/, "");
  const listed = series.filter(s => !s.dashed).map((s, i) => ({ ...s, _ci: i }));
  const colourOf = Object.fromEntries(listed.map(s => [s.label, s._ci]));
  // Remembered per graph (its card's title) for this page visit, so a new range keeps the choice.
  const chartKey = (host.closest("[data-title]") || {}).dataset ? host.closest("[data-title]").dataset.title : "";
  if (!host._hidden && chartKey && CHART_HIDDEN[chartKey]) host._hidden = new Set(CHART_HIDDEN[chartKey]);
  const hidden = host._hidden || new Set();
  series = series.filter(s => !hidden.has(baseLabel(s))).map(s => ({ ...s, _ci: colourOf[baseLabel(s)] ?? 0 }));
  const all = series.flatMap(s => s.points);
  const current = series.filter(s => !s.dashed);
  const previous = series.filter(s => s.dashed);
  // Compare: the previous period gets its own grey panel under the current one, on the same scale
  // and time axis, so the two never draw over each other.
  const stacked = !!opts.compare;
  if (!current.some(s => s.points.length) && !(stacked && all.length)) {
    host.innerHTML = `<div class="chart-empty">No data in this range yet</div>`;
    if (opts.zoom && typeof chartAttachEmpty === "function") chartAttachEmpty(host);
    return;
  }
  const W = Math.max(200, host.clientWidth || 420);
  // Charts in resizable dashboard tiles take the height they are given, leaving room for the legend.
  const reserve = (listed.length > 1 ? 22 : 0) + (stacked ? 18 : 0);
  const fill = host.classList.contains("chart-fill");
  const H = fill ? Math.max(stacked ? 140 : 70, host.clientHeight - reserve - 4) : stacked ? 260 : 150;
  const padL = 62, padR = 8, padT = 8, padB = 18, gapMid = stacked ? 22 : 0;
  const end = opts.zoom ? opts.zoom[1] : Date.now() / 1000;
  const start = opts.zoom ? opts.zoom[0] : end - opts.hours * 3600;
  const peak = Math.max(...all.map(p => (isNum(p.max) ? p.max : p.value)), 0);
  const yMax = opts.max || (peak > 0 ? peak * 1.1 : 1);
  const x = t => padL + ((t - start) / (end - start)) * (W - padL - padR);
  // Panels: [top, bottom] of each plot area. Current on top; previous below, a little shorter.
  const plotH = H - padT - padB - gapMid;
  const curH = stacked ? Math.round(plotH * 0.56) : plotH;
  const panels = [{ top: padT, bottom: padT + curH, series: current }];
  if (stacked) panels.push({ top: padT + curH + gapMid, bottom: H - padB, series: previous, grey: true });
  const yIn = panel => v => panel.top + (1 - v / yMax) * (panel.bottom - panel.top);

  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H });
  // The stylesheet fixes chart height at 150 px; the stacked compare chart needs its own.
  if (stacked && !fill) svg.style.height = `${H}px`;
  for (const panel of panels) {
    const y = yIn(panel);
    const ticks = panel.grey ? 2 : 3;
    for (let i = 0; i <= ticks; i++) {
      const v = (yMax * i) / ticks;
      svg.appendChild(svgEl("line", { x1: padL, x2: W - padR, y1: y(v), y2: y(v), class: "chart-gridline" }));
      const label = svgEl("text", { x: padL - 6, y: y(v) + 3, "text-anchor": "end", class: "chart-axis" });
      label.textContent = opts.fmt(v);
      svg.appendChild(label);
    }
  }
  const timeLabel = (t, withDate) => {
    const d = new Date(t * 1000);
    const long = end - start > 48 * 3600;
    return long || withDate
      ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + (long ? "" : " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }))
      : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  };
  [start, (start + end) / 2, end].forEach((t, i) => {
    const label = svgEl("text", { x: x(t), y: H - 4, "text-anchor": ["start", "middle", "end"][i], class: "chart-axis" });
    label.textContent = timeLabel(t);
    svg.appendChild(label);
  });
  const span = end - start;
  if (stacked) {
    // Panel captions: which window each one shows.
    const cap = (text, yPos, cls) => {
      const el = svgEl("text", { x: padL + 4, y: yPos, class: `chart-caption ${cls}` });
      el.textContent = text;
      svg.appendChild(el);
    };
    cap("Now", padT + 10, "");
    cap(`Previous: ${timeLabel(start - span, true)} to ${timeLabel(end - span, true)}`, panels[1].top + 10, "chart-caption-prev");
    if (!previous.some(s => s.points.length)) {
      const none = svgEl("text", { x: (padL + W - padR) / 2, y: (panels[1].top + panels[1].bottom) / 2 + 4, "text-anchor": "middle", class: "chart-axis" });
      none.textContent = "No data from the previous period";
      svg.appendChild(none);
    }
  }

  // A gap wider than three sample spacings (or three minutes) breaks the line.
  // Step charts hold each value until the next one: they plot metrics stored
  // only on change, where a long gap means "unchanged", not "missing".
  // Three missed polls (or three buckets on long ranges) count as a gap.
  const pollEvery = Math.max(parseInt(cachedSettings.default_poll_interval || "300", 10),
                             parseInt(cachedSettings.default_ping_interval || "60", 10));
  const gapLimit = opts.step ? Infinity : Math.max(3 * pollEvery, (opts.hours * 3600 / 300) * 3);
  for (const panel of panels) {
    const y = yIn(panel);
    panel.series.forEach((s, si) => {
      if (!s.points.length) return;
      const color = panel.grey ? "prev" : s._ci;
      // Points split into segments at gaps. Dense series (more readings than pixels allow) are
      // averaged per PX_PER_BUCKET pixels for the line, which is what makes it round; the highest
      // reading of each bucket is kept for the faint peak band, so a spike still shows its height.
      // Steps stay square and unaveraged.
      const segments = [];
      let prevT = null;
      s.points.forEach(p => {
        if (prevT === null || p.timestamp - prevT > gapLimit) segments.push([]);
        segments[segments.length - 1].push(p);
        prevT = p.timestamp;
      });
      const base = y(0).toFixed(1);
      let line = "";
      let area = "";
      let band = "";
      for (const raw of segments) {
        let mean = raw.map(p => [x(Math.max(p.timestamp, start)), y(p.value)]);
        let peak = null;
        if (opts.step) {
          mean.push([x(end), mean[mean.length - 1][1]]);
        } else if (raw.length > 2 && (mean[mean.length - 1][0] - mean[0][0]) / raw.length < PX_PER_BUCKET) {
          const buckets = new Map();
          raw.forEach((p, i) => {
            const k = Math.floor(mean[i][0] / PX_PER_BUCKET);
            const bkt = buckets.get(k) || { n: 0, x: 0, v: 0, top: -Infinity };
            bkt.n++; bkt.x += mean[i][0]; bkt.v += p.value; bkt.top = Math.max(bkt.top, isNum(p.max) ? p.max : p.value);
            buckets.set(k, bkt);
          });
          const list = [...buckets.values()];
          mean = list.map(k => [k.x / k.n, y(k.v / k.n)]);
          peak = list.map(k => [k.x / k.n, y(k.top)]);
        }
        const d = opts.step ? stepPath(mean) : smoothPath(mean);
        line += ` ${d}`;
        area += ` ${d} L ${mean[mean.length - 1][0].toFixed(1)} ${base} L ${mean[0][0].toFixed(1)} ${base} Z`;
        // The band: up along the peaks, back along the line (a B-spline reversed is the same curve).
        if (peak && peak.some((pt, i) => mean[i][1] - pt[1] > 1)) {
          band += ` ${smoothPath(peak)} L ${mean[mean.length - 1][0].toFixed(1)} ${mean[mean.length - 1][1].toFixed(1)}`
            + ` ${smoothPath(mean.slice().reverse()).replace(/^M/, "L")} Z`;
        }
      }
      if (band) svg.appendChild(svgEl("path", { d: band, class: `band s${color}` }));
      svg.appendChild(svgEl("path", { d: area, class: `area s${color}` }));
      // Several series in the grey panel: vary the dash so they stay apart without colour.
      const dash = panel.grey && si ? ` prev-alt${Math.min(si, 3)}` : "";
      svg.appendChild(svgEl("path", { d: line, class: `series s${color}${dash}` }));
    });
  }

  const cursor = svgEl("line", { y1: padT, y2: H - padB, class: "chart-cursor hidden" });
  svg.appendChild(cursor);
  const tooltip = document.getElementById("chart-tooltip");
  svg.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    const px = ((ev.clientX - rect.left) / rect.width) * W;
    if (px < padL) return;
    const t = start + ((px - padL) / (W - padL - padR)) * (end - start);
    const lines = [new Date(t * 1000).toLocaleString()];
    const readout = (list, prefix) => list.forEach(s => {
      const p = nearestPoint(s.points, t);
      if (p && Math.abs(p.timestamp - t) <= gapLimit) lines.push(`${prefix}${s.label}: ${opts.fmt(p.value)}`);
    });
    readout(current, "");
    if (stacked && previous.length) {
      lines.push(`Previous (${new Date((t - span) * 1000).toLocaleString()}):`);
      readout(previous.map(s => ({ ...s, label: s.label.replace(/ \(previous\)$/, "") })), "  ");
    }
    cursor.setAttribute("x1", px);
    cursor.setAttribute("x2", px);
    cursor.classList.remove("hidden");
    tooltip.innerHTML = lines.map(escapeHtml).join("<br>");
    show(tooltip);
    placeTooltip(tooltip, ev.clientX, ev.clientY);
  });
  svg.addEventListener("mouseleave", () => {
    cursor.classList.add("hidden");
    hide(tooltip);
  });
  host.appendChild(svg);
  // Drag to zoom, Reset zoom and Enlarge (charts.js).
  if (typeof chartAttach === "function") chartAttach(host, svg, { W, H, padL, padR, padT, padB, start, end });

  series = current;
  if (listed.length > 1) {
    // Each entry switches its series on or off (the last one shown stays on).
    const legend = document.createElement("div");
    legend.className = "chart-legend";
    legend.innerHTML = listed.map(s => {
      const off = hidden.has(s.label);
      const last = s.points.length ? opts.fmt(s.points[s.points.length - 1].value) : "-";
      return `<button type="button" class="legend-item legend-toggle${off ? " off" : ""}" data-series-toggle="${escapeHtml(s.label)}"
        aria-pressed="${!off}" title="${off ? "Show" : "Hide"} ${escapeHtml(s.label)}"><span class="legend-indicator legend-s${escapeHtml(s._ci)}"></span>${escapeHtml(s.label)} <span class="dim">${escapeHtml(off ? "hidden" : last)}</span></button>`;
    }).join("");
    legend.addEventListener("click", ev => {
      const b = ev.target.closest("[data-series-toggle]");
      if (!b) return;
      const label = b.dataset.seriesToggle;
      const set = new Set(host._hidden || []);
      if (set.has(label)) set.delete(label);
      else if (listed.length - set.size > 1) set.add(label);
      else return;
      host._hidden = set;
      if (chartKey) CHART_HIDDEN[chartKey] = [...set];
      if (host._chart) lineChart(host, host._chart.series, host._chart.opts);
    });
    host.appendChild(legend);
  }

  // Delta indicator: average of the first series against the same window one period earlier.
  if (opts.compare) {
    const cur = series.find(s => !s.dashed);
    const prev = previous[0];
    const avg = pts => (pts.length ? pts.reduce((a, p) => a + p.value, 0) / pts.length : null);
    const a = cur && avg(cur.points), b = prev && avg(prev.points);
    const el = document.createElement("div");
    el.className = "chart-delta";
    const period = opts.hours >= 168 ? "last week" : opts.hours >= 24 ? "the previous day" : "the previous period";
    if (a === null || b === null) {
      el.textContent = `No data from ${period} to compare yet`;
    } else {
      const pctChange = b ? ((a - b) / Math.abs(b)) * 100 : null;
      el.innerHTML = `${escapeHtml(cur.label)} avg ${escapeHtml(opts.fmt(a))} vs ${escapeHtml(opts.fmt(b))} ${escapeHtml(period)}` +
        (isNum(pctChange) ? ` <span class="${pctChange >= 0 ? "chg-up" : "chg-down"}">${pctChange >= 0 ? "▲" : "▼"} ${Math.abs(pctChange).toFixed(0)}%</span>` : "");
    }
    host.appendChild(el);
  }
}

// Places a fixed tooltip beside the cursor, flipping left or up when it would leave the viewport.
function placeTooltip(tip, cx, cy) {
  const gap = 12;
  const w = tip.offsetWidth, h = tip.offsetHeight;
  let left = cx + gap, top = cy + gap;
  if (left + w > window.innerWidth - 4) left = Math.max(4, cx - gap - w);
  if (top + h > window.innerHeight - 4) top = Math.max(4, cy - gap - h);
  tip.style.left = `${left}px`;
  tip.style.top = `${top}px`;
}

function nearestPoint(points, t) {
  let lo = 0, hi = points.length - 1;
  if (hi < 0) return null;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (points[mid].timestamp < t) lo = mid; else hi = mid;
  }
  return Math.abs(points[lo].timestamp - t) <= Math.abs(points[hi].timestamp - t) ? points[lo] : points[hi];
}

// --- Modals: Add Target & Edit Target ---

function readIntervalField(id) {
  const raw = document.getElementById(id).value.trim();
  return raw ? parseInt(raw, 10) : null;
}

const SERVICE_PROFILE = "service_check";
const PING_PROFILE = "ping_only";
// The three kinds of target and the template each starts with.
const KIND_PROFILE = { ping: PING_PROFILE, device: "generic_device", service: SERVICE_PROFILE };
const kindOfProfile = id => (id === SERVICE_PROFILE ? "service" : id === PING_PROFILE ? "ping" : "device");

/** Shows the fields for one kind of target (ping, SNMP device, service), nothing that does not apply.
 * .snmp-only: SNMP devices; .service-only: port and web checks; .device-or-ping: both kinds with an
 * address of their own. A boolean is the older form (true: service, false: SNMP device). */
function setDeviceFormKind(modal, kind) {
  if (kind === true || kind === false) kind = kind ? "service" : "device";
  modal.dataset.kind = kind;
  modal.querySelectorAll(".snmp-only").forEach(el => el.classList.toggle("hidden", kind !== "device"));
  modal.querySelectorAll(".service-only").forEach(el => el.classList.toggle("hidden", kind !== "service"));
  modal.querySelectorAll(".device-or-ping").forEach(el => el.classList.toggle("hidden", kind === "service"));
  syncCheckKind(modal);
  modal.querySelectorAll("[data-kind]").forEach(b => {
    const on = b.dataset.kind === kind;
    b.classList.toggle("active", on);
    b.setAttribute("aria-checked", String(on));
  });
}

/** Web checks replace the address and port fields with the page address and its expectations. */
function syncCheckKind(modal) {
  const sel = modal.querySelector("[data-check-kind]");
  const service = !modal.querySelector(".service-only").classList.contains("hidden");
  const web = service && sel && sel.value === "http";
  modal.querySelectorAll(".web-check").forEach(el => el.classList.toggle("hidden", !web));
  modal.querySelectorAll(".tcp-field").forEach(el => el.classList.toggle("web-hidden", web));
}

/** Service check fields of the Add (prefix "input") or Edit ("edit") dialog, for the API. */
function checkFields(prefix) {
  const kind = document.getElementById(`${prefix}-check-kind`).value;
  if (kind !== "http") return { service_kind: "tcp" };
  return {
    service_kind: "http",
    service_url: document.getElementById(`${prefix}-web-url`).value.trim(),
    service_expect: {
      status: document.getElementById(`${prefix}-web-status`).value.trim() || "200-399",
      keyword: document.getElementById(`${prefix}-web-keyword`).value,
      insecure: document.getElementById(`${prefix}-web-insecure`).checked,
    },
  };
}

const PROBE_LABEL = { ping: "Test ping", device: "Test & auto-detect", service: "Test connection" };

/** The Add window with what is already known filled in (Inventory, Proxmox). What the target is
 * (ping, SNMP, a service) is not known, so it starts on Ping, which suits anything, and the note
 * says where the details came from; Test shows what answers before anything is added. */
function openAddPrefilled(ip, name, noteHtml) {
  document.getElementById("btn-open-add").click();
  document.querySelector('#add-kind [data-kind="ping"]').click();
  document.getElementById("input-ip").value = ip || "";
  document.getElementById("input-hostname").value = name || "";
  const note = document.getElementById("add-from-inv");
  note.innerHTML = `${noteHtml} Choose what to watch below: <em>Ping</em> works for anything, <em>Device statistics</em> if it runs SNMP `
    + "(switches, NAS, printers, servers), <em>Service</em> for a port or web page. <em>Test</em> shows what answers before anything is added.";
  note.classList.remove("hidden");
}

function initModals() {
  const addModal = document.getElementById("modal-add-device");
  const btnProbe = document.getElementById("btn-probe");
  const probeBox = document.getElementById("probe-results-box");
  const addError = document.getElementById("add-ip-error");

  document.getElementById("btn-open-add").addEventListener("click", () => {
    ["input-ip", "input-hostname", "input-poll", "input-ping", "input-service-port"].forEach(f => { document.getElementById(f).value = ""; });
    document.getElementById("select-profile").value = "generic_device";
    document.getElementById("input-check-kind").value = "tcp";
    ["input-web-url", "input-web-status", "input-web-keyword"].forEach(f => { document.getElementById(f).value = ""; });
    document.getElementById("input-web-insecure").checked = false;
    setDeviceFormKind(addModal, "device");
    btnProbe.textContent = PROBE_LABEL.device;
    document.getElementById("input-port").value = cachedSettings.default_snmp_port || "161";
    // The stored default community is never sent to the browser: empty uses it.
    document.getElementById("input-community").value = "";
    document.getElementById("input-community").placeholder = cachedSettings.default_snmp_community__set
      ? "Default community (stored, hidden)" : "public";
    document.getElementById("check-allow-unverified").checked = false;
    hide(probeBox);
    hide(addError);
    hide(document.getElementById("add-from-inv"));
    probeVerified = false;
    show(addModal);
    document.getElementById("input-ip").focus();
  });

  const closeAdd = () => hide(addModal);
  document.getElementById("btn-close-modal").addEventListener("click", closeAdd);
  document.getElementById("btn-cancel-modal").addEventListener("click", closeAdd);
  // A changed address invalidates any earlier probe result.
  document.getElementById("input-ip").addEventListener("input", () => { probeVerified = false; });
  document.getElementById("input-service-port").addEventListener("input", () => { probeVerified = false; });
  const isService = () => document.getElementById("select-profile").value === SERVICE_PROFILE;
  const isPing = () => document.getElementById("select-profile").value === PING_PROFILE;
  document.getElementById("add-kind").addEventListener("click", ev => {
    const b = ev.target.closest("[data-kind]");
    if (!b) return;
    const kind = b.dataset.kind;
    document.getElementById("select-profile").value = KIND_PROFILE[kind];
    setDeviceFormKind(addModal, kind);
    btnProbe.textContent = PROBE_LABEL[kind];
    probeVerified = false;
    hide(probeBox);
    if (!addModal.classList.contains("scan-mode")) document.getElementById("input-ip").focus();
  });
  document.getElementById("select-profile").addEventListener("change",
    () => setDeviceFormKind(addModal, kindOfProfile(document.getElementById("select-profile").value)));
  document.getElementById("input-check-kind").addEventListener("change", () => { probeVerified = false; syncCheckKind(addModal); });
  document.getElementById("edit-check-kind").addEventListener("change", () => syncCheckKind(document.getElementById("modal-edit-device")));
  const editModalEl = document.getElementById("modal-edit-device");
  document.getElementById("edit-upstream").addEventListener("change", syncUpstreamPort);
  document.getElementById("edit-profile").addEventListener("change",
    () => setDeviceFormKind(editModalEl, kindOfProfile(document.getElementById("edit-profile").value)));

  btnProbe.addEventListener("click", async () => {
    const webCheck = isService() && document.getElementById("input-check-kind").value === "http";
    if (webCheck) {
      const fields = checkFields("input");
      show(probeBox);
      probeBox.className = "probe-box";
      probeBox.innerHTML = `<div>Fetching <strong>${escapeHtml(fields.service_url)}</strong>...</div>`;
      btnProbe.disabled = true;
      try {
        const r = await api("/api/devices/probe", { method: "POST", body: { ...fields, hostname: "" } });
        probeVerified = r.open;
        probeBox.className = `probe-box ${r.open ? "probe-success" : "probe-fail"}`;
        probeBox.innerHTML = `
          <div>${r.open ? "&check;" : "&times;"} <strong>Page:</strong> ${r.open ? `HTTP ${Number(r.status)} in ${escapeHtml((r.connect_ms || 0).toFixed(0))} ms` : escapeHtml(r.error || "no answer")}</div>
          <div>${r.ping ? "&check;" : "&times;"} <strong>ICMP echo:</strong> ${r.ping ? `${escapeHtml((r.ping_ms || 0).toFixed(1))} ms` : "no reply (fine if the host blocks ping)"}</div>`;
        if (!document.getElementById("input-hostname").value) document.getElementById("input-hostname").value = fields.service_url.replace(/^https?:\/\//, "");
      } catch (err) {
        probeVerified = false;
        probeBox.className = "probe-box probe-fail";
        probeBox.innerHTML = `<div>&times; ${escapeHtml(err.message)}</div>`;
      } finally {
        btnProbe.disabled = false;
      }
      return;
    }
    const ip = document.getElementById("input-ip").value.trim();
    if (!ip) {
      showError("add-ip-error", "Enter an IP address first.");
      return;
    }
    hide(addError);
    if (isPing()) {
      // Ping only: three echoes, nothing else is tried.
      btnProbe.disabled = true;
      show(probeBox);
      probeBox.className = "probe-box";
      probeBox.innerHTML = `<div>Pinging <strong>${escapeHtml(ip)}</strong>...</div>`;
      try {
        const r = await api("/api/devices/probe", { method: "POST", body: { ip_address: ip, mode: "ping" } });
        probeVerified = r.ping;
        probeBox.className = `probe-box ${r.ping ? "probe-success" : "probe-fail"}`;
        probeBox.innerHTML = r.ping
          ? `<div>&check; <strong>ICMP echo:</strong> ${Number(r.replies)} of ${Number(r.sent)} replies, ${escapeHtml(r.ping_ms.toFixed(1))} ms on average</div>`
          : `<div>&times; <strong>No reply</strong> to ${Number(r.sent)} pings. The device may be off, or block ping (a phone asleep, a firewall). Tick "Add it even if it does not answer yet" to add it anyway.</div>`;
      } catch (err) {
        probeVerified = false;
        probeBox.className = "probe-box probe-fail";
        probeBox.innerHTML = `<div>&times; ${escapeHtml(err.message)}</div>`;
      } finally {
        btnProbe.disabled = false;
      }
      return;
    }
    const service = isService();
    const servicePort = parseInt(document.getElementById("input-service-port").value, 10);
    if (service && !(servicePort >= 1 && servicePort <= 65535)) {
      showError("add-ip-error", "Enter the port to check (1 to 65535).");
      return;
    }
    btnProbe.textContent = "Testing...";
    btnProbe.disabled = true;
    show(probeBox);
    probeBox.className = "probe-box";
    probeBox.innerHTML = `<div>Connecting to <strong>${escapeHtml(ip)}${service ? ":" + servicePort : ""}</strong> via ICMP and ${service ? "TCP" : "SNMP"}...</div>`;

    if (service) {
      try {
        const r = await api("/api/devices/probe", { method: "POST", body: { ip_address: ip, service_port: servicePort } });
        probeVerified = r.open;
        probeBox.className = `probe-box ${r.open ? "probe-success" : "probe-fail"}`;
        probeBox.innerHTML = `
          <div>${r.open ? "&check;" : "&times;"} <strong>Port ${Number(r.port)}:</strong> ${r.open ? `accepted the connection in ${escapeHtml(r.connect_ms.toFixed(1))} ms` : "refused or timed out"}</div>
          <div>${r.ping ? "&check;" : "&times;"} <strong>ICMP echo:</strong> ${r.ping ? `${escapeHtml((r.ping_ms || 0).toFixed(1))} ms` : "no reply (fine if the host blocks ping; the port decides up or down)"}</div>`;
        if (!document.getElementById("input-hostname").value) document.getElementById("input-hostname").value = `${ip}:${servicePort}`;
      } catch (err) {
        probeVerified = false;
        probeBox.className = "probe-box probe-fail";
        probeBox.innerHTML = `<div>&times; ${escapeHtml(err.message)}</div>`;
      } finally {
        btnProbe.textContent = PROBE_LABEL.service;
        btnProbe.disabled = false;
      }
      return;
    }

    try {
      const result = await api("/api/devices/probe", {
        method: "POST",
        body: {
          ip_address: ip,
          community: document.getElementById("input-community").value.trim(),
          port: parseInt(document.getElementById("input-port").value, 10) || 161
        }
      });

      if (!result.success) {
        probeVerified = false;
        probeBox.className = "probe-box probe-fail";
        probeBox.innerHTML = `<div>&times; <strong>Host unreachable</strong>: ${escapeHtml(result.error || "timed out")}</div>`;
        showToast(`Probe: ${ip} did not answer ping`, "error");
        return;
      }

      probeVerified = true;
      probeBox.className = "probe-box probe-success";
      const pingText = isNum(result.latency_ms) ? `${result.latency_ms.toFixed(1)} ms` : "OK";
      const snmpText = result.snmp_active ? `Responded (${escapeHtml(result.sys_descr.slice(0, 60))})` : "No SNMP response (check community string)";
      probeBox.innerHTML = `
        <div>&check; <strong>ICMP echo:</strong> ${escapeHtml(pingText)}</div>
        <div>${result.snmp_active ? "&check;" : "&times;"} <strong>SNMP v2c:</strong> ${snmpText}</div>
        <div class="probe-suggestion">Suggested profile: <strong>${escapeHtml(result.profile_name)}</strong></div>
      `;
      if (result.sys_name && !document.getElementById("input-hostname").value) {
        document.getElementById("input-hostname").value = result.sys_name;
      }
      if (result.profile_id) document.getElementById("select-profile").value = result.profile_id;
      showToast(`Probe: ${result.sys_name || ip} detected as ${result.profile_name}`, "success");
    } catch (err) {
      probeVerified = false;
      probeBox.className = "probe-box probe-fail";
      probeBox.innerHTML = `<div>&times; ${escapeHtml(err.message)}</div>`;
      showToast(`Probe failed: ${err.message}`, "error");
    } finally {
      btnProbe.textContent = PROBE_LABEL.device;
      btnProbe.disabled = false;
    }
  });

  document.getElementById("btn-submit-device").addEventListener("click", async () => {
    const webAdd = isService() && document.getElementById("input-check-kind").value === "http";
    const ip = webAdd ? "-" : document.getElementById("input-ip").value.trim();
    if (!ip) {
      showError("add-ip-error", "IP address is required.");
      return;
    }
    if (!probeVerified && !document.getElementById("check-allow-unverified").checked) {
      if (!(await confirmDialog({ title: "Save without testing?",
        message: isService() ? "The port has not answered a test yet. Save it anyway? It shows as down until it does."
          : isPing() ? "It has not answered a ping test yet. Add it anyway? It shows as offline until it answers."
          : "This device has not been tested with Test & auto-detect, so the template and community are unchecked.",
        confirmLabel: "Save anyway" }))) return;
    }

    const payload = {
      hostname: document.getElementById("input-hostname").value.trim() || ip,
      ip_address: ip,
      profile_id: document.getElementById("select-profile").value,
      snmp_community: document.getElementById("input-community").value.trim(),
      snmp_port: parseInt(document.getElementById("input-port").value, 10) || 161,
      poll_interval: readIntervalField("input-poll"),
      ping_interval: readIntervalField("input-ping"),
      service_port: parseInt(document.getElementById("input-service-port").value, 10) || null,
      ...(isService() ? checkFields("input") : {})
    };
    if (webAdd) {
      payload.ip_address = "";
      payload.hostname = document.getElementById("input-hostname").value.trim() || payload.service_url;
    }

    try {
      await api("/api/devices", { method: "POST", body: payload });
      closeAdd();
      showToast(`Target ${payload.hostname} added. Initial poll started.`, "success");
      loadDevices();
    } catch (err) {
      showError("add-ip-error", err.message);
      showToast(`Could not add target: ${err.message}`, "error");
    }
  });

  const editModal = document.getElementById("modal-edit-device");
  const closeEdit = () => hide(editModal);
  document.getElementById("btn-close-edit-modal").addEventListener("click", closeEdit);
  document.getElementById("btn-cancel-edit-modal").addEventListener("click", closeEdit);

  document.getElementById("btn-save-edit-device").addEventListener("click", async () => {
    const id = parseInt(document.getElementById("edit-device-id").value, 10);
    // A web check takes its host from the page address, so the address field may be empty.
    const webEdit = document.getElementById("edit-profile").value === SERVICE_PROFILE
      && document.getElementById("edit-check-kind").value === "http";
    const ip = document.getElementById("edit-ip").value.trim();
    if (!ip && !webEdit) {
      showError("edit-ip-error", "IP address is required.");
      return;
    }

    const payload = {
      hostname: document.getElementById("edit-hostname").value.trim() || ip,
      ip_address: ip,
      profile_id: document.getElementById("edit-profile").value,
      snmp_community: document.getElementById("edit-community").value.trim(),
      snmp_port: parseInt(document.getElementById("edit-port").value, 10) || 161,
      poll_interval: readIntervalField("edit-poll"),
      ping_interval: readIntervalField("edit-ping"),
      service_port: parseInt(document.getElementById("edit-service-port").value, 10) || null,
      ...editExtras(),
      tags: document.getElementById("edit-tags").value.split(",").map(t => t.trim()).filter(Boolean),
      ...(document.getElementById("edit-profile").value === SERVICE_PROFILE ? checkFields("edit") : {})
    };

    try {
      await api(`/api/devices/${id}`, { method: "PUT", body: payload });
      closeEdit();
      showToast(`Device ${payload.hostname} saved. Re-polling now.`, "success");
      if (activeDeviceId === id) loadDeviceDetail(id, true);
      else loadDevices();
    } catch (err) {
      showError("edit-ip-error", err.message);
      showToast(`Could not save device: ${err.message}`, "error");
    }
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") { closeAdd(); closeEdit(); }
  });
}

// Details the administrator may set in the app; keys match OVERRIDE_FIELDS in server.py.
const OVERRIDE_FIELDS = [["sys_name", "Name reported"], ["sys_location", "Location"], ["sys_contact", "Contact"], ["model", "Model"]];

/** Group, uplink and detail overrides in the Edit dialog. */
async function fillEditExtras(d) {
  const group = document.getElementById("edit-group");
  const auto = DEVICE_GROUPS[d.device_group ? "" : d.group] || null;
  group.innerHTML = `<option value="">Automatic${auto ? ` (${escapeHtml(auto[0])})` : ""}</option>` +
    Object.entries(DEVICE_GROUPS).sort((a, b) => a[1][1] - b[1][1])
      .map(([id, [label]]) => `<option value="${escapeHtml(id)}">${escapeHtml(label)}</option>`).join("");
  group.value = d.device_group || "";
  let devices = lastFleet ? lastFleet[0] : null;
  if (!devices) {
    try { devices = (await api("/api/devices")).devices; } catch (e) { devices = []; }
  }
  const up = document.getElementById("edit-upstream");
  up.innerHTML = `<option value="">Guess from the network (map)</option>` + devices
    .filter(x => x.id !== d.id && !x.service_port)
    .sort((a, b) => a.hostname.localeCompare(b.hostname))
    .map(x => `<option value="${Number(x.id)}">${escapeHtml(x.hostname)} (${escapeHtml(x.ip_address)})</option>`).join("");
  up.value = d.upstream_device_id ? String(d.upstream_device_id) : "";
  document.getElementById("edit-upstream-port").value = d.upstream_port || "";
  syncUpstreamPort();
  const polled = d.inventory_polled || {};
  const over = d.overrides || {};
  document.getElementById("edit-overrides").innerHTML = OVERRIDE_FIELDS.map(([k, label]) => {
    const reported = k in polled ? polled[k] : (d.inventory || {})[k];
    return `<div class="form-group"><label for="edit-ov-${escapeHtml(k)}">${escapeHtml(label)}</label>
      <input type="text" id="edit-ov-${escapeHtml(k)}" data-override="${escapeHtml(k)}" maxlength="128" value="${escapeHtml(over[k] || "")}"
        placeholder="${escapeHtml(reported ? `Device says: ${reported}` : "Not reported by the device")}"></div>`;
  }).join("");
  // Open the section when something in it is set, so it is not hidden away.
  document.getElementById("edit-more").open = !!(d.upstream_device_id || Object.keys(over).length);
}

function syncUpstreamPort() {
  document.getElementById("edit-upstream-port-group").classList.toggle("hidden", !document.getElementById("edit-upstream").value);
}

function editExtras() {
  const up = document.getElementById("edit-upstream").value;
  const overrides = {};
  document.querySelectorAll("#edit-overrides [data-override]").forEach(i => { if (i.value.trim()) overrides[i.dataset.override] = i.value.trim(); });
  return {
    device_group: document.getElementById("edit-group").value,
    upstream_device_id: up ? Number(up) : null,
    upstream_port: up ? document.getElementById("edit-upstream-port").value.trim() : "",
    overrides,
  };
}

/** Edit device: the tags as chips; Change tags opens the tag manager and writes back to #edit-tags. */
function drawEditTags() {
  const list = document.getElementById("edit-tags").value.split(",").map(t => t.trim()).filter(Boolean);
  document.getElementById("edit-tags-chips").innerHTML = list.length ? tagChips(list) : `<span class="dim">None</span>`;
}

document.addEventListener("click", async ev => {
  if (!ev.target.closest || !ev.target.closest("#btn-edit-tags")) return;
  const input = document.getElementById("edit-tags");
  const picked = await tagPicker({ title: `Tags for ${document.getElementById("edit-hostname").value || "this device"}`,
    applied: input.value.split(",").map(t => t.trim()).filter(Boolean), confirmLabel: "Use these tags",
    help: "Saved with the device when you press Save changes." });
  if (picked === null) return;
  input.value = picked.join(", ");
  drawEditTags();
});

async function openEditModal(id) {
  try {
    const data = await api(`/api/devices/${id}`);
    const d = data.device;
    document.getElementById("edit-device-id").value = d.id;
    document.getElementById("edit-ip").value = d.ip_address;
    document.getElementById("edit-hostname").value = d.hostname;
    document.getElementById("edit-tags").value = (d.tags || []).join(", ");
    drawEditTags();
    document.getElementById("edit-community").value = "";
    document.getElementById("edit-community").placeholder = d.snmp_community_set
      ? "Stored (hidden): empty keeps it" : "public";
    document.getElementById("edit-port").value = d.snmp_port;
    document.getElementById("edit-profile").value = d.profile_id;
    document.getElementById("edit-poll").value = d.poll_interval || "";
    document.getElementById("edit-ping").value = d.ping_interval || "";
    document.getElementById("edit-service-port").value = d.service_port || "";
    const ex = d.service_expect || {};
    document.getElementById("edit-check-kind").value = d.service_kind === "http" ? "http" : "tcp";
    document.getElementById("edit-web-url").value = d.service_url || "";
    document.getElementById("edit-web-status").value = ex.status || "";
    document.getElementById("edit-web-keyword").value = ex.keyword || "";
    document.getElementById("edit-web-insecure").checked = !!ex.insecure;
    await fillEditExtras(d);
    setDeviceFormKind(document.getElementById("modal-edit-device"), kindOfProfile(d.profile_id));
    hide(document.getElementById("edit-ip-error"));
    show(document.getElementById("modal-edit-device"));
    document.getElementById("edit-ip").focus();
  } catch (err) {
    showToast(`Could not load device for editing: ${err.message}`, "error");
  }
}

function showError(elemId, msg) {
  const el = document.getElementById(elemId);
  el.textContent = msg;
  show(el);
}

// --- Settings & Audit ---

// [id, title, blurb, menu group, permission to change it]. Account and Users are fixed cards in index.html.
const SETTINGS_SECTIONS = [
  ["account", "Account", "", "You", null],
  ["alerts", "Alert rules", "Every condition that opens a problem: whether it is on, its threshold, how long it must last, its severity and whether Telegram hears about it. Set for all devices, a template, a tag or one device.", "Monitoring", "settings.alerts"],
  ["notify", "Notifications", "Messages to your phone through a Telegram bot. Each event can be switched on or off and has its own message text.", "Monitoring", "settings.notifications"],
  ["polling", "Polling", "How often devices are checked. Shorter intervals give finer graphs and a larger database.", "Monitoring", "settings.system"],
  ["snmp", "SNMP defaults", "Used when adding a device. Every device can override these in its Edit dialog.", "Monitoring", "settings.system"],
  ["live", "Live mode", "Faster polling for the device page you have open. Live samples are held in memory for 15 minutes and never written to the database.", "Monitoring", "settings.system"],
  ["groups", "Groups and tags", "", "Monitoring", "devices.manage"],
  ["maintenance", "Maintenance windows", "", "Monitoring", "problems.ack"],
  ["demo", "Demo data", "This monitor was installed with made-up devices to look around. Remove them when you are ready to use it for real.", "System", "settings.system"],
  ["users", "Users", "", "System", "users.manage"],
  ["login", "Login security", "Extra protection for logins.", "System", "settings.system"],
  ["retention", "Data retention and storage", "How long history is kept. Raw samples are rolled up into hourly min / avg / max before they expire.", "System", "settings.system"],
  ["backups", "Backups", "Where backups go and how to rebuild. Without Syncthing they stay in the container (the newest 7); with Syncthing they are written to the synced folder, so your NAS holds them.", "System", "settings.system"],
  ["updates", "Updates", "New versions from the project's signed releases. Each update keeps a backup and the previous version for two days, so it can be undone.", "System", "settings.system"],
  ["https", "HTTPS", "", "System", "settings.system"],
  ["pihole", "Pi-hole", "", "System", "settings.system"],
  ["unifi", "UniFi", "", "System", "settings.system"],
  ["proxmox", "Proxmox", "", "System", "settings.system"],
  ["system", "System", "Server and poller status.", "System", "settings.system"],
];
const STATIC_SETTINGS_CARDS = new Set(["account", "users", "proxmox", "groups", "https", "maintenance", "pihole", "unifi"]);
let settingsSchema = null;
let settingsRoute = { scope: "global", target: "", focus: false };
let settingsSection = "alerts";
let settingsLoaded = false;
let settingsOriginal = {};

async function loadSettingValues() {
  try {
    cachedSettings = await api("/api/settings");
  } catch (err) {
    showToast(`Could not load settings: ${err.message}`, "error");
  }
}

let settingsLoadSeq = 0;

async function loadSettings() {
  // Only the newest load renders: an older one finishing late would reset the section and alert scope.
  const seq = ++settingsLoadSeq;
  try {
    if (!settingsSchema) settingsSchema = (await api("/api/settings/schema")).schema;
    const [values, system] = await Promise.all([api("/api/settings"), api("/api/system")]);
    if (seq !== settingsLoadSeq) return;
    cachedSettings = values;
    settingsOriginal = Object.assign({}, values);
    renderSettings(values, system);
  } catch (err) {
    showToast(`Could not load settings: ${err.message}`, "error");
  }
}

function settingInput(s, value) {
  const id = `setting-${escapeHtml(s.key)}`;
  const common = `id="${id}" data-setting="${escapeHtml(s.key)}"`;
  if (s.type.startsWith("select:")) {
    return `<select ${common}>${s.type.slice(7).split(",").map(o =>
      `<option value="${escapeHtml(o)}" ${o === value ? "selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select>`;
  }
  if (s.type === "secret") {
    // Stored secrets are never sent to the browser; an empty field keeps the stored value.
    const ph = settingsOriginal[`${s.key}__set`] ? "Stored and hidden: type a new value to replace" : "Not set";
    return `<input type="password" ${common} value="" placeholder="${escapeHtml(ph)}" autocomplete="off">` +
      `<button class="btn" type="button" data-reveal="${escapeHtml(s.key)}">Show</button>`;
  }
  if (s.type === "int" || s.type === "float") {
    return `<input type="number" ${common} value="${escapeHtml(value)}" min="${escapeHtml(s.min)}" max="${escapeHtml(s.max)}" step="${s.type === "int" ? 1 : 0.1}">`;
  }
  if (s.type === "time") return `<input type="time" ${common} value="${escapeHtml(value)}">`;
  if (s.type === "template") return `<textarea ${common} rows="3" maxlength="500" spellcheck="false">${escapeHtml(value)}</textarea>`;
  return `<input type="text" ${common} value="${escapeHtml(value)}">`;
}

/** Settings sections this user may open: Users only with users.manage, Demo data only while there is demo data. */
let demoOn = false;
function settingsSectionsShown() {
  return SETTINGS_SECTIONS.filter(([id, , , , perm]) => (id !== "users" || can(perm)) && (id !== "demo" || demoOn));
}

function demoPanel(d) {
  if (!d || !d.on) return "";
  const admin = currentUser && currentUser.role === "admin";
  return `<div class="backup-panel demo-panel">
    <p>${d.devices ? `${escapeHtml(d.devices)} made-up devices` : "Made-up devices"} fill the dashboard, the map, the graphs and the history, so you can try everything without touching your network. Their readings are invented here; nothing is sent to those addresses.</p>
    <p>Removing them deletes the demo devices with their history and events, and the groups and tags that came with them. Your account, your settings and any device you added yourself stay. With nothing left, the setup guide opens to find the devices on your network.</p>
    ${admin ? `<button type="button" class="btn btn-danger-solid" id="btn-demo-remove">Remove the demo data and start for real</button>`
      : `<p class="form-help">An administrator can remove it.</p>`}
  </div>`;
}

async function removeDemoData(btn) {
  const ok = await confirmDialog({ title: "Remove the demo data?", confirmLabel: "Remove it", danger: true,
    message: "The made-up devices, their history and events, and the groups and tags that came with them are deleted. This cannot be undone." });
  if (!ok) return;
  btn.disabled = true;
  try {
    const r = await api("/api/demo/remove", { method: "POST", body: {} });
    showToast(`Demo data removed (${r.removed.devices} devices). Ready for your own.`, "success");
    if (r.setup) { window.location.hash = "#/setup"; window.location.reload(); return; }
    demoOn = false;
    window.location.hash = "#/settings/alerts";
    loadSettings();
  } catch (err) {
    showToast(err.message, "error");
    btn.disabled = false;
  }
}

function showSettingsSection(id) {
  const shown = settingsSectionsShown().map(x => x[0]);
  settingsSection = shown.includes(id) ? id : shown.includes("alerts") ? "alerts" : shown[0];
  document.querySelectorAll("#view-settings [data-card]").forEach(c => c.classList.toggle("hidden", c.dataset.card !== settingsSection));
  document.querySelectorAll("#settings-nav a").forEach(a => {
    a.classList.toggle("active", a.dataset.section === settingsSection);
    if (a.dataset.section === settingsSection) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const entry = SETTINGS_SECTIONS.find(x => x[0] === settingsSection);
  setPageTitle(`Settings: ${entry ? entry[1] : ""}`);
  if (settingsSection === "users") loadUsers();
  if (settingsSection === "account") renderAccountCard();
  if (settingsSection === "proxmox") loadPveSettings();
  if (settingsSection === "https") loadTlsSettings();
  if (settingsSection === "maintenance") loadMaintenance();
  if (settingsSection === "pihole") loadLanSettings("pihole");
  if (settingsSection === "unifi") loadLanSettings("unifi");
  if (settingsSection === "groups") loadTaxonomy().then(renderTaxonomySettings);
}

function renderSettings(values, system) {
  demoOn = !!(system.demo && system.demo.on);
  let group = "";
  document.getElementById("settings-nav").innerHTML = settingsSectionsShown().map(([id, title, , g]) => {
    const head = g !== group ? `<div class="settings-nav-group">${escapeHtml(g)}</div>` : "";
    group = g;
    const badge = id === "updates" && typeof updateWaiting !== "undefined" && updateWaiting
      ? `<span class="nav-badge" aria-label="An update is ready">1</span>` : "";
    return `${head}<a data-section="${escapeHtml(id)}" href="#/settings/${escapeHtml(id)}">${escapeHtml(title)}${badge}</a>`;
  }).join("");

  const cards = SETTINGS_SECTIONS.filter(([id]) => !STATIC_SETTINGS_CARDS.has(id) && (id !== "demo" || demoOn)).map(([id, title, blurb, , perm]) => {
    const readOnly = perm && !can(perm);
    // Command replies are edited in the command builder (botcmds.js), not as rows here.
    const rows = settingsSchema.filter(s => s.section === id && !s.key.startsWith("bot_tpl_")).map(s => {
      // Message texts sit full width under their event's on / off row (or alone for problem messages).
      const tpl = s.type === "template";
      const paired = tpl && settingsSchema.some(x => x.key === `notify_on_${s.key.slice(11)}`);
      const cls = tpl ? (paired ? " tpl-row" : " tpl-row tpl-only") : "";
      return `
      <div class="setting-row${cls}" data-row="${escapeHtml(s.key)}"${id === "notify" ? ` data-ntab="${notifyTab(s.key)}"` : ""}>
        <div><label for="setting-${escapeHtml(s.key)}">${escapeHtml(paired ? "Message" : s.label)}</label></div>
        <div class="setting-input">${settingInput(s, values[s.key] ?? s.default)}<span class="unit">${escapeHtml(s.unit || "")}</span></div>
        <div class="setting-help">${escapeHtml(s.help || "")}${s.min !== null && s.min !== undefined ? ` <span class="dim">(${escapeHtml(s.min)} to ${escapeHtml(s.max)}, default ${escapeHtml(s.default)})</span>` : ""}<span class="err"></span></div>
      </div>`;
    }).join("");
    let extra = "";
    if (id === "retention") extra = storagePanel(system.storage, values);
    if (id === "system") extra = systemPanel(system);
    if (id === "backups") extra = backupsSection(system.backup);
    if (id === "updates") extra = updatesSection(system.update);
    if (id === "demo") extra = demoPanel(system.demo);
    if (id === "notify") extra = notifyPanel() + `<div id="bot-builder" class="bot-builder" data-ntab="commands"></div>`
      + `<div id="notify-changed" class="notify-changed" data-ntab="changed"></div>`;
    if (id === "alerts") extra = alertRulesPanel();
    const note = readOnly ? `<div class="panel-note-bar warn">Your account can view these settings but not change them.</div>` : "";
    return `<section class="settings-card${readOnly ? " read-only" : ""}" id="settings-${escapeHtml(id)}" data-card="${escapeHtml(id)}">
      <div class="settings-card-head"><h3>${escapeHtml(title)}</h3><p>${escapeHtml(blurb)}${SECTION_LINKS[id] || ""}</p></div>
      ${id === "notify" ? notifyTabsBar() : ""}${note}${id === "updates" ? extra + rows : rows + extra}</section>`;
  }).join("");
  document.getElementById("settings-sections").innerHTML = cards;
  document.querySelectorAll("#settings-sections .read-only [data-setting], #settings-sections .read-only button").forEach(el => { el.disabled = true; });
  settingsLoaded = true;
  updateSettingsDirty();
  applySettingDependencies();
  applyNotifyTab();
  loadNotifyInfo();
  showSettingsSection(settingsSection);
  // A re-render (Discard, Save) keeps the alert scope on screen unless a link asked for another.
  const ar = settingsRoute.focus ? settingsRoute : arScope;
  loadAlertRules(ar.scope, ar.target);
  settingsRoute = { scope: "global", target: "", focus: false };
}

function renderAccountCard() {
  const u = currentUser;
  if (!u) return;
  document.getElementById("account-who").innerHTML = `<table class="kv-table"><tbody>
    <tr><td>Username</td><td>${escapeHtml(u.username)}</td></tr>
    <tr><td>Role</td><td>${escapeHtml(u.role_label)}</td></tr>
    <tr><td>Devices</td><td>${u.scoped ? "Only the templates and devices an administrator chose" : "All devices"}</td></tr>
  </tbody></table>`;
  if (typeof renderTwoFactor === "function") renderTwoFactor();
}

/** Rows shown only when the setting they depend on has the given value (nothing shown that cannot be used). */
function settingVisibleWhen(key) {
  if (key.startsWith("notify_tpl_")) {
    const toggle = `notify_on_${key.slice(11)}`;
    return settingsSchema.some(s => s.key === toggle) ? [[toggle, "on"], ["telegram_enabled", "on"]] : [["telegram_enabled", "on"]];
  }
  if (key === "notify_repeat_severity") return [["telegram_enabled", "on"], ["notify_repeat_hours", "!0"]];
  if (key === "notify_quiet_start" || key === "notify_quiet_end") return [["notify_quiet", "on"], ["telegram_enabled", "on"]];
  if (key === "notify_silent_start" || key === "notify_silent_end" || key === "notify_silent_sound_from") return [["notify_silent", "on"], ["telegram_enabled", "on"]];
  if (key === "notify_group_seconds" || key === "notify_group_min") return [["notify_group", "on"], ["telegram_enabled", "on"]];
  if (key === "notify_digest_day") return [["notify_digest", "weekly"], ["telegram_enabled", "on"]];
  if (key === "notify_digest_time") return [["notify_digest", "!off"], ["telegram_enabled", "on"]];
  if (key.startsWith("bot_tpl_")) return [["telegram_enabled", "on"], ["telegram_commands", "on"]];
  if (key.startsWith("notify_") || key.startsWith("telegram_") && key !== "telegram_enabled") return [["telegram_enabled", "on"]];
  return [];
}

function applySettingDependencies() {
  const value = k => { const el = document.getElementById(`setting-${k}`); return el ? el.value : ""; };
  document.querySelectorAll("#settings-sections .setting-row").forEach(row => {
    const ok = settingVisibleWhen(row.dataset.row).every(([k, v]) => v.startsWith("!") ? value(k) !== v.slice(1) && value(k) !== "" : value(k) === v);
    row.classList.toggle("hidden", !ok);
  });
  const panel = document.getElementById("notify-panel");
  if (panel) panel.classList.toggle("hidden", value("telegram_enabled") !== "on");
}

// Notifications in three tabs (the list had grown long): how messages travel, when they are
// held or silent, and what they say. Nothing is removed; rows are only grouped.
const NOTIFY_TABS = [["delivery", "Delivery"], ["when", "When"], ["messages", "Messages"], ["commands", "Commands"], ["changed", "Changed alerts"]];
// Tabs that apply only while Telegram is on (Changed alerts also covers what shows in the app).
const NOTIFY_TELEGRAM_TABS = new Set(["when", "messages", "commands"]);
let notifyTabActive = "delivery";

function notifyTab(key) {
  if (key.startsWith("notify_on_") || key.startsWith("notify_tpl_")) return "messages";
  if (key.startsWith("bot_tpl_")) return "commands";
  if (/^notify_(quiet|silent|repeat|new_device|digest|group)/.test(key)) return "when";
  return "delivery";
}

function notifyTabsBar() {
  return `<div class="tab-bar ntab-bar" id="ntab-bar" role="tablist">${NOTIFY_TABS.map(([id, label]) =>
    `<a class="tab${id === notifyTabActive ? " active" : ""}" data-ntab-go="${escapeHtml(id)}" role="tab" tabindex="0">${escapeHtml(label)}</a>`).join("")}</div>`;
}

function applyNotifyTab() {
  const card = document.querySelector('#settings-sections [data-card="notify"]');
  if (!card) return;
  card.querySelectorAll("[data-ntab]").forEach(el => el.classList.toggle("ntab-off", el.dataset.ntab !== notifyTabActive));
  card.querySelectorAll("[data-ntab-go]").forEach(a => a.classList.toggle("active", a.dataset.ntabGo === notifyTabActive));
  // Until Telegram is on only Delivery and Changed alerts have anything to show.
  const on = (document.getElementById("setting-telegram_enabled") || {}).value === "on";
  card.querySelectorAll("[data-ntab-go]").forEach(a => a.classList.toggle("hidden", !on && NOTIFY_TELEGRAM_TABS.has(a.dataset.ntabGo)));
  if (!on && NOTIFY_TELEGRAM_TABS.has(notifyTabActive)) { notifyTabActive = "delivery"; applyNotifyTab(); return; }
  if (notifyTabActive === "commands" && typeof renderBotBuilder === "function") renderBotBuilder();
  if (notifyTabActive === "changed" && typeof loadChangedAlerts === "function") loadChangedAlerts();
}

// Short cross-links between the two halves of alerting: what is a problem, and how you hear about it.
const SECTION_LINKS = {
  alerts: ` <a href="#/settings/notify">How you are told: Notifications</a>`,
  notify: ` <a href="#/settings/alerts">What counts as a problem, and per rule Telegram and sound: Alert rules</a>`,
};

function notifyPanel() {
  return `<div class="notify-panel hidden" id="notify-panel" data-ntab="delivery">
    <div class="notify-actions">
      <button class="btn" type="button" id="btn-notify-find">Find my chat</button>
      <button class="btn" type="button" id="btn-notify-test">Send test message</button>
      <button class="btn" type="button" id="btn-notify-test-silent" title="Sends a message without a sound, the way the silent window does">Send silent test</button>
      <span class="dim" id="notify-status"></span>
    </div>
    <div class="form-help">Find my chat: open your bot in Telegram and send it any message first. It uses the saved token, so save the token before pressing it.</div>
    <details class="notify-placeholders"><summary>Placeholders you can use in messages</summary><table class="storage-table"><tbody id="notify-placeholders"></tbody></table></details>
  </div>`;
}

async function loadNotifyInfo() {
  const body = document.getElementById("notify-placeholders");
  if (!body) return;
  try {
    const info = await api("/api/notify/info");
    body.innerHTML = Object.entries(info.placeholders).map(([k, v]) => `<tr><td><code>{${escapeHtml(k)}}</code></td><td>${escapeHtml(v)}</td></tr>`).join("");
    const q = info.outbox && info.outbox.queued;
    document.getElementById("notify-status").textContent = [
      q ? `${q} message${q === 1 ? "" : "s"} waiting to send (retried until Telegram answers, up to 24 h)` : "",
      info.last_error ? `Last send failed: ${info.last_error}` : info.sent ? `${info.sent} sent since start` : "",
    ].filter(Boolean).join(". ");
    if (typeof decorateTemplateRows === "function") decorateTemplateRows(info);
  } catch (err) { /* panel stays without the list */ }
}

function storagePanel(st, values) {
  const metricRows = st.rows.metrics + st.rows.metrics_hourly;
  const bytesPerRow = metricRows ? (st.total_bytes - st.free_bytes) / metricRows : 64;
  const rawDays = parseInt(values.raw_retention_days || "7", 10);
  const trendDays = parseInt(values.metric_retention_days || "365", 10);
  // Hourly trend rows: one per metric key per hour, approximated from today's raw rate.
  const keysPerHour = Math.max(1, st.rows.metrics_hourly / Math.max(1, (Date.now() / 1000 - (st.oldest_trend || Date.now() / 1000)) / 3600));
  const steadyRows = st.metric_rows_per_day * rawDays + Math.min(keysPerHour * 24 * trendDays, st.metric_rows_per_day / 60 * 24 * trendDays);
  const stat = (n, label) => `<div><div class="stat-num">${escapeHtml(n)}</div><div class="stat-label">${escapeHtml(label)}</div></div>`;
  return `<div class="kv-grid">
      ${stat(formatBytes(st.total_bytes), "Database size")}
      ${stat(st.metric_rows_per_day.toLocaleString(), "Metric rows per day")}
      ${stat("≈ " + formatBytes(steadyRows * bytesPerRow), "Estimated size at steady state")}
      ${stat(st.oldest_raw ? formatAgo(st.oldest_raw).replace(" ago", "") : "-", "Raw history span")}
    </div>
    <table class="storage-table"><tbody>
      <tr><td>Raw samples</td><td>${Number(st.rows.metrics).toLocaleString()} rows</td></tr>
      <tr><td>Hourly trends</td><td>${Number(st.rows.metrics_hourly).toLocaleString()} rows</td></tr>
      <tr><td>Events / audit</td><td>${Number(st.rows.events).toLocaleString()} / ${Number(st.rows.audit_log).toLocaleString()} rows</td></tr>
      <tr><td>Reusable free space</td><td>${formatBytes(st.free_bytes)}</td></tr>
      <tr><td>File</td><td>${escapeHtml(st.path)}</td></tr>
    </tbody></table>`;
}

function vaultSummary(v) {
  if (!v.enabled) return { cls: "warn", text: v.error || "Vault unavailable: secrets cannot be stored." };
  // key_path and error come only with System settings.
  const where = v.source === "key file" && v.key_path ? `key file ${v.key_path}` : v.source;
  const warn = v.key_beside_database
    ? " The key file sits in the same folder as the database, and this folder is synced to the cloud: anyone with a copy of both can decrypt. Set MONITOR_KEY_FILE to a location outside the synced folder, or use a MONITOR_MASTER_KEY passphrase."
    : "";
  return { cls: warn ? "warn" : "", text: `Secrets are encrypted with AES-256-GCM. Master key: ${where}.${warn}` };
}

function systemPanel(sys) {
  const jobs = Object.entries(sys.scheduler.jobs_in_flight).map(([k, v]) => `${k} ${v}`).join(", ") || "idle";
  const rows = [
    ["Version", sys.built ? `${sys.version}, built ${sys.built}` : `${sys.version} (from the source folder)`], ["Python", sys.python], ["Listening on", sys.listen],
    ["Server uptime", formatDuration(Date.now() / 1000 - sys.started_at)],
    ["Devices", sys.devices], ["Poller jobs running", jobs],
    ["Live devices", sys.scheduler.live_devices.length ? sys.scheduler.live_devices.join(", ") : "none"],
    ["Last scheduler tick", formatAgo(sys.scheduler.last_tick)],
    ["Credential vault", sys.vault.enabled ? `AES-256-GCM, ${sys.vault.encrypted_items} encrypted item(s), key from ${sys.vault.source}` : `Unavailable${sys.vault.error ? `: ${sys.vault.error}` : ""}`],
  ];
  const admin = currentUser && currentUser.role === "admin";
  return `<table class="storage-table"><tbody>${rows.map(r =>
    `<tr><td>${escapeHtml(r[0])}</td><td>${escapeHtml(r[1])}</td></tr>`).join("")}</tbody></table>
    ${admin ? `<div class="report-panel">
      <h4>Report a problem</h4>
      <p class="form-help">Something not working as it should? Make a report and attach it to a new issue on the project's GitHub page. It lists the version, how the monitor was installed, device counts, recent updates and recent warnings. Addresses, names and passwords are masked, you see all of it first and the monitor sends nothing by itself.</p>
      <button type="button" class="btn btn-small" id="btn-make-report">Make a report</button>
      <div id="report-out"></div>
    </div>` : ""}`;
}

async function makeProblemReport(btn) {
  btn.disabled = true;
  const out = document.getElementById("report-out");
  try {
    const r = await api("/api/support/report");
    out.innerHTML = `<pre class="update-log report-text"></pre>
      <div class="report-actions">
        <button type="button" class="btn btn-small" data-report="copy">Copy</button>
        <button type="button" class="btn btn-small" data-report="save">Save as a file</button>
        <a class="btn btn-small btn-primary" target="_blank" rel="noopener noreferrer"></a>
      </div>
      <p class="form-help">On GitHub: describe what happened and what you expected, then paste the report into the box for it.</p>`;
    out.querySelector(".report-text").textContent = r.report;
    const link = out.querySelector("a");
    link.href = r.issue_url;
    link.textContent = "Open a new issue on GitHub";
    out.onclick = async ev => {
      const what = ev.target.closest("[data-report]")?.dataset.report;
      if (what === "copy") {
        try { await navigator.clipboard.writeText(r.report); showToast("Copied", "success"); } catch (e) { showToast("Could not copy: select the text instead", "error"); }
      }
      if (what === "save") {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(new Blob([r.report], { type: "text/plain" }));
        a.download = `home-monitor-report-${new Date().toISOString().slice(0, 10)}.txt`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      }
    };
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    btn.disabled = false;
  }
}

/** Validates against the schema in the browser so errors show before saving. */
function validateSetting(s, raw) {
  if (s.type === "int" || s.type === "float") {
    if (raw.trim() === "") return "Required";
    const n = Number(raw);
    if (!isFinite(n) || (s.type === "int" && !Number.isInteger(n))) return s.type === "int" ? "Whole number required" : "Number required";
    if (n < s.min || n > s.max) return `Must be ${s.min} to ${s.max}`;
  }
  return "";
}

function settingsChanges() {
  const changes = {};
  let invalid = 0;
  document.querySelectorAll("#settings-sections [data-setting]").forEach(input => {
    const s = settingsSchema.find(x => x.key === input.dataset.setting);
    const row = input.closest(".setting-row");
    const err = validateSetting(s, input.value);
    row.classList.toggle("invalid", !!err);
    row.querySelector(".err").textContent = err;
    if (err) invalid++;
    const original = String(settingsOriginal[s.key] ?? s.default);
    // Number inputs may reformat the stored text (e.g. "2.0" shown as "2"), so compare numerically.
    const changed = (s.type === "int" || s.type === "float")
      ? Number(input.value) !== Number(original) || input.value.trim() === ""
      : input.value !== original;
    row.classList.toggle("changed", changed);
    if (changed) changes[s.key] = input.value;
  });
  return { changes, invalid };
}

function updateSettingsDirty() {
  const { changes, invalid } = settingsChanges();
  const n = Object.keys(changes).length;
  document.getElementById("settings-dirty").textContent =
    invalid ? `${invalid} invalid value${invalid > 1 ? "s" : ""}` : n ? `${n} unsaved change${n > 1 ? "s" : ""}` : "";
  document.getElementById("btn-save-settings").disabled = invalid > 0;
  document.getElementById("btn-save-settings").classList.toggle("hidden", !n);
  document.getElementById("btn-discard-settings").classList.toggle("hidden", !n);
  const dirtySections = new Set(Object.keys(changes).map(k => settingsSchema.find(s => s.key === k).section));
  document.querySelectorAll("#settings-nav a").forEach(a => a.classList.toggle("dirty", dirtySections.has(a.dataset.section)));
}

function initSettingsAndAudit() {
  const sections = document.getElementById("settings-sections");
  sections.addEventListener("input", updateSettingsDirty);
  sections.addEventListener("change", () => { updateSettingsDirty(); applySettingDependencies(); applyNotifyTab(); });
  sections.addEventListener("click", ev => {
    const t = ev.target.closest("[data-ntab-go]");
    if (t) { notifyTabActive = t.dataset.ntabGo; applyNotifyTab(); }
    const demoBtn = ev.target.closest("#btn-demo-remove");
    if (demoBtn) removeDemoData(demoBtn);
    const reportBtn = ev.target.closest("#btn-make-report");
    if (reportBtn) makeProblemReport(reportBtn);
  });
  sections.addEventListener("keydown", ev => {
    const t = ev.target.closest && ev.target.closest("[data-ntab-go]");
    if (t && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); notifyTabActive = t.dataset.ntabGo; applyNotifyTab(); }
  });
  sections.addEventListener("click", async (ev) => {
    if (ev.target.id === "btn-notify-find" || ev.target.id === "btn-notify-test" || ev.target.id === "btn-notify-test-silent") {
      const status = document.getElementById("notify-status");
      ev.target.disabled = true;
      try {
        if (ev.target.id === "btn-notify-find") {
          const r = await api("/api/notify/find-chat", { method: "POST", body: {} });
          if (r.searching) {
            status.textContent = `Now send any message to @${r.bot} in Telegram, then press Find my chat again (within ${Math.round(r.seconds / 60)} minutes).`;
            return;
          }
          if (!(await confirmDialog({ title: "Use this chat?", message: `@${r.bot} got a message from "${r.chat_name || "a chat without a name"}". ` +
            "Alerts and password reset codes will go to this chat. Use it only if this is you.", detail: `Chat ID ${r.chat_id}`,
            confirmLabel: "Use this chat" }))) {
            status.textContent = "Not used. Press Find my chat to search again.";
            return;
          }
          const input = document.getElementById("setting-telegram_chat_id");
          input.value = r.chat_id;
          updateSettingsDirty();
          status.textContent = `Using ${r.chat_name || "your chat"} via @${r.bot}. Save to keep it.`;
        } else {
          const silent = ev.target.id === "btn-notify-test-silent";
          const r = await api("/api/notify/test", { method: "POST", body: { chat_id: document.getElementById("setting-telegram_chat_id").value, silent } });
          status.textContent = (silent ? "Silent test sent: your phone should show it without a sound." : "Test message sent.") +
            ` The monitor's clock says ${r.clock}; the silent window is ${r.silent_now ? "on" : "off"} right now.`;
        }
      } catch (err) {
        status.textContent = err.message;
      } finally {
        ev.target.disabled = false;
      }
      return;
    }
    const btn = ev.target.closest("[data-reveal]");
    if (!btn) return;
    const input = document.getElementById(`setting-${btn.dataset.reveal}`);
    input.type = input.type === "password" ? "text" : "password";
    btn.textContent = input.type === "password" ? "Show" : "Hide";
  });
  registerUnsavedGuard(target => {
    if (!settingsLoaded || (target && target.startsWith("#/settings"))) return "";
    const n = Object.keys(settingsChanges().changes).length;
    return n ? `${n} setting${n === 1 ? "" : "s"}` : "";
  });
  window.addEventListener("discardunsaved", () => { settingsLoaded = false; });
  document.getElementById("btn-discard-settings").addEventListener("click", () => loadSettings());
  document.getElementById("btn-save-settings").addEventListener("click", async () => {
    const { changes, invalid } = settingsChanges();
    if (invalid || !Object.keys(changes).length) return;
    try {
      const res = await api("/api/settings", { method: "POST", body: changes });
      showToast(`Saved ${res.changed.length} setting${res.changed.length === 1 ? "" : "s"}.`, "success");
      settingsLoaded = false;
      loadSettings();
    } catch (err) {
      showToast(`Settings not saved: ${err.message}`, "error");
    }
  });

  document.getElementById("btn-refresh-audit").addEventListener("click", loadAuditLogs);
  document.getElementById("btn-refresh-events").addEventListener("click", loadEvents);
}

let auditPage = 1;

function auditFilters() {
  const val = id => document.getElementById(id).value;
  const p = new URLSearchParams();
  if (val("au-q").trim()) p.set("q", val("au-q").trim());
  if (val("au-category")) p.set("category", val("au-category"));
  const range = val("au-range");
  if (range === "custom") {
    if (val("au-from")) p.set("from", Math.floor(new Date(val("au-from") + "T00:00").getTime() / 1000));
    if (val("au-to")) p.set("to", Math.floor(new Date(val("au-to") + "T00:00").getTime() / 1000) + 86400);
  } else if (range) {
    p.set("from", Math.floor(Date.now() / 1000) - Number(range));
  }
  return p;
}

function initAuditLog() {
  const form = document.getElementById("audit-filters");
  let typing = null;
  const reload = () => { auditPage = 1; loadAuditLogs(); };
  form.addEventListener("submit", ev => { ev.preventDefault(); reload(); });
  form.addEventListener("change", ev => {
    if (ev.target.id === "au-range") document.getElementById("au-dates").classList.toggle("hidden", ev.target.value !== "custom");
    if (ev.target.id !== "au-q") reload();
  });
  document.getElementById("au-q").addEventListener("input", () => { clearTimeout(typing); typing = setTimeout(reload, 300); });
  document.getElementById("au-clear").addEventListener("click", () => { form.reset(); hide(document.getElementById("au-dates")); reload(); });
  document.getElementById("audit-pager").addEventListener("click", ev => {
    const b = ev.target.closest("[data-page]");
    if (!b || b.disabled) return;
    auditPage = Number(b.dataset.page);
    loadAuditLogs().then(() => document.getElementById("view-audit").scrollIntoView({ block: "start" }));
  });
}

async function loadAuditLogs() {
  try {
    const p = auditFilters();
    const filtered = [...p.keys()].length > 0;
    p.set("page", auditPage);
    p.set("per_page", 50);
    const data = await api(`/api/audit?${p}`);
    const cat = document.getElementById("au-category");
    const keep = cat.value;
    cat.innerHTML = `<option value="">All categories</option>` + (data.categories || [])
      .map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
    cat.value = keep;
    document.getElementById("audit-pager").innerHTML = pagerHtml(data.page, data.pages, data.total, data.per_page);
    document.getElementById("au-clear").classList.toggle("hidden", !filtered);
    fillTable("audit-table-body", (data.logs || []).map(l => `
      <tr>
        <td data-sort="${escapeHtml(l.timestamp)}">${escapeHtml(formatTime(l.timestamp))}</td>
        <td class="text-cell"><span class="status-pill status-unknown">${escapeHtml(l.category)}</span></td>
        <td class="text-cell"><strong>${escapeHtml(l.message)}</strong></td>
        <td class="text-cell">${escapeHtml(l.actor || "")}</td>
        <td class="text-cell dim" data-perm="audit.sensitive">${escapeHtml(l.source || "")}</td>
        <td class="text-cell dim">${escapeHtml(l.details || "")}</td>
      </tr>`).join(""), document.getElementById("au-clear").classList.contains("hidden") ? "No audit logs recorded yet." : "No entries match these filters.", 6);
  } catch (err) {
    showToast(`Could not load audit log: ${err.message}`, "error");
  }
}

// --- Live Mode ---
//
// While a device page is open the browser renews a short server-side lease
// and fetches in-memory samples taken every few seconds. Charts, KPI cards
// and port rates for that device are redrawn with those samples appended.
// Nothing here is persisted; leaving the page lets the lease lapse.

const LIVE_STORE = "monitor.live.v1";
let liveEnabled = true;
try { liveEnabled = localStorage.getItem(LIVE_STORE) !== "off"; } catch (err) { liveEnabled = true; }
const live = { deviceId: null, timer: null, since: 0, metrics: {}, rates: {}, interval: null, granted: false };
const LIVE_WINDOW = 900;

function initLive() {
  document.getElementById("btn-live").addEventListener("click", () => {
    liveEnabled = !liveEnabled;
    try { localStorage.setItem(LIVE_STORE, liveEnabled ? "on" : "off"); } catch (err) { /* storage unavailable */ }
    if (liveEnabled && activeDeviceId) startLive(activeDeviceId);
    else { const id = live.deviceId; stopLive(); live.deviceId = id; }
    showToast(liveEnabled ? "Live mode on for this device page." : "Live mode off. Data refreshes at the normal poll interval.", "info");
    updateLivePill();
    applyLive();
  });
}

function resetLiveBuffers() {
  live.since = 0; live.metrics = {}; live.rates = {}; live.interval = null; live.granted = false;
}

function startLive(id) {
  if (live.deviceId !== id) resetLiveBuffers();
  live.deviceId = id;
  if (liveEnabled && !live.timer) {
    pollLive();
    live.timer = setInterval(pollLive, 5000);
  }
  updateLivePill();
}

function stopLive() {
  if (live.timer) clearInterval(live.timer);
  live.timer = null;
  live.deviceId = null;
  resetLiveBuffers();
}

async function pollLive() {
  const id = live.deviceId;
  if (!id || !liveEnabled) return;
  let r;
  try {
    r = await api(`/api/devices/${id}/live`, { method: "POST", body: { since: live.since } });
  } catch (err) {
    return;
  }
  if (live.deviceId !== id) return;
  live.granted = r.granted;
  live.interval = r.interval;
  const cutoff = Date.now() / 1000 - LIVE_WINDOW;
  for (const [key, pts] of Object.entries(r.metrics || {})) {
    const series = live.metrics[key] || (live.metrics[key] = []);
    pts.forEach(([t, v]) => { series.push({ timestamp: t, value: v }); live.since = Math.max(live.since, t); });
    while (series.length && series[0].timestamp < cutoff) series.shift();
  }
  for (const [idx, pts] of Object.entries(r.rates || {})) {
    const series = live.rates[idx] || (live.rates[idx] = []);
    pts.forEach(p => { series.push(p); live.since = Math.max(live.since, p[0]); });
    while (series.length && series[0][0] < cutoff) series.shift();
  }
  updateLivePill();
  applyLive();
}

function liveActiveFor(deviceId) {
  return liveEnabled && live.deviceId === deviceId && deviceId === activeDeviceId;
}

function updateLivePill() {
  const pill = document.getElementById("btn-live");
  pill.classList.remove("on", "waiting");
  if (!liveEnabled) {
    pill.textContent = "LIVE OFF";
  } else if (!live.granted && live.interval === null && live.timer) {
    pill.textContent = live.since ? "LIVE BUSY" : "LIVE \u2026";
    pill.classList.add("waiting");
  } else if (!live.granted) {
    pill.textContent = "LIVE BUSY";
    pill.title = "Too many device pages are in live mode. Close another one or raise the limit in Settings.";
    pill.classList.add("waiting");
  } else {
    pill.textContent = `LIVE ${Math.round(live.interval || 5)}s`;
    pill.classList.add("on");
  }
}

function livePointsFor(key) {
  const m = /^if\.(\d+)\.(in|out)_bps$/.exec(key || "");
  if (m) return (live.rates[m[1]] || []).map(p => ({ timestamp: p[0], value: m[2] === "in" ? p[1] : p[2] }));
  return live.metrics[key] || [];
}

/** Appends live samples newer than the last stored point to each series of a chart. */
function liveMergeSeries(series, opts) {
  if (!opts.deviceId || !liveActiveFor(opts.deviceId) || opts.hours > 24) return series;
  return series.map(s => {
    const last = s.points.length ? s.points[s.points.length - 1].timestamp : 0;
    const extra = livePointsFor(s.key).filter(p => p.timestamp > last + 1);
    return extra.length ? Object.assign({}, s, { points: s.points.concat(extra) }) : s;
  });
}

function liveLatest() {
  if (!liveActiveFor(activeDeviceId)) return {};
  const out = {};
  for (const [k, pts] of Object.entries(live.metrics)) if (pts.length) out[k] = pts[pts.length - 1].value;
  return out;
}

function liveRatesNow() {
  if (!liveActiveFor(activeDeviceId)) return {};
  const out = {};
  for (const [idx, pts] of Object.entries(live.rates)) {
    if (pts.length) out[idx] = { in_bps: pts[pts.length - 1][1], out_bps: pts[pts.length - 1][2] };
  }
  return out;
}

function applyLive() {
  if (!activeDeviceId) return;
  if (activeTab === "overview" && lastDetail) {
    const m = Object.fromEntries(lastDetail.latest_metrics.map(x => [x.metric_key, x.value]));
    renderOverviewKpis(lastDetail, Object.assign(m, liveLatest()));
  }
  document.querySelectorAll("#view-device-detail .chart-host").forEach(host => {
    if (host._chart) drawChart(host, liveMergeSeries(host._chart.series, host._chart.opts), host._chart.opts);
  });
  if (activeTab === "ports" && portsCache) loadPorts(true);
}

// --- Dashboard ---
//
// A grid of tiles the user can reorder by dragging, resize (1 to 4 columns),
// configure and remove. The layout is stored server-side so it is the same in
// every browser. All tiles share one data fetch per refresh.

const WIDGETS = {
  summary: { title: "Status summary", span: 4 },
  problems: { title: "Active problems", span: 2 },
  availability: { title: "Device availability", span: 2 },
  wan: { title: "Internet (WAN)", span: 2 },
  top_ports: { title: "Busiest ports", span: 2, config: { limit: 8 } },
  wireless: { title: "Wireless", span: 2 },
  top_cpu: { title: "Device load", span: 2 },
  events: { title: "Recent events", span: 4, config: { limit: 12 } },
  graph: { title: "Graph (pick any device graph)", span: 2, config: {} },
  offline: { title: "Offline now", span: 2 },
  proxmox: { title: "Proxmox guests", span: 2 },
  pihole: { title: "Pi-hole", span: 2 },
  storage: { title: "Disks filling up", span: 2 },
  host_actions: { title: "Host actions", span: 2 },
  workflows: { title: "Workflow runs", span: 2 },
  maintenance: { title: "Maintenance windows", span: 2 },
  new_devices: { title: "New devices", span: 2 },
  note: { title: "Note", span: 2, config: { text: "" } },
};
// Tiles drawn from GET /api/dashboard/extras, fetched only when the dashboard shows one.
const DASH_EXTRAS = new Set(["proxmox", "pihole", "storage", "host_actions", "workflows", "maintenance", "new_devices"]);
let dashName = "default";
let dashTitle = "Overview";
let dashList = [];
let dashLayout = [];
let dashDefault = [];
let dashColumns = 4;
let dashColumnOptions = [2, 3, 4, 6, 8, 12];
const DASH_ROW_PX = 90;
const DASH_GAP_PX = 14;
const DEFAULT_ROWS = { summary: 2, problems: 3, availability: 3, events: 4, graph: 3, top_ports: 4, top_cpu: 4, wireless: 3, wan: 4,
  offline: 3, proxmox: 4, pihole: 2, storage: 3, host_actions: 3, workflows: 3, maintenance: 2, new_devices: 3, note: 2 };
const dashStore = { get() { try { return localStorage.getItem("dash-current") || ""; } catch (e) { return ""; } },
                    set(v) { try { localStorage.setItem("dash-current", v); } catch (e) { /* private window */ } } };
let dashEditing = false;
let dashData = null;
let dashGraphsAt = 0;
let dragId = null;
let dashObserver = null;

function applyWidgetSize(el, w) {
  el.style.gridColumn = `span ${Math.min(w.span, dashColumns)}`;
  el.style.gridRow = `span ${w.rows || DEFAULT_ROWS[w.type] || 3}`;
}
let widgetBeingConfigured = null;

function initDashboard() {
  const grid = document.getElementById("dash-grid");
  const addSel = document.getElementById("dash-add");
  addSel.innerHTML = `<option value="">+ Add tile...</option>` +
    Object.entries(WIDGETS).map(([type, w]) => `<option value="${escapeHtml(type)}">${escapeHtml(w.title)}</option>`).join("");

  document.getElementById("dash-edit").addEventListener("click", () => {
    dashEditing = !dashEditing;
    document.getElementById("dash-edit").textContent = dashEditing ? "Done" : "Edit dashboard";
    document.getElementById("dash-edit").classList.toggle("btn-primary", dashEditing);
    ["dash-add", "dash-reset", "dash-edit-hint", "dash-columns", "dash-rename", "dash-delete"].forEach(id => document.getElementById(id).classList.toggle("hidden", !dashEditing));
    document.getElementById("dash-delete").classList.toggle("hidden", !dashEditing || dashList.length < 2);
    if (!dashEditing) showToast(`${dashTitle} saved.`, "success");
    renderDashboard();
    updateToTop();
  });
  addSel.addEventListener("change", async () => {
    const type = addSel.value;
    addSel.value = "";
    if (!type) return;
    const w = { id: `w-${type}-${Date.now().toString(36)}`, type, span: Math.min(dashColumns, Math.max(1, Math.round(WIDGETS[type].span * dashColumns / 4))),
                rows: DEFAULT_ROWS[type] || 3, config: Object.assign({}, WIDGETS[type].config || {}) };
    if (FILTERABLE_WIDGETS.has(type)) {
      const f = await chooseWidgetFilter(WIDGETS[type].title);
      if (f === null) return;
      if (f) w.config.filter = f;
    }
    dashLayout.push(w);
    saveDashboard();
    renderDashboard();
    if (type === "graph") openWidgetConfig(w);
  });
  document.getElementById("dash-pick").addEventListener("change", (ev) => loadDashboard(ev.target.value));
  document.getElementById("dash-new").addEventListener("click", openAddDashboard);
  document.getElementById("dash-rename").addEventListener("click", async () => {
    const t = await promptDialog({ title: "Rename this dashboard", input: { value: dashTitle, placeholder: "Overview" }, confirmLabel: "Rename" });
    if (t === null || !t.trim()) return;
    dashTitle = t.trim().slice(0, 60);
    await saveDashboard();
    await loadDashboard(dashName);
  });
  document.getElementById("dash-delete").addEventListener("click", async () => {
    if (!(await confirmDialog({ title: `Delete ${dashTitle}?`, message: "This dashboard and its tiles are removed for everyone. The other dashboards stay.",
      confirmLabel: "Delete", danger: true }))) return;
    try {
      const r = await api(`/api/dashboards/${encodeURIComponent(dashName)}`, { method: "DELETE" });
      await loadDashboard(r.dashboards[0].name);
      showToast("Dashboard deleted.", "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  });
  document.getElementById("dash-reset").addEventListener("click", async () => {
    if (!(await confirmDialog({ title: "Reset the dashboard?", message: "Your tiles, sizes and order are replaced with the default layout.",
      confirmLabel: "Reset", danger: true }))) return;
    dashLayout = JSON.parse(JSON.stringify(dashDefault));
    saveDashboard();
    renderDashboard();
  });

  grid.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-act]");
    if (!btn) return;
    const w = dashLayout.find(x => x.id === btn.closest("[data-wid]").dataset.wid);
    if (!w) return;
    const pos = dashLayout.indexOf(w);
    if (btn.dataset.act === "left" && pos > 0) dashLayout.splice(pos - 1, 0, dashLayout.splice(pos, 1)[0]);
    if (btn.dataset.act === "right" && pos < dashLayout.length - 1) dashLayout.splice(pos + 1, 0, dashLayout.splice(pos, 1)[0]);
    if (btn.dataset.act === "shrink") w.span = Math.max(1, w.span - 1);
    if (btn.dataset.act === "grow") w.span = Math.min(dashColumns, w.span + 1);
    if (btn.dataset.act === "remove") dashLayout = dashLayout.filter(x => x !== w);
    if (btn.dataset.act === "config") { openWidgetConfig(w); return; }
    if (btn.dataset.act === "rename") { renameWidget(w); return; }
    if (btn.dataset.act === "note") { editNote(w); return; }
    saveDashboard();
    renderDashboard();
  });
  grid.addEventListener("change", (ev) => {
    const sel = ev.target.closest("[data-act-filter]");
    if (!sel) return;
    const w = dashLayout.find(x => x.id === sel.closest("[data-wid]").dataset.wid);
    if (!w) return;
    if (sel.value) w.config.filter = sel.value; else delete w.config.filter;
    saveDashboard();
    renderDashboard();
  });

  // Pointer-based reordering: drag a tile by its header. Works with mouse, pen and
  // touch, and is not hijacked by links or tables inside the tile the way native
  // HTML5 drag and drop is.
  let drag = null;
  const clearMarks = () => grid.querySelectorAll(".drop-before, .drop-after, .dragging")
    .forEach(el => el.classList.remove("drop-before", "drop-after", "dragging"));
  grid.addEventListener("pointerdown", (ev) => {
    const head = ev.target.closest(".widget-head");
    if (!dashEditing || !head || ev.target.closest("button, a, select, input, [data-act]") || ev.button !== 0) return;
    const el = head.closest("[data-wid]");
    drag = { id: el.dataset.wid, el, over: null, after: false };
    el.classList.add("dragging");
    head.setPointerCapture(ev.pointerId);
    ev.preventDefault();
  });
  grid.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    grid.querySelectorAll(".drop-before, .drop-after").forEach(el => el.classList.remove("drop-before", "drop-after"));
    const hit = document.elementFromPoint(ev.clientX, ev.clientY);
    const over = hit && hit.closest("#dash-grid [data-wid]");
    if (!over || over === drag.el) { drag.over = null; return; }
    const rect = over.getBoundingClientRect();
    drag.over = over;
    drag.after = ev.clientX > rect.left + rect.width / 2;
    over.classList.add(drag.after ? "drop-after" : "drop-before");
  });
  const finishDrag = (commit) => {
    if (!drag) return;
    const { id, over, after } = drag;
    drag = null;
    clearMarks();
    if (!commit || !over) return;
    const moving = dashLayout.find(x => x.id === id);
    dashLayout = dashLayout.filter(x => x !== moving);
    const target = dashLayout.findIndex(x => x.id === over.dataset.wid);
    dashLayout.splice(target + (after ? 1 : 0), 0, moving);
    saveDashboard();
    renderDashboard();
  };
  grid.addEventListener("pointerup", () => finishDrag(true));
  grid.addEventListener("pointercancel", () => finishDrag(false));

  // Corner resize: width snaps to grid columns, height to 90 px rows.
  let resize = null;
  grid.addEventListener("pointerdown", (ev) => {
    const handle = ev.target.closest(".resize-handle");
    if (!dashEditing || !handle) return;
    const el = handle.closest("[data-wid]");
    // Measure from where the drag began: the tile may move to another row while it grows.
    const start = el.getBoundingClientRect();
    resize = { el, w: dashLayout.find(x => x.id === el.dataset.wid), left: start.left, top: start.top };
    el.classList.add("resizing");
    handle.setPointerCapture(ev.pointerId);
    ev.preventDefault();
    ev.stopPropagation();
  });
  grid.addEventListener("pointermove", (ev) => {
    if (!resize) return;
    const colW = (grid.clientWidth - DASH_GAP_PX * (dashColumns - 1)) / dashColumns;
    const span = Math.max(1, Math.min(dashColumns, Math.round((ev.clientX - resize.left + DASH_GAP_PX) / (colW + DASH_GAP_PX))));
    const rows = Math.max(1, Math.min(12, Math.round((ev.clientY - resize.top + DASH_GAP_PX) / (DASH_ROW_PX + DASH_GAP_PX))));
    if (span !== resize.w.span || rows !== resize.w.rows) {
      resize.w.span = span;
      resize.w.rows = rows;
      applyWidgetSize(resize.el, resize.w);
    }
    resize.el.querySelector(".size-badge").textContent = `${span} x ${rows}`;
  });
  const endResize = () => {
    if (!resize) return;
    resize.el.classList.remove("resizing");
    resize = null;
    saveDashboard();
  };
  grid.addEventListener("pointerup", endResize);
  grid.addEventListener("pointercancel", endResize);

  document.getElementById("dash-columns").addEventListener("change", (ev) => {
    const next = parseInt(ev.target.value, 10);
    // Keep each tile's share of the width when the grid changes.
    dashLayout.forEach(w => { w.span = Math.max(1, Math.min(next, Math.round(w.span * next / dashColumns))); });
    dashColumns = next;
    saveDashboard();
    renderDashboard();
  });

  // Tile contents follow the tile size: charts are redrawn at the new size from the
  // history they already hold (no refetch); tables and tile grids reflow by CSS.
  const pending = new Map();
  dashObserver = new ResizeObserver(entries => {
    for (const entry of entries) {
      const body = entry.target;
      clearTimeout(pending.get(body));
      pending.set(body, setTimeout(() => {
        body.querySelectorAll(".chart-host").forEach(h => {
          if (h._chart) drawChart(h, liveMergeSeries(h._chart.series, h._chart.opts), h._chart.opts);
        });
      }, 120));
    }
  });

  const modal = document.getElementById("modal-widget");
  const close = () => { hide(modal); widgetBeingConfigured = null; };
  document.getElementById("btn-close-widget").addEventListener("click", close);
  document.getElementById("btn-cancel-widget").addEventListener("click", close);
  document.getElementById("widget-device").addEventListener("change", () => loadWidgetGraphOptions());
  document.getElementById("btn-save-widget").addEventListener("click", () => {
    const w = widgetBeingConfigured;
    const def = widgetGraphDefs[document.getElementById("widget-graph").value];
    if (!w || !def) { close(); return; }
    w.config = {
      device_id: parseInt(document.getElementById("widget-device").value, 10),
      title: def.title, series: def.series, fmt: def.fmt, max: def.max || null, step: !!def.step,
      hours: parseInt(document.getElementById("widget-hours").value, 10),
      compare: document.getElementById("widget-compare").checked,
    };
    close();
    saveDashboard();
    dashGraphsAt = 0;
    renderDashboard();
  });
}

async function saveDashboard() {
  try {
    await api("/api/dashboard", { method: "PUT", body: { name: dashName, title: dashTitle, layout: dashLayout, columns: dashColumns } });
  } catch (err) {
    showToast(`Dashboard not saved: ${err.message}`, "error");
  }
}

async function renameWidget(w) {
  const t = await promptDialog({ title: "Rename this tile", message: "Leave it empty to go back to the standard name.",
    input: { value: w.name || "", placeholder: widgetTitle(Object.assign({}, w, { name: "" })) }, confirmLabel: "Rename" });
  if (t === null) return;
  if (t.trim()) w.name = t.trim().slice(0, 60); else delete w.name;
  saveDashboard();
  renderDashboard();
}

async function editNote(w) {
  const t = await promptDialog({ title: "Note", message: "Plain text, shown as written: a reminder, who to call, where the spare cables are.",
    input: { value: w.config.text || "", multiline: true }, confirmLabel: "Save" });
  if (t === null) return;
  w.config.text = t.slice(0, 1500);
  saveDashboard();
  renderDashboard();
}

/** Add dashboard: a name, then blank or one of the ready-made dashboards. */
async function openAddDashboard() {
  let data;
  try {
    data = await api("/api/dashboards");
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  const card = (id, title, desc, tiles) => `<label class="dash-tpl"><input type="radio" name="dash-tpl" value="${escapeHtml(id)}"${id ? "" : " checked"}>
    <span class="dash-tpl-body"><strong>${escapeHtml(title)}</strong><span class="dim">${escapeHtml(desc)}</span>
    ${tiles ? `<span class="dash-tpl-tiles">${tiles.map(t => `<span class="dash-chip">${escapeHtml((WIDGETS[t] || { title: t }).title)}</span>`).join("")}</span>` : ""}</span></label>`;
  back.innerHTML = `<form class="modal dialog modal-wide" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Add dashboard</span></div>
    <div class="modal-body">
      <div class="form-group"><label for="dash-new-title">Name</label><input id="dash-new-title" type="text" maxlength="60" placeholder="My dashboard"></div>
      <div class="form-help">Start blank and add tiles yourself, or pick a ready-made one. Either way you can change it afterwards with Edit dashboard.</div>
      <div class="dash-tpl-grid">${card("", "Blank", "An empty grid: add the tiles you want.", null)}
        ${data.templates.map(t => card(t.id, t.title, t.description, Array.from(new Set(t.tiles)))).join("")}</div>
    </div>
    <div class="modal-footer"><button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Add dashboard</button></div>
  </form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  const title = form.querySelector("#dash-new-title");
  const close = () => back.remove();
  form.addEventListener("change", ev => {
    // The template's name is a good start; your own typing wins.
    if (ev.target.name === "dash-tpl" && (!title.value || title.dataset.auto === "1")) {
      const t = data.templates.find(x => x.id === ev.target.value);
      title.value = t ? t.title : "";
      title.dataset.auto = "1";
    }
  });
  title.addEventListener("input", () => { title.dataset.auto = "0"; });
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    const template = form.querySelector("input[name=dash-tpl]:checked").value;
    try {
      const r = await api("/api/dashboards", { method: "POST", body: { title: title.value.trim() || "New dashboard", template } });
      close();
      await loadDashboard(r.name);
      if (!template && !dashEditing) document.getElementById("dash-edit").click();
      showToast(`${r.title} added.`, "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  });
  form.querySelector("[data-x]").addEventListener("click", close);
  back.addEventListener("keydown", ev => { if (ev.key === "Escape") close(); });
  title.focus();
}

function renderDashSwitch() {
  document.getElementById("dash-title").textContent = dashTitle;
  const pick = document.getElementById("dash-pick");
  pick.innerHTML = dashList.map(d => `<option value="${escapeHtml(d.name)}"${d.name === dashName ? " selected" : ""}>${escapeHtml(d.title)}</option>`).join("");
  pick.classList.toggle("hidden", dashList.length < 2);
  document.getElementById("dash-delete").classList.toggle("hidden", !dashEditing || dashList.length < 2);
}

async function loadDashboard(name) {
  document.getElementById("dash-setup-banner").classList.toggle("hidden", setupCompleted !== false);
  const want = typeof name === "string" && name ? name : dashStore.get() || "default";
  try {
    let r;
    try {
      r = await api(`/api/dashboard?name=${encodeURIComponent(want)}`);
    } catch (err) {
      r = await api("/api/dashboard");          // the remembered one was deleted: back to the first
      if (r.dashboards.length && !r.dashboards.some(d => d.name === "default")) r = await api(`/api/dashboard?name=${encodeURIComponent(r.dashboards[0].name)}`);
    }
    dashName = r.name;
    dashTitle = r.title;
    dashList = r.dashboards;
    dashStore.set(dashName);
    renderDashSwitch();
    dashLayout = r.layout;
    dashDefault = r.default;
    dashColumns = r.columns || 4;
    dashColumnOptions = r.column_options || dashColumnOptions;
    const sel = document.getElementById("dash-columns");
    sel.innerHTML = dashColumnOptions.map(n => `<option value="${escapeHtml(n)}" ${n === dashColumns ? "selected" : ""}>${escapeHtml(n)} columns</option>`).join("");
  } catch (err) {
    showToast(`Could not load dashboard: ${err.message}`, "error");
    return;
  }
  dashGraphsAt = 0;
  renderDashboard();
}

function widgetTitle(w) {
  if (w.name) return w.name;
  if (w.type === "graph" && w.config.title) {
    const dev = dashData && dashData.devices.find(d => d.id === w.config.device_id);
    return `${dev ? dev.hostname + ": " : ""}${w.config.title}`;
  }
  return WIDGETS[w.type].title;
}

function renderDashboard() {
  const grid = document.getElementById("dash-grid");
  grid.classList.toggle("editing", dashEditing);
  grid.style.gridTemplateColumns = `repeat(${dashColumns}, minmax(0, 1fr))`;
  if (dashObserver) dashObserver.disconnect();
  grid.innerHTML = dashLayout.map(w => `
    <div class="widget" data-wid="${escapeHtml(w.id)}">
      <div class="widget-head">
        <span><span class="drag-handle" title="Drag to move">\u2807</span><span data-title>${escapeHtml(widgetTitle(w))}</span></span>
        <span class="dim" data-sub></span>
        <div class="widget-tools">
          <button class="btn" data-act="left" title="Move earlier">&larr;</button>
          <button class="btn" data-act="right" title="Move later">&rarr;</button>
          <button class="btn" data-act="rename" title="Rename this tile">Rename</button>
          <button class="btn" data-act="shrink" title="Narrower">&minus;</button>
          <button class="btn" data-act="grow" title="Wider">+</button>
          ${w.type === "graph" ? `<button class="btn" data-act="config" title="Choose device, graph and time range">Configure</button>` : ""}
          ${w.type === "note" ? `<button class="btn" data-act="note" title="Write the note">Edit text</button>` : ""}
          ${FILTERABLE_WIDGETS.has(w.type) ? widgetFilterSelect(w) : ""}
          <button class="btn btn-danger" data-act="remove" title="Remove tile">&times;</button>
        </div>
      </div>
      <div class="widget-body" data-body></div>
      <span class="resize-handle" title="Drag to resize"></span>
      <span class="size-badge"></span>
    </div>`).join("") || `<div class="panel panel-padded dim">The dashboard is empty. Click "Edit dashboard" and add tiles.</div>`;
  grid.querySelectorAll("[data-wid]").forEach(el => {
    const w = dashLayout.find(x => x.id === el.dataset.wid);
    applyWidgetSize(el, w);
    el.querySelector(".size-badge").textContent = `${w.span} x ${w.rows}`;
    if (dashObserver) dashObserver.observe(el.querySelector("[data-body]"));
  });
  dashGraphsAt = 0;
  refreshDashboard();
}

async function refreshDashboard() {
  const hash = window.location.hash || "#/dashboard";
  if (hash !== "#/dashboard" && hash !== "#/") return;
  const topLimit = Math.max(5, ...dashLayout.filter(w => w.type === "top_ports").map(w => w.config.limit || 8));
  const evLimit = Math.max(10, ...dashLayout.filter(w => w.type === "events").map(w => w.config.limit || 12));
  try {
    const [devices, problems, events, top, wan] = await Promise.all([
      api("/api/devices"), api("/api/problems"), api("/api/events"),
      api(`/api/interfaces/top?limit=${topLimit}`), api("/api/wan"),
    ]);
    const want = Array.from(new Set(dashLayout.map(w => w.type).filter(t => DASH_EXTRAS.has(t))));
    const extras = want.length ? await api(`/api/dashboard/extras?want=${want.join(",")}`) : {};
    dashData = { devices: devices.devices, problems: shownProblems(problems.problems), events: events.events.slice(0, evLimit),
                 top: top.interfaces, wan: wan.wan, extras };
  } catch (err) {
    console.error("Dashboard refresh failed", err);
    return;
  }
  const redrawGraphs = Date.now() - dashGraphsAt > 60000;
  if (redrawGraphs) dashGraphsAt = Date.now();
  for (const w of dashLayout) {
    const el = document.querySelector(`#dash-grid [data-wid="${CSS.escape(w.id)}"]`);
    if (!el) continue;
    el.querySelector("[data-title]").textContent = widgetTitle(w);
    const body = el.querySelector("[data-body]");
    const sub = el.querySelector("[data-sub]");
    // A tile set to one group or tag draws from that part of the data only.
    const all = dashData;
    dashData = widgetData(w, all);
    try {
      (DASH_RENDER[w.type] || DASH_RENDER_MORE[w.type])(w, body, sub, redrawGraphs);
      applyBars(body);
      if (w.config.filter) sub.textContent = [sub.textContent, widgetFilterLabel(w.config.filter)].filter(Boolean).join(", ");
    } catch (err) {
      body.innerHTML = `<div class="chart-empty">${escapeHtml(err.message)}</div>`;
    } finally {
      dashData = all;
    }
  }
}

// Tiles that can show one group or one tag (config.filter: "group:<id>" or "tag:<name>").
const FILTERABLE_WIDGETS = new Set(["summary", "problems", "availability", "events", "top_ports", "top_cpu", "wireless", "offline"]);

function widgetFilterLabel(f) {
  if (f.startsWith("group:")) return (DEVICE_GROUPS[f.slice(6)] || [f.slice(6)])[0];
  return `tag ${f.slice(4)}`;
}

function widgetFilterSelect(w) {
  const v = w.config.filter || "";
  const opts = [["", "All devices"]]
    .concat(taxo.groups.filter(g => g.devices).map(g => [`group:${g.id}`, `Group: ${g.name}`]))
    .concat(taxo.tags.map(t => [`tag:${t.name}`, `Tag: ${t.name}`]));
  return `<select data-act-filter title="Show all devices, one group or one tag">${opts.map(([k, l]) =>
    `<option value="${escapeHtml(k)}"${k === v ? " selected" : ""}>${escapeHtml(l)}</option>`).join("")}</select>`;
}

/** Asked when a tile that can be narrowed is added: "" for all devices, "group:x" or "tag:y", null when cancelled. */
function chooseWidgetFilter(title) {
  return new Promise(resolve => {
    const back = document.createElement("div");
    back.className = "modal-backdrop dialog-backdrop";
    const opts = [["", "All devices"]]
      .concat(taxo.groups.filter(g => g.devices).map(g => [`group:${g.id}`, `Group: ${g.name}`]))
      .concat(taxo.tags.map(t => [`tag:${t.name}`, `Tag: ${t.name}`]));
    back.innerHTML = `<form class="modal dialog" role="dialog" aria-modal="true">
      <div class="modal-header"><span>Add ${escapeHtml(title)}</span></div>
      <div class="modal-body">
        <div class="form-group"><label for="wf-filter">Show</label>
          <select id="wf-filter">${opts.map(([k, l]) => `<option value="${escapeHtml(k)}">${escapeHtml(l)}</option>`).join("")}</select>
          <div class="form-help">${taxo.tags.length ? "Only these devices, their problems and events. Change it later with the list in the tile's header."
            : "No tags yet: add them on the Devices page (+ tag beside a name) to show only those devices here."}</div></div>
      </div>
      <div class="modal-footer"><button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">Add tile</button></div>
    </form>`;
    document.body.appendChild(back);
    const form = back.querySelector("form");
    const done = v => { back.remove(); resolve(v); };
    form.addEventListener("submit", ev => { ev.preventDefault(); done(form.querySelector("#wf-filter").value); });
    form.querySelector("[data-x]").addEventListener("click", () => done(null));
    back.addEventListener("keydown", ev => { if (ev.key === "Escape") done(null); });
    form.querySelector("#wf-filter").focus();
  });
}

/** The dashboard data seen by one tile: everything, or one group's or tag's devices and their problems, events and ports. */
function widgetData(w, all) {
  const f = w.config.filter;
  if (!f || !FILTERABLE_WIDGETS.has(w.type)) return all;
  const group = f.startsWith("group:") ? f.slice(6) : "", tag = f.startsWith("tag:") ? f.slice(4) : "";
  const devices = all.devices.filter(d => deviceMatches(d, group, tag));
  const ids = new Set(devices.map(d => d.id));
  return { ...all, devices, problems: all.problems.filter(p => ids.has(p.device_id)),
           events: all.events.filter(e => ids.has(e.device_id)), top: all.top.filter(r => ids.has(r.device_id)) };
}

function deviceLink(id, name) {
  return `<a class="device-link" href="#/device/${Number(id)}">${escapeHtml(name)}</a>`;
}

/** An extras part, or a message in the tile when it is missing or not allowed. */
function dashExtra(body, part) {
  const x = (dashData.extras || {})[part];
  if (!x) { body.innerHTML = `<div class="empty-cell">Loading...</div>`; return null; }
  if (x.error) { body.innerHTML = `<div class="empty-cell">${escapeHtml(x.error)}</div>`; return null; }
  return x;
}
const dashTable = (head, rows, empty) => rows.length
  ? `<table><thead><tr>${head.map(h => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`
  : `<div class="empty-cell">${escapeHtml(empty)}</div>`;
const runPill = s => `<span class="status-pill ${s === "success" || s === "ok" ? "status-ok" : s === "running" ? "sev-pill-info" : s === "failed" || s === "error" || s === "interrupted" ? "status-err" : "status-warn"}">${escapeHtml(s || "?")}</span>`;

const DASH_RENDER_MORE = {
  offline(w, body, sub) {
    body.classList.add("flush");
    const since = {};
    dashData.problems.forEach(p => { if (p.problem_key === "unreachable") since[p.device_id] = p.since; });
    const down = dashData.devices.filter(d => d.status === "offline").sort((a, b) => (since[a.id] || 0) - (since[b.id] || 0));
    sub.textContent = down.length ? `${down.length} offline` : "";
    body.innerHTML = down.length ? dashTable(["Device", "Address", "Down for"], down.map(d => `<tr>
        <td class="text-cell">${deviceLink(d.id, d.hostname)}</td><td class="dim">${escapeHtml(d.ip_address)}</td>
        <td>${since[d.id] ? escapeHtml(formatSince(since[d.id])) : "-"}</td></tr>`), "")
      : `<div class="ok-state">Everything is online.</div>`;
  },
  proxmox(w, body, sub) {
    const x = dashExtra(body, "proxmox");
    if (!x) return;
    body.classList.add("flush");
    const running = x.guests.filter(g => g.status === "running").length;
    sub.textContent = `${running} / ${x.guests.length} running, ${x.nodes.length} node${x.nodes.length === 1 ? "" : "s"}`;
    const order = g => (g.status === "running" ? 2 : g.onboot ? 0 : 1);
    const guests = x.guests.slice().sort((a, b) => order(a) - order(b) || String(a.name).localeCompare(String(b.name)));
    body.innerHTML = dashTable(["Guest", "Node", "State", "Memory"], guests.map(g => `<tr>
      <td class="text-cell">${g.device_id ? deviceLink(g.device_id, g.name || g.vmid) : escapeHtml(g.name || String(g.vmid))} <span class="dim">${escapeHtml(g.type)} ${Number(g.vmid)}</span></td>
      <td class="dim">${escapeHtml(g.node)}</td>
      <td><span class="status-pill ${g.status === "running" ? "status-ok" : g.onboot ? "status-err" : "status-unknown"}" title="${g.onboot ? "Starts at boot" : ""}">${escapeHtml(g.status || "?")}</span></td>
      <td class="bar-cell">${g.maxmem && isNum(g.mem) ? barHtml(100 * g.mem / g.maxmem) : "-"}</td></tr>`), "No guests found yet.");
  },
  pihole(w, body, sub) {
    const x = dashExtra(body, "pihole");
    if (!x) return;
    const m = x.metrics;
    sub.textContent = x.device ? x.device.hostname : "";
    const n = v => isNum(v) ? Math.round(v).toLocaleString() : "-";
    body.innerHTML = `<div class="summary-tiles">
      ${statTile(n(m["pihole.queries"]), "Queries today", "", "#/pihole")}
      ${statTile(isNum(m["pihole.blocked_pct"]) ? m["pihole.blocked_pct"].toFixed(1) + "%" : "-", "Blocked", "", "#/pihole")}
      ${statTile(m["pihole.blocking"] === 1 ? "On" : m["pihole.blocking"] === 0 ? "Off" : "-", "Blocking", m["pihole.blocking"] === 0 ? "stat-bad" : "stat-ok", "#/pihole")}
      ${statTile(isNum(m["dns.ms"]) ? m["dns.ms"].toFixed(0) + " ms" : m["dns.ok"] === 0 ? "No answer" : "-", "DNS answer", m["dns.ok"] === 0 ? "stat-bad" : "", "#/pihole")}
    </div>`;
  },
  storage(w, body, sub) {
    const x = dashExtra(body, "storage");
    if (!x) return;
    body.classList.add("flush");
    const soon = x.rows.filter(r => r.days !== null && r.days !== undefined);
    sub.textContent = soon.length ? `${soon.length} growing` : "";
    body.innerHTML = dashTable(["Device", "Volume", "Used", "Full in"], x.rows.slice(0, 12).map(r => `<tr>
      <td class="text-cell">${deviceLink(r.device_id, r.hostname)}</td><td class="text-cell">${escapeHtml(r.label)}</td>
      <td class="bar-cell">${barHtml(r.now)}</td>
      <td class="${isNum(r.days) && r.days < 30 ? "text-bad" : "dim"}">${isNum(r.days) ? `${Math.round(r.days)} days` : "not filling"}</td></tr>`), "No disk history yet.");
  },
  host_actions(w, body) {
    const x = dashExtra(body, "host_actions");
    if (!x) return;
    body.classList.add("flush");
    body.innerHTML = dashTable(["When", "Host", "Action", "Result"], x.runs.slice(0, 10).map(r => `<tr>
      <td class="dim">${escapeHtml(formatAgo(r.started_at))}</td><td class="text-cell">${deviceLink(r.device_id, r.hostname)}</td>
      <td class="text-cell"><a href="#/automation" title="${escapeHtml(r.username || "")}">${escapeHtml(r.name)}${r.choice ? ` <span class="dim">${escapeHtml(r.choice)}</span>` : ""}</a></td>
      <td>${runPill(r.status)}</td></tr>`), "No host actions have run yet.");
  },
  workflows(w, body) {
    const x = dashExtra(body, "workflows");
    if (!x) return;
    body.classList.add("flush");
    body.innerHTML = dashTable(["When", "Workflow", "Started by", "Result"], x.runs.slice(0, 10).map(r => `<tr>
      <td class="dim">${escapeHtml(formatAgo(r.started_at))}</td><td class="text-cell"><a href="#/automation">${escapeHtml(r.name)}</a></td>
      <td class="dim">${escapeHtml(r.trigger || "")}</td><td>${runPill(r.status)}</td></tr>`), "No workflow has run yet.");
  },
  maintenance(w, body, sub) {
    const x = dashExtra(body, "maintenance");
    if (!x) return;
    body.classList.add("flush");
    const now = Date.now() / 1000;
    const list = x.windows.filter(m => m.end > now).sort((a, b) => a.start - b.start);
    sub.textContent = list.filter(m => m.start <= now).length ? "in maintenance now" : "";
    body.innerHTML = dashTable(["What", "From", "Until", "Note"], list.map(m => `<tr>
      <td class="text-cell">${escapeHtml(m.label || `${m.scope} ${m.target || ""}`)}${m.start <= now ? ` <span class="status-pill sev-pill-info">now</span>` : ""}</td>
      <td class="dim">${escapeHtml(formatTime(m.start))}</td><td class="dim">${escapeHtml(formatTime(m.end))}</td>
      <td class="text-cell dim">${escapeHtml(m.note || "")}</td></tr>`), "No maintenance planned.");
  },
  new_devices(w, body, sub) {
    const x = dashExtra(body, "new_devices");
    if (!x) return;
    body.classList.add("flush");
    sub.textContent = x.count ? `${x.count} not marked known` : "";
    body.innerHTML = dashTable(["Device", "Address", "Wi-Fi", "First seen"], x.rows.slice(0, 12).map(r => `<tr>
      <td class="text-cell"><a href="#/inventory">${escapeHtml(r.hostname || r.vendor || r.mac)}</a></td>
      <td class="dim">${escapeHtml(r.ip || "")}</td><td class="dim">${escapeHtml(r.ssid || "")}</td>
      <td class="dim">${escapeHtml(formatAgo(r.first_seen))}</td></tr>`), "No unknown devices. Everything seen is marked known.");
  },
  note(w, body) {
    const text = (w.config.text || "").trim();
    body.innerHTML = text ? `<div class="dash-note">${escapeHtml(text)}</div>`
      : `<div class="empty-cell">${dashEditing ? "Click Edit text to write the note." : "Empty note."}</div>`;
  },
};

const DASH_RENDER = {
  summary(w, body) {
    const d = dashData.devices;
    const online = d.filter(x => x.status === "online").length;
    const offline = d.filter(x => x.status === "offline").length;
    const crit = dashData.problems.filter(p => isOpenProblem(p) && p.severity === "critical").length;
    const high = dashData.problems.filter(p => isOpenProblem(p) && p.severity === "high").length;
    const warn = dashData.problems.filter(p => isOpenProblem(p) && p.severity === "warning").length;
    const clients = d.reduce((a, x) => a + (x.summary.clients || 0), 0);
    const wan = dashData.wan[0];
    body.innerHTML = `<div class="summary-tiles">
      ${statTile(d.length, "Devices", "", "#/devices")}
      ${statTile(online, "Online", "stat-ok", "#/devices/online")}
      ${statTile(offline, "Offline", offline ? "stat-bad" : "", "#/devices/offline")}
      ${high ? statTile(`${crit} / ${high} / ${warn}`, "Critical / high / warning", crit || high ? "stat-bad" : "stat-warn", "#/devices/problems")
        : statTile(`${crit} / ${warn}`, "Critical / warning", crit ? "stat-bad" : warn ? "stat-warn" : "", "#/devices/problems")}
      ${statTile(clients, "Wireless clients", "", "#/devices/wireless")}
      ${wan ? statTile(`${formatBps(wan.in_bps)}`, `WAN down (up ${formatBps(wan.out_bps)})`, wan.oper === 1 ? "" : "stat-bad", `#/device/${wan.device_id}/ports`) : ""}
    </div>`;
  },

  problems(w, body, sub) {
    // Only what still needs someone: an acknowledged problem has been seen to, so it lives on the
    // Devices page (Acknowledged problems) and the device's own page, not here.
    const list = shownProblems(dashData.problems).filter(p => !p.acknowledged_at);
    sub.textContent = list.length ? `${list.length} open` : "";
    body.classList.add("flush");
    if (!list.length) {
      body.innerHTML = `<div class="ok-state">Nothing needs attention.</div>`;
      return;
    }
    body.innerHTML = `<table><tbody>${list.map(p => `
      <tr class="${p.acknowledged_at ? "acked" : ""}">
        <td>${severityPill(p.severity)}</td>
        <td class="text-cell">${deviceLink(p.device_id, p.hostname)}</td>
        <td class="text-cell">${escapeHtml(p.message)}${ackLabel(p)}</td>
        <td class="dim">${escapeHtml(formatSince(p.since))}</td>
        <td>${p.severity !== "info" ? ackButton(p) : ""}</td>
      </tr>`).join("")}</tbody></table>`;
  },

  availability(w, body, sub) {
    const probBy = {};
    dashData.problems.forEach(p => { if (isOpenProblem(p)) (probBy[p.device_id] = probBy[p.device_id] || []).push(p); });
    const up = dashData.devices.filter(d => d.status === "online").length;
    sub.textContent = `${up} / ${dashData.devices.length} up`;
    body.innerHTML = `<div class="avail-grid">${dashData.devices.map(d => {
      const probs = probBy[d.id] || [];
      const state = d.status === "offline" ? "down" : probs.length ? "warn" : "up";
      const down = probs.find(p => p.problem_key === "unreachable");
      const detail = d.status === "offline"
        ? `down ${down ? "for " + formatSince(down.since) : ""}`
        : probs.length ? `${probs.length} problem${probs.length > 1 ? "s" : ""}` : `${isNum(d.last_ping_ms) ? d.last_ping_ms.toFixed(0) + " ms" : "up"}`;
      return `<a class="avail-tile ${state}" href="#/device/${Number(d.id)}" title="${escapeHtml(d.ip_address)}">
        <strong>${escapeHtml(d.hostname)}</strong>${escapeHtml(detail)}</a>`;
    }).join("")}</div>`;
  },

  wan(w, body, sub, redraw) {
    const list = dashData.wan;
    if (!list.length) {
      body.innerHTML = `<div class="dim">No WAN interface found. Add your gateway with the UniFi gateway profile.</div>`;
      return;
    }
    const x = list[0];
    sub.textContent = `${x.hostname} ${x.label}`;
    let host = body.querySelector(".chart-host");
    if (!host || redraw) {
      body.classList.add("fill-body");
      body.innerHTML = `<div class="wan-head"></div><div class="chart-host chart-fill"></div>`;
      host = body.querySelector(".chart-host");
      // Peaks come from the short-interval WAN sampler; the averages alone hide speed tests and bursts.
      drawDefinition(host, x.device_id, {
        series: [[`if.${x.if_index}.in_bps`, "Download"], [`if.${x.if_index}.out_bps`, "Upload"],
                 [`if.${x.if_index}.in_peak_bps`, "Download peak"], [`if.${x.if_index}.out_peak_bps`, "Upload peak"]], fmt: "bps",
      }, 24);
    }
    const stat = (n, label, cls = "") => `<div class="stat-inline ${escapeHtml(cls)}"><div class="stat-num">${escapeHtml(n)}</div><div class="stat-label">${escapeHtml(label)}</div></div>`;
    body.querySelector(".wan-head").innerHTML =
      stat(x.oper === 1 ? "UP" : "DOWN", "Link", x.oper === 1 ? "stat-ok" : "stat-bad") +
      stat(formatBps(x.in_bps), "Download avg") + stat(formatBps(x.out_bps), "Upload avg") +
      stat(formatBps(x.in_peak_bps), "Download peak") + stat(formatBps(x.out_peak_bps), "Upload peak") +
      stat(formatSpeed(x.speed_mbps), "Link speed");
  },

  top_ports(w, body) {
    body.classList.add("flush");
    const rows = dashData.top.slice(0, w.config.limit || 8);
    body.innerHTML = rows.length ? `<table><thead><tr><th>Device</th><th>Port</th><th>In</th><th>Out</th><th>Util</th></tr></thead><tbody>${rows.map(r => `
      <tr>
        <td class="text-cell">${deviceLink(r.device_id, r.hostname)}</td>
        <td class="text-cell"><a class="device-link" href="#/device/${Number(r.device_id)}/ports">${escapeHtml(r.label)}</a> <span class="dim">${escapeHtml(r.alias && r.alias !== r.label ? r.alias : "")}</span></td>
        <td>${formatBps(r.in_bps)}</td>
        <td>${formatBps(r.out_bps)}</td>
        <td class="bar-cell">${barHtml(r.util_pct, isNum(r.util_pct) ? (r.util_pct < 10 ? r.util_pct.toFixed(1) : r.util_pct.toFixed(0)) + "%" : null)}</td>
      </tr>`).join("")}</tbody></table>` : `<div class="empty-cell">No port traffic yet.</div>`;
  },

  wireless(w, body, sub) {
    body.classList.add("flush");
    const aps = dashData.devices.filter(d => isNum(d.summary.clients));
    sub.textContent = `${aps.reduce((a, d) => a + d.summary.clients, 0)} clients`;
    body.innerHTML = aps.length ? `<table><thead><tr><th>Access point</th><th>Clients</th><th>2.4 / 5 GHz</th><th>Channels</th><th>2.4 GHz busy</th><th>5 GHz busy</th></tr></thead><tbody>${aps.map(d => {
      const s = d.summary;
      return `<tr>
        <td class="text-cell"><a class="device-link" href="#/device/${Number(d.id)}/wireless">${escapeHtml(d.hostname)}</a></td>
        <td>${escapeHtml(s.clients)}</td>
        <td>${escapeHtml(s.clients_2g ?? "-")} / ${escapeHtml(s.clients_5g ?? "-")}</td>
        <td>${escapeHtml(s.channel_2g ?? "-")} / ${escapeHtml(s.channel_5g ?? "-")}</td>
        <td class="bar-cell">${barHtml(s.util_2g)}</td>
        <td class="bar-cell">${barHtml(s.util_5g)}</td>
      </tr>`;
    }).join("")}</tbody></table>` : `<div class="empty-cell">No access points monitored.</div>`;
  },

  top_cpu(w, body) {
    body.classList.add("flush");
    const rows = dashData.devices.slice().sort((a, b) => (b.summary.cpu_pct ?? -1) - (a.summary.cpu_pct ?? -1));
    body.innerHTML = `<table><thead><tr><th>Device</th><th>CPU</th><th>Memory</th><th>Uptime</th></tr></thead><tbody>${rows.map(d => `
      <tr>
        <td class="text-cell">${deviceLink(d.id, d.hostname)}</td>
        <td class="bar-cell">${barHtml(d.summary.cpu_pct)}</td>
        <td class="bar-cell">${barHtml(d.summary.mem_pct)}</td>
        <td>${isNum(d.summary.uptime_seconds) ? formatDuration(d.summary.uptime_seconds) : "-"}</td>
      </tr>`).join("")}</tbody></table>`;
  },

  events(w, body) {
    body.classList.add("flush");
    const rows = dashData.events.slice(0, w.config.limit || 12);
    body.innerHTML = rows.length ? `<table><tbody>${rows.map(e => `
      <tr>
        <td class="dim">${escapeHtml(formatAgo(e.timestamp))}</td>
        <td class="text-cell">${deviceLink(e.device_id, e.hostname)}</td>
        <td>${severityPill(e.severity)}</td>
        <td class="text-cell">${escapeHtml(e.message)}</td>
      </tr>`).join("")}</tbody></table>` : `<div class="empty-cell">No events yet. Events are logged when something changes: a device goes down or recovers, a problem opens or resolves, a port changes state, a device reboots or its firmware changes.</div>`;
  },

  graph(w, body, sub, redraw) {
    const c = w.config;
    if (!c.device_id || !c.series) {
      body.innerHTML = `<div class="dim">Graph tile: shows any graph from any device on the dashboard. Click "Edit dashboard", then "Configure" on this tile to choose the device, graph and time range.</div>`;
      return;
    }
    sub.textContent = c.hours >= 24 ? `${c.hours / 24}d` : `${c.hours}h`;
    if (!redraw && body.querySelector(".chart-host svg")) return;
    body.classList.add("fill-body");
    body.innerHTML = `<div class="chart-host chart-fill"></div>`;
    drawDefinition(body.querySelector(".chart-host"), c.device_id, c, c.hours || 24, !!c.compare);
  },
};

let widgetGraphDefs = [];

async function openWidgetConfig(w) {
  widgetBeingConfigured = w;
  const devices = dashData ? dashData.devices : (await api("/api/devices")).devices;
  const sel = document.getElementById("widget-device");
  sel.innerHTML = devices.map(d => `<option value="${Number(d.id)}">${escapeHtml(d.hostname)}</option>`).join("");
  if (w.config.device_id) sel.value = String(w.config.device_id);
  document.getElementById("widget-hours").value = String(w.config.hours || 24);
  document.getElementById("widget-compare").checked = !!w.config.compare;
  show(document.getElementById("modal-widget"));
  loadWidgetGraphOptions(w.config.title);
}

async function loadWidgetGraphOptions(selectTitle) {
  const id = parseInt(document.getElementById("widget-device").value, 10);
  const graphSel = document.getElementById("widget-graph");
  graphSel.innerHTML = `<option>Loading...</option>`;
  try {
    const detail = await api(`/api/devices/${id}`);
    const ports = detail.sections.includes("interfaces") ? (await api(`/api/devices/${id}/ports`)).ports : [];
    widgetGraphDefs = graphDefinitions(detail, ports);
    graphSel.innerHTML = widgetGraphDefs.map((g, i) => `<option value="${i}">${escapeHtml(g.title)}</option>`).join("");
    const idx = widgetGraphDefs.findIndex(g => g.title === selectTitle);
    if (idx >= 0) graphSel.value = String(idx);
  } catch (err) {
    graphSel.innerHTML = "";
    showToast(`Could not load graphs: ${err.message}`, "error");
  }
}


// --- Credentials (vault) ---

async function loadCredentials() {
  let data;
  try {
    data = await api("/api/credentials");
  } catch (err) {
    showToast(`Could not load credentials: ${err.message}`, "error");
    return;
  }
  const v = vaultSummary(data.vault);
  const note = document.getElementById("vault-note");
  note.textContent = v.text;
  note.className = `panel-note-bar ${v.cls}`;
  fillTable("credentials-body", data.credentials.map(c => `
    <tr>
      <td class="text-cell"><strong>${escapeHtml(c.name)}</strong></td>
      <td class="text-cell">${c.cred_type === "ssh_key" ? `SSH key${c.has_passphrase ? " (with passphrase)" : ""}${c.public_fingerprint ? `<div class="dim task-cmd">${escapeHtml(c.public_fingerprint)}</div>` : ""}` : "Password"}</td>
      <td>${escapeHtml(c.username || "-")}</td>
      <td data-sort="${escapeHtml(c.created_at)}" class="dim">${escapeHtml(formatTime(c.created_at))}</td>
      <td class="actions-cell">
        <button class="btn" data-perm="credentials.use" data-cred-test="${Number(c.id)}" title="Log in to a host with it (runs only 'true')">Test</button>
        <button class="btn" data-cred-edit="${Number(c.id)}">Edit</button>
        <button class="btn btn-danger" data-cred-delete="${Number(c.id)}" data-name="${escapeHtml(c.name)}">Delete</button>
      </td>
    </tr>`).join(""), "No credentials stored yet.", 5);
  credentialCache = data.credentials;
  keygenAvailable = data.keygen_available !== false;
}
let keygenAvailable = true;
let credentialCache = [];

function openCredentialModal(cred) {
  const editing = !!cred;
  document.getElementById("credential-title").textContent = editing ? `Edit ${cred.name}` : "Add Credential";
  document.getElementById("cred-id").value = editing ? cred.id : "";
  document.getElementById("cred-name").value = editing ? cred.name : "";
  document.getElementById("cred-username").value = editing ? (cred.username || "") : "";
  const type = document.getElementById("cred-type");
  type.value = editing ? cred.cred_type : "password";
  type.disabled = editing;
  document.getElementById("cred-password").value = "";
  document.getElementById("cred-key").value = "";
  document.getElementById("cred-passphrase").value = "";
  document.querySelector("input[name=cred-key-mode][value=paste]").checked = true;
  document.getElementById("cred-generate-option").classList.toggle("hidden", editing || !keygenAvailable);
  document.getElementById("cred-secret-help").textContent = editing
    ? "Leave empty to keep the stored secret. A new value replaces it."
    : "Encrypted with AES-256-GCM before it is stored. It is never shown again.";
  // The public half of a key is not secret: shown so it can be copied to more hosts.
  document.getElementById("cred-public").value = editing && cred.public_key ? cred.public_key : "";
  document.getElementById("cred-public-fp").textContent = editing && cred.public_fingerprint ? cred.public_fingerprint : "";
  hide(document.getElementById("cred-error"));
  syncCredentialType();
  show(document.getElementById("modal-credential"));
  document.getElementById("cred-name").focus();
}

function syncCredentialType() {
  const isKey = document.getElementById("cred-type").value === "ssh_key";
  const generate = isKey && document.querySelector("input[name=cred-key-mode]:checked").value === "generate";
  const editing = !!document.getElementById("cred-id").value;
  document.getElementById("cred-key-source").classList.toggle("hidden", !isKey || editing || !keygenAvailable);
  document.getElementById("cred-secret-group").classList.toggle("hidden", generate);
  document.getElementById("cred-password").classList.toggle("hidden", isKey);
  document.getElementById("cred-key").classList.toggle("hidden", !isKey);
  document.getElementById("cred-passphrase-group").classList.toggle("hidden", !isKey || generate);
  document.getElementById("cred-generate-help").classList.toggle("hidden", !generate);
  document.getElementById("cred-public-group").classList.toggle("hidden", !isKey || !document.getElementById("cred-public").value);
  document.getElementById("cred-secret-label").textContent = isKey ? "Private key" : "Password";
  document.getElementById("btn-save-credential").textContent = generate ? "Generate and save" : "Save";
}

/** Copies text; falls back to a selected textarea where the Clipboard API is unavailable (plain HTTP on the LAN). */
async function copyText(text, textarea) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    textarea.select();
    document.execCommand("copy");
  }
  showToast("Copied.", "success");
}

function initCredentials() {
  const modal = document.getElementById("modal-credential");
  const close = () => {
    hide(modal);
    // Do not leave secrets in the DOM after the dialog closes.
    document.getElementById("cred-password").value = "";
    document.getElementById("cred-key").value = "";
    document.getElementById("cred-passphrase").value = "";
  };
  document.getElementById("btn-add-credential").addEventListener("click", () => openCredentialModal(null));
  document.getElementById("btn-close-credential").addEventListener("click", close);
  document.getElementById("btn-cancel-credential").addEventListener("click", close);
  document.getElementById("cred-type").addEventListener("change", syncCredentialType);
  document.getElementById("cred-key-source").addEventListener("change", syncCredentialType);
  document.getElementById("btn-copy-public").addEventListener("click", () => {
    const box = document.getElementById("cred-public");
    copyText(box.value, box);
  });
  document.getElementById("credentials-body").addEventListener("click", async (ev) => {
    const edit = ev.target.closest("[data-cred-edit]");
    if (edit) { openCredentialModal(credentialCache.find(c => c.id === Number(edit.dataset.credEdit))); return; }
    const del = ev.target.closest("[data-cred-delete]");
    if (!del || !(await confirmDialog({ title: "Delete credential?", message: `Delete "${del.dataset.name}"? Workflow steps and Fix SNMP using it will stop working until they get another credential.`,
      confirmLabel: "Delete", danger: true }))) return;
    try {
      await api(`/api/credentials/${del.dataset.credDelete}`, { method: "DELETE" });
      showToast("Credential deleted.", "success");
      loadCredentials();
      loadAutomation();
    } catch (err) {
      showToast(`Delete failed: ${err.message}`, "error");
    }
  });
  document.getElementById("btn-save-credential").addEventListener("click", async () => {
    const id = document.getElementById("cred-id").value;
    const type = document.getElementById("cred-type").value;
    const generate = type === "ssh_key" && !id && document.querySelector("input[name=cred-key-mode]:checked").value === "generate";
    const body = {
      name: document.getElementById("cred-name").value.trim(),
      cred_type: type,
      username: document.getElementById("cred-username").value.trim(),
      secret: generate ? "" : type === "ssh_key" ? document.getElementById("cred-key").value : document.getElementById("cred-password").value,
    };
    if (generate) body.generate = true;
    else if (type === "ssh_key") body.passphrase = document.getElementById("cred-passphrase").value;
    try {
      const res = id ? await api(`/api/credentials/${id}`, { method: "PUT", body })
        : await api("/api/credentials", { method: "POST", body });
      close();
      loadCredentials();
      loadAutomation();  // the workflow editor's credential list comes from the automation data
      if (type === "ssh_key" && res.public_key && (generate || body.secret)) {
        alertDialog({ title: generate ? "Key pair created" : "Key stored",
          message: "Add this public key to ~/.ssh/authorized_keys on each host this credential logs in to (one line). It is also shown when you edit the credential.",
          detail: res.public_key, confirmLabel: "Done" });
      } else {
        showToast(id ? "Credential updated." : "Credential stored (encrypted).", "success");
      }
    } catch (err) {
      showError("cred-error", err.message);
    }
  });
}


// --- Automation data and SSH host keys ---

// Hosts (with host key state) and credentials that the workflow editor and Fix SNMP pick from.
let autoData = null;

async function loadAutomation() {
  try {
    autoData = await api("/api/automation");
    const note = document.getElementById("workflows-note");
    if (note && !autoData.ssh_available && !note.classList.contains("warn")) {
      note.textContent = "The OpenSSH client (ssh) was not found on this machine. Install it to run command steps.";
      note.classList.add("warn");
    }
  } catch (err) {
    showToast(`Could not load hosts and credentials: ${err.message}`, "error");
  }
}

/** Host key approval for task.device_ids on task.ssh_port (workflow hosts and Fix SNMP). */
async function openHostKeys(task) {
  if (!autoData) await loadAutomation();
  const body = document.getElementById("hostkeys-body");
  body.innerHTML = task.device_ids.map(id => {
    const d = ((autoData && autoData.devices) || []).find(x => x.id === id);
    return `<tr data-hk-device="${Number(id)}"><td class="text-cell"><strong>${escapeHtml(d ? d.hostname : id)}</strong></td><td class="hk-state dim">Contacting host...</td><td></td></tr>`;
  }).join("");
  show(document.getElementById("modal-hostkeys"));
  await Promise.all(task.device_ids.map(async id => {
    const row = body.querySelector(`[data-hk-device="${id}"]`);
    try {
      const r = await api(`/api/devices/${id}/hostkey?port=${task.ssh_port}`);
      const p = r.presented;
      const approved = r.approved.find(k => p && k.fingerprint === p.fingerprint);
      if (p.error) {
        row.cells[1].textContent = p.error;
        row.cells[1].className = "text-err";
      } else if (approved) {
        row.cells[1].innerHTML = `<code>${escapeHtml(p.key_type)} ${escapeHtml(p.fingerprint)}</code>`;
        row.cells[2].innerHTML = `<span class="status-pill status-ok">approved</span> <button class="btn" data-perm="devices.manage" data-hk-forget="${escapeHtml(id)}">Forget</button>`;
      } else {
        const changed = r.approved.length ? `<div class="text-err">WARNING: this differs from the key approved earlier (${escapeHtml(r.approved[0].fingerprint)}). Only approve if you reinstalled the host.</div>` : "";
        row.cells[1].innerHTML = `<code>${escapeHtml(p.key_type)} ${escapeHtml(p.fingerprint)}</code>${changed}`;
        // Approving decides where stored credentials are sent: Manage credentials only.
        row.cells[2].innerHTML = can("credentials.manage")
          ? `<button class="btn btn-primary" data-hk-approve="${escapeHtml(id)}" data-fp="${escapeHtml(p.fingerprint)}" data-port="${Number(task.ssh_port)}">Approve</button>`
          : `<span class="dim">Someone with the Manage credentials permission needs to approve it.</span>`;
      }
    } catch (err) {
      row.cells[1].textContent = err.message;
    }
  }));
}

function initHostKeys() {
  const hkModal = document.getElementById("modal-hostkeys");
  const closeHk = () => { hide(hkModal); loadAutomation(); };
  document.getElementById("btn-close-hostkeys").addEventListener("click", closeHk);
  document.getElementById("btn-done-hostkeys").addEventListener("click", closeHk);
  document.getElementById("hostkeys-body").addEventListener("click", async (ev) => {
    const approve = ev.target.closest("[data-hk-approve]");
    const forget = ev.target.closest("[data-hk-forget]");
    try {
      if (approve) {
        await api(`/api/devices/${approve.dataset.hkApprove}/hostkey`, { method: "POST",
          body: { fingerprint: approve.dataset.fp, port: parseInt(approve.dataset.port, 10) } });
        approve.outerHTML = `<span class="status-pill status-ok">approved</span>`;
        showToast("Host key approved.", "success");
      } else if (forget && await confirmDialog({ title: "Forget this host key?", message: "Workflows and Fix SNMP stop connecting to this host until its key is approved again.",
        confirmLabel: "Forget", danger: true })) {
        await api(`/api/devices/${forget.dataset.hkForget}/hostkey`, { method: "DELETE" });
        forget.parentElement.innerHTML = `<span class="dim">forgotten</span>`;
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}
