/* Settings, Updates: check the project's releases, update in place, undo an update, and the history.
 *
 * Root on the box does the work (updatectl.py, through a path unit): it downloads the newest
 * release, checks its signature against the key built into this version, keeps a backup and the
 * previous version for two days, and puts everything back if the new version does not answer.
 * This page only asks and shows what root reports: which step an update is on, the result, and the
 * history with each run's log. A red number on Settings says when a new version is waiting.
 */

let updatesPoll = null;
let updateWaiting = 0;          // 1 while a new version waits (the red number)
let updateLast = null;          // the last status the server sent, kept while it restarts
let updateOffline = false;      // the server did not answer the last poll (restarting during an update)
let updateHistoryRows = null;   // the history as last loaded (null: load it)
let updateWasRunning = false;

const UPDATE_STEPS = [
  ["download", "Downloading the new version"],
  ["verify", "Checking it is the project's own release"],
  ["ready", "Getting ready"],
  ["copy", "Unpacking the new version"],
  ["check", "Checking your data with the new version"],
  ["repair", "Installing anything that is missing"],
  ["backup", "Backing up your data"],
  ["replace", "Installing the new version"],
  ["health", "Starting the new version"],
];
const UPDATE_KINDS = {
  update: "Update from the app",
  upgrade: "Upgrade from the Proxmox host",
  "rollback-code": "Undo, keeping that day's data",
  "rollback-all": "Undo, with the data from before",
};

function isAdmin() { return !!(currentUser && currentUser.role === "admin"); }

function updatesWhen(t) {
  return t ? new Date(t * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

/** Release notes (GitHub's text) as simple HTML: headings, lists, bold and code. Everything is escaped first. */
function updateNotesHtml(text) {
  const inline = s => escapeHtml(s).replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = [];
  let list = false;
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    const item = /^[-*] +(.*)$/.exec(line);
    if (item) {
      if (!list) { out.push("<ul>"); list = true; }
      out.push(`<li>${inline(item[1])}</li>`);
      continue;
    }
    if (list) { out.push("</ul>"); list = false; }
    const head = /^#{1,6} +(.*)$/.exec(line);
    if (head) out.push(`<h5>${inline(head[1])}</h5>`);
    else if (line) out.push(`<p>${inline(line)}</p>`);
  }
  if (list) out.push("</ul>");
  return out.join("");
}

function updateChangesHtml(check) {
  const changes = (check.changes && check.changes.length) ? check.changes
    : [{ version: check.latest, published: check.published, notes: check.notes }];
  return changes.map((c, i) => `
    <details class="update-change" ${i === 0 ? "open" : ""}>
      <summary><strong>${escapeHtml(c.version)}</strong>${c.published ? ` <span class="dim">${escapeHtml(String(c.published).slice(0, 10))}</span>` : ""}</summary>
      <div class="update-notes-body">${updateNotesHtml(c.notes) || `<p class="dim">No notes for this version.</p>`}</div>
    </details>`).join("");
}

const UPDATE_ICON = `<svg class="update-app-icon" viewBox="0 0 48 48" aria-hidden="true"><rect x="2" y="2" width="44" height="44" rx="11"/><path d="M9 28h7l3-8 5 14 4-10 2 4h9"/></svg>`;

function updateProgressHtml(u) {
  const p = u.progress || { steps: {}, state: "running", to: (u.check || {}).latest || "" };
  const steps = p.steps || {};
  let done = 0;
  const items = UPDATE_STEPS.map(([id, label]) => {
    const st = steps[id] || "pending";
    if (st === "ok" || st === "skip") done += 1;
    if (st === "run") done += 0.5;
    const note = st === "skip" ? `<span class="dim"> (not needed)</span>` : "";
    return `<li class="ustep ustep-${escapeHtml(st)}"><span class="ustep-dot" aria-hidden="true"></span><span>${escapeHtml(label)}${note}</span></li>`;
  }).join("");
  const pct = Math.min(100, Math.round(done * 100 / UPDATE_STEPS.length));
  const current = UPDATE_STEPS.find(([id]) => id === p.current);
  const restarting = updateOffline || (p.current === "replace" || p.current === "health");
  return `<div class="update-progress" role="status" aria-live="polite">
    <div class="update-progress-head">
      <div class="update-orbit" aria-hidden="true"><span></span></div>
      <div>
        <h4>Updating to ${escapeHtml(p.to || "the new version")}</h4>
        <p class="form-help">${current ? escapeHtml(current[1]) + "..." : "Starting..."} This takes about a minute. You can leave this page open: it follows along by itself.</p>
      </div>
      <div class="update-pct">${pct}%</div>
    </div>
    <div class="update-bar"><span data-pct="${Math.round(pct / 5) * 5}"></span></div>
    <ol class="update-steps">${items}</ol>
    ${restarting ? `<p class="update-restart">${updateOffline ? "The monitor is restarting with the new version. Reconnecting..." : "The monitor restarts in a moment; this page reconnects by itself."}</p>` : ""}
  </div>`;
}

function updateResultHtml(u) {
  const p = u.progress;
  if (p.state === "ok") {
    const reload = u.current === p.to;
    return `<div class="update-result ok" role="status">
      <svg class="update-tick" viewBox="0 0 52 52" aria-hidden="true"><circle cx="26" cy="26" r="24"/><path d="M15 27l7 7 15-16"/></svg>
      <div><h4>Updated to ${escapeHtml(p.to)}</h4>
        <p class="form-help">Everything went through and the new version is answering. ${reload ? "Reload the page to use it." : ""}</p></div>
      ${reload ? `<button type="button" class="btn btn-primary btn-small" data-update-action="reload">Reload the page</button>`
        : `<button type="button" class="btn btn-small" data-update-action="dismiss">Dismiss</button>`}
    </div>`;
  }
  const failedStep = UPDATE_STEPS.find(([id]) => (p.steps || {})[id] === "fail");
  return `<div class="update-result failed" role="status">
    <svg class="update-cross" viewBox="0 0 52 52" aria-hidden="true"><circle cx="26" cy="26" r="24"/><path d="M18 18l16 16M34 18L18 34"/></svg>
    <div><h4>The update to ${escapeHtml(p.to)} did not go through</h4>
      <p class="form-help">${failedStep ? `It stopped at: ${escapeHtml(failedStep[1].toLowerCase())}. ` : ""}Your monitor is running ${escapeHtml(u.current)} again, with your data as it was. The history below has the full log.</p>
      ${p.error ? `<p class="update-error">${escapeHtml(p.error)}</p>` : ""}</div>
    <button type="button" class="btn btn-small" data-update-action="dismiss">Dismiss</button>
  </div>`;
}

function updateHeroHtml(u, busy) {
  const check = u.check;
  const admin = isAdmin();
  const checkBtn = admin ? `<button type="button" class="btn btn-small" data-update-action="check" ${busy ? "disabled" : ""}>Check for updates</button>` : "";
  if (u.pending.check) {
    return `<div class="update-hero"><div class="update-orbit small" aria-hidden="true"><span></span></div>
      <div class="update-hero-text"><h4>Checking for updates...</h4><p class="form-help">Asking the project's release page.</p></div></div>`;
  }
  if (check && !check.ok) {
    return `<div class="update-hero"><div class="update-hero-text"><h4>The check did not work</h4>
      <p class="update-error">${escapeHtml(check.error || "The check failed")}</p>
      <p class="form-help">Tried ${escapeHtml(formatAgo(check.time))}.</p></div>${checkBtn}</div>`;
  }
  if (check && check.newer && u.waiting) {
    return `<div class="update-hero available">
      ${UPDATE_ICON}
      <div class="update-hero-text">
        <h4>Homelab Monitor ${escapeHtml(check.latest)} <span class="update-new-pill">New</span></h4>
        <p class="form-help">Released ${escapeHtml((check.published || "").slice(0, 10))}. You have ${escapeHtml(u.current)}. Checked ${escapeHtml(formatAgo(check.time))}.</p>
      </div>
      <div class="update-whats-new"><h5>What is new</h5>${updateChangesHtml(check)}</div>
      ${admin ? `<div class="update-hero-actions">
        <button type="button" class="btn btn-primary" data-update-action="install" ${busy ? "disabled" : ""}>Update now</button>
        <button type="button" class="btn" data-update-action="skip" ${busy ? "disabled" : ""}>Skip this version</button>
        ${checkBtn}
      </div>` : ""}
    </div>`;
  }
  if (check && check.newer && u.skipped && u.skipped === check.latest) {
    return `<div class="update-hero">
      <div class="update-hero-text"><h4>You skipped ${escapeHtml(check.latest)}</h4>
        <p class="form-help">It stays here without the red number. A newer version than this brings the number back.</p></div>
      <details class="update-whats-new compact"><summary>What is new in ${escapeHtml(check.latest)}</summary>${updateChangesHtml(check)}</details>
      ${admin ? `<div class="update-hero-actions">
        <button type="button" class="btn btn-small" data-update-action="unskip" ${busy ? "disabled" : ""}>Show it again</button>
        <button type="button" class="btn btn-small" data-update-action="install" ${busy ? "disabled" : ""}>Update to ${escapeHtml(check.latest)}</button>
      </div>` : ""}
    </div>`;
  }
  return `<div class="update-hero">
    <svg class="update-tick still" viewBox="0 0 52 52" aria-hidden="true"><circle cx="26" cy="26" r="24"/><path d="M15 27l7 7 15-16"/></svg>
    <div class="update-hero-text"><h4>${check ? `Homelab Monitor ${escapeHtml(u.current)} is up to date` : `Homelab Monitor ${escapeHtml(u.current)}`}</h4>
      <p class="form-help">${check ? `Checked ${escapeHtml(formatAgo(check.time))}.` : "Not checked yet."}</p></div>
    ${checkBtn}
  </div>`;
}

function updateDismissed(p) {
  try { return localStorage.getItem("hm-update-seen") === String(p.finished); } catch (e) { return false; }
}

function updatesSection(u) {
  if (!u) return "";
  updateLast = u;
  setUpdateWaiting(u.waiting || 0);
  if (!u.installed) {
    return `<div class="backup-panel" id="updates-panel"><div class="panel-note-bar warn">Update works on an installed monitor (installed with home_monitor.sh). This copy is a development copy: update it from the repository instead.</div>
      <p class="form-help">Running version ${escapeHtml(u.current)}. Releases: <a href="${escapeHtml(u.repository)}/releases" target="_blank" rel="noopener noreferrer">${escapeHtml(u.repository)}</a></p></div>`;
  }
  const pending = u.pending || {};
  const p = u.progress;
  const running = pending.work || (p && p.state === "running");
  const busy = pending.check || running;
  let top;
  if (running) top = updateProgressHtml(u);
  else if (p && p.finished && !updateDismissed(p)) top = updateResultHtml(u) + updateHeroHtml(u, busy);
  else top = updateHeroHtml(u, busy);

  const back = u.rollback || {};
  let rollback = "";
  if (back.all && isAdmin() && !running) {
    rollback = `<div class="update-rollback">
      <h4>Undo the update to ${escapeHtml(back.from)}</h4>
      <p class="form-help">Possible until ${escapeHtml(updatesWhen(back.expires))}. Either way, the state now is backed up first.</p>
      <div class="update-rollback-actions">
        <button type="button" class="btn btn-small" data-update-action="rollback-code" ${back.code && !busy ? "" : "disabled"}>Back to ${escapeHtml(back.to)}, keep today's data</button>
        <button type="button" class="btn btn-small" data-update-action="rollback-all" ${busy ? "disabled" : ""}>Back to ${escapeHtml(back.to)} with the data from before the update</button>
      </div>
      ${back.code ? "" : `<p class="form-help">Keeping today's data is not possible: this update changed how the data is stored, and ${escapeHtml(back.to)} cannot read it.</p>`}
    </div>`;
  }
  // The history is loaded once, then again when an update or undo has just finished.
  if (updateWasRunning && !running) updateHistoryRows = null;
  updateWasRunning = !!running;
  const history = isAdmin() ? `<div class="update-history" id="update-history">${updateHistoryHtml(updateHistoryRows)}</div>` : "";
  if (isAdmin() && updateHistoryRows === null && !updateOffline) setTimeout(loadUpdateHistory, 0);
  return `<div class="backup-panel" id="updates-panel">
    ${top}${rollback}${history}
    <p class="form-help">Updates come from <a href="${escapeHtml(u.repository)}/releases" target="_blank" rel="noopener noreferrer">the project's releases</a> and are installed only when their signature matches the key built into this version. Before updating, a backup is made and kept for two days with the previous version. The monitor is briefly unavailable while it restarts. Without internet access, <code>bash home_monitor.sh --upgrade</code> on the Proxmox host does the same.</p>
  </div>`;
}

// --- History ---

function updateHistoryHtml(history) {
  if (history === null) return `<h4>Update history</h4><p class="form-help">Loading...</p>`;
  if (typeof history === "string") return `<h4>Update history</h4><p class="form-help">${escapeHtml(history)}</p>`;
  return `<h4>Update history</h4>` + (history.length ? `<table class="storage-table update-history-table"><thead><tr>
      <th>When</th><th>What</th><th>Version</th><th>Result</th><th></th></tr></thead><tbody>${history.map(h => `
      <tr>
        <td>${escapeHtml(updatesWhen(h.time))}</td>
        <td>${escapeHtml(UPDATE_KINDS[h.kind] || h.kind)}</td>
        <td>${h.from ? `${escapeHtml(h.from)} to ` : ""}${escapeHtml(h.to || "")}</td>
        <td><span class="update-pill ${h.ok ? "ok" : "bad"}">${h.ok ? "Passed" : "Failed"}</span>${!h.ok && h.error ? `<div class="form-help">${escapeHtml(h.error)}</div>` : ""}</td>
        <td>${h.log ? `<button type="button" class="btn btn-small" data-update-log="${Number(h.id)}">View log</button>` : ""}</td>
      </tr>`).join("")}</tbody></table>`
    : `<p class="form-help">Nothing yet. Every update, upgrade and undo is listed here with its result and its log.</p>`);
}

let updateHistoryLoading = false;

async function loadUpdateHistory() {
  if (updateHistoryLoading) return;
  updateHistoryLoading = true;
  try {
    updateHistoryRows = (await api("/api/updates/history")).history;
  } catch (err) {
    updateHistoryRows = err.message;
  } finally {
    updateHistoryLoading = false;
  }
  const box = document.getElementById("update-history");
  if (box) box.innerHTML = updateHistoryHtml(updateHistoryRows);
}

async function showUpdateLog(id) {
  let text;
  try {
    text = (await api(`/api/updates/history/${Number(id)}/log`)).log;
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<div class="modal dialog update-log-dialog" role="dialog" aria-modal="true" aria-label="Update log">
    <div class="modal-header"><span>Update log</span></div>
    <div class="modal-body"><pre class="update-log"></pre></div>
    <div class="modal-footer">
      <button type="button" class="btn" data-log="copy">Copy</button>
      <button type="button" class="btn" data-log="save">Save as a file</button>
      <button type="button" class="btn btn-primary" data-log="close">Close</button>
    </div></div>`;
  back.querySelector(".update-log").textContent = text;
  const before = document.activeElement;
  const close = () => { document.removeEventListener("keydown", onKey, true); back.remove(); if (before && before.focus) before.focus(); };
  const onKey = ev => { if (ev.key === "Escape") { ev.preventDefault(); close(); } };
  document.addEventListener("keydown", onKey, true);
  back.addEventListener("mousedown", ev => { if (ev.target === back) close(); });
  back.addEventListener("click", async ev => {
    const what = ev.target.closest("[data-log]")?.dataset.log;
    if (what === "close") close();
    if (what === "copy") {
      try { await navigator.clipboard.writeText(text); showToast("Copied", "success"); } catch (e) { showToast("Could not copy: select the text instead", "error"); }
    }
    if (what === "save") {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      a.download = `update-log-${Number(id)}.txt`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }
  });
  document.body.appendChild(back);
  back.querySelector("[data-log=close]").focus();
  const pre = back.querySelector(".update-log");
  pre.scrollTop = pre.scrollHeight;          // the end says how it finished
}

// --- The red number ---

function setUpdateWaiting(n) {
  updateWaiting = n ? 1 : 0;
  const badge = document.getElementById("nav-settings-badge");
  if (badge) {
    badge.classList.toggle("hidden", !updateWaiting);
    document.getElementById("nav-settings")?.setAttribute("aria-label", updateWaiting ? "Settings, an update is ready" : "Settings");
  }
  const link = document.querySelector('#settings-nav a[data-section="updates"]');
  if (link) {
    let b = link.querySelector(".nav-badge");
    if (updateWaiting && !b) link.insertAdjacentHTML("beforeend", `<span class="nav-badge" aria-label="An update is ready">1</span>`);
    if (!updateWaiting && b) b.remove();
  }
}

async function refreshUpdateBadge() {
  if (!isAdmin()) { setUpdateWaiting(0); return; }
  try {
    const s = await api("/api/updates/summary");
    setUpdateWaiting(s.waiting);
  } catch (e) { /* offline: keep the last state */ }
}

// --- Following an update ---

async function refreshUpdates() {
  try {
    const sys = await api("/api/system");
    updateOffline = false;
    const panel = document.getElementById("updates-panel");
    if (panel) {
      const fresh = document.createElement("div");
      fresh.innerHTML = updatesSection(sys.update);
      panel.replaceWith(fresh.firstElementChild);
    } else {
      setUpdateWaiting(sys.update.waiting);
    }
    const u = sys.update || {};
    const p = u.progress;
    if (!u.pending?.check && !u.pending?.work && !(p && p.state === "running")) stopUpdatesPoll();
  } catch (e) {
    // While the monitor restarts during an update the page cannot reach it: show that, keep trying.
    if (updateLast && (updateLast.pending?.work || updateLast.progress?.state === "running")) {
      updateOffline = true;
      const panel = document.getElementById("updates-panel");
      if (panel) {
        const fresh = document.createElement("div");
        fresh.innerHTML = updatesSection(updateLast);
        panel.replaceWith(fresh.firstElementChild);
      }
    }
  }
}

function stopUpdatesPoll() {
  if (updatesPoll) { clearInterval(updatesPoll); updatesPoll = null; }
}

function startUpdatesPoll() {
  stopUpdatesPoll();
  let n = 0;
  updatesPoll = setInterval(() => { if (++n > 900) stopUpdatesPoll(); else refreshUpdates(); }, 2000);
}

const UPDATE_CONFIRM = {
  install: v => ({ title: `Update to ${v.latest}?`, confirmLabel: "Update now",
    message: `The monitor backs up first, installs ${v.latest}, then restarts (about a minute). If the new version does not start, the current one is put back by itself. For two days you can undo the update here.` }),
  "rollback-code": b => ({ title: `Go back to ${b.to}?`, confirmLabel: `Back to ${b.to}`,
    message: `${b.to} runs again with today's data: devices, history and settings changed since the update stay. Features new in ${b.from} are gone until you update again.` }),
  "rollback-all": b => ({ title: `Go back to ${b.to} and its data?`, confirmLabel: "Restore both", danger: true,
    message: `${b.to} runs again with the data from just before the update. Anything changed since then (history, devices, settings) is lost. The state now is backed up first.` }),
};

function initUpdates() {
  const root = document.getElementById("settings-sections");
  if (!root) return;
  root.addEventListener("click", async ev => {
    const logBtn = ev.target.closest("[data-update-log]");
    if (logBtn) { showUpdateLog(logBtn.dataset.updateLog); return; }
    const btn = ev.target.closest("[data-update-action]");
    if (!btn) return;
    const action = btn.dataset.updateAction;
    if (action === "reload" || action === "dismiss") {
      const p = updateLast && updateLast.progress;
      try { if (p) localStorage.setItem("hm-update-seen", String(p.finished)); } catch (e) { /* private window */ }
      if (action === "reload") window.location.reload();
      else btn.closest(".update-result")?.remove();
      return;
    }
    let path = "/api/updates/check", body = {};
    const u = updateLast || (await api("/api/system")).update || {};
    if (action === "skip" || action === "unskip") {
      path = `/api/updates/${action}`;
      body = action === "skip" ? { version: (u.check || {}).latest } : {};
    } else if (action !== "check") {
      const opts = action === "install" ? UPDATE_CONFIRM.install(u.check || {}) : UPDATE_CONFIRM[action](u.rollback || {});
      if (!(await confirmDialog(opts))) return;
      path = action === "install" ? "/api/updates/install" : "/api/updates/rollback";
      if (action !== "install") body = { mode: action === "rollback-code" ? "code" : "all" };
    }
    btn.disabled = true;
    try {
      await api(path, { method: "POST", body });
      if (action === "skip") showToast("Skipped. The red number comes back when a newer version is out.", "success");
      else if (action === "check") showToast("Checking the releases...", "success");
      await refreshUpdates();
      if (action !== "skip" && action !== "unskip") startUpdatesPoll();
    } catch (err) {
      showToast(err.message, "error");
      btn.disabled = false;
    }
  });
  setInterval(refreshUpdateBadge, 10 * 60 * 1000);
}

document.addEventListener("DOMContentLoaded", initUpdates);
