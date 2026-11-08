/* Settings, Updates: check the project's releases, update in place, undo an update.
 *
 * Root on the box does the work (updatectl.py, through a path unit): it downloads the newest
 * release, checks its signature against the key built into this version, keeps a backup and the
 * previous version for two days, and puts everything back if the new version does not answer.
 * This page only asks and shows what root reports.
 */

let updatesPoll = null;

function updatesWhen(t) {
  return t ? new Date(t * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

function updatesSection(u) {
  if (!u) return "";
  const check = u.check || null;
  const last = u.last || null;
  const pending = u.pending || {};
  const back = u.rollback || {};
  if (!u.installed) {
    return `<div class="panel-note-bar warn">Update works on an installed monitor (installed with infra.sh). This copy is a development copy: update it from the repository instead.</div>
      <p class="form-help">Running version ${escapeHtml(u.current)}. Releases: <a href="${escapeHtml(u.repository)}/releases" target="_blank" rel="noopener noreferrer">${escapeHtml(u.repository)}</a></p>`;
  }
  let latest = `<span class="dim">Not checked yet</span>`;
  if (pending.check) latest = `<span class="text-warn">Checking...</span>`;
  else if (check && !check.ok) latest = `<span class="text-err">${escapeHtml(check.error || "The check failed")}</span>`;
  else if (check) latest = check.newer
    ? `<strong>${escapeHtml(check.latest)}</strong> is available <span class="dim">(released ${escapeHtml((check.published || "").slice(0, 10))}, checked ${escapeHtml(formatAgo(check.time))})</span>`
    : `<span class="text-ok">Up to date</span> <span class="dim">(newest release ${escapeHtml(check.latest)}, checked ${escapeHtml(formatAgo(check.time))})</span>`;
  let lastLine = `<span class="dim">None from here yet</span>`;
  if (pending.work) lastLine = `<span class="text-warn">Working... the monitor restarts on its own; this page reconnects.</span>`;
  else if (last) {
    const what = last.action === "install" || last.action === "update-install" ? "Update" : "Rollback";
    lastLine = last.ok
      ? `<span class="text-ok">${what} done</span>: ${escapeHtml(last.from || "")} to ${escapeHtml(last.to || "")} <span class="dim">${escapeHtml(formatAgo(last.time))}</span>`
      : `<span class="text-err">${what} failed</span> <span class="dim">${escapeHtml(formatAgo(last.time))}</span><div class="form-help">${escapeHtml(last.error || "")}</div>`;
    if (last.output) lastLine += `<details class="backup-output"><summary>Details</summary><pre>${escapeHtml(last.output)}</pre></details>`;
  }
  const busy = pending.check || pending.work;
  const notes = check && check.ok && check.newer && check.notes
    ? `<details class="backup-output" open><summary>What is new in ${escapeHtml(check.latest)}</summary><pre class="update-notes">${escapeHtml(check.notes)}</pre></details>` : "";
  const updateBtn = check && check.ok && check.newer
    ? `<button type="button" class="btn btn-primary btn-small" data-update-action="install" ${busy ? "disabled" : ""}>Update to ${escapeHtml(check.latest)}</button>` : "";
  let rollback = "";
  if (back.all) {
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
  return `<div class="backup-panel" id="updates-panel">
    <table class="storage-table"><tbody>
      <tr><td>Running</td><td>${escapeHtml(u.current)}</td></tr>
      <tr><td>Newest release</td><td>${latest}
        <button type="button" class="btn btn-small" data-update-action="check" ${busy ? "disabled" : ""}>Check for updates</button> ${updateBtn}</td></tr>
      <tr><td>Last update</td><td>${lastLine}</td></tr>
    </tbody></table>
    ${notes}${rollback}
    <p class="form-help">Updates come from <a href="${escapeHtml(u.repository)}/releases" target="_blank" rel="noopener noreferrer">the project's releases</a> and are installed only when their signature matches the key built into this version. Before updating, a backup is made and kept for two days with the previous version. The monitor is briefly unavailable while it restarts. Without internet access, <code>bash infra.sh --upgrade</code> on the Proxmox host does the same.</p>
  </div>`;
}

async function refreshUpdates() {
  try {
    const sys = await api("/api/system");
    const card = document.querySelector('#settings-sections [data-card="updates"]');
    const panel = card && card.querySelector("#updates-panel");
    if (!panel) { stopUpdatesPoll(); return; }
    const fresh = document.createElement("div");
    fresh.innerHTML = updatesSection(sys.update);
    panel.replaceWith(fresh.firstElementChild);
    const p = (sys.update && sys.update.pending) || {};
    if (!p.check && !p.work) stopUpdatesPoll();
  } catch (e) {
    // While the monitor restarts during an update the page cannot reach it: keep trying.
  }
}

function stopUpdatesPoll() {
  if (updatesPoll) { clearInterval(updatesPoll); updatesPoll = null; }
}

function startUpdatesPoll() {
  stopUpdatesPoll();
  let n = 0;
  updatesPoll = setInterval(() => { if (++n > 600) stopUpdatesPoll(); else refreshUpdates(); }, 3000);
}

const UPDATE_CONFIRM = {
  install: v => ({ title: `Update to ${v.latest}?`, confirmLabel: "Update now",
    message: `The monitor backs up first, installs ${v.latest}, then restarts (about a minute). If the new version does not start, the current one is put back by itself. For two days you can undo the update in this card.` }),
  "rollback-code": b => ({ title: `Go back to ${b.to}?`, confirmLabel: `Back to ${b.to}`,
    message: `${b.to} runs again with today's data: devices, history and settings changed since the update stay. Features new in ${b.from} are gone until you update again.` }),
  "rollback-all": b => ({ title: `Go back to ${b.to} and its data?`, confirmLabel: "Restore both", danger: true,
    message: `${b.to} runs again with the data from just before the update. Anything changed since then (history, devices, settings) is lost. The state now is backed up first.` }),
};

function initUpdates() {
  const root = document.getElementById("settings-sections");
  if (!root) return;
  root.addEventListener("click", async ev => {
    const btn = ev.target.closest("[data-update-action]");
    if (!btn) return;
    const action = btn.dataset.updateAction;
    let path = "/api/updates/check", body = {};
    if (action !== "check") {
      const sys = await api("/api/system");
      const u = sys.update || {};
      const opts = action === "install" ? UPDATE_CONFIRM.install(u.check || {}) : UPDATE_CONFIRM[action](u.rollback || {});
      if (!(await confirmDialog(opts))) return;
      path = action === "install" ? "/api/updates/install" : "/api/updates/rollback";
      if (action !== "install") body = { mode: action === "rollback-code" ? "code" : "all" };
    }
    btn.disabled = true;
    try {
      await api(path, { method: "POST", body });
      showToast(action === "check" ? "Checking the releases..." : "Started. The monitor restarts on its own; this page follows along.", "success");
      refreshUpdates();
      startUpdatesPoll();
    } catch (err) {
      showToast(err.message, "error");
      btn.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", initUpdates);
