/* Restore from a file (tasks 297 and 299): Settings, Data and backups, and the setup page of a fresh install.
 *
 * 1. Choose the file. The server asks for the password and code first (or the setup code on the setup page),
 *    then the file is sent as it is, with a progress bar.
 * 2. The server says which version made it and offers the ways it may be restored: never into an older version.
 *    The backup passphrase and RESTORE typed confirm it.
 * 3. Root restores it (it may update first). The monitor restarts on the backup's data, so this page follows the
 *    progress, waits while the monitor is away and ends at the login, where the backup's accounts work.
 *
 * routes: { start, upload, restore, status } and extra: a function giving fields every request adds (the setup
 * code on the setup page).
 */

const RESTORE_ROUTES = { start: "/api/backups/upload/start", upload: "/api/backups/upload",
  restore: "/api/backups/restore", status: "/api/backups/restore/status" };
// The setup page of a fresh install (task 299): no account yet, the setup code travels with every request.
const SETUP_RESTORE_ROUTES = { start: "/api/setup/restore/start", upload: "/api/setup/restore/upload",
  restore: "/api/setup/restore", status: "/api/setup/restore/status" };

function setupRestore() {
  const field = document.getElementById("auth-token");
  const code = field ? field.value.trim() : "";
  if (setupTokenRequired && !code) {
    const e = document.getElementById("auth-error");
    e.textContent = "Type the setup code first: the restore needs it too.";
    show(e);
    if (field) field.focus();
    return;
  }
  restoreDialog({ routes: SETUP_RESTORE_ROUTES, extra: () => ({ setup_token: code }),
    headers: () => (code ? { "X-Setup-Token": code } : {}) });
}

function restoreUpload(url, file, onProgress, headers = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = ev => { if (ev.lengthComputable) onProgress(ev.loaded / ev.total); };
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText || "{}"); } catch (e) { data = {}; }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new Error(data.error || `The upload failed (HTTP ${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error("The upload was cut off. Try again."));
    xhr.send(file);
  });
}

function restoreDialog({ routes = RESTORE_ROUTES, extra = () => ({}), headers = () => ({}), post = null } = {}) {
  const send = post || ((path, body) => api(path, { method: "POST", body }));
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<div class="modal dialog restore-dialog" role="dialog" aria-modal="true" aria-labelledby="restore-title">
    <div class="modal-header"><span id="restore-title">Restore from a backup file</span>
      <button type="button" class="btn" data-x aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <div class="restore-step" data-step="file">
        <div class="dialog-message">Choose a backup file (monitor-backup-...tar.gz). Everything on this monitor is replaced by what the backup holds: devices, history, users and settings.</div>
        <div class="form-group"><input type="file" id="restore-file" accept=".gz,application/gzip"></div>
        <div class="restore-bar hidden" id="restore-bar"><span style="width:0%"></span></div>
      </div>
      <div class="restore-step hidden" data-step="choose">
        <div class="dialog-message" id="restore-about"></div>
        <div class="form-group" id="restore-choices"></div>
        <div class="form-group"><label for="restore-pass">Backup passphrase of this backup</label>
          <input type="password" id="restore-pass" autocomplete="off" maxlength="1024"></div>
        <div class="form-group"><label for="restore-confirm">Type RESTORE to replace this monitor's data</label>
          <input type="text" id="restore-confirm" autocomplete="off" spellcheck="false"></div>
      </div>
      <div class="form-help text-err hidden" id="restore-err"></div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn" data-x>Cancel</button>
      <button type="button" class="btn btn-primary" id="restore-go">Upload and check</button>
    </div></div>`;
  document.body.appendChild(back);
  const $ = sel => back.querySelector(sel);
  const err = text => { $("#restore-err").textContent = text || ""; $("#restore-err").classList.toggle("hidden", !text); };
  let info = null;
  const close = () => { $("#restore-pass").value = ""; back.remove(); };
  back.querySelectorAll("[data-x]").forEach(b => b.addEventListener("click", close));

  async function upload() {
    const file = $("#restore-file").files[0];
    if (!file) { err("Choose a backup file first."); return; }
    err("");
    $("#restore-go").disabled = true;
    try {
      await send(routes.start, extra());
      $("#restore-bar").classList.remove("hidden");
      info = await restoreUpload(routes.upload, file, f => { $("#restore-bar span").style.width = `${Math.round(f * 100)}%`; }, headers());
    } catch (e) {
      err(e.message);
      $("#restore-go").disabled = false;
      return;
    }
    const made = info.version ? `version ${escapeHtml(info.version)}` : "an unknown version";
    $("#restore-about").innerHTML = `This backup was made with ${made}${info.created ? ` (${escapeHtml(info.created)})` : ""}. This monitor runs ${escapeHtml(info.this_version)}.`
      + (info.verdict === "newer" ? " This version cannot read it, so the monitor updates first. A backup is never restored into an older version." : "");
    $("#restore-choices").innerHTML = info.choices.length
      ? info.choices.map((c, i) => `<label class="check-label"><input type="radio" name="restore-choice" value="${escapeHtml(c.choice)}" ${i === 0 ? "checked" : ""}> ${escapeHtml(c.label)}</label>`).join("")
      : `<div class="text-err">${escapeHtml(info.message || "This backup cannot be restored here.")}</div>`;
    back.querySelector('[data-step="file"]').classList.add("hidden");
    back.querySelector('[data-step="choose"]').classList.remove("hidden");
    $("#restore-go").textContent = "Restore";
    $("#restore-go").disabled = !info.choices.length;
    $("#restore-go").onclick = restore;
    $("#restore-pass").focus();
  }

  async function restore() {
    const choice = (back.querySelector('input[name="restore-choice"]:checked') || {}).value;
    const passphrase = $("#restore-pass").value;
    if ($("#restore-confirm").value.trim() !== "RESTORE") { err("Type RESTORE to confirm."); return; }
    if (!passphrase) { err("Give the backup passphrase of this backup."); return; }
    err("");
    $("#restore-go").disabled = true;
    try {
      await send(routes.restore, Object.assign({ choice, passphrase, confirm: "RESTORE" }, extra()));
    } catch (e) {
      err(e.message);
      $("#restore-go").disabled = false;
      return;
    }
    close();
    followRestore(routes, headers);
  }

  $("#restore-go").onclick = upload;
}

// Step 3: a full-screen view. Root's progress while the monitor runs; "restarting" while it is away; the login once
// it answers again (the backup's accounts). A failure before the restart shows root's lines.
function followRestore(routes, headers = () => ({})) {
  const screen = document.createElement("div");
  screen.className = "restore-screen";
  screen.setAttribute("role", "status");
  screen.setAttribute("aria-live", "polite");
  document.body.appendChild(screen);
  const steps = { check: "Checking the backup", update: "Updating to the chosen version", restore: "Restoring the data", done: "Starting again" };
  const draw = (title, text, lines = [], failed = false) => {
    screen.innerHTML = `<div class="restore-screen-box">
      <h3 class="${failed ? "text-err" : ""}">${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p>
      ${lines.length ? `<pre>${escapeHtml(lines.join("\n"))}</pre>` : ""}
      ${failed ? `<button type="button" class="btn" data-close>Close</button>` : ""}</div>`;
    const btn = screen.querySelector("[data-close]");
    if (btn) btn.addEventListener("click", () => screen.remove());
  };
  draw("Restoring", "Checking the backup...");
  let wentAway = false;
  const tick = async () => {
    let status = null;
    try {
      const res = await fetch(routes.status, { cache: "no-store", headers: headers() });
      if (res.ok) status = await res.json();
      else if (res.status === 401 || res.status === 403) status = "back";
    } catch (e) {
      wentAway = true;
    }
    if (status === "back" || (wentAway && status)) {
      draw("Restored", "The monitor is running on the backup's data. Log in with an account from the backup.");
      setTimeout(() => location.reload(), 3000);
      return;
    }
    if (status && status.progress) {
      const p = status.progress;
      if (p.state === "failed") { draw("Not restored", "Nothing was changed. The monitor runs on the data it had.", p.lines || [], true); return; }
      if (p.state === "done") {
        draw("Restored", "The monitor is running on the backup's data. Log in with an account from the backup.");
        setTimeout(() => location.reload(), 3000);
        return;
      }
      draw("Restoring", `${steps[p.step] || "Working"}...`, (p.lines || []).slice(-6));
    } else if (wentAway) {
      draw("Restoring", "The monitor is restarting. This page carries on by itself.");
    }
    setTimeout(tick, 2000);
  };
  setTimeout(tick, 1500);
}
