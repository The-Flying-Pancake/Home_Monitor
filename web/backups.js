/* Settings, Data and backups: where backups go, Syncthing on or off, back up now, last results.
 *
 * Without Syncthing, backups stay in the container (DATA/backups, newest 7). With Syncthing,
 * they are written into the synced folder (default /mnt/Syncthing/Monitor), one folder per app
 * (/mnt/Syncthing/<App>); the identity share (cert.pem, key.pem, config.xml) is only read
 * to give this container the same Syncthing device ID. Changes are applied by root in the
 * container (sitectl.py site-request through a path unit); the result shows here.
 */

let backupsPoll = null;

function backupsSection(b) {
  if (!b) return "";
  const st = b.syncthing_settings || {};
  const res = b.results || {};
  const pending = b.pending || {};
  const latest = b.latest ? `${b.latest.name}, ${formatAgo(b.latest.time)} (${formatBytes(b.latest.size)})` : "None yet";
  const rows = [
    ["Backups go to", b.syncthing ? `${b.folder} (synced by Syncthing)` : `${b.folder} (inside the container)`],
    ["Schedule", b.installed ? b.schedule : "Not scheduled here (development copy; the container runs a daily timer)"],
    ["Backups there", `${b.count}${b.count ? `, ${formatBytes(b.total_bytes)} in total` : ""}`],
    ["Newest", latest],
  ];
  const keyLabels = { "sealed": "Sealed with your passphrase", "withheld": "Left out of backups that leave this box",
    "clear-local": "In the clear, inside this container only" };
  if (b.installed && keyLabels[b.key_state]) rows.push(["Key in backups", keyLabels[b.key_state]]);
  if (b.restore_source) rows.push(["Restore source (home_monitor.sh)", b.restore_source]);
  const resultLine = (r, isPending, label) => {
    if (isPending) return `<span class="text-warn">${escapeHtml(label)} requested, waiting for the container...</span>`;
    if (!r) return `<span class="dim">Not run yet</span>`;
    return `<span class="${r.ok ? "text-ok" : "text-err"}">${r.ok ? "Done" : "Failed"}</span> <span class="dim">${escapeHtml(formatAgo(r.time))}</span>`;
  };
  const helper = b.installed ? "" : `<div class="panel-note-bar warn">This copy has no root helper (development machine): changes are saved and apply in the container.</div>`;
  const noPassphrase = b.installed && b.passphrase_set === false
    ? `<div class="panel-note-bar warn" id="bk-no-passphrase">No backup passphrase is set. New backups that leave this box do not carry the key that opens your stored passwords, so a rebuild from them cannot use those passwords. Backups also cannot be proven unchanged. Set one with Set backup passphrase below and keep it in your password manager.</div>`
    : "";
  return `${helper}${noPassphrase}<div class="backup-panel" id="backups-panel">
    <table class="storage-table"><tbody>${rows.map(r => `<tr><td>${escapeHtml(r[0])}</td><td>${escapeHtml(r[1])}</td></tr>`).join("")}
      <tr><td>Last backup</td><td>${resultLine(res.backup, pending.backup, "Backup")}
        <button type="button" class="btn btn-small" data-backup-action="run" data-perm="settings.system">Back up now</button></td></tr>
      ${b.installed ? `<tr><td>Backup passphrase</td><td>${resultLine(res.passphrase, pending.passphrase, "Saving")}
        <button type="button" class="btn btn-small" data-backup-action="passphrase" data-perm="settings.system">${b.passphrase_set ? "Change backup passphrase" : "Set backup passphrase"}</button>
        ${res.passphrase && !res.passphrase.ok && !pending.passphrase ? `<div class="form-help text-err">${escapeHtml(res.passphrase.output)}</div>` : ""}</td></tr>` : ""}
      <tr><td>Syncthing set-up</td><td>${resultLine(res.site, pending.site, "Applying")}
        ${res.site && res.site.output ? `<details class="backup-output"><summary>Details</summary><pre>${escapeHtml(res.site.output)}</pre></details>` : ""}</td></tr>
    </tbody></table>
    <form class="backup-form" id="backup-form" data-perm="settings.system">
      <label class="check-label"><input type="checkbox" id="bk-syncthing" ${st.enabled ? "checked" : ""}> Back up to Syncthing</label>
      <div class="bk-st-fields ${st.enabled ? "" : "hidden"}" id="bk-st-fields">
        <div class="form-row">
          <div class="form-group"><label for="bk-keys">Identity share (NFS export with cert.pem, key.pem, config.xml)</label>
            <input type="text" id="bk-keys" value="${escapeHtml(st.keys_source || "")}" placeholder="192.168.1.10:/Share/SyncThingKeys/Monitor" spellcheck="false"></div>
          <div class="form-group"><label for="bk-folder">Synced folder (backups are written here)</label>
            <input type="text" id="bk-folder" value="${escapeHtml(st.data_folder || "/mnt/Syncthing/Monitor")}" spellcheck="false"></div>
        </div>
        <div class="form-help">The identity gives this container the same Syncthing device ID every time it is rebuilt, so your main Syncthing server keeps syncing the folder. The folder must be shared with that server in the config.xml you keep on the share.</div>
      </div>
      <div class="bk-actions"><button type="submit" class="btn btn-primary">Save backup location</button></div>
    </form>
    <p class="form-help">Each backup holds everything a rebuild needs: devices and history, users (with their 2FA), workflows, settings, NFS and Syncthing choices and, sealed with your backup passphrase, the key that unlocks the stored passwords. A restore checks each backup against your passphrase and warns you about any it cannot prove unchanged, so keep the passphrase somewhere apart from the backups. To rebuild: run home_monitor.sh on the Proxmox host, then <code>/root/restore.sh</code> in the new container (or set RESTORE="latest" at the top of home_monitor.sh).</p>
  </div>`;
}

async function refreshBackups() {
  try {
    const sys = await api("/api/system");
    const card = document.querySelector('#settings-sections [data-card="backups"]');
    const panel = card && card.querySelector("#backups-panel");
    if (!panel) return;
    // Keep the form's unsaved input: only the status table is redrawn.
    const fresh = document.createElement("div");
    fresh.innerHTML = backupsSection(sys.backup);
    panel.querySelector("table").replaceWith(fresh.querySelector("#backups-panel table"));
    const p = sys.backup.pending || {};
    if (!p.backup && !p.site && !p.passphrase) stopBackupsPoll();
    // The yellow bar and the button's label follow a passphrase saved meanwhile.
    const bar = card.querySelector("#bk-no-passphrase");
    if (bar && sys.backup.passphrase_set) bar.remove();
  } catch (e) { stopBackupsPoll(); }
}

function stopBackupsPoll() {
  if (backupsPoll) { clearInterval(backupsPoll); backupsPoll = null; }
}

function startBackupsPoll() {
  stopBackupsPoll();
  let n = 0;
  backupsPoll = setInterval(() => { if (++n > 60) stopBackupsPoll(); else refreshBackups(); }, 3000);
}

function initBackups() {
  const root = document.getElementById("settings-sections");
  root.addEventListener("change", ev => {
    if (ev.target.id === "bk-syncthing") {
      document.getElementById("bk-st-fields").classList.toggle("hidden", !ev.target.checked);
    }
  });
  root.addEventListener("click", async ev => {
    const pass = ev.target.closest("[data-backup-action=passphrase]");
    if (pass) { setBackupPassphrase(pass); return; }
    const btn = ev.target.closest("[data-backup-action=run]");
    if (!btn) return;
    btn.disabled = true;
    try {
      await api("/api/backups/run", { method: "POST", body: {} });
      showToast("Backup requested; it runs in the container now.", "success");
      refreshBackups();
      startBackupsPoll();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      btn.disabled = false;
    }
  });
  root.addEventListener("submit", async ev => {
    if (ev.target.id !== "backup-form") return;
    ev.preventDefault();
    const on = document.getElementById("bk-syncthing").checked;
    const body = on ? { enabled: true, keys_source: document.getElementById("bk-keys").value.trim(),
      data_folder: document.getElementById("bk-folder").value.trim() } : { enabled: false };
    if (!on && !(await confirmDialog({ title: "Keep backups in the container?",
      message: "Syncthing is switched off and new backups stay inside the container only. Existing backups on the NAS are not touched.",
      confirmLabel: "Keep them locally" }))) return;
    try {
      await api("/api/backups/site", { method: "PUT", body });
      showToast(on ? "Saved. The container is setting up Syncthing." : "Saved. Backups stay in the container.", "success");
      refreshBackups();
      startBackupsPoll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

// Set or change the backup passphrase: typed twice, sent once, never shown again. The server asks
// for your password (and code) first; root saves it and makes a sealed backup straight away.
function passphraseDialog(change) {
  return new Promise(resolve => {
    const back = document.createElement("div");
    back.className = "modal-backdrop dialog-backdrop";
    const box = document.createElement("form");
    box.className = "modal dialog";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.innerHTML = `
      <div class="modal-header"><span>${change ? "Change backup passphrase" : "Set backup passphrase"}</span></div>
      <div class="modal-body">
        <div class="dialog-message">Keep this passphrase in a password manager, apart from the backups. Without it a sealed backup cannot be opened and nobody can recover it for you.${change ? " Backups made before the change still need the old passphrase, so keep that one too until they are gone." : ""}</div>
        <div class="form-group"><label for="bk-pass1">New backup passphrase (12 or more characters)</label>
          <input type="password" id="bk-pass1" autocomplete="new-password" minlength="12" maxlength="1024" required></div>
        <div class="form-group"><label for="bk-pass2">The same again</label>
          <input type="password" id="bk-pass2" autocomplete="new-password" minlength="12" maxlength="1024" required></div>
        <div class="form-help text-err hidden" id="bk-pass-err"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn" data-dialog="cancel">Cancel</button>
        <button type="submit" class="btn btn-primary">Save passphrase</button>
      </div>`;
    back.appendChild(box);
    document.body.appendChild(back);
    const before = document.activeElement;
    const done = value => {
      document.removeEventListener("keydown", onKey, true);
      box.querySelectorAll("input").forEach(i => { i.value = ""; });
      back.remove();
      if (before && before.focus) before.focus();
      resolve(value);
    };
    const onKey = ev => { if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); done(null); } };
    document.addEventListener("keydown", onKey, true);
    box.querySelector("[data-dialog=cancel]").addEventListener("click", () => done(null));
    box.addEventListener("submit", ev => {
      ev.preventDefault();
      const a = box.querySelector("#bk-pass1").value, b = box.querySelector("#bk-pass2").value;
      const err = box.querySelector("#bk-pass-err");
      const problem = a.length < 12 ? "The passphrase must be at least 12 characters." : a !== b ? "The two passphrases are not the same." : "";
      err.textContent = problem;
      err.classList.toggle("hidden", !problem);
      if (!problem) done(a);
    });
    box.querySelector("#bk-pass1").focus();
  });
}

async function setBackupPassphrase(btn) {
  const change = /Change/.test(btn.textContent);
  let value = await passphraseDialog(change);
  if (value === null) return;
  btn.disabled = true;
  try {
    await api("/api/backups/passphrase", { method: "POST", body: { passphrase: value } });
    value = null;
    showToast("Passphrase sent. The container saves it and makes a sealed backup now.", "success");
    refreshBackups();
    startBackupsPoll();
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    value = null;
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", initBackups);
