/* Settings, Users: add, edit, block, log out, reset the password of and delete users.
 *
 * Roles bundle permissions; Custom ticks them one by one. Device access limits a
 * user to chosen templates and devices. The server enforces all of it; this page
 * only presents it. Every change asks for the administrator's password (once per
 * 5 minutes) through the shared confirmation in app.js.
 */

let usersData = null;

async function loadUsers() {
  const body = document.getElementById("users-body");
  try {
    usersData = await api("/api/users");
  } catch (err) {
    body.innerHTML = `<div class="panel-note-bar warn">${escapeHtml(err.message)}</div>`;
    return;
  }
  renderUsers();
}

function userAccessText(u) {
  if (u.device_scope.all) return "All devices";
  const t = u.device_scope.profiles.map(id => (usersData.templates.find(x => x.id === id) || { name: id }).name);
  const d = u.device_scope.devices.map(id => (usersData.devices.find(x => x.id === id) || { hostname: `#${id}` }).hostname);
  return [...t.map(n => `${n} (template)`), ...d].join(", ");
}

function renderUsers() {
  const roles = Object.fromEntries(usersData.roles.map(r => [r.id, r.label]));
  const rows = usersData.users.map(u => {
    const status = u.disabled ? `<span class="status-pill status-err">Blocked</span>`
      : u.sessions ? `<span class="status-pill status-ok">Signed in</span> <span class="dim">${escapeHtml(u.sessions)} session${u.sessions > 1 ? "s" : ""}</span>`
      : `<span class="status-pill status-unknown">Signed out</span>`;
    return `<tr>
      <td class="text-cell"><strong>${escapeHtml(u.username)}</strong>${u.you ? ' <span class="ack-tag">you</span>' : ""}
        ${u.display_name ? `<div class="dim">${escapeHtml(u.display_name)}</div>` : ""}</td>
      <td class="text-cell">${escapeHtml(roles[u.role] || u.role)}${u.two_factor ? ' <span class="ack-tag" title="Two-factor authentication is on">2FA</span>' : ""}</td>
      <td class="text-cell users-access">${escapeHtml(userAccessText(u))}</td>
      <td class="text-cell">${status}</td>
      <td data-sort="${escapeHtml(u.last_login || 0)}">${u.last_login ? escapeHtml(formatAgo(u.last_login)) : '<span class="dim">Never</span>'}</td>
      <td class="actions-cell">${u.can_change ? `
        <button type="button" class="btn" data-user-edit="${escapeHtml(u.username)}">Edit</button>
        <span class="user-more">
          <button type="button" class="btn" data-user-menu="${escapeHtml(u.username)}" aria-haspopup="true" aria-label="More actions for ${escapeHtml(u.username)}">More</button>
        </span>` : ""}
      </td>
    </tr>`;
  }).join("");
  document.getElementById("users-body").innerHTML = `<table class="sortable users-table">
    <thead><tr><th>User</th><th>Role</th><th>Devices</th><th>Status</th><th>Last login</th><th class="no-sort">Actions</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

/** Small menu of the less common actions, so the row stays short (options appear when clicked). */
function openUserMenu(btn, u) {
  document.querySelectorAll(".user-row-menu").forEach(m => m.remove());
  const menu = document.createElement("div");
  menu.className = "user-row-menu";
  const items = [];
  if (u.sessions && !u.you) items.push(["logout", "Log out everywhere"]);
  items.push(["password", "Set a new password"]);
  if (u.two_factor) items.push(["2fa-reset", "Reset two-factor authentication"]);
  if (!u.you) items.push([u.disabled ? "unblock" : "block", u.disabled ? "Unblock" : "Block"]);
  if (!u.you) items.push(["delete", "Delete user"]);
  menu.innerHTML = items.map(([k, l]) => `<button type="button" class="user-menu-item${k === "delete" || k === "block" ? " danger" : ""}" data-user-action="${escapeHtml(k)}">${escapeHtml(l)}</button>`).join("");
  btn.parentElement.appendChild(menu);
  menu.addEventListener("click", ev => {
    const b = ev.target.closest("[data-user-action]");
    if (!b) return;
    menu.remove();
    userAction(u, b.dataset.userAction);
  });
}

async function userAction(u, action) {
  const name = u.username;
  try {
    if (action === "logout") {
      if (!(await confirmDialog({ title: `Log out ${name}?`, message: "Every browser where they are signed in has to log in again.", confirmLabel: "Log out" }))) return;
      const r = await api(`/api/users/${encodeURIComponent(name)}/logout`, { method: "POST", body: {} });
      showToast(`Ended ${r.ended} session${r.ended === 1 ? "" : "s"} for ${name}`, "success");
    } else if (action === "password") {
      const pw = await promptDialog({ title: `New password for ${name}`,
        message: `At least ${usersData.min_length} characters. ${u.you ? "Your other sessions are logged out." : "Their sessions are logged out; tell them the new password another way."}`,
        input: { label: "New password", placeholder: "" }, confirmLabel: "Set password" });
      if (pw === null) return;
      await api(`/api/users/${encodeURIComponent(name)}/password`, { method: "POST", body: { password: pw } });
      showToast(`Password changed for ${name}`, "success");
    } else if (action === "2fa-reset") {
      if (!(await confirmDialog({ title: `Reset 2FA for ${name}?`, danger: true, confirmLabel: "Reset 2FA",
        message: "For a lost phone without recovery codes. Their sessions end; they log in with the password and can set 2FA up again." }))) return;
      await api(`/api/users/${encodeURIComponent(name)}/2fa-reset`, { method: "POST", body: {} });
      showToast(`Two-factor authentication reset for ${name}`, "success");
    } else if (action === "block" || action === "unblock") {
      const block = action === "block";
      if (block && !(await confirmDialog({ title: `Block ${name}?`, message: "They are logged out at once and cannot log in until unblocked. Nothing they set up is removed.", confirmLabel: "Block", danger: true }))) return;
      await api(`/api/users/${encodeURIComponent(name)}`, { method: "PUT", body: { disabled: block } });
      showToast(`${name} ${block ? "blocked" : "unblocked"}`, "success");
    } else if (action === "delete") {
      if (!(await confirmDialog({ title: `Delete ${name}?`, message: "The account is removed and its sessions end. The audit log keeps what they did.", confirmLabel: "Delete user", danger: true }))) return;
      await api(`/api/users/${encodeURIComponent(name)}`, { method: "DELETE" });
      showToast(`Deleted ${name}`, "success");
    }
  } catch (err) {
    showToast(err.message, "error");
  }
  loadUsers();
}

function userEditorHtml(u) {
  const role = u ? u.role : "viewer";
  const scope = u ? u.device_scope : { all: true, profiles: [], devices: [] };
  const perms = new Set(u ? u.permissions : []);
  const usedTemplates = new Set(usersData.devices.map(d => d.profile_id));
  const templates = usersData.templates.filter(t => usedTemplates.has(t.id) || (scope.profiles || []).includes(t.id));
  return `
    ${u ? "" : `<div class="form-row">
      <div class="form-group"><label for="ue-username">Username</label><input type="text" id="ue-username" maxlength="32" autocomplete="off" spellcheck="false"></div>
      <div class="form-group"><label for="ue-password">Password</label><input type="password" id="ue-password" autocomplete="new-password" placeholder="At least ${escapeHtml(usersData.min_length)} characters"></div>
    </div>`}
    <div class="form-group"><label for="ue-display">Display name (optional)</label><input type="text" id="ue-display" maxlength="64" value="${escapeHtml(u ? u.display_name : "")}"></div>
    <div class="form-group"><label for="ue-role">Role</label>
      <select id="ue-role">${usersData.roles.map(r => `<option value="${escapeHtml(r.id)}" ${r.id === role ? "selected" : ""}>${escapeHtml(r.label)}</option>`).join("")}</select>
      <div class="form-help" id="ue-role-help"></div>
    </div>
    <div class="ue-perms" id="ue-perms">${usersData.permissions.map(p => `<label class="ue-perm" title="${escapeHtml(p.help)}">
      <input type="checkbox" value="${escapeHtml(p.id)}" ${perms.has(p.id) ? "checked" : ""}> <span><strong>${escapeHtml(p.label)}</strong><span class="dim">${escapeHtml(p.help)}</span></span></label>`).join("")}</div>
    <div class="form-group ue-scope-group" id="ue-scope-group"><label>Devices</label>
      <label class="check-label"><input type="radio" name="ue-scope" value="all" ${scope.all ? "checked" : ""}> All devices</label>
      <label class="check-label"><input type="radio" name="ue-scope" value="some" ${scope.all ? "" : "checked"}> Only the templates and devices ticked below</label>
      <div class="ue-scope ${scope.all ? "hidden" : ""}" id="ue-scope">
        <div class="ue-scope-col"><div class="dim">Templates (includes devices added later)</div>
          ${templates.map(t => `<label class="check-label"><input type="checkbox" data-scope-profile="${escapeHtml(t.id)}" ${(scope.profiles || []).includes(t.id) ? "checked" : ""}> ${escapeHtml(t.name)}</label>`).join("")}</div>
        <div class="ue-scope-col"><div class="dim">Single devices</div>
          ${usersData.devices.map(d => `<label class="check-label"><input type="checkbox" data-scope-device="${escapeHtml(d.id)}" ${(scope.devices || []).includes(d.id) ? "checked" : ""}> ${escapeHtml(d.hostname)}</label>`).join("")}</div>
      </div>
    </div>
    <div class="form-error hidden" id="ue-error"></div>`;
}

function syncUserEditor(box) {
  const role = box.querySelector("#ue-role").value;
  const r = usersData.roles.find(x => x.id === role);
  box.querySelector("#ue-role-help").textContent = r.help;
  const custom = role === "custom";
  // Fixed roles show what they include (read only); Custom makes the boxes editable.
  box.querySelectorAll("#ue-perms input").forEach(i => {
    if (!custom) i.checked = r.permissions.includes(i.value);
    i.disabled = !custom;
  });
  box.querySelector("#ue-perms").classList.toggle("ue-perms-fixed", !custom);
  box.querySelector("#ue-scope-group").classList.toggle("hidden", role === "admin");
  const some = box.querySelector("input[name=ue-scope]:checked").value === "some";
  box.querySelector("#ue-scope").classList.toggle("hidden", !some);
}

function openUserEditor(u) {
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal modal-wide user-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>${u ? `Edit ${escapeHtml(u.username)}` : "Add user"}</span>
      <button type="button" class="btn" data-ue-close aria-label="Close">&times;</button></div>
    <div class="modal-body">${userEditorHtml(u)}</div>
    <div class="modal-footer"><button type="button" class="btn" data-ue-close>Cancel</button>
      <button type="submit" class="btn btn-primary">${u ? "Save changes" : "Add user"}</button></div>
  </form>`;
  document.body.appendChild(back);
  const box = back.querySelector("form");
  const initial = () => JSON.stringify(collect());
  const collect = () => {
    const role = box.querySelector("#ue-role").value;
    const some = box.querySelector("input[name=ue-scope]:checked").value === "some";
    const out = {
      display_name: box.querySelector("#ue-display").value.trim(), role,
      permissions: [...box.querySelectorAll("#ue-perms input:checked")].map(i => i.value),
      device_scope: some ? { all: false,
        profiles: [...box.querySelectorAll("[data-scope-profile]:checked")].map(i => i.dataset.scopeProfile),
        devices: [...box.querySelectorAll("[data-scope-device]:checked")].map(i => Number(i.dataset.scopeDevice)) } : { all: true },
    };
    if (!u) { out.username = box.querySelector("#ue-username").value.trim(); out.password = box.querySelector("#ue-password").value; }
    return out;
  };
  syncUserEditor(box);
  const start = initial();
  const close = async () => {
    if (initial() !== start && !(await confirmDialog({ title: "Discard these changes?", confirmLabel: "Discard", danger: true }))) return;
    back.remove();
  };
  box.addEventListener("change", () => syncUserEditor(box));
  box.querySelectorAll("[data-ue-close]").forEach(b => b.addEventListener("click", close));
  back.addEventListener("keydown", ev => { if (ev.key === "Escape" && !document.querySelector(".dialog:not(.user-editor)")) close(); });
  box.addEventListener("submit", async ev => {
    ev.preventDefault();
    const err = box.querySelector("#ue-error");
    const body = collect();
    try {
      if (u) await api(`/api/users/${encodeURIComponent(u.username)}`, { method: "PUT", body });
      else await api("/api/users", { method: "POST", body });
      back.remove();
      showToast(u ? `Saved ${u.username}` : `Added ${body.username}`, "success");
      loadUsers();
    } catch (e) {
      err.textContent = e.message;
      show(err);
    }
  });
  (box.querySelector("#ue-username") || box.querySelector("#ue-display")).focus();
}

function initUsers() {
  document.getElementById("btn-add-user").addEventListener("click", () => usersData && openUserEditor(null));
  document.getElementById("users-body").addEventListener("click", ev => {
    const edit = ev.target.closest("[data-user-edit]");
    if (edit) return openUserEditor(usersData.users.find(x => x.username === edit.dataset.userEdit));
    const more = ev.target.closest("[data-user-menu]");
    if (more) {
      ev.stopPropagation();
      openUserMenu(more, usersData.users.find(x => x.username === more.dataset.userMenu));
    }
  });
  document.addEventListener("click", ev => {
    if (!ev.target.closest(".user-row-menu")) document.querySelectorAll(".user-row-menu").forEach(m => m.remove());
  });
}

document.addEventListener("DOMContentLoaded", initUsers);
