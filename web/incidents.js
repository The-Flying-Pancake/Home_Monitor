/* Incidents page (#/incidents, #/incidents/<id>) and the change log (#/incidents/changes).
 * An incident is a person's record of something that went wrong: priority, status, owner, devices,
 * linked problems, the write-up, a timeline of notes and follow-up actions (incidents.py). The change
 * log lists maintenance windows kept a year; a window can be marked as a change. */

const INC_TONES = { P1: "bad", P2: "warn", P3: "info", Open: "bad", Investigating: "warn", Monitoring: "warn", Resolved: "good",
  Plan: "info", "In progress": "warn", Done: "good", Change: "info" };
let incMeta = null;          // the list reply: devices, owners and the choices, for the forms
let incShow = "open";
let incChanges = "1";

function incPill(word) {
  return `<span class="rep-pill rt-${escapeHtml(INC_TONES[word] || "none")}">${escapeHtml(word)}</span>`;
}

/** The button on an open problem (problems list and device page): opens an incident from it. */
function incidentButton(p) {
  if (!p || p.severity === "info") return "";
  return ` <button type="button" class="btn btn-small" data-perm="incidents.manage" data-incident-device="${Number(p.device_id)}" ` +
    `data-incident-key="${escapeHtml(p.problem_key)}" title="Open an incident record for this problem">Open incident</button>`;
}

function incLocalInput(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const two = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}`;
}

function incFromInput(value) {
  return value ? Math.floor(new Date(value).getTime() / 1000) : null;
}

function incTabs(active) {
  return `<div class="tab-bar inc-tabs">
    <a class="tab ${active === "list" ? "active" : ""}" href="#/incidents">Incidents</a>
    <a class="tab ${active === "changes" ? "active" : ""}" href="#/incidents/changes">Changes</a></div>`;
}

async function loadIncidents(route) {
  const root = document.getElementById("incidents-root");
  try {
    if (route === "changes") return await renderChangeLog(root);
    incMeta = await api(`/api/incidents?show=${encodeURIComponent(incShow)}`);
    if (route) return await renderIncident(root, parseInt(route, 10));
    renderIncidentList(root);
  } catch (err) {
    root.innerHTML = `${incTabs(route === "changes" ? "changes" : "list")}<div class="panel inc-panel"><p class="text-err">${escapeHtml(err.message)}</p></div>`;
  }
}

function renderIncidentList(root) {
  const rows = incMeta.incidents;
  const opts = incMeta.devices.map(d => `<option value="${Number(d.id)}">${escapeHtml(d.name)}</option>`).join("");
  root.innerHTML = `${incTabs("list")}
    <div class="panel inc-panel">
      <div class="inc-toolbar">
        <div class="inc-filter" role="group" aria-label="Which incidents">
          <button type="button" class="btn btn-small ${incShow === "open" ? "btn-primary" : ""}" data-inc-show="open">Open</button>
          <button type="button" class="btn btn-small ${incShow === "all" ? "btn-primary" : ""}" data-inc-show="all">All</button>
        </div>
        ${incMeta.can_manage ? `<button type="button" class="btn btn-primary" id="btn-inc-new">New incident</button>` : ""}
      </div>
      ${incMeta.can_manage ? `<form class="inc-new hidden" id="inc-new-form" autocomplete="off">
        <div class="form-row three">
          <div class="form-group"><label for="inc-new-title">Title</label><input type="text" id="inc-new-title" maxlength="120" placeholder="Internet down after the router update"></div>
          <div class="form-group"><label for="inc-new-priority">Priority</label><select id="inc-new-priority">
            ${incMeta.priorities.map(p => `<option value="${escapeHtml(p)}" ${p === "P2" ? "selected" : ""}>${escapeHtml(p)}</option>`).join("")}</select></div>
          <div class="form-group"><label for="inc-new-devices">Devices</label><select id="inc-new-devices" multiple size="4">${opts}</select></div>
        </div>
        <div class="form-help" id="inc-new-msg"></div>
        <div class="pve-actions"><button type="submit" class="btn btn-primary">Open the incident</button></div>
      </form>` : ""}
      <table class="inc-table"><thead><tr><th>ID</th><th>Pri</th><th>Title</th><th>Since</th><th>Owner</th><th>Devices</th><th>Status</th></tr></thead>
      <tbody>${rows.length ? rows.map(i => `<tr>
        <td><a href="#/incidents/${Number(i.id)}" class="device-link">${escapeHtml(i.ref)}</a></td><td>${incPill(i.priority)}</td>
        <td class="text-cell"><a href="#/incidents/${Number(i.id)}">${escapeHtml(i.title)}</a></td>
        <td>${escapeHtml(formatTime(i.started_at))}</td><td class="text-cell">${escapeHtml(i.owner || "")}</td>
        <td class="text-cell">${escapeHtml(i.devices.map(d => d.name).join(", "))}</td><td>${incPill(i.status)}</td></tr>`).join("")
        : `<tr><td colspan="7" class="empty-cell">${incShow === "open" ? "No open incidents." : "No incidents yet."} Open one from a problem, or with New incident.</td></tr>`}</tbody></table>
    </div>`;
}

function incField(id, label, value, rows) {
  return `<div class="form-group inc-wide"><label for="${escapeHtml(id)}">${escapeHtml(label)}</label>
    <textarea id="${escapeHtml(id)}" rows="${Number(rows)}" maxlength="4000">${escapeHtml(value || "")}</textarea></div>`;
}

async function renderIncident(root, id) {
  const inc = (await api(`/api/incidents/${id}`)).incident;
  const manage = incMeta.can_manage;
  const chosen = new Set(inc.devices.map(d => d.id));
  const known = new Set(incMeta.devices.map(d => d.id));
  const devOpts = incMeta.devices.map(d => `<option value="${Number(d.id)}" ${chosen.has(d.id) ? "selected" : ""}>${escapeHtml(d.name)}</option>`).join("")
    + inc.devices.filter(d => !known.has(d.id)).map(d => `<option value="${Number(d.id)}" selected>${escapeHtml(d.name)} (deleted)</option>`).join("");
  const sel = (id2, list, value) => `<select id="${escapeHtml(id2)}">${list.map(v => `<option value="${escapeHtml(v)}" ${v === value ? "selected" : ""}>${escapeHtml(v)}</option>`).join("")}</select>`;
  const write = [["Summary", inc.summary], ["Root cause", inc.root_cause], ["Impact", inc.impact], ["Next step", inc.next_step]];
  const edit = manage ? `<form class="inc-edit" id="inc-edit-form" data-inc-id="${Number(inc.id)}" autocomplete="off">
      <div class="form-row three">
        <div class="form-group inc-wide"><label for="inc-title">Title</label><input type="text" id="inc-title" maxlength="120" value="${escapeHtml(inc.title)}"></div>
        <div class="form-group"><label for="inc-priority">Priority</label>${sel("inc-priority", incMeta.priorities, inc.priority)}</div>
        <div class="form-group"><label for="inc-status">Status</label>${sel("inc-status", incMeta.statuses, inc.status)}</div>
      </div>
      <div class="form-row three">
        <div class="form-group"><label for="inc-owner">Owner</label><input type="text" id="inc-owner" maxlength="64" list="inc-owners" value="${escapeHtml(inc.owner || "")}" placeholder="A user or a name">
          <datalist id="inc-owners">${incMeta.owners.map(o => `<option value="${escapeHtml(o)}"></option>`).join("")}</datalist></div>
        <div class="form-group"><label for="inc-started">Started</label><input type="datetime-local" id="inc-started" value="${escapeHtml(incLocalInput(inc.started_at))}"></div>
        <div class="form-group ${inc.status === "Resolved" ? "" : "hidden"}" id="inc-resolved-wrap"><label for="inc-resolved">Resolved</label><input type="datetime-local" id="inc-resolved" value="${escapeHtml(incLocalInput(inc.resolved_at))}"></div>
      </div>
      <div class="form-group"><label for="inc-devices">Devices</label><select id="inc-devices" multiple size="5">${devOpts}</select>
        <div class="form-help">Hold Ctrl (or Cmd) to choose more than one.</div></div>
      ${incField("inc-summary", "Summary", inc.summary, 3)}${incField("inc-root", "Root cause", inc.root_cause, 3)}
      ${incField("inc-impact", "Impact", inc.impact, 2)}${incField("inc-next", "Next step", inc.next_step, 2)}
      <div class="form-help" id="inc-edit-msg"></div>
      <div class="pve-actions"><button type="submit" class="btn btn-primary">Save</button></div>
    </form>` : `<dl class="inc-facts">
      <dt>Owner</dt><dd>${escapeHtml(inc.owner || "Nobody yet")}</dd>
      <dt>Started</dt><dd>${escapeHtml(formatTime(inc.started_at))}</dd>
      ${inc.resolved_at ? `<dt>Resolved</dt><dd>${escapeHtml(formatTime(inc.resolved_at))}</dd>` : ""}
      <dt>Devices</dt><dd>${escapeHtml(inc.devices.map(d => d.name).join(", ") || "None")}</dd>
      ${write.filter(w => w[1]).map(w => `<dt>${escapeHtml(w[0])}</dt><dd class="inc-text">${escapeHtml(w[1])}</dd>`).join("")}</dl>`;
  const problems = inc.problems.length ? `<ul class="inc-problems">${inc.problems.map(p => `<li>
      <a class="device-link" href="#/device/${Number(p.device_id)}">${escapeHtml((inc.devices.find(d => d.id === p.device_id) || {}).name || "Device")}</a>
      ${escapeHtml(p.message)} ${p.open ? incPill("Open") : `<span class="dim">cleared</span>`}</li>`).join("")}</ul>` : "";
  const actionRows = inc.actions.map((a, n) => `<tr>
      <td>${Number(n + 1)}</td><td class="text-cell">${escapeHtml(a.description)}</td><td class="text-cell">${escapeHtml(a.owner || "")}</td>
      <td>${escapeHtml(a.due || "")}</td>
      <td>${manage ? `<select data-inc-action-status="${Number(a.id)}" aria-label="Status of action ${Number(n + 1)}">${incMeta.action_statuses.map(s =>
        `<option value="${escapeHtml(s)}" ${s === a.status ? "selected" : ""}>${escapeHtml(s)}</option>`).join("")}</select>` : incPill(a.status)}</td>
      <td class="actions-cell">${manage ? `<button type="button" class="btn btn-small" data-inc-action-remove="${Number(a.id)}">Remove</button>` : ""}</td></tr>`).join("");
  const actions = `<table class="inc-table"><thead><tr><th>#</th><th>Action</th><th>Owner</th><th>Due</th><th>Status</th><th></th></tr></thead>
      <tbody>${actionRows || `<tr><td colspan="6" class="empty-cell">No actions yet.</td></tr>`}</tbody></table>
    ${manage ? `<form class="inc-action-form" id="inc-action-form" autocomplete="off">
      <div class="form-row three">
        <div class="form-group inc-wide"><label for="inc-action-desc">New action</label><input type="text" id="inc-action-desc" maxlength="300" placeholder="Label the breaker in the cupboard"></div>
        <div class="form-group"><label for="inc-action-owner">Owner</label><input type="text" id="inc-action-owner" maxlength="64" list="inc-owners"></div>
        <div class="form-group"><label for="inc-action-due">Due</label><input type="date" id="inc-action-due"></div>
      </div>
      <div class="pve-actions"><button type="submit" class="btn">Add action</button></div></form>` : ""}`;
  const notes = `<ol class="inc-timeline">${inc.notes.map(n => `<li class="${n.kind === "status" ? "inc-status-note" : ""}">
      <span class="dim">${escapeHtml(formatTime(n.at))}${n.kind === "status" ? "" : ` · ${escapeHtml(n.author)}`}</span>
      <span class="inc-text">${escapeHtml(n.text)}</span></li>`).join("")}</ol>
    ${manage ? `<form class="inc-note-form" id="inc-note-form" autocomplete="off">
      <div class="form-group"><label for="inc-note">Add a note</label><textarea id="inc-note" rows="2" maxlength="2000" placeholder="What was found or tried"></textarea></div>
      <div class="pve-actions"><button type="submit" class="btn">Add note</button></div></form>` : ""}`;
  root.innerHTML = `${incTabs("list")}
    <div class="panel inc-panel" id="inc-view" data-inc-id="${Number(inc.id)}">
      <div class="inc-head"><a href="#/incidents" class="dim">Incidents</a>
        <h2><span class="inc-ref">${escapeHtml(inc.ref)}</span> ${escapeHtml(inc.title)}</h2>
        <div class="inc-pills">${incPill(inc.priority)} ${incPill(inc.status)} <span class="dim">for ${escapeHtml(formatDuration(inc.seconds))}</span></div></div>
      ${edit}
      ${problems ? `<h3 class="inc-sub">Linked problems</h3>${problems}` : ""}
      <h3 class="inc-sub">Actions</h3>${actions}
      <h3 class="inc-sub">Timeline</h3>${notes}
    </div>`;
}

async function renderChangeLog(root) {
  const data = await api(`/api/maintenance/history?changes=${encodeURIComponent(incChanges)}`);
  let day = "";
  const rows = data.windows.map(w => {
    const d = new Date(w.start * 1000).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
    const head = d !== day ? `<tr class="inc-day"><td colspan="6">${escapeHtml(d)}</td></tr>` : "";
    day = d;
    const mark = data.can_mark ? `<button type="button" class="btn btn-small" data-perm="problems.ack" data-change-mark="${Number(w.id)}" data-change-note="${escapeHtml(w.change_note || "")}">${w.change ? "Edit" : "Mark as change"}</button>` : "";
    return `${head}<tr>
      <td>${escapeHtml(new Date(w.start * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))}</td>
      <td>${escapeHtml(formatDuration(Math.max(0, Math.min(w.end, Date.now() / 1000) - w.start)))}</td>
      <td class="text-cell">${escapeHtml(w.covers)}</td>
      <td class="text-cell">${w.change ? `${incPill("Change")} ${escapeHtml(w.change_note)}` : ""}${w.note ? ` <span class="dim">${escapeHtml(w.note)}</span>` : ""}</td>
      <td class="text-cell">${escapeHtml(w.by || "")}</td><td class="actions-cell">${mark}</td></tr>`;
  }).join("");
  root.innerHTML = `${incTabs("changes")}
    <div class="panel inc-panel">
      <div class="inc-toolbar">
        <div class="inc-filter" role="group" aria-label="Which windows">
          <button type="button" class="btn btn-small ${incChanges === "1" ? "btn-primary" : ""}" data-change-show="1">Changes</button>
          <button type="button" class="btn btn-small ${incChanges === "0" ? "btn-primary" : ""}" data-change-show="0">All maintenance</button>
        </div>
        <span class="dim">The last year. Mark a maintenance window as a change in Settings, Maintenance windows, or here.</span>
      </div>
      <table class="inc-table"><thead><tr><th>At</th><th>Lasted</th><th>Covers</th><th>What was changed</th><th>By</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="empty-cell">${incChanges === "1" ? "No changes in the last year." : "No maintenance windows in the last year."}</td></tr>`}</tbody></table>
    </div>`;
}

function incRoute() {
  const m = (window.location.hash || "").match(/^#\/incidents(?:\/(\d+|changes))?$/);
  return m ? m[1] || "" : "";
}

async function incSave(viewId, path, method, body, msg) {
  try {
    await api(path, { method, body });
    if (msg) showToast(msg, "success");
    if (viewId) loadIncidents(String(viewId));
  } catch (err) {
    showToast(err.message, "error");
  }
}

function initIncidents() {
  document.addEventListener("click", async ev => {
    const from = ev.target.closest("[data-incident-key]");
    if (from) {
      ev.preventDefault();
      const body = { from_problem: { device_id: parseInt(from.dataset.incidentDevice, 10), problem_key: from.dataset.incidentKey } };
      if (!(await confirmDialog({ title: "Open an incident for this problem?", message: "Its device, start time and the problem are filled in. You can change everything on the incident's page.", confirmLabel: "Open incident" }))) return;
      try {
        const r = await api("/api/incidents", { method: "POST", body });
        showToast(r.existing ? `${r.incident.ref} is already open for this problem.` : `Opened ${r.incident.ref}.`, "success");
        window.location.hash = `#/incidents/${Number(r.incident.id)}`;
      } catch (err) {
        showToast(err.message, "error");
      }
      return;
    }
    const root = document.getElementById("incidents-root");
    if (!root || !root.contains(ev.target)) return;
    const showBtn = ev.target.closest("[data-inc-show]");
    if (showBtn) { incShow = showBtn.dataset.incShow; loadIncidents(""); return; }
    const chShow = ev.target.closest("[data-change-show]");
    if (chShow) { incChanges = chShow.dataset.changeShow; loadIncidents("changes"); return; }
    if (ev.target.closest("#btn-inc-new")) {
      const form = document.getElementById("inc-new-form");
      form.classList.toggle("hidden");
      if (!form.classList.contains("hidden")) document.getElementById("inc-new-title").focus();
      return;
    }
    const mark = ev.target.closest("[data-change-mark]");
    if (mark) {
      const wid = mark.dataset.changeMark;
      const note = await promptDialog({ title: "Mark as a change", message: "In a few words, what was changed. Leave it empty to remove the mark.",
        input: { label: "What was changed", placeholder: "Firmware 7.2 on the switches", value: mark.dataset.changeNote }, confirmLabel: "Save" });
      if (note === null) return;
      try {
        await api(`/api/maintenance/${encodeURIComponent(wid)}/change`, { method: "POST", body: { change_note: note.trim() } });
        loadIncidents("changes");
      } catch (err) {
        showToast(err.message, "error");
      }
      return;
    }
    const view = document.getElementById("inc-view");
    const id = view ? view.dataset.incId : "";
    const remove = ev.target.closest("[data-inc-action-remove]");
    if (remove && id) {
      incSave(id, `/api/incidents/${encodeURIComponent(id)}/actions/${encodeURIComponent(remove.dataset.incActionRemove)}`, "DELETE", undefined, "Action removed.");
    }
  });
  document.addEventListener("change", ev => {
    const root = document.getElementById("incidents-root");
    if (!root || !root.contains(ev.target)) return;
    const st = ev.target.closest("[data-inc-action-status]");
    const view = document.getElementById("inc-view");
    if (st && view) {
      incSave(view.dataset.incId, `/api/incidents/${encodeURIComponent(view.dataset.incId)}/actions/${encodeURIComponent(st.dataset.incActionStatus)}`,
        "PUT", { status: st.value }, "Action updated.");
    }
    if (ev.target.id === "inc-status") {
      document.getElementById("inc-resolved-wrap").classList.toggle("hidden", ev.target.value !== "Resolved");
    }
  });
  document.addEventListener("submit", async ev => {
    const root = document.getElementById("incidents-root");
    if (!root || !root.contains(ev.target)) return;
    ev.preventDefault();
    const view = document.getElementById("inc-view");
    const id = view ? view.dataset.incId : "";
    const chosen = sel => [...document.getElementById(sel).selectedOptions].map(o => parseInt(o.value, 10));
    if (ev.target.id === "inc-new-form") {
      const msg = document.getElementById("inc-new-msg");
      try {
        const r = await api("/api/incidents", { method: "POST", body: { title: document.getElementById("inc-new-title").value,
          priority: document.getElementById("inc-new-priority").value, devices: chosen("inc-new-devices") } });
        window.location.hash = `#/incidents/${Number(r.incident.id)}`;
      } catch (err) {
        msg.textContent = err.message;
        msg.className = "form-help text-err";
      }
    } else if (ev.target.id === "inc-edit-form") {
      const status = document.getElementById("inc-status").value;
      const body = { title: document.getElementById("inc-title").value, priority: document.getElementById("inc-priority").value, status,
        owner: document.getElementById("inc-owner").value, started_at: incFromInput(document.getElementById("inc-started").value),
        devices: chosen("inc-devices"), summary: document.getElementById("inc-summary").value,
        root_cause: document.getElementById("inc-root").value, impact: document.getElementById("inc-impact").value,
        next_step: document.getElementById("inc-next").value };
      if (status === "Resolved" && document.getElementById("inc-resolved").value) body.resolved_at = incFromInput(document.getElementById("inc-resolved").value);
      try {
        await api(`/api/incidents/${encodeURIComponent(id)}`, { method: "PUT", body });
        showToast("Saved.", "success");
        loadIncidents(id);
      } catch (err) {
        const msg = document.getElementById("inc-edit-msg");
        msg.textContent = err.message;
        msg.className = "form-help text-err";
      }
    } else if (ev.target.id === "inc-action-form") {
      incSave(id, `/api/incidents/${encodeURIComponent(id)}/actions`, "POST", { description: document.getElementById("inc-action-desc").value,
        owner: document.getElementById("inc-action-owner").value, due: document.getElementById("inc-action-due").value }, "Action added.");
    } else if (ev.target.id === "inc-note-form") {
      incSave(id, `/api/incidents/${encodeURIComponent(id)}/notes`, "POST", { text: document.getElementById("inc-note").value }, "");
    }
  });
}

initIncidents();
