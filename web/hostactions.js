/* Host actions: the fixed maintenance catalogue (hostactions.py) run once on a Linux host over SSH.
 *
 * Opened from a device's page (Host actions), from a problem row (Fix...) with the actions that suit that
 * problem listed first, or from the Automation page. Checks run at one click; clean-ups and restarts show a
 * preview first, and restarts ask for the device's name. Any action can be saved as a workflow instead,
 * where it can be given a schedule.
 */

let haCatalogue = null;
let haLoading = null;
let ha = null;
let haTimer = null;

const HA_KINDS = {
  check: ["Checks", "Change nothing. One click."],
  change: ["Clean-ups and repairs", "Show what would change first."],
  restart: ["Restarts", "Preview first, then type the device's name to confirm."],
};
const HA_STATUS = { running: ["status-unknown", "running"], ok: ["status-ok", "done"], failed: ["status-err", "failed"],
  error: ["status-err", "error"], interrupted: ["status-warn", "interrupted"] };

function haPill(status) {
  const [cls, text] = HA_STATUS[status] || ["status-unknown", status || "?"];
  return `<span class="status-pill ${cls}">${escapeHtml(text)}</span>`;
}

function haAllowed() { return !document.body.classList.contains("lacks-automation-run"); }
/** Linux hosts polled over SNMP (Proxmox hosts use the same template); not port checks. */
function haEligible(d) { return !!d && d.profile_id === "linux_host" && !d.service_port; }

function haLoadCatalogue() {
  if (haCatalogue) return Promise.resolve(haCatalogue);
  if (!haAllowed()) return Promise.resolve(null);
  if (!haLoading) {
    haLoading = api("/api/host-actions").then(r => { haCatalogue = r.actions; haMergeTemplates(); return haCatalogue; })
      .catch(() => null).finally(() => { haLoading = null; });
  }
  return haLoading;
}

/** The catalogue in the workflow editor's command templates, so a workflow step can use the same scripts. */
function haMergeTemplates() {
  if (typeof WF_COMMAND_TEMPLATES === "undefined" || !haCatalogue) return;
  for (const a of haCatalogue) {
    if (WF_COMMAND_TEMPLATES.some(t => t.id === "ha_" + a.id)) continue;
    WF_COMMAND_TEMPLATES.push({ id: "ha_" + a.id, name: `Host action: ${a.name}`, suits: ["linux_host"],
      timeout_s: Math.min(3600, Math.max(30, a.timeout)), command: a.script, expect_disconnect: a.reboot,
      note: a.note + (a.choice ? ` Set C on the first line to the ${a.choice.label.toLowerCase()}.` : "") +
        (a.reboot ? " Follow it with Wait for ping (stops answering) and Wait for ping (answers)." : "") });
  }
}

function haFits(key) {
  if (!haCatalogue) { haLoadCatalogue(); return false; }
  return haCatalogue.some(a => a.fits.some(f => key === f || key.startsWith(f + ":")));
}

/** The Fix... button on a problem: Linux hosts only, problems an action helps with, users who may run actions. */
function haProblemButton(p, device) {
  if (!haAllowed() || !haEligible(device) || !p.problem_key || !haFits(p.problem_key)) return "";
  return ` <button class="btn btn-ack" data-perm="automation.run" data-ha-device="${Number(p.device_id)}" data-ha-problem="${escapeHtml(p.problem_key)}"` +
    ` data-ha-message="${escapeHtml(p.message)}" title="Checks and fixes for this problem, run on the host over SSH">Fix...</button>`;
}

function haCredKey(id) { return `ha-cred-${id}`; }
function haRemember(key, value) { try { localStorage.setItem(key, value); } catch (e) { /* private window */ } }
function haRecall(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }

function haBody() {
  return { credential_id: parseInt(document.getElementById("ha-cred").value, 10) || null,
    ssh_port: parseInt(document.getElementById("ha-port").value, 10) || 22 };
}

async function openHostActions(deviceId, problemKey = "", message = "", runId = null) {
  if (!autoData) await loadAutomation();
  let view;
  try {
    view = await api(`/api/host-actions?device_id=${Number(deviceId)}&problem=${encodeURIComponent(problemKey || "")}`);
  } catch (err) {
    showToast(`Could not open host actions: ${err.message}`, "error");
    return;
  }
  haCatalogue = view.actions;
  ha = { device: view.device, problemKey, message, suggested: view.suggested || [], runs: view.runs || [],
    showAll: !(view.suggested || []).length, action: null, choice: "", previewed: null };
  document.getElementById("ha-title").textContent = `Host actions on ${view.device.hostname}`;
  const creds = (autoData && autoData.credentials) || [];
  const sel = document.getElementById("ha-cred");
  sel.innerHTML = creds.map(c => `<option value="${Number(c.id)}">${escapeHtml(c.name)} (${escapeHtml(c.username || "root")})</option>`).join("");
  const remembered = haRecall(haCredKey(deviceId));
  if (remembered && creds.some(c => String(c.id) === remembered)) sel.value = remembered;
  const none = !creds.length;
  document.getElementById("ha-nocred").classList.toggle("hidden", !none);
  document.getElementById("ha-form").classList.toggle("hidden", none);
  document.getElementById("ha-hostkey").classList.toggle("hidden", none || view.device.host_key);
  const prob = document.getElementById("ha-problem");
  prob.textContent = message ? `For the problem: ${message}` : "";
  prob.classList.toggle("hidden", !message);
  show(document.getElementById("modal-hostact"));
  if (runId || view.running) haWatch(runId || view.running);
  else haShowList();
}

function haItem(a, choice) {
  const direct = a.kind === "check" && !a.choice;
  return `<div class="ha-item">
      <div class="ha-item-text"><strong>${escapeHtml(a.name)}</strong>${choice ? ` <span class="dim">(${escapeHtml(choice)})</span>` : ""}
        <div class="dim">${escapeHtml(a.note)}</div></div>
      <button type="button" class="btn${direct ? " btn-primary" : ""}" data-ha-open="${escapeHtml(a.id)}" data-ha-choice="${escapeHtml(choice || "")}">${direct ? "Run" : "Open"}</button>
    </div>`;
}

function haShowList() {
  ha.view = "list";
  ha.action = null;
  const byId = Object.fromEntries(haCatalogue.map(a => [a.id, a]));
  let html = "";
  if (ha.suggested.length) {
    html += `<div class="output-label">Suggested for this problem</div>` +
      ha.suggested.filter(s => byId[s.id]).map(s => haItem(byId[s.id], s.choice)).join("");
  }
  if (ha.showAll) {
    for (const kind of Object.keys(HA_KINDS)) {
      const list = haCatalogue.filter(a => a.kind === kind);
      html += `<div class="output-label">${escapeHtml(HA_KINDS[kind][0])} <span class="dim">${escapeHtml(HA_KINDS[kind][1])}</span></div>` +
        list.map(a => haItem(a, "")).join("");
    }
  } else {
    html += `<button type="button" class="btn ha-more" id="btn-ha-all">Show all ${haCatalogue.length} actions</button>`;
  }
  if (ha.runs.length) {
    html += `<div class="output-label">Recent runs here</div><table class="ha-runs"><tbody>` + ha.runs.map(r => `
      <tr class="clickable-row" data-ha-run="${Number(r.id)}"><td>${escapeHtml(formatTime(r.started_at))}</td>
      <td class="text-cell">${escapeHtml(r.name)}${r.choice ? ` <span class="dim">(${escapeHtml(r.choice)})</span>` : ""}</td>
      <td class="dim">${escapeHtml(r.username || "")}</td><td>${haPill(r.status)}</td></tr>`).join("") + `</tbody></table>`;
  }
  document.getElementById("ha-list").innerHTML = html;
  show(document.getElementById("ha-list"));
  for (const id of ["ha-detail", "ha-run", "btn-ha-back", "btn-ha-preview", "btn-ha-run", "btn-ha-workflow"]) hide(document.getElementById(id));
}

async function haOpen(id, choice) {
  const a = haCatalogue.find(x => x.id === id);
  if (!a) return;
  ha.action = a;
  ha.choice = choice || (a.choice && a.choice.default) || "";
  ha.previewed = null;
  if (a.kind === "check" && !a.choice) {
    haRun();
    return;
  }
  ha.view = "detail";
  hide(document.getElementById("ha-list"));
  hide(document.getElementById("ha-run"));
  const guest = ha.device.guest;
  const snap = guest && a.kind !== "check"
    ? `<label class="checkbox-label"><input type="checkbox" id="ha-snapshot"${a.snapshot ? " checked" : ""}> Take a Proxmox snapshot of ${escapeHtml(guest.name || "#" + guest.vmid)} first</label>` : "";
  const confirm = a.kind === "restart"
    ? `<div class="form-group"><label for="ha-confirm">Type <strong>${escapeHtml(ha.device.hostname)}</strong> to confirm</label><input type="text" id="ha-confirm" autocomplete="off"></div>` : "";
  let choiceHtml = "";
  if (a.choice) {
    const opts = a.choice.options || [];
    choiceHtml = `<div class="form-group"><label for="ha-choice">${escapeHtml(a.choice.label)}</label>` + (a.choice.listed
      ? `<select id="ha-choice"><option value="">Loading the list from the host...</option></select>`
      : `<select id="ha-choice">${opts.map(o => `<option${o === ha.choice ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select>`) + `</div>`;
  }
  const det = document.getElementById("ha-detail");
  det.innerHTML = `<h4 class="ha-name">${escapeHtml(a.name)}</h4><div class="form-help">${escapeHtml(a.note)}</div>${choiceHtml}
    <div id="ha-preview-box" class="hidden"><div class="output-label">Preview <span class="dim">(nothing changed yet)</span></div><pre id="ha-preview" class="fixsnmp-diff"></pre></div>
    ${snap}${confirm}`;
  show(det);
  show(document.getElementById("btn-ha-back"));
  show(document.getElementById("btn-ha-workflow"));
  document.getElementById("btn-ha-preview").classList.toggle("hidden", !a.has_preview);
  show(document.getElementById("btn-ha-run"));
  haSyncRun();
  if (a.choice && a.choice.listed) {
    try {
      const r = await api(`/api/devices/${ha.device.id}/host-actions/${a.id}`, { method: "POST", body: { ...haBody(), mode: "choices" } });
      const sel = document.getElementById("ha-choice");
      if (!sel || ha.action !== a) return;
      const opts = r.options.includes(ha.choice) || !ha.choice ? r.options : [ha.choice, ...r.options];
      sel.innerHTML = opts.length ? `<option value="">Choose...</option>` + opts.map(o => `<option${o === ha.choice ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")
        : `<option value="">Nothing found on this host</option>`;
    } catch (err) {
      const sel = document.getElementById("ha-choice");
      if (sel) sel.innerHTML = `<option value="">Could not read the list</option>`;
      showToast(err.message, "error");
    }
  }
}

function haCurrentChoice() {
  const sel = document.getElementById("ha-choice");
  return sel ? sel.value : "";
}

/** Run needs a choice when the action takes one, and for changes and restarts a preview of that same choice. */
function haSyncRun() {
  const a = ha.action;
  const choice = haCurrentChoice();
  const needPreview = a.kind !== "check";
  const ready = (!a.choice || !!choice) && (!needPreview || ha.previewed === choice);
  const btn = document.getElementById("btn-ha-run");
  btn.disabled = !ready;
  btn.textContent = a.kind === "restart" ? "Restart" : "Run";
  btn.classList.toggle("btn-danger-solid", a.kind === "restart");
  btn.classList.toggle("btn-primary", a.kind !== "restart");
  btn.title = ready ? "" : (a.choice && !choice ? `Choose a ${a.choice.label.toLowerCase()} first` : "Preview first");
}

async function haPreview() {
  const a = ha.action;
  const choice = haCurrentChoice();
  const btn = document.getElementById("btn-ha-preview");
  btn.disabled = true;
  try {
    const r = await api(`/api/devices/${ha.device.id}/host-actions/${a.id}`, { method: "POST", body: { ...haBody(), mode: "preview", choice } });
    document.getElementById("ha-preview").textContent = r.output || "(no output)";
    show(document.getElementById("ha-preview-box"));
    ha.previewed = choice;
    haRemember(haCredKey(ha.device.id), String(haBody().credential_id));
    haSshOffer("");
  } catch (err) {
    showToast(`Preview failed: ${err.message}`, "error");
    haSshOffer(err.message);
  } finally {
    btn.disabled = false;
    haSyncRun();
  }
}

async function haRun() {
  const a = ha.action;
  const choice = a.choice ? (ha.view === "detail" ? haCurrentChoice() : ha.choice) : "";
  const snap = document.getElementById("ha-snapshot");
  const conf = document.getElementById("ha-confirm");
  try {
    const r = await api(`/api/devices/${ha.device.id}/host-actions/${a.id}`, { method: "POST", body: {
      ...haBody(), mode: "run", choice, problem_key: ha.problemKey || "",
      snapshot: !!(snap && snap.checked && ha.view === "detail"), confirm: conf ? conf.value : "" } });
    haRemember(haCredKey(ha.device.id), String(haBody().credential_id));
    haWatch(r.run_id);
  } catch (err) {
    showToast(err.message, "error");
    haSshOffer(err.message);
  }
}

/** Copy console commands: shown only after a failure that means SSH did not let the monitor in. */
function haSshOffer(message) {
  const b = document.getElementById("btn-ha-sshsetup");
  if (b) b.classList.toggle("hidden", !(typeof isSshLoginFailure === "function" && isSshLoginFailure(message)));
}

async function haWorkflow() {
  const a = ha.action;
  try {
    const r = await api(`/api/devices/${ha.device.id}/host-actions/${a.id}`, { method: "POST",
      body: { ...haBody(), mode: "workflow", choice: haCurrentChoice() } });
    closeHostActions();
    showToast("Saved as a workflow. Give its trigger a schedule to repeat it.", "success");
    window.location.hash = "#/automation";
    setTimeout(async () => {
      await loadWorkflows();
      const wf = wfList && wfList.workflows.find(w => w.id === r.workflow_id);
      if (wf) openWorkflowModal(wf);
    }, 300);
  } catch (err) {
    showToast(err.message, "error");
  }
}

function haWatch(runId) {
  ha.view = "run";
  for (const id of ["ha-list", "ha-detail", "btn-ha-preview", "btn-ha-run", "btn-ha-workflow"]) hide(document.getElementById(id));
  show(document.getElementById("btn-ha-back"));
  const box = document.getElementById("ha-run");
  box.innerHTML = `<div class="ha-run-head">Starting...</div><pre class="fixsnmp-diff ha-output"></pre>`;
  show(box);
  clearTimeout(haTimer);
  const tick = async () => {
    if (!ha || ha.view !== "run") return;
    try {
      const { run } = await api(`/api/host-actions/runs/${Number(runId)}`);
      box.querySelector(".ha-run-head").innerHTML = `${haPill(run.status)} <strong>${escapeHtml(run.name)}</strong>` +
        `${run.choice ? ` (${escapeHtml(run.choice)})` : ""} <span class="dim">started ${escapeHtml(formatTime(run.started_at))}` +
        `${run.username ? " by " + escapeHtml(run.username) : ""}${run.finished_at ? ", took " + escapeHtml(formatDuration(run.finished_at - run.started_at)) : ""}</span>`;
      box.querySelector(".ha-output").textContent = run.output || (run.status === "running" ? "Running on the host..." : "(no output)");
      if (run.status === "running") haTimer = setTimeout(tick, 2000);
      else if (run.status !== "success") haSshOffer(run.output || "");
      else if (typeof loadHostActionRuns === "function" && !document.getElementById("view-automation").classList.contains("hidden")) loadHostActionRuns();
    } catch (err) {
      box.querySelector(".ha-run-head").textContent = err.message;
    }
  };
  tick();
}

document.addEventListener("click", async ev => {
  if (!ev.target.closest || !ev.target.closest("#btn-ha-sshsetup") || !ha) return;
  const out = await copySshSetup(ha.device.id, haBody().credential_id);
  if (out) {
    const box = document.getElementById("ha-run");
    box.innerHTML = `<div class="ha-run-head">Paste this into the host's root shell (Proxmox: the guest's Console), then try again:</div><pre class="fixsnmp-diff ha-output"></pre>`;
    box.querySelector(".ha-output").textContent = out;
    show(box);
  }
});

function closeHostActions() {
  clearTimeout(haTimer);
  haSshOffer("");
  ha = null;
  hide(document.getElementById("modal-hostact"));
}

async function loadHostActionRuns() {
  const body = document.getElementById("ha-runs-body");
  if (!body || !haAllowed()) return;
  haLoadCatalogue();
  try {
    const r = await api("/api/host-actions/runs");
    fillTable("ha-runs-body", r.runs.map(x => `
      <tr class="clickable-row" data-ha-run="${Number(x.id)}" data-ha-run-device="${Number(x.device_id)}">
        <td data-sort="${x.started_at}">${escapeHtml(formatTime(x.started_at))}</td>
        <td class="text-cell">${escapeHtml(x.hostname)}</td>
        <td class="text-cell">${escapeHtml(x.name)}${x.choice ? ` <span class="dim">(${escapeHtml(x.choice)})</span>` : ""}</td>
        <td class="dim">${escapeHtml(x.username || "")}</td>
        <td>${haPill(x.status)}</td>
        <td data-sort="${x.finished_at ? x.finished_at - x.started_at : ""}">${x.finished_at ? formatDuration(x.finished_at - x.started_at) : "-"}</td>
      </tr>`).join(""), "No host actions run yet.", 6);
    const pick = document.getElementById("ha-host-pick");
    const hosts = ((autoData && autoData.devices) || []).filter(haEligible);
    pick.innerHTML = `<option value="">Run an action on...</option>` +
      hosts.map(d => `<option value="${Number(d.id)}">${escapeHtml(d.hostname)}</option>`).join("");
  } catch (err) {
    showToast(`Could not load host action runs: ${err.message}`, "error");
  }
}

function initHostActions() {
  document.addEventListener("click", ev => {
    const b = ev.target.closest("[data-ha-device]");
    if (b) {
      ev.preventDefault();
      ev.stopPropagation();
      openHostActions(Number(b.dataset.haDevice), b.dataset.haProblem || "", b.dataset.haMessage || "");
    }
  }, true);
  document.getElementById("btn-close-hostact").addEventListener("click", closeHostActions);
  document.getElementById("btn-ha-back").addEventListener("click", () => {
    clearTimeout(haTimer);
    if (ha.view === "run" || ha.view === "detail") {
      // Refresh the recent runs before going back to the list.
      api(`/api/host-actions?device_id=${ha.device.id}&problem=${encodeURIComponent(ha.problemKey || "")}`)
        .then(v => { if (ha) { ha.runs = v.runs || []; haShowList(); } }).catch(() => haShowList());
    }
  });
  document.getElementById("ha-list").addEventListener("click", ev => {
    const open = ev.target.closest("[data-ha-open]");
    if (open) return haOpen(open.dataset.haOpen, open.dataset.haChoice);
    if (ev.target.closest("#btn-ha-all")) { ha.showAll = true; return haShowList(); }
    const run = ev.target.closest("[data-ha-run]");
    if (run) haWatch(Number(run.dataset.haRun));
  });
  document.getElementById("ha-detail").addEventListener("change", ev => {
    if (ev.target.id === "ha-choice") {
      ha.previewed = null;
      hide(document.getElementById("ha-preview-box"));
      haSyncRun();
    }
  });
  document.getElementById("btn-ha-preview").addEventListener("click", haPreview);
  document.getElementById("btn-ha-run").addEventListener("click", haRun);
  document.getElementById("btn-ha-workflow").addEventListener("click", haWorkflow);
  document.getElementById("btn-ha-hostkey").addEventListener("click", async () => {
    await openHostKeys({ device_ids: [ha.device.id], ssh_port: haBody().ssh_port });
    hide(document.getElementById("ha-hostkey"));
  });
  document.getElementById("btn-ha-addcred").addEventListener("click", () => {
    closeHostActions();
    window.location.hash = "#/automation";
    setTimeout(() => openCredentialModal(null), 300);
  });
  const runs = document.getElementById("ha-runs-body");
  if (runs) runs.addEventListener("click", ev => {
    const row = ev.target.closest("[data-ha-run]");
    if (row) openHostActions(Number(row.dataset.haRunDevice), "", "", Number(row.dataset.haRun));
  });
  const pick = document.getElementById("ha-host-pick");
  if (pick) pick.addEventListener("change", () => {
    const id = parseInt(pick.value, 10);
    pick.value = "";
    if (id) openHostActions(id);
  });
}

document.addEventListener("DOMContentLoaded", initHostActions);
