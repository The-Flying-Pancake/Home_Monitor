/* First-run setup wizard.
 *
 * Opened from the Setup tab it runs in preview mode: every step works (the
 * network scan and the Telegram connection are real), the answers are
 * validated by the server exactly as in a real run, and the last step shows
 * the plan without writing anything. On a fresh install (no setup recorded)
 * the same page opens in place of the dashboard, the rest of the app is out of
 * reach until it is done (the menu is replaced by the wizard's steps), and the
 * last step applies the plan after asking for the administrator's password
 * (and authenticator code with 2FA), every time. The server refuses a second
 * run once setup is complete. Relies on app.js helpers (api, escapeHtml,
 * showToast, show, hide).
 */

const SETUP_STEPS = [
  ["welcome", "Welcome"], ["account", "Account"], ["scan", "Network scan"], ["pick", "Devices"],
  ["services", "Services"], ["config", "Monitoring"], ["ssh", "SSH commands"], ["syncthing", "Syncthing"], ["nfs", "NFS mounts"],
  ["telegram", "Telegram"], ["review", "Review"],
];
const SUBNET_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

let setupState = null;
let setupScanTimer = null;
let setupSvcTimer = null;

function freshSetupState(preview, status) {
  return {
    preview, step: 0, status,
    account: { username: "", password: "", password2: "" },
    scan: { wanted: null, subnets: [status.default_subnet || ""], community: "", job: null, results: [] },
    picked: {},          // ip -> {hostname, profile_id}; profile ping_only for devices without SNMP
    services: { wanted: null, mode: "common", custom: "", job: null, results: [], picked: {} },   // "ip:port" -> {hostname}
    config: { default_snmp_community: "", ...status.defaults },
    ssh: { enabled: null, name: "root", username: "root", cred_type: "password", secret: "" },
    syncthing: { enabled: null, keys_source: "", data_folder: "/mnt/Syncthing/Monitor" },
    nfs: { enabled: null, mounts: [{ source: "", target: "", options: "defaults" }] },
    telegram: { enabled: null, token: "", chat_id: "", chat_name: "", tested: false },
    admin: { password: "", code: "", needsCode: false },
    result: null,
  };
}

/** While setup is not complete the app is the wizard: menu hidden, steps in the sidebar. */
function applySetupLock() {
  const locked = setupCompleted === false;
  document.getElementById("app-shell").classList.toggle("setup-locked", locked);
}

async function openSetup(preview) {
  let status;
  try {
    status = await api("/api/setup/status");
  } catch (err) {
    showToast(`Could not load setup: ${err.message}`, "error");
    return;
  }
  if (!setupState || setupState.preview !== preview) setupState = freshSetupState(preview, status);
  if (!profileOptionsHtml) await loadProfiles();
  applySetupLock();
  renderSetup();
}

function setupPayload() {
  const s = setupState;
  const settings = {};
  for (const [k, v] of Object.entries(s.config)) if (String(v).trim() !== "") settings[k] = String(v).trim();
  return {
    settings,
    site: {
      ssh: s.ssh.enabled ? { enabled: true, credential: { name: s.ssh.name, username: s.ssh.username, cred_type: s.ssh.cred_type, secret: s.ssh.secret } } : { enabled: false },
      syncthing: s.syncthing.enabled ? { enabled: true, keys_source: s.syncthing.keys_source, data_folder: s.syncthing.data_folder } : { enabled: false },
      nfs: s.nfs.enabled ? { enabled: true, mounts: s.nfs.mounts } : { enabled: false },
      telegram: s.telegram.enabled ? { enabled: true, token: s.telegram.token, chat_id: s.telegram.chat_id } : { enabled: false },
    },
    devices: Object.entries(s.picked).map(([ip, d]) => ({ ip_address: ip, hostname: d.hostname, profile_id: d.profile_id }))
      .concat(s.services.wanted ? Object.entries(s.services.picked).map(([key, d]) => ({
        ip_address: key.split(":")[0], service_port: Number(key.split(":")[1]), hostname: d.hostname, profile_id: SERVICE_PROFILE })) : []),
  };
}

/** Monitor as: ping only, or an SNMP template (port checks are the Services step). */
function setupProfileOptions(selected) {
  const snmpOnes = profileOptionsHtml.replace(/<option value="(ping_only|service_check)">[^<]*<\/option>/g, "");
  return `<option value="ping_only">Ping only</option><optgroup label="SNMP template">${snmpOnes}</optgroup>`
    .replace(`value="${selected}"`, `value="${selected}" selected`);
}

function yesNo(key, question, help) {
  const v = key === "scan" ? setupState.scan.wanted : key === "services" ? setupState.services.wanted : setupState[key].enabled;
  return `<div class="setup-question"><div class="setup-q">${escapeHtml(question)}</div>${help ? `<div class="form-help">${help}</div>` : ""}
    <div class="setup-yesno">
      <button type="button" class="btn${v === true ? " btn-primary" : ""}" data-yes="${key}">Yes</button>
      <button type="button" class="btn${v === false ? " btn-primary" : ""}" data-no="${key}">No, skip</button>
    </div></div>`;
}

function field(path, label, value, attrs = "") {
  const type = /type=/.test(attrs) ? "" : 'type="text" ';
  return `<div class="form-group"><label>${escapeHtml(label)}</label><input ${type}data-path="${path}" value="${escapeHtml(value ?? "")}" ${attrs}></div>`;
}

/** A secret field: masked, with a Show button (a password never shows while typed). */
function secretField(path, label, value, extra = "") {
  return `<div class="form-group"><label>${escapeHtml(label)}</label>
    <div class="secret-input"><input type="password" data-path="${path}" value="${escapeHtml(value ?? "")}" autocomplete="new-password" spellcheck="false" ${extra}>
    <button type="button" class="btn btn-small" data-reveal-path="${path}">Show</button></div></div>`;
}

function stepBody(id) {
  const s = setupState;
  switch (id) {
    case "welcome":
      return `<h2>Welcome to Homelab Monitor</h2>
        <p>This sets up monitoring for your network in a few steps: a scan to find your devices, how often to poll them, and optional extras (SSH commands, Syncthing backups, NFS mounts, Telegram messages). Every extra can be skipped and changed later in Settings.</p>
        ${s.preview ? `<div class="setup-preview-note">Preview mode: everything works, including the scan, but nothing is saved. The last step shows what a real first run would do.</div>`
          : `<div class="form-help">The rest of the monitor opens once this is done. You can log out at any time (top right) and carry on later.</div>`}`;
    case "account":
      if (!s.preview) return `<p>Your administrator account is set up: you are logged in as <strong>${escapeHtml(currentUser ? currentUser.username : "")}</strong>.</p>
        <p class="dim">Recommended once setup is done: turn on two-factor authentication in Settings, Account.</p>`;
      return `<p>On a fresh install this step creates the administrator account. In preview the password rules are checked and nothing is created.</p>
        <div class="form-row">${field("account.username", "Username", s.account.username, 'autocomplete="off"')}</div>
        <div class="form-row">${secretField("account.password", "Password (12 or more characters)", s.account.password)}
        ${secretField("account.password2", "Repeat password", s.account.password2)}</div>`;
    case "scan": {
      const job = s.scan.job;
      const progress = job ? `<div class="setup-progress"><div style-width="${job.total ? Math.round(100 * job.done / job.total) : 0}"></div></div>
        <div class="dim">${job.finished ? `Scanned ${job.total} addresses in ${job.seconds} s: ${job.results.length} answered.` : `Scanning ${job.done} / ${job.total}...`}</div>` : "";
      const nets = s.scan.subnets.map((n, i) => `<div class="subnet-row">
          <input type="text" data-subnet="${i}" value="${escapeHtml(n)}" placeholder="192.168.1.0/24" spellcheck="false">
          ${s.scan.subnets.length > 1 ? `<button type="button" class="btn btn-small" data-subnet-del="${i}" title="Remove this subnet" aria-label="Remove">&times;</button>` : ""}
        </div>`).join("");
      return yesNo("scan", "Scan the network for devices?", "Pings every address in the subnets and asks each one over SNMP what it is. Devices without SNMP (phones, TVs, cameras, smart plugs) can be added to ping. Nothing leaves your network.") +
        (s.scan.wanted ? `<div class="form-group"><label>Subnets</label><div class="subnet-list">${nets}</div>
            <button type="button" class="btn btn-small" id="setup-subnet-add">+ Add a subnet</button>
            <div class="form-help">Private ranges only (10.x, 172.16 to 31.x, 192.168.x), up to 1024 addresses in total. Several VLANs? Add each one.</div></div>
          <div class="form-row">${secretField("scan.community", "SNMP community string", s.scan.community, 'placeholder="Leave empty to use the current default"')}</div>
          <button type="button" class="btn btn-primary" id="setup-scan-start"${job && !job.finished ? " disabled" : ""}>${job ? "Scan again" : "Start scan"}</button>${progress}` : "");
    }
    case "pick": {
      const rows = s.scan.results;
      if (!rows.length) return `<p class="dim">${s.scan.wanted ? "The scan found nothing yet. Go back and run it, or continue without adding devices." : "No scan was run. You can add devices later from the Devices page."}</p>`;
      return `<p>Tick the devices to monitor. <strong>Ping only</strong> watches up or down and response time; an <strong>SNMP template</strong> also collects interfaces, CPU, memory and storage. Names and the choice can be changed here and later.</p>
        <div class="setup-pick-bar"><button type="button" class="btn" id="setup-pick-everything">Tick all</button><button type="button" class="btn" id="setup-pick-all">Tick those with SNMP</button><button type="button" class="btn" id="setup-pick-none">Clear</button><span class="dim">${Object.keys(s.picked).length} ticked</span></div>
        <div class="setup-table-wrap"><table class="setup-table"><thead><tr><th></th><th>IP</th><th>Name</th><th>Answers</th><th>Monitor as</th><th>Description</th></tr></thead><tbody>
        ${rows.map(r => {
          const p = s.picked[r.ip];
          return `<tr class="${r.monitored ? "dim" : ""}">
            <td>${r.monitored ? "" : `<input type="checkbox" data-pick="${escapeHtml(r.ip)}"${p ? " checked" : ""}>`}</td>
            <td>${escapeHtml(r.ip)}</td>
            <td>${r.monitored ? `${escapeHtml(r.name || r.dns_name)} <span class="dim">(already monitored)</span>` : `<input type="text" data-pick-name="${escapeHtml(r.ip)}" value="${escapeHtml(p ? p.hostname : (r.name || r.dns_name || r.ip))}">`}</td>
            <td>${r.ping ? "ping" : ""}${r.ping && r.snmp ? ", " : ""}${r.snmp ? "SNMP" : ""}</td>
            <td>${r.monitored ? escapeHtml(r.profile_name) : `<select data-pick-profile="${escapeHtml(r.ip)}">${setupProfileOptions(p ? p.profile_id : r.profile_id)}</select>`}</td>
            <td class="dim setup-descr">${escapeHtml(r.descr)}</td></tr>`;
        }).join("")}</tbody></table></div>`;
    }
    case "services": {
      const sv = s.services;
      const hosts = Object.keys(s.picked);
      if (!hosts.length) return `<p class="dim">No devices are ticked, so there is nothing to look for services on. Port and web checks can be added later from the Devices page (Add, Service).</p>`;
      const job = sv.job;
      const modes = [["common", "Common services"], ["custom", "Choose ports"], ["all", "All 65,535 ports"]].map(([k, l]) =>
        `<button type="button" class="btn${sv.mode === k ? " active" : ""}" data-svc-mode="${k}">${l}</button>`).join("");
      const rows = sv.results.flatMap(r => (r.open_ports || []).map(port => ({ r, port, key: `${r.ip}:${port}` })));
      const progress = job ? `<div class="setup-progress"><div style-width="${job.finished ? 100 : job.total ? Math.round(100 * job.done / job.total) : 0}"></div></div>
        <div class="dim">${escapeHtml(scanStatusTextFor(job, true))}</div>` : "";
      const table = rows.length ? `<div class="setup-pick-bar"><button type="button" class="btn" id="setup-svc-all">Tick all</button><button type="button" class="btn" id="setup-svc-none">Clear</button><span class="dim">${Object.keys(sv.picked).length} ticked</span></div>
        <div class="setup-table-wrap"><table class="setup-table"><thead><tr><th></th><th>Device</th><th>Port</th><th>Name</th></tr></thead><tbody>
        ${rows.map(({ r, port, key }) => {
          const picked = sv.picked[key];
          const dev = (s.picked[r.ip] || {}).hostname || r.ip;
          const known = (r.monitored_ports || []).includes(port);
          return `<tr class="${known ? "dim" : ""}"><td>${known ? "" : `<input type="checkbox" data-svc="${escapeHtml(key)}"${picked ? " checked" : ""}>`}</td>
            <td>${escapeHtml(dev)} <span class="dim">${escapeHtml(r.ip)}</span></td><td>${Number(port)}${PORT_NAMES[port] ? ` <span class="dim">${escapeHtml(PORT_NAMES[port])}</span>` : ""}</td>
            <td>${known ? `<span class="dim">already monitored</span>` : `<input type="text" data-svc-name="${escapeHtml(key)}" value="${escapeHtml(picked ? picked.hostname : `${dev} ${PORT_NAMES[port] || port}`)}">`}</td></tr>`;
        }).join("")}</tbody></table></div>` : job && job.finished ? `<p class="dim">No open ports found on the devices you ticked.</p>` : "";
      return yesNo("services", "Look for services on these devices?", `Tries TCP ports on the ${hosts.length} device${hosts.length === 1 ? "" : "s"} you ticked (web pages, SSH, file shares, media servers). Each open port you tick becomes its own check: up when the port answers.`) +
        (sv.wanted ? `<div class="form-group"><label>Ports to look for</label><div class="seg kind-seg">${modes}</div>
            ${sv.mode === "custom" ? `<input type="text" data-path="services.custom" value="${escapeHtml(sv.custom)}" placeholder="22,80,443,8000-8100" spellcheck="false">` : ""}
            ${sv.mode === "all" ? `<div class="panel-note-bar warn">This takes a while: about a minute per device on a quiet network, longer with firewalls. Open ports appear as they are found, and you can stop and keep what was found.</div>` : ""}</div>
          <button type="button" class="btn btn-primary" id="setup-svc-start"${job && !job.finished ? " disabled" : ""}>${job ? "Look again" : "Look for services"}</button>
          ${job && !job.finished ? `<button type="button" class="btn" id="setup-svc-stop">Stop</button>` : ""}${progress}${table}` : "");
    }
    case "config":
      return `<p>How often devices are checked and how long history is kept. The defaults suit a home network.</p>
        <div class="form-row">${secretField("config.default_snmp_community", "Default SNMP community (for new devices)", s.config.default_snmp_community || s.scan.community, 'placeholder="Leave empty to keep the current one"')}</div>
        <div class="form-row">${field("config.default_poll_interval", "SNMP poll interval (seconds)", s.config.default_poll_interval, 'type="number" min="10"')}
        ${field("config.default_ping_interval", "Ping interval (seconds)", s.config.default_ping_interval, 'type="number" min="5"')}</div>
        <div class="form-row">${field("config.raw_retention_days", "Keep full detail for (days)", s.config.raw_retention_days, 'type="number" min="1"')}
        ${field("config.metric_retention_days", "Keep hourly trends for (days)", s.config.metric_retention_days, 'type="number" min="7"')}</div>`;
    case "ssh":
      return yesNo("ssh", "Allow the monitor to run commands on your hosts over SSH?", "Needed for workflows (restart sequences, updates) and Fix SNMP. Credentials are stored encrypted. You approve each host's SSH key before it is used.") +
        (s.ssh.enabled ? `<div class="form-row">${field("ssh.name", "Credential name", s.ssh.name)}${field("ssh.username", "Username", s.ssh.username, 'autocomplete="off"')}</div>
          <div class="form-group"><label>Type</label><select data-path="ssh.cred_type"><option value="password"${s.ssh.cred_type === "password" ? " selected" : ""}>Password</option><option value="ssh_key"${s.ssh.cred_type === "ssh_key" ? " selected" : ""}>Private key</option></select></div>
          ${s.ssh.cred_type === "ssh_key"
            ? `<div class="form-group"><label>Private key</label><textarea data-path="ssh.secret" class="masked-text" rows="4" spellcheck="false" autocomplete="off">${escapeHtml(s.ssh.secret)}</textarea>
               <button type="button" class="btn btn-small" data-reveal-text="ssh.secret">Show</button></div>`
            : secretField("ssh.secret", "Password", s.ssh.secret)}` : "");
    case "syncthing":
      return yesNo("syncthing", "Back up through Syncthing?", "For people who already run Syncthing. The container restores its Syncthing identity (cert.pem, key.pem, config.xml) from a share, so your main Syncthing server recognises it without being set up again, then syncs the backup folder. Leave this off if you back up another way.") +
        (s.syncthing.enabled ? `${field("syncthing.keys_source", "Where the Syncthing identity is kept (NFS export)", s.syncthing.keys_source, 'placeholder="192.168.1.10:/Share/Backups/SyncThingKeys/Monitor"')}
          ${field("syncthing.data_folder", "Backup folder inside the container (synced by Syncthing)", s.syncthing.data_folder)}` : "");
    case "nfs":
      return yesNo("nfs", "Mount NFS shares in the container?", "For example a NAS folder the backups or Syncthing use. Mounts are created by the container scripts and kept in /etc/fstab; nothing is mounted on this page.") +
        (s.nfs.enabled ? s.nfs.mounts.map((m, i) => `<div class="form-row setup-mount">
            ${field(`nfs.mounts.${i}.source`, "NFS export", m.source, 'placeholder="192.168.1.10:/Share/Folder"')}
            ${field(`nfs.mounts.${i}.target`, "Mount at", m.target, 'placeholder="/mnt/folder"')}
            ${field(`nfs.mounts.${i}.options`, "Options", m.options)}
            ${s.nfs.mounts.length > 1 ? `<button type="button" class="btn btn-danger" data-mount-del="${i}" title="Remove">&times;</button>` : ""}
          </div>`).join("") + `<button type="button" class="btn" id="setup-mount-add">Add another mount</button>` : "");
    case "telegram": {
      const t = s.telegram;
      return yesNo("telegram", "Send notifications to Telegram?", "Messages when a device goes offline, a problem opens, a watched service stops or a workflow finishes. This is the monitor's only internet connection (api.telegram.org). Which events and the message text are set later in Settings.") +
        (t.enabled ? `<ol class="setup-steps-list">
            <li>In Telegram, open a chat with <strong>@BotFather</strong> and send <code>/newbot</code>. Give it a name and a username ending in "bot".</li>
            <li>BotFather replies with a token like <code>123456789:AA...</code>. Paste it below.</li>
            <li>Open your new bot in Telegram and press <strong>Start</strong> (or send it any message).</li>
            <li>Press <strong>Find my chat</strong>, then <strong>Send test message</strong>.</li>
          </ol>
          ${secretField("telegram.token", "Bot token", t.token)}
          <div class="setup-yesno"><button type="button" class="btn" id="setup-tg-find">Find my chat</button>
          ${t.chat_id ? `<button type="button" class="btn" id="setup-tg-test">Send test message</button>` : ""}
          <span class="dim" id="setup-tg-status">${t.chat_id ? `Chat: ${escapeHtml(t.chat_name || t.chat_id)}${t.tested ? ", test sent" : ""}` : ""}</span></div>` : "");
    }
    case "review":
      return reviewBody();
    default:
      return "";
  }
}

/** The review: one card per area with what will happen, then the exact steps (collapsed). */
function reviewBody() {
  const s = setupState;
  const r = s.result;
  const devices = Object.values(s.picked);
  const services = s.services.wanted ? Object.values(s.services.picked) : [];
  const card = (on, icon, title, lines) => `<div class="review-card${on ? "" : " off"}">
      <div class="review-head"><span class="review-icon" aria-hidden="true">${on ? "✓" : "–"}</span><span class="review-emoji" aria-hidden="true">${icon}</span><strong>${escapeHtml(title)}</strong></div>
      <ul>${lines.map(l => `<li>${escapeHtml(l)}</li>`).join("")}</ul></div>`;
  const names = devices.slice(0, 6).map(d => d.hostname).join(", ") + (devices.length > 6 ? ` and ${devices.length - 6} more` : "");
  const cards = [
    card(true, "👤", "Account", [s.preview ? `Administrator ${s.account.username || "(not chosen)"}` : `Administrator ${currentUser ? currentUser.username : ""} (logged in)`]),
    card(devices.length > 0, "🖧", `Devices (${devices.length})`, devices.length ? [names,
      `${devices.filter(d => d.profile_id === "ping_only").length} ping only, ${devices.filter(d => d.profile_id !== "ping_only").length} with SNMP`] : ["None: add them later on the Devices page"]),
    card(services.length > 0, "🔌", `Services (${services.length})`, services.length
      ? [services.slice(0, 6).map(x => x.hostname).join(", ") + (services.length > 6 ? ` and ${services.length - 6} more` : "")] : ["None: add them later (Add, Service)"]),
    card(true, "⏱", "Monitoring", [`SNMP every ${s.config.default_poll_interval || "?"} s, ping every ${s.config.default_ping_interval || "?"} s`,
      `Full detail kept ${s.config.raw_retention_days || "?"} days, trends ${s.config.metric_retention_days || "?"} days`,
      s.config.default_snmp_community || s.scan.community ? "New SNMP community stored encrypted" : "SNMP community unchanged"]),
    card(!!s.ssh.enabled, "🔑", "SSH commands", s.ssh.enabled ? [`Credential ${s.ssh.name} for ${s.ssh.username} (${s.ssh.cred_type === "ssh_key" ? "private key" : "password"}), encrypted`] : ["Skipped"]),
    card(!!s.syncthing.enabled, "🔄", "Syncthing backups", s.syncthing.enabled ? [`Identity from ${s.syncthing.keys_source}`, `Backups in ${s.syncthing.data_folder}`] : ["Skipped"]),
    card(!!s.nfs.enabled, "🗄", "NFS mounts", s.nfs.enabled ? s.nfs.mounts.map(m => `${m.source} at ${m.target}`) : ["Skipped"]),
    card(!!s.telegram.enabled, "💬", "Telegram", s.telegram.enabled ? [`Messages to ${s.telegram.chat_name || s.telegram.chat_id}`] : ["Skipped"]),
  ].join("");
  const plan = r ? `<details class="review-plan"><summary>Exact steps (${r.plan.length})</summary>
      <ol>${r.plan.map(l => `<li>${escapeHtml(l)}</li>`).join("")}</ol></details>
      ${r.devices.skipped.length ? `<div class="dim">Skipped: ${r.devices.skipped.map(x => escapeHtml(`${x.ip_address} (${x.reason})`)).join(", ")}</div>` : ""}` : `<div class="dim">Checking your answers...</div>`;
  const confirm = s.preview || !r ? "" : `<div class="review-confirm">
      <div class="setup-q">Confirm it is you</div>
      <div class="form-help">Setup stores credentials and changes the whole install, so it needs your password${s.admin.needsCode ? " and authenticator code" : ""} now, every time.</div>
      <div class="form-row">${secretField("admin.password", "Your password", s.admin.password, 'autocomplete="current-password"')}
      ${s.admin.needsCode ? field("admin.code", "Authenticator code", s.admin.code, 'inputmode="numeric" maxlength="10" autocomplete="one-time-code"') : ""}</div></div>`;
  return `<p>${s.preview ? "What a real first run would do with these answers. Nothing has been saved." : "Check everything, then press Apply setup."}</p>
    <div class="review-grid">${cards}</div>${plan}${confirm}
    <div class="setup-error hidden" id="setup-error"></div>`;
}

function renderSetup() {
  const s = setupState;
  const [id] = SETUP_STEPS[s.step];
  const last = s.step === SETUP_STEPS.length - 1;
  const steps = SETUP_STEPS.map(([k, label], i) =>
    `<li class="${i === s.step ? "current" : i < s.step ? "done" : ""}">${escapeHtml(label)}</li>`).join("");
  document.getElementById("setup-steps").innerHTML = steps;
  document.getElementById("setup-side-steps").innerHTML = steps;
  document.getElementById("setup-body").innerHTML = stepBody(id);
  document.getElementById("setup-mode").textContent = s.preview ? "Preview: nothing is saved" : "First-run setup";
  if (typeof setPageTitle === "function") setPageTitle("Setup");
  document.getElementById("setup-back").classList.toggle("hidden", s.step === 0);
  const next = document.getElementById("setup-next");
  next.textContent = last ? (s.preview ? "Finish preview" : "Apply setup") : s.step === 0 ? "Start" : "Next";
  next.classList.toggle("hidden", last && !s.result);
  document.getElementById("setup-restart").classList.toggle("hidden", !s.preview || s.step === 0);
  document.querySelectorAll("#setup-body [style-width]").forEach(el => { el.style.width = `${el.getAttribute("style-width")}%`; });
  if (id === "review" && !s.result) runPreview();
}

function setPath(path, value) {
  const parts = path.split(".");
  let o = setupState;
  for (const p of parts.slice(0, -1)) o = o[p];
  o[parts[parts.length - 1]] = value;
}

function subnetProblem(n) {
  const m = SUBNET_RE.exec(n.trim());
  if (!m) return `"${n}" is not a subnet like 192.168.1.0/24`;
  const o = m.slice(1, 5).map(Number);
  if (o.some(x => x > 255) || +m[5] > 32) return `"${n}" is not a valid subnet`;
  const priv = o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168);
  if (!priv) return `${n} is not a private range`;
  return "";
}

function stepProblem(id) {
  const s = setupState;
  if (id === "account" && s.preview) {
    if (!/^[A-Za-z0-9._-]{1,32}$/.test(s.account.username)) return "Username: 1 to 32 letters, digits, dot, dash or underscore.";
    if (s.account.password.length < 12) return "Password: at least 12 characters.";
    if (s.account.password !== s.account.password2) return "The passwords do not match.";
  }
  if (["scan", "ssh", "syncthing", "nfs", "telegram"].includes(id) && (id === "scan" ? s.scan.wanted : s[id].enabled) === null) return "Choose Yes or No, skip.";
  if (id === "services" && Object.keys(s.picked).length && s.services.wanted === null) return "Choose Yes or No, skip.";
  if (id === "services" && s.services.job && !s.services.job.finished) return "Wait for the search to finish, or stop it.";
  if (id === "scan" && s.scan.wanted && s.scan.job && !s.scan.job.finished) return "Wait for the scan to finish.";
  if (id === "telegram" && s.telegram.enabled && !s.telegram.chat_id) return "Find your chat first, or choose No.";
  return "";
}

async function runPreview() {
  const s = setupState;
  try {
    s.result = await api("/api/setup/preview", { method: "POST", body: setupPayload() });
    if (!s.preview) {
      try { s.admin.needsCode = (await api("/api/auth/2fa")).enabled; } catch (err) { s.admin.needsCode = false; }
    }
  } catch (err) {
    s.result = null;
    document.getElementById("setup-body").innerHTML = `<p class="text-err">${escapeHtml(err.message)}</p><p class="dim">Go back to the step it names and correct it.</p>`;
    return;
  }
  renderSetup();
}

/** The services step's search: open ports on the devices ticked in the Devices step. */
async function startServiceScan() {
  const sv = setupState.services;
  const ports = sv.mode === "custom" ? sv.custom.trim() : sv.mode;
  if (!ports) { showToast("Enter the ports to look for, for example 80,443,8000-8100", "error"); return; }
  try {
    const r = await api("/api/setup/scan", { method: "POST", body: { hosts: Object.keys(setupState.picked), ports } });
    sv.job = { id: r.id, total: r.total, done: 0, finished: false, results: [], phase: "ports" };
    sv.results = [];
    renderSetup();
    pollServiceScan();
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function pollServiceScan() {
  clearTimeout(setupSvcTimer);
  const sv = setupState.services;
  try {
    const job = await api(`/api/setup/scan/${sv.job.id}`);
    sv.job = job;
    sv.results = job.results;
    if (!job.finished) setupSvcTimer = setTimeout(pollServiceScan, 1000);
  } catch (err) {
    showToast(`Search: ${err.message}`, "error");
  }
  if (SETUP_STEPS[setupState.step][0] === "services") renderSetup();
}

/** Progress text of a port search (shared wording with the Add window). */
function scanStatusTextFor(v, service) {
  const found = service ? `${v.results.reduce((a, r) => a + (r.open_ports || []).length, 0)} open ports` : `${v.results.length} found`;
  if (v.finished) return `${v.stopped ? "Stopped" : "Done"} after ${formatDuration(v.seconds || 0)}: ${found}`;
  if (v.phase === "live") return `Finding the hosts that are up... ${found}`;
  const eta = isNum(v.eta_seconds) && v.eta_seconds > 5 ? `, about ${formatDuration(v.eta_seconds)} left` : "";
  return `${(v.done || 0).toLocaleString()} of ${(v.total || 0).toLocaleString()} connections tried, ${found}${eta}`;
}

async function pollScan() {
  clearTimeout(setupScanTimer);
  const s = setupState;
  try {
    const job = await api(`/api/setup/scan/${s.scan.job.id}`);
    s.scan.job = job;
    s.scan.results = job.results;
    if (job.finished) {
      // Pre-tick new devices that answered SNMP; the others are a click away (Tick all) as ping only.
      for (const r of job.results) if (!r.monitored && r.snmp && !s.picked[r.ip]) s.picked[r.ip] = { hostname: r.name || r.dns_name || r.ip, profile_id: r.profile_id };
    } else {
      setupScanTimer = setTimeout(pollScan, 1000);
    }
  } catch (err) {
    showToast(`Scan: ${err.message}`, "error");
  }
  if (SETUP_STEPS[s.step][0] === "scan") renderSetup();
}

function initSetup() {
  const body = document.getElementById("setup-body");
  body.addEventListener("input", (ev) => {
    const el = ev.target;
    if (el.dataset.path) {
      setPath(el.dataset.path, el.value);
      if (el.dataset.path.startsWith("telegram.token")) { setupState.telegram.chat_id = ""; setupState.telegram.tested = false; }
    } else if (el.dataset.subnet !== undefined) {
      setupState.scan.subnets[+el.dataset.subnet] = el.value;
    } else if (el.dataset.pickName && setupState.picked[el.dataset.pickName]) {
      setupState.picked[el.dataset.pickName].hostname = el.value;
    } else if (el.dataset.svcName && setupState.services.picked[el.dataset.svcName]) {
      setupState.services.picked[el.dataset.svcName].hostname = el.value;
    }
  });
  body.addEventListener("change", (ev) => {
    const el = ev.target;
    if (el.dataset.svc) {
      const sv = setupState.services;
      if (el.checked) {
        const name = body.querySelector(`[data-svc-name="${CSS.escape(el.dataset.svc)}"]`);
        sv.picked[el.dataset.svc] = { hostname: name ? name.value : el.dataset.svc };
      } else {
        delete sv.picked[el.dataset.svc];
      }
      renderSetup();
      return;
    }
    const r = setupState.scan.results.find(x => x.ip === (el.dataset.pick || el.dataset.pickProfile));
    if (el.dataset.pick) {
      if (el.checked) {
        const nameInput = body.querySelector(`[data-pick-name="${CSS.escape(r.ip)}"]`);
        const prof = body.querySelector(`[data-pick-profile="${CSS.escape(r.ip)}"]`);
        setupState.picked[r.ip] = { hostname: nameInput ? nameInput.value : r.ip, profile_id: prof ? prof.value : r.profile_id };
      } else {
        delete setupState.picked[r.ip];
      }
      renderSetup();
    } else if (el.dataset.pickProfile && setupState.picked[r.ip]) {
      setupState.picked[r.ip].profile_id = el.value;
    } else if (el.dataset.path === "ssh.cred_type") {
      setPath("ssh.cred_type", el.value);
      setupState.ssh.secret = "";
      renderSetup();
    }
  });
  body.addEventListener("click", async (ev) => {
    const b = ev.target.closest("button");
    if (!b) return;
    const s = setupState;
    if (b.dataset.revealPath) {
      const input = body.querySelector(`input[data-path="${CSS.escape(b.dataset.revealPath)}"]`);
      input.type = input.type === "password" ? "text" : "password";
      b.textContent = input.type === "password" ? "Show" : "Hide";
    } else if (b.dataset.revealText) {
      const ta = body.querySelector(`textarea[data-path="${CSS.escape(b.dataset.revealText)}"]`);
      ta.classList.toggle("masked-text");
      b.textContent = ta.classList.contains("masked-text") ? "Show" : "Hide";
    } else if (b.dataset.yes || b.dataset.no) {
      const key = b.dataset.yes || b.dataset.no;
      if (key === "scan") s.scan.wanted = !!b.dataset.yes;
      else if (key === "services") s.services.wanted = !!b.dataset.yes;
      else s[key].enabled = !!b.dataset.yes;
      renderSetup();
    } else if (b.id === "setup-subnet-add") {
      s.scan.subnets.push("");
      renderSetup();
      const inputs = body.querySelectorAll("[data-subnet]");
      inputs[inputs.length - 1].focus();
    } else if (b.dataset.subnetDel !== undefined) {
      s.scan.subnets.splice(+b.dataset.subnetDel, 1);
      renderSetup();
    } else if (b.id === "setup-scan-start") {
      const subnets = [...new Set(s.scan.subnets.map(n => n.trim()).filter(Boolean))];
      const problem = subnets.length ? subnets.map(subnetProblem).find(Boolean) : "Enter at least one subnet.";
      if (problem) { showToast(problem, "error"); return; }
      try {
        const r = await api("/api/setup/scan", { method: "POST", body: { subnets, community: s.scan.community } });
        s.scan.job = { id: r.id, total: r.total, done: 0, finished: false, results: [] };
        renderSetup();
        pollScan();
      } catch (err) {
        showToast(err.message, "error");
      }
    } else if (b.id === "setup-pick-everything") {
      // Everything new: SNMP devices with their template, the rest as ping only.
      for (const r of s.scan.results) if (!r.monitored && !s.picked[r.ip]) s.picked[r.ip] = { hostname: r.name || r.dns_name || r.ip, profile_id: r.snmp ? r.profile_id : "ping_only" };
      renderSetup();
    } else if (b.dataset.svcMode) {
      s.services.mode = b.dataset.svcMode;
      renderSetup();
    } else if (b.id === "setup-svc-start") {
      if (s.services.mode === "all" && !(await confirmDialog({ title: "Look on all 65,535 ports?",
        message: "Every port of every ticked device is tried. This can take a long time; open ports appear as they are found and Stop keeps them.",
        confirmLabel: "Start" }))) return;
      startServiceScan();
    } else if (b.id === "setup-svc-stop") {
      try { await api(`/api/setup/scan/${s.services.job.id}`, { method: "DELETE" }); } catch (err) { showToast(err.message, "error"); }
    } else if (b.id === "setup-svc-all") {
      for (const r of s.services.results) for (const port of r.open_ports || []) {
        const key = `${r.ip}:${port}`;
        if (!(r.monitored_ports || []).includes(port) && !s.services.picked[key]) {
          s.services.picked[key] = { hostname: `${(s.picked[r.ip] || {}).hostname || r.ip} ${PORT_NAMES[port] || port}` };
        }
      }
      renderSetup();
    } else if (b.id === "setup-svc-none") {
      s.services.picked = {};
      renderSetup();
    } else if (b.id === "setup-pick-all") {
      for (const r of s.scan.results) if (!r.monitored && r.snmp && !s.picked[r.ip]) s.picked[r.ip] = { hostname: r.name || r.dns_name || r.ip, profile_id: r.profile_id };
      renderSetup();
    } else if (b.id === "setup-pick-none") {
      s.picked = {};
      renderSetup();
    } else if (b.id === "setup-mount-add") {
      s.nfs.mounts.push({ source: "", target: "", options: "defaults" });
      renderSetup();
    } else if (b.dataset.mountDel) {
      s.nfs.mounts.splice(+b.dataset.mountDel, 1);
      renderSetup();
    } else if (b.id === "setup-tg-find" || b.id === "setup-tg-test") {
      const status = document.getElementById("setup-tg-status");
      b.disabled = true;
      try {
        if (b.id === "setup-tg-find") {
          const r = await api("/api/notify/find-chat", { method: "POST", body: { token: s.telegram.token } });
          if (r.searching) {
            status.textContent = `Now send any message to @${r.bot} in Telegram, then press Find my chat again (within ${Math.round(r.seconds / 60)} minutes).`;
            b.disabled = false;
            return;
          }
          if (!(await confirmDialog({ title: "Use this chat?", message: `@${r.bot} got a message from "${r.chat_name || "a chat without a name"}". ` +
            "Alerts and password reset codes will go to this chat. Use it only if this is you.", detail: `Chat ID ${r.chat_id}`,
            confirmLabel: "Use this chat" }))) {
            status.textContent = "Not used. Press Find my chat to search again.";
            b.disabled = false;
            return;
          }
          s.telegram.chat_id = r.chat_id;
          s.telegram.chat_name = `${r.chat_name || r.chat_id} via @${r.bot}`;
        } else {
          await api("/api/notify/test", { method: "POST", body: { token: s.telegram.token, chat_id: s.telegram.chat_id } });
          s.telegram.tested = true;
        }
        renderSetup();
      } catch (err) {
        status.textContent = err.message;
        b.disabled = false;
      }
    }
  });
  document.getElementById("setup-back").addEventListener("click", () => {
    setupState.step = Math.max(0, setupState.step - 1);
    setupState.result = null;
    renderSetup();
  });
  document.getElementById("setup-restart").addEventListener("click", async () => {
    setupState = null;
    await openSetup(true);
  });
  document.getElementById("setup-next").addEventListener("click", async () => {
    const s = setupState;
    const [id] = SETUP_STEPS[s.step];
    const problem = stepProblem(id);
    if (problem) {
      showToast(problem, "error");
      return;
    }
    if (id !== "review") {
      // The community used for the scan is the obvious default for the devices it found.
      if (id === "scan" && !s.config.default_snmp_community && s.scan.community) s.config.default_snmp_community = s.scan.community;
      s.step += 1;
      s.result = null;
      renderSetup();
      return;
    }
    if (s.preview) {
      showToast("Preview finished. Nothing was saved.", "success");
      return;
    }
    const box = document.getElementById("setup-error");
    if (!s.admin.password) {
      box.textContent = "Enter your password to apply the setup.";
      show(box);
      return;
    }
    const next = document.getElementById("setup-next");
    next.disabled = true;
    try {
      const r = await api("/api/setup/apply", { method: "POST",
        body: { ...setupPayload(), admin_password: s.admin.password, admin_code: s.admin.code } });
      s.admin.password = s.admin.code = "";
      showToast(`Setup complete: ${r.devices.added.length} device${r.devices.added.length === 1 ? "" : "s"} added.`, "success");
      await refreshSetupNav();
      setupState = null;
      window.location.hash = "#/devices";
    } catch (err) {
      box.textContent = err.message;
      show(box);
    } finally {
      next.disabled = false;
    }
  });
}

/** A fresh install opens setup on start and nothing else until it is applied; afterwards it is gone. */
async function refreshSetupNav() {
  try {
    const st = await api("/api/setup/status");
    setupCompleted = st.completed;
    applySetupLock();
    return st;
  } catch (err) {
    return null;
  }
}
