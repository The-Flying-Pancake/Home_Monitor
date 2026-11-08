/**
 * Page chrome: left menu, top bar (page title, notifications, theme, user menu), back to top,
 * permission-aware hiding and the unsaved-changes guard used when leaving a page.
 */

const THEME_STORE = "monitor.theme.v1";
const SIDEBAR_STORE = "monitor.sidebar.v1";
let currentUser = null;
let bellData = { items: [], read_at: 0, unread: 0 };
let bellTimer = null;

// Pages that hold unsaved edits register a check here: (targetHash) => what would be lost, or "".
// targetHash is null when the page itself is closing or reloading.
const unsavedGuards = [];
let guardHash = window.location.hash;
let guardBusy = false;

function registerUnsavedGuard(fn) { unsavedGuards.push(fn); }

/**
 * The one hashchange handler (bound in app.js). With unsaved edits it puts the old address back,
 * asks in-app, and routes only if the user chooses to leave. Listener order cannot be relied on
 * for this, so routing always goes through here.
 */
async function routeGuarded() {
  if (guardBusy) return;
  const target = window.location.hash;
  const pending = unsavedSummary(target);
  if (!pending.length) { guardHash = target; handleRouting(); return; }
  guardBusy = true;
  history.replaceState(null, "", guardHash || "#/dashboard");
  const go = await confirmLeave(target);
  if (go) {
    window.dispatchEvent(new Event("discardunsaved"));
    guardHash = target;
    history.replaceState(null, "", target);
    handleRouting();
  }
  guardBusy = false;
}

function unsavedSummary(target = null) {
  return unsavedGuards.map(fn => { try { return fn(target) || ""; } catch (e) { return ""; } }).filter(Boolean);
}

/** Asks before leaving with unsaved changes. Resolves true when it is fine to go. */
async function confirmLeave(target = null) {
  const pending = unsavedSummary(target);
  if (!pending.length) return true;
  return confirmDialog({
    title: "Leave without saving?",
    message: `You have unsaved changes:\n${pending.map(p => "- " + p).join("\n")}\n\nThey are lost if you leave this page.`,
    confirmLabel: "Leave without saving", cancelLabel: "Stay on this page", danger: true, arm: false,
  });
}

function storeGet(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }
function storeSet(key, value) { try { localStorage.setItem(key, value); } catch (e) { /* storage blocked */ } }

// --- Theme ---

function effectiveTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === "light" || set === "dark") return set;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function syncThemeButton() {
  const theme = effectiveTheme();
  // The icons follow data-theme; set it explicitly so the system choice shows the right one too.
  document.documentElement.dataset.theme = theme;
  const btn = document.getElementById("btn-theme");
  btn.title = theme === "light" ? "Switch to dark mode" : "Switch to light mode";
}

function toggleTheme() {
  const next = effectiveTheme() === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  storeSet(THEME_STORE, next);
  syncThemeButton();
  // Charts read colours from CSS, but cached SVGs keep old computed fills: redraw what is open.
  window.dispatchEvent(new Event("themechange"));
}

// --- Menu and page title ---

const PAGE_TITLES = {
  "nav-dashboard": "Dashboard", "nav-devices": "Devices", "nav-map": "Network map", "nav-inventory": "Inventory", "nav-wifi": "Wi-Fi", "nav-pihole": "Pi-hole", "nav-events": "Event log", "nav-automation": "Automation",
  "nav-settings": "Settings", "nav-audit": "Audit log",
  "nav-availability": "Availability", "nav-proxmox": "Proxmox", "nav-guide": "Guide",
};

function setPageTitle(text) {
  document.getElementById("topbar-title").textContent = text || "";
  document.title = text ? `${text} - Network Monitor` : "Network Monitor & Automation";
}

function titleForHash(hash) {
  if (hash.startsWith("#/device/")) return lastDetail && lastDetail.device ? lastDetail.device.hostname : "Device";
  if (hash.startsWith("#/events")) return "Event log";
  if (hash === "#/setup") return "Setup";
  const active = document.querySelector(".side-nav a.active");
  return active ? PAGE_TITLES[active.id] || "" : "";
}

/** Phones: the menu is a drawer over the page, opened from the top bar's menu button. */
function setMenuOpen(open) {
  document.getElementById("app-shell").classList.toggle("menu-open", open);
  const btn = document.getElementById("btn-menu");
  btn.setAttribute("aria-expanded", open ? "true" : "false");
  btn.setAttribute("aria-label", open ? "Close the menu" : "Open the menu");
}

function setSidebarCollapsed(collapsed) {
  const shell = document.getElementById("app-shell");
  shell.classList.toggle("collapsed", collapsed);
  const btn = document.getElementById("btn-sidebar-collapse");
  btn.title = collapsed ? "Expand the menu" : "Collapse the menu";
  btn.setAttribute("aria-label", btn.title);
  storeSet(SIDEBAR_STORE, collapsed ? "collapsed" : "open");
}

// --- Current user and permissions ---

const ALL_PERMISSIONS = ["devices.poll", "problems.ack", "devices.manage", "map.edit", "dashboard.edit", "automation.run",
  "automation.edit", "credentials.manage", "settings.alerts", "settings.notifications", "settings.system", "audit.view",
  "users.manage"];

function can(perm) {
  if (!currentUser) return true;
  return currentUser.permissions.includes(perm);
}

/** Elements marked data-perm="a b" hide unless the user has all of those permissions (body classes, see style.css). */
function applyCurrentUser(user) {
  currentUser = user;
  for (const p of ALL_PERMISSIONS) document.body.classList.toggle("lacks-" + p.replace(".", "-"), !user.permissions.includes(p));
  document.getElementById("header-username").textContent = user.username;
  document.getElementById("header-avatar").textContent = user.username.slice(0, 2);
  document.getElementById("header-role").textContent = `${user.role_label}${user.scoped ? ", some devices only" : ""}`;
  refreshBell();
  if (typeof showChanges === "function") showChanges();
  if (typeof refreshFeatures === "function") refreshFeatures();
  if (typeof refreshUpdateBadge === "function") refreshUpdateBadge();
  if (typeof loadTaxonomy === "function") loadTaxonomy();
}

// --- Notification centre ---

const BELL_LINK = e => e.device_id ? `#/device/${e.device_id}${e.event_type === "problem" ? "" : "/events"}` : "#/events";

function bellSeverity(e) {
  if (e.event_type === "problem" && /^Resolved:/.test(e.message)) return "ok";
  return e.severity;
}

function renderBell() {
  const count = document.getElementById("bell-count");
  const n = bellData.unread;
  count.textContent = n > 99 ? "99+" : String(n);
  count.classList.toggle("hidden", !n);
  document.getElementById("btn-bell").setAttribute("aria-label", n ? `Notifications, ${n} unread` : "Notifications");
  document.getElementById("btn-bell-read").classList.toggle("hidden", !n);
  const list = document.getElementById("bell-list");
  if (!bellData.items.length) {
    list.innerHTML = `<div class="bell-empty">Nothing yet. Problems, recoveries, workflow results and actions that could not be done show here.</div>`;
    return;
  }
  list.innerHTML = bellData.items.map(e => {
    const where = e.hostname ? escapeHtml(e.hostname) : e.actor ? `You (${escapeHtml(e.actor)})` : "System";
    return `<a class="bell-item ${e.timestamp > bellData.read_at ? "unread" : ""}" href="${BELL_LINK(e)}">
      <span class="bell-dot sev-${escapeHtml(bellSeverity(e))}"></span>
      <span class="bell-text"><strong>${where}</strong> ${escapeHtml(e.message)}
        <div class="bell-meta">${escapeHtml(formatAgo(e.timestamp))}, ${escapeHtml(e.event_type === "action" ? "could not be done" : e.event_type)}</div></span>
    </a>`;
  }).join("");
}

async function refreshBell() {
  if (!currentUser) return;
  try {
    bellData = await api("/api/notifications");
    renderBell();
  } catch (e) { /* offline or logged out: keep the last list */ }
}

async function markBellRead() {
  const newest = bellData.items.length ? bellData.items[0].timestamp : Math.floor(Date.now() / 1000);
  try {
    const r = await api("/api/notifications/read", { method: "POST", body: { upto: newest } });
    bellData.read_at = r.read_at;
    bellData.unread = 0;
    renderBell();
  } catch (e) { showToast(`Could not mark as read: ${e.message}`, "error"); }
}

function setPopup(btnId, panelId, open) {
  const btn = document.getElementById(btnId);
  const panel = document.getElementById(panelId);
  panel.classList.toggle("hidden", !open);
  btn.setAttribute("aria-expanded", String(open));
}

// --- Back to top ---

function updateToTop() {
  // Hidden while the dashboard is being edited: it would sit over the last tile's resize corner.
  const editing = typeof dashEditing !== "undefined" && dashEditing && !document.getElementById("view-dashboard").classList.contains("hidden");
  document.getElementById("btn-to-top").classList.toggle("hidden", window.scrollY < 400 || editing);
}

// Collapsible panels: a header marked data-collapse="<name>" folds its panel; remembered per browser.
const COLLAPSE_STORE = "monitor.collapsed.v1";

function collapsedSet() {
  try { return new Set(JSON.parse(storeGet(COLLAPSE_STORE) || "[]")); } catch (e) { return new Set(); }
}

function applyCollapsed(root = document) {
  const shut = collapsedSet();
  root.querySelectorAll("[data-collapse]").forEach(h => {
    const panel = h.closest(".panel");
    if (!panel) return;
    panel.classList.toggle("collapsed", shut.has(h.dataset.collapse));
    h.setAttribute("aria-expanded", String(!shut.has(h.dataset.collapse)));
  });
}

function toggleCollapse(h) {
  const shut = collapsedSet();
  const name = h.dataset.collapse;
  if (shut.has(name)) shut.delete(name); else shut.add(name);
  storeSet(COLLAPSE_STORE, JSON.stringify([...shut]));
  applyCollapsed();
}

function initShell() {
  applyCollapsed();
  document.addEventListener("click", ev => {
    const h = ev.target.closest("[data-collapse]");
    if (h && !ev.target.closest("button, a, input, select")) toggleCollapse(h);
  });
  document.addEventListener("keydown", ev => {
    const h = ev.target.closest && ev.target.closest("[data-collapse]");
    if (h && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); toggleCollapse(h); }
  });
  setSidebarCollapsed(storeGet(SIDEBAR_STORE) === "collapsed");
  document.documentElement.classList.remove("sidebar-collapsed");
  document.getElementById("btn-sidebar-collapse").addEventListener("click",
    () => setSidebarCollapsed(!document.getElementById("app-shell").classList.contains("collapsed")));
  document.getElementById("btn-menu").addEventListener("click",
    () => setMenuOpen(!document.getElementById("app-shell").classList.contains("menu-open")));
  document.getElementById("sidebar-scrim").addEventListener("click", () => setMenuOpen(false));
  // Choosing a page closes the drawer; Settings and Back keep it open, to show the other menu.
  document.getElementById("sidebar").addEventListener("click", ev => {
    const a = ev.target.closest("a[href]");
    if (a && a.id !== "nav-settings" && a.id !== "settings-back") setMenuOpen(false);
  });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") setMenuOpen(false); });

  if (!storeGet(THEME_STORE)) delete document.documentElement.dataset.theme;
  syncThemeButton();
  document.getElementById("btn-theme").addEventListener("click", toggleTheme);
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
      if (storeGet(THEME_STORE)) return;
      delete document.documentElement.dataset.theme;
      syncThemeButton();
      window.dispatchEvent(new Event("themechange"));
    });
  }

  document.getElementById("btn-bell").addEventListener("click", ev => {
    ev.stopPropagation();
    const open = document.getElementById("bell-panel").classList.contains("hidden");
    setPopup("btn-user", "user-menu", false);
    setPopup("btn-bell", "bell-panel", open);
    if (open) refreshBell();
  });
  document.getElementById("btn-bell-read").addEventListener("click", ev => { ev.stopPropagation(); markBellRead(); });
  document.getElementById("bell-list").addEventListener("click", () => setPopup("btn-bell", "bell-panel", false));
  document.getElementById("bell-all").addEventListener("click", () => setPopup("btn-bell", "bell-panel", false));
  document.getElementById("btn-user").addEventListener("click", ev => {
    ev.stopPropagation();
    const open = document.getElementById("user-menu").classList.contains("hidden");
    setPopup("btn-bell", "bell-panel", false);
    setPopup("btn-user", "user-menu", open);
  });
  document.getElementById("user-menu").addEventListener("click", () => setPopup("btn-user", "user-menu", false));
  document.addEventListener("click", ev => {
    if (!ev.target.closest(".bell-wrap")) setPopup("btn-bell", "bell-panel", false);
    if (!ev.target.closest(".user-wrap")) setPopup("btn-user", "user-menu", false);
  });
  document.addEventListener("keydown", ev => {
    if (ev.key !== "Escape") return;
    setPopup("btn-bell", "bell-panel", false);
    setPopup("btn-user", "user-menu", false);
  });
  bellTimer = setInterval(refreshBell, 30000);

  window.addEventListener("scroll", updateToTop, { passive: true });
  document.getElementById("btn-to-top").addEventListener("click", () => {
    const smooth = !(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    window.scrollTo({ top: 0, behavior: smooth ? "smooth" : "auto" });
  });

  // Unsaved changes: routeGuarded asks in-app when the hash changes; reload or close gets the
  // browser's own question (browsers do not allow a page-drawn dialog there).
  window.addEventListener("beforeunload", ev => {
    if (unsavedSummary().length) { ev.preventDefault(); ev.returnValue = ""; }
  });
}

document.addEventListener("DOMContentLoaded", initShell);
