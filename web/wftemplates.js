/* Workflow templates: commands for a Run command step, and whole workflows added to the canvas.
 *
 * Command templates: suits lists the device templates (profile_id) a command is meant for, and
 * hostname optionally matches host names (Proxmox hosts use the generic Linux profile). The picker
 * lists templates that suit every chosen host first. Add a template by adding an entry here.
 *
 * Every Linux command runs non-interactively over SSH as the credential's user (root here; for
 * another user put sudo -n in front of apt-get and systemctl). Notes on the update commands:
 *   apt-get, not apt: apt's command line is not stable for scripts and warns when it has no terminal.
 *   DEBIAN_FRONTEND=noninteractive plus --force-confdef / --force-confold: a package that asks about
 *     a changed config file keeps the current file instead of waiting for an answer that never comes.
 *   dpkg --configure -a first: finishes an upgrade that was interrupted, which otherwise blocks apt.
 *   The restart is handed to systemd 5 s later (systemd-run --on-active), so the command itself exits 0
 *     and the step passes. A plain "reboot" cuts the SSH session and the step reads as failed.
 */

const WF_UPDATE_CORE = [
  "set -e",
  "export DEBIAN_FRONTEND=noninteractive",
  "dpkg --configure -a",
  "apt-get update",
  "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade",
  "apt-get -y --purge autoremove",
  "apt-get autoclean",
];
const WF_REBOOT_LATER = 'echo "Restarting in 5 s"; systemd-run --on-active=5 /bin/systemctl reboot';

const WF_COMMAND_TEMPLATES = [
  {
    id: "apt_update", name: "Debian / Ubuntu: update all packages, no restart", suits: ["linux_host"], timeout_s: 1800,
    command: WF_UPDATE_CORE.join("\n"),
    note: "Updates the package lists, installs every upgrade (full-upgrade, so new dependencies are added and replaced ones removed), removes packages nothing needs any more and clears old downloads.",
  },
  {
    id: "apt_update_reboot_needed", name: "Debian / Ubuntu: update, restart only if needed", suits: ["linux_host"], timeout_s: 1800,
    command: [...WF_UPDATE_CORE,
      'if [ -f /var/run/reboot-required ]; then ' + WF_REBOOT_LATER + '; else echo "No restart needed"; fi'].join("\n"),
    note: "Restarts only when an update asks for it (/var/run/reboot-required, usually a new kernel or libc). Do not follow it with Wait for ping: when no restart is needed the host never goes down.",
  },
  {
    id: "apt_update_reboot", name: "Debian / Ubuntu: update, then always restart", suits: ["linux_host"], timeout_s: 1800,
    command: [...WF_UPDATE_CORE, WF_REBOOT_LATER].join("\n"),
    note: "Your original command with the gaps closed. Follow it with Wait for ping (stops answering) and Wait for ping (answers), or use the \"Update and restart Linux hosts\" workflow template.",
  },
  {
    id: "pve_update", name: "Proxmox VE host: update all packages, no restart", suits: ["linux_host"], hostname: /pve|proxmox/i, timeout_s: 1800,
    command: [...WF_UPDATE_CORE.slice(0, 4),
      "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade",
      "apt-get -y --purge autoremove", "apt-get autoclean"].join("\n"),
    note: "Proxmox must be updated with dist-upgrade, never plain upgrade. Without a subscription the pve-enterprise repository makes apt-get update fail (401): switch to pve-no-subscription first. Restarting the host stops its guests; if this monitor runs on that host, the run stops with it.",
  },
  {
    id: "linux_reboot", name: "Linux: restart", suits: ["linux_host"], timeout_s: 30,
    command: WF_REBOOT_LATER,
    note: "Hands the restart to systemd so the step passes. Follow it with Wait for ping.",
  },
  {
    id: "unifi_reboot", name: "UniFi access point or switch: restart", suits: ["unifi_ap", "unifi_switch"], timeout_s: 30, any_exit: true, expect_disconnect: true,
    command: "reboot",
    note: "Log in with the device SSH user and password set in UniFi Network (Settings, System, Device SSH authentication). The connection drops as the device restarts, so any exit code counts as success.",
  },
  {
    id: "unifi_os_reboot", name: "UniFi OS console (UCG, UDM, UXG): restart", suits: ["unifi_gateway"], timeout_s: 30, any_exit: true, expect_disconnect: true,
    command: "reboot",
    note: "Logs in as root with the console's SSH password (UniFi OS, Settings, Advanced, SSH). The whole site loses its gateway while it restarts: restart it last.",
  },
  {
    id: "edgeos_reboot", name: "EdgeRouter (EdgeOS): restart", suits: ["ubiquiti_edgeos"], timeout_s: 30, any_exit: true, expect_disconnect: true,
    command: "sudo /sbin/reboot",
    note: "EdgeOS admin users run the restart through sudo; the connection drops, so any exit code counts as success.",
  },
  {
    id: "linux_free_space", name: "Linux: free disk space (old logs, package cache)", suits: ["linux_host"], timeout_s: 600,
    command: ["df -h / | tail -1", "journalctl --vacuum-time=14d", "apt-get clean", "apt-get -y --purge autoremove",
      "find /tmp -xdev -type f -atime +7 -delete 2>/dev/null || true", "df -h / | tail -1"].join("\n"),
    note: "Keeps two weeks of system logs, empties the package cache, removes packages nothing needs and clears week-old files in /tmp. Shows the free space before and after.",
  },
  {
    id: "linux_restart_service", name: "Linux: restart a service and check it", suits: ["linux_host"], timeout_s: 120,
    command: 'SERVICE=nginx\nsystemctl restart "$SERVICE"\nsleep 3\nsystemctl is-active "$SERVICE"',
    note: "Change SERVICE to the service's name. The step fails if the service is not running 3 s after the restart.",
  },
  {
    id: "linux_health", name: "Linux: quick health check (read only)", suits: ["linux_host"], timeout_s: 60, any_exit: true,
    command: ["uptime", "free -h", "df -h -x tmpfs -x devtmpfs", "systemctl --failed --no-legend || true",
      "[ -f /var/run/reboot-required ] && echo 'A restart is needed' || echo 'No restart needed'"].join("\n"),
    note: "Changes nothing: load, memory, disks, failed services and whether an update wants a restart. The run log shows the output.",
  },
  {
    id: "pihole_update", name: "Pi-hole: update Pi-hole", suits: ["linux_host"], hostname: /pi-?hole|dns/i, timeout_s: 1200,
    command: "pihole -up",
    note: "Updates Pi-hole itself. DNS answers pause for a moment while it restarts its resolver.",
  },
  {
    id: "pihole_gravity", name: "Pi-hole: refresh the block lists", suits: ["linux_host"], hostname: /pi-?hole|dns/i, timeout_s: 900,
    command: "pihole -g",
    note: "Downloads the block lists again (gravity). The Pi-hole page then shows the new list age.",
  },
  {
    id: "pve_guests", name: "Proxmox VE host: list guests (read only)", suits: ["linux_host"], hostname: /pve|proxmox/i, timeout_s: 60,
    command: "qm list; pct list",
    note: "Every VM and container with its state; changes nothing.",
  },
];

/* Whole workflows. kind "chain" adds, per chosen host in order: the steps from steps(host).
 * order "restart" sorts hosts furthest from the gateway first (from the network map). */
const WF_FLOW_TEMPLATES = [
  {
    id: "linux_update_restart", name: "Update and restart Linux hosts", suits: ["linux_host"], order: "restart", quiet: true, report: true,
    help: "For each host: update packages, restart, wait until it stops answering ping, wait until it answers again, wait for SNMP. Hosts run one after another, furthest from the gateway first.",
    steps: () => [
      { type: "command", command: WF_COMMAND_TEMPLATES[0].command, timeout_s: 1800, label: "Update packages" },
      { type: "command", command: WF_REBOOT_LATER, timeout_s: 30, expect_disconnect: true, label: "Restart" },
      { type: "wait_ping", state: "down", timeout_s: 180, failNext: true },
      { type: "wait_ping", state: "up", timeout_s: 900 },
      { type: "wait_snmp", timeout_s: 300 },
    ],
  },
  {
    id: "linux_update", name: "Update Linux hosts, no restart", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "One Run command step on all chosen hosts, one host at a time.",
    single: () => ({ type: "command", command: WF_COMMAND_TEMPLATES[0].command, timeout_s: 1800, label: "Update packages" }),
  },
  {
    id: "unifi_restart_order", name: "Restart UniFi devices in order", suits: ["unifi_ap", "unifi_switch", "unifi_gateway", "ubiquiti_edgeos"], order: "restart", quiet: true,
    help: "Restarts each chosen device furthest from the gateway first, so nothing restarts while a device it depends on is down: restart, wait until it stops answering ping, wait until it answers again.",
    steps: (host) => [
      { type: "command", command: host.profile_id === "ubiquiti_edgeos" ? "sudo /sbin/reboot" : "reboot", any_exit: true, expect_disconnect: true, timeout_s: 30, label: `Restart ${host.hostname}` },
      { type: "wait_ping", state: "down", timeout_s: 120, failNext: true },
      // Gateways take longest: UniFi OS boots, then brings the WAN and its services up.
      { type: "wait_ping", state: "up", timeout_s: host.profile_id === "unifi_gateway" ? 900 : 600 },
    ],
  },
  {
    id: "restart_sequence", name: "Restart sequence (any hosts, your command)", suits: [], order: "restart", askCommand: true, quiet: true,
    help: "Pick the hosts and the restart command. Each gets: run the command, wait until it stops answering ping, wait until it answers again.",
    steps: (host, command) => [
      { type: "command", command, any_exit: true, expect_disconnect: true, timeout_s: 60, label: `Restart ${host.hostname}` },
      { type: "wait_ping", state: "down", timeout_s: 120, failNext: true },
      { type: "wait_ping", state: "up", timeout_s: 600 },
    ],
  },
  {
    id: "pve_snapshot_update", name: "Snapshot, update and restart Proxmox guests", suits: ["linux_host"], order: "restart", quiet: true, report: true,
    needsGuests: true,
    help: "For each chosen host that is a Proxmox VM or container: take a snapshot to roll back to, update, restart and wait until it is back. Hosts that are not Proxmox guests get no snapshot. Needs the action token (Settings, Proxmox).",
    steps: (host) => {
      const g = (wfPveGuests || []).find(x => x.device_id === host.id);
      return [
        ...(g ? [{ type: "pve_snapshot", node: g.node, guest_type: g.type, vmid: g.vmid, guest_name: g.name || "", timeout_s: 600 }] : []),
        { type: "command", command: WF_COMMAND_TEMPLATES[0].command, timeout_s: 1800, label: `Update ${host.hostname}` },
        { type: "command", command: WF_REBOOT_LATER, timeout_s: 30, expect_disconnect: true, label: `Restart ${host.hostname}` },
        { type: "wait_ping", state: "down", timeout_s: 180, failNext: true },
        { type: "wait_ping", state: "up", timeout_s: 900 },
      ];
    },
  },
  {
    id: "restart_service", name: "Restart a service on Linux hosts", suits: ["linux_host"], order: "chosen", askCommand: true,
    askLabel: "Service name", askDefault: "", quiet: false, report: true,
    help: "Restarts one systemd service on each chosen host and checks it is running 3 s later. Pair it with the trigger \"A watched service or process stops\" to heal it by itself.",
    single: (service) => ({ type: "command", timeout_s: 120, label: `Restart ${service}`,
      command: `systemctl restart '${String(service).replace(/'/g, "")}'\nsleep 3\nsystemctl is-active '${String(service).replace(/'/g, "")}'` }),
  },
  {
    id: "free_space", name: "Free disk space on Linux hosts", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Old logs, the package cache and unneeded packages, on every chosen host. Pair it with the trigger \"A measurement goes above\" on disk use.",
    single: () => ({ type: "command", command: WF_COMMAND_TEMPLATES.find(c => c.id === "linux_free_space").command, timeout_s: 600, label: "Free disk space" }),
  },
  {
    id: "health_check", name: "Health check, results on Telegram", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Reads load, memory, disks, failed services and whether a restart is pending on each chosen host, changing nothing. The summary at the end lists what passed. Good on a weekly schedule.",
    single: () => ({ type: "command", command: WF_COMMAND_TEMPLATES.find(c => c.id === "linux_health").command, timeout_s: 60, any_exit: true, label: "Health check" }),
  },
  {
    id: "pihole_refresh", name: "Update Pi-hole and its block lists", suits: ["linux_host"], hostname: /pi-?hole|dns/i, order: "chosen", quiet: true, report: true,
    help: "Updates Pi-hole, then downloads the block lists again. DNS blips while it restarts, so its alerts are kept quiet meanwhile.",
    steps: (host) => [
      { type: "command", command: "pihole -up", timeout_s: 1200, label: `Update Pi-hole on ${host.hostname}` },
      { type: "command", command: "pihole -g", timeout_s: 900, label: "Refresh block lists" },
    ],
  },
  {
    id: "wifi_tidy", name: "Reconnect weak Wi-Fi on access points", suits: ["unifi_ap"], order: "chosen", noCred: true, report: true,
    help: "On each chosen access point, devices below the weak-signal line are dropped so they rejoin (at most once an hour each; the never-reconnect list is left alone). Needs UniFi connected with an account that may make changes.",
    steps: () => [{ type: "wifi_reconnect" }],
  },
];

/** A Run command step from the Linux host actions (hostactions.js loads them into the command templates).
 * Missing (the catalogue is not loaded) gives no step; the template's help says what it needs. */
function wfHa(id, label) {
  const t = WF_COMMAND_TEMPLATES.find(c => c.id === "ha_" + id);
  return t ? { type: "command", command: t.command, timeout_s: t.timeout_s, expect_disconnect: !!t.expect_disconnect, label } : null;
}
const wfHaSteps = (...pairs) => () => pairs.map(([id, label]) => wfHa(id, label)).filter(Boolean);

// Whole workflows made of host actions: the same fixed scripts as the Host actions window.
WF_FLOW_TEMPLATES.push(
  {
    id: "ha_weekly_tidy", name: "Weekly tidy-up on Linux hosts", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Host actions on each chosen host: empty the package cache, shrink the journal to 200 MB, remove unused packages and old kernels, clear week-old files in /tmp. Give it a weekly schedule.",
    steps: wfHaSteps(["apt_clean", "Empty package cache"], ["journal_vacuum", "Shrink the journal"], ["autoremove", "Remove unused packages"], ["tmp_clean", "Clear old /tmp files"]),
  },
  {
    id: "ha_disk_rescue", name: "Disk filling up: report, clean, report again", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "What is using the disk, then the safe clean-ups (package cache, journal), then the disk again so the summary shows what was freed. Pair it with the trigger \"A measurement goes above or below a value\" on disk use.",
    steps: wfHaSteps(["disk_usage", "Disk space before"], ["apt_clean", "Empty package cache"], ["journal_vacuum", "Shrink the journal"], ["disk_usage", "Disk space after"]),
  },
  {
    id: "ha_security_report", name: "Security and updates report", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Changes nothing: the security report, updates waiting and failed services on each chosen host, with a summary on Telegram. Good on a weekly schedule.",
    steps: wfHaSteps(["security_check", "Security report"], ["updates_pending", "Updates waiting"], ["failed_units", "Failed services"]),
  },
  {
    id: "ha_updates_services", name: "Install updates, then restart what still uses old libraries", suits: ["linux_host"], order: "chosen", quiet: true, report: true,
    help: "Installs updates without restarting the machine, then restarts only the services still running old libraries (needrestart). The machine itself keeps running.",
    steps: wfHaSteps(["install_updates", "Install updates"], ["restart_outdated", "Restart outdated services"]),
  },
  {
    id: "ha_docker_tidy", name: "Docker tidy-up", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Lists the containers and their state, then removes untagged images and build cache only. Nothing that would need a download is removed.",
    steps: wfHaSteps(["containers", "Containers"], ["docker_prune", "Remove dangling images"]),
  },
  {
    id: "ha_disk_health", name: "Disk health check", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Changes nothing: SMART health of every disk, filesystems that went read-only and time sync, on each chosen host. Good on a weekly schedule.",
    steps: wfHaSteps(["disk_health", "SMART health"], ["filesystems", "Read-only filesystems"], ["time_sync", "Time sync"]),
  },
  {
    id: "ha_pve_check", name: "Proxmox host check", suits: ["linux_host"], hostname: /pve|proxmox/i, order: "chosen", quiet: false, report: true,
    help: "Changes nothing: storage and ZFS pools, failed services and updates waiting on each chosen Proxmox host.",
    steps: wfHaSteps(["pve_storage", "Storage and ZFS"], ["failed_units", "Failed services"], ["updates_pending", "Updates waiting"]),
  },
  {
    id: "ha_heal_failed", name: "Clear failed services and check again", suits: ["linux_host"], order: "chosen", quiet: false, report: true,
    help: "Lists failed services, clears their failed markers (so a service that recovered stops showing) and lists them again. Services that are really broken show up the second time.",
    steps: wfHaSteps(["failed_units", "Failed services"], ["reset_failed", "Clear failed markers"], ["failed_units", "Failed services after"]),
  },
);

/** True when the template is meant for this host (template list and hostname pattern). */
function wfTemplateSuits(t, host) {
  if (!host || !t.suits.length) return false;
  if (!t.suits.includes(host.profile_id)) return false;
  return !t.hostname || t.hostname.test(host.hostname);
}
