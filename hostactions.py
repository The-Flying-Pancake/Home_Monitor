"""Host actions: a fixed catalogue of maintenance jobs for Linux hosts (Debian, Ubuntu, Proxmox VE), run once
over SSH from a device or one of its problems, or turned into a workflow.

Nothing here takes a command from the browser. Each action is written below with its script; the only value
that reaches the host from outside is a "choice" (a service, container, pool or size), and it is accepted
only when it matches CHOICE_RE (and the action's fixed options when it has them), then passed as one
shell-quoted assignment (C='name') ahead of the script. Scripts that take a choice check on the host that
it names something real before using it.

Kinds:
  check    reads and reports, changes nothing: runs at one click
  change   clean-ups and repairs: a preview shows what would change; the run needs a preview of the same
           action (and choice) by the same user in the last PREVIEW_TTL seconds
  restart  stops something for a moment: preview, the device's name typed to confirm, a Proxmox snapshot
           offered first when the device is a guest the monitor knows, notifications muted for a restart
           of the whole machine

Every script runs as the credential's user: root, or a user with passwordless sudo (PRELUDE sets $S to
"sudo -n" and stops with exit 97 when sudo would ask for a password).

Deliberately absent: deleting files or folders by name, fsck, partition or disk changes, firewall or user
changes, snapshot rollback, stopping or deleting guests. Those stay manual or in a workflow you write.
"""

import re
import shlex
import threading
import time
from typing import Any, Callable, Dict, List, Optional

CHOICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:+-]{0,127}")
PREVIEW_TTL = 15 * 60
MAX_OUTPUT = 32 * 1024
NO_SUDO, NOT_FOUND = 97, 96
# Services an action never restarts: the session itself, the network, the init system, this monitor.
BLOCKED_SERVICES = re.compile(r"(dbus|dbus-broker|systemd-.*|networking|NetworkManager|ifup@.*|ifupdown.*|user@.*|"
                              r"getty@.*|serial-getty@.*|homelab-monitor.*|polkit|udisks2|pve-cluster|corosync)", re.I)

PRELUDE = ('S=""; if [ "$(id -u)" -ne 0 ]; then if sudo -n true 2>/dev/null; then S="sudo -n"; '
           f'else echo "HM_NO_SUDO"; exit {NO_SUDO}; fi; fi; export LC_ALL=C; '
           'h() { echo; echo "== $1 =="; }; '
           'none() { awk \'{print} END {if (NR == 0) print "(none)"}\'; }\n')
REBOOT_REQUIRED = ('if [ -f /var/run/reboot-required ]; then echo "yes: $(tr \'\\n\' \' \' < /var/run/reboot-required.pkgs 2>/dev/null)"; '
                   'else echo "no"; fi')
NO_VIRT = "-x tmpfs -x devtmpfs -x squashfs -x overlay"
SIMULATE = "apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null"
APT_HOSTS = ("{ sed -n 's#^deb[^ ]* \\(\\[[^]]*\\] \\)\\{0,1\\}[a-z+]*://\\([^/ ]*\\).*#\\2#p' /etc/apt/sources.list "
             "/etc/apt/sources.list.d/*.list 2>/dev/null; sed -n 's#^URIs:.*://\\([^/ ]*\\).*#\\1#p' "
             "/etc/apt/sources.list.d/*.sources 2>/dev/null; } | sort -u | head -6")


def _lines(*parts: str) -> str:
    return "\n".join(parts)


# Each action: id, name, kind, note, fits (problem key prefixes it helps with), timeout (s), run (script),
# optional preview (script), choice ({label, list script | options, default}), snapshot (offered on by default).
ACTIONS: List[Dict[str, Any]] = [
    # --- Checks: change nothing ---
    {"id": "disk_usage", "name": "Disk space: what is using it", "kind": "check", "timeout": 420,
     "fits": ["storage", "volume_full", "forecast_full"],
     "note": "Filesystems and inodes, the largest folders, big files written in the last day (what makes a disk grow), "
             "the journal, the package cache, kernels, Docker and deleted files still held open.",
     "run": _lines(
         f'h "Filesystems"; df -hT {NO_VIRT} 2>/dev/null',
         f'h "Inodes"; df -i {NO_VIRT} 2>/dev/null',
         'h "Largest folders on / (two levels)"; $S timeout 240 du -xh -d 2 / 2>/dev/null | sort -rh | head -25',
         'h "Big files written in the last day (over 50 MB)"; $S timeout 120 find / -xdev -type f -mmin -1440 -size +50M '
         "-printf '%s\\t%TY-%Tm-%Td %TH:%TM\\t%p\\n' 2>/dev/null | sort -rn | head -15 | "
         "awk -F '\\t' '{printf \"%9.1f MB  %s  %s\\n\", $1 / 1048576, $2, $3}' | none",
         'h "System journal"; $S journalctl --disk-usage 2>/dev/null || echo "no journal"',
         'h "Package cache"; $S du -sh /var/cache/apt 2>/dev/null || echo "no apt cache"',
         'h "Kernels"; echo "running: $(uname -r)"; dpkg -l "linux-image-*" "pve-kernel-*" "proxmox-kernel-*" 2>/dev/null '
         "| awk '/^ii/ {print \"installed: \" $2}'",
         'h "Docker"; if command -v docker >/dev/null 2>&1; then $S docker system df; else echo "not installed"; fi',
         'h "Deleted files still held open (over 10 MB)"; if command -v lsof >/dev/null 2>&1; then $S lsof -nP +L1 2>/dev/null '
         "| awk 'NR > 1 && $7 > 10485760 {printf \"%9.1f MB  %s (pid %s)  %s\\n\", $7 / 1048576, $1, $2, $NF}' | sort -rn | head -10 | none; "
         'else echo "lsof is not installed: skipped"; fi')},
    {"id": "health", "name": "Quick health check", "kind": "check", "timeout": 60,
     "fits": ["restarted", "workflow", "health"],
     "note": "Load, memory, disks, failed services and whether an update wants a restart.",
     "run": _lines('h "Uptime and load"; uptime', 'h "Memory"; free -h', f'h "Filesystems"; df -h {NO_VIRT}',
                   'h "Failed services"; systemctl --failed --no-legend --no-pager --plain | none',
                   f'h "Restart needed"; {REBOOT_REQUIRED}')},
    {"id": "top_processes", "name": "Busiest processes", "kind": "check", "timeout": 60, "fits": ["cpu", "mem", "watch:process"],
     "note": "What uses the CPU right now (two samples a second apart) and what holds the most memory.",
     "run": _lines('h "CPU now"; top -b -n 2 -d 1 -o %CPU 2>/dev/null | awk \'/^top -/ {n++} n == 2\' | sed -n "7,22p"',
                   'h "Memory"; free -h',
                   'h "Largest in memory"; ps -eo pid,user:12,pmem,rss:10,etime,comm --sort=-rss | head -16',
                   'h "Pressure (share of time waiting)"; for r in cpu memory io; do printf "%-7s " $r; '
                   'head -1 /proc/pressure/$r 2>/dev/null || echo "not available"; done')},
    {"id": "failed_units", "name": "Failed services and why", "kind": "check", "timeout": 60, "fits": ["watch", "health"],
     "note": "Every failed systemd service with its last log lines.",
     "run": _lines('h "Failed services"; systemctl --failed --no-legend --no-pager --plain | none',
                   "for u in $(systemctl --failed --no-legend --plain | awk '{print $1}' | head -5); do "
                   'h "Last lines of $u"; $S journalctl -u "$u" -n 15 --no-pager -o short-iso 2>/dev/null; done')},
    {"id": "service_status", "name": "A service: status and last 50 log lines", "kind": "check", "timeout": 60,
     "fits": ["watch:service", "snmp", "pihole_blocking", "dns_down", "dns_slow"],
     "choice": {"label": "Service", "list": "services"},
     "note": "Whether it runs, since when and what it last wrote to the journal.",
     "run": _lines(f'$S systemctl cat -- "$C" >/dev/null 2>&1 || {{ echo "No service called $C on this host"; exit {NOT_FOUND}; }}',
                   'h "Status"; systemctl status --no-pager -l -n 0 -- "$C"',
                   'h "Last 50 log lines"; $S journalctl -u "$C" -n 50 --no-pager -o short-iso')},
    {"id": "updates_pending", "name": "Updates waiting and restart needed", "kind": "check", "timeout": 120,
     "fits": ["restarted"],
     "note": "From the last package list refresh (nothing is downloaded): what would install, security updates, held "
             "packages, interrupted installs, services still running old libraries and whether a restart is needed.",
     "run": _lines('h "Package lists"; L=$(ls -t /var/lib/apt/lists/*Release 2>/dev/null | head -1); '
                   '[ -n "$L" ] && echo "last refreshed $(stat -c %y "$L" | cut -d. -f1)" || echo "never refreshed"',
                   f'U=$({SIMULATE} | awk \'/^Inst / {{print $2}}\'); N=$(echo "$U" | grep -c .); '
                   f'SEC=$({SIMULATE} | grep "^Inst" | grep -ci security)',
                   'h "Waiting to install"; echo "$N packages, $SEC from security sources"; echo "$U" | head -40',
                   'h "Held packages"; apt-mark showhold 2>/dev/null | none',
                   'h "Interrupted installs"; $S dpkg --audit 2>/dev/null | none',
                   'h "Services still running old libraries"; if command -v needrestart >/dev/null 2>&1; then '
                   "$S needrestart -b -r l 2>/dev/null | sed -n 's/^NEEDRESTART-SVC: //p' | none; "
                   'else echo "needrestart is not installed: skipped"; fi',
                   f'h "Restart needed"; {REBOOT_REQUIRED}')},
    {"id": "disk_health", "name": "Disk health (SMART)", "kind": "check", "timeout": 120, "fits": ["disk_smart", "disk_temp"],
     "note": "SMART verdict, wear, bad sectors and temperature per disk. Needs smartmontools; a VM or container has "
             "virtual disks, so check its Proxmox host instead.",
     "run": _lines('V=$(systemd-detect-virt 2>/dev/null || echo none)',
                   'if [ "$V" != none ]; then echo "This is a $V guest: its disks are virtual. Run this on the Proxmox host."; exit 0; fi',
                   'if ! command -v smartctl >/dev/null 2>&1; then echo "smartmontools is not installed (apt-get install smartmontools)."; exit 0; fi',
                   '$S smartctl --scan | while read -r dev flag type rest; do h "$dev"; '
                   '$S smartctl -H -i -d "$type" "$dev" | grep -E "Model|Serial|Capacity|overall-health|SMART Health"; '
                   '$S smartctl -A -d "$type" "$dev" | grep -E "Reallocated_Sector|Pending_Sector|Offline_Uncorrectable|'
                   'Temperature_Celsius|Power_On_Hours|Wear_Leveling|Percentage Used|Media and Data Integrity|Available Spare:|Temperature:"; done')},
    {"id": "filesystems", "name": "Filesystems: read-only or erroring", "kind": "check", "timeout": 60,
     "fits": ["storage", "volume_state", "disk_smart", "health"],
     "note": "Filesystems that switched to read-only after errors. Disk errors in the kernel log.",
     "run": _lines('h "Read-only filesystems"; awk \'$4 ~ /(^|,)ro(,|$)/ && $3 !~ /^(squashfs|iso9660|proc|sysfs|tmpfs|ramfs|'
                   'cgroup2?|overlay|nsfs|autofs|securityfs|pstore|efivarfs|bpf|tracefs|debugfs|configfs|fusectl|binfmt_misc|'
                   'mqueue|hugetlbfs|devpts)$/ {print $2 " (" $3 ", " $1 ")"}\' /proc/mounts | none',
                   'h "Disk and filesystem errors in the kernel log"; '
                   'if K=$($S dmesg -T --level=err,crit,alert,emerg 2>/dev/null); then echo "$K" | '
                   'grep -iE "ext4|xfs|btrfs|zfs|i/o error|blk_update|nvme|ata[0-9]|scsi|remount" | tail -20 | none; '
                   'else echo "the kernel log is not readable here (a container)"; fi')},
    {"id": "containers", "name": "Docker containers: restarting or unhealthy", "kind": "check", "timeout": 90,
     "fits": ["cpu", "mem", "watch"],
     "note": "Every container's state. For any that keep restarting, are unhealthy or stopped with an error: their last log lines.",
     "run": _lines('command -v docker >/dev/null 2>&1 || { echo "Docker is not installed on this host"; exit 0; }',
                   "h \"Containers\"; $S docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Image}}'",
                   "B=$({ $S docker ps -a --filter status=restarting --format '{{.Names}}'; "
                   "$S docker ps --filter health=unhealthy --format '{{.Names}}'; "
                   "$S docker ps -a --filter status=exited --format '{{.Names}} {{.Status}}' | grep -v 'Exited (0)' | awk '{print $1}'; } | sort -u | head -5)",
                   'h "In trouble"; echo "$B" | none',
                   'for n in $B; do h "Last lines of $n"; $S docker logs --tail 20 "$n" 2>&1; done')},
    {"id": "network_dns", "name": "Network and DNS", "kind": "check", "timeout": 60, "fits": [],
     "note": "Addresses, routes, DNS servers, a ping of the gateway and name lookups of the package sources.",
     "run": _lines('h "Addresses"; ip -br addr', 'h "Routes"; ip route',
                   'h "DNS servers"; grep -E "^nameserver" /etc/resolv.conf | none',
                   "G=$(ip route | awk '/^default/ {print $3; exit}')",
                   'h "Gateway"; if [ -n "$G" ]; then ping -c 2 -W 2 "$G" | tail -2; else echo "no default route"; fi',
                   f'h "Name lookups"; for n in $({APT_HOSTS}); do if getent hosts "$n" >/dev/null; then echo "$n: resolves"; '
                   'else echo "$n: does not resolve"; fi; done')},
    {"id": "security_check", "name": "Security check (report only)", "kind": "check", "timeout": 90, "fits": [],
     "note": "Listening ports, recent logins, failed SSH logins in the last day (and from where) and security updates waiting.",
     "run": _lines("h \"Listening ports\"; $S ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}' | sort -u | none",
                   'h "Recent logins"; last -n 10 -w 2>/dev/null | head -12 | none',
                   'F=$($S journalctl -u ssh -u sshd --since -24h --no-pager -o cat 2>/dev/null | grep -E "Failed password|Invalid user|authentication failure")',
                   'h "Failed SSH logins, last 24 hours"; echo "$F" | grep -c . ; '
                   "echo \"$F\" | grep -oE 'from [0-9a-fA-F.:]+' | sort | uniq -c | sort -rn | head -5",
                   f'h "Security updates waiting"; {SIMULATE} | grep "^Inst" | grep -ci security')},
    {"id": "time_sync", "name": "Clock and time sync", "kind": "check", "timeout": 30, "fits": [],
     "note": "The clock, whether it is synchronised and from where.",
     "run": _lines('h "Clock"; timedatectl 2>/dev/null || date',
                   'h "Time source"; if command -v chronyc >/dev/null 2>&1; then chronyc tracking; chronyc sources 2>/dev/null; '
                   'else timedatectl timesync-status 2>/dev/null || echo "not available"; fi')},
    {"id": "pve_storage", "name": "Proxmox host: storage, ZFS and backups", "kind": "check", "timeout": 90,
     "fits": ["pve_guest_disk", "volume_state", "storage", "forecast_full"],
     "note": "Proxmox storage use, ZFS pool health, LVM thin pools and the last backup log lines.",
     "run": _lines('command -v pvesm >/dev/null 2>&1 || { echo "This is not a Proxmox VE host"; exit 0; }',
                   'h "Storage"; $S pvesm status',
                   'h "ZFS pools"; if command -v zpool >/dev/null 2>&1; then $S zpool list; echo; $S zpool status -x; else echo "no ZFS"; fi',
                   "h \"LVM thin pools\"; $S lvs --noheadings -o lv_name,vg_name,lv_size,data_percent,metadata_percent -S 'lv_attr=~^t' 2>/dev/null | none",
                   'h "Latest backup logs"; for f in $(ls -t /var/log/vzdump/*.log 2>/dev/null | head -8); do '
                   'echo "$(basename "$f"): $(tail -1 "$f")"; done | none')},
    {"id": "pihole_status", "name": "Pi-hole: status and blocklist age", "kind": "check", "timeout": 60,
     "fits": ["pihole_lists", "pihole_blocking", "dns_down", "dns_slow"],
     "note": "Whether Pi-hole blocks, its versions and when the blocklists were last updated.",
     "run": _lines('command -v pihole >/dev/null 2>&1 || { echo "Pi-hole is not installed on this host"; exit 0; }',
                   'h "Status"; $S pihole status', 'h "Versions"; pihole -v 2>/dev/null',
                   'h "Blocklists"; G=/etc/pihole/gravity.db; if [ -f $G ]; then echo "last updated $(stat -c %y $G | cut -d. -f1)"; fi')},

    # --- Changes: preview first ---
    {"id": "apt_clean", "name": "Empty the package download cache", "kind": "change", "timeout": 120,
     "fits": ["storage", "volume_full", "forecast_full"],
     "note": "Deletes downloaded package files apt keeps after installing. They are downloaded again if ever needed.",
     "preview": 'h "Package cache"; $S du -sh /var/cache/apt/archives',
     "run": '$S apt-get clean && echo "Emptied." && $S du -sh /var/cache/apt/archives'},
    {"id": "journal_vacuum", "name": "Shrink the system journal", "kind": "change", "timeout": 300,
     "fits": ["storage", "volume_full", "forecast_full"],
     "choice": {"label": "Keep the newest", "options": ["100M", "200M", "500M", "1G"], "default": "200M"},
     "note": "Deletes the oldest system log entries until the journal fits the size you choose.",
     "preview": 'h "System journal now"; $S journalctl --disk-usage; echo "Keeps the newest $C."',
     "run": '$S journalctl --vacuum-size="$C"; h "Journal after"; $S journalctl --disk-usage'},
    {"id": "autoremove", "name": "Remove unused packages and old kernels", "kind": "change", "timeout": 900, "snapshot": True,
     "fits": ["storage", "volume_full", "forecast_full"],
     "note": "Packages nothing needs any more, by apt's own list: usually old kernels. The running kernel is never removed.",
     "preview": 'h "Would remove"; apt-get -s -o Debug::NoLocking=1 --purge autoremove 2>/dev/null | awk \'/^(Purg|Remv) / {print $2}\' | none',
     "run": '$S env DEBIAN_FRONTEND=noninteractive apt-get -y --purge autoremove'},
    {"id": "docker_prune", "name": "Docker: remove dangling images and build cache", "kind": "change", "timeout": 600,
     "fits": ["storage", "volume_full", "forecast_full"],
     "note": "Only untagged leftover image layers and the build cache. Images in use, stopped containers and volumes are "
             "kept (this network cannot download images again).",
     "preview": _lines('command -v docker >/dev/null 2>&1 || { echo "Docker is not installed on this host"; exit 0; }',
                       'h "Docker disk use"; $S docker system df',
                       "h \"Dangling images\"; $S docker images -f dangling=true --format '{{.ID}}  {{.Size}}  {{.CreatedSince}}' | none"),
     "run": _lines('command -v docker >/dev/null 2>&1 || { echo "Docker is not installed on this host"; exit 0; }',
                   '$S docker image prune -f', '$S docker builder prune -f', 'h "Docker disk use after"; $S docker system df')},
    {"id": "logrotate_now", "name": "Rotate logs now", "kind": "change", "timeout": 300,
     "fits": ["storage", "volume_full", "forecast_full"],
     "note": "Runs the normal log rotation straight away, so large logs are compressed and the oldest dropped as configured.",
     "preview": ('h "Largest files in /var/log"; $S find /var/log -xdev -type f -printf \'%s\\t%p\\n\' 2>/dev/null | sort -rn | '
                 "head -15 | awk -F '\\t' '{printf \"%9.1f MB  %s\\n\", $1 / 1048576, $2}'"),
     "run": '$S logrotate -f /etc/logrotate.conf && echo "Rotated." ; df -h /var/log'},
    {"id": "tmp_clean", "name": "Delete week-old files in /tmp", "kind": "change", "timeout": 300,
     "fits": ["storage", "volume_full", "forecast_full"],
     "note": "Files in /tmp neither changed nor read for 7 days.",
     "preview": ("h \"Would delete\"; $S find /tmp -xdev -type f -mtime +7 -atime +7 -printf '%s\\n' 2>/dev/null | "
                 "awk '{s += $1; n++} END {printf \"%d files, %.1f MB\\n\", n, s / 1048576}'"),
     "run": '$S find /tmp -xdev -type f -mtime +7 -atime +7 -delete 2>/dev/null; echo "Done."; df -h /tmp'},
    {"id": "dpkg_configure", "name": "Finish interrupted package installs", "kind": "change", "timeout": 900, "snapshot": True,
     "fits": [],
     "note": "Completes an install or update that was cut off, which otherwise blocks every later update.",
     "preview": 'h "Interrupted installs"; $S dpkg --audit | none',
     "run": '$S env DEBIAN_FRONTEND=noninteractive dpkg --configure -a && echo "Done."'},
    {"id": "install_updates", "name": "Install updates now (no restart)", "kind": "change", "timeout": 1800, "snapshot": True,
     "fits": ["restarted"],
     "note": "Refreshes the package lists and installs every update, keeping changed config files. Does not restart; "
             "run Updates waiting afterwards to see whether a restart is needed. Proxmox without a subscription needs "
             "the pve-no-subscription repository.",
     "preview": _lines(f'h "Would install (from the last refresh)"; {SIMULATE} | awk \'/^Inst / {{print $2}}\' | none'),
     "run": _lines('set -e', '$S env DEBIAN_FRONTEND=noninteractive dpkg --configure -a',
                   '$S env DEBIAN_FRONTEND=noninteractive apt-get update',
                   '$S env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef '
                   '-o Dpkg::Options::=--force-confold dist-upgrade',
                   f'set +e; h "Restart needed"; {REBOOT_REQUIRED}')},
    {"id": "reset_failed", "name": "Clear failed service markers", "kind": "change", "timeout": 30, "fits": ["watch"],
     "note": "Forgets old failures, so the list shows only what fails from now on. Starts nothing.",
     "preview": 'h "Failed services"; systemctl --failed --no-legend --no-pager --plain | none',
     "run": '$S systemctl reset-failed; h "Failed services now"; systemctl --failed --no-legend --no-pager --plain | none'},
    {"id": "dns_flush", "name": "Flush the DNS cache", "kind": "change", "timeout": 30, "fits": [],
     "note": "Clears names systemd-resolved remembers, for when a changed address is still answered the old way.",
     "preview": 'h "Resolver cache"; resolvectl statistics 2>/dev/null | grep -i -A3 cache || echo "systemd-resolved is not in use: nothing to flush"',
     "run": 'if command -v resolvectl >/dev/null 2>&1; then $S resolvectl flush-caches && echo "Flushed."; else echo "systemd-resolved is not in use"; fi'},
    {"id": "pihole_gravity", "name": "Pi-hole: update blocklists", "kind": "change", "timeout": 900, "fits": ["pihole_lists"],
     "note": "Downloads the blocklists again (gravity). DNS keeps answering meanwhile.",
     "preview": 'command -v pihole >/dev/null 2>&1 || { echo "Pi-hole is not installed"; exit 0; }; '
                'G=/etc/pihole/gravity.db; h "Blocklists"; [ -f $G ] && echo "last updated $(stat -c %y $G | cut -d. -f1)"',
     "run": '$S pihole -g'},
    {"id": "zfs_scrub", "name": "Proxmox host: start a ZFS scrub", "kind": "change", "timeout": 60, "fits": ["volume_state"],
     "choice": {"label": "Pool", "list": "zpools"},
     "note": "Reads every block of the pool to find and repair errors. Runs in the background for hours and slows the disks meanwhile.",
     "preview": f'$S zpool list -H -o name | grep -qx -- "$C" || {{ echo "No pool called $C"; exit {NOT_FOUND}; }}; h "Pool"; $S zpool status -- "$C" | head -20',
     "run": f'$S zpool list -H -o name | grep -qx -- "$C" || exit {NOT_FOUND}; $S zpool scrub -- "$C" && echo "Scrub started. Follow it with: zpool status $C"'},

    # --- Restarts: preview, typed confirmation ---
    {"id": "restart_service", "name": "Restart a service", "kind": "restart", "timeout": 120,
     "fits": ["watch:service", "snmp", "cpu", "mem", "pihole_blocking", "dns_down", "dns_slow"],
     "choice": {"label": "Service", "list": "services"},
     "note": "Restarts one service and checks it is running 3 s later. The network, systemd itself and this monitor are not offered.",
     "preview": _lines(f'$S systemctl cat -- "$C" >/dev/null 2>&1 || {{ echo "No service called $C on this host"; exit {NOT_FOUND}; }}',
                       'h "Status now"; systemctl status --no-pager -l -n 5 -- "$C"'),
     "run": _lines(f'$S systemctl cat -- "$C" >/dev/null 2>&1 || {{ echo "No service called $C on this host"; exit {NOT_FOUND}; }}',
                   '$S systemctl restart -- "$C"; sleep 3',
                   'if systemctl is-active --quiet -- "$C"; then echo "$C is running."; else '
                   'systemctl status --no-pager -l -n 15 -- "$C"; exit 1; fi')},
    {"id": "restart_container", "name": "Docker: restart a container", "kind": "restart", "timeout": 180,
     "fits": ["cpu", "mem", "watch"], "choice": {"label": "Container", "list": "containers"},
     "note": "Restarts one container and shows its state afterwards.",
     "preview": _lines(f'$S docker inspect "$C" >/dev/null 2>&1 || {{ echo "No container called $C"; exit {NOT_FOUND}; }}',
                       "h \"Now\"; $S docker inspect -f '{{.State.Status}} since {{.State.StartedAt}}, restarted {{.RestartCount}} times' \"$C\"",
                       'h "Last log lines"; $S docker logs --tail 15 "$C" 2>&1'),
     "run": _lines(f'$S docker inspect "$C" >/dev/null 2>&1 || exit {NOT_FOUND}',
                   "$S docker restart \"$C\" && sleep 3 && $S docker inspect -f '{{.State.Status}}' \"$C\"")},
    {"id": "restart_outdated", "name": "Restart services still running old libraries", "kind": "restart", "timeout": 300,
     "snapshot": False, "fits": ["restarted"],
     "note": "After updates: restarts only the services needrestart lists, instead of the whole machine.",
     "preview": _lines('command -v needrestart >/dev/null 2>&1 || { echo "needrestart is not installed (apt-get install needrestart)"; exit 0; }',
                       "h \"Would restart\"; $S needrestart -b -r l 2>/dev/null | sed -n 's/^NEEDRESTART-SVC: //p' | none"),
     "run": _lines(f'command -v needrestart >/dev/null 2>&1 || {{ echo "needrestart is not installed"; exit {NOT_FOUND}; }}',
                   '$S env NEEDRESTART_MODE=a needrestart -r a -b', 'h "Still listed"; '
                   "$S needrestart -b -r l 2>/dev/null | sed -n 's/^NEEDRESTART-SVC: //p' | none")},
    {"id": "reboot", "name": "Restart the machine", "kind": "restart", "timeout": 30, "snapshot": True, "reboot": True,
     "fits": ["restarted"],
     "note": "Restarts it, then waits until it stops and starts answering ping again. Its notifications are muted "
             "meanwhile. A Proxmox host stops its guests while it restarts.",
     "preview": _lines('h "Up for"; uptime', f'h "Restart needed"; {REBOOT_REQUIRED}',
                       'if command -v qm >/dev/null 2>&1; then h "Running guests (they stop too)"; '
                       "$S qm list 2>/dev/null | awk 'NR > 1 && $3 == \"running\" {print \"VM \" $1 \" \" $2}'; "
                       "$S pct list 2>/dev/null | awk 'NR > 1 && $2 == \"running\" {print \"CT \" $1 \" \" $NF}'; fi"),
     "run": '$S systemd-run --on-active=5 /bin/systemctl reboot && echo "Restarting in 5 s"'},
]
BY_ID = {a["id"]: a for a in ACTIONS}
KINDS = ("check", "change", "restart")

# Lists a choice is picked from, run on the host; one name per line.
LISTS = {
    "services": "systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | "
                "awk '$2 == \"loaded\" && ($3 == \"active\" || $3 == \"failed\") {sub(/\\.service$/, \"\", $1); print $1}'",
    "containers": "command -v docker >/dev/null 2>&1 && $S docker ps -a --format '{{.Names}}'",
    "zpools": "command -v zpool >/dev/null 2>&1 && $S zpool list -H -o name",
}


class ActionError(Exception):
    pass


def public(action: Dict[str, Any]) -> Dict[str, Any]:
    """What the browser shows: no scripts but the run script, for "Make this a workflow" and the template picker."""
    out = {k: action[k] for k in ("id", "name", "kind", "note", "fits", "timeout")}
    out["has_preview"] = "preview" in action
    out["snapshot"] = bool(action.get("snapshot"))
    out["reboot"] = bool(action.get("reboot"))
    if action.get("choice"):
        c = action["choice"]
        out["choice"] = {"label": c["label"], "options": c.get("options"), "default": c.get("default"), "listed": "list" in c}
    return out


def catalogue() -> List[Dict[str, Any]]:
    return [dict(public(a), script=workflow_script(a["id"])) for a in ACTIONS]


def check_choice(action: Dict[str, Any], choice: Optional[str]) -> Optional[str]:
    c = action.get("choice")
    if not c:
        return None
    choice = (choice or c.get("default") or "").strip()
    if not choice or not CHOICE_RE.fullmatch(choice):
        raise ActionError(f"Choose a {c['label'].lower()}: letters, digits and @ . _ : + - only")
    if c.get("options") and choice not in c["options"]:
        raise ActionError(f"{c['label']} must be one of {', '.join(c['options'])}")
    if c.get("list") == "services" and action["kind"] == "restart" and BLOCKED_SERVICES.fullmatch(choice.removesuffix(".service")):
        raise ActionError(f"{choice} is not restarted from here: it would cut off the host, the network or this monitor")
    return choice


def script(action_id: str, mode: str, choice: Optional[str] = None) -> str:
    """The script sent to the host for mode "preview", "run" or "list" (choices). choice must have passed check_choice."""
    action = BY_ID[action_id]
    head = PRELUDE + (f"C={shlex.quote(choice)}\n" if choice else "")
    if mode == "list":
        return head + LISTS[action["choice"]["list"]] + "\nexit 0"
    body = action[mode]
    return head + body + ("\nexit 0" if action["kind"] == "check" or mode == "preview" else "")


def workflow_script(action_id: str, choice: Optional[str] = None) -> str:
    """The run script as a workflow command step: the choice (or a placeholder to edit) on its own first line."""
    action = BY_ID[action_id]
    c = action.get("choice")
    first = ""
    if c:
        value = choice or c.get("default") or "name"
        first = f"C={shlex.quote(value)}   # {c['label'].lower()}" + ("" if choice or c.get("default") else ": change this") + "\n"
    return first + PRELUDE + action["run"] + ("\nexit 0" if action["kind"] == "check" else "")


def parse_list(stdout: str) -> List[str]:
    out = []
    for line in stdout.splitlines():
        name = line.strip()
        if name and CHOICE_RE.fullmatch(name) and name not in out:
            out.append(name)
    return out[:300]


def suggest(problem_key: str) -> List[Dict[str, Any]]:
    """Actions that fit a problem, most specific first, with the choice the problem names (a watched service)."""
    if not problem_key:
        return []
    parts = problem_key.split(":")
    preset = None
    if parts[0] == "watch" and len(parts) >= 3 and CHOICE_RE.fullmatch(parts[2]):
        preset = parts[2]
    elif parts[0] == "snmp":
        preset = "snmpd"
    elif parts[0] in ("pihole_blocking", "dns_down", "dns_slow"):
        preset = "pihole-FTL"
    out = []
    for a in ACTIONS:
        hit = next((f for f in a["fits"] if problem_key == f or problem_key.startswith(f + ":")), None)
        if hit:
            choice = preset if a.get("choice", {}).get("list") == "services" else None
            out.append({"id": a["id"], "choice": choice, "specific": hit.count(":")})
    # Checks first (they change nothing), then changes, then restarts.
    out.sort(key=lambda s: (-s["specific"], KINDS.index(BY_ID[s["id"]]["kind"])))
    return [{"id": s["id"], "choice": s["choice"]} for s in out]


def plain_failure(result: Dict[str, Any], login_problem: Callable[[str], Optional[str]]) -> Optional[str]:
    """Plain words for a run that never reached the script, or stopped at the prelude or a missing choice."""
    if result["status"] == "timeout":
        return f"Gave up: {result.get('stderr') or 'the host took too long'}"
    if result["status"] != "completed":
        raw = (result.get("stderr") or result["status"]).strip()
        plain = login_problem(raw)
        return f"Could not log in over SSH: {plain} ({raw[:200]})" if plain else f"Could not log in over SSH: {raw[:300]}"
    if result["exit_code"] == NO_SUDO and "HM_NO_SUDO" in (result.get("stdout") or ""):
        return ("This credential's user is not root and sudo asks for a password. Use a root credential or allow "
                "passwordless sudo for this user.")
    return None


class Previews:
    """Who previewed what, recently: a change or restart runs only after its preview."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.seen: Dict[tuple, float] = {}

    def mark(self, user: str, device_id: int, action_id: str, choice: Optional[str], now: Optional[float] = None) -> None:
        now = now or time.time()
        with self.lock:
            self.seen = {k: t for k, t in self.seen.items() if now - t < PREVIEW_TTL}
            self.seen[(user, device_id, action_id, choice or "")] = now

    def fresh(self, user: str, device_id: int, action_id: str, choice: Optional[str], now: Optional[float] = None) -> bool:
        now = now or time.time()
        with self.lock:
            t = self.seen.get((user, device_id, action_id, choice or ""))
        return t is not None and now - t < PREVIEW_TTL


PREVIEWS = Previews()


class Runs:
    """Runs in progress: one at a time per device."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active: Dict[int, int] = {}       # device_id -> run id

    def claim(self, device_id: int, run_id_factory: Callable[[], int]) -> int:
        with self.lock:
            if device_id in self.active:
                raise ActionError("Another action is running on this device. Wait for it to finish.")
            run_id = run_id_factory()
            self.active[device_id] = run_id
            return run_id

    def release(self, device_id: int) -> None:
        with self.lock:
            self.active.pop(device_id, None)

    def running(self) -> Dict[int, int]:
        with self.lock:
            return dict(self.active)


RUNS = Runs()


def trim(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n[output cut at 32 KB]"
