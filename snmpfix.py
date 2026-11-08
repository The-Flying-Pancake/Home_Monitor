"""Built-in "Fix SNMP" action for Linux hosts running net-snmp (Debian, Ubuntu, Proxmox).

Hosts set up by hand carry years of artefacts: Debian's "view systemonly"
(system group only), "rocommunity x default" (any source), rouser lines,
agentaddress limited to localhost, extra files under snmpd.conf.d. Patching
around them proved fragile, so this action writes a complete, clean
snmpd.conf instead:

  agentAddress on all IPv4 addresses (UDP 161). No udp6 endpoint: snmpd exits at
  start when any listed endpoint cannot be opened, which happens on hosts and
  containers with IPv6 disabled; the monitor polls over IPv4
  one view (hmmonitor) of the whole tree, read only
  the community from Settings (or the device), for the monitor's own
  address (/32) and localhost only
  sysLocation, sysContact, sysName and "master agentx" kept when present

Everything else is dropped, including includeDir (old drop-in files under
snmpd.conf.d stay on disk but are no longer read). The old file is kept as
snmpd.conf.hm-backup-<time>.

Over SSH: READ_SCRIPT reports what is installed, whether the login is root
or can use sudo without a password, whether ufw is active, and the current
file. apply_script() installs snmpd with apt-get when missing, writes the
new file from stdin (the community never appears in a command line), opens
UDP 161 in ufw for the monitor's address only when ufw is active, enables
and restarts snmpd. The backup name is printed before the restart, so a
failed start is always rolled back; the last snmpd log lines come back with
the failure. The server then checks from the monitor that the interface
table answers and restores the backup if it does not.

copy_script() produces the same steps as a shell script to paste into the
host by hand (root or sudo), with the file in a quoted heredoc.
"""

import hashlib
import re
import shlex
import socket
import time
from typing import Any, Dict, List, Optional

import poller

CONF = "/etc/snmp/snmpd.conf"
VIEW = "hmmonitor"
MASK = "••••"
HEREDOC_END = "HM_SNMPD_CONF_END"
# Lines from the old file that are kept: identity of the host and AgentX for subagents.
_KEEP = re.compile(r"^\s*(syslocation|syscontact|sysname|sysservices|master)\b\s*(.*)$", re.I)
_COMMUNITY_FIELD = re.compile(r"^(\s*(?:ro|rw)community6?\s+)(\S+)|^(\s*com2sec6?\s+(?:-Cn\s+\S+\s+)?\S+\s+\S+\s+)(\S+)", re.I)
# What the old file had, by kind, for the plain-words list of changes.
_KINDS = [
    (re.compile(r"^\s*(ro|rw)community6?\b", re.I), "community access line"),
    (re.compile(r"^\s*com2sec6?\b", re.I), "com2sec line"),
    (re.compile(r"^\s*(ro|rw)user\b", re.I), "SNMPv3 user line"),
    (re.compile(r"^\s*createuser\b", re.I), "SNMPv3 user definition"),
    (re.compile(r"^\s*view\b", re.I), "view line"),
    (re.compile(r"^\s*(group|access)\b", re.I), "VACM group or access line"),
    (re.compile(r"^\s*agentaddress\b", re.I), "listening address line"),
    (re.compile(r"^\s*includedir\b|^\s*includefile\b", re.I), "include line"),
    (re.compile(r"^\s*(extend|exec|pass|pass_persist|proc|disk|load)\b", re.I), "extension or check line"),
]

# $S: empty for root, "sudo -n" otherwise (fails at once instead of prompting).
_SUDO = 'S=""; [ "$(id -u)" -eq 0 ] || S="sudo -n"; '
READ_SCRIPT = (
    'if [ "$(id -u)" -eq 0 ]; then echo HM_ROOT=1; else echo HM_ROOT=0; '
    + 'if sudo -n true 2>/dev/null; then echo HM_SUDO=1; else echo HM_SUDO=0; fi; fi; '
    + _SUDO
    + 'if command -v snmpd >/dev/null 2>&1 || [ -x /usr/sbin/snmpd ]; then echo HM_INSTALLED=1; else echo HM_INSTALLED=0; fi; '
    + 'if command -v apt-get >/dev/null 2>&1; then echo HM_APT=1; else echo HM_APT=0; fi; '
    + 'echo "HM_ACTIVE=$(systemctl is-active snmpd 2>/dev/null || true)"; '
    + 'if command -v ufw >/dev/null 2>&1 && $S ufw status 2>/dev/null | grep -q "^Status: active"; then echo HM_UFW=1; else echo HM_UFW=0; fi; '
    + 'echo "HM_DROPINS=$(ls /etc/snmp/snmpd.conf.d 2>/dev/null | tr "\\n" " ")"; '
    + f'echo HM_CONF_BEGIN; $S cat {CONF} 2>/dev/null || true'
)


def apply_script(monitor_ip: str) -> str:
    """Install when missing, back up, write stdin to the config, open ufw for the monitor, restart."""
    ip = shlex.quote(monitor_ip)
    return (
        'set -e; ' + _SUDO
        + 'if ! command -v snmpd >/dev/null 2>&1 && [ ! -x /usr/sbin/snmpd ]; then '
        + '$S env DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null >/dev/null; '
        + '$S env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq snmpd </dev/null >/dev/null; echo INSTALLED=1; fi; '
        + '$S mkdir -p /etc/snmp; '
        + f'if [ -f {CONF} ]; then B="{CONF}.hm-backup-$(date +%Y%m%d%H%M%S)"; $S cp -p {CONF} "$B"; else B=none; fi; '
        + 'echo "BACKUP=$B"; '
        + f'$S tee {CONF}.hm-new >/dev/null; '
        + f'$S chmod 600 {CONF}.hm-new; $S mv {CONF}.hm-new {CONF}; '
        + f'if command -v ufw >/dev/null 2>&1 && $S ufw status 2>/dev/null | grep -q "^Status: active"; then '
        + f'$S ufw allow from {ip} to any port 161 proto udp >/dev/null; echo UFW=1; fi; '
        + '$S systemctl enable snmpd >/dev/null 2>&1 || true; '
        + 'if $S systemctl restart snmpd && sleep 3 && $S systemctl is-active --quiet snmpd; then echo HM_STARTED=1; else '
        + 'echo HM_STARTED=0; $S journalctl -u snmpd -n 12 --no-pager -o cat 2>&1 | sed "s/^/LOG: /"; exit 3; fi'
    )


def snmpd_log(stdout: str) -> str:
    """The snmpd journal lines apply_script prints when snmpd does not start."""
    return "\n".join(l[5:] for l in stdout.splitlines() if l.startswith("LOG: "))


def login_problem(stderr: str) -> Optional[str]:
    """Plain words for the SSH failures people meet first."""
    text = stderr or ""
    if "Permission denied" in text:
        return ("the host refused the login. Check the credential's user and password; Debian and Ubuntu refuse "
                "root password logins by default (PermitRootLogin prohibit-password), so use an SSH key credential "
                "or a user with passwordless sudo")
    if "Host key verification failed" in text or "REMOTE HOST IDENTIFICATION HAS CHANGED" in text:
        return "the host's SSH key differs from the approved one. If the host was reinstalled, approve its new key"
    if "Connection refused" in text:
        return "nothing listens for SSH on that port"
    if "timed out" in text.lower() or "No route to host" in text:
        return "the host did not answer on the SSH port"
    return None


USER_RE = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")
KEY_RE = re.compile(r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]{40,}")


def ssh_setup_script(monitor_ip: str, username: str = "root", public_key: Optional[str] = None) -> str:
    """One command to paste into a host's root shell so this monitor can log in over SSH:
    installs openssh-server when missing, allows password and key logins from the monitor's address
    only (root by key only when the credential has a key, root by password otherwise) (a Match block at the end of sshd_config, between markers, replaced on a
    second run), adds the credential's public key when it has one, checks the file with sshd -t
    (the backup comes back if it fails) and restarts SSH. It sets no password: that stays with you."""
    import ipaddress
    ip = str(ipaddress.ip_address(monitor_ip))
    user = username if USER_RE.fullmatch(username or "") else "root"
    key = None
    if public_key:
        m = KEY_RE.match(public_key.strip())
        key = m.group(0) + " homelab-monitor" if m else None
    lines = [
        'set -e',
        '[ "$(id -u)" -eq 0 ] || { echo "Run this as root: sudo -i first, then paste it again."; exit 1; }',
        'if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server; fi',
        'F=/etc/ssh/sshd_config',
        'cp -p "$F" "$F.homelab-monitor.bak"',
        'sed -i "/^# BEGIN homelab-monitor/,/^# END homelab-monitor/d" "$F"',
        f"printf '%s\\n' '# BEGIN homelab-monitor: SSH logins from the monitor ({ip})' 'Match Address {ip}' "
        "'    PubkeyAuthentication yes' '    PasswordAuthentication yes' "
        f"'    PermitRootLogin {'prohibit-password' if key else 'yes'}' '# END homelab-monitor' >> \"$F\"",
        'mkdir -p /run/sshd',
        'if ! /usr/sbin/sshd -t; then cp -p "$F.homelab-monitor.bak" "$F"; echo "sshd refused the change: the old file is back."; exit 1; fi',
    ]
    if key:
        lines += [
            f'U={user}',
            'H=$(getent passwd "$U" | cut -d: -f6)',
            'if [ -n "$H" ]; then mkdir -p "$H/.ssh"; chmod 700 "$H/.ssh"; touch "$H/.ssh/authorized_keys"; chmod 600 "$H/.ssh/authorized_keys"; '
            f"grep -qF '{key.split()[1]}' \"$H/.ssh/authorized_keys\" || echo '{key}' >> \"$H/.ssh/authorized_keys\"; "
            'chown -R "$U:" "$H/.ssh"; else echo "No user $U on this host: create it, then paste this again."; fi',
        ]
    lines += [
        '(systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true)',
        '(systemctl restart ssh 2>/dev/null || systemctl restart sshd)',
        f'echo "SSH is ready for the monitor ({ip}). Back in the monitor: approve the host key if asked, then Preview changes again."',
    ]
    if not key:
        lines.insert(-1, f'echo "The monitor logs in as {user} with its stored password. No password set for {user} yet? Run: passwd {user}"')
    return "sh -c " + shlex.quote("; ".join(lines))


def parse_read(stdout: str) -> Dict[str, Any]:
    """Splits READ_SCRIPT output into status flags and the current file ("" when absent)."""
    head, _, conf = stdout.partition("HM_CONF_BEGIN\n")
    flags = dict(line.split("=", 1) for line in head.splitlines() if "=" in line)
    return {"installed": flags.get("HM_INSTALLED") == "1", "apt": flags.get("HM_APT") == "1",
            "active": flags.get("HM_ACTIVE", "").strip(), "root": flags.get("HM_ROOT", "1") == "1",
            "sudo": flags.get("HM_SUDO", "1") == "1", "ufw": flags.get("HM_UFW") == "1",
            "dropins": [f for f in flags.get("HM_DROPINS", "").split() if f], "conf": conf}


def rollback_script(backup: str) -> str:
    return (_SUDO + f'$S cp -p {shlex.quote(backup)} {CONF} && $S systemctl restart snmpd')


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def community_problem(community: str) -> Optional[str]:
    """snmpd.conf is whitespace separated: a community with spaces, # or quotes would break the file."""
    if not community:
        return "No SNMP community is set (Settings, SNMP defaults, or the device's Edit dialog)"
    if re.search(r"[\s#\"'\\]", community) or len(community) > 64:
        return "The SNMP community contains spaces, quotes, # or backslashes, which snmpd.conf cannot hold"
    return None


def build_conf(current: str, community: str, monitor_ip: str, now: Optional[float] = None) -> Dict[str, Any]:
    """The complete new snmpd.conf and a plain-words list of what changes."""
    kept: List[str] = []
    counts: Dict[str, int] = {}
    for line in current.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        m = _KEEP.match(line)
        if m and m.group(2).strip():
            key = m.group(1).lower()
            name = {"syslocation": "sysLocation", "syscontact": "sysContact", "sysname": "sysName",
                    "sysservices": "sysServices", "master": "master"}[key]
            if not any(k.split()[0] == name for k in kept):
                kept.append(f"{name:<12} {m.group(2).strip()}")
            continue
        kind = next((label for rx, label in _KINDS if rx.match(line)), "other setting")
        counts[kind] = counts.get(kind, 0) + 1
    if not any(k.startswith("sysLocation") for k in kept):
        kept.insert(0, f"{'sysLocation':<12} Unknown")
    if not any(k.startswith("sysContact") for k in kept):
        kept.insert(1, f"{'sysContact':<12} root")
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
    content = "\n".join([
        f"# snmpd.conf written by Homelab Monitor on {stamp}.",
        f"# Read-only SNMP for the monitor at {monitor_ip} and for this host itself. The previous",
        "# file is kept beside this one as snmpd.conf.hm-backup-<time>.",
        "agentAddress udp:161",
        f"view   {VIEW}  included   .1",
        f"rocommunity  {community} {monitor_ip}/32 -V {VIEW}",
        f"rocommunity  {community} 127.0.0.1 -V {VIEW}",
        *kept,
        "",
    ])
    changes = [f"Writes a clean snmpd.conf: read-only access for this monitor ({monitor_ip}) and the host itself, nothing else",
               "Listens on all IPv4 addresses (UDP 161)"]
    if counts:
        changes.append("Removes from the old file: " + ", ".join(f"{n} {k}{'s' if n > 1 else ''}" for k, n in counts.items()))
    keep_names = [" ".join(k.split()) if k.startswith("master") else k.split()[0] for k in kept
                  if not k.endswith(" Unknown") and " ".join(k.split()) != "sysContact root"]
    if keep_names:
        changes.append("Keeps " + ", ".join(keep_names) + " from the old file")
    return {"content": content, "changes": changes, "removed": counts}


def mask(text: str, secrets: List[str]) -> str:
    """Hides community strings: the value field of community lines, and any known secret elsewhere."""
    out = []
    for line in text.splitlines():
        line = _COMMUNITY_FIELD.sub(lambda m: (m.group(1) or m.group(3)) + MASK, line)
        for s in secrets:
            if s:
                line = line.replace(s, MASK)
        out.append(line)
    return "\n".join(out)


def copy_script(content: str, monitor_ip: str) -> str:
    """The apply steps as a script to paste into the host's shell (as root, or a user with sudo)."""
    assert HEREDOC_END not in content
    return "\n".join([
        "# Homelab Monitor: Fix SNMP by hand. Paste into the host's shell (root, or a user with sudo).",
        'S=""; [ "$(id -u)" -eq 0 ] || S="sudo"',
        "if ! command -v snmpd >/dev/null 2>&1 && [ ! -x /usr/sbin/snmpd ]; then",
        "  $S apt-get update && $S env DEBIAN_FRONTEND=noninteractive apt-get install -y snmpd",
        "fi",
        "$S mkdir -p /etc/snmp",
        f'[ -f {CONF} ] && $S cp -p {CONF} "{CONF}.hm-backup-$(date +%Y%m%d%H%M%S)"',
        f"$S tee {CONF} >/dev/null <<'{HEREDOC_END}'",
        content.rstrip("\n"),
        HEREDOC_END,
        f"$S chmod 600 {CONF}",
        'if command -v ufw >/dev/null 2>&1 && $S ufw status | grep -q "^Status: active"; then',
        f"  $S ufw allow from {monitor_ip} to any port 161 proto udp",
        "fi",
        "$S systemctl enable snmpd",
        "$S systemctl restart snmpd",
        "systemctl --no-pager status snmpd | head -n 5",
        "",
    ])


def source_address(target: str) -> Optional[str]:
    """The address this monitor uses to reach target: what the host sees as the source of SNMP requests.
    A UDP connect only selects a route; no packet is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 9))
            addr = s.getsockname()[0]
            return None if addr.startswith("0.") else addr
    except OSError:
        return None


def verify(device: Dict[str, Any], community: str, attempts: int = 5) -> bool:
    """True when the interface table answers from the monitor: the restricted view hides it."""
    for _ in range(attempts):
        rows = poller.snmp_walk(device["ip_address"], "1.3.6.1.2.1.2.2.1.2", community, device.get("snmp_port") or 161,
                                2.0, 0, max_rows=5)
        if rows:
            return True
        time.sleep(2)
    return False
