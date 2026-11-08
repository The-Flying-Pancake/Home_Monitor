"""Report a problem: a plain-text summary of this monitor for a GitHub issue. Standard library only.

  python3 report.py --db DATA/monitor.db [--app APP_DIR] [--install INSTALL_DIR] [--journal]

Used by Settings, System (Report a problem) in the app and by home_monitor.sh --report on the
Proxmox host, which copies this file into the container and runs it as root (--journal adds the
service's state and the end of its log, which only root can read).

What it holds: versions, how the monitor was installed, the system, device counts by template and
status, a few settings that are only on or off, storage, the update history and recent warnings.
What it never holds: stored passwords, keys or tokens (secret columns are never read), and before
anything is shown, addresses, device names, user names, email addresses, web addresses and anything
that looks like name=secret are masked. Nothing is sent anywhere: the person reads it, then copies it.
"""

import argparse
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALL_DIR = "/etc/homelab-monitor-install"
REPO = "https://github.com/The-Flying-Pancake/Home_Monitor"
ISSUE_URL = REPO + "/issues/new?template=problem.yml"

# --- Masking ---

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b|\b[0-9a-fA-F]{1,4}::[0-9a-fA-F:]*\b")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL = re.compile(r"\b(?:https?|ssh|nfs|smb)://[^\s\"'<>]+", re.I)
_SECRET = re.compile(r"(?i)\b([\w-]*(?:passphrase|password|passwd|token|secret|community|apikey|api_key|key)[\w-]*)(\s*[=:]\s*)(\S+)")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def redact(text: str, names: Iterable[str] = ()) -> str:
    """Addresses, names, emails, web addresses and name=secret pairs masked."""
    text = _ANSI.sub("", text or "")
    text = _URL.sub("<web address>", text)
    text = _EMAIL.sub("<email>", text)
    text = _MAC.sub("<mac>", text)
    text = _IPV4.sub("<address>", text)
    text = _IPV6.sub("<address>", text)
    text = _SECRET.sub(lambda m: m.group(1) + m.group(2) + "••••", text)
    for i, name in enumerate(sorted({n for n in names if n and len(n) >= 3}, key=len, reverse=True)):
        text = re.sub(r"(?i)(?<![\w-])" + re.escape(name) + r"(?![\w-])", "<name>", text)
    return text


# --- Reading (never a secret) ---

def _read(path: str, limit: int = 200_000) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _json(path: str) -> Any:
    try:
        return json.loads(_read(path) or "null")
    except ValueError:
        return None


def app_version(app_dir: str) -> str:
    for line in _read(os.path.join(app_dir, "server.py"), 1_000_000).splitlines():
        if line.startswith("APP_VERSION = "):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def _os_name() -> str:
    for line in _read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.platform()


def _install_kind(install_dir: str) -> str:
    conf = _read(os.path.join(install_dir, "install.conf"))
    m = re.search(r'^TARGET="(\w+)"', conf, re.M)
    if m:
        return {"container": "Proxmox container (home_monitor.sh)", "local": "on a machine of its own (--local)"}.get(m.group(1), m.group(1))
    return "a development copy (not installed with home_monitor.sh)"


def _ago(ts: Any) -> str:
    try:
        s = int(time.time() - float(ts))
    except (TypeError, ValueError):
        return "never"
    if s < 120:
        return f"{s}s ago"
    if s < 7200:
        return f"{s // 60}m ago"
    if s < 172800:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def _when(ts: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return "?"


def _rows(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> List[tuple]:
    try:
        return conn.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []


def build(db: str, app_dir: str = HERE, install_dir: str = INSTALL_DIR, journal: bool = False,
          extra: Optional[Dict[str, Any]] = None) -> str:
    """The report, masked. extra: what only the running monitor knows (uptime, poller, its recent log)."""
    extra = extra or {}
    out: List[str] = []
    names: List[str] = [socket.gethostname()]
    add = out.append

    def free(text: Any) -> str:
        """Text written by devices, people or the system (messages, errors, log lines): names masked too."""
        return redact(str(text), names)

    add("Home Monitor problem report")
    add(f"Made {time.strftime('%Y-%m-%d %H:%M %Z')}. Addresses, names and secrets are masked.")
    add("")
    add("## This monitor")
    built = _read(os.path.join(app_dir, "BUILD"), 100).strip()
    add(f"Version: {app_version(app_dir)}{f', built {built}' if built else ''}")
    add(f"Installed as: {_install_kind(install_dir)}")
    add(f"System: {_os_name()}; Python {platform.python_version()}")
    for k in ("uptime", "poller", "vault"):
        if extra.get(k):
            add(f"{k.capitalize()}: {extra[k]}")

    conn: Optional[sqlite3.Connection] = None
    if os.path.exists(db):
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error:
            conn = None
    add("")
    add("## Devices")
    if conn is None:
        add("The database could not be opened.")
    else:
        names += [r[0] for r in _rows(conn, "SELECT hostname FROM devices;")]
        names += [r[0] for r in _rows(conn, "SELECT username FROM accounts;")]
        total = _rows(conn, "SELECT COUNT(*) FROM devices;")
        add(f"Total: {total[0][0] if total else 0}")
        status = _rows(conn, "SELECT status, COUNT(*) FROM devices GROUP BY status ORDER BY 2 DESC;")
        if status:
            add("By status: " + ", ".join(f"{s} {n}" for s, n in status))
        tpl = _rows(conn, "SELECT profile_id, COUNT(*) FROM devices GROUP BY profile_id ORDER BY 2 DESC;")
        if tpl:
            add("By template: " + ", ".join(f"{p} {n}" for p, n in tpl))
        add("")
        add("## Settings (on or off)")
        wanted = ("telegram_enabled", "telegram_commands", "notify_quiet", "update_auto_check", "demo_mode",
                  "setup_completed", "raw_retention_days", "metric_retention_days", "default_poll_interval",
                  "default_ping_interval")
        got = dict(_rows(conn, f"SELECT key, value FROM settings WHERE key IN ({','.join('?' * len(wanted))});", wanted))
        add(", ".join(f"{k} {got.get(k, '-') or '-'}" for k in wanted))
        add("")
        add("## Last day")
        since = int(time.time()) - 86400
        ev = _rows(conn, "SELECT severity, COUNT(*) FROM events WHERE timestamp > ? GROUP BY severity ORDER BY 2 DESC;", (since,))
        add("Events: " + (", ".join(f"{s} {n}" for s, n in ev) or "none"))
        recent = _rows(conn, "SELECT timestamp, severity, event_type, message FROM events WHERE timestamp > ? "
                             "AND severity IN ('critical', 'high', 'warning') ORDER BY timestamp DESC LIMIT 10;", (since,))
        for ts, sev, kind, msg in recent:
            add(f"  {_when(ts)} {sev} {kind}: {free(str(msg)[:200])}")

    add("")
    add("## Storage")
    for path, label in ((db, "Database"), (db + "-wal", "Database journal")):
        try:
            add(f"{label}: {os.path.getsize(path) / 1048576:.1f} MB")
        except OSError:
            pass
    try:
        u = shutil.disk_usage(os.path.dirname(os.path.abspath(db)))
        add(f"Disk: {u.free / 1073741824:.1f} GB free of {u.total / 1073741824:.1f} GB")
    except OSError:
        pass
    data_dir = os.path.dirname(os.path.abspath(db))
    backups = os.path.join(data_dir, "backups")
    try:
        newest = max((os.path.getmtime(os.path.join(backups, n)) for n in os.listdir(backups) if n.startswith("monitor-backup-")),
                     default=None)
        add(f"Newest backup: {_ago(newest) if newest else 'none in the backup folder'}")
    except OSError:
        add("Newest backup: no backup folder")

    add("")
    add("## Updates")
    check = _json(os.path.join(data_dir, "update-check.result.json")) or {}
    if check:
        add(f"Last check: {_ago(check.get('time'))}, " + (f"newest release {check.get('latest')}" if check.get("ok")
                                                             else f"failed: {free(str(check.get('error'))[:300])}"))
    else:
        add("Last check: never")
    last = _json(os.path.join(data_dir, "update.result.json")) or {}
    if last:
        add(f"Last update or undo: {_ago(last.get('time'))}, " + ("passed" if last.get("ok") else f"failed: {free(str(last.get('error'))[:300])}"))
    history = _json(os.path.join(install_dir, "update-history.json")) or []
    for h in history[:8] if isinstance(history, list) else []:
        if isinstance(h, dict):
            add(f"  {_when(h.get('time'))} {h.get('kind')} {h.get('from') or '?'} to {h.get('to') or '?'}: "
                + ("passed" if h.get("ok") else f"failed ({free(str(h.get('error'))[:200])})"))

    if extra.get("log"):
        add("")
        add("## Recent warnings and errors (the monitor's own log, since it started)")
        out.extend(f"  {free(line)}" for line in extra["log"][-40:])

    if journal:
        add("")
        add("## Service")
        for cmd, label in ((["systemctl", "is-active", "homelab-monitor"], "Monitor service"),
                           (["systemctl", "is-active", "hm-egress"], "Outbound firewall")):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                add(f"{label}: {(r.stdout or r.stderr).strip() or 'unknown'}")
            except (OSError, subprocess.SubprocessError):
                add(f"{label}: could not ask systemd")
        try:
            r = subprocess.run(["journalctl", "-u", "homelab-monitor", "-n", "60", "--no-pager", "-o", "short-iso"],
                               capture_output=True, text=True, timeout=20)
            add("")
            add("## The end of the service log")
            out.extend(f"  {free(line)}" for line in (r.stdout or r.stderr).strip().splitlines()[-60:])
        except (OSError, subprocess.SubprocessError):
            add("The service log could not be read.")

    if conn is not None:
        conn.close()
    return redact("\n".join(out)) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Home Monitor: a problem report to paste into a GitHub issue.")
    ap.add_argument("--db", default=os.environ.get("MONITOR_DB_PATH") or "/var/lib/homelab-monitor/monitor.db")
    ap.add_argument("--app", default=HERE, help="the installed app folder")
    ap.add_argument("--install", default=INSTALL_DIR)
    ap.add_argument("--journal", action="store_true", help="add the service state and log (root only)")
    args = ap.parse_args(argv)
    sys.stdout.write(build(args.db, args.app, args.install, args.journal))
    sys.stdout.write(f"\nTo report it: {ISSUE_URL}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
