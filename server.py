"""Local HTTP server and background polling scheduler for Homelab Monitor.

Provides a multithreaded REST API and static file web server bound strictly
to 127.0.0.1 with zero external dependencies.

Browser-facing defenses: the Host header must name this server (blocks DNS
rebinding), mutating requests must carry a same-origin or absent Origin and
an application/json Content-Type (a cross-site page cannot send that without
a CORS preflight, which this server never approves). Every /api/ route except
the auth routes requires a login session (auth.py), and routes that use
stored credentials need the password confirmed within the last few minutes.
"""

import concurrent.futures
import http.cookies
import http.server
import io
import ipaddress
import json
import logging
import os
import re
import socket
import socketserver
import sqlite3
import ssl
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import alerts
import botcmds
import customoids
import auth
import availability
import changelog
import digest
import forecast
import hostactions
import inventory
import lanhttp
import maintenance
import pihole
import unifi
import proxmox
import taxonomy
import telebot
import tpl
import tls
import database
import poller
import rbac
import totp
import schedule
import ssh_runner
import discovery
import notify
import setup
import sitecheck
import snmpfix
import topology
import workflows
import report
from vault import VAULT, VaultError

WEB_DIR = os.path.join(BASE_DIR, "web")
# 127.0.0.1 on a workstation; the container sets MONITOR_LISTEN=0.0.0.0 to serve the LAN.
LISTEN_HOST = os.environ.get("MONITOR_LISTEN", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("MONITOR_PORT", "8080"))
ALLOWED_HOSTS = {f"127.0.0.1:{LISTEN_PORT}", f"localhost:{LISTEN_PORT}"}
# Extra names the server may be reached by (comma separated, e.g. "monitor,monitor.lan").
ALLOWED_NAMES = {n.strip().lower() for n in os.environ.get("MONITOR_HOSTNAMES", "").split(",") if n.strip()}


def host_allowed(host_header: str) -> bool:
    """DNS rebinding guard: the Host header must name this server.

    Local names always pass. When listening beyond loopback, an IP literal or
    one of MONITOR_HOSTNAMES (plus this machine's own hostname) also passes; an
    attacker's domain that resolves to the LAN address does not.
    """
    host = host_header.strip().lower()
    if host in ALLOWED_HOSTS:
        return True
    if LISTEN_HOST in ("127.0.0.1", "localhost", "::1"):
        return False
    name, sep, port = host.rpartition(":") if not host.endswith("]") else (host, "", "")
    if not sep or port != str(LISTEN_PORT):
        return False
    name = name.strip("[]")
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    own = socket.gethostname().lower()
    return name in ALLOWED_NAMES or name == own or (name.split(".")[0] == own and name.endswith((".lan", ".local", ".home", ".internal")))
MAX_BODY_BYTES = 64 * 1024
# Web server limits, sized for the default 1 GB container. A socket timeout alone restarts on every
# byte, so a request also has a deadline for its request line, headers and body together.
READ_IDLE_SECONDS = 10
READ_TOTAL_SECONDS = 20
WRITE_SECONDS = 60
# A browser opens up to 6 connections per host, so 64 covers about ten busy browsers. One address
# may hold 24 of them. This machine (health checks, the installer and shell scripts) has a few
# more and no per-address limit, so it can still reach the monitor while the cap is full.
MAX_CONNECTIONS = 64
LOCAL_EXTRA_CONNECTIONS = 8
MAX_PER_ADDRESS = 24
BUSY_TEXT = "The monitor is busy. Please try again in a moment."
SLOW_REQUEST_TEXT = "The request took too long to arrive. Please try again."
# Message editor previews per session in each window of seconds.
TEMPLATE_PREVIEW_LIMIT = 120
TEMPLATE_PREVIEW_WINDOW = 60
# Spelled out per kind, so a later default-src change cannot widen scripts or styles by accident.
# img-src data: is for the 2FA QR code, shown as a data: image.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

STATIC_FILES = {
    "": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/map.js": ("map.js", "application/javascript; charset=utf-8"),
    "/workflows.js": ("workflows.js", "application/javascript; charset=utf-8"),
    "/wftemplates.js": ("wftemplates.js", "application/javascript; charset=utf-8"),
    "/hostactions.js": ("hostactions.js", "application/javascript; charset=utf-8"),
    "/telegram.js": ("telegram.js", "application/javascript; charset=utf-8"),
    "/workflows.css": ("workflows.css", "text/css; charset=utf-8"),
    "/setup.js": ("setup.js", "application/javascript; charset=utf-8"),
    "/alerts.js": ("alerts.js", "application/javascript; charset=utf-8"),
    "/snmp.js": ("snmp.js", "application/javascript; charset=utf-8"),
    "/theme.js": ("theme.js", "application/javascript; charset=utf-8"),
    "/shell.js": ("shell.js", "application/javascript; charset=utf-8"),
    "/users.js": ("users.js", "application/javascript; charset=utf-8"),
    "/security.js": ("security.js", "application/javascript; charset=utf-8"),
    "/adddevice.js": ("adddevice.js", "application/javascript; charset=utf-8"),
    "/backups.js": ("backups.js", "application/javascript; charset=utf-8"),
    "/updates.js": ("updates.js", "application/javascript; charset=utf-8"),
    "/charts.js": ("charts.js", "application/javascript; charset=utf-8"),
    "/availability.js": ("availability.js", "application/javascript; charset=utf-8"),
    "/proxmox.js": ("proxmox.js", "application/javascript; charset=utf-8"),
    "/taxonomy.js": ("taxonomy.js", "application/javascript; charset=utf-8"),
    "/tls.js": ("tls.js", "application/javascript; charset=utf-8"),
    "/changes.js": ("changes.js", "application/javascript; charset=utf-8"),
    "/lan.js": ("lan.js", "application/javascript; charset=utf-8"),
    "/inventory.js": ("inventory.js", "application/javascript; charset=utf-8"),
    "/botcmds.js": ("botcmds.js", "application/javascript; charset=utf-8"),
    "/guide.js": ("guide.js", "application/javascript; charset=utf-8"),
    "/guide.html": ("guide.html", "text/html; charset=utf-8"),
}

# Settings schema: the single definition of every global setting, its section
# on the settings page, type, range, default and help text. Values are stored
# as text in the settings table; validation and typed reads use this schema.
SETTINGS_SCHEMA = [
    # key, section, label, type, unit, min, max, default, help
    ("default_snmp_community", "snmp", "Community string", "secret", "", None, None, "public",
     "Default SNMPv2c community for new devices. Each device can override it, or use SNMPv3 instead (Add or Edit device)."),
    ("default_snmp_port", "snmp", "SNMP port", "int", "UDP", 1, 65535, "161", "Standard agents listen on 161."),
    ("default_poll_interval", "polling", "SNMP poll interval", "int", "s", 10, 86400, "300",
     "How often metrics and tables are collected. Lower means finer graphs and a larger database."),
    ("default_ping_interval", "polling", "Ping interval", "int", "s", 5, 86400, "60",
     "How often reachability and latency are checked."),
    ("default_timeout", "polling", "Request timeout", "float", "s", 0.5, 10.0, "2.0",
     "Wait per SNMP request before retrying."),
    ("default_retries", "polling", "Retries", "int", "", 0, 5, "2", "Extra attempts per SNMP request."),
    ("live_interval", "live", "Live refresh interval", "int", "s", 5, 60, "5",
     "Poll rate for the device page you are viewing. Live samples stay in memory and are never written."),
    ("live_max_devices", "live", "Live devices at once", "int", "", 1, 4, "2",
     "Caps extra load when several device pages are open."),
    ("wan_sample_interval", "polling", "WAN peak sampling", "int", "s", 0, 60, "10",
     "Reads the WAN counters this often and stores the highest rate seen per poll interval, so short bursts such as a speed test show up. 0 turns it off."),
    ("problem_resolve_minutes", "alerts", "Resolve after", "int", "min", 0, 120, "5",
     "A threshold problem must stay clear this long before it counts as resolved. Prevents flapping. Reachability resolves immediately."),
    ("raw_retention_days", "retention", "Raw samples", "int", "days", 1, 90, "7",
     "Full-resolution history. Older data is kept as hourly averages."),
    ("metric_retention_days", "retention", "Hourly trends", "int", "days", 7, 3650, "365",
     "Hourly min / avg / max kept for long-range graphs."),
    ("audit_retention_days", "retention", "Audit log", "int", "days", database.AUDIT_RETENTION_FLOOR, 3650, "90",
     "Who did what in the app. Kept for at least 90 days, so a change cannot be hidden by shortening this."),
    ("event_retention_days", "retention", "Events", "int", "days", 1, 3650, "90",
     "Device and system events shown on the Events page."),
    ("require_2fa", "login", "Require two-factor authentication", "select:off,admins,all", "", None, None, "off",
     "Off means each person chooses. With admins, every administrator must use it. With all, everyone must. "
     "Anyone it covers sets it up straight after their next password. While this is on, changes that ask for the "
     "highest confirmation need two-factor authentication for everyone. To turn it on, your own account needs it first."),
    ("update_auto_check", "updates", "Check for updates every day", "select:on,off", "", None, None, "on",
     "Looks for a new version once a day and shows a red number on Settings when one is ready. "
     "Nothing is installed until you choose to."),
    ("telegram_enabled", "notify", "Telegram notifications", "select:off,on", "", None, None, "off",
     "Sends messages through a Telegram bot. This is the app's only internet connection (api.telegram.org)."),
    ("telegram_token", "notify", "Bot token", "secret", "", None, None, "",
     "From @BotFather. Stored encrypted; never shown again after saving."),
    ("telegram_chat_id", "notify", "Chat ID", "text", "", None, None, "",
     "Filled in by Find my chat after you send the bot a message."),
    ("telegram_commands", "notify", "Answer commands", "select:on,off", "", None, None, "on",
     "The bot answers /status, /problems, /device NAME and /changes from your chat, read only. "
     "Messages from any other chat are ignored."),
] + [
    (f"bot_tpl_{key}", "notify", label, "template", "", None, None, default, help_)
    for key, (label, help_, default, _presets) in telebot.TEMPLATES.items()
] + [
    ("notify_quiet", "notify", "Quiet hours", "select:off,on", "", None, None, "off",
     "Holds non-critical messages and sends one summary when quiet hours end. Critical problems always go straight away."),
    ("notify_min_severity", "notify", "Send problems from", "select:warning,info,high,critical", "", None, None, "warning",
     "Problems at this severity and above are sent. Each alert rule can override this (always or never) under Alert rules."),
    ("notify_repeat_hours", "notify", "Repeat reminders", "int", "h", 0, 168, "0",
     "Resend a reminder for a problem that is still open and not acknowledged, every this many hours. 0 turns it off."),
    ("notify_repeat_severity", "notify", "Remind from", "select:critical,high,warning,info", "", None, None, "critical",
     "Reminders are sent for problems at this severity and above."),
    ("notify_quiet_start", "notify", "Quiet from", "time", "", None, None, "22:00", "Local time, 24-hour."),
    ("notify_quiet_end", "notify", "Quiet until", "time", "", None, None, "07:00", "Local time, 24-hour."),
    ("notify_silent", "notify", "Silent window", "select:off,on", "", None, None, "off",
     "Messages still arrive straight away but make no sound on the phone (a maintenance window, the night). "
     "Unlike quiet hours nothing is held back. Each alert rule can choose Always ring or Always silent under Alert rules."),
    ("notify_silent_start", "notify", "Silent from", "time", "", None, None, "22:00", "Local time, 24-hour."),
    ("notify_silent_end", "notify", "Silent until", "time", "", None, None, "07:00", "Local time, 24-hour."),
    ("notify_silent_sound_from", "notify", "Still ring from", "select:critical,high,warning,none", "", None, None, "critical",
     "Problems at this severity and above still make a sound during the silent window (device offline is critical). "
     "Back online and resolved messages never ring. None: everything is silent."),
    ("notify_group", "notify", "Group messages that come at once", "select:on,off", "", None, None, "on",
     "When several devices go down or come back together (restarting access points, a switch), you get one message "
     "listing them instead of one each. Problem and device messages wait a few seconds to see whether more follow."),
    ("notify_group_seconds", "notify", "Wait to group", "int", "s", 5, 600, "30",
     "Messages wait until none has come for this long, so machines shut down one after another end up in one message "
     "(at most four times this after the first). Longer groups more, but every message is that much later."),
    ("notify_group_min", "notify", "Group from", "int", "messages", 2, 50, "3",
     "Fewer than this many are sent one by one as usual."),
    ("notify_new_devices", "notify", "Message about devices just added", "select:off,on", "", None, None, "off",
     "Off: problems that open in the first minutes after a device is added (setup, scan or Add) are logged but not sent, "
     "so adding many devices does not flood the chat. Later problems and recoveries follow the alert rules as usual."),
    ("notify_new_device_minutes", "notify", "Quiet for new devices", "int", "min", 1, 1440, "30",
     "How long a newly added device stays quiet."),
    ("notify_digest", "notify", "Summary message", "select:off,daily,weekly", "", None, None, "off",
     "A short summary on Telegram: availability, problems, new devices on the network, volumes filling up and "
     "certificates running out. Off by default."),
    ("notify_digest_day", "notify", "Weekly summary on", "select:monday,tuesday,wednesday,thursday,friday,saturday,sunday",
     "", None, None, "monday", "Only for the weekly summary."),
    ("notify_digest_time", "notify", "Send the summary at", "time", "", None, None, "08:00", "Local time, 24-hour."),
] + [row for kind, (label, on, tpl) in notify.EVENTS.items() for row in (
    # Problem messages are switched per alert rule; only the other events have an on / off setting.
    (f"notify_on_{kind}", "notify", label, "select:on,off" if on else "select:off,on", "", None, None, "on" if on else "off", ""),
    (f"notify_tpl_{kind}", "notify", f"{label}: message", "template", "", None, None, tpl, ""),
) if on is not None or row[0].startswith("notify_tpl_")]
SETTINGS = {row[0]: dict(zip(("key", "section", "label", "type", "unit", "min", "max", "default", "help"), row))
            for row in SETTINGS_SCHEMA}


def get_setting(settings: Dict[str, str], key: str):
    """Reads a typed setting value, falling back to the schema default when invalid."""
    spec = SETTINGS[key]
    raw = settings.get(key, spec["default"])
    kind = {"int": int, "float": float}.get(spec["type"])
    if kind is None:
        return raw
    try:
        value = kind(raw)
    except ValueError:
        return kind(spec["default"])
    return min(spec["max"], max(spec["min"], value))

log = logging.getLogger("server")

_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class AuthRequired(Exception):
    """401 or 403 that tells the frontend which prompt to show (setup, login or confirm)."""

    def __init__(self, status: int, message: str, mode: str, extra: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.mode = mode
        self.extra = extra or {}


class RequestError(Exception):
    """Client error mapped to an HTTP status and JSON error message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _lockout_error(wait: float) -> RequestError:
    """The 429 shown while a client or username is locked out after failed passwords or codes."""
    return RequestError(429, f"Too many failed attempts. Try again in {int(wait) + 1} seconds")


class ActionError(RequestError):
    """An action the user asked for that cannot be done (no credential, host key not approved,
    vault locked). Unlike a form validation error it is recorded as an event, so it reaches
    the notification centre and the event log."""

    def __init__(self, status: int, message: str, device_id: Optional[int] = None) -> None:
        super().__init__(status, message)
        self.device_id = device_id


# --- Input Validation ---

def is_valid_host(host_str: str) -> bool:
    """Checks for an IPv4 literal or an RFC 1123 hostname.

    Validates per label with a bounded pattern; a single pattern with nested
    quantifiers over the whole name backtracks exponentially.
    """
    if not host_str or len(host_str) > 253:
        return False
    try:
        ipaddress.IPv4Address(host_str)
        return True
    except ValueError:
        pass
    # Dotted all-numeric strings that failed IPv4 parsing (e.g. 999.1.1.1) are typos, not names.
    if re.fullmatch(r"[\d.]+", host_str):
        return False
    return all(_LABEL.fullmatch(label) for label in host_str.split("."))


def validate_target_address(address: str) -> str:
    """Accepts an IPv4 literal, or a hostname that currently resolves to IPv4.

    Unresolvable names are rejected so that a device name typed into the
    address field is caught at save time rather than polled forever.
    """
    if not is_valid_host(address):
        raise RequestError(400, f"'{address}' is not a valid IPv4 address or hostname (example: 192.168.1.10)")
    try:
        ipaddress.IPv4Address(address)
        return address
    except ValueError:
        pass
    try:
        socket.getaddrinfo(address, None, socket.AF_INET)
    except (socket.gaierror, UnicodeError):
        raise RequestError(400, f"'{address}' does not resolve. Enter the device's IP address (example: 192.168.1.10)")
    return address


def _get_str(payload: Dict[str, Any], key: str, default: str = "", max_len: int = 255) -> str:
    value = payload.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise RequestError(400, f"'{key}' must be a string")
    value = value.strip()
    if len(value) > max_len:
        raise RequestError(400, f"'{key}' exceeds {max_len} characters")
    return value


def _get_int(payload: Dict[str, Any], key: str, default: Optional[int], lo: int, hi: int) -> Optional[int]:
    value = payload.get(key, default)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise RequestError(400, f"'{key}' must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise RequestError(400, f"'{key}' must be an integer")
    if isinstance(value, float) and value != number:
        raise RequestError(400, f"'{key}' must be an integer")
    if not lo <= number <= hi:
        raise RequestError(400, f"'{key}' must be between {lo} and {hi}")
    return number


def _known_profile_ids() -> set:
    return {p["profile_id"] for p in poller.load_hardware_profiles()}


SERVICE_PROFILE = "service_check"
PING_PROFILE = "ping_only"


def profile_uses_snmp(profile_id: Optional[str], profiles: Optional[Dict[str, Dict[str, Any]]] = None) -> bool:
    """False for templates without SNMP (ping only, port and web checks): nothing is sent over SNMP."""
    profiles = profiles or {p["profile_id"]: p for p in poller.load_hardware_profiles()}
    return (profiles.get(profile_id or "") or {}).get("snmp", True) is not False


def parse_device_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validates and normalizes an add or edit device request body."""
    profile_id = _get_str(payload, "profile_id", "generic_device", max_len=64)
    if profile_id not in _known_profile_ids():
        raise RequestError(400, f"Unknown profile '{profile_id}'")
    web_check = profile_id == SERVICE_PROFILE and payload.get("service_kind") == "http"
    # A web check takes its host from the URL (below); everything else needs the address field.
    ip_address = "" if web_check else validate_target_address(_get_str(payload, "ip_address", max_len=253))
    hostname = _get_str(payload, "hostname", max_len=128) or ip_address
    # Port checks (the service_check template) need a TCP port; every other template has none (0).
    service_port = 0
    service = None
    if profile_id == SERVICE_PROFILE:
        kind = _get_str(payload, "service_kind", "tcp", max_len=8)
        if kind not in ("tcp", "http"):
            raise RequestError(400, "service_kind must be tcp or http")
        if kind == "http":
            # A web check: the URL decides host and port; ping goes to the same host.
            url = _get_str(payload, "service_url", max_len=500)
            u = urlparse(url)
            if u.scheme not in ("http", "https") or not u.hostname:
                raise RequestError(400, "Enter the full address of the page, for example https://192.168.1.20:8443/health")
            ip_address = validate_target_address(u.hostname)
            try:
                service_port = u.port or (443 if u.scheme == "https" else 80)
            except ValueError:
                raise RequestError(400, "The port in that address is not valid")
            raw = payload.get("service_expect") or {}
            if not isinstance(raw, dict):
                raise RequestError(400, "service_expect must be an object")
            status = str(raw.get("status") or "200-399").replace(" ", "")[:40]
            if not re.fullmatch(r"\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*", status):
                raise RequestError(400, "Expected status: codes or ranges such as 200-399 or 200,204")
            service = {"service_kind": "http", "service_url": url,
                       "service_expect": {"status": status, "keyword": str(raw.get("keyword") or "")[:200],
                                          "insecure": raw.get("insecure") is True}}
            hostname = _get_str(payload, "hostname", max_len=128) or url
        else:
            service_port = _get_int(payload, "service_port", None, 1, 65535)
            if not service_port:
                raise RequestError(400, "A port check needs the service port (1 to 65535), for example 443")
            service = {"service_kind": "tcp", "service_url": None, "service_expect": {}}
    extra = None
    if any(k in payload for k in ("device_group", "upstream_device_id", "overrides")):
        group = _get_str(payload, "device_group", "", max_len=40)
        if group and group not in taxonomy.group_ids():
            raise RequestError(400, "Unknown device group")
        upstream = payload.get("upstream_device_id")
        if upstream in ("", None):
            upstream = None
        elif not (isinstance(upstream, int) and not isinstance(upstream, bool)) or not database.get_device(upstream):
            raise RequestError(400, "The upstream device does not exist")
        raw = payload.get("overrides") or {}
        if not isinstance(raw, dict):
            raise RequestError(400, "overrides must be an object")
        overrides = {k: str(v).strip()[:128] for k, v in raw.items() if k in OVERRIDE_FIELDS and str(v or "").strip()}
        extra = {"device_group": group or None, "upstream_device_id": upstream,
                 "upstream_port": (_get_str(payload, "upstream_port", "", max_len=32) or None) if upstream else None,
                 "overrides": overrides}
    tags = None
    if "tags" in payload:
        if not isinstance(payload["tags"], list) or not all(isinstance(t, str) for t in payload["tags"]):
            raise RequestError(400, "tags must be a list of names")
        try:
            tags = [taxonomy.normalise_tag(t) for t in payload["tags"] if str(t).strip()]
        except taxonomy.TaxonomyError as exc:
            raise RequestError(400, str(exc))
    return {
        "_extra": extra,
        "_tags": tags,
        "_service": service,
        "service_port": service_port,
        "hostname": hostname,
        "ip_address": ip_address,
        "profile_id": profile_id,
        # Empty means "unchanged" on edit and "use the default community" on add: the
        # browser never receives stored community strings, so it cannot echo them back.
        "snmp_community": _get_str(payload, "snmp_community", "", max_len=128) or None,
        "_snmp": parse_snmp_v3(payload),
        "snmp_port": _get_int(payload, "snmp_port", 161, 1, 65535),
        "poll_interval": _get_int(payload, "poll_interval", None, 10, 86400),
        "ping_interval": _get_int(payload, "ping_interval", None, 5, 86400),
    }


_CRED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.@-]{0,63}")


def workflow_fields(name: str, description: str, graph: Dict[str, Any], is_active: bool) -> Dict[str, Any]:
    """Row fields for a validated graph: the schedule on its trigger becomes trigger_type, cron and run_at."""
    sched = workflows.graph_trigger(graph)["schedule"]
    trigger_type, cron, run_at = schedule.to_trigger(sched)
    return {"name": name, "description": description, "graph": graph, "steps": workflows.step_order(graph),
            "schedule": sched, "trigger_type": trigger_type, "trigger_cron": cron, "run_at": run_at, "is_active": is_active}


def parse_workflow_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validates a workflow: name and either a graph from the editor (see workflows.parse_graph)
    or the older step list with trigger_type and trigger_cron."""
    name = _get_str(payload, "name", max_len=80)
    if not name:
        raise RequestError(400, "A workflow name is required")
    devices = {d["id"] for d in database.list_devices()}
    creds = {c["id"] for c in database.list_credentials()}
    try:
        if "graph" in payload:
            graph = workflows.parse_graph(payload.get("graph"), devices, creds)
        else:
            trigger_type = _get_str(payload, "trigger_type", "manual", max_len=16)
            if trigger_type not in ("manual", "schedule"):
                raise RequestError(400, "Trigger must be manual or schedule")
            sched = {"kind": "manual"}
            if trigger_type == "schedule":
                sched = schedule.parse(schedule.from_cron(_get_str(payload, "trigger_cron", "", max_len=100) or "-"))
            graph = workflows.steps_to_graph(workflows.parse_steps(payload.get("steps"), devices, creds), sched)
    except (workflows.WorkflowError, schedule.ScheduleError) as exc:
        message = str(exc)
        raise RequestError(400, message if isinstance(exc, workflows.WorkflowError) else f"Schedule: {message}")
    return workflow_fields(name, _get_str(payload, "description", "", max_len=500), graph,
                           payload.get("is_active", True) is not False)


def workflow_view(wf: Dict[str, Any]) -> Dict[str, Any]:
    """A workflow as the editor uses it: graph and schedule filled in for rows saved before the graph editor."""
    out = dict(wf)
    if not out.get("schedule"):
        out["schedule"] = schedule.from_cron(wf["trigger_cron"]) if wf["trigger_type"] == "schedule" else {"kind": "manual"}
    if not out.get("graph"):
        out["graph"] = workflows.steps_to_graph(wf["steps"], out["schedule"])
    out["schedule_text"] = schedule.describe(out["schedule"])
    if out["schedule"].get("kind") == "event":
        out["schedule_text"] = workflows.event_text(out["schedule"], {d["id"]: d["hostname"] for d in database.list_devices()},
                                                    {customoids.metric_key(c["id"]): c["label"] for c in customoids.all_defs()})
    return out


def password_credential_ids() -> set:
    return {c["id"] for c in database.list_credentials() if c["cred_type"] == "password"}


def check_password_credential(user: Any, cred_id: Optional[int]) -> None:
    """A stored password may log in to any address it is pointed at, so using one needs Manage
    credentials (administrators have it)."""
    if cred_id and cred_id in password_credential_ids() and not user.can("credentials.manage"):
        raise RequestError(403, "Using a stored password needs the Manage credentials permission. Use an SSH key credential instead.")


def check_credential_use(user: Any, cred_id: Optional[int]) -> None:
    """Logging in to a host with a stored credential needs Use stored credentials, and a password
    credential also needs Manage credentials. The password rule is checked first."""
    check_password_credential(user, cred_id)
    if cred_id and not user.can("credentials.use"):
        raise RequestError(403, "Using a stored credential needs the Use stored credentials permission.")


def workflow_rights_problem(user: rbac.User, wf: Dict[str, Any]) -> Optional[str]:
    """Why this user may not save or run the workflow unattended, or None: a device outside their
    device access, a password credential without Manage credentials, or a command step without
    Use stored credentials. Saving, running by hand and scheduled runs all use this one rule."""
    reach = workflow_reach_problem(user, wf)
    if reach:
        return reach
    commands = [s for s in wf["steps"] if s.get("type") == "command"]
    passwords = password_credential_ids()
    if not user.can("credentials.manage") and any(s.get("credential_id") in passwords for s in commands):
        return "it logs in with a stored password, which needs the Manage credentials permission"
    if commands and not user.can("credentials.use"):
        return "it runs commands with a stored credential, which needs the Use stored credentials permission"
    return None


def workflow_author_problem(wf: Dict[str, Any]) -> Optional[str]:
    """Checked when a scheduled or event run starts: the user who last saved the workflow must still
    exist, not be blocked, may run or edit workflows and reach every device in it. Workflows saved
    before the author was recorded have none and run as before (the next save records one)."""
    author = wf.get("saved_by")
    if not author:
        return None
    account = database.get_user(author)
    if account is None:
        return f"the user who last saved it ({author}) no longer exists"
    if account.get("disabled"):
        return f"the user who last saved it ({author}) is blocked"
    user = rbac.User(account)
    if not user.can(("automation.edit", "automation.run")):
        return f"the user who last saved it ({author}) may no longer run or edit workflows"
    if user.scope is not None:
        user.bind_devices(database.device_profiles())
    return workflow_rights_problem(user, wf)


def workflow_reach_problem(user: rbac.User, wf: Dict[str, Any]) -> Optional[str]:
    """Why the workflow reaches past the user's device access, or None. Unscoped users reach everything.
    Fail closed: a guest that is not in the Proxmox layout yet counts as outside."""
    if user.scope is None:
        return None
    reach = workflows.reach_of(wf)
    if any(not user.sees_id(h) for h in reach["devices"]):
        return "it uses devices outside the device access of " + user.username
    for scope, target in reach["mutes"]:
        if scope == "all":
            return "it keeps every device quiet, which needs access to every device"
        if not maintenance_in_scope(user, scope, target):
            return "it keeps a group or tag quiet that reaches outside the device access of " + user.username
    if reach["guests"]:
        mapped = {(g.get("node"), g.get("vmid")): g.get("device_id") for g in proxmox.layout().get("guests", [])}
        for guest in reach["guests"]:
            if not mapped.get(guest) or not user.sees_id(mapped[guest]):
                return "it snapshots a Proxmox guest outside the device access of " + user.username
    return None


def workflows_in_scope(user: rbac.User, rows: List[Dict[str, Any]], key: str = "id") -> List[Dict[str, Any]]:
    """Workflows (or their runs, key="workflow_id") that stay inside the user's device access."""
    if user.scope is None:
        return rows
    outside = {w["id"] for w in database.list_workflows() if workflow_reach_problem(user, w)}
    return [r for r in rows if r[key] not in outside]


def maintenance_in_scope(user: rbac.User, scope: str, target: str) -> bool:
    """Whether a maintenance window stays inside the user's device access. A group or tag must have
    members and every member must be inside (the same matching the alerts use); an empty one could
    later fill with devices the user cannot see. Every device needs access to every device."""
    if user.scope is None:
        return True
    if scope == "all":
        return False
    if scope == "device":
        return str(target).isdigit() and user.sees_id(int(target))
    w = {"scope": scope, "target": str(target or "")}
    members = [d["id"] for d in database.list_devices() if maintenance.covers(w, with_group(d))]
    return bool(members) and all(user.sees_id(i) for i in members)


def maintenance_view(user: rbac.User, windows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The windows this user may see: those inside their device access."""
    if user.scope is None:
        return windows
    return [w for w in windows if maintenance_in_scope(user, w["scope"], w["target"])]


WORKFLOW_SCOPE_MARKER = "checked_workflow_scope"


def check_workflow_scope() -> int:
    """Once per database: counts saved workflows whose author is limited to some devices and that
    would now be skipped, and tells administrators once. Nothing is changed."""
    if database.get_all_settings().get(WORKFLOW_SCOPE_MARKER) == "1":
        return 0
    found = 0
    for wf in database.list_workflows():
        account = database.get_user(wf["saved_by"]) if wf.get("saved_by") else None
        if account and rbac.scope_of(account) is not None and workflow_author_problem(wf):
            found += 1
    if found:
        _notify_admins(f"{found} saved workflow(s) reach further than the person who saved them can now reach, so they "
                       "will be skipped when they are due. Open them and save them again as someone allowed to run them.")
    database.set_internal_setting(WORKFLOW_SCOPE_MARKER, "1")
    return found


CREDENTIALS_USE_MARKER = "migrated_credentials_use"
# Custom users holding any of these could already log in to hosts with a stored credential
# somewhere (workflows, host actions, Fix SNMP, the credential test), so they keep that on upgrade.
CREDENTIALS_USE_FROM = ("automation.edit", "automation.run", "devices.manage", "credentials.manage")


def migrate_credentials_use() -> int:
    """Once per database: gives the new Use stored credentials permission to custom users who could
    already use stored credentials, so nobody silently loses anything. Each grant is audited and
    every active administrator gets one notice. Built-in roles need nothing: their permissions are
    worked out when read. The marker stops a later grant to someone it was taken from on purpose."""
    if database.get_all_settings().get(CREDENTIALS_USE_MARKER) == "1":
        return 0
    given = 0
    for account in database.list_users():
        if (account.get("role") or "") != "custom":
            continue
        perms = rbac.permissions_for(account)
        if "credentials.use" in perms or not perms & set(CREDENTIALS_USE_FROM):
            continue
        database.update_user(account["username"], {"permissions": json.dumps(rbac.parse_permissions(
            sorted(perms | {"credentials.use"})))})
        database.add_audit("users", f"Gave {account['username']} the Use stored credentials permission",
                           "Automatic on upgrade: they could already run or edit workflows, run Fix SNMP or test a credential")
        given += 1
    if given:
        _notify_admins(f"Home Monitor now has a Use stored credentials permission. {given} user(s) who could already run or "
                       "edit workflows, run Fix SNMP or test a credential were given it, so nothing changes for them. "
                       "The audit log names each one. You can change this in Settings, Users.")
    database.set_internal_setting(CREDENTIALS_USE_MARKER, "1")
    return given


def _notify_admins(text: str) -> None:
    """One notice in the bell of every active administrator."""
    for account in database.list_users():
        if account.get("role") == "admin" and not account.get("disabled"):
            database.add_event(None, "warning", "action", text, actor=account["username"])


RETENTION_RAISED_DETAIL = "Automatic on upgrade: the audit log is now kept for at least 90 days"


def migrate_retention(existing: Dict[str, str]) -> bool:
    """Once, before the settings are filled in: events keep exactly the retention they had, and the
    audit log is raised to the floor when it was shorter. True when it was raised. Reads the stored
    value itself, because get_setting would already clamp it."""
    if "event_retention_days" in existing:
        return False
    try:
        days = max(1, min(3650, int(existing.get("audit_retention_days") or 90)))
    except ValueError:
        days = 90
    database.set_internal_setting("event_retention_days", str(days))
    if days >= database.AUDIT_RETENTION_FLOOR:
        return False
    database.update_setting("audit_retention_days", str(database.AUDIT_RETENTION_FLOOR))
    database.add_audit("settings", f"Audit log retention raised from {days} to {database.AUDIT_RETENTION_FLOOR} days",
                       RETENTION_RAISED_DETAIL)
    return True


SECURITY_NOTICE_MARKER = "notice_security_0_12"


def security_notice(existing: Dict[str, str], has_accounts: bool, raised: bool) -> None:
    """Once per database (Q14): tells administrators that security alerts are on and, when it applies,
    that the audit log is now kept for at least 90 days. A fresh install has nothing to be told."""
    if existing.get(SECURITY_NOTICE_MARKER) == "1":
        return
    if has_accounts:
        parts = []
        s = database.get_all_settings()
        if s.get("telegram_enabled") == "on":
            parts.append("Home Monitor now sends a Telegram alert for security events such as a new user, a changed "
                         "credential or an approved host key. You can turn this off in Settings, Notifications.")
        if raised:
            parts.append("The audit log is now kept for at least 90 days.")
        parts.append("You can also require two-factor authentication in Settings, Login security.")
        if parts:
            _notify_admins(" ".join(parts))
    database.set_internal_setting(SECURITY_NOTICE_MARKER, "1")


# --- Required after an update ---
# Steps an install must have done before it is used, such as a backup passphrase: an update that
# brings one adds it here. While a step is needed, an administrator who can do it sees a screen
# that locks the app (only REQUIRED_ROUTES answer) until the check passes; everyone else only sees
# a note. The check is cheap: it runs on every request.

def backup_passphrase_needed() -> bool:
    """An installed monitor with no backup passphrase (and none being saved right now)."""
    conf = os.environ.get("MONITOR_INSTALL_CONF", "")
    if not conf or not os.path.isfile(conf):
        return False                        # a development copy: no root helper, no backups of its own
    if os.path.exists(os.path.join(os.path.dirname(conf), "backup-passphrase")):
        return False
    data_dir = os.path.dirname(os.path.abspath(database.DB_FILE))
    return not os.path.exists(os.path.join(data_dir, "requests", PASSPHRASE_REQUEST))


REQUIRED_STEPS = [
    {"id": "backup_passphrase", "permission": "settings.system", "needed": backup_passphrase_needed,
     "title": "Set a backup passphrase",
     "why": ("Without it, backups that leave this box cannot carry the key to your stored passwords, so a rebuild "
             "would lose them. No backup can be proven unchanged either. It takes a minute. Keep the passphrase in "
             "your password manager, apart from the backups."),
     "other_way": "Or in the container's console as root: /root/backup-passphrase.sh"},
]
REQUIRED_TEXT = "Finish a required step to continue"
# What answers while a required step locks the app: the screen's own status, the step itself (with
# its password confirmation), What's changed and logging out. /api/auth/* is open anyway.
REQUIRED_ROUTES = {("GET", "/api/required"), ("POST", "/api/backups/passphrase"), ("GET", "/api/changes"),
                   ("POST", "/api/changes/seen")}


def required_steps(user: "rbac.User") -> Dict[str, list]:
    """The steps needed now: "mine" (this user can do them, so they lock the app) and "others"
    (an administrator has to)."""
    mine, others = [], []
    for step in REQUIRED_STEPS:
        try:
            needed = step["needed"]()
        except Exception:
            log.exception("Required step check %s failed", step["id"])
            needed = False
        if not needed:
            continue
        public = {k: step[k] for k in ("id", "title", "why", "other_way")}
        if user.can(step["permission"]) and user.scope is None:
            mine.append(public)
        else:
            others.append({"id": step["id"], "title": step["title"]})
    return {"mine": mine, "others": others}



TWO_FACTOR_RULES = ("off", "admins", "all")
ENROL_TEXT = "Set up two-factor authentication to continue"
TIER3_NEEDS_2FA_TEXT = "This action needs two-factor authentication. Turn it on in Settings, Account."
# What a person who must set up 2FA can still reach: the setup itself, the password step it asks
# for and logging out (the status is public and answered before this check).
ENROL_ROUTES = {("GET", "/api/auth/2fa"), ("POST", "/api/auth/2fa/start"), ("POST", "/api/auth/2fa/enable"),
                ("POST", "/api/auth/confirm"), ("POST", "/api/auth/logout")}


def two_factor_rule() -> str:
    """require_2fa: off, admins or all. Read on every request, without decrypting anything."""
    rule = database.get_plain_setting("require_2fa", "off")
    return rule if rule in TWO_FACTOR_RULES else "off"


def two_factor_covers(account: Dict[str, Any], rule: Optional[str] = None) -> bool:
    """Whether the rule requires 2FA of this account (whether or not it has it)."""
    rule = two_factor_rule() if rule is None else rule
    return rule == "all" or (rule == "admins" and (account.get("role") or "admin") == "admin")


def must_enrol(account: Optional[Dict[str, Any]]) -> bool:
    """An account the rule covers that has no 2FA yet. Never while the vault is locked: no secret could
    be stored, so nobody must be stopped at a form that cannot succeed."""
    if not account or account.get("totp_enabled") or not VAULT.enabled:
        return False
    return two_factor_covers(account)


def security_alert(key: str, who: Optional[str] = None, source: Optional[str] = None, **values: Any) -> None:
    """A Telegram security alert (notify.SECURITY_TEXTS), naming who did it and from where (the
    thread's audit context unless given). It never breaks the action it reports."""
    try:
        actor, src = database.audit_identity()
        who = actor if who is None else who
        NOTIFIER.security(key, who="" if who == "system" else who, source=src if source is None else source, **values)
    except Exception:
        log.exception("Could not queue the security alert %s", key)


LOCKOUT_ALERT_GAP = 15 * 60
LOCKOUT_ALERTS_PER_HOUR = 20
_LOCKOUT = {"lock": threading.Lock(), "sent": {}, "hour": []}


def _lockout_alert(client: str, username: Optional[str], keys: list) -> None:
    """auth.LIMITER.on_lockout: an audit row for every lockout, and an alert at most once per target
    every 15 minutes and 20 an hour in all. A username is named only when that account exists, so
    made-up names cannot be pushed into the chat."""
    account = database.get_user(username) if username and _USERNAME.fullmatch(username) else None
    target = account["username"] if account and "user:" + username.lower() in keys else client
    database.add_audit("auth", "Login lockout started", target)
    now = time.time()
    with _LOCKOUT["lock"]:
        sent, hour = _LOCKOUT["sent"], [t for t in _LOCKOUT["hour"] if now - t < 3600]
        _LOCKOUT["hour"] = hour
        if now - sent.get(target, 0.0) < LOCKOUT_ALERT_GAP or len(hour) >= LOCKOUT_ALERTS_PER_HOUR:
            return
        sent[target] = now
        hour.append(now)
        for old in sorted(sent, key=sent.get)[:max(0, len(sent) - 256)]:
            del sent[old]
    security_alert("lockout", target=target)


auth.LIMITER.on_lockout = _lockout_alert


def migrate_tasks_to_workflows() -> int:
    """SSH tasks were folded into workflows: each task becomes a one-step workflow, then the task is removed."""
    moved = 0
    creds = {c["id"] for c in database.list_credentials()}
    devices = {d["id"] for d in database.list_devices()}
    for task in database.list_tasks():
        hosts = [i for i in task["device_ids"] if i in devices]
        sched = schedule.from_cron(task["trigger_cron"]) if task["trigger_type"] == "schedule" else {"kind": "manual"}
        if hosts and task["credential_id"] in creds:
            step = {"type": "command", "label": "", "command": task["command"], "device_ids": hosts,
                    "credential_id": task["credential_id"], "timeout_s": task["timeout_s"] or 60,
                    "ssh_port": task["ssh_port"] or 22, "expected_exit_code": task["expected_exit_code"] or 0,
                    "any_exit": False, "on_failure": "stop", "retries": 0}
            graph = workflows.steps_to_graph([step], sched)
            wid = database.save_workflow(None, workflow_fields(task["name"], "Converted from an SSH task", graph,
                                                               bool(task["is_active"])))
            database.add_audit("workflow", f"Converted SSH task {task['name']} into workflow {wid}",
                               f"Schedule: {schedule.describe(sched)}")
            moved += 1
        else:
            database.add_audit("workflow", f"Removed SSH task {task['name']}",
                               "Not converted: its hosts or credential no longer exist")
        database.retire_task(task["id"])
    return moved


def parse_credential_payload(payload: Dict[str, Any], require_secret: bool) -> Dict[str, Any]:
    """Validates a credential create or update. The secret is optional on update (keep existing)."""
    name = _get_str(payload, "name", max_len=64)
    if not _CRED_NAME.fullmatch(name):
        raise RequestError(400, "Name must start with a letter or digit and use letters, digits, spaces, _ . @ or -")
    cred_type = _get_str(payload, "cred_type", "password", max_len=16)
    if cred_type not in database.CREDENTIAL_TYPES:
        raise RequestError(400, "Type must be password or ssh_key")
    username = _get_str(payload, "username", "", max_len=64)
    secret = payload.get("secret") or ""
    if not isinstance(secret, str) or len(secret) > 16384:
        raise RequestError(400, "Secret must be text of at most 16 KB")
    passphrase = payload.get("passphrase") or ""
    if cred_type != "ssh_key" or not isinstance(passphrase, str) or len(passphrase) > 1024 or "\n" in passphrase:
        passphrase = ""
    public_key = None
    if cred_type == "ssh_key" and payload.get("generate") is True:
        # The pair is made here: the private half goes straight into the vault, only the public half is returned.
        try:
            secret, public_key = ssh_runner.generate_keypair(f"homelab-monitor {name}")
        except ssh_runner.SshKeyError as exc:
            raise ActionError(502, f"Could not generate a key pair: {exc}")
        passphrase = ""
    if require_secret and not secret:
        raise RequestError(400, "A password or private key is required")
    if secret and cred_type == "ssh_key":
        if not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", secret):
            raise RequestError(400, "SSH key must be a private key in PEM / OpenSSH format (-----BEGIN ... PRIVATE KEY-----)")
        if public_key is None:
            given = payload.get("public_key")
            public_key = ssh_runner.public_key_of(secret) or \
                (given.strip() if isinstance(given, str) and ssh_runner.valid_public_key(given.strip()) else None)
    return {"name": name, "cred_type": cred_type, "username": username, "secret": secret or None,
            "passphrase": passphrase, "public_key": public_key}


SNMP_V3_FIELDS = ("user", "level", "auth_protocol", "priv_protocol")


def parse_snmp_v3(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The SNMP version and v3 settings of an Add or Edit device form, or None when the form does not
    send a version (older pages and the setup guide: the device keeps what it has). Blank passwords
    mean "unchanged" on edit; they are checked once merged with what is stored (finish_snmp_v3)."""
    version = payload.get("snmp_version")
    if version is None:
        return None
    if version not in ("v2c", "v3"):
        raise RequestError(400, "The SNMP version is v2c or v3")
    if version == "v2c":
        return {"version": "v2c", "v3": None}
    raw = payload.get("snmp_v3")
    if not isinstance(raw, dict):
        raise RequestError(400, "SNMPv3 needs a user name and passwords")
    v3 = {k: str(raw.get(k) or "").strip() for k in SNMP_V3_FIELDS}
    for k in ("auth_password", "priv_password"):
        v = raw.get(k)
        if v is not None and (not isinstance(v, str) or len(v) > 128 or chr(10) in v or chr(13) in v):
            raise RequestError(400, "An SNMPv3 password is at most 128 characters on one line")
        v3[k] = v or ""
    return {"version": "v3", "v3": v3}


def finish_snmp_v3(snmp: Optional[Dict[str, Any]], before: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Fills blank passwords from the stored settings and checks the whole; None when unchanged."""
    if snmp is None or snmp["version"] == "v2c":
        return snmp
    import snmpv3
    v3 = dict(snmp["v3"])
    old = (before or {}).get("snmp_v3") or {}
    for k in ("auth_password", "priv_password"):
        if not v3[k]:
            v3[k] = old.get(k, "")
    if v3["level"] == "authNoPriv":
        v3["priv_password"] = ""
    cred = snmpv3.Credential(user=v3["user"], level=v3["level"] or "authPriv", auth_protocol=v3["auth_protocol"] or "SHA",
                             auth_password=v3["auth_password"], priv_protocol=v3["priv_protocol"] or "AES",
                             priv_password=v3["priv_password"])
    problems = cred.problems()
    if problems:
        raise RequestError(400, "SNMPv3: " + problems[0])
    return {"version": "v3", "v3": {"user": cred.user, "level": cred.level, "auth_protocol": cred.auth_protocol,
                                    "auth_password": cred.auth_password, "priv_protocol": cred.priv_protocol,
                                    "priv_password": cred.priv_password}}


def public_snmp_v3(v3: Dict[str, Any]) -> Dict[str, Any]:
    """SNMPv3 settings as the browser sees them: the passwords only as set or not set."""
    v3 = v3 or {}
    return {**{k: v3.get(k, "") for k in SNMP_V3_FIELDS},
            "auth_password_set": bool(v3.get("auth_password")), "priv_password_set": bool(v3.get("priv_password"))}


# --- SNMP check: what is wrong with a device's SNMP, in plain words (a device's page) ---

SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
# A user name no device has, to learn whether a device speaks SNMPv3 at all (it answers "unknown user").
PROBE_V3_USER = "home-monitor-check"


def snmp_check(device: Dict[str, Any]) -> Dict[str, Any]:
    """Step by step: ping, an SNMP answer, the user and password (v3) or the community (v2c), then
    whether values can be read. When a v3 signature is wrong, the other protocols are tried quietly
    (MD5 too, only to recognise it) so the advice can say what to change. Stored secrets are used,
    never shown."""
    import dataclasses
    import snmpv3
    ip, port = device["ip_address"], int(device.get("snmp_port") or 161)
    steps: List[Dict[str, Any]] = []
    advice = ""

    def step(name: str, ok: Optional[bool], detail: str) -> None:
        steps.append({"step": name, "ok": ok, "detail": detail})

    alive, ms = poller.ping_host(ip, 2.0)
    step("Ping", True if alive else None,
         f"Answers in {ms:.0f} ms" if alive and ms is not None else "Answers" if alive
         else "No answer to ping. Some devices block ping; SNMP is checked anyway.")

    def v3_get(cred) -> Optional[List[Tuple[str, Any]]]:
        return snmpv3.request(ip, port, poller.PDU_GET, [SYS_NAME_OID], cred, 2.0, 1, diagnostic=True)

    if device.get("snmp_version") == "v3":
        cred = poller.snmp_target(device)
        problems = cred.problems()
        if problems:
            step("SNMPv3 settings", False, problems[0])
            return {"ok": False, "version": "v3", "steps": steps,
                    "advice": "Open Edit device and fill in the SNMPv3 settings as set on the device."}
        snmpv3.forget(ip, port)
        got = v3_get(cred)
        if not got:
            err = snmpv3.last_error(ip)
            if snmpv3._engine(ip, port) is None:
                step("SNMPv3 answer", False, "The device does not answer SNMPv3.")
                advice = ("Check that SNMP is switched on on the device with version 3 chosen, that the port is "
                          f"{port} and that nothing blocks UDP {port} between the monitor and the device.")
            else:
                step("SNMPv3 answer", True, "The device answers SNMPv3.")
                if "does not know this user" in err:
                    step("User", False, f"The device does not know the user {cred.user}.")
                    advice = "User names must match exactly, capitals included. Check the user on the device and in Edit device."
                elif "Wrong authentication" in err or "security level" in err or "privacy" in err.lower():
                    step("User", True, f"The device knows the user {cred.user}.")
                    signed_only = dataclasses.replace(cred, level="authNoPriv")
                    found = None
                    for proto in [cred.auth_protocol] + [p for p in ("SHA", "SHA-256", "MD5") if p != cred.auth_protocol]:
                        if v3_get(dataclasses.replace(signed_only, auth_protocol=proto)):
                            found = proto
                            break
                    if found is None:
                        step("Authentication", False, "The authentication password does not match.")
                        advice = ("Type the authentication password again in Edit device, exactly as on the device. "
                                  "If it is right, the device may use a protocol the monitor does not know.")
                    elif found == "MD5":
                        step("Authentication", False, "The device is set to MD5.")
                        advice = ("On the device, choose SHA as the authentication protocol (it may be called HMAC-SHA) "
                                  "and keep the same password. MD5 is no longer safe, so the monitor does not use it.")
                    elif found != cred.auth_protocol:
                        step("Authentication", False, f"The device uses {found}, not {cred.auth_protocol}.")
                        advice = f"In Edit device, choose {found} as the authentication protocol."
                    else:
                        step("Authentication", True, f"The password and {found} are right.")
                        if cred.level == "authPriv":
                            step("Privacy", False, "The device refused the encrypted request.")
                            advice = ("Privacy is on in the monitor. Either the device has privacy off (then untick Use privacy "
                                      "in Edit device), or the privacy password differs, or the device uses DES instead of AES "
                                      "(choose AES on the device, or leave privacy off on both).")
                        else:
                            step("Privacy", False, "The device wants privacy (encryption) for this user.")
                            advice = ("Tick Use privacy in Edit device and type the privacy password set on the device. "
                                      "The device must use AES.")
                else:
                    step("Answer", False, err or "The device refused the request.")
                    advice = "Check the SNMPv3 settings on the device and in Edit device."
            return {"ok": False, "version": "v3", "steps": steps, "advice": advice}
        step("SNMPv3 answer", True, "The device answers SNMPv3.")
        step("User and password", True, f"The device accepts {cred.user} with {cred.auth_protocol}"
             + (" and privacy." if cred.level == "authPriv" else " (signed only, privacy off)."))
        target = cred
    else:
        target = poller.snmp_target(device, database.get_all_settings().get("default_snmp_community") or "public")
        name = poller.snmp_get(ip, SYS_NAME_OID, target, port, 2.0, 1)
        if not poller.has_value(name):
            step("SNMP v2c answer", False, "No answer with this community.")
            snmpv3.forget(ip, port)
            v3_get(snmpv3.Credential(user=PROBE_V3_USER, level="authNoPriv", auth_protocol="SHA",
                                     auth_password="not-a-real-password"))
            if snmpv3._engine(ip, port) is not None:
                step("SNMPv3", None, "The device answers SNMPv3.")
                advice = ("The device may have v2c switched off. Either switch v2c on there with the same community, "
                          "or set up an SNMPv3 user on it and choose v3 in Edit device.")
            else:
                advice = ("Check the community (capitals count), that SNMP is switched on on the device and that "
                          f"nothing blocks UDP {port} between the monitor and the device.")
            return {"ok": False, "version": "v2c", "steps": steps, "advice": advice}
        step("SNMP v2c answer", True, "The device answers with this community.")
    rows = poller.snmp_walk(ip, IF_DESCR_OID, target, port, 2.0, 1, max_rows=200)
    if rows:
        step("Values", True, f"Reads {len(rows)} network interface{'s' if len(rows) != 1 else ''} and the rest of the template.")
    else:
        step("Values", False, "The device answers but shows only its basic details.")
        advice = ("Its SNMP view is limited. On a Linux host, Fix SNMP widens it; on other devices, allow the full view "
                  "(or the interfaces) for this community or user.")
    return {"ok": bool(rows), "version": device.get("snmp_version") or "v2c", "steps": steps, "advice": advice}



def public_device(device: Dict[str, Any]) -> Dict[str, Any]:
    """A device as sent to the browser: the decrypted community is replaced by a flag."""
    out = dict(device)
    out["snmp_community_set"] = bool(out.pop("snmp_community", None))
    out["snmp_v3"] = public_snmp_v3(out.get("snmp_v3") or {})
    apply_overrides(out)
    out["group"] = device_group(out)
    out["tags"] = taxonomy.device_tags(out)
    out["snmp"] = profile_uses_snmp(out.get("profile_id"))
    return out


def parse_settings_payload(payload: Dict[str, Any]) -> Dict[str, str]:
    """Validates a settings update against the schema. Errors name the field label.

    An empty value for a secret setting means "keep the stored value".
    """
    updates = {}
    for key, value in payload.items():
        spec = SETTINGS.get(key)
        if spec is None:
            raise RequestError(400, f"Unknown setting '{key}'")
        if spec["type"] == "secret" and (value is None or str(value).strip() == ""):
            continue
        if isinstance(value, (dict, list, bool)) or value is None:
            raise RequestError(400, f"Invalid value for {spec['label']}")
        text = str(value).strip()
        limit = 500 if spec["type"] == "template" else 255
        if len(text) > limit:
            raise RequestError(400, f"{spec['label']} exceeds {limit} characters")
        if spec["type"] in ("int", "float"):
            kind = int if spec["type"] == "int" else float
            try:
                number = kind(text)
            except ValueError:
                raise RequestError(400, f"{spec['label']} must be {'a whole number' if kind is int else 'a number'}")
            if not spec["min"] <= number <= spec["max"]:
                raise RequestError(400, f"{spec['label']} must be between {spec['min']} and {spec['max']}")
            text = str(number)
        elif spec["type"].startswith("select:"):
            if text not in spec["type"][7:].split(","):
                raise RequestError(400, f"Invalid option for {spec['label']}")
        elif spec["type"] == "time":
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", text):
                raise RequestError(400, f"{spec['label']} must be a time such as 22:00")
        elif spec["type"] == "template" and not text:
            text = spec["default"]
        if key == "telegram_chat_id" and text and not re.fullmatch(r"-?\d{1,20}", text):
            raise RequestError(400, "Chat ID is a number (Find my chat fills it in)")
        updates[key] = text
    if "raw_retention_days" in updates or "metric_retention_days" in updates:
        current = database.get_all_settings()
        raw = int(updates.get("raw_retention_days", current.get("raw_retention_days", "7")))
        trend = int(updates.get("metric_retention_days", current.get("metric_retention_days", "365")))
        if trend < raw:
            raise RequestError(400, "Hourly trends must be kept at least as long as raw samples")
    return updates


# --- Views: problems, neighbours and device summaries ---

RECENT_REBOOT_SECONDS = 3600


def alert_policy() -> alerts.Policy:
    """The rule catalogue (built-in and every profile's alerts) with the administrator's stored overrides."""
    return alerts.Policy(alerts.catalogue(poller.load_hardware_profiles()), database.list_alert_overrides(), taxonomy.tag_rank())


SUMMARY_KEYS = ["uptime_seconds", "cpu_usage_pct", "cpu_idle_pct", "cpu_load_1m", "mem_used_pct", "mem_total_kb",
                "mem_avail_kb", "mem_buffer_kb", "mem_cached_kb", "mem_total_mb", "mem_free_mb",
                "clients_total", "clients_2g", "clients_5g", "radio_2g_util_pct", "radio_5g_util_pct",
                "radio_2g_channel", "radio_5g_channel", "wan_status", "system_temp_c",
                "tls_days_left", "dns.ok", "dns.ms", "pihole.blocking", "pihole.gravity_days", "pihole.paused"]

# Snapshot tables the trigger set reads for each device.
PROBLEM_TABLES = ("interfaces", "storage", "radios", "disks", "volumes", "sensors", "processes", "services", "health", "wifi_clients")

_METRIC_KEY = re.compile(r"[A-Za-z0-9_.]{1,64}")


def memory_used_pct(m: Dict[str, float]) -> Optional[float]:
    """Memory used % excluding buffers and cache (stored by the poller as mem_used_pct)."""
    if "mem_used_pct" in m:
        return m["mem_used_pct"]
    return poller.memory_used_pct(m)


def cpu_pct(m: Dict[str, float]) -> Optional[float]:
    if "cpu_usage_pct" in m:
        return m["cpu_usage_pct"]
    if "cpu_idle_pct" in m:
        return 100.0 - m["cpu_idle_pct"]
    return None


def port_summary(interfaces: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    ports = [r for r in interfaces.values() if r.get("kind") == "port"]
    return {
        "total": len(ports),
        "up": sum(1 for r in ports if r.get("oper") == 1),
        "down": sum(1 for r in ports if r.get("oper") != 1 and r.get("admin") == 1),
        "disabled": sum(1 for r in ports if r.get("admin") == 2),
    }


def _alert_scope(scope: str, target: str) -> Tuple[str, Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Validates a scope and returns (profile id, device, the profiles whose rules are listed)."""
    profiles = poller.load_hardware_profiles()
    by_id = {p["profile_id"]: p for p in profiles}
    if scope == "global":
        if target:
            raise RequestError(400, "The global scope takes no target")
        used = {d["profile_id"] for d in database.list_devices()}
        return "", None, [p for p in profiles if p["profile_id"] in used]
    if scope == "template":
        if target not in by_id:
            raise RequestError(404, "Template not found")
        return target, None, [by_id[target]]
    if scope == "device":
        device = database.get_device(int(target)) if target.isdigit() else None
        if not device:
            raise RequestError(404, "Device not found")
        return device["profile_id"], device, [by_id[device["profile_id"]]] if device["profile_id"] in by_id else []
    if scope == "tag":
        # Every device with this tag, whatever its template: the templates of those devices are listed.
        if not any(t["name"] == target for t in taxonomy.tags()):
            raise RequestError(404, "Tag not found")
        used = {d["profile_id"] for d in database.list_devices() if target.lower() in (t.lower() for t in taxonomy.device_tags(d))}
        return "", None, [p for p in profiles if p["profile_id"] in used]
    raise RequestError(400, "scope must be global, template, tag or device")


def alert_rules_view(scope: str, target: str) -> Dict[str, Any]:
    """Every rule that applies at a scope with its effective values, where each came from, and what is set here."""
    profile_id, device, listed = _alert_scope(scope, target)
    profiles = poller.load_hardware_profiles()
    policy = alerts.Policy(alerts.catalogue(profiles), database.list_alert_overrides(), taxonomy.tag_rank())
    shown = [r for r in alerts.builtin_rules()] + [r for p in listed for r in alerts.profile_rules(p)]
    rules = []
    # The tags in play: the one being edited, or the device's own (they sit between template and device).
    tags = [target] if scope == "tag" else taxonomy.device_tags(device) if device else []
    for r in shown:
        values, source = policy.resolve(r["id"], profile_id, device["id"] if device else None, upto=scope, tags=tags)
        parent = {"global": "default", "template": "global", "tag": "global", "device": "tag"}[scope]
        inherited, _ = policy.resolve(r["id"], profile_id, device["id"] if device else None, upto=parent, tags=tags)
        rules.append({"id": r["id"], "group": r["group"], "label": r["label"], "unit": r["unit"], "min": r["min"],
                      "max": r["max"], "help": r["help"], "has_threshold": r["threshold"] is not None,
                      "as_reported": r["id"] == "health", "effective": values, "source": source, "inherited": inherited,
                      "here": policy.overridden_here(r["id"], scope, target)})
    devices = database.list_devices()
    counts: Dict[str, int] = {}
    for d in devices:
        counts[d["profile_id"]] = counts.get(d["profile_id"], 0) + 1
    return {"scope": scope, "target": target, "rules": rules, "severities": list(alerts.SEVERITIES),
            "tags": [{"name": t["name"], "colour": t["colour"]} for t in taxonomy.tags()],
            "device_tags": tags if scope == "device" else [],
            "templates": sorted(({"id": p["profile_id"], "name": p.get("name", p["profile_id"]), "devices": counts.get(p["profile_id"], 0)}
                                 for p in profiles), key=lambda t: (t["devices"] == 0, t["name"].lower())),
            "devices": sorted(({"id": d["id"], "hostname": d["hostname"], "profile_id": d["profile_id"]} for d in devices),
                              key=lambda d: d["hostname"].lower())}


def backup_status() -> Dict[str, Any]:
    """Where /root/backup.sh writes (same rule as sitectl.py), what is there, and the restore sources
    home_monitor.sh set. On a development copy there is no backup timer: installed is False."""
    data_dir = os.path.dirname(os.path.abspath(database.DB_FILE))
    site = setup.get_site()
    st = site.get("syncthing") or {}
    syncthing = bool(st.get("enabled") and st.get("data_folder"))
    folder = st["data_folder"] if syncthing else os.path.join(data_dir, "backups")
    conf: Dict[str, str] = {}
    try:
        with open(os.environ.get("MONITOR_INSTALL_CONF", ""), encoding="utf-8") as f:
            for line in f:
                m = re.fullmatch(r'([A-Z_]+)="(.*)"', line.strip())
                if m:
                    conf[m.group(1)] = m.group(2)
    except OSError:
        pass
    files = []
    try:
        for name in os.listdir(folder):
            if name.startswith("monitor-backup-") and name.endswith(".tar.gz"):
                st_ = os.stat(os.path.join(folder, name))
                files.append({"name": name, "size": st_.st_size, "time": int(st_.st_mtime)})
    except OSError:
        pass
    files.sort(key=lambda f: f["time"], reverse=True)
    results = {k: _read_result(data_dir, k) for k in ("backup", "site", "passphrase")}
    pending = {k: _request_time(data_dir, k) > ((results[k] or {}).get("time") or 0) for k in ("backup", "site")}
    # The passphrase request is removed by root as soon as it is read: waiting while it is there.
    pending["passphrase"] = os.path.exists(os.path.join(data_dir, "requests", PASSPHRASE_REQUEST))
    # Root keeps the backup passphrase beside install.conf (root only: the app sees only whether it exists).
    install_dir = os.path.dirname(os.environ.get("MONITOR_INSTALL_CONF", "") or "")
    passphrase_set = bool(conf) and bool(install_dir) and os.path.exists(os.path.join(install_dir, "backup-passphrase"))
    # Where the key goes in the next backup: sealed with a passphrase; without one it stays only in
    # backups kept inside the container and is left out of those synced off the box.
    key_state = "sealed" if passphrase_set else ("withheld" if syncthing else "clear-local")
    return {"installed": bool(conf), "folder": folder, "syncthing": syncthing, "count": len(files),
            "latest": files[0] if files else None, "total_bytes": sum(f["size"] for f in files),
            "schedule": "Daily at 03:30, the newest 7 kept",
            "passphrase_set": passphrase_set, "key_state": key_state,
            "restore_source": conf.get("SYNCTHING_KEYS_NFS") or conf.get("BACKUP_NFS") or "",
            "data_dir": data_dir, "results": results, "pending": pending,
            "syncthing_settings": {"enabled": bool(st.get("enabled")), "keys_source": st.get("keys_source", ""),
                                   "data_folder": st.get("data_folder") or "/mnt/Syncthing/Monitor"}}


# Root-side actions (see deploy/sitectl.py and the hm-site / hm-backup-now path units): the app
# writes DATA/requests/<kind>; root applies it and leaves DATA/<kind>.result.json.
ROOT_REQUESTS = ("site", "backup", "update-check", "update-install", "rollback-code", "rollback-all")
UPDATE_KEEP_SECONDS = 2 * 24 * 3600          # how long an update can be undone (updatectl.py keeps the copy as long)
UPDATE_STATE = "/etc/homelab-monitor-install/last-update.json"
# Written by root (updatectl.py), readable by the app's group: the history and one log file per entry.
UPDATE_HISTORY = "/etc/homelab-monitor-install/update-history.json"
UPDATE_LOGS = "/etc/homelab-monitor-install/update-logs"
UPDATE_SKIP_KEY = "update_skip_version"     # internal setting: the version the person chose to skip
AUTO_CHECK_SECONDS = 24 * 3600
_VERSION_RE = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")
UPDATE_STEPS = ("download", "verify", "ready", "copy", "check", "repair", "backup", "replace", "health")


def request_root_action(kind: str) -> None:
    if kind not in ROOT_REQUESTS:
        raise ValueError(kind)
    folder = os.path.join(os.path.dirname(os.path.abspath(database.DB_FILE)), "requests")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, kind), "w", encoding="ascii") as f:
        f.write(str(int(time.time())))


# Settings, Backups, Set backup passphrase: the passphrase goes to root sealed with the vault key
# (sitectl.py passphrase-request, through hm-passphrase.path), so it is never on disk in the clear.
PASSPHRASE_REQUEST = "backup-passphrase"
PASSPHRASE_CONTEXT = "backup-passphrase-request"
PASSPHRASE_MIN, PASSPHRASE_MAX = 12, 1024


def backup_passphrase_problem(value: Any) -> str:
    if not isinstance(value, str) or len(value) < PASSPHRASE_MIN:
        return f"The backup passphrase must be at least {PASSPHRASE_MIN} characters"
    if len(value) > PASSPHRASE_MAX or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return "The backup passphrase is too long or holds a character that cannot be typed"
    return ""


def request_backup_passphrase(passphrase: str) -> None:
    """Leaves the new backup passphrase for root, sealed with the vault key. One request at a time."""
    if not VAULT.enabled:
        raise RequestError(409, "The vault is locked, so the passphrase cannot be passed on safely. Use /root/backup-passphrase.sh in the container.")
    token = VAULT.encrypt(passphrase, PASSPHRASE_CONTEXT)
    folder = os.path.join(os.path.dirname(os.path.abspath(database.DB_FILE)), "requests")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, PASSPHRASE_REQUEST)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise RequestError(409, "A new backup passphrase is already being saved. Wait a moment and try again.")
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(token + "\n")


def _request_time(data_dir: str, kind: str) -> int:
    try:
        with open(os.path.join(data_dir, "requests", kind), encoding="ascii") as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _installed_version(app_dir: str) -> str:
    try:
        with open(os.path.join(app_dir, "server.py"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("APP_VERSION = "):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def update_status() -> Dict[str, Any]:
    """Settings, Updates: the last check, the last update or rollback, what is waiting and the ways back.
    Root does the work (updatectl.py through hm-update.path); this only reads what it left."""
    data_dir = os.path.dirname(os.path.abspath(database.DB_FILE))

    def result(kind: str) -> Optional[Dict[str, Any]]:
        try:
            with open(os.path.join(data_dir, f"{kind}.result.json"), encoding="utf-8") as f:
                r = json.load(f)
        except (OSError, ValueError):
            return None
        keep = ("time", "ok", "action", "error", "current", "latest", "newer", "name", "published", "notes", "url",
                "from", "to", "output")
        out = {k: r.get(k) for k in keep if k in r}
        for k in ("notes", "output", "error"):
            if isinstance(out.get(k), str):
                out[k] = out[k][-6000:]
        if isinstance(r.get("changes"), list):
            out["changes"] = [{k: str(c.get(k) or "")[:6000 if k == "notes" else 200] for k in ("version", "name", "published", "notes")}
                              for c in r["changes"][:30] if isinstance(c, dict)]
        return out

    check, last = result("update-check"), result("update")
    if check and check.get("ok"):
        # A check saved before an update said "newer" about the version that now runs: judge it again.
        check["newer"] = _vt(check.get("latest")) > _vt(APP_VERSION)
        check["current"] = APP_VERSION
        if not check["newer"]:
            check.pop("changes", None)
    pending_check = _request_time(data_dir, "update-check") > ((check or {}).get("time") or 0)
    pending_work = max(_request_time(data_dir, k) for k in ("update-install", "rollback-code", "rollback-all")) \
        > ((last or {}).get("time") or 0)
    try:
        with open(UPDATE_STATE, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    back: Dict[str, Any] = {"all": False, "code": False}
    if (state and not state.get("rolled_back") and time.time() - float(state.get("time") or 0) <= UPDATE_KEEP_SECONDS
            and _installed_version(BASE_DIR + ".old") == state.get("from_version") and APP_VERSION == state.get("to_version")):
        back = {"all": True, "code": bool(state.get("schema_same")), "from": state.get("to_version"),
                "to": state.get("from_version"), "expires": int(float(state["time"]) + UPDATE_KEEP_SECONDS)}
    installed = os.path.isdir(os.path.join(data_dir, "requests")) and os.path.exists("/etc/systemd/system/hm-update.path")
    skipped = database.get_all_settings().get(UPDATE_SKIP_KEY) or ""
    progress = update_progress(data_dir, pending_work)
    # An update cut short by a restart (or one that stopped answering for hours) never writes its result:
    # without this the page would show it running for ever and keep Update and Undo locked. At boot,
    # updatectl.py recover records it properly; until then it is shown as cut short.
    if progress and progress["state"] == "running" and (
            (progress["boot"] and progress["boot"] != _boot_id()) or time.time() - progress["updated"] > 2 * 3600):
        progress.update(state="failed", interrupted=True, finished=progress["updated"] or int(time.time()),
                        error="The update was cut short: the monitor's machine restarted (or the update stopped) "
                              "before it finished. Settings, System shows the version that runs now.")
        progress["steps"] = {s: ("fail" if v == "run" else v) for s, v in progress["steps"].items()}
        pending_work = False
    elif pending_work and not progress and time.time() - max(_request_time(data_dir, k) for k in
                                                              ("update-install", "rollback-code", "rollback-all")) > 2 * 3600:
        pending_work = False       # asked hours ago and never answered: the request is not waited for
    return {"installed": installed, "current": APP_VERSION, "check": check, "last": last,
            "pending": {"check": pending_check, "work": pending_work}, "rollback": back,
            "progress": progress, "skipped": skipped,
            "waiting": update_waiting(check, skipped),
            "repository": "https://github.com/The-Flying-Pancake/Home_Monitor"}


def _vt(v: Any) -> Tuple[int, ...]:
    return tuple(int(x) for x in str(v).split(".")) if _VERSION_RE.fullmatch(str(v or "")) else (0, 0, 0)


def demo_status() -> Dict[str, Any]:
    """Settings, Demo data: shown only while the made-up devices from an install with demo data are on."""
    if poller.demo is None:
        return {"on": False, "devices": 0}
    return poller.demo.status()


def update_waiting(check: Optional[Dict[str, Any]], skipped: str) -> int:
    """1 while a newer version is known and has not been skipped (the red number), else 0."""
    if not check or not check.get("ok") or not check.get("newer"):
        return 0
    latest = check.get("latest")
    if _vt(latest) <= _vt(APP_VERSION) or (skipped and _vt(latest) <= _vt(skipped)):
        return 0
    return 1


def update_progress(data_dir: str, running: bool) -> Optional[Dict[str, Any]]:
    """Which step the update is on (DATA/update-progress.json, written by root), only the known fields.
    Shown while an update runs and for ten minutes after it ends."""
    try:
        with open(os.path.join(data_dir, "update-progress.json"), encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    ended = int(raw.get("finished") or 0)
    if ended and time.time() - ended > 600 and not running:
        return None
    steps = raw.get("steps") if isinstance(raw.get("steps"), dict) else {}
    return {"state": str(raw.get("state") or "")[:10], "from": str(raw.get("from") or "")[:20], "to": str(raw.get("to") or "")[:20],
            "started": int(raw.get("started") or 0), "finished": ended, "current": str(raw.get("current") or "")[:20],
            "error": str(raw.get("error") or "")[:2000], "interrupted": bool(raw.get("interrupted")),
            "boot": str(raw.get("boot") or "")[:64], "updated": int(raw.get("time") or 0),
            "steps": {s: str(steps.get(s) or "pending")[:10] for s in UPDATE_STEPS}}


def _boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as f:
            return f.read().strip()[:64]
    except OSError:
        return ""


def update_history() -> List[Dict[str, Any]]:
    """Every update, upgrade and rollback root recorded, newest first (no logs: those are fetched one by one)."""
    try:
        with open(UPDATE_HISTORY, encoding="utf-8") as f:
            rows = json.load(f)
    except (OSError, ValueError):
        return []
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and isinstance(r.get("id"), int):
            out.append({"id": r["id"], "time": int(r.get("time") or 0), "kind": str(r.get("kind") or "")[:20],
                        "source": str(r.get("source") or "")[:10], "from": str(r.get("from") or "")[:20],
                        "to": str(r.get("to") or "")[:20], "ok": bool(r.get("ok")), "error": str(r.get("error") or "")[:2000],
                        "log": bool(r.get("log"))})
    return out[:50]


def update_history_log(entry_id: int) -> Optional[str]:
    """The log of one history entry. Only a number that is in the history opens a file, and the file
    name is made from that number here: nothing from the browser becomes part of a path."""
    if not any(r["id"] == entry_id and r["log"] for r in update_history()):
        return None
    path = os.path.join(UPDATE_LOGS, f"{int(entry_id)}.log")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, encoding="utf-8", errors="replace") as f:
            return f.read(2 * 1024 * 1024)
    except OSError:
        return None


def auto_update_check(now: Optional[float] = None) -> bool:
    """Once a day, when Check for updates every day is on: ask root to look for a new version.
    Returns whether it asked."""
    now = time.time() if now is None else now
    if (database.get_all_settings().get("update_auto_check") or "on") != "on":
        return False
    status = update_status()
    if not status["installed"] or status["pending"]["check"] or status["pending"]["work"]:
        return False
    data_dir = os.path.dirname(os.path.abspath(database.DB_FILE))
    last = max((status["check"] or {}).get("time") or 0, _request_time(data_dir, "update-check"))
    if now - last < AUTO_CHECK_SECONDS:
        return False
    request_root_action("update-check")
    return True


class _RecentLog(logging.Handler):
    """The monitor's last warnings and errors since it started, for Report a problem (in memory only)."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        import collections
        self.lines = collections.deque(maxlen=60)
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record).splitlines()[0][:400])
        except Exception:  # noqa: BLE001 (a log line must never break the app)
            pass


RECENT_LOG = _RecentLog()


def problem_report() -> Dict[str, Any]:
    """Settings, System, Report a problem: what report.py gathers plus what only the running app knows."""
    stats = scheduler.stats()
    jobs = ", ".join(f"{k} {v}" for k, v in (stats.get("jobs_in_flight") or {}).items()) or "idle"
    extra = {"uptime": f"{int((time.time() - STARTED_AT) // 3600)}h {int((time.time() - STARTED_AT) % 3600 // 60)}m",
             "poller": f"{jobs}; last tick {int(time.time() - float(stats.get('last_tick') or 0))}s ago",
             "vault": "unlocked" if VAULT.enabled else "locked or unavailable",
             "log": list(RECENT_LOG.lines)}
    text = report.build(database.DB_FILE, BASE_DIR, os.path.dirname(UPDATE_HISTORY), journal=False, extra=extra)
    return {"report": text, "issue_url": report.ISSUE_URL}


def _auto_update_loop() -> None:
    time.sleep(300)                  # let the monitor settle after a start
    while True:
        try:
            auto_update_check()
        except Exception:  # noqa: BLE001 (a failed check must never stop the loop)
            log.exception("Daily update check")
        time.sleep(3600)


ALERT_SEEN_RESTORE = "alert_seen_restore"
ALERT_SEEN_UPDATE = "alert_seen_update"
ROOT_ALERT_MAX_AGE = 86400


def watch_root_results(now: Optional[float] = None) -> int:
    """Restores and updates are done by root, the restore while the monitor is stopped, so root cannot
    record them in this database. Here each new result gets one audit row and one alert. Not part of
    initialise(): the trial run before an update or restore calls that. Returns how many were sent."""
    now = time.time() if now is None else now
    s = database.get_all_settings()
    sent = 0
    restore = _read_result(os.path.dirname(os.path.abspath(database.DB_FILE)), "restore")
    if restore and restore["time"]:
        try:
            seen = int(s.get(ALERT_SEEN_RESTORE) or 0)
        except ValueError:
            seen = 0
        if restore["time"] > seen:
            database.set_internal_setting(ALERT_SEEN_RESTORE, str(restore["time"]))
            # A database from before this watcher has no marker: only a recent restore is news.
            if seen or now - restore["time"] < ROOT_ALERT_MAX_AGE:
                name = os.path.basename(str(restore.get("file") or "")) or "unknown"
                database.add_audit("backup", f"Data restored from backup {name}", "", actor="root")
                security_alert("restored", who="root", source="", file=name)
                sent += 1
    history = update_history()
    newest = max((h["id"] for h in history), default=0)
    marker = s.get(ALERT_SEEN_UPDATE) or ""
    if not marker.isdigit():
        # First run: what is already there is history, not news.
        database.set_internal_setting(ALERT_SEEN_UPDATE, str(newest))
        return sent
    fresh = sorted((h for h in history if h["id"] > int(marker) and now - h["time"] < ROOT_ALERT_MAX_AGE),
                   key=lambda h: h["id"])[-5:]
    for h in fresh:
        kind = (h["kind"] or "update").replace("-", " ").capitalize()
        if h["ok"]:
            text = f"{kind} from {h['from']} to {h['to']} finished"
            security_alert("update_ok", who="root", source="", **{"kind": kind, "from": h["from"], "to": h["to"]})
        else:
            text = f"{kind} from {h['from']} to {h['to']} failed"
            security_alert("update_failed", who="root", source="", kind=kind, to=h["to"], error=h["error"][:300] or "unknown")
        database.add_audit("system", text, h["error"][:500], actor="root")
        sent += 1
    if newest > int(marker):
        database.set_internal_setting(ALERT_SEEN_UPDATE, str(newest))
    return sent


def _read_result(data_dir: str, kind: str) -> Optional[Dict[str, Any]]:
    try:
        with open(os.path.join(data_dir, f"{kind}.result.json"), encoding="utf-8") as f:
            r = json.load(f)
        return {"time": int(r.get("time") or 0), "ok": bool(r.get("ok")), "output": str(r.get("output") or "")[-4000:],
                "file": r.get("file"), "folder": r.get("folder")}
    except (OSError, ValueError):
        return None




def parse_syncthing_site(body: Dict[str, Any]) -> Dict[str, Any]:
    """Settings, Backups: Syncthing on (identity NFS export, synced folder) or off."""
    if body.get("enabled") is not True:
        return {"enabled": False}
    keys = _get_str(body, "keys_source", max_len=300).strip()
    folder = _get_str(body, "data_folder", "/mnt/Syncthing/Monitor", max_len=300).strip() or "/mnt/Syncthing/Monitor"
    # The same rules root applies again on the container (sitecheck.py): below /mnt or /srv, no spaces.
    try:
        keys = sitecheck.nfs_source(keys, "Identity share")
        folder = sitecheck.folder(folder, "Synced folder")
    except sitecheck.SiteError as exc:
        raise RequestError(400, str(exc))
    return {"enabled": True, "keys_source": keys, "data_folder": folder}


def alert_overview(user: "rbac.User") -> Dict[str, Any]:
    """Every override set anywhere, grouped by where it is set, for the one-place view of what differs from defaults."""
    profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
    rules = alerts.catalogue(list(profiles.values()))
    defaults = alerts.defaults
    devices = {d["id"]: d for d in database.device_profiles()}
    names = {d["id"]: d["hostname"] for d in database.list_devices()}
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for o in database.list_alert_overrides():
        rule = rules.get(o["rule_id"])
        if rule is None:
            continue
        if o["scope"] == "device":
            did = int(o["target"]) if o["target"].isdigit() else None
            if did not in devices or not user.sees_id(did):
                continue
            name = names.get(did, f"Device {did}")
        elif user.scope is not None:
            continue
        elif o["scope"] == "template":
            name = profiles.get(o["target"], {}).get("name", o["target"])
        elif o["scope"] == "tag":
            name = f"Tag {o['target']}"
        else:
            name = "All devices"
        g = groups.setdefault((o["scope"], o["target"]), {"scope": o["scope"], "target": o["target"], "name": name, "items": []})
        g["items"].append({"rule_id": o["rule_id"], "label": rule["label"], "group": rule["group"], "field": o["field"],
                           "value": alerts.decode(o["field"], o["value"]), "default": defaults(rule).get(o["field"]),
                           "unit": rule["unit"]})
    order = {"global": 0, "template": 1, "tag": 2, "device": 3}
    out = sorted(groups.values(), key=lambda g: (order.get(g["scope"], 3), g["name"].lower()))
    for g in out:
        g["items"].sort(key=lambda i: (i["group"], i["label"], i["field"]))
    return {"groups": out, "fields": list(alerts.FIELDS)}


def changed_alert_settings(user: "rbac.User", now: Optional[float] = None) -> Dict[str, Any]:
    """Settings, Notifications, Changed alerts: everything that makes alerts differ from the defaults,
    wherever it is set, with a link to where it is changed. A user limited to some devices sees the
    changes on their devices only (the inventory's network-wide rules are left out for them)."""
    now = now if now is not None else time.time()
    scope_link = {"global": "#/settings/alerts", "template": "#/settings/alerts/template/", "tag": "#/settings/alerts/tag/",
                  "device": "#/settings/alerts/device/"}
    rules = []
    for g in alert_overview(user)["groups"]:
        link = scope_link.get(g["scope"], "#/settings/alerts")
        if g["scope"] != "global":
            link += quote(str(g["target"]), safe="")
        rules.append({"scope": g["scope"], "name": g["name"], "link": link,
                      "changes": [{"label": i["label"], "field": i["field"], "value": i["value"], "default": i["default"],
                                   "unit": i["unit"]} for i in g["items"]]})
    names = {d["id"]: d["hostname"] for d in database.list_devices()}
    windows = []
    for w in maintenance_view(user, maintenance.windows(now)):
        if w["state"] == "ended":
            continue
        target = str(w.get("target") or "")
        what = ("Every device" if w["scope"] == "all" else
                names.get(int(target), f"Device {target}") if w["scope"] == "device" and target.isdigit() else
                f"Group {target}" if w["scope"] == "group" else f"Tag {target}")
        windows.append({"what": what, "state": w["state"], "start": w["start"], "end": w["end"], "note": w.get("note") or ""})
    out: Dict[str, Any] = {"rules": rules, "maintenance": windows, "inventory": None}
    if user.scope is None:
        listing = inventory.listing(now)
        label = lambda r: r.get("name") or r.get("device_name") or r.get("seen_name") or r["mac"]
        out["inventory"] = {
            "quiet_networks": inventory.quiet_ssid_list(),
            "network_wifi": [{"name": k, "rule": v} for k, v in sorted(inventory.wifi_net_alerts().items(), key=lambda kv: kv[0].lower())],
            "quiet_devices": sorted((label(r) for r in listing["rows"] if r["quiet"]), key=str.lower),
            "device_wifi": sorted(({"name": label(r), "mac": r["mac"], "rule": r["wifi_alert"]} for r in listing["rows"] if r["wifi_alert"] != ""),
                                  key=lambda x: x["name"].lower()),
        }
    return out


def parse_alert_changes(body: Any) -> Tuple[str, str, List[Tuple[str, str, Optional[str]]]]:
    """Validates PUT /api/alert-rules: {scope, target, changes: [{rule_id, field, value}]}; value null inherits."""
    if not isinstance(body, dict):
        raise RequestError(400, "Body must be an object")
    scope, target = body.get("scope"), str(body.get("target") or "")
    if not isinstance(scope, str):
        raise RequestError(400, "scope is required")
    profile_id, device, listed = _alert_scope(scope, target)
    rules = alerts.catalogue(poller.load_hardware_profiles())
    allowed = {r["id"] for r in alerts.builtin_rules()} | {r["id"] for p in listed for r in alerts.profile_rules(p)}
    changes = body.get("changes")
    if not isinstance(changes, list) or not 0 < len(changes) <= 500:
        raise RequestError(400, "changes must be a list of 1 to 500 entries")
    out = []
    for c in changes:
        if not isinstance(c, dict) or c.get("rule_id") not in allowed or c.get("field") not in alerts.FIELDS:
            raise RequestError(400, f"Unknown rule or field: {c.get('rule_id') if isinstance(c, dict) else c}")
        rule = rules[c["rule_id"]]
        if c.get("value") is None:
            out.append((rule["id"], c["field"], None))
            continue
        try:
            value = alerts.parse_value(rule, c["field"], c["value"])
        except ValueError as exc:
            raise RequestError(400, f"{rule['label']}: {exc}")
        out.append((rule["id"], c["field"], alerts.encode(c["field"], value)))
    return scope, target, out


def device_limits(device: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Effective temperature limits for colouring a device's disk and sensor tables."""
    rule = alert_policy().for_device(device)
    return {k: rule(k)["threshold"] for k in ("disk_temp", "sensor_temp", "disk_full")}


def _problem(device: Dict[str, Any], r: Dict[str, Any], rule_id: str, key: str, message: str,
             severity: Optional[str] = None) -> Dict[str, Any]:
    """One evaluated problem with its rule's severity, wait and Telegram choices for the problem engine."""
    return {"device_id": device["id"], "hostname": device["hostname"], "key": key, "rule": rule_id,
            "severity": r["severity"] or severity or "warning", "message": message,
            "for_s": r["for_minutes"] * 60, "telegram": r["telegram"], "resolved": r["resolved"],
            "sound": r.get("sound", "default")}


def device_problems(device: Dict[str, Any], m: Dict[str, float],
                    tables: Dict[str, Dict[str, Dict[str, Any]]],
                    rule: Optional[Callable[[str], Dict[str, Any]]] = None, watches: Optional[list] = None,
                    profile: Optional[Dict[str, Any]] = None) -> list:
    """Evaluates the trigger set for one device.

    tables maps a snapshot table name (see PROBLEM_TABLES) to its rows.
    rule maps a rule id to its effective settings for this device
    (alerts.Policy.for_device); without it every rule has its defaults.
    profile supplies the device template's own alerts. Returns problems
    (see _problem). key identifies the condition (not its current value) so
    the problem engine can track it across polls while the message text changes.
    """
    rule = rule or alerts.default_policy([profile] if profile else []).for_device(device)
    interfaces = tables.get("interfaces", {})
    out = []

    def add(rule_id: str, key: str, message: str, severity: Optional[str] = None) -> None:
        r = rule(rule_id)
        if r["enabled"]:
            out.append(_problem(device, r, rule_id, key, message, severity))

    def limit(rule_id: str) -> Optional[float]:
        r = rule(rule_id)
        return r["threshold"] if r["enabled"] else None

    def num(v: float) -> str:
        return f"{v:g}"

    port = device.get("service_port") or 0
    web = device.get("service_kind") == "http" and device.get("service_url")
    what = device["service_url"] if web else f"port {port}"
    if device["status"] == "offline":
        add("unreachable", "unreachable",
            f"Unreachable: no ping reply and {what} not answering" if port else "Device unreachable (no ICMP reply)")
        return out
    if port:
        # Port checks have no SNMP: only the service itself is judged.
        if m.get("service_up") == 0:
            code = m.get("http_status")
            detail = f"answered HTTP {int(code)}, not what was expected" if web and isinstance(code, (int, float)) \
                else "not answering as expected" if web else "not answering"
            add("service_down", "service_down", f"{what[0].upper() + what[1:]} {detail} (the host answers ping)")
        slow = limit("service_slow")
        if slow is not None and m.get("service_up") == 1 and isinstance(m.get("tcp_connect_ms"), (int, float)) \
                and m["tcp_connect_ms"] >= slow:
            add("service_slow", "service_slow", f"Port {port} took {num(m['tcp_connect_ms'])} ms to connect (threshold {num(slow)} ms)")
        lan_service_problems(device, m, tables, add, limit)
        return out
    if device.get("snmp_status") == "no_response":
        add("snmp", "snmp", "SNMP agent not responding (host answers ping)")
    elif device.get("snmp_status") == "ok" and "uptime_seconds" in m and not interfaces:
        # Net-SNMP's default Debian config exposes only the system group ("view systemonly").
        add("snmp_view", "snmp_view",
            "SNMP agent only exposes basic system information (restricted view): interfaces, CPU, memory "
            "and storage are unavailable. Widen the view in the device's snmpd.conf")
    cpu, t = cpu_pct(m), limit("cpu")
    if cpu is not None and t is not None and cpu >= t:
        add("cpu", "cpu", f"CPU usage {cpu:.0f}% (threshold {num(t)}%)")
    mem, t = memory_used_pct(m), limit("mem")
    if mem is not None and t is not None and mem >= t:
        add("mem", "mem", f"Memory used {mem:.0f}% (threshold {num(t)}%)")
    full = limit("disk_full")
    for idx, s in tables.get("storage", {}).items():
        if full is not None and s.get("kind") in ("disk", "flash") and s.get("used_pct", 0) >= full:
            add("disk_full", f"storage:{idx}", f"Storage {s['descr']} {s['used_pct']:.0f}% full")
    for idx, v in tables.get("volumes", {}).items():
        # Profile-defined tables carry "ok"; the QNAP collector reports the word "Ready".
        if v.get("ok") is False or ("ok" not in v and v.get("status") and str(v["status"]).lower() != "ready"):
            add("volume_state", f"volume_state:{idx}", f"Volume {v['descr']} is {v['status']}")
        if full is not None and is_number(v.get("used_pct")) and v["used_pct"] >= full:
            add("disk_full", f"volume_full:{idx}", f"Volume {v['descr']} {v['used_pct']:.0f}% full")
    hot = limit("disk_temp")
    for idx, dsk in tables.get("disks", {}).items():
        if dsk.get("ok") is False or ("ok" not in dsk and dsk.get("smart") and str(dsk["smart"]).upper() != "GOOD"):
            add("disk_smart", f"disk_smart:{idx}", f"Disk {dsk['name']} ({dsk.get('model') or 'unknown model'}) SMART status {dsk['smart']}")
        if hot is not None and is_number(dsk.get("temp_c")) and dsk["temp_c"] >= hot:
            add("disk_temp", f"disk_temp:{idx}", f"Disk {dsk['name']} at {dsk['temp_c']} C (threshold {num(hot)} C)")
    hot = limit("sensor_temp")
    for idx, t in tables.get("sensors", {}).items():
        if hot is not None and is_number(t.get("temp_c")) and t["temp_c"] >= hot:
            add("sensor_temp", f"sensor_temp:{t.get('slug', idx)}",
                f"Sensor {t['name']} at {t['temp_c']:.0f} C (threshold {num(hot)} C)")
    for idx, h in tables.get("health", {}).items():
        if h.get("ok") is False:
            detail = h.get("status") or (f"{h['pct']:.0f}%" if is_number(h.get("pct")) else h.get("value"))
            add("health", f"health:{idx}", f"{(h.get('kind') or 'Component').capitalize()} {h.get('name') or idx}: {detail}",
                h.get("severity", "warning"))
    for pr in alerts.profile_rules(profile or {}):
        v = m.get(pr["key"])
        r = rule(pr["id"])
        if v is None or not r["enabled"]:
            continue
        if pr["op"]:
            hit = v < r["threshold"] if pr["op"] == "below" else v > r["threshold"]
        else:
            hit = (v in pr["values"]) != pr["negate"]
        if hit:
            word = pr["words"].get(str(int(v)) if float(v).is_integer() else str(v), f"{v:g}")
            add(pr["id"], f"alert:{pr['alert_id']}", pr["message"].replace("{value}", word))
    # Watched names: only judged when the table was collected, so an SNMP outage is not reported as every service stopping.
    for w in watches or []:
        table = tables.get("processes" if w["kind"] == "process" else "services", {})
        if not table:
            continue
        row = table.get(w["name"])
        if row is None:
            add("watch", f"watch:{w['kind']}:{w['name']}", f"Watched {w['kind']} {w['name']} is not running")
        elif w["kind"] == "service" and row.get("state") != "running":
            add("watch", f"watch:{w['kind']}:{w['name']}", f"Watched service {w['name']} is {row.get('state')}")
    band_names = {"ng": "2.4 GHz", "na": "5 GHz"}
    busy = limit("radio")
    for r in tables.get("radios", {}).values():
        if busy is not None and (r.get("util_pct") or 0) >= busy:
            add("radio", f"radio:{r.get('band')}",
                f"{band_names.get(r.get('band'), r.get('name'))} channel utilisation {r['util_pct']}%")
    worst = limit("port_errors")
    for idx, r in interfaces.items():
        if r.get("kind") != "port" or worst is None:
            continue
        errors = (r.get("in_errors_delta") or 0) + (r.get("out_errors_delta") or 0)
        if errors >= worst:
            add("port_errors", f"port_errors:{idx}",
                f"Port {r['label']} {('(' + r['alias'] + ') ') if r.get('alias') else ''}"
                f"logged {errors} error{'s' if errors != 1 else ''} since the last poll")
    uptime = m.get("uptime_seconds")
    if uptime is not None and uptime < RECENT_REBOOT_SECONDS:
        add("restarted", "restarted", f"Restarted {uptime / 60:.0f} minutes ago")
    lan_service_problems(device, m, tables, add, limit)
    return out


def lan_service_problems(device: Dict[str, Any], m: Dict[str, float], tables: Dict[str, Dict[str, Dict[str, Any]]],
                         add: Callable, limit: Callable) -> None:
    """Certificate expiry (website checks), DNS and Pi-hole (pihole.py), weak Wi-Fi (unifi.py), added through add."""
    days = m.get("tls_days_left")
    left = limit("cert_expiry")
    if is_number(days) and left is not None and days <= left:
        add("cert_expiry", "cert_expiry", f"Certificate of {device.get('service_url') or device['hostname']} "
            + (f"expired {abs(days):.0f} days ago" if days < 0 else f"runs out in {days:.0f} days"))
    if m.get("dns.ok") == 0:
        add("dns_down", "dns_down", "DNS is not answering: the test lookup got no reply")
    slow = limit("dns_slow")
    if m.get("dns.ok") == 1 and is_number(m.get("dns.ms")) and slow is not None and m["dns.ms"] >= slow:
        add("dns_slow", "dns_slow", f"DNS took {m['dns.ms']:.0f} ms to answer (threshold {slow:g} ms)")
    # A pause with a timer (from the Pi-hole page or Pi-hole's own) is not a problem.
    if m.get("pihole.blocking") == 0 and m.get("pihole.paused") != 1:
        add("pihole_blocking", "pihole_blocking", "Pi-hole blocking is switched off")
    old = limit("pihole_lists")
    if is_number(m.get("pihole.gravity_days")) and old is not None and m["pihole.gravity_days"] >= old:
        add("pihole_lists", "pihole_lists", f"Pi-hole blocklists last updated {m['pihole.gravity_days']:.0f} days ago")
    weak = limit("wifi_weak")
    if weak is not None:
        poor = sorted((c for c in tables.get("wifi_clients", {}).values() if is_number(c.get("signal")) and c["signal"] < weak),
                      key=lambda c: c["signal"])
        if poor:
            # A device can have its own line, or be left out (Inventory, Edit, Weak Wi-Fi signal), and so
            # can a whole Wi-Fi network (Inventory, Wi-Fi networks); the device's own rule wins.
            own, nets = inventory.wifi_alerts(), inventory.wifi_net_alerts()
            poor = [c for c in poor if c["signal"] < (inventory.weak_line(c.get("mac"), weak, own, c.get("ssid"), nets) or float("-inf"))]
        if poor:
            names = ", ".join(f"{c.get('name') or c.get('mac')} ({c['signal']:.0f} dBm)" for c in poor[:5])
            more = f" and {len(poor) - 5} more" if len(poor) > 5 else ""
            add("wifi_weak", "wifi_weak", f"{len(poor)} device{'s' if len(poor) != 1 else ''} on weak Wi-Fi: {names}{more}")


def is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def workflow_problems(device: Dict[str, Any], failures: list,
                      rule: Optional[Callable[[str], Dict[str, Any]]] = None) -> list:
    """A workflow whose latest run failed a step on this device is a problem there until a later run is clean."""
    wf_rule = (rule or alerts.default_policy().for_device(device))("workflow")
    if not wf_rule["enabled"]:
        return []
    out = []
    for f in failures:
        steps = [s["title"] for s in f["failed"] if s["host_id"] == device["id"]]
        if steps:
            out.append(_problem(device, wf_rule, "workflow", f"workflow:{f['workflow_id']}",
                                f"Workflow '{f['name']}' failed at: {steps[-1]}"))
    return out


def device_tables(device_id: int) -> Dict[str, Dict[str, Dict[str, Any]]]:
    return {name: database.get_device_table(device_id, name) for name in PROBLEM_TABLES}


def evaluate_problems() -> list:
    """Evaluates every device's triggers now (not the stored open set)."""
    devices = database.list_devices()
    latest = database.get_latest_metrics_all(SUMMARY_KEYS)
    policy = alert_policy()
    out = []
    failures = database.latest_workflow_failures()
    watches: Dict[int, list] = {}
    for w in database.list_watches():
        watches.setdefault(w["device_id"], []).append(w)
    profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
    forecasts = forecast.cached()
    for d in devices:
        m = latest.get(d["id"], {})
        profile = profiles.get(d["profile_id"], {})
        if profile.get("alerts"):
            m = dict(m, **{r["metric_key"]: r["value"] for r in database.get_latest_metrics(d["id"])})
        rule = policy.for_device(d)
        out.extend(device_problems(d, m, device_tables(d["id"]), rule, watches.get(d["id"]), profile))
        if d["status"] != "offline":
            out.extend(workflow_problems(d, failures, rule))
            out.extend(custom_oid_problems(d))
            out.extend(forecast_problems(d, rule, forecasts.get(d["id"], [])))
    out.extend(proxmox_problems(devices, policy))
    return root_cause(out, devices)


def proxmox_problems(devices: List[Dict[str, Any]], policy: alerts.Policy, lay: Optional[Dict[str, Any]] = None,
                     now: Optional[float] = None) -> list:
    """Guests that should run and do not, that keep restarting, or run out of memory or disk (proxmox.py).
    A problem goes on the guest's own monitored device, or on its node's when the guest is not monitored."""
    lay = lay if lay is not None else proxmox.layout()
    if not lay.get("guests"):
        return []
    now = now if now is not None else time.time()
    by_id = {d["id"]: d for d in devices}
    node_dev = {n["node"]: by_id.get(n.get("device_id")) for n in lay.get("nodes", [])}
    out = []
    for g in lay["guests"]:
        own = by_id.get(g.get("device_id"))
        dev = own or node_dev.get(g["node"])
        if not dev:
            continue
        rule = policy.for_device(dev)
        name = f"{g.get('name') or 'guest'} ({g['vmid']})"
        where = "" if own else f" on {g['node']}"

        def add(rule_id: str, message: str) -> None:
            r = rule(rule_id)
            if r["enabled"]:
                out.append(_problem(dev, r, rule_id, f"{rule_id}:{g['node']}/{g['vmid']}", message))

        if g.get("onboot") and g.get("status") != "running":
            add("pve_guest_down", f"Guest {name}{where} is {g.get('status') or 'not running'}, although it starts at boot")
        if g.get("status") != "running":
            continue
        n = len([t for t in (lay.get("restarts") or {}).get(f"{g['node']}/{g['vmid']}", []) if now - t < 3600])
        limit = rule("pve_guest_restarts")["threshold"]
        if limit and n >= limit:
            add("pve_guest_restarts", f"Guest {name}{where} restarted {n} times in the last hour")
        if g.get("maxmem") and is_number(g.get("mem")):
            pct, limit = 100.0 * g["mem"] / g["maxmem"], rule("pve_guest_memory")["threshold"]
            if limit and pct >= limit:
                add("pve_guest_memory", f"Guest {name}{where} uses {pct:.0f}% of its memory (threshold {limit:g}%)")
        if g.get("type") == "lxc" and g.get("maxdisk") and is_number(g.get("disk")):
            pct, limit = 100.0 * g["disk"] / g["maxdisk"], rule("pve_guest_disk")["threshold"]
            if limit and pct >= limit:
                add("pve_guest_disk", f"Container {name}{where} disk {pct:.0f}% full (threshold {limit:g}%)")
    return out


# Added to an offline device's problem; the grouped Telegram message reads the names after it.
BEHIND_NOTE = ". Also unreachable behind it: "

# A volume emptier than this is not warned about however fast it grows (57% and growing after a
# clean-up was noise).
FORECAST_MIN_PCT = 80


def forecast_problems(device: Dict[str, Any], rule: Callable[[str], Dict[str, Any]], rows: list) -> list:
    """A volume or disk at least FORECAST_MIN_PCT full and forecast to be full within the rule's number of days (forecast.py)."""
    r = rule("forecast_full")
    if not r["enabled"] or r["threshold"] is None:
        return []
    rows = [f for f in rows if isinstance(f.get("now"), (int, float)) and f["now"] >= FORECAST_MIN_PCT]
    return [_problem(device, r, "forecast_full", f"forecast_full:{f['key']}",
                     f"{f['label']} is {f['now']:.0f}% full and growing {f['per_day']:.2f} points a day: full in about {f['days']:.0f} days")
            for f in rows if f["days"] is not None and f["days"] <= r["threshold"]]


# Devices unreachable only because something upstream of them is down (map parents), with that device.
BEHIND: Dict[int, int] = {}


def upstream_chain(parent: Dict[str, Optional[str]], device_id: int) -> List[int]:
    """The monitored devices above one on the map, nearest first (objects such as a modem are passed over)."""
    out, node, seen = [], f"d:{device_id}", set()
    while node and node not in seen:
        seen.add(node)
        node = parent.get(node)
        if node and node.startswith("d:"):
            out.append(int(node[2:]))
    return out


def root_cause(problems: list, devices: List[Dict[str, Any]], parent: Optional[Dict[str, Optional[str]]] = None) -> list:
    """Root-cause alerts: an unreachable device whose upstream on the map is also unreachable is "behind"
    the highest unreachable device of that unbroken chain. Its problem says so and sends no message of
    its own (BEHIND, see the problem job); the device that failed lists those behind it."""
    down = {p["device_id"] for p in problems if p["key"] == "unreachable"}
    BEHIND.clear()
    if len(down) < 2:
        return problems
    try:
        parent = parent if parent is not None else map_view()["parent"]
    except Exception:
        log.exception("Map unavailable for root-cause alerts")
        return problems
    names = {d["id"]: d["hostname"] for d in devices}
    for dev in down:
        root = None
        for up in upstream_chain(parent, dev):
            if up not in down:
                break
            root = up
        if root is not None:
            BEHIND[dev] = root
    for p in problems:
        if p["key"] != "unreachable":
            continue
        if p["device_id"] in BEHIND:
            p["message"] = f"Unreachable behind {names.get(BEHIND[p['device_id']], 'an upstream device')}, which is down"
        else:
            hidden = sorted(names.get(d, str(d)) for d, r in BEHIND.items() if r == p["device_id"])
            if hidden:
                p["message"] += f"{BEHIND_NOTE}{', '.join(hidden)}"
    return problems


def custom_oid_problems(device: Dict[str, Any]) -> list:
    """Thresholds set on custom OIDs (customoids.py). Their own severity; Telegram follows the minimum severity."""
    if not customoids.for_device(device):
        return []
    latest = {r["metric_key"]: r["value"] for r in database.get_latest_metrics(device["id"]) if r["metric_key"].startswith("custom.")}
    return [{"device_id": device["id"], "hostname": device["hostname"], "key": p["key"], "rule": "custom",
             "severity": p["severity"], "message": p["message"], "for_s": 0, "telegram": "default", "resolved": "on"}
            for p in customoids.problems(device, latest)]


def all_problems() -> list:
    """Open problems as tracked by the problem engine, with start time."""
    return database.list_active_problems()


# Groups on the devices page and in the map. A template's category picks the group; the
# administrator can choose another per device (devices.device_group). id -> (label, order).
# The built-in groups; custom ones, names and order live in taxonomy.py.
DEVICE_GROUPS = taxonomy.BUILTIN_GROUPS
CATEGORY_GROUP = {"gateway": "gateway", "router": "gateway", "firewall": "gateway", "switch": "switch",
                  "wireless_ap": "wireless_ap", "nas": "nas", "server": "server", "workstation": "workstation",
                  "power": "power", "printer": "printer", "service": "service", "ping": "other"}
# Details the administrator may fill in or correct in the app; shown instead of what the device reports.
OVERRIDE_FIELDS = {"sys_name": "Name reported", "sys_location": "Location", "sys_contact": "Contact", "model": "Model"}
# Info problems (a restart, for example) leave the devices page after this long; warnings stay until fixed.
INFO_ATTENTION_SECONDS = 30 * 60
ATTENTION_EVENT_TYPES = ("reboot", "problem", "telegram", "action", "workflow")


def device_group(device: Dict[str, Any], profiles: Optional[Dict[str, Dict[str, Any]]] = None,
                 known: Optional[set] = None) -> str:
    """The administrator's choice (a built-in or custom group), else the group of the template's category."""
    if device.get("device_group") and device["device_group"] in (known if known is not None else taxonomy.group_ids()):
        return device["device_group"]
    profiles = profiles or {p["profile_id"]: p for p in poller.load_hardware_profiles()}
    category = (profiles.get(device.get("profile_id")) or {}).get("category", "")
    return CATEGORY_GROUP.get(category, "other")


def apply_overrides(device: Dict[str, Any]) -> Dict[str, Any]:
    """The inventory as shown: administrator overrides win; the polled values stay under inventory_polled."""
    inv = dict(device.get("inventory") or {})
    over = {k: v for k, v in (device.get("overrides") or {}).items() if k in OVERRIDE_FIELDS and v}
    if over:
        device["inventory_polled"] = {k: inv.get(k) for k in over}
        inv.update(over)
    device["inventory"] = inv
    return device


def attention_by_device(devices: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """The one thing worth showing next to each device's status: its worst open problem, or an
    event of the last half hour (a restart, a Telegram message) that then fades away."""
    rank = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    now = time.time()
    out: Dict[int, Dict[str, Any]] = {}
    for p in database.list_active_problems():
        if p.get("severity") == "info" and now - (p.get("since") or now) > INFO_ATTENTION_SECONDS:
            continue
        cur = out.get(p["device_id"])
        if cur is None or rank.get(p["severity"], 3) < rank.get(cur["severity"], 3):
            out[p["device_id"]] = {"kind": "problem", "severity": p["severity"], "message": p["message"],
                                   "since": p.get("since"), "acknowledged": bool(p.get("acknowledged_at"))}
    recent, _ = database.list_events_filtered(since=int(now - INFO_ATTENTION_SECONDS), limit=500)
    for e in recent:
        # Routine changes (added, edited, software, inventory) are for the event log, not the marker.
        if e.get("event_type") not in ATTENTION_EVENT_TYPES:
            continue
        if e.get("device_id") and e["device_id"] not in out:
            out[e["device_id"]] = {"kind": "event", "severity": e["severity"], "message": e["message"],
                                   "since": e["timestamp"], "event_id": e["id"]}
    return out


def device_list_view() -> list:
    """Device inventory joined with headline metrics and port counts for the devices table."""
    devices = database.list_devices()
    profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
    known_groups = taxonomy.group_ids()
    attention = attention_by_device(devices)
    latest = database.get_latest_metrics_all(SUMMARY_KEYS)
    ifaces_by_device: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for row in database.get_table_all_devices("interfaces"):
        ifaces_by_device.setdefault(row["device_id"], {})[row["row_key"]] = row
    for d in devices:
        d.pop("snmp_community", None)
        d["snmp_v3"] = public_snmp_v3(d.get("snmp_v3") or {})
        apply_overrides(d)
        d["group"] = device_group(d, profiles, known_groups)
        d["tags"] = taxonomy.device_tags(d)
        d["snmp"] = profile_uses_snmp(d.get("profile_id"), profiles)
        d["attention"] = attention.get(d["id"])
        m = latest.get(d["id"], {})
        d["summary"] = {
            "uptime_seconds": m.get("uptime_seconds"),
            "cpu_pct": cpu_pct(m),
            "mem_pct": memory_used_pct(m),
            "clients": m.get("clients_total"),
            "clients_2g": m.get("clients_2g"),
            "clients_5g": m.get("clients_5g"),
            "channel_2g": m.get("radio_2g_channel"),
            "channel_5g": m.get("radio_5g_channel"),
            "util_2g": m.get("radio_2g_util_pct"),
            "util_5g": m.get("radio_5g_util_pct"),
            "ports": port_summary(ifaces_by_device.get(d["id"], {})),
        }
    return devices


# Interface kinds kept as 7-day raw history only, without hourly long-term trends.
SHORT_TERM_IF_KINDS = ("vlan", "bridge", "radio")


def untracked_keys(device: Dict[str, Any]) -> list:
    profile = next((p for p in poller.load_hardware_profiles() if p["profile_id"] == device["profile_id"]), {})
    return sorted({m["key"] for m in profile.get("metrics", []) if m.get("history") == "none"} | {"uptime_seconds"})


def metric_info(device: Dict[str, Any]) -> Dict[str, Any]:
    """Labels, units, groups and value words the profile gives its metrics, for the UI."""
    profile = next((p for p in poller.load_hardware_profiles() if p["profile_id"] == device["profile_id"]), {})
    info = {s["key"]: {k: s[k] for k in ("label", "unit", "group", "values", "kpi") if k in s}
            for s in profile.get("metrics", []) if s.get("label")}
    info.update(customoids.metric_info(device))
    return info


# The graphs a device's Overview tab shows, when someone chose them (otherwise the default set).
# One internal setting, {device id: [graph id, ...]}: a graph id is the key of its first series
# (cpu_usage_pct, if.5.in_bps, custom.3), so it survives renames. A normal backup carries it.
OVERVIEW_KEY = "overview_graphs"
OVERVIEW_MAX = 12
_GRAPH_ID = re.compile(r"[\w.:-]{1,80}")


def _overview_all() -> Dict[str, List[str]]:
    try:
        value = json.loads(database.get_all_settings().get(OVERVIEW_KEY) or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def overview_graphs(device_id: int) -> Optional[List[str]]:
    chosen = _overview_all().get(str(device_id))
    return chosen if isinstance(chosen, list) else None


def set_overview_graphs(device_id: int, graphs: Optional[List[str]]) -> None:
    """graphs None goes back to the default set."""
    every = _overview_all()
    if graphs is None:
        every.pop(str(device_id), None)
    else:
        every[str(device_id)] = graphs
    database.set_internal_setting(OVERVIEW_KEY, json.dumps(every))


def short_term_metric_keys() -> set:
    """(device_id, key) rate series that get no hourly trend (VLAN, bridge and radio interfaces)."""
    out = set()
    for r in database.get_table_all_devices("interfaces"):
        if r.get("kind") in SHORT_TERM_IF_KINDS:
            out.add((r["device_id"], f"if.{r['row_key']}.in_bps"))
            out.add((r["device_id"], f"if.{r['row_key']}.out_bps"))
    return out


def wan_interfaces() -> list:
    """WAN uplinks: interfaces named by a profile metric whose key starts with "wan_"."""
    profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
    out = []
    for d in database.list_devices():
        names = {m["if_name"] for m in profiles.get(d["profile_id"], {}).get("metrics", [])
                 if m.get("if_name") and m["key"].startswith("wan_")}
        if not names:
            continue
        latest = None
        for r in database.get_device_table(d["id"], "interfaces").values():
            if r.get("label") in names:
                if latest is None:
                    latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(d["id"])}
                out.append({"device_id": d["id"], "hostname": d["hostname"], "if_index": r["if_index"],
                            "label": r["label"], "oper": r.get("oper"), "speed_mbps": r.get("speed_mbps"),
                            "in_bps": r.get("in_bps"), "out_bps": r.get("out_bps"),
                            "in_peak_bps": latest.get(f"if.{r['if_index']}.in_peak_bps"),
                            "out_peak_bps": latest.get(f"if.{r['if_index']}.out_peak_bps")})
    return out


_MAP_NODE = re.compile(r"(d:\d+|o:\d+|monitor)")


def monitor_address() -> Optional[str]:
    """This server's LAN address: the source address the OS would use towards the gateway.

    A UDP connect only selects a route; no packet is sent.
    """
    target = next((d["ip_address"] for d in database.list_devices() if d["profile_id"] == "unifi_gateway"), None)
    if not target:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def map_view() -> Dict[str, Any]:
    """Inferred topology merged with the administrator's objects, manual links, hidden links and positions."""
    devices = database.list_devices()
    fdb: Dict[int, Dict[str, int]] = {}
    for r in database.get_table_all_devices("fdb"):
        fdb.setdefault(r["device_id"], {})[r["row_key"]] = r["if_index"]
    arp = {r["row_key"]: r["mac"] for r in database.get_table_all_devices("arp")}
    imacs: Dict[int, set] = {}
    labels: Dict[int, Dict[int, str]] = {}
    for r in database.get_table_all_devices("interfaces"):
        if r.get("mac"):
            imacs.setdefault(r["device_id"], set()).add(r["mac"])
        labels.setdefault(r["device_id"], {})[r["if_index"]] = r.get("label") or str(r["if_index"])
    inferred = topology.infer(devices, fdb, arp, imacs, monitor_address())

    def port_label(node: str, port: Optional[int]) -> Optional[str]:
        if port is None or not node.startswith("d:"):
            return None
        return labels.get(int(node[2:]), {}).get(port, str(port))

    problems: Dict[int, int] = {}
    for p in database.list_active_problems():
        if p["severity"] != "info" and not p.get("acknowledged_at"):
            problems[p["device_id"]] = problems.get(p["device_id"], 0) + 1
    nodes = inferred["nodes"]
    for n in nodes:
        n["problems"] = problems.get(n["device_id"], 0) if n["device_id"] else 0
        n["clients"] = sum(inferred["clients"].get(n["key"], {}).values())
    for o in database.list_map_objects():
        nodes.append({"key": f"o:{o['id']}", "object_id": o["id"], "device_id": None, "label": o["label"],
                      "kind": o["kind"], "status": None, "ip": None, "problems": 0, "clients": 0})
    keys = {n["key"] for n in nodes}

    links = {}
    for l in inferred["links"]:
        links[(l["a"], l["b"])] = dict(l, a_port=port_label(l["a"], l["a_port"]), b_port=port_label(l["b"], l["b_port"]),
                                       hidden=False)
    for m in database.list_map_links():
        if m["node_a"] not in keys or m["node_b"] not in keys:
            continue
        pair = (m["node_a"], m["node_b"])
        if m["hidden"]:
            if pair in links:
                links[pair]["hidden"] = True
        else:
            links[pair] = {"a": pair[0], "b": pair[1], "a_port": None, "b_port": None, "source": "manual", "hidden": False}
    links_list = list(links.values())

    root = next((n["key"] for n in nodes if n["kind"] == "gateway"), nodes[0]["key"] if nodes else None)
    parent = topology.tree(sorted(keys), links_list, root) if root else {}
    # UniFi (unifi.py) knows the layout: which device and port each UniFi device is plugged into,
    # and where clients are connected. Its links replace the guessed ones (a link to one of the
    # administrator's objects stays: UniFi cannot see an unmanaged switch); the uplink set below still
    # has the last word.
    # Proxmox knows which node runs each guest: that replaces the guessed host of a VM or container.
    lay = proxmox.layout()
    if lay.get("guests") and root:
        node_key = {n["node"]: f"d:{n['device_id']}" for n in lay.get("nodes", []) if n.get("device_id")}
        changed = False
        for g in lay["guests"]:
            child, up = f"d:{g['device_id']}" if g.get("device_id") else None, node_key.get(g["node"])
            if not child or not up or child == up or child not in keys or up not in keys:
                continue
            guessed = parent.get(child)
            if guessed == up:
                continue
            if guessed and not str(guessed).startswith("o:"):
                links.pop(tuple(sorted((child, guessed))), None)
            pair = tuple(sorted((child, up)))
            links[pair] = {"a": pair[0], "b": pair[1], "a_port": None, "b_port": None, "source": "proxmox",
                           "kind": "virtual", "hidden": False}
            changed = True
        if changed:
            links_list = list(links.values())
            parent = topology.tree(sorted(keys), links_list, root)
    uf_links, ap_clients = unifi_map_links(devices, imacs, labels)
    if uf_links and root:
        for child, up, port, kind in uf_links:
            if child not in keys or up not in keys or child == up or str(parent.get(child) or "").startswith("o:"):
                continue
            guessed = parent.get(child)
            # A VM, container or service on a host: UniFi sees it on the host's switch port, but it
            # lives on the host (its virtual link stays).
            current = links.get(tuple(sorted((child, guessed)))) if guessed else None
            if current and current.get("kind") in ("virtual", "service"):
                continue
            if guessed and guessed != up:
                links.pop(tuple(sorted((child, guessed))), None)
            pair = tuple(sorted((child, up)))
            old = links.get(pair, {})
            links[pair] = dict({"a": pair[0], "b": pair[1], "a_port": port if pair[0] == up else old.get("a_port"),
                                "b_port": port if pair[1] == up else old.get("b_port"), "source": "unifi",
                                "hidden": old.get("hidden", False)}, **({"kind": "wifi"} if kind == "wifi" else {}))
        links_list = list(links.values())
        parent = topology.tree(sorted(keys), links_list, root)
    for n in nodes:
        if n["key"] in ap_clients:
            n["clients"] = ap_clients[n["key"]]
    # The upstream set on a device (Edit device) is authoritative: its guessed uplink goes and
    # the link set there takes its place.
    owned = False
    for d in devices:
        up = d.get("upstream_device_id")
        child, up_key = f"d:{d['id']}", f"d:{up}"
        if not up or child not in keys or up_key not in keys:
            continue
        guessed = parent.get(child)
        if guessed and guessed != up_key:
            links.pop(tuple(sorted((child, guessed))), None)
        pair = tuple(sorted((child, up_key)))
        port = d.get("upstream_port") or None
        links[pair] = {"a": pair[0], "b": pair[1], "a_port": port if pair[0] == up_key else None,
                       "b_port": port if pair[1] == up_key else None, "source": "owner", "hidden": False}
        owned = True
    if owned:
        links_list = list(links.values())
        parent = topology.tree(sorted(keys), links_list, root) if root else {}
    return {"nodes": nodes, "links": links_list, "root": root, "parent": parent,
            "positions": database.get_map_positions(), "object_kinds": list(database.MAP_OBJECT_KINDS)}


def unifi_map_links(devices: List[Dict[str, Any]], imacs: Dict[int, set], labels: Dict[int, Dict[int, str]]):
    """From UniFi's layout: [(child node, parent node, port label on the parent, "cable" or "wifi")] for
    monitored devices, and the Wi-Fi client count of each monitored access point ({node: count})."""
    uf = unifi.topology()
    if not uf.get("devices"):
        return [], {}
    by_ip = proxmox.devices_by_ip(devices)

    def node(mac: str, ip: Optional[str]) -> Optional[str]:
        if ip and ip in by_ip:
            return f"d:{by_ip[ip]}"
        mac = (mac or "").lower()
        hit = next((i for i, macs in imacs.items() if mac and mac in {str(m).lower() for m in macs}), None)
        return f"d:{hit}" if hit else None

    def port_label(parent: str, port: Any, names: Dict[str, Any]) -> Optional[str]:
        if port in (None, ""):
            return None
        n = str(port)
        own = labels.get(int(parent[2:]), {}) if parent.startswith("d:") else {}
        for label in own.values():
            if str(label).endswith(f"/{n}") or str(label) in (n, f"Port {n}"):
                return str(label)
        return names.get(n) or f"Port {n}"

    infra = {d["mac"]: d for d in uf["devices"] if d.get("mac")}
    out, counts = [], {}
    for d in uf["devices"]:
        child = node(d["mac"], d.get("ip"))
        up = infra.get(d.get("uplink_mac") or "")
        parent = node(up["mac"], up.get("ip")) if up else None
        if child and parent:
            out.append((child, parent, port_label(parent, d.get("uplink_port"), up.get("ports") or {}),
                        "wifi" if d.get("uplink_type") == "wireless" else "cable"))
    monitored = set()
    for c in uf.get("clients") or []:
        child = node(c.get("mac"), c.get("ip"))
        if c.get("wired"):
            sw = infra.get(c.get("sw_mac") or "")
            parent = node(sw["mac"], sw.get("ip")) if sw else None
            if child and parent:
                out.append((child, parent, port_label(parent, c.get("sw_port"), sw.get("ports") or {}), "cable"))
        else:
            ap = infra.get(c.get("ap_mac") or "")
            parent = node(ap["mac"], ap.get("ip")) if ap else None
            if child and parent:
                out.append((child, parent, None, "wifi"))
                monitored.add(child)
            elif parent:
                counts[parent] = counts.get(parent, 0) + 1
    return out, counts


def wifi_view() -> Dict[str, Any]:
    """The Wi-Fi page: every monitored access point and every Wi-Fi device on them (unifi.py)."""
    weak = alert_policy().resolve("wifi_weak", upto="global")[0]["threshold"] or -75
    own, nets = inventory.wifi_alerts(), inventory.wifi_net_alerts()
    nets_lower = {k.lower(): v for k, v in nets.items()}
    aps, rows = [], []
    for d in database.list_devices():
        table = database.get_device_table(d["id"], "wifi_clients")
        if not table:
            continue
        clients = list(table.values())
        scores = [c["experience"] for c in clients if is_number(c.get("experience"))]
        bands: Dict[str, int] = {}
        for c in clients:
            bands[c.get("band") or "?"] = bands.get(c.get("band") or "?", 0) + 1
        aps.append({"device_id": d["id"], "name": d["hostname"], "ip": d["ip_address"], "status": d["status"],
                    "clients": len(clients), "weak": sum(1 for c in clients if is_number(c.get("signal")) and c["signal"] < weak),
                    "experience": round(sum(scores) / len(scores)) if scores else None, "bands": bands})
        for c in clients:
            rows.append(dict(c, ap_id=d["id"], ap_name=d["hostname"], blocked=unifi.why_not(c),
                             alert=own.get(inventory.normalise_mac(c.get("mac")) or "", ""),
                             net_alert=nets_lower.get(str(c.get("ssid") or "").lower(), "")))
    return {"aps": sorted(aps, key=lambda a: a["name"].lower()), "clients": rows, "weak_dbm": weak,
            "never": unifi.never_list(), "last": unifi.LAST.copy()}


# --- Host actions (hostactions.py): the fixed catalogue of maintenance jobs, run once over SSH ---

def host_action_guest(device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The Proxmox guest this device is, when the action token can snapshot it; otherwise None."""
    try:
        if not (proxmox.is_enabled() and proxmox.is_configured() and proxmox.actions_ready()):
            return None
        g = next((g for g in proxmox.layout().get("guests", []) if g.get("device_id") == device["id"]), None)
    except Exception:
        return None
    if not g or g.get("type") not in ("qemu", "lxc"):
        return None
    return {"node": str(g["node"]), "type": g["type"], "vmid": int(g["vmid"]), "name": g.get("name") or ""}


def is_this_machine(device: Dict[str, Any]) -> bool:
    """True when the device's address is one of this monitor's own (the route to it is local)."""
    return snmpfix.source_address(device["ip_address"]) == device["ip_address"]


def host_action_view(device: Dict[str, Any], problem_key: str) -> Dict[str, Any]:
    guest = host_action_guest(device)
    return {"device": {"id": device["id"], "hostname": device["hostname"], "profile_id": device["profile_id"],
                       "host_key": bool(database.get_host_keys(device["id"])),
                       "guest": guest and {"name": guest["name"], "vmid": guest["vmid"]}},
            "suggested": hostactions.suggest(problem_key),
            "runs": database.list_action_runs(device["id"], 10),
            "running": hostactions.RUNS.running().get(device["id"])}


def _host_action_workflow(device: Dict[str, Any], action: Dict[str, Any], choice: Optional[str], cred_id: int,
                          port: int, saved_by: Optional[str] = None) -> int:
    """Saves the action as a manual workflow on this host: run it again from there, or give it a schedule."""
    step = {"type": "command", "device_ids": [device["id"]], "credential_id": cred_id, "ssh_port": port,
            "command": hostactions.workflow_script(action["id"], choice), "timeout_s": max(30, min(3600, action["timeout"])),
            "label": action["name"][:80], "expect_disconnect": bool(action.get("reboot"))}
    steps = [step]
    if action.get("reboot"):
        steps += [{"type": "wait_ping", "device_id": device["id"], "state": "down", "timeout_s": 180},
                  {"type": "wait_ping", "device_id": device["id"], "state": "up", "timeout_s": 900}]
    devices = {d["id"] for d in database.list_devices()}
    creds = {c["id"] for c in database.list_credentials()}
    try:
        graph = workflows.steps_to_graph(workflows.parse_steps(steps, devices, creds))
    except workflows.WorkflowError as exc:
        raise RequestError(400, str(exc))
    name = f"{action['name']} on {device['hostname']}"[:80]
    fields = workflow_fields(name, "Made from a host action. Add a schedule on its trigger to repeat it.", graph, True)
    fields["saved_by"] = saved_by
    return database.save_workflow(None, fields)


def run_host_action(run_id: int, device: Dict[str, Any], action: Dict[str, Any], choice: Optional[str],
                    cred: Dict[str, Any], keys: list, port: int, guest: Optional[Dict[str, Any]], username: str) -> None:
    """One run on its own thread: optional snapshot, the script, and for a restart the ping waits."""
    out: List[str] = []
    state = {"status": "error", "code": None}
    window = None

    def save(status: str, finished: bool = False) -> None:
        database.update_action_run(run_id, status, hostactions.trim("\n".join(out)), state["code"], finished)

    try:
        if guest:
            out.append(f"Taking a Proxmox snapshot of {guest['name'] or guest['vmid']} first...")
            save("running")
            try:
                snap = proxmox.snapshot(guest["node"], guest["type"], guest["vmid"], f"Before host action '{action['name']}'", 600)
            except proxmox.ProxmoxError as exc:
                out.append(f"The snapshot failed, so the action did not run: {exc}")
                state["status"] = "failed"
                return
            out[-1] = f"Snapshot {snap} taken (Proxmox, the guest, Snapshots)."
            save("running")
        if action.get("reboot"):
            now = time.time()
            window = maintenance.add("device", str(device["id"]), now, now + 30 * 60, f"Host action '{action['name']}'",
                                     f"action:{run_id}", now=now)["id"]
        r = ssh_runner.run_command(device["ip_address"], port, cred, hostactions.script(action["id"], "run", choice), keys,
                                   action["timeout"])
        state["code"] = r.get("exit_code")
        text = ((r.get("stdout") or "") + (("\n" + r["stderr"]) if r.get("stderr") else "")).strip()
        plain = hostactions.plain_failure(r, snmpfix.login_problem)
        if plain and not (action.get("reboot") and workflows.dropped(r)):
            out.append(plain)
            state["status"] = "failed"
            return
        if text:
            out.append(text)
        if state["code"] == hostactions.NOT_FOUND:
            state["status"] = "failed"
            return
        ok = r["status"] == "completed" and state["code"] == 0 or (action.get("reboot") and workflows.dropped(r))
        if not ok:
            out.append(f"Exit code {state['code']}")
            state["status"] = "failed"
            return
        if action.get("reboot"):
            out.append("Waiting for it to stop answering ping...")
            save("running")
            ok = _wait_ping(device["ip_address"], False, 180)
            out[-1] = "It stopped answering ping." if ok else "It kept answering ping for 3 minutes: did it restart?"
            if ok:
                out.append("Waiting for it to answer again...")
                save("running")
                ok = _wait_ping(device["ip_address"], True, 900)
                out[-1] = "It answers ping again." if ok else "It did not answer ping within 15 minutes."
            if not ok:
                state["status"] = "failed"
                return
        state["status"] = "ok"
    except Exception as exc:
        logging.getLogger("hostactions").exception("Host action run %s crashed", run_id)
        out.append(f"Internal error: {exc}")
        state["status"] = "error"
    finally:
        if window:
            try:
                maintenance.end_at(window, time.time() + 300)
            except Exception:
                logging.getLogger("hostactions").exception("Could not end maintenance window %s", window)
        if action["kind"] != "check":
            word = "done" if state["status"] == "ok" else "failed"
            database.add_event(device["id"], "info" if state["status"] == "ok" else "warning", "action",
                               f"Host action '{action['name']}'{(' (' + choice + ')') if choice else ''} {word} (by {username})")
        save(state["status"], finished=True)
        hostactions.RUNS.release(device["id"])


def _wait_ping(ip: str, up: bool, timeout: int) -> bool:
    deadline = time.time() + timeout
    streak = 0
    while time.time() < deadline:
        alive, _ = poller.ping_host(ip, 2.0)
        if not up and not alive:
            return True
        streak = streak + 1 if (up and alive) else 0
        if streak >= workflows.UP_STREAK:
            return True
        time.sleep(workflows.POLL_SECONDS)
    return False


def host_action(user: Any, device: Dict[str, Any], action_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """modes: choices (list a service, container or pool on the host), preview, run, workflow (save as a workflow)."""
    action = hostactions.BY_ID.get(action_id)
    if not action:
        raise RequestError(404, "Unknown action")
    mode = _get_str(payload, "mode", "run", max_len=10)
    if mode not in ("choices", "preview", "run", "workflow"):
        raise RequestError(400, "mode must be choices, preview, run or workflow")
    name = device["hostname"]
    try:
        choice = None if mode == "choices" else hostactions.check_choice(action, _get_str(payload, "choice", "", max_len=128))
    except hostactions.ActionError as exc:
        raise RequestError(400, str(exc))
    cred_id = _get_int(payload, "credential_id", None, 1, 2**31)
    port = _get_int(payload, "ssh_port", 22, 1, 65535)
    check_credential_use(user, cred_id)
    if mode == "workflow":
        if not user.can("automation.edit"):
            raise RequestError(403, "Making workflows needs the Edit workflows permission")
        if not cred_id or cred_id not in {c["id"] for c in database.list_credentials()}:
            raise RequestError(400, "Choose a stored credential")
        wid = _host_action_workflow(device, action, choice, cred_id, port, user.username)
        database.add_audit("workflow", f"Created workflow from host action {action['name']} on {name}",
                           f"Workflow {wid}, by {user.username}")
        return {"workflow_id": wid}
    cred = database.get_credential_secret(cred_id) if cred_id else None
    if not cred:
        raise RequestError(400, "Choose a stored credential (root, or a user allowed to run sudo without a password)")
    keys = database.get_host_keys(device["id"])
    if not keys:
        raise RequestError(409, f"Approve {name}'s SSH host key first")
    if mode == "choices":
        if not (action.get("choice") or {}).get("list"):
            raise RequestError(400, "This action has nothing to choose from the host")
        r = ssh_runner.run_command(device["ip_address"], port, cred, hostactions.script(action_id, "list"), keys, 30)
        plain = hostactions.plain_failure(r, snmpfix.login_problem)
        if plain:
            raise RequestError(502, plain)
        options = hostactions.parse_list(r.get("stdout") or "")
        if action["kind"] == "restart" and action["choice"]["list"] == "services":
            options = [o for o in options if not hostactions.BLOCKED_SERVICES.fullmatch(o)]
        return {"options": options}
    if mode == "preview":
        if "preview" not in action:
            raise RequestError(400, "This action changes nothing: run it directly")
        r = ssh_runner.run_command(device["ip_address"], port, cred, hostactions.script(action_id, "preview", choice), keys, 120)
        plain = hostactions.plain_failure(r, snmpfix.login_problem)
        if plain:
            raise RequestError(502, plain)
        text = ((r.get("stdout") or "") + (("\n" + r["stderr"]) if r.get("stderr") else "")).strip()
        if r.get("exit_code") == hostactions.NOT_FOUND:
            raise RequestError(404, text or "Not found on this host")
        hostactions.PREVIEWS.mark(user.username, device["id"], action_id, choice)
        return {"output": hostactions.trim(text)}
    # run
    if action["kind"] != "check" and not hostactions.PREVIEWS.fresh(user.username, device["id"], action_id, choice):
        raise RequestError(409, "Preview it first (a preview stays valid for 15 minutes)")
    if action["kind"] == "restart":
        if _get_str(payload, "confirm", "", max_len=200).strip().lower() != name.strip().lower():
            raise RequestError(400, f"Type the device's name ({name}) to confirm")
        if action.get("reboot") and is_this_machine(device):
            raise RequestError(409, "This is the machine the monitor runs on: restart it from its own console")
    guest = host_action_guest(device) if payload.get("snapshot") is True and action["kind"] != "check" else None
    if payload.get("snapshot") is True and action["kind"] != "check" and not guest:
        raise RequestError(409, "A snapshot needs this device linked to a Proxmox guest and the action token (Settings, Proxmox)")
    problem_key = _get_str(payload, "problem_key", "", max_len=200)
    try:
        run_id = hostactions.RUNS.claim(device["id"], lambda: database.start_action_run(
            device["id"], action_id, action["name"], choice or "", user.username, problem_key))
    except hostactions.ActionError as exc:
        raise RequestError(409, str(exc))
    database.add_audit("action", f"Ran host action {action['name']} on {name}",
                       f"Run {run_id}{', ' + choice if choice else ''}{', snapshot first' if guest else ''}, by {user.username}")
    threading.Thread(target=run_host_action, name=f"hostaction-{run_id}", daemon=True,
                     args=(run_id, device, action, choice, cred, keys, port, guest, user.username)).start()
    return {"run_id": run_id}


def fix_snmp(device: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """Preview or apply the snmpd.conf change for a Linux host (see snmpfix.py)."""
    mode = _get_str(payload, "mode", "preview", max_len=8)
    if mode not in ("preview", "apply", "script"):
        raise RequestError(400, "mode must be preview, apply or script")
    cred_id = _get_int(payload, "credential_id", None, 1, 2**31)
    cred = database.get_credential_secret(cred_id) if cred_id else None
    # Reasons Fix SNMP cannot run are ActionErrors: recorded as events, so they reach the notification centre.
    name = device["hostname"]
    port = _get_int(payload, "ssh_port", 22, 1, 65535)
    keys = database.get_host_keys(device["id"])
    # The source address the host will see: the route towards the host itself (works without a
    # gateway device; the gateway route is the fallback when the host does not resolve yet).
    monitor_ip = snmpfix.source_address(device["ip_address"]) or monitor_address()
    if not monitor_ip:
        raise ActionError(409, f"Fix SNMP on {name}: could not work out this monitor's address towards the host", device["id"])
    settings = database.get_all_settings()
    # A device on SNMPv3 gets its user written; any other its community (and the default, hidden too).
    v3 = poller.snmp_target(device) if device.get("snmp_version") == "v3" else None
    if v3 is not None:
        community = None
        secrets = [v3.auth_password, v3.priv_password]
        problem = (v3.problems() or [None])[0] or snmpfix.v3_problem(v3)
        target = v3
    else:
        community = device.get("snmp_community") or get_setting(settings, "default_snmp_community") or "public"
        secrets = [community, get_setting(settings, "default_snmp_community")]
        problem = snmpfix.community_problem(community)
        target = community
    if problem:
        raise ActionError(400, f"Fix SNMP on {name}: {problem}", device["id"])
    if mode == "script" and not (cred and keys):
        # Commands to paste by hand work without SSH from here: built from an empty file
        # (sysLocation and sysContact then take their defaults).
        database.add_audit("snmp", f"Fix SNMP commands copied for {name}", f"Monitor address {monitor_ip}")
        return {"script": snmpfix.copy_script(snmpfix.build_conf("", community, monitor_ip, v3=v3)["content"], monitor_ip)}
    if not cred:
        raise ActionError(400, f"Fix SNMP on {name}: choose a stored credential (root, or a user allowed to run sudo without a password)", device["id"])
    if not keys:
        raise ActionError(409, f"Fix SNMP on {name}: approve this host's SSH key first", device["id"])

    read = ssh_runner.run_command(device["ip_address"], port, cred, snmpfix.READ_SCRIPT, keys, 30)
    if read["status"] != "completed" or read["exit_code"] != 0:
        raw = snmpfix.mask(read["stderr"] or read["status"], secrets).strip()
        plain = snmpfix.login_problem(raw)
        raise ActionError(502, f"Fix SNMP on {name}: could not log in over SSH as {cred.get('username') or 'root'}: "
                               + (f"{plain} ({raw[:200]})" if plain else raw[:300]), device["id"])
    state = snmpfix.parse_read(read["stdout"])
    if not state["root"] and not state["sudo"]:
        raise ActionError(409, f"Fix SNMP on {name}: {cred.get('username') or 'this user'} is not root and sudo asks for a password. "
                               "Use a root credential, or allow passwordless sudo for this user, or use Copy as commands.", device["id"])
    if not state["installed"] and not state["apt"]:
        raise ActionError(409, f"Fix SNMP on {name}: snmpd is not installed and this host has no apt-get. Install net-snmp with the system's package manager, then try again.", device["id"])
    current = state["conf"]
    plan = snmpfix.build_conf(current, community, monitor_ip, v3=v3)
    changes = list(plan["changes"])
    if not state["installed"]:
        changes.insert(0, "snmpd is not installed: installs it with apt-get (the host downloads the package)")
    elif state["active"] != "active":
        changes.insert(0, f"snmpd is {state['active'] or 'not running'}: enables and starts it")
    if not current and state["installed"]:
        changes.insert(0, f"{snmpfix.CONF} is missing: writes a new one")
    if state["dropins"]:
        changes.append(f"Files in /etc/snmp/snmpd.conf.d are no longer read: {', '.join(state['dropins'])}")
    if state["ufw"]:
        changes.append(f"ufw is active: allows UDP 161 from {monitor_ip} only")
    # Already clean: the same file apart from its date line, installed and running.
    same = lambda a, b: [l for l in a.splitlines()[1:]] == [l for l in b.splitlines()[1:]]
    unchanged = bool(current) and same(current, plan["content"]) and state["installed"] and state["active"] == "active"
    fingerprint = snmpfix.sha(f"{int(state['installed'])}{state['active']}\n{current}")
    if mode == "preview":
        return {"content": snmpfix.mask(plan["content"], secrets), "changes": changes, "sha": fingerprint,
                "monitor_ip": monitor_ip, "unchanged": unchanged, "user": cred.get("username") or "root",
                "root": state["root"]}
    if mode == "script":
        # The real community, for pasting by hand: this route needs a fresh password confirmation.
        database.add_audit("snmp", f"Fix SNMP commands copied for {name}", f"Monitor address {monitor_ip}")
        return {"script": snmpfix.copy_script(plan["content"], monitor_ip)}

    if _get_str(payload, "expected_sha", max_len=64) != fingerprint:
        raise RequestError(409, "The host changed since the preview. Preview again before applying.")
    database.add_event(device["id"], "info", "action", f"Fix SNMP started on {name}: writing snmpd.conf and restarting snmpd")
    # Installing the package can take a few minutes on a slow mirror.
    applied = ssh_runner.run_command(device["ip_address"], port, cred, snmpfix.apply_script(monitor_ip), keys, 600,
                                     input_data=plan["content"].encode("utf-8"))
    backup = next((l.split("=", 1)[1] for l in applied["stdout"].splitlines() if l.startswith("BACKUP=")), None)
    if applied["status"] != "completed" or applied["exit_code"] != 0 or not backup:
        log = snmpfix.snmpd_log(applied["stdout"])
        detail = ("snmpd did not start with the new file. Its log: " + log) if log else \
            (applied["stderr"] or applied["stdout"] or applied["status"])
        detail = snmpfix.mask(detail, secrets)[:700]
        outcome = "; snmpd.conf left as it was" if not backup else ""
        if backup and backup != "none":
            back = ssh_runner.run_command(device["ip_address"], port, cred, snmpfix.rollback_script(backup), keys, 60)
            ok = back["status"] == "completed" and back["exit_code"] == 0
            outcome = f"; the previous file was restored ({backup})" if ok else f"; restoring {backup} also failed, restore it by hand"
            database.add_audit("snmp", f"Fix SNMP on {device['hostname']} rolled back", backup)
        raise ActionError(502, f"Fix SNMP on {name} failed{outcome}: {detail}", device["id"])
    if not snmpfix.verify(device, target):
        if backup == "none":
            database.add_event(device["id"], "warning", "action", "Fix SNMP: snmpd installed and configured but interfaces do not answer yet")
            return {"success": False, "rolled_back": False, "backup": backup,
                    "message": "snmpd was installed and configured but did not answer from here. Check a firewall on the host (UDP 161)."}
        ssh_runner.run_command(device["ip_address"], port, cred, snmpfix.rollback_script(backup), keys, 60)
        database.add_event(device["id"], "warning", "action", f"Fix SNMP: interfaces still not visible, restored {backup}")
        database.add_audit("snmp", f"Fix SNMP on {device['hostname']} rolled back", backup)
        return {"success": False, "rolled_back": True, "backup": backup,
                "message": "snmpd restarted but the interface table still did not answer, so the backup was restored."}
    database.add_event(device["id"], "info", "action", f"Fix SNMP done on {name}: clean snmpd.conf written (backup {backup})")
    database.add_audit("snmp", f"Fix SNMP applied on {device['hostname']}", f"Backup {backup}")
    # Poll and re-evaluate at once so the restricted-view warning clears in seconds, not at the next poll.
    scheduler.refresh_device(device["id"])
    return {"success": True, "backup": backup, "message": "snmpd now answers with interfaces, CPU, memory and storage."}


NOTIFIER = notify.Notifier(database.get_all_settings)
BOT = telebot.Bot(database.get_all_settings)
workflows.on_finished = lambda wf, status, failed: NOTIFIER.event(
    "workflow", {"workflow": wf["name"], "status": status, "failed_step": f" at step: {failed}" if failed else ""},
    critical=False)
workflows.weak_dbm = lambda: alert_policy().resolve("wifi_weak", upto="global")[0]["threshold"] or -75
workflows.on_started = lambda wf, trigger: NOTIFIER.event("workflow_start", {"workflow": wf["name"], "trigger": trigger})
workflows.send_telegram = NOTIFIER.message
tls.on_failure = lambda reason: security_alert("https_failed", reason=reason)
botcmds.wifi_view = lambda: wifi_view()
botcmds.device_group = lambda d: device_group(d)

# The built-in commands in the builder: which reply texts each one uses.
BOT_BUILTIN_TEMPLATES = {"status": ["status"], "problems": ["problems", "problem_item"], "device": ["device", "problem_item"],
                         "changes": ["changes"]}


def bot_commands_view() -> Dict[str, Any]:
    settings = database.get_all_settings()
    data = botcmds.load()
    builtin = [{"name": name, "description": telebot.BUILTIN_INFO[name], "on": name not in data["off"],
                "templates": [{"key": k, "label": telebot.TEMPLATES[k][0], "help": telebot.TEMPLATES[k][1],
                               "text": telebot.template(settings, k), "default": telebot.TEMPLATES[k][2],
                               "presets": telebot.TEMPLATES[k][3], "placeholders": telebot.TEMPLATE_PLACEHOLDERS[k]} for k in keys]}
               for name, keys in BOT_BUILTIN_TEMPLATES.items()]
    custom = [dict(c, on=c["name"] not in data["off"]) for c in data["custom"]]
    return {"builtin": builtin, "custom": custom, "sources": botcmds.sources_view(), "max": botcmds.MAX_COMMANDS,
            "max_limit": botcmds.MAX_LIMIT, "answering": telebot.enabled(settings), "tricks": tpl.TRICKS}


def bot_preview(payload: Dict[str, Any]) -> str:
    """The reply a command would give now, with the texts being edited (nothing is saved)."""
    arg = _get_str(payload, "arg", "", max_len=60)
    if payload.get("builtin"):
        name = _get_str(payload, "builtin", "", max_len=20)
        if name not in BOT_BUILTIN_TEMPLATES:
            raise RequestError(400, "Unknown command")
        texts = payload.get("texts") if isinstance(payload.get("texts"), dict) else {}
        settings = dict(database.get_all_settings())
        for k, v in texts.items():
            if k in telebot.TEMPLATES and isinstance(v, str):
                settings[f"bot_tpl_{k}"] = v[:500]
        if name == "device" and not arg:
            devices = database.list_devices()
            open_ids = {p["device_id"] for p in database.list_active_problems()}
            pick = next((d for d in devices if d["id"] in open_ids), devices[0] if devices else None)
            arg = pick["hostname"] if pick else ""
        return telebot.COMMANDS[name](arg, settings)
    try:
        cmd = botcmds.clean(payload.get("command") if isinstance(payload.get("command"), dict) else {})
    except botcmds.CommandError as exc:
        raise RequestError(400, str(exc))
    return botcmds.render(cmd, arg)


def save_bot_commands(payload: Dict[str, Any], who: str) -> Dict[str, Any]:
    texts = payload.get("texts") if isinstance(payload.get("texts"), dict) else {}
    for k, v in texts.items():
        if k not in telebot.TEMPLATES or not isinstance(v, str):
            raise RequestError(400, "Unknown reply text")
        if len(v) > 500:
            raise RequestError(400, f"{telebot.TEMPLATES[k][0]} is longer than 500 characters")
    custom = payload.get("custom") if isinstance(payload.get("custom"), list) else []
    off = payload.get("off") if isinstance(payload.get("off"), list) else []
    try:
        data = botcmds.save(custom, off)
    except botcmds.CommandError as exc:
        raise RequestError(400, str(exc))
    for k, v in texts.items():
        database.update_setting(f"bot_tpl_{k}", v.strip() or telebot.TEMPLATES[k][2])
    database.add_audit("notify", "Telegram commands saved",
                       f"By {who}: {len(data['custom'])} of your own" + (f", off: {', '.join(data['off'])}" if data["off"] else ""))
    return bot_commands_view()


def device_values(device: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not device:
        return {}
    # device_id is not a placeholder: it tags the outbox row so the sent message shows on the device's events.
    return {"device": device["hostname"], "ip": device["ip_address"], "template": device["profile_id"],
            "device_id": device.get("id")}


def with_group(device: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The device with its effective group, for maintenance windows that cover a group."""
    return dict(device, group=device_group(device)) if device else None


def maintenance_window(device: Optional[Dict[str, Any]], current: Optional[list] = None) -> Optional[Dict[str, Any]]:
    return maintenance.active_for(with_group(device), current=current)


# (device_id, problem key) whose opening message was held back (maintenance or root cause), so the
# matching "resolved" message is held back too.
HELD_BACK: set = set()


# Warnings that come just before "offline" when a device shuts down: its SNMP agent (or the checked
# service) stops a moment before it stops answering ping. Their message waits one ping interval (plus
# SETTLE_EXTRA_SECONDS); if the device is offline by then, the offline message says it all and this
# one (and its later "resolved") is not sent. {(device_id, key): {"at": opened, "p": problem}}
SETTLE_KEYS = ("snmp", "service_down")
SETTLE_EXTRA_SECONDS = 30
PENDING_SETTLE: Dict[tuple, Dict[str, Any]] = {}


def settle_seconds(device: Dict[str, Any], settings: Dict[str, str]) -> int:
    ping = device.get("ping_interval") or get_setting(settings, "default_ping_interval")
    return int(max(30, min(600, ping + SETTLE_EXTRA_SECONDS)))


def release_settled(now: float, devices: Dict[int, Dict[str, Any]], settings: Dict[str, str], min_sev: str) -> None:
    """Sends the held warnings whose device still answers ping after the wait; drops the ones whose
    device went offline (or sits behind one that did) in the meantime."""
    if not PENDING_SETTLE:
        return
    down = {p["device_id"] for p in database.list_active_problems() if p["problem_key"] == "unreachable"}
    for (dev_id, key), item in list(PENDING_SETTLE.items()):
        device = devices.get(dev_id)
        if device is None:
            PENDING_SETTLE.pop((dev_id, key), None)
            continue
        if dev_id in down or dev_id in BEHIND:
            PENDING_SETTLE.pop((dev_id, key), None)
            HELD_BACK.add((dev_id, key))           # its "resolved" stays quiet too
            database.add_event(dev_id, "info", "problem",
                               f"Not sent to Telegram: {item['p']['message']} (the device went offline; that message covers it)")
            continue
        if now - item["at"] < settle_seconds(device, settings):
            continue
        PENDING_SETTLE.pop((dev_id, key), None)
        p = item["p"]
        if alerts.should_send(p, p["severity"], min_sev) and not in_new_device_quiet(device, settings):
            notify_problem(device, key, p["severity"], p["message"], opened=True, sound=p.get("sound", "default"))
        else:
            HELD_BACK.add((dev_id, key))


def in_new_device_quiet(device: Optional[Dict[str, Any]], settings: Dict[str, str], now: Optional[float] = None) -> bool:
    """True while a newly added device's first problems are kept off Telegram (notify_new_devices off)."""
    if not device or settings.get("notify_new_devices", "off") == "on":
        return False
    minutes = get_setting(settings, "notify_new_device_minutes")
    return ((now or time.time()) - (device.get("created_at") or 0)) < minutes * 60


def notify_problem(device: Optional[Dict[str, Any]], key: str, severity: str, message: str,
                   opened: bool, lasted: str = "", sound: str = "default") -> None:
    """Maps a problem change to its notification event: reachability, watched names or other problems.
    sound is the rule's choice for the phone (alerts.SOUND); the sender applies the silent window."""
    values = dict(device_values(device), severity=severity, problem=message, duration=lasted,
                  topic="proxmox" if key.startswith("pve_") else "",
                  behind=message.split(BEHIND_NOTE, 1)[1].strip() if key == "unreachable" and BEHIND_NOTE in message else "")
    if key.startswith("workflow:"):
        return      # the run itself sends the "workflow" message when it finishes
    if key == "unreachable":
        NOTIFIER.event("device_offline" if opened else "device_online", values, critical=opened, sound=sound)
    elif key.startswith("watch:") and opened:
        _, kind, name = key.split(":", 2)
        NOTIFIER.event("watch", dict(values, watch_kind=kind, watch_name=name), critical=severity == "critical", sound=sound)
    elif opened:
        NOTIFIER.event("problem", values, critical=severity == "critical", sound=sound)
    else:
        NOTIFIER.event("problem_resolved", values, sound=sound)


def parse_device_list(entries: Any) -> List[Dict[str, Any]]:
    """Validates a list of devices to add (from the scan): each like an Add Target request."""
    if not isinstance(entries, list) or len(entries) > 500:
        raise RequestError(400, "devices must be a list of up to 500 entries")
    out, seen = [], set()
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            raise RequestError(400, f"Device {i} is not an object")
        try:
            fields = parse_device_payload({"ip_address": e.get("ip_address"), "hostname": e.get("hostname") or "",
                                           "profile_id": e.get("profile_id") or "generic_device",
                                           "service_port": e.get("service_port")})
        except RequestError as exc:
            raise RequestError(400, f"Device {i}: {exc.message}")
        key = (fields["ip_address"], fields["service_port"])
        if key not in seen:
            seen.add(key)
            out.append(fields)
    return out


def add_devices(fields_list: List[Dict[str, Any]], community: Optional[str], dry_run: bool) -> Dict[str, list]:
    """Adds devices, skipping addresses already monitored. dry_run reports without writing."""
    existing = {(d["ip_address"], d.get("service_port") or 0) for d in database.list_devices()}
    added, skipped = [], []
    for f in fields_list:
        if (f["ip_address"], f.get("service_port") or 0) in existing:
            skipped.append({"ip_address": f["ip_address"], "service_port": f.get("service_port") or 0, "reason": "already monitored"})
            continue
        if not dry_run:
            f = dict(f, snmp_community=community or database.get_all_settings().get("default_snmp_community") or "public")
            f.pop("_extra", None)
            f.pop("_snmp", None)          # the setup guide and scans add v2c devices
            f.pop("_tags", None)
            service = f.pop("_service", None)
            device_id = database.add_device(**f)
            if service:
                database.set_service_check(device_id, **service)
            database.add_event(device_id, "info", "config", f"Device added to monitoring ({f['ip_address']}, profile {f['profile_id']})")
            scheduler.poll_now(device_id)
        added.append({"ip_address": f["ip_address"], "hostname": f["hostname"], "profile_id": f["profile_id"],
                      "service_port": f.get("service_port") or 0})
    return {"added": added, "skipped": skipped}


SETUP_SETTING_KEYS = ("default_snmp_community", "default_poll_interval", "default_ping_interval",
                      "raw_retention_days", "metric_retention_days")


def parse_setup(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validates the whole wizard payload; the same checks run for preview and the real run."""
    raw_settings = payload.get("settings") or {}
    if not isinstance(raw_settings, dict) or set(raw_settings) - set(SETUP_SETTING_KEYS):
        raise RequestError(400, "Unexpected setting in setup")
    settings_updates = parse_settings_payload({k: v for k, v in raw_settings.items() if v not in (None, "")})
    try:
        site, secrets = setup.parse_site(payload.get("site"), {c["id"] for c in database.list_credentials()})
    except setup.SetupError as exc:
        raise RequestError(400, str(exc))
    devices = parse_device_list(payload.get("devices") or [])
    return {"settings": settings_updates, "site": site, "secrets": secrets, "devices": devices}


def neighbours_view(device_id: int) -> list:
    """Hosts seen by a device, with MAC, IP, VLAN, port and where else they appear.

    Joins every switch FDB with every router ARP table so a switch port shows
    the IP of the host behind it and a gateway ARP entry shows the switch port
    the host is plugged into. MACs matching a monitored device are named.
    """
    devices = {d["id"]: d for d in database.list_devices()}
    by_ip = {d["ip_address"]: d for d in devices.values() if not d.get("service_port")}
    arp = database.get_table_all_devices("arp")
    fdb = database.get_table_all_devices("fdb")
    mac_to_ip = {r["mac"]: r["row_key"] for r in arp}
    iface_cache: Dict[int, Dict[str, Dict[str, Any]]] = {}

    def port_label(dev_id: int, if_index: Any) -> str:
        if dev_id not in iface_cache:
            iface_cache[dev_id] = database.get_device_table(dev_id, "interfaces")
        r = iface_cache[dev_id].get(str(if_index), {})
        label = r.get("label", str(if_index))
        return f"{label} ({r['alias']})" if r.get("alias") and r.get("alias") != label else label

    def seen_on(mac: str, skip_device: int) -> str:
        spots = [f"{devices[r['device_id']]['hostname']} {port_label(r['device_id'], r['if_index'])}"
                 for r in fdb if r["row_key"] == mac and r["device_id"] != skip_device and r["device_id"] in devices]
        return ", ".join(spots)

    rows = []
    for r in fdb:
        if r["device_id"] != device_id:
            continue
        ip = mac_to_ip.get(r["row_key"])
        rows.append({
            "mac": r["row_key"], "ip": ip, "vlan": r.get("vlan"),
            "if_index": r["if_index"], "port": port_label(device_id, r["if_index"]),
            "device": by_ip[ip]["hostname"] if ip in by_ip else None,
            "seen_on": seen_on(r["row_key"], device_id), "source": "fdb",
        })
    for r in arp:
        if r["device_id"] != device_id:
            continue
        ip = r["row_key"]
        rows.append({
            "mac": r["mac"], "ip": ip, "vlan": None,
            "if_index": r["if_index"], "port": port_label(device_id, r["if_index"]),
            "device": by_ip[ip]["hostname"] if ip in by_ip else None,
            "seen_on": seen_on(r["mac"], device_id), "source": "arp",
        })
    return rows


# --- Authentication ---

# Routes reachable without a session: the login screen (with its 2FA step and password recovery) needs them.
PUBLIC_API = {("GET", "/api/auth/status"), ("POST", "/api/auth/login"), ("POST", "/api/auth/setup"),
              ("POST", "/api/auth/login/mfa"), ("POST", "/api/auth/recover/start"), ("POST", "/api/auth/recover/finish")}
# Step-up tiers per route: rbac.TIER_ROUTES. The setup wizard's apply is stricter: the password
# (and code) travel in the request itself, every time.
_USERNAME = re.compile(r"[A-Za-z0-9._-]{1,32}")
# Checked when the username is unknown, so a wrong name costs the same time as a wrong password.
_DUMMY_HASH = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = auth.hash_password(auth.secrets.token_urlsafe(16))
    return _DUMMY_HASH


def needs_confirmation(method: str, path: str) -> bool:
    """Whether the route needs any step-up (tier 2 or 3)."""
    return rbac.route_tier(method, path) > 1


def second_factor_ok(username: str, code: str) -> bool:
    """An authenticator code (not reused) or an unused recovery code; a recovery code is spent."""
    t = database.get_totp(username)
    if not t["enabled"] or not t["secret"]:
        return False
    step = totp.verify(t["secret"], code, last_step=t["last_step"])
    if step is not None:
        # Atomic: of two parallel requests with the same code, only one consumes the step.
        return database.consume_totp_step(username, step)
    i = totp.match_recovery(code, t["recovery"])
    if i is not None:
        left = database.consume_recovery_code(username, t["recovery"][i])
        if left is None:
            return False
        database.add_audit("auth", f"Recovery code used by {username}", f"{left} left", actor=username)
        security_alert("recovery_code", who=username, name=username, left=left)
        return True
    return False


SENSITIVE_AUDIT_CATEGORIES = {"ssh", "credential", "auth", "users", "snmp"}


def telegram_ready() -> bool:
    s = database.get_all_settings()
    return s.get("telegram_enabled") == "on" and bool(s.get("telegram_token")) and bool(s.get("telegram_chat_id"))


# --- HTTP Handler ---

class _TimedRaw(io.RawIOBase):
    """Socket reads with a limit per read and one for the whole request."""

    def __init__(self, sock, idle: float, total: float, after: Optional[float]) -> None:
        super().__init__()
        self.sock = sock
        self.idle = idle
        self.after = after
        self.deadline = time.monotonic() + total

    def readable(self) -> bool:
        return True

    def limit(self, seconds: float) -> None:
        """Shortens the time left, for example for a body read only so it can be dropped."""
        self.deadline = min(self.deadline, time.monotonic() + seconds)

    def readinto(self, b) -> int:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request took too long")
        self.sock.settimeout(min(self.idle, left))
        try:
            return self.sock.recv_into(b)
        finally:
            # Writes (the reply) use their own timeout.
            self.sock.settimeout(self.after)


class _TimedRequest:
    """Gives a request handler read limits (idle and total) and a write timeout."""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(WRITE_SECONDS)
        # The stdlib reader holds a reference that would keep the socket open: close it first.
        self.rfile.close()
        self.rfile = io.BufferedReader(_TimedRaw(self.connection, READ_IDLE_SECONDS, READ_TOTAL_SECONDS, WRITE_SECONDS))


class ApiRequestHandler(_TimedRequest, http.server.BaseHTTPRequestHandler):
    """Handles HTTP requests for static assets and REST API endpoints."""

    server_version = "HomelabMonitor"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppresses default stderr access logging."""
        return

    def _security_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if self._scheme() == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _send_json(self, status_code: int, data: Any) -> None:
        """Sends a JSON response with strict local security headers."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        for cookie in getattr(self, "_cookies_out", []):
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, file_name: str, content_type: str) -> None:
        """Serves a fixed file from the web directory."""
        try:
            with open(os.path.join(WEB_DIR, file_name), "rb") as f:
                content = f.read()
        except OSError:
            self._send_json(404, {"error": "File not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(content)

    def _check_host(self) -> None:
        if not host_allowed(self.headers.get("Host", "")):
            raise RequestError(421, "Misdirected request")

    def _scheme(self) -> str:
        return "https" if isinstance(self.connection, ssl.SSLSocket) else "http"

    def _https_lost(self) -> bool:
        """HTTPS failed and this is plain HTTP from another computer (this machine may still log in)."""
        return bool(tls.SERVER.failure) and self._scheme() == "http" and not self.server.local_client(self.client_address)

    def _check_mutation(self) -> None:
        origin = self.headers.get("Origin")
        # Same-origin only: the page must have been loaded from the host this request is addressed to.
        if origin is not None and origin.lower() != f"{self._scheme()}://{self.headers.get('Host', '').lower()}":
            raise RequestError(403, "Cross-origin request rejected")
        if self.command in ("POST", "PUT"):
            ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if ctype != "application/json":
                raise RequestError(415, "Content-Type must be application/json")

    def _discard_body(self) -> None:
        """Reads an unread request body before an early error reply.

        Replying and closing with request bytes still unread makes the OS reset
        the connection (notably on Windows), so the client sees a network error
        instead of the JSON error message.
        """
        if getattr(self, "_body_read", False) or self.command not in ("POST", "PUT"):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if 0 < length <= MAX_BODY_BYTES:
            raw = getattr(self.rfile, "raw", None)
            if isinstance(raw, _TimedRaw):
                raw.limit(2.0)
            try:
                self.rfile.read(length)
            except OSError:
                pass
        self._body_read = True
        self.close_connection = True

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise RequestError(400, "Invalid Content-Length")
        if length < 0 or length > MAX_BODY_BYTES:
            raise RequestError(413, "Request body too large")
        try:
            raw = self.rfile.read(length) if length else b""
        except TimeoutError:
            self._body_read = True
            self.close_connection = True
            raise RequestError(408, SLOW_REQUEST_TEXT)
        self._body_read = True
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestError(400, "Invalid JSON payload")
        if not isinstance(payload, dict):
            raise RequestError(400, "JSON payload must be an object")
        return payload

    def _session_token(self) -> Optional[str]:
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = jar.get(auth.SESSION_COOKIE)
        return morsel.value if morsel else None

    def _set_session_cookie(self, token: Optional[str]) -> None:
        # SameSite=Strict keeps the cookie off cross-site requests; HttpOnly keeps it away from page
        # scripts. Secure over HTTPS, so the browser never sends it over plain HTTP again.
        attrs = "Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if self._scheme() == "https" else "")
        if token:
            self._cookies_out = [f"{auth.SESSION_COOKIE}={token}; {attrs}; Max-Age={auth.SESSION_MAX_SECONDS}"]
        else:
            self._cookies_out = [f"{auth.SESSION_COOKIE}=; {attrs}; Max-Age=0"]

    def _require_session(self, path: str) -> None:
        """Gate for every API route: login, then password confirmation where needed."""
        self.token = self._session_token()
        self.session = auth.SESSIONS.get(self.token)
        self.user = None
        self.account = None
        if (self.command, path) in PUBLIC_API:
            if self.session is not None:
                try:
                    self._load_user()
                except AuthRequired:
                    pass
            return
        if self.session is None:
            if database.get_account() is None:
                raise AuthRequired(401, "Create the administrator account first", "setup")
            raise AuthRequired(401, "Log in to continue", "login")
        self._load_user()
        # Required 2FA, decided from the account on every request: also a session opened before
        # the rule was switched on. Only the setup, its password step and Log out stay open.
        if must_enrol(self.account) and (self.command, path) not in ENROL_ROUTES:
            raise AuthRequired(403, ENROL_TEXT, "enrol")
        # Required after an update: locks the app for those who can finish the step (see REQUIRED_STEPS).
        if not path.startswith("/api/auth/") and (self.command, path) not in REQUIRED_ROUTES:
            mine = required_steps(self.user)["mine"]
            if mine:
                raise AuthRequired(403, REQUIRED_TEXT, "required", {"steps": mine})
        if not path.startswith("/api/auth/") and not rbac.allowed(self.user, self.command, path):
            raise RequestError(403, "Your account does not have permission to do that")
        # Every per-device route, any method: outside the user's device access it does not exist.
        dev = re.match(r"/api/devices/(\d+)(?:/|$)", path)
        if dev and not self.user.sees_id(int(dev.group(1))):
            raise RequestError(404, "Device not found")
        # Network-wide changes and objects everyone shares (rbac.UNSCOPED_ROUTES).
        if self.user.scope is not None and rbac.needs_all_devices(self.command, path):
            raise RequestError(403, "This needs access to every device.")
        tier = rbac.route_tier(self.command, path)
        if tier > 1:
            self._require_tier(tier, path)

    def _require_tier(self, tier: int, path: str = "") -> None:
        """Step-up check: a recent password (tier 2) or password and code (tier 3) on this session.
        A tier 3 user without 2FA confirms with the password alone; the reply says so, to suggest 2FA.
        While 2FA is required, tier 3 needs it for everyone (starting the setup is the way in)."""
        if tier >= 3 and path != "/api/auth/2fa/start" and two_factor_rule() != "off" \
                and not (self.account or {}).get("totp_enabled"):
            raise RequestError(403, TIER3_NEEDS_2FA_TEXT)
        until = self.session.get("tier3_until" if tier >= 3 else "tier2_until", 0)
        if until >= time.time():
            return
        has_2fa = database.get_totp(self.session["username"])["enabled"]
        need_code = tier >= 3 and has_2fa
        raise AuthRequired(403, "Confirm with your password and authenticator code" if need_code else "Confirm your password to continue",
                           "confirm", {"tier": tier, "mfa": need_code, "suggest_2fa": tier >= 3 and not has_2fa})

    def _load_user(self) -> None:
        """Reads the account on every request, so a block, role change or deletion applies at once."""
        account = database.get_user(self.session["username"])
        if account is None or account.get("disabled"):
            auth.SESSIONS.revoke_user(self.session["username"])
            self.session = None
            raise AuthRequired(401, "This account is blocked" if account else "Log in to continue", "login")
        self.account = account
        self.user = rbac.User(account)
        database.set_audit_context(self.user.username, self.client_address[0])
        if self.user.scope is not None:
            self.user.bind_devices(database.device_profiles())

    def _require_device(self, device_id: int) -> Dict[str, Any]:
        """The device, or 404 when it does not exist or is outside the user's device access."""
        device = database.get_device(device_id)
        if not device or (self.user is not None and not self.user.sees(device)):
            raise RequestError(404, "Device not found")
        return device

    def _vault_status(self, **extra: Any) -> Dict[str, Any]:
        """Vault state; where the key lives and any vault error only for System settings."""
        out = dict(VAULT.status(), **extra)
        if not self.user.can("settings.system"):
            out.pop("key_path", None)
            out.pop("error", None)
        return out

    def _require_perm(self, perm: str) -> None:
        if self.user is None or not self.user.can(perm):
            raise RequestError(403, "Your account does not have permission to do that")

    def _dispatch(self, handler) -> None:
        # Every audit row this request writes names the address; the user once the session is read.
        database.set_audit_context("anonymous", self.client_address[0])
        try:
            self._check_host()
            if self.command != "GET":
                self._check_mutation()
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            # HTTPS should be on but failed: nothing that carries a password or a session crosses the
            # network in the clear. The login page asks the status, which says only that it is lost.
            if path.startswith("/api/") and self._https_lost() and (self.command, path) != ("GET", "/api/auth/status"):
                raise RequestError(403, tls.REFUSED_TEXT)
            if path.startswith("/api/"):
                self._require_session(path)
                if path.startswith("/api/auth/"):
                    self._auth_route(path)
                    return
                if path == "/api/users" or path.startswith("/api/users/"):
                    self._users_route(path)
                    return
                if path == "/api/notifications/read" and self.command == "POST":
                    upto = _get_int(self._read_json(), "upto", int(time.time()), 0, int(time.time()) + 60)
                    database.update_user(self.user.username, {"notify_read_at": upto})
                    self._send_json(200, {"success": True, "read_at": upto})
                    return
                if path == "/api/backups/site" and self.command == "PUT":
                    # Syncthing on or off for backups. Saved with the other site settings (so backups
                    # carry it), then root applies it (identity from the NAS, folder, service).
                    site = setup.get_site()
                    site["syncthing"] = parse_syncthing_site(self._read_json())
                    setup.save_site(site)
                    request_root_action("site")
                    st = site["syncthing"]
                    database.add_audit("backup", "Backups go to Syncthing" if st["enabled"] else "Backups kept locally (Syncthing off)",
                                       (f"{st['data_folder']} (identity {st['keys_source']}); " if st["enabled"] else "") + f"by {self.user.username}")
                    self._send_json(200, backup_status())
                    return
                if path == "/api/demo/remove" and self.command == "POST":
                    # Administrators only (an unlisted route), with the password (rbac.TIER_ROUTES).
                    self._read_json()
                    if not demo_status()["on"]:
                        raise RequestError(409, "There is no demo data to remove")
                    done = poller.demo.remove(log=log.info)
                    # Nothing left: the setup guide runs again, to find the real network.
                    fresh = not database.list_devices()
                    if fresh:
                        database.set_internal_setting(setup.COMPLETED_KEY, "")
                    database.add_audit("system", "Demo data removed", f"{done['devices']} devices; by {self.user.username}")
                    self._send_json(200, {"removed": done, "demo": demo_status(), "setup": fresh})
                    return
                if path.startswith("/api/updates/") and self.command == "POST":
                    # Administrators only (unlisted routes need the administrator role); installing and
                    # undoing also need the password and code (rbac.TIER_ROUTES). Root does the work.
                    body = self._read_json()
                    status = update_status()
                    if path == "/api/updates/skip":
                        version = str(body.get("version") or "")
                        if not _VERSION_RE.fullmatch(version) or version != (status["check"] or {}).get("latest"):
                            raise RequestError(409, "That is not the version waiting to be installed")
                        database.set_internal_setting(UPDATE_SKIP_KEY, version)
                        database.add_audit("system", f"Skipped update {version}", f"By {self.user.username}")
                        self._send_json(200, update_status())
                        return
                    if path == "/api/updates/unskip":
                        database.set_internal_setting(UPDATE_SKIP_KEY, "")
                        database.add_audit("system", "Skipped update shown again", f"By {self.user.username}")
                        self._send_json(200, update_status())
                        return
                    if not status["installed"]:
                        raise RequestError(409, "Update works on an installed monitor (home_monitor.sh); this copy has no update helper")
                    if status["pending"]["work"]:
                        raise RequestError(409, "An update or rollback is already running")
                    if path == "/api/updates/check":
                        request_root_action("update-check")
                        database.add_audit("system", "Checked for updates", f"By {self.user.username}")
                    elif path == "/api/updates/install":
                        known = status["check"] or {}
                        if not known.get("newer"):
                            raise RequestError(409, "Check for updates first: no newer version is known")
                        request_root_action("update-install")
                        database.add_audit("system", f"Update to {known.get('latest')} started",
                                           f"From {APP_VERSION}; by {self.user.username}")
                    elif path == "/api/updates/rollback":
                        mode = body.get("mode")
                        back = status["rollback"]
                        if mode not in ("code", "all") or not back.get(mode):
                            raise RequestError(409, "That way back is not open now")
                        request_root_action(f"rollback-{mode}")
                        database.add_audit("system", f"Rollback to {back.get('to')} started",
                                           ("Keeping today's data" if mode == "code" else "With the data from before the update")
                                           + f"; by {self.user.username}")
                    else:
                        raise RequestError(404, "Endpoint not found")
                    self._send_json(200, update_status())
                    return
                if path == "/api/backups/passphrase" and self.command == "POST":
                    payload = self._read_json()
                    passphrase = payload.get("passphrase") if isinstance(payload, dict) else None
                    problem = backup_passphrase_problem(passphrase)
                    if problem:
                        raise RequestError(400, problem)
                    had_one = bool(backup_status().get("passphrase_set"))
                    request_backup_passphrase(passphrase)
                    passphrase = None
                    database.add_audit("backup", "Backup passphrase " + ("change" if had_one else "set") + " requested",
                                       f"By {self.user.username}")
                    security_alert("backup_passphrase", how="changed" if had_one else "set")
                    self._send_json(200, backup_status())
                    return
                if path == "/api/backups/run" and self.command == "POST":
                    self._read_json()       # an unread body makes some systems reset the connection
                    request_root_action("backup")
                    database.add_audit("backup", "Backup requested", f"By {self.user.username}")
                    self._send_json(200, backup_status())
                    return
            handler(parsed)
        except AuthRequired as exc:
            self._discard_body()
            self._send_json(exc.status, dict(exc.extra, error=exc.message, auth=exc.mode))
        except RequestError as exc:
            self._discard_body()
            if isinstance(exc, ActionError):
                session = getattr(self, "session", None)
                database.add_event(exc.device_id, "warning", "action", exc.message,
                                   actor=session["username"] if session else None)
            self._send_json(exc.status, {"error": exc.message})
        except sqlite3.IntegrityError as exc:
            what = "credential with that name" if "credentials" in str(exc) else "device with that address (and port)"
            self._send_json(409, {"error": f"A {what} already exists"})
        except auth.Busy:
            self._discard_body()
            self._send_json(503, {"error": "Busy, try again in a moment"})
        except OverflowError:
            # A number in the path or body too large for SQLite (beyond 64 bits).
            self._discard_body()
            self._send_json(400, {"error": "Number out of range"})
        except VaultError as exc:
            log.error("Vault error for %s %s: %s", self.command, self.path, exc)
            self._send_json(503, {"error": f"Credential vault unavailable: {exc}"})
        except Exception:
            log.exception("Unhandled error for %s %s", self.command, self.path)
            self._send_json(500, {"error": "Internal server error"})
        finally:
            database.clear_audit_context()

    def _auth_route(self, path: str) -> None:
        client = self.client_address[0]
        if self.command == "GET" and path == "/api/auth/status":
            account = database.get_account()
            self._send_json(200, {"configured": account is not None, "authenticated": self.user is not None,
                                  "username": self.user.username if self.user else None,
                                  "user": self.user.to_json() if self.user else None,
                                  "min_length": auth.MIN_PASSWORD_LENGTH,
                                  "setup_token_required": account is None and bool(os.environ.get("MONITOR_SETUP_TOKEN")),
                                  # Forgotten password: possible when Telegram works and someone has 2FA.
                                  "recovery": account is not None and telegram_ready() and database.any_totp_user(),
                                  # The shell scripts print the address with the right scheme from this.
                                  "https": tls.SERVER.context is not None,
                                  # Yes or no only: the page is public, so the reason stays in Settings.
                                  "https_lost": self._https_lost(),
                                  "enrol_2fa": must_enrol(self.account)})
            return
        if self.command == "GET" and path == "/api/auth/2fa":
            t = database.get_totp(self.user.username)
            self._send_json(200, {"enabled": t["enabled"], "recovery_left": len(t["recovery"]) if t["enabled"] else 0})
            return
        if self.command != "POST":
            raise RequestError(404, "Endpoint not found")
        payload = self._read_json()

        if path in ("/api/auth/login", "/api/auth/confirm"):
            username = _get_str(payload, "username", max_len=32) if path == "/api/auth/login" else self.session["username"]
            known = _USERNAME.fullmatch(username) is not None
            self._check_lockout(client, username if known else None)
            password = _get_str(payload, "password", max_len=auth.MAX_PASSWORD_LENGTH)
            account = database.get_user(username) if known else None
            ok = auth.verify_password(password, account["password_hash"] if account else _dummy_hash()) and account is not None
            if not ok:
                auth.LIMITER.failed(client, username if known else None)
                database.add_audit("auth", "Failed login" if path == "/api/auth/login" else "Failed password confirmation",
                                   f"From {client}", actor=account["username"] if account else None)
                raise RequestError(401, "Wrong username or password" if path == "/api/auth/login" else "Wrong password")
            if path == "/api/auth/login" and account.get("disabled"):
                database.add_audit("auth", f"Blocked user {account['username']} tried to log in", f"From {client}",
                                   actor=account["username"])
                raise RequestError(403, "This account is blocked. Ask an administrator.")
            has_2fa = database.get_totp(account["username"])["enabled"]
            if path == "/api/auth/login":
                if has_2fa:
                    # Password right: the session waits for the authenticator code (POST /api/auth/login/mfa).
                    # The counters stay until the code is right too, so wrong codes add up across logins.
                    # A new challenge voids the user's earlier one.
                    challenge = auth.LOGIN_CHALLENGES.issue(account["username"], auth.CHALLENGE_SECONDS)
                    self._send_json(200, {"mfa_required": True, "challenge": challenge})
                    return
                auth.LIMITER.succeeded(client, account["username"])
                self._start_session(account["username"], client, tier3=True)
                self._send_json(200, {"success": True, "username": account["username"], "enrol_2fa": must_enrol(account)})
                return
            tier = _get_int(payload, "tier", 2, 2, 3)
            if tier >= 3 and has_2fa:
                if not second_factor_ok(account["username"], _get_str(payload, "code", max_len=16)):
                    auth.LIMITER.failed(client, account["username"])
                    database.add_audit("auth", "Failed authenticator code at confirmation", f"{account['username']} from {client}")
                    raise RequestError(401, "Wrong or already used authenticator code")
            auth.LIMITER.succeeded(client, account["username"])
            auth.SESSIONS.confirm(self.token, tier)
            self._send_json(200, {"success": True, "username": account["username"], "tier": tier})
            return

        if path == "/api/auth/login/mfa":
            self._check_lockout(client)
            challenge = _get_str(payload, "challenge", max_len=64)
            username = auth.LOGIN_CHALLENGES.peek(challenge)
            if not username:
                raise RequestError(401, "The login step expired. Enter your password again.")
            code = _get_str(payload, "code", max_len=16)
            # Pay first: the failure is counted before the code is checked, under the limiter's lock.
            self._reserve_attempt(client, username)
            if not second_factor_ok(username, code):
                auth.LOGIN_CHALLENGES.fail(challenge)
                database.add_audit("auth", "Failed authenticator code at login", f"{username} from {client}", actor=username)
                raise RequestError(401, "Wrong or already used authenticator code")
            auth.LOGIN_CHALLENGES.drop(challenge)
            auth.LIMITER.succeeded(client, username)
            self._start_session(username, client, tier3=True)
            self._send_json(200, {"success": True, "username": username})
            return

        if path.startswith("/api/auth/2fa/"):
            self._twofa_route(path, payload, client)
            return

        if path in ("/api/auth/recover/start", "/api/auth/recover/finish"):
            self._recover_route(path, payload, client)
            return

        if path == "/api/auth/setup":
            # Whoever creates the account owns the install. From another machine (the LXC on the LAN)
            # that needs the one-time token the deploy script prints; without one, only localhost may.
            token = os.environ.get("MONITOR_SETUP_TOKEN", "")
            if token:
                # Bytes: compare_digest refuses non-ASCII text with a TypeError (a 500, not a 403).
                if not auth.hmac.compare_digest(_get_str(payload, "setup_token", max_len=128).encode("utf-8"),
                                                token.encode("utf-8")):
                    raise RequestError(403, "Setup token missing or wrong")
            elif not ipaddress.ip_address(client).is_loopback:
                raise RequestError(403, "The administrator account can only be created from this machine")
            username = _get_str(payload, "username", max_len=32)
            password = _get_str(payload, "password", max_len=auth.MAX_PASSWORD_LENGTH)
            if not _USERNAME.fullmatch(username):
                raise RequestError(400, "Username: 1 to 32 letters, digits, dot, dash or underscore")
            problem = auth.password_problem(password)
            if problem:
                raise RequestError(400, problem)
            if not database.create_account(username, auth.hash_password(password)):
                raise RequestError(409, "An administrator account already exists")
            changelog.mark_seen(username)
            self._set_session_cookie(auth.SESSIONS.create(username))
            database.add_audit("auth", f"Created administrator account {username}", f"From {client}", actor=username)
            self._send_json(201, {"success": True, "username": username})
            return

        if path == "/api/auth/logout":
            auth.SESSIONS.revoke(self.token)
            self._set_session_cookie(None)
            self._send_json(200, {"success": True})
            return

        if path == "/api/auth/password":
            account = database.get_account(self.session["username"])
            self._check_lockout(client, account["username"])
            current = _get_str(payload, "current", max_len=auth.MAX_PASSWORD_LENGTH)
            if not auth.verify_password(current, account["password_hash"]):
                auth.LIMITER.failed(client, account["username"])
                raise RequestError(401, "Current password is wrong")
            auth.LIMITER.succeeded(client, account["username"])
            new = _get_str(payload, "new", max_len=auth.MAX_PASSWORD_LENGTH)
            problem = auth.password_problem(new)
            if problem:
                raise RequestError(400, problem)
            database.set_account_password(account["username"], auth.hash_password(new))
            auth.SESSIONS.revoke_user(account["username"], except_token=self.token)
            database.add_audit("auth", f"Changed password for {account['username']}", "Their other sessions logged out")
            self._send_json(200, {"success": True})
            return
        raise RequestError(404, "Endpoint not found")

    @staticmethod
    def _check_lockout(client: str, username: Optional[str] = None) -> None:
        """429 while this address (or this username) is locked out after failed passwords or codes."""
        wait = auth.LIMITER.locked_for(client, username)
        if wait > 0:
            raise _lockout_error(wait)

    @staticmethod
    def _reserve_attempt(client: str, username: Optional[str] = None) -> None:
        """Counts one failed attempt now, or 429 while locked out (auth.LoginLimiter.reserve)."""
        wait = auth.LIMITER.reserve(client, username)
        if wait > 0:
            raise _lockout_error(wait)

    def _start_session(self, username: str, client: str, tier3: bool) -> None:
        database.update_user(username, {"last_login": int(time.time())})
        auth.SESSIONS.revoke(self.token)
        self._set_session_cookie(auth.SESSIONS.create(username, tier3=tier3))
        database.add_audit("auth", f"Logged in as {username}", f"From {client}", actor=username)

    def _twofa_route(self, path: str, payload: Dict[str, Any], client: str) -> None:
        """Own 2FA: start (tier 3), enable with a first code, new recovery codes (tier 3), disable (tier 3)."""
        name = self.user.username
        if path == "/api/auth/2fa/start":
            secret = totp.new_secret()
            auth.SESSIONS.put(self.token, "totp_pending", secret)
            uri = totp.otpauth_uri(secret, name)
            # The secret goes to this browser once, for the authenticator app; it is never sent again.
            self._send_json(200, {"secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                                  "uri": uri, "svg": totp.qr_svg(uri)})
            return
        if path == "/api/auth/2fa/enable":
            self._check_lockout(client, name)
            secret = auth.SESSIONS.take(self.token, "totp_pending")
            if not secret:
                raise RequestError(409, "Start the 2FA setup first")
            step = totp.verify(secret, _get_str(payload, "code", max_len=16))
            if step is None:
                auth.LIMITER.failed(client, name)
                raise RequestError(400, "That code does not match. Check the time on your phone and try the newest code.")
            auth.LIMITER.succeeded(client, name)
            codes = totp.new_recovery_codes()
            database.set_totp(name, secret, True, [totp.hash_recovery(c) for c in codes], last_step=step)
            auth.SESSIONS.put(self.token, "totp_pending", None)
            auth.SESSIONS.confirm(self.token, 3)
            # A session someone else may hold must now log in again, with the code.
            n = auth.SESSIONS.revoke_user(name, except_token=self.token)
            database.add_audit("auth", f"Two-factor authentication turned on for {name}",
                               f"From {client}; {n} other session(s) logged out")
            self._send_json(200, {"success": True, "recovery_codes": codes})
            return
        if path == "/api/auth/2fa/recovery":
            t = database.get_totp(name)
            if not t["enabled"]:
                raise RequestError(409, "Two-factor authentication is off")
            codes = totp.new_recovery_codes()
            database.set_totp_progress(name, recovery=[totp.hash_recovery(c) for c in codes])
            database.add_audit("auth", f"New recovery codes for {name}", "The old ones no longer work")
            self._send_json(200, {"success": True, "recovery_codes": codes})
            return
        if path == "/api/auth/2fa/disable":
            if two_factor_covers(self.account):
                raise RequestError(409, "This monitor requires two-factor authentication for your account, so it cannot be "
                                        "turned off here. An administrator can change that in Settings, Login security.")
            database.set_totp(name, None, False)
            n = auth.SESSIONS.revoke_user(name, except_token=self.token)
            database.add_audit("auth", f"Two-factor authentication turned off for {name}",
                               f"From {client}; {n} other session(s) logged out")
            security_alert("twofa_off", name=name)
            self._send_json(200, {"success": True})
            return
        raise RequestError(404, "Endpoint not found")

    def _recover_route(self, path: str, payload: Dict[str, Any], client: str) -> None:
        """Forgotten password: username and authenticator code, then a one-time code sent by Telegram.
        Without both nothing changes. Answers do not reveal whether a username exists."""
        self._check_lockout(client)
        if not telegram_ready():
            raise RequestError(409, "Password recovery needs Telegram notifications set up. Use /root/reset-admin.sh on the container instead.")
        username = _get_str(payload, "username", max_len=32)
        generic = "Username or authenticator code not accepted"
        known = _USERNAME.fullmatch(username) is not None
        if path == "/api/auth/recover/start":
            code = _get_str(payload, "code", max_len=16)
            # The same guess as a login code with less needed to try it: paid for first, under one lock.
            self._reserve_attempt(client, username if known else None)
            account = database.get_user(username) if known else None
            if not account or account.get("disabled") or not database.get_totp(username)["enabled"] \
                    or not second_factor_ok(username, code):
                database.add_audit("auth", "Failed password recovery start", f"User {username or '?'} from {client}",
                                   actor=account["username"] if account else None)
                raise RequestError(401, generic)
            # Recovery start never cleared the counters: only the charge for this right answer goes.
            auth.LIMITER.refund(client, username)
            code ="".join(auth.secrets.choice("0123456789") for _ in range(8))
            ticket = auth.RECOVERY_CHALLENGES.issue(username, auth.RECOVERY_CODE_SECONDS, secret=code)
            s = database.get_all_settings()
            try:
                notify.send(s["telegram_token"], s["telegram_chat_id"],
                            f"Password reset code for {username}: {code}\nValid for 10 minutes. If you did not ask for this, ignore it.")
            except notify.TelegramError as exc:
                auth.RECOVERY_CHALLENGES.drop(ticket)
                raise RequestError(502, f"Could not send the code through Telegram: {exc}")
            database.add_audit("auth", f"Password recovery code sent for {username}", f"From {client}", actor=username)
            self._send_json(200, {"success": True, "ticket": ticket})
            return
        self._check_lockout(client, username if known else None)
        new = _get_str(payload, "new", max_len=auth.MAX_PASSWORD_LENGTH)
        problem = auth.password_problem(new)
        if problem:
            raise RequestError(400, problem)
        who = auth.RECOVERY_CHALLENGES.check(_get_str(payload, "ticket", max_len=64), _get_str(payload, "telegram_code", max_len=16))
        if not who or who != username:
            auth.LIMITER.failed(client, username if known else None)
            database.add_audit("auth", "Failed password recovery finish", f"User {username or '?'} from {client}",
                               actor=username if known and database.get_user(username) else None)
            raise RequestError(401, "That code is wrong or has expired")
        # The account may have changed since the start: blocked, or 2FA turned off. Same answer as above.
        account = database.get_user(username)
        if not account or account.get("disabled") or not database.get_totp(username)["enabled"]:
            auth.LIMITER.failed(client, username)
            database.add_audit("auth", "Password recovery refused at the last step",
                               f"User {username}: blocked or two-factor authentication off, from {client}",
                               actor=username if account else None)
            raise RequestError(401, "That code is wrong or has expired")
        database.set_account_password(username, auth.hash_password(new))
        auth.SESSIONS.revoke_user(username)
        auth.LIMITER.succeeded(client, username)
        database.add_audit("auth", f"Password reset by recovery for {username}", f"From {client}; their sessions logged out",
                           actor=username)
        security_alert("recovered", who=username, name=username)
        self._send_json(200, {"success": True})

    # --- Users (Settings, Users; needs users.manage, checked by the route table) ---

    def _user_view(self, u: Dict[str, Any], live: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        scope = rbac.scope_of(u)
        return {"username": u["username"], "display_name": u.get("display_name") or "", "role": u.get("role") or "viewer",
                "permissions": sorted(rbac.permissions_for(u)), "disabled": bool(u.get("disabled")),
                "device_scope": {"all": True} if scope is None else dict(scope, all=False),
                "created_at": u["created_at"], "last_login": u.get("last_login"),
                "sessions": live.get(u["username"], {}).get("sessions", 0),
                "last_active": live.get(u["username"], {}).get("last_active"),
                "two_factor": bool(u.get("totp_enabled")),
                "you": u["username"] == self.user.username,
                "can_change": self._can_change_user(u)}

    def _can_change_user(self, u: Dict[str, Any]) -> bool:
        """Whether this user may act on u at all (the page hides Edit and More otherwise)."""
        try:
            self._check_user_change(u, {})
        except RequestError:
            return False
        return True

    def _active_admins(self, without: Optional[str] = None) -> int:
        return sum(1 for u in database.list_users()
                   if (u.get("role") == "admin") and not u.get("disabled") and u["username"] != without)

    def _parse_user_fields(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if "role" in payload:
            role = payload.get("role")
            if role not in rbac.ROLES:
                raise RequestError(400, "Role must be one of " + ", ".join(rbac.ROLES))
            out["role"] = role
            out["permissions"] = json.dumps(rbac.parse_permissions(payload.get("permissions"))) if role == "custom" else None
        if "device_scope" in payload:
            scope = rbac.parse_scope(payload.get("device_scope"),
                                     [p["profile_id"] for p in poller.load_hardware_profiles()],
                                     [d["id"] for d in database.device_profiles()])
            if not scope["all"] and not scope["profiles"] and not scope["devices"]:
                raise RequestError(400, "Pick at least one template or device, or allow all devices")
            out["device_scope"] = json.dumps(scope)
        if "display_name" in payload:
            out["display_name"] = _get_str(payload, "display_name", max_len=64) or None
        if "disabled" in payload:
            out["disabled"] = 1 if payload.get("disabled") is True else 0
        return out

    def _checked_workflow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """A workflow from the editor, refused when it reaches past the saver's rights; records the saver."""
        fields = parse_workflow_payload(payload)
        problem = workflow_rights_problem(self.user, fields)
        if problem:
            raise RequestError(403, f"Cannot save this workflow: {problem}")
        fields["saved_by"] = self.user.username
        return fields

    def _check_upstream(self, extra: Optional[Dict[str, Any]], before: Optional[Dict[str, Any]]) -> None:
        """An upstream device outside the user's device access answers as if it did not exist. The
        upstream a device already has may be kept, so an edit does not fail on a field left as it was."""
        up = (extra or {}).get("upstream_device_id")
        if up is None or self.user.sees_id(up) or (before and before.get("upstream_device_id") == up):
            return
        raise RequestError(400, "The upstream device does not exist")

    def _check_user_change(self, target: Optional[Dict[str, Any]], fields: Dict[str, Any]) -> None:
        """Limits on a user manager who is not an administrator: no administrator accounts, no
        permission or device access they do not hold themselves, and no changes to their own rights."""
        me = self.user
        if me.is_admin:
            return
        if target is not None and target.get("role") == "admin":
            raise RequestError(403, "Only an administrator can change an administrator account")
        if target is not None and not rbac.permissions_for(target) <= me.perms:
            raise RequestError(403, "Only an administrator can change a user with permissions you do not have")
        profile_of = None
        if me.scope is not None:
            profile_of = {d["id"]: d["profile_id"] for d in database.device_profiles()}
        # Covers every change to a user: fields, block, password, 2FA reset, log out and delete.
        if target is not None and me.scope is not None and not rbac.scope_within(rbac.scope_of(target), me.scope, profile_of):
            raise RequestError(403, "Only an administrator can change a user with device access you do not have.")
        if target is not None and target["username"] == me.username and any(k in fields for k in ("role", "permissions", "device_scope")):
            raise RequestError(403, "You cannot change your own role, permissions or device access")
        if "role" in fields:
            if fields["role"] == "admin":
                raise RequestError(403, "Only an administrator can make someone an administrator")
            granted = rbac.permissions_for({"role": fields["role"], "permissions": fields.get("permissions")})
            if "users.manage" in granted:
                raise RequestError(403, "Only an administrator can give the Manage users permission")
            if not granted <= me.perms:
                raise RequestError(403, "You cannot give a permission you do not have yourself")
        if me.scope is not None and "device_scope" in fields:
            granted_scope = rbac.scope_of({"role": "custom", "device_scope": fields["device_scope"]})
            if not rbac.scope_within(granted_scope, me.scope, profile_of):
                raise RequestError(403, "You cannot give access to devices outside your own device access")

    def _users_route(self, path: str) -> None:
        live = auth.SESSIONS.by_user()
        m = re.fullmatch(r"/api/users(?:/([A-Za-z0-9._-]{1,32})(?:/(password|logout|2fa-reset))?)?", path)
        if not m:
            raise RequestError(404, "Endpoint not found")
        name, action = m.group(1), m.group(2)
        if self.command == "GET" and not name:
            self._send_json(200, {"users": [self._user_view(u, live) for u in database.list_users()],
                                  "roles": [{"id": k, "label": v[0], "help": v[1],
                                             "permissions": sorted(v[2]) if v[2] is not None else None}
                                            for k, v in rbac.ROLES.items()],
                                  "permissions": [{"id": k, "label": l, "help": h} for k, l, h in rbac.PERMISSIONS],
                                  "templates": sorted(({"id": p["profile_id"], "name": p.get("name", p["profile_id"])}
                                                       for p in poller.load_hardware_profiles()), key=lambda t: t["name"].lower()),
                                  "devices": sorted(({"id": d["id"], "hostname": d["hostname"], "profile_id": d["profile_id"]}
                                                     for d in database.list_devices()), key=lambda d: d["hostname"].lower()),
                                  "min_length": auth.MIN_PASSWORD_LENGTH})
            return
        payload = self._read_json() if self.command in ("POST", "PUT") else {}
        if self.command == "POST" and not name:
            username = _get_str(payload, "username", max_len=32)
            if not _USERNAME.fullmatch(username):
                raise RequestError(400, "Username: 1 to 32 letters, digits, dot, dash or underscore")
            password = _get_str(payload, "password", max_len=auth.MAX_PASSWORD_LENGTH)
            problem = auth.password_problem(password)
            if problem:
                raise RequestError(400, problem)
            fields = self._parse_user_fields(dict({"role": "viewer"}, **payload))
            if self.user.scope is not None and "device_scope" not in fields:
                fields["device_scope"] = json.dumps(dict(self.user.scope, all=False))
            self._check_user_change(None, fields)
            if not database.create_user(username, auth.hash_password(password), fields["role"], fields.get("permissions"),
                                        fields.get("device_scope"), fields.get("display_name")):
                raise RequestError(409, "A user with that name already exists")
            changelog.mark_seen(username)  # a new user starts with nothing unread
            database.add_audit("users", f"Added user {username} ({rbac.ROLES[fields['role']][0]})", f"By {self.user.username}")
            security_alert("user_added", name=username, role=rbac.ROLES[fields["role"]][0])
            if fields["role"] == "admin":
                security_alert("admin_added", name=username)
            self._send_json(201, {"success": True, "user": self._user_view(database.get_user(username), live)})
            return
        target = database.get_user(name) if name else None
        if target is None:
            raise RequestError(404, "User not found")
        is_admin = target.get("role") == "admin" and not target.get("disabled")
        if self.command == "PUT" and not action:
            fields = self._parse_user_fields(payload)
            self._check_user_change(target, fields)
            losing_admin = is_admin and (fields.get("role", "admin") != "admin" or fields.get("disabled"))
            if losing_admin and self._active_admins(without=name) == 0:
                raise RequestError(409, "Keep at least one active administrator")
            if name == self.user.username and fields.get("disabled"):
                raise RequestError(409, "You cannot block your own account")
            database.update_user(name, fields)
            if fields.get("disabled"):
                auth.SESSIONS.revoke_user(name)
            what = ", ".join(k.replace("_", " ") for k in fields) or "nothing"
            database.add_audit("users", f"{'Blocked' if fields.get('disabled') else 'Changed'} user {name}",
                               f"{what}; by {self.user.username}")
            role = fields.get("role", target.get("role"))
            if role == "admin" and target.get("role") != "admin":
                security_alert("admin_added", name=name)
            elif (role != target.get("role")) or ("permissions" in fields and fields["permissions"] != target.get("permissions")):
                security_alert("role_changed", name=name, role=rbac.ROLES.get(role, (role,))[0])
            self._send_json(200, {"success": True, "user": self._user_view(database.get_user(name), live)})
            return
        if self.command in ("POST", "DELETE") and name != self.user.username:
            self._check_user_change(target, {})
        if self.command == "POST" and action == "password":
            password = _get_str(payload, "password", max_len=auth.MAX_PASSWORD_LENGTH)
            problem = auth.password_problem(password)
            if problem:
                raise RequestError(400, problem)
            database.set_account_password(name, auth.hash_password(password))
            auth.SESSIONS.revoke_user(name, except_token=self.token if name == self.user.username else None)
            database.add_audit("users", f"Reset the password of {name}", f"By {self.user.username}; their sessions logged out")
            self._send_json(200, {"success": True})
            return
        if self.command == "POST" and action == "2fa-reset":
            # For a user who lost their phone and their recovery codes; they set it up again after logging in.
            database.set_totp(name, None, False)
            auth.SESSIONS.revoke_user(name, except_token=self.token if name == self.user.username else None)
            database.add_audit("users", f"Reset two-factor authentication of {name}", f"By {self.user.username}; their sessions logged out")
            security_alert("twofa_reset", name=name)
            self._send_json(200, {"success": True})
            return
        if self.command == "POST" and action == "logout":
            n = auth.SESSIONS.revoke_user(name, except_token=self.token if name == self.user.username else None)
            database.add_audit("users", f"Logged out {name}", f"{n} session(s); by {self.user.username}")
            self._send_json(200, {"success": True, "ended": n})
            return
        if self.command == "DELETE" and not action:
            if name == self.user.username:
                raise RequestError(409, "You cannot delete your own account")
            if is_admin and self._active_admins(without=name) == 0:
                raise RequestError(409, "Keep at least one active administrator")
            database.delete_user(name)
            auth.SESSIONS.revoke_user(name)
            database.add_audit("users", f"Deleted user {name}", f"By {self.user.username}")
            security_alert("user_deleted", name=name)
            self._send_json(200, {"success": True})
            return
        raise RequestError(404, "Endpoint not found")

    def _start_scan(self, payload: Dict[str, Any], community: str, ports: Any) -> "discovery.ScanJob":
        """One scan over "subnets" (a list), "subnet" (one, the older form) or "hosts" (addresses)."""
        hosts = payload.get("hosts")
        if hosts is not None and (not isinstance(hosts, list) or not all(isinstance(h, str) and len(h) <= 15 for h in hosts)):
            raise RequestError(400, 'hosts must be a list of addresses such as ["192.168.1.20"]')
        subnets = payload.get("subnets")
        if subnets is None and not hosts:
            subnets = [_get_str(payload, "subnet", max_len=43)]
        if not hosts and (not isinstance(subnets, list) or not all(isinstance(s, str) and len(s) <= 43 for s in subnets)):
            raise RequestError(400, 'subnets must be a list such as ["192.168.1.0/24"]')
        devices = database.list_devices()
        known = {d["ip_address"] for d in devices if not d.get("service_port")}
        known_ports = {(d["ip_address"], d["service_port"]) for d in devices if d.get("service_port")}
        try:
            return discovery.SCANNER.start(subnets, community, known, ports=ports, hosts=hosts or None, known_ports=known_ports)
        except discovery.DiscoveryError as exc:
            raise RequestError(400, str(exc))

    @staticmethod
    def _tagged_ids(tag: str) -> set:
        """Ids of the devices with this tag (any case)."""
        low = tag.lower()
        return {d["id"] for d in database.list_devices() if low in (t.lower() for t in taxonomy.device_tags(d))}

    def _events_page(self, q: Dict[str, list]) -> Dict[str, Any]:
        """GET /api/events: filtered, paginated event log. Without page parameters it returns the latest 200."""
        def one(key: str) -> str:
            return (q.get(key, [""])[0] or "").strip()
        per_page = _get_int({"n": one("per_page") or "50"}, "n", 50, 10, 500)
        page = _get_int({"n": one("page") or "1"}, "n", 1, 1, 100000)
        device = one("device")
        severity = one("severity") if one("severity") in alerts.SEVERITIES else ""
        since = _get_int({"n": one("from")}, "n", None, 0, 2 ** 40) if one("from") else None
        until = _get_int({"n": one("to")}, "n", None, 0, 2 ** 40) if one("to") else None
        device_id = int(device) if device.isdigit() else None
        if device_id is not None and not self.user.sees_id(device_id):
            device_id = -1
        events, total = database.list_events_filtered(
            q=one("q")[:100], device_id=device_id, severity=severity, event_type=one("type")[:32],
            since=since, until=until, allowed_ids=None if self.user.scope is None else self.user.allowed_ids,
            actor=self.user.username, offset=(page - 1) * per_page, limit=per_page,
            device_ids=self._tagged_ids(one("tag")) if one("tag") else None)
        return {"events": events, "total": total, "page": page, "per_page": per_page,
                "pages": max(1, -(-total // per_page)), "types": database.event_types()}

    def do_GET(self) -> None:
        self._dispatch(self._get)

    def do_POST(self) -> None:
        self._dispatch(self._post)

    def do_PUT(self) -> None:
        self._dispatch(self._put)

    def do_DELETE(self) -> None:
        self._dispatch(self._delete)

    # --- Routes ---

    def _get(self, parsed) -> None:
        path = parsed.path.rstrip("/")

        if path in STATIC_FILES:
            self._serve_file(*STATIC_FILES[path])
            return

        if path == "/api/devices":
            self._send_json(200, {"devices": self.user.visible(device_list_view(), key="id")})
            return

        if path == "/api/problems":
            self._send_json(200, {"problems": self.user.visible(all_problems())})
            return

        if path == "/api/events":
            self._send_json(200, self._events_page(parse_qs(parsed.query)))
            return

        if path == "/api/availability":
            devices = self.user.visible(database.list_devices(), key="id")
            stats = availability.summary([d["id"] for d in devices])
            key, tz = self._avail_range(parse_qs(parsed.query))
            ranged = availability.ranged([d["id"] for d in devices], key, tz)
            profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
            self._send_json(200, {"range": key, "devices": [dict({k: d.get(k) for k in ("id", "hostname", "ip_address", "profile_id", "status",
                                                                         "service_port", "service_kind")},
                                                   group=device_group(d, profiles), tags=taxonomy.device_tags(d),
                                                   ranged=ranged[d["id"]], **stats[d["id"]]) for d in devices]})
            return

        match_avail = re.fullmatch(r"/api/availability/(\d+)", path)
        if match_avail:
            device_id = int(match_avail.group(1))
            if not self.user.sees_id(device_id) or not database.get_device(device_id):
                raise RequestError(404, "Device not found")
            key, tz = self._avail_range(parse_qs(parsed.query))
            data = availability.detail(device_id)
            data["range"] = key
            data["ranged"] = availability.ranged([device_id], key, tz)[device_id]
            self._send_json(200, data)
            return

        if path == "/api/taxonomy":
            # Groups and tags with how many devices use each (the device lists, filters and Settings).
            data = taxonomy.summary()
            profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
            known = {g["id"] for g in data["groups"]}
            counts: Dict[str, int] = {}
            for d in self.user.visible(database.list_devices(), key="id"):
                g = device_group(d, profiles, known)
                counts[g] = counts.get(g, 0) + 1
            for g in data["groups"]:
                g["devices"] = counts.get(g["id"], 0)
            self._send_json(200, data)
            return

        if path == "/api/features":
            # Optional parts of the app the menu shows only when switched on and set up.
            self._send_json(200, {"proxmox": proxmox.is_enabled() and proxmox.is_configured() and self.user.scope is None,
                                  # After an upgrade from before HTTPS: ask someone who may change it, once.
                                  "tls_prompt": self.user.can("settings.system") and tls.public_state()["prompt"],
                                  # The inventory lists every address on the network: not for users limited to some devices.
                                  "inventory": self.user.scope is None,
                                  "wifi": unifi.is_enabled() and unifi.is_configured() and self.user.scope is None,
                                  "pihole": pihole.is_enabled() and pihole.is_configured() and self.user.scope is None})
            return

        if path == "/api/tls":
            self._send_json(200, tls.public_state())
            return
        if path == "/api/alerts/changed":
            self._send_json(200, changed_alert_settings(self.user))
            return
        if path == "/api/required":
            steps = required_steps(self.user)
            data_dir = os.path.dirname(os.path.abspath(database.DB_FILE))
            result = _read_result(data_dir, "passphrase")
            self._send_json(200, dict(steps, passphrase_pending=os.path.exists(os.path.join(data_dir, "requests", PASSPHRASE_REQUEST)),
                                      passphrase_error=(result["output"] if result and not result["ok"] else "")))
            return
        if path == "/api/maintenance":
            scopes = [s for s in maintenance.SCOPES if s != "all" or self.user.scope is None]
            self._send_json(200, {"windows": maintenance_view(self.user, maintenance.windows()), "scopes": scopes})
            return
        if path == "/api/inventory":
            if self.user.scope is not None:
                raise RequestError(403, "The inventory lists every device on the network")
            self._send_json(200, dict(inventory.listing(), weak_dbm=alert_policy().resolve("wifi_weak", upto="global")[0]["threshold"] or -75))
            return
        if path == "/api/pihole/config":
            self._send_json(200, pihole.public_config())
            return
        if path in ("/api/pihole", "/api/wifi"):
            if self.user.scope is not None:
                raise RequestError(403, "This page covers the whole network")
            self._send_json(200, pihole.view(database.list_devices()) if path == "/api/pihole" else wifi_view())
            return
        if path == "/api/unifi/config":
            self._send_json(200, unifi.public_config())
            return
        if path == "/api/changes":
            # What's changed: every release note, and the ones this user has not read yet.
            self._send_json(200, changelog.view(self.user.username))
            return
        if path == "/api/tls/certificate":
            # The public certificate only (never the key), to trust it on a computer or phone.
            pem = tls.certificate_pem().encode("ascii", "replace")
            if not pem:
                raise RequestError(404, "HTTPS is off")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Disposition", 'attachment; filename="homelab-monitor.crt"')
            self.send_header("Content-Length", str(len(pem)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(pem)
            return

        if path == "/api/proxmox/config":
            # The settings card: switch and connection without contacting Proxmox (the secret only as set / not set).
            self._send_json(200, dict(proxmox.public_config(), action_token_id=proxmox.action_config()["token_id"],
                                      action_secret_set=bool(proxmox.action_config()["secret"])))
            return

        if path == "/api/proxmox/rrd":
            if self.user.scope is not None:
                raise RequestError(403, "The Proxmox view needs access to every device")
            q = parse_qs(parsed.query)
            cfg = proxmox.load_config()
            if not (proxmox.is_enabled() and proxmox.is_configured(cfg)):
                raise RequestError(409, "Proxmox is not switched on (Settings, Proxmox)")
            node = q.get("node", [""])[0]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node):
                raise RequestError(400, "Unknown node name")
            vmid = q.get("vmid", [""])[0]
            try:
                points = proxmox.rrd(proxmox.Client(cfg), node, q.get("type", ["node"])[0],
                                     int(vmid) if vmid.isdigit() else None, q.get("timeframe", ["hour"])[0])
            except proxmox.ProxmoxError as exc:
                raise RequestError(400, str(exc))
            self._send_json(200, {"points": points})
            return

        if path == "/api/proxmox":
            # The cluster view lists every guest, so it is for users who see every device.
            if self.user.scope is not None:
                raise RequestError(403, "The Proxmox view needs access to every device")
            force = parse_qs(parsed.query).get("refresh", ["0"])[0] == "1"
            try:
                data = proxmox.overview([{"id": d["id"], "hostname": d["hostname"], "ip_address": d["ip_address"], "service_port": d.get("service_port")}
                                         for d in database.list_devices()], force=force)
            except proxmox.ProxmoxError as exc:
                data = {"configured": True, "error": str(exc)}
            self._send_json(200, dict(data, config=proxmox.public_config()))
            return

        if path == "/api/notifications":
            account = database.get_user(self.user.username)
            items = database.list_notifications(None if self.user.scope is None else self.user.allowed_ids,
                                                self.user.username)
            read_at = account.get("notify_read_at") or 0
            self._send_json(200, {"items": items, "read_at": read_at,
                                  "unread": sum(1 for e in items if e["timestamp"] > read_at)})
            return

        match_dev = re.fullmatch(r"/api/devices/(\d+)(?:/(ports|neighbours|wireless|storage|health|processes|software|events|history|dns))?", path)
        if match_dev:
            device_id = int(match_dev.group(1))
            device = database.get_device(device_id)
            if not device:
                raise RequestError(404, "Device not found")
            self._send_json(200, self._device_view(device, match_dev.group(2), parse_qs(parsed.query)))
            return

        if path == "/api/profiles":
            profiles = [{"profile_id": p["profile_id"], "name": p.get("name", p["profile_id"])}
                        for p in poller.load_hardware_profiles()]
            self._send_json(200, {"profiles": sorted(profiles, key=lambda p: p["name"])})
            return

        if path == "/api/settings":
            values = database.get_all_settings()
            # Secret settings are reported as set or not set, never by value.
            self._send_json(200, {k: ("" if s["type"] == "secret" else values.get(k, s["default"]))
                                  for k, s in SETTINGS.items()}
                            | {f"{k}__set": bool(values.get(k)) for k, s in SETTINGS.items() if s["type"] == "secret"})
            return

        if path == "/api/settings/schema":
            self._send_json(200, {"schema": list(SETTINGS.values())})
            return

        if path == "/api/support/report":
            if not self.user.is_admin:
                raise RequestError(403, "Only administrators can make a problem report")
            database.add_audit("system", "Problem report made", f"By {self.user.username}")
            self._send_json(200, problem_report())
            return

        if path == "/api/updates/summary":
            # The red number on Settings: administrators only (they are the ones who can update).
            if not self.user.is_admin:
                self._send_json(200, {"waiting": 0})
                return
            u = update_status()
            self._send_json(200, {"waiting": u["waiting"], "latest": (u["check"] or {}).get("latest"),
                                  "running": bool(u["pending"]["work"])})
            return

        hist = re.fullmatch(r"/api/updates/history(?:/(\d{1,16})/log)?", path)
        if hist:
            if not self.user.is_admin:
                raise RequestError(403, "Only administrators can see the update history")
            if not hist.group(1):
                self._send_json(200, {"history": update_history()})
                return
            text = update_history_log(int(hist.group(1)))
            if text is None:
                raise RequestError(404, "That log is no longer kept")
            self._send_json(200, {"id": int(hist.group(1)), "log": text})
            return

        if path == "/api/system":
            self._send_json(200, {
                "version": APP_VERSION,
                "built": BUILT,
                "python": sys.version.split()[0],
                "started_at": STARTED_AT,
                "listen": f"{LISTEN_HOST}:{LISTEN_PORT}",
                "devices": len(database.list_devices()),
                "scheduler": scheduler.stats(),
                "storage": database.storage_stats(),
                "vault": self._vault_status(encrypted_items=database.count_encrypted_secrets()),
                "backup": backup_status(),
                "update": update_status(),
                "demo": demo_status(),
            })
            return

        if path == "/api/credentials":
            creds = [dict(c, public_fingerprint=ssh_runner.public_fingerprint(c["public_key"]) if c["public_key"] else None)
                     for c in database.list_credentials()]
            self._send_json(200, {"credentials": creds, "vault": self._vault_status(),
                                  "keygen_available": ssh_runner.keygen_available()})
            return

        if path == "/api/host-actions":
            params = parse_qs(parsed.query)
            out: Dict[str, Any] = {"actions": hostactions.catalogue()}
            raw_id = params.get("device_id", [""])[0]
            if raw_id:
                device = self._require_device(_get_int({"d": raw_id}, "d", 0, 1, 2**31))
                out.update(host_action_view(device, params.get("problem", [""])[0][:200]))
            self._send_json(200, out)
            return

        if path == "/api/host-actions/runs":
            raw_id = parse_qs(parsed.query).get("device_id", [""])[0]
            device_id = self._require_device(_get_int({"d": raw_id}, "d", 0, 1, 2**31))["id"] if raw_id else None
            runs = [r for r in database.list_action_runs(device_id, 50) if self.user.sees_id(r["device_id"])]
            self._send_json(200, {"runs": runs, "running": hostactions.RUNS.running()})
            return

        match_arun = re.fullmatch(r"/api/host-actions/runs/(\d+)", path)
        if match_arun:
            run = database.get_action_run(int(match_arun.group(1)))
            if not run or not self.user.sees_id(run["device_id"]):
                raise RequestError(404, "Run not found")
            self._send_json(200, {"run": run})
            return

        if path == "/api/automation":
            # What the workflow editor and Fix SNMP pick from: hosts (with host key state), credentials.
            devices = [{"id": d["id"], "hostname": d["hostname"], "ip_address": d["ip_address"],
                        "profile_id": d["profile_id"], "host_key": bool(database.get_host_keys(d["id"]))}
                       for d in database.list_devices() if self.user.sees_id(d["id"])]
            self._send_json(200, {"devices": devices, "credentials": database.list_credentials(),
                                  "ssh_available": bool(ssh_runner.ssh_binary())})
            return

        match_hk = re.fullmatch(r"/api/devices/(\d+)/hostkey", path)
        if match_hk:
            device = database.get_device(int(match_hk.group(1)))
            if not device:
                raise RequestError(404, "Device not found")
            params = parse_qs(parsed.query)
            port = _get_int({"p": params.get("port", ["22"])[0]}, "p", 22, 1, 65535)
            self._send_json(200, {"approved": database.get_host_keys(device["id"]),
                                  "presented": ssh_runner.fetch_host_key(device["ip_address"], port)})
            return

        if path == "/api/dashboard":
            name = dashboard_name(parse_qs(parsed.query).get("name", ["default"])[0])
            dash = stored_dashboard(name)
            if dash is None:
                raise RequestError(404, "Dashboard not found")
            title = dash.get("title") or ("Overview" if name == "default" else name)
            self._send_json(200, {"name": name, "title": title, "layout": dash["widgets"], "columns": dash["columns"],
                                  "default": DEFAULT_DASHBOARD, "column_options": DASHBOARD_COLUMNS,
                                  "dashboards": dashboards_list()})
            return

        if path == "/api/dashboards":
            self._send_json(200, {"dashboards": dashboards_list(),
                                  "templates": [{k: t[k] for k in ("id", "title", "description", "columns")}
                                                | {"tiles": [w["type"] for w in t["widgets"]]} for t in DASHBOARD_TEMPLATES]})
            return

        if path == "/api/dashboard/extras":
            want = [w for w in parse_qs(parsed.query).get("want", [""])[0].split(",") if w in EXTRA_WIDGETS]
            self._send_json(200, dashboard_extras(want, self.user))
            return

        if path == "/api/wan":
            self._send_json(200, {"wan": wan_interfaces()})
            return

        if path == "/api/interfaces/top":
            params = parse_qs(parsed.query)
            limit = _get_int({"n": params.get("limit", ["10"])[0]}, "n", 10, 1, 50)
            self._send_json(200, {"interfaces": self.user.visible(top_interfaces(limit))})
            return

        if path == "/api/map":
            view = map_view()
            if self.user.scope is not None:
                # Devices outside the user's access leave the map; hand-drawn objects stay.
                view["nodes"] = [n for n in view["nodes"] if not n.get("device_id") or self.user.sees_id(n["device_id"])]
                keys = {n["key"] for n in view["nodes"]}
                view["links"] = [l for l in view["links"] if l["a"] in keys and l["b"] in keys]
                view["parent"] = {k: v for k, v in view["parent"].items() if k in keys and v in keys}
            self._send_json(200, view)
            return

        if path == "/api/setup/status":
            own = monitor_address()
            self._send_json(200, {"completed": setup.is_completed(), "monitor_ip": own,
                                  "default_subnet": discovery.default_subnet(own), "site": setup.get_site(),
                                  "defaults": {k: database.get_all_settings().get(k, SETTINGS[k]["default"])
                                               for k in SETUP_SETTING_KEYS if k != "default_snmp_community"}})
            return

        match_scan = re.fullmatch(r"/api/(?:setup|devices)/scan/([0-9a-f]{32})", path)
        if match_scan:
            job = discovery.SCANNER.get(match_scan.group(1))
            if not job:
                raise RequestError(404, "Scan not found")
            self._send_json(200, job.view())
            return

        if path == "/api/custom-oids":
            # ?device=<id>: what applies to that device (its own and its template's); otherwise every definition.
            q = parse_qs(parsed.query)
            dev = q.get("device", [""])[0]
            if dev.isdigit():
                device = database.get_device(int(dev))
                if not device or not self.user.sees_id(device["id"]):
                    raise RequestError(404, "Device not found")
                defs = customoids.for_device(device)
                strings = database.get_device_table(device["id"], "custom")
                self._send_json(200, {"definitions": defs, "strings": list(strings.values()),
                                      "enterprise": customoids.enterprise_root(device), "kinds": list(customoids.KINDS)})
                return
            defs = [d for d in customoids.all_defs() if d["scope"] == "template" or self.user.sees_id(int(d["target"]))]
            self._send_json(200, {"definitions": defs, "kinds": list(customoids.KINDS)})
            return

        match_walk = re.fullmatch(r"/api/devices/(\d+)/snmp-walk", path)
        if match_walk:
            device = database.get_device(int(match_walk.group(1)))
            if not device:
                raise RequestError(404, "Device not found")
            q = parse_qs(parsed.query)
            oid = q.get("oid", [""])[0] or customoids.enterprise_root(device)
            try:
                self._send_json(200, customoids.walk(device, oid[:200], max_rows=500))
            except ValueError as exc:
                raise RequestError(400, str(exc))
            return

        if path == "/api/alert-rules":
            q = parse_qs(parsed.query)
            if q.get("scope", [""])[0] == "overview":
                self._send_json(200, alert_overview(self.user))
                return
            scope, target = q.get("scope", ["global"])[0], q.get("target", [""])[0]
            if scope == "device" and target.isdigit() and not self.user.sees_id(int(target)):
                raise RequestError(404, "Device not found")
            view = alert_rules_view(scope, target)
            view["devices"] = self.user.visible(view["devices"], key="id")
            self._send_json(200, view)
            return

        if path == "/api/notify/bot-commands":
            self._send_json(200, bot_commands_view())
            return

        if path == "/api/notify/bot-choices":
            try:
                self._send_json(200, botcmds.choices(parse_qs(parsed.query).get("source", [""])[0]))
            except botcmds.CommandError as exc:
                raise RequestError(400, str(exc))
            return

        if path == "/api/notify/info":
            status = NOTIFIER.status()
            self._send_json(200, {"placeholders": notify.PLACEHOLDERS,
                                  "events": {k: v[0] for k, v in notify.EVENTS.items()},
                                  "event_placeholders": notify.EVENT_PLACEHOLDERS, "presets": notify.PRESETS,
                                  "emojis": notify.EMOJIS, "sample": notify.SAMPLE, "tricks": tpl.TRICKS,
                                  "commands": {k: {"placeholders": telebot.TEMPLATE_PLACEHOLDERS[k], "default": v[2],
                                                   "presets": [v[2]] + v[3]} for k, v in telebot.TEMPLATES.items()},
                                  "command_samples": telebot.samples(),
                                  "sent": status["sent"], "last_error": status["last_error"],
                                  "outbox": {"queued": status["queued"], "oldest_seconds": status["oldest_seconds"]}})
            return

        if path == "/api/workflows":
            shown = workflows_in_scope(self.user, database.list_workflows())
            ids = {w["id"] for w in shown}
            self._send_json(200, {"workflows": [workflow_view(w) for w in shown],
                                  "running": {k: v for k, v in workflows.MANAGER.running().items() if k in ids}})
            return

        if path == "/api/workflows/runs":
            wid = parse_qs(parsed.query).get("workflow_id", [None])[0]
            wid = _get_int({"w": wid}, "w", None, 1, 2**31) if wid else None
            self._send_json(200, {"runs": workflows_in_scope(self.user, database.list_workflow_runs(wid), "workflow_id")})
            return

        match_wrun = re.fullmatch(r"/api/workflow-runs/(\d+)", path)
        if match_wrun:
            run = database.get_workflow_run(int(match_wrun.group(1)))
            if not run or not workflows_in_scope(self.user, [run], "workflow_id"):
                raise RequestError(404, "Run not found")
            self._send_json(200, run)
            return

        if path == "/api/audit":
            q = parse_qs(parsed.query)

            def one(key: str) -> str:
                return (q.get(key, [""])[0] or "").strip()
            sensitive = self.user.can("audit.sensitive")
            per_page = _get_int({"n": one("per_page") or "50"}, "n", 50, 10, 500)
            page = _get_int({"n": one("page") or "1"}, "n", 1, 1, 100000)
            since = _get_int({"n": one("from")}, "n", None, 0, 2 ** 40) if one("from") else None
            until = _get_int({"n": one("to")}, "n", None, 0, 2 ** 40) if one("to") else None
            logs, total = database.list_audit_filtered(
                q=one("q")[:100], category=one("category")[:32], since=since, until=until,
                search_details=sensitive, offset=(page - 1) * per_page, limit=per_page)
            if not sensitive:
                # Fingerprints, client addresses and credential details stay with those allowed to see them.
                for entry in logs:
                    if entry.get("category") in SENSITIVE_AUDIT_CATEGORIES and entry.get("details"):
                        entry["details"] = "(hidden: needs the Sensitive audit details permission)"
                    entry["source"] = ""
                    if entry.get("category") in SENSITIVE_AUDIT_CATEGORIES:
                        entry["actor"] = ""
            self._send_json(200, {"logs": logs, "total": total, "page": page, "per_page": per_page,
                                  "pages": max(1, -(-total // per_page)), "categories": database.audit_categories()})
            return

        raise RequestError(404, "Endpoint not found")

    def _device_view(self, device: Dict[str, Any], section: Optional[str], params: Dict[str, list]) -> Dict[str, Any]:
        """Builds the JSON for /api/devices/<id> and its sub-sections."""
        device_id = device["id"]
        if section is None:
            latest = database.get_latest_metrics(device_id)
            m = {row["metric_key"]: row["value"] for row in latest}
            interfaces = database.get_device_table(device_id, "interfaces")
            now = int(time.time())
            return {
                "device": public_device(device),
                "latest_metrics": [row for row in latest if not row["metric_key"].startswith("if.")],
                "ping_history": database.get_metric_history(device_id, "icmp_ping_ms", now - 3600, now),
                "sections": database.list_table_names(device_id),
                # Latest-only metrics: shown as current values, never graphed.
                "untracked": untracked_keys(device),
                "metric_info": metric_info(device),
                "overview_graphs": overview_graphs(device_id),
                "ports": port_summary(interfaces),
                "cpu_pct": cpu_pct(m),
                "mem_pct": memory_used_pct(m),
                "problems": [p for p in database.list_active_problems() if p["device_id"] == device_id],
                "events": database.list_events(device_id, limit=10),
                "forecasts": forecast.cached().get(device_id, []),
                "maintenance": maintenance_window(device),
            }
        if section == "ports":
            interfaces = database.get_device_table(device_id, "interfaces")
            ssid_by_iface = {r.get("name"): r for r in database.get_device_table(device_id, "ssids").values()}
            mac_counts: Dict[int, int] = {}
            for row in database.get_device_table(device_id, "fdb").values():
                mac_counts[row["if_index"]] = mac_counts.get(row["if_index"], 0) + 1
            rows = sorted(interfaces.values(), key=lambda r: r["if_index"])
            wan = {w["if_index"] for w in wan_interfaces() if w["device_id"] == device_id}
            for r in rows:
                r["mac_count"] = mac_counts.get(r["if_index"], 0)
                r["group"], r["group_rank"] = interface_group(r, ssid_by_iface)
                r["wan"] = r["if_index"] in wan
            return {"ports": rows}
        if section == "neighbours":
            return {"neighbours": neighbours_view(device_id)}
        if section == "wireless":
            return {"radios": list(database.get_device_table(device_id, "radios").values()),
                    "ssids": list(database.get_device_table(device_id, "ssids").values()),
                    "port_hosts": ap_port_hosts(device),
                    # Per device, from UniFi (unifi.py), when it is connected.
                    "wifi_clients": sorted(database.get_device_table(device_id, "wifi_clients").values(),
                                           key=lambda c: c.get("signal") if is_number(c.get("signal")) else 0)}
        if section == "dns":
            return {"upstreams": list(database.get_device_table(device_id, "pihole_upstreams").values()),
                    "blocked": list(database.get_device_table(device_id, "pihole_blocked").values())}
        if section == "storage":
            return {"storage": list(database.get_device_table(device_id, "storage").values()),
                    "disks": list(database.get_device_table(device_id, "disks").values()),
                    "volumes": list(database.get_device_table(device_id, "volumes").values()),
                    "sensors": list(database.get_device_table(device_id, "sensors").values()),
                    "diskio": list(database.get_device_table(device_id, "diskio").values()),
                    "limits": device_limits(device)}
        if section == "health":
            rows = database.get_device_table(device_id, "health").values()
            return {"health": sorted(rows, key=lambda r: (str(r.get("kind", "")), str(r.get("name", ""))))}
        if section == "processes":
            return {"processes": sorted(database.get_device_table(device_id, "processes").values(), key=lambda r: r["name"].lower()),
                    "services": sorted(database.get_device_table(device_id, "services").values(), key=lambda r: r["name"].lower()),
                    "watches": database.list_watches(device_id)}
        if section == "software":
            rows = database.get_device_table(device_id, "software").values()
            return {"software": sorted(rows, key=lambda r: r["name"].lower()),
                    "events": [e for e in database.list_events(device_id, limit=200) if e["event_type"] == "software"][:20]}
        if section == "events":
            return {"events": database.list_events(device_id, limit=200)}
        # history: ?keys=a,b&hours=24
        keys = [k for k in params.get("keys", [""])[0].split(",") if k][:8]
        if not keys or not all(_METRIC_KEY.fullmatch(k) for k in keys):
            raise RequestError(400, "keys must be 1 to 8 metric keys")
        hours = _get_int({"h": params.get("hours", ["24"])[0]}, "h", 24, 1, 24 * 400)
        end = int(time.time())
        span = hours * 3600
        start = end - span
        # A zoomed chart asks for its own window (start / end) so the buckets get finer; shift
        # keeps the comparison on the original period (the day or week before), not the zoom span.
        if params.get("start") and params.get("end"):
            start = _get_int({"n": params["start"][0]}, "n", start, 0, end)
            end = _get_int({"n": params["end"][0]}, "n", end, start + 60, end + 3600)
        shift = _get_int({"n": params.get("shift", [str(end - start)])[0]}, "n", end - start, 60, 400 * 86400)
        out = {"hours": hours, "start": start, "end": end, "series": {
            k: database.get_metric_history_bucketed(device_id, k, start, end) for k in keys}}
        if params.get("compare", ["0"])[0] == "1":
            # The previous window of the same length, shifted forward onto the current
            # time axis so both curves overlay (yesterday on today, last week on this week).
            out["previous"] = {}
            for k in keys:
                points = database.get_metric_history_bucketed(device_id, k, start - shift, end - shift)
                out["previous"][k] = [dict(p, timestamp=p["timestamp"] + shift) for p in points]
        return out

    def _post(self, parsed) -> None:
        path = parsed.path.rstrip("/")
        payload = self._read_json()

        match_hk = re.fullmatch(r"/api/devices/(\d+)/hostkey", path)
        if match_hk:
            device = database.get_device(int(match_hk.group(1)))
            if not device:
                raise RequestError(404, "Device not found")
            expected = _get_str(payload, "fingerprint", max_len=100)
            port = _get_int(payload, "port", 22, 1, 65535)
            # Re-fetch and compare, so the approved key is the one the administrator was shown.
            presented = ssh_runner.fetch_host_key(device["ip_address"], port)
            if presented.get("error"):
                raise RequestError(502, presented["error"])
            if presented["fingerprint"] != expected:
                raise RequestError(409, "The host key changed since it was shown. Review it again before approving.")
            database.approve_host_key(device["id"], presented["key_type"], presented["key_b64"], presented["fingerprint"])
            database.add_event(device["id"], "info", "ssh", f"SSH host key approved ({presented['key_type']} {presented['fingerprint']})")
            database.add_audit("ssh", f"Approved SSH host key for {device['hostname']}",
                               f"{presented['fingerprint']}; by {self.user.username}")
            security_alert("key_approved", device=device["hostname"])
            self._send_json(200, {"success": True})
            return

        if path == "/api/credentials":
            fields = parse_credential_payload(payload, require_secret=True)
            cred_id = database.add_credential(fields["name"], fields["cred_type"], fields["username"], fields["secret"],
                                              fields["passphrase"], fields["public_key"])
            how = "generated key pair" if payload.get("generate") is True and fields["cred_type"] == "ssh_key" else fields["cred_type"]
            database.add_audit("credential", f"Added credential {fields['name']}", f"Type: {how}")
            security_alert("cred_added", name=fields["name"])
            self._send_json(201, {"success": True, "id": cred_id, "public_key": fields["public_key"]})
            return

        match_ctest = re.fullmatch(r"/api/credentials/(\d+)/test", path)
        if match_ctest:
            # Logs in and runs `true`: proves the username, secret and host key without changing anything.
            # The rules come before the secret is decrypted.
            check_credential_use(self.user, int(match_ctest.group(1)))
            cred = database.get_credential_secret(int(match_ctest.group(1)))
            if not cred:
                raise RequestError(404, "Credential not found")
            device = self._require_device(_get_int(payload, "device_id", None, 1, 2 ** 31) or 0)
            port = _get_int(payload, "ssh_port", 22, 1, 65535)
            keys = database.get_host_keys(device["id"])
            if not keys:
                message = (f"{device['hostname']}'s SSH host key is not approved yet. Review and approve it, then test again."
                           if self.user.can("credentials.manage") else
                           f"{device['hostname']}'s SSH host key is not approved yet. Someone with the Manage credentials "
                           "permission needs to approve it.")
                self._send_json(200, {"ok": False, "need_hostkey": True, "device_id": device["id"], "message": message})
                return
            r = ssh_runner.run_command(device["ip_address"], port, cred, "true", keys, 20)
            ok = r["status"] == "completed" and r["exit_code"] == 0
            detail = (r.get("stderr") or r.get("stdout") or r["status"]).strip()[:300]
            database.add_audit("credential", f"Tested credential {cred['name']} on {device['hostname']}",
                               "Login worked" if ok else "Login failed")
            self._send_json(200, {"ok": ok, "message": f"Logged in to {device['hostname']} as {cred['username']}" if ok
                                  else f"Could not log in to {device['hostname']}: {detail or 'no detail'}"})
            return

        if path == "/api/problems/ack":
            device_id = _get_int(payload, "device_id", None, 1, 2**31)
            key = _get_str(payload, "problem_key", max_len=128)
            ack = payload.get("acknowledged", True)
            if device_id is None or not key or not isinstance(ack, bool):
                raise RequestError(400, "device_id, problem_key and a boolean acknowledged are required")
            if not self.user.sees_id(device_id):
                # Outside the user's device access the problem does not exist.
                raise RequestError(404, "Problem is no longer open")
            note = _get_str(payload, "note", "", max_len=200)
            row = database.acknowledge_problem(device_id, key, ack, note)
            if row is None:
                raise RequestError(404, "Problem is no longer open")
            database.add_event(device_id, "info", "problem",
                               f"{'Acknowledged' if ack else 'Acknowledgement removed'}: {row['message']}"
                               + (f" ({note})" if ack and note else ""))
            self._send_json(200, {"success": True})
            return

        if path == "/api/devices/tags":
            # Tag or untag several devices at once (the selection bar on the Devices page).
            ids = payload.get("device_ids")
            if not isinstance(ids, list) or not 0 < len(ids) <= 500 or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
                raise RequestError(400, "device_ids must be a list of device ids")
            add, remove = payload.get("add") or [], payload.get("remove") or []
            if not isinstance(add, list) or not isinstance(remove, list) or not (add or remove):
                raise RequestError(400, "Give tags to add or remove")
            ids = [i for i in ids if self.user.sees_id(i)]
            try:
                changed = taxonomy.tag_devices(ids, add, remove)
            except taxonomy.TaxonomyError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("device", f"Tags changed on {changed} device(s)",
                               f"Added {', '.join(add) or 'none'}; removed {', '.join(remove) or 'none'}; by {self.user.username}")
            self._send_json(200, {"success": True, "changed": changed})
            return

        if path == "/api/setup/scan":
            community = _get_str(payload, "community", "", max_len=128) or \
                database.get_all_settings().get("default_snmp_community") or "public"
            # Devices (ping and SNMP), or with "ports" the services step: open ports on the hosts picked.
            ports = payload.get("ports") or None
            if ports is not None and not isinstance(ports, (str, list)):
                raise RequestError(400, "ports must be text such as 80,443,8000-8010")
            job = self._start_scan(payload, community, ports=ports)
            database.add_audit("setup", f"{'Port' if job.ports else 'Network'} scan of {job.subnet}",
                               f"{len(job.hosts)} addresses{f', {len(job.ports)} ports' if job.ports else ''}")
            self._send_json(200, {"id": job.id, "total": len(job.hosts), "subnets": job.subnets, "ports": len(job.ports)})
            return

        if path == "/api/devices/scan":
            # Add device: find hosts (SNMP and ping) or open TCP ports on one or more subnets.
            community = _get_str(payload, "community", "", max_len=128) or \
                database.get_all_settings().get("default_snmp_community") or "public"
            ports = payload.get("ports") or None
            if ports is not None and not isinstance(ports, (str, list)):
                raise RequestError(400, "ports must be text such as 80,443,8000-8010")
            job = self._start_scan(payload, community, ports=ports)
            database.add_audit("device", f"{'Port' if job.ports else 'Network'} scan of {job.subnet}",
                               f"{len(job.hosts)} addresses{f', {len(job.ports)} ports' if job.ports else ''}; by {self.user.username}")
            self._send_json(200, {"id": job.id, "total": len(job.hosts), "subnets": job.subnets, "ports": len(job.ports)})
            return

        if path in ("/api/setup/preview", "/api/setup/apply"):
            parsed_setup = parse_setup(payload)
            labels = {k: SETTINGS[k]["label"] for k in SETTINGS}
            plan = setup.plan_lines(parsed_setup["settings"], parsed_setup["site"],
                                    [dict(d) for d in parsed_setup["devices"]], labels)
            if path == "/api/setup/preview":
                result = add_devices(parsed_setup["devices"], None, dry_run=True)
                self._send_json(200, {"preview": True, "plan": plan, "devices": result})
                return
            if setup.is_completed():
                # Second lock after /api/auth/setup: the wizard never runs twice, so it cannot be used to take over.
                database.add_audit("setup", "Refused a second run of the setup wizard", f"By {self.user.username}")
                raise RequestError(409, "Setup has already been completed on this install")
            # The admin password (and code with 2FA) is checked on every apply, whatever the session timers say.
            account = database.get_user(self.user.username)
            self._check_lockout(self.client_address[0], self.user.username)
            if not auth.verify_password(_get_str(payload, "admin_password", max_len=auth.MAX_PASSWORD_LENGTH),
                                        account["password_hash"]):
                auth.LIMITER.failed(self.client_address[0], self.user.username)
                database.add_audit("setup", "Setup apply refused: wrong password", f"By {self.user.username}")
                raise RequestError(401, "Your password is needed to apply the setup, and that one is wrong")
            if database.get_totp(self.user.username)["enabled"] and \
                    not second_factor_ok(self.user.username, _get_str(payload, "admin_code", max_len=16)):
                auth.LIMITER.failed(self.client_address[0], self.user.username)
                raise RequestError(401, "Your authenticator code is needed to apply the setup")
            for k, v in parsed_setup["settings"].items():
                database.update_setting(k, v)
            secrets = parsed_setup["secrets"]
            if "credential" in secrets:
                c = secrets["credential"]
                database.add_credential(c["name"], c["cred_type"], c["username"], c["secret"])
            if "telegram" in secrets:
                database.update_setting("telegram_token", secrets["telegram"]["token"])
                database.update_setting("telegram_chat_id", secrets["telegram"]["chat_id"])
                database.update_setting("telegram_enabled", "on")
            setup.save_site(parsed_setup["site"])
            site_now = parsed_setup["site"]
            if (site_now.get("syncthing") or {}).get("enabled") or (site_now.get("nfs") or {}).get("enabled"):
                # Root applies it (Syncthing identity, folder, NFS mounts): see request_root_action.
                request_root_action("site")
            result = add_devices(parsed_setup["devices"], parsed_setup["settings"].get("default_snmp_community"), dry_run=False)
            setup.mark_completed()
            database.add_audit("setup", "First-run setup completed",
                               f"{len(result['added'])} device(s) added, {len(parsed_setup['settings'])} setting(s)")
            self._send_json(200, {"preview": False, "plan": plan, "devices": result})
            return

        if path == "/api/devices/bulk-add":
            result = add_devices(parse_device_list(payload.get("devices")), _get_str(payload, "community", "", max_len=128) or None,
                                 dry_run=payload.get("dry_run") is True)
            self._send_json(200, result)
            return

        if path == "/api/devices/bulk-delete":
            ids = payload.get("device_ids")
            if not isinstance(ids, list) or not ids or len(ids) > 500 or \
                    not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
                raise RequestError(400, "device_ids must be a list of 1 to 500 device ids")
            deleted = [i for i in dict.fromkeys(ids) if self.user.sees_id(i) and database.delete_device(i)]
            self._send_json(200, {"success": True, "deleted": deleted, "missing": [i for i in ids if i not in deleted]})
            return

        if path == "/api/devices/poll-all":
            device_ids = [d["id"] for d in database.device_profiles() if self.user.sees_id(d["id"])]
            for device_id in device_ids:
                scheduler.poll_now(device_id)
            self._send_json(200, {"success": True, "queued": len(device_ids)})
            return

        if path == "/api/workflows":
            fields = self._checked_workflow(payload)
            wid = database.save_workflow(None, fields)
            database.add_audit("workflow", f"Created workflow {fields['name']}", f"{len(fields['steps'])} steps")
            self._send_json(201, {"success": True, "id": wid})
            return

        match_wf_run = re.fullmatch(r"/api/workflows/(\d+)/run", path)
        if match_wf_run:
            wf = database.get_workflow(int(match_wf_run.group(1)))
            if not wf:
                raise RequestError(404, "Workflow not found")
            # The same rule as saving and scheduled runs: devices, password credentials and Use stored credentials.
            problem = workflow_rights_problem(self.user, wf)
            if problem:
                raise ActionError(403, f"Cannot run {wf['name']}: {problem}")
            blockers = workflows.preflight(wf)
            if blockers:
                # Recorded as an event (notification centre); the run never starts half way.
                raise ActionError(409, "; ".join(b["message"] for b in blockers),
                                  next((b["device_id"] for b in blockers if b["device_id"]), None))
            try:
                run_id = workflows.MANAGER.start(wf, "manual")
            except workflows.WorkflowError as exc:
                raise RequestError(409, str(exc))
            database.add_audit("workflow", f"Ran workflow {wf['name']} manually", f"Run {run_id}")
            self._send_json(200, {"success": True, "run_id": run_id})
            return

        match_wf_cancel = re.fullmatch(r"/api/workflow-runs/(\d+)/cancel", path)
        if match_wf_cancel:
            run = database.get_workflow_run(int(match_wf_cancel.group(1)))
            if not run or not workflows_in_scope(self.user, [run], "workflow_id"):
                raise RequestError(404, "Run not found")
            if not workflows.MANAGER.cancel(int(match_wf_cancel.group(1))):
                raise RequestError(409, "That run is not in progress")
            database.add_audit("workflow", "Cancelled workflow run", match_wf_cancel.group(1))
            self._send_json(200, {"success": True})
            return

        if path == "/api/template/render":
            # The editors' preview: the client's sample values through the real engine (nothing stored).
            # Typing waits for a pause before each preview, so the limit only stops scripted use.
            if not auth.SESSIONS.allow(self.token, "tpl_preview", TEMPLATE_PREVIEW_LIMIT, TEMPLATE_PREVIEW_WINDOW):
                raise RequestError(429, "Too many previews in a short time. Please wait a moment.")
            text = _get_str(payload, "text", "", max_len=4000)
            raw = payload.get("values") if isinstance(payload.get("values"), dict) else {}
            values = {str(k)[:64]: (v if isinstance(v, (int, float)) and not isinstance(v, bool) else str(v)[:4000])
                      for k, v in list(raw.items())[:200] if v is not None}
            try:
                out = tpl.render(text, values, known=set(values), strict=True)
            except tpl.TemplateLimit:
                raise RequestError(400, "This template makes the text too long to build. "
                                        "Shorten it or use fewer replace or join filters.")
            self._send_json(200, {"text": out})
            return

        if path == "/api/notify/bot-preview":
            self._send_json(200, {"text": bot_preview(payload)})
            return

        if path == "/api/notify/bot-commands":
            self._send_json(200, save_bot_commands(payload, self.user.username))
            return

        if path in ("/api/notify/test", "/api/notify/find-chat"):
            # The wizard sends the token it was just given; Settings uses the stored one.
            stored = database.get_all_settings()
            token = _get_str(payload, "token", "", max_len=100) or stored.get("telegram_token", "")
            if not re.fullmatch(r"\d{5,12}:[A-Za-z0-9_-]{30,64}", token):
                raise RequestError(400, "That does not look like a bot token from @BotFather (digits, a colon, then letters)")
            try:
                if path == "/api/notify/find-chat":
                    # Two presses: the first starts a search, and only a message sent after it counts, so a
                    # stranger who messaged the bot earlier is never picked. The page shows the chat's name
                    # and asks before using it. While the bot polls for commands, a second getUpdates would
                    # cut it off: the bot keeps the chat during the search.
                    bot = notify.bot_name(token)
                    if not BOT.finding():
                        BOT.start_find()
                        self._send_json(200, {"searching": True, "seconds": telebot.FIND_SECONDS, "bot": bot})
                    else:
                        chat = BOT.last_chat if telebot.enabled(stored) and BOT.thread else telebot.find_chat_since(token, BOT.find_since)
                        if not chat:
                            raise RequestError(404, f"No message to @{bot} yet. Send it any message in Telegram, then press Find my chat again.")
                        BOT.end_find()
                        self._send_json(200, {"chat_id": chat["id"], "chat_name": chat["name"], "bot": bot})
                else:
                    chat_id = _get_str(payload, "chat_id", "", max_len=24) or stored.get("telegram_chat_id", "")
                    if not re.fullmatch(r"-?\d{1,20}", chat_id):
                        raise RequestError(400, "Find your chat first")
                    silent = payload.get("silent") is True
                    text = ("Silent test from Homelab Monitor. This one should arrive without a sound."
                            if silent else "Test message from Homelab Monitor. Notifications are working.")
                    notify.send(token, chat_id, text, silent=silent)
                    # The silent window is judged by the monitor's clock: show it, so a wrong time zone is visible.
                    now = datetime.now()
                    self._send_json(200, {"success": True, "silent": silent, "clock": now.strftime("%H:%M"),
                                          "silent_now": notify.is_silent(stored, "warning", "default", now)})
            except notify.TelegramError as exc:
                raise RequestError(502, str(exc))
            database.add_audit("notify", "Telegram " + ("chat lookup" if path.endswith("chat") else "test message"), "")
            return

        if path == "/api/map/objects":
            label = _get_str(payload, "label", max_len=64)
            kind = _get_str(payload, "kind", "other", max_len=16)
            if not label or kind not in database.MAP_OBJECT_KINDS:
                raise RequestError(400, f"label and kind ({', '.join(database.MAP_OBJECT_KINDS)}) are required")
            object_id = database.add_map_object(label, kind)
            database.add_audit("map", f"Added map object {label}", kind)
            self._send_json(201, {"success": True, "key": f"o:{object_id}"})
            return

        if path == "/api/map/links":
            a, b = _get_str(payload, "a", max_len=24), _get_str(payload, "b", max_len=24)
            action = _get_str(payload, "action", max_len=8)
            keys = {n["key"] for n in map_view()["nodes"]}
            if a == b or a not in keys or b not in keys or action not in ("add", "hide", "remove"):
                raise RequestError(400, "a and b must be two different map nodes; action is add, hide or remove")
            if action == "remove":
                database.delete_map_link(a, b)
            else:
                database.set_map_link(a, b, hidden=action == "hide")
            database.add_audit("map", f"Map link {action}", f"{a} - {b}")
            self._send_json(200, {"success": True})
            return

        if path == "/api/custom-oids":
            try:
                d = customoids.parse(payload, [p["profile_id"] for p in poller.load_hardware_profiles()],
                                     [x["id"] for x in database.device_profiles()])
            except ValueError as exc:
                raise RequestError(400, str(exc))
            if d["scope"] == "device" and not self.user.sees_id(int(d["target"])):
                raise RequestError(404, "Device not found")
            if d["scope"] == "template" and self.user.scope is not None:
                raise RequestError(403, "Template-wide OIDs need access to every device")
            def_id = customoids.add(d)
            database.add_audit("snmp", f"Custom OID {d['label']} added ({d['scope']} {d['target']})", d["oid"])
            if d["scope"] == "device":
                scheduler.poll_now(int(d["target"]))
            self._send_json(201, {"success": True, "id": def_id})
            return

        match_check = re.fullmatch(r"/api/devices/(\d+)/snmp-check", path)
        if match_check:
            device = self._require_device(int(match_check.group(1)))
            if device.get("service_port") or not profile_uses_snmp(device.get("profile_id")):
                raise RequestError(400, "This device is not read over SNMP")
            self._send_json(200, snmp_check(device))
            return

        match_fix = re.fullmatch(r"/api/devices/(\d+)/fix-snmp", path)
        if match_fix:
            device = database.get_device(int(match_fix.group(1)))
            if not device:
                raise RequestError(404, "Device not found")
            # Linux hosts, and any device that does not answer SNMP yet (template not detectable without it).
            if device["profile_id"] != "linux_host" and device.get("snmp_status") == "ok":
                raise RequestError(400, "Fix SNMP applies to Linux hosts, or to devices whose SNMP does not answer")
            check_credential_use(self.user, _get_int(payload, "credential_id", None, 1, 2**31))
            self._send_json(200, fix_snmp(device, payload))
            return

        match_sshset = re.fullmatch(r"/api/devices/(\d+)/ssh-setup", path)
        if match_sshset:
            # The command to paste on a host whose SSH does not let the monitor in yet (Fix SNMP, Host actions).
            device = self._require_device(int(match_sshset.group(1)))
            cred_id = _get_int(payload, "credential_id", None, 1, 2**31)
            # Nothing logs in to a host here, so Use stored credentials is not needed; a password still needs Manage credentials.
            check_password_credential(self.user, cred_id)
            # Public parts only: the script needs the user name and the public key, never a secret.
            cred = database.get_credential_public(cred_id) if cred_id else None
            no_key = "This SSH key has no public key saved, so the commands cannot be built. Add the key again or generate a new one."
            public_key = None
            if cred and cred["cred_type"] == "ssh_key":
                public_key = cred.get("public_key") or None
                if not public_key:
                    # A key saved before public keys were kept: work it out once from the private key.
                    secret = database.get_credential_secret(cred_id)
                    public_key = ssh_runner.public_key_of(secret["secret"]) if secret and secret.get("secret") else None
                if not public_key:
                    raise RequestError(409, no_key)
            monitor_ip = snmpfix.source_address(device["ip_address"]) or monitor_address()
            if not monitor_ip:
                raise RequestError(409, "Could not work out this monitor's address towards the host")
            try:
                script = snmpfix.ssh_setup_script(monitor_ip, (cred or {}).get("username") or "root", public_key)
            except ValueError:
                if public_key:
                    raise RequestError(409, no_key)
                raise
            database.add_audit("ssh", f"SSH setup commands copied for {device['hostname']}", f"Monitor address {monitor_ip}")
            self._send_json(200, {"script": script, "monitor_ip": monitor_ip, "kind": "key" if public_key else "password"})
            return

        match_hact = re.fullmatch(r"/api/devices/(\d+)/host-actions/([a-z_]{1,40})", path)
        if match_hact:
            device = self._require_device(int(match_hact.group(1)))
            self._send_json(200, host_action(self.user, device, match_hact.group(2), payload))
            return

        match_watch = re.fullmatch(r"/api/devices/(\d+)/watches", path)
        if match_watch:
            device = database.get_device(int(match_watch.group(1)))
            if not device:
                raise RequestError(404, "Device not found")
            kind = _get_str(payload, "kind", max_len=10)
            name = _get_str(payload, "name", max_len=128)
            watched = payload.get("watched")
            if kind not in database.WATCH_KINDS or not name or not isinstance(watched, bool):
                raise RequestError(400, "kind (process or service), name and a boolean watched are required")
            if database.set_watch(device["id"], kind, name, watched):
                database.add_event(device["id"], "info", "config",
                                   f"{'Watching' if watched else 'Stopped watching'} {kind} {name}")
            self._send_json(200, {"success": True, "watches": database.list_watches(device["id"])})
            return

        match_poll = re.fullmatch(r"/api/devices/(\d+)/poll", path)
        if match_poll:
            device = database.get_device(int(match_poll.group(1)))
            if not device:
                raise RequestError(404, "Device not found")
            result = poller.poll_single_device(device)
            self._send_json(200, {"success": True, "result": result})
            return

        match_live = re.fullmatch(r"/api/devices/(\d+)/live", path)
        if match_live:
            device_id = int(match_live.group(1))
            if not database.get_device(device_id):
                raise RequestError(404, "Device not found")
            since = payload.get("since", 0)
            if not isinstance(since, (int, float)) or isinstance(since, bool):
                raise RequestError(400, "since must be a timestamp")
            settings = database.get_all_settings()
            granted = scheduler.live.touch(device_id, get_setting(settings, "live_max_devices"))
            self._send_json(200, {"granted": granted, **scheduler.live.since(device_id, float(since))})
            return

        if path == "/api/devices":
            fields = parse_device_payload(payload)
            if fields["snmp_community"] is None:
                fields["snmp_community"] = database.get_all_settings().get("default_snmp_community") or "public"
            extra = fields.pop("_extra", None)
            service = fields.pop("_service", None)
            tags = fields.pop("_tags", None)
            snmp = finish_snmp_v3(fields.pop("_snmp", None), None)
            self._check_upstream(extra, None)
            device_id = database.add_device(**fields)
            if snmp:
                database.set_device_snmp(device_id, snmp["version"], snmp["v3"])
            if extra:
                database.set_device_overrides(device_id, **extra)
            if tags:
                taxonomy.set_device_tags(device_id, tags)
            if service:
                database.set_service_check(device_id, **service)
            database.add_event(device_id, "info", "config", f"Device added to monitoring ({fields['ip_address']}, profile {fields['profile_id']})")
            scheduler.poll_now(device_id)
            self._send_json(201, {"success": True, "device_id": device_id})
            return

        if path == "/api/devices/probe":
            if payload.get("service_kind") == "http":
                # Web check test: the same fetch the poller makes.
                fields = parse_device_payload(dict(payload, profile_id=SERVICE_PROFILE))
                svc = fields["_service"]
                r = poller.http_check(svc["service_url"], svc["service_expect"], 8.0)
                alive, ping_ms = poller.ping_host(fields["ip_address"], 2.0)
                self._send_json(200, {"service": True, "web": True, "ping": alive, "ping_ms": ping_ms, "open": r["up"],
                                      "status": r["status"], "connect_ms": r["ms"], "error": r["error"], "redirect": r.get("redirect"),
                                      "port": fields["service_port"]})
                return
            ip_address = validate_target_address(_get_str(payload, "ip_address", max_len=253))
            if payload.get("mode") == "ping":
                # Ping-only device test: three echoes, nothing else.
                replies = [poller.ping_host(ip_address, 2.0) for _ in range(3)]
                times = [ms for up, ms in replies if up and ms is not None]
                self._send_json(200, {"ping": bool(times), "replies": len(times), "sent": 3,
                                      "ping_ms": round(sum(times) / len(times), 2) if times else None})
                return
            service_port = _get_int(payload, "service_port", None, 1, 65535)
            if service_port:
                # Port check test: ping and one TCP connection, no SNMP.
                alive, ping_ms = poller.ping_host(ip_address, 2.0)
                open_, connect_ms = poller.tcp_check(ip_address, service_port, 3.0)
                self._send_json(200, {"service": True, "ping": alive, "ping_ms": ping_ms, "port": service_port,
                                      "open": open_, "connect_ms": connect_ms})
                return
            community = (_get_str(payload, "community", "", max_len=128)
                         or database.get_all_settings().get("default_snmp_community") or "public")
            port = _get_int(payload, "port", 161, 1, 65535)
            snmp = parse_snmp_v3(payload)
            if snmp and snmp["version"] == "v3":
                # Test connection with v3: blank passwords come from the device being edited.
                device_id = _get_int(payload, "device_id", None, 1, 2 ** 31 - 1)
                before = database.get_device(device_id) if device_id else None
                if before is not None and not self.user.sees_id(device_id):
                    before = None
                v3 = finish_snmp_v3(snmp, before)["v3"]
                target = poller.snmp_target({"snmp_version": "v3", "snmp_v3": v3})
                import snmpv3
                snmpv3.forget(ip_address, port)        # a fresh discovery, as the first poll makes
                result = poller.probe_device(ip_address, community=target, port=port)
                if result.get("success") and not result.get("snmp_active"):
                    result["snmp_error"] = snmpv3.last_error(ip_address) or "No answer to SNMPv3"
                self._send_json(200, result)
                return
            self._send_json(200, poller.probe_device(ip_address, community=community, port=port))
            return

        if path == "/api/proxmox/fingerprint":
            # Shown for the administrator to compare with the Proxmox GUI before pinning; nothing is stored.
            try:
                fp = proxmox.fetch_fingerprint(_get_str(payload, "url", max_len=200))
            except proxmox.ProxmoxError as exc:
                raise RequestError(400, str(exc))
            self._send_json(200, {"fingerprint": fp})
            return

        if path == "/api/dashboards":
            made = create_dashboard(payload.get("title"), payload.get("template") or "")
            database.add_audit("dashboard", f"Dashboard {made['title']} added", str(payload.get("template") or "blank")[:40])
            self._send_json(201, made)
            return

        if path == "/api/maintenance":
            now = time.time()
            try:
                minutes = _get_int(payload, "minutes", None, 1, 14 * 24 * 60)
                start = float(payload.get("start") or now)
                end = start + minutes * 60 if minutes else float(payload.get("end") or 0)
                scope, target = _get_str(payload, "scope", max_len=10), _get_str(payload, "target", max_len=120)
                if scope in maintenance.SCOPES and not maintenance_in_scope(self.user, scope, target):
                    raise RequestError(403, "That window covers devices outside your device access.")
                w = maintenance.add(scope, target, start, end, _get_str(payload, "note", max_len=200), self.user.username, now)
            except (maintenance.MaintenanceError, TypeError, ValueError) as exc:
                raise RequestError(400, str(exc))
            database.add_audit("maintenance", f"Maintenance window for {w['scope']} {w['target']}".strip(),
                               f"{datetime.fromtimestamp(w['start']):%Y-%m-%d %H:%M} to {datetime.fromtimestamp(w['end']):%Y-%m-%d %H:%M}"
                               f"{'; ' + w['note'] if w['note'] else ''}; by {self.user.username}")
            self._send_json(201, {"success": True, "window": w, "windows": maintenance_view(self.user, maintenance.windows())})
            return
        match_mw = re.fullmatch(r"/api/maintenance/(\d+)/end", path)
        if match_mw:
            # Outside the user's device access a window does not exist.
            known = next((x for x in maintenance.windows() if x["id"] == int(match_mw.group(1))), None)
            if not known or not maintenance_in_scope(self.user, known["scope"], known["target"]):
                raise RequestError(404, "No such maintenance window")
            w = maintenance.end(int(match_mw.group(1)))
            if not w:
                raise RequestError(404, "No such maintenance window")
            database.add_audit("maintenance", f"Ended maintenance window for {w['scope']} {w['target']}".strip(), f"By {self.user.username}")
            self._send_json(200, {"success": True, "windows": maintenance_view(self.user, maintenance.windows())})
            return
        if path == "/api/proxmox/guest":
            node, kind = _get_str(payload, "node", max_len=64), _get_str(payload, "type", max_len=8)
            vmid, action = _get_int(payload, "vmid", None, 1, 999999999), _get_str(payload, "action", max_len=12)
            if vmid is None:
                raise RequestError(400, "vmid is required")
            if self.user.scope is not None:
                mapped = next((x.get("device_id") for x in proxmox.layout().get("guests", [])
                               if x.get("node") == node and x.get("vmid") == vmid), None)
                if not mapped or not self.user.sees_id(mapped):
                    raise RequestError(404, "Guest not found")
            try:
                proxmox.guest_action(node, kind, vmid, action)
            except proxmox.ProxmoxError as exc:
                raise RequestError(400, str(exc))
            g = next((x for x in proxmox.layout().get("guests", []) if x["node"] == node and x["vmid"] == vmid), {})
            text = f"Proxmox: {action} {g.get('name') or 'guest'} ({vmid}) on {node}"
            database.add_audit("device", text, f"By {self.user.username}")
            dev = g.get("device_id") or next((n.get("device_id") for n in proxmox.layout().get("nodes", []) if n["node"] == node), None)
            database.add_event(dev, "info", "action", f"{text}, by {self.user.username}")
            self._send_json(200, {"success": True})
            return
        if path == "/api/wifi/reconnect":
            mac = _get_str(payload, "mac", max_len=17).lower()
            row = next((c for c in wifi_view()["clients"] if c.get("mac") == mac), None)
            if not row:
                raise RequestError(404, "That device is not on a monitored access point")
            try:
                unifi.reconnect(mac)
            except unifi.UnifiError as exc:
                raise RequestError(400, str(exc))
            text = f"Reconnected {row.get('name') or mac} ({mac}) on {row['ap_name']}"
            database.add_event(row["ap_id"], "info", "action", f"{text}, by {self.user.username}")
            database.add_audit("device", text, f"By {self.user.username}")
            self._send_json(200, {"success": True})
            return
        if path == "/api/pihole/blocking":
            enabled = payload.get("enabled")
            if not isinstance(enabled, bool):
                raise RequestError(400, "enabled is true or false")
            minutes = _get_int(payload, "minutes", None, 1, 24 * 60)
            try:
                pihole.set_blocking(enabled, minutes * 60 if minutes else None)
                pihole.run(database.list_devices())
            except pihole.PiholeError as exc:
                raise RequestError(400, str(exc))
            text = "Pi-hole blocking switched back on" if enabled else f"Pi-hole blocking paused for {minutes} minutes"
            database.add_audit("system", text, f"By {self.user.username}")
            dev = pihole.pihole_device(pihole.load_config(), database.list_devices())
            database.add_event(dev["id"] if dev else None, "info", "action", f"{text}, by {self.user.username}")
            self._send_json(200, {"success": True, "pihole": pihole.view(database.list_devices())})
            return
        if path == "/api/inventory":
            try:
                mac = inventory.add(str(payload.get("mac") or ""), payload)
            except inventory.InventoryError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("device", f"Added {mac} to the inventory by hand, as known", f"By {self.user.username}")
            self._send_json(200, {"success": True, "mac": mac})
            return
        if path == "/api/inventory/known":
            n = inventory.mark_all_known()
            database.add_audit("device", f"Marked {n} new address(es) known in the inventory", f"By {self.user.username}")
            self._send_json(200, {"success": True, "changed": n})
            return
        if path in ("/api/pihole/fingerprint", "/api/unifi/fingerprint"):
            try:
                fp = lanhttp.fetch_fingerprint(_get_str(payload, "url", max_len=200))
            except lanhttp.LanError as exc:
                raise RequestError(400, str(exc))
            self._send_json(200, {"fingerprint": fp})
            return
        if path == "/api/pihole/test":
            cfg = self._pihole_payload(payload)
            try:
                self._send_json(200, {"success": True, "result": pihole.test(cfg)})
            except (pihole.PiholeError, lanhttp.LanError) as exc:
                raise RequestError(400, str(exc))
            return
        if path == "/api/unifi/test":
            cfg = self._unifi_payload(payload)
            try:
                self._send_json(200, {"success": True, "result": unifi.test(cfg)})
            except (unifi.UnifiError, lanhttp.LanError) as exc:
                raise RequestError(400, str(exc))
            return
        if path == "/api/changes/seen":
            changelog.mark_seen(self.user.username)
            self._send_json(200, {"success": True})
            return
        if path == "/api/tls/dismiss":
            # "Keep HTTP for now" on the question after an upgrade: changes nothing else, so no password.
            tls.dismiss_prompt()
            database.add_audit("system", "Kept plain HTTP (HTTPS question answered)", f"By {self.user.username}")
            self._send_json(200, {"success": True})
            return
        if path == "/api/proxmox/test":
            cfg = self._proxmox_payload(payload)
            try:
                seen = proxmox.check(proxmox.Client(cfg))
            except proxmox.ProxmoxError as exc:
                raise RequestError(400, str(exc))
            self._send_json(200, dict(seen, success=True))
            return

        if path == "/api/settings":
            updates = parse_settings_payload(payload)
            current = database.get_all_settings()
            changed = [k for k, v in updates.items() if current.get(k) != v]
            denied = [SETTINGS[k]["label"] for k in changed
                      if not self.user.can(rbac.settings_permission(SETTINGS[k]["section"]))]
            if denied:
                raise RequestError(403, "Your account cannot change: " + ", ".join(denied))
            if any(SETTINGS[k]["type"] == "secret" for k in changed):
                self._require_tier(rbac.SECRET_SETTING_TIER)
            if "require_2fa" in changed and updates["require_2fa"] != "off" and two_factor_rule() == "off":
                # Never a rule nobody can meet: the person turning it on and at least one active
                # administrator already have 2FA, so someone can always still get in.
                self._require_tier(3, path)
                if not database.get_totp(self.user.username)["enabled"]:
                    raise RequestError(409, "Turn on two-factor authentication for your own account first (Settings, "
                                            "Account), so you cannot be locked out.")
                if not any(u.get("role") == "admin" and not u.get("disabled") and u.get("totp_enabled")
                           for u in database.list_users()):
                    raise RequestError(409, "At least one administrator must have two-factor authentication on first.")
            for key in changed:
                database.update_setting(key, updates[key])
            if changed:
                database.add_audit("settings", f"Changed {len(changed)} setting(s)",
                                   ", ".join(SETTINGS[k]["label"] for k in changed))
            for key, what in (("audit_retention_days", "Audit log"), ("event_retention_days", "Events")):
                if key in changed:
                    old = get_setting(current, key)
                    database.add_audit("settings", f"{what} retention changed from {old} to {updates[key]} days")
                    if key == "audit_retention_days":
                        security_alert("retention", days=updates[key], old=old)
            self._send_json(200, {"success": True, "changed": changed})
            return

        raise RequestError(404, "Endpoint not found")

    @staticmethod
    def _avail_range(q: Dict[str, List[str]]) -> Tuple[str, int]:
        """?range=24h|7d|30d|90d (default 24h) and tz=<minutes east of UTC> from the browser."""
        key = q.get("range", ["24h"])[0]
        if key not in availability.RANGE_BARS:
            raise RequestError(400, "range is 24h, 7d, 30d or 90d")
        try:
            tz = int(q.get("tz", ["0"])[0])
        except ValueError:
            raise RequestError(400, "tz is minutes east of UTC")
        if not -900 <= tz <= 900:
            raise RequestError(400, "tz is minutes east of UTC")
        return key, tz

    @staticmethod
    def _stored_secret(stored: Dict[str, str], cfg: Dict[str, str], keys: Tuple[str, ...], ask: str) -> str:
        """The stored secret, only for the stored address, fingerprint and account. A test or save
        aimed anywhere else must bring its own secret, so the stored one never leaves for a new place."""
        def norm(k: str, v: str) -> str:
            v = (v or "").strip()
            return v.rstrip("/").lower() if k == "url" else (
                "".join(ch for ch in v.lower() if ch in "0123456789abcdef") if k == "fingerprint" else v)
        if not stored.get("secret"):
            return ""
        if all(norm(k, stored.get(k, "")) == norm(k, cfg.get(k, "")) for k in keys):
            return stored["secret"]
        raise RequestError(400, ask)

    def _pihole_payload(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """Pi-hole settings from a request; an empty secret means "keep the stored one"."""
        stored = pihole.load_config()
        dev = payload.get("device_id")
        if dev not in (None, "") and (isinstance(dev, bool) or not isinstance(dev, int) or not database.get_device(dev)):
            raise RequestError(400, "Choose one of the monitored devices")
        cfg = {"url": _get_str(payload, "url", max_len=200).rstrip("/"), "secret": _get_str(payload, "secret", max_len=300),
               "device_id": str(dev) if dev else "", "test_name": _get_str(payload, "test_name", max_len=200) or pihole.DEFAULT_TEST_NAME}
        try:
            lanhttp.parse_url(cfg["url"], "the Pi-hole")
            cfg["fingerprint"] = lanhttp.normalise_fingerprint(_get_str(payload, "fingerprint", max_len=200))
        except lanhttp.LanError as exc:
            raise RequestError(400, str(exc))
        if not cfg["secret"]:
            cfg["secret"] = self._stored_secret(stored, cfg, ("url", "fingerprint"),
                                                "Enter the password again for a new address or fingerprint")
        if not cfg["secret"]:
            raise RequestError(400, "Enter the app password (Pi-hole 6) or the API token (Pi-hole 5)")
        return cfg

    def _unifi_payload(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """UniFi settings from a request; an empty password means "keep the stored one"."""
        stored = unifi.load_config()
        cfg = {"url": _get_str(payload, "url", max_len=200).rstrip("/"), "username": _get_str(payload, "username", max_len=100),
               "secret": _get_str(payload, "secret", max_len=300), "site": _get_str(payload, "site", max_len=40) or "default"}
        try:
            scheme, _, _ = lanhttp.parse_url(cfg["url"], "the UniFi gateway")
            cfg["fingerprint"] = lanhttp.normalise_fingerprint(_get_str(payload, "fingerprint", max_len=200))
        except lanhttp.LanError as exc:
            raise RequestError(400, str(exc))
        if not cfg["secret"] and cfg["username"]:
            cfg["secret"] = self._stored_secret(stored, cfg, ("url", "fingerprint", "username"),
                                                "Enter the password again for a new address, fingerprint or username")
        if scheme != "https":
            raise RequestError(400, "UniFi only answers over https://, for example https://192.168.1.1")
        if not cfg["username"] or not cfg["secret"]:
            raise RequestError(400, "Enter the username and password of the local UniFi account")
        return cfg

    def _proxmox_payload(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """Proxmox settings from a request; an empty secret means "keep the stored one"."""
        stored = proxmox.load_config()
        cfg = {"url": _get_str(payload, "url", max_len=200).rstrip("/"),
               "token_id": _get_str(payload, "token_id", max_len=200),
               "secret": _get_str(payload, "secret", max_len=200)}
        try:
            proxmox.parse_url(cfg["url"])
            cfg["fingerprint"] = proxmox.normalise_fingerprint(_get_str(payload, "fingerprint", max_len=200))
        except proxmox.ProxmoxError as exc:
            raise RequestError(400, str(exc))
        if not cfg["secret"] and cfg["token_id"]:
            cfg["secret"] = self._stored_secret(stored, cfg, ("url", "fingerprint", "token_id"),
                                                "Enter the token secret again for a new address, fingerprint or token ID")
        if not cfg["token_id"] or not cfg["secret"]:
            raise RequestError(400, "Enter the token ID and its secret")
        return cfg

    def _put(self, parsed) -> None:
        path = parsed.path.rstrip("/")
        if path == "/api/inventory/quiet-ssids":
            try:
                saved = inventory.set_quiet_ssids(self._read_json().get("ssids"))
            except inventory.InventoryError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("device", "Quiet Wi-Fi networks in the inventory: " + (", ".join(saved) or "none"),
                               f"By {self.user.username}")
            self._send_json(200, {"success": True, "ssids": saved})
            return
        if path == "/api/inventory/wifi-networks":
            before = inventory.wifi_net_alerts()
            try:
                saved = inventory.set_wifi_net_alerts(self._read_json().get("weak"))
            except inventory.InventoryError as exc:
                raise RequestError(400, str(exc))
            if saved != before:
                said = ", ".join(f"{k} {'never reported' if v == 'off' else f'below {v} dBm'}" for k, v in sorted(saved.items())) or "none"
                database.add_audit("device", f"Weak Wi-Fi rules per network: {said}", f"By {self.user.username}")
            self._send_json(200, {"success": True, "weak": saved})
            return
        match_inv = re.fullmatch(r"/api/inventory/([0-9a-fA-F:.-]{12,17})", path)
        if match_inv:
            body = self._read_json()
            mac = inventory.normalise_mac(match_inv.group(1)) or ""
            before = inventory.wifi_alerts().get(mac, "")
            try:
                inventory.edit(match_inv.group(1), body)
            except inventory.InventoryError as exc:
                raise RequestError(400, str(exc))
            after = inventory.wifi_alerts().get(mac, "")
            if after != before:
                said = {"": "reported as usual", "off": "never reported"}.get(after, f"reported below {after} dBm")
                database.add_audit("device", f"Weak Wi-Fi for {mac}: {said}", f"By {self.user.username}")
            self._send_json(200, {"success": True})
            return
        if path == "/api/proxmox/actions":
            body = self._read_json()
            try:
                if body.get("remove") is True:
                    proxmox.save_action_token("", "")
                    note = "Removed the Proxmox action token"
                else:
                    tid = _get_str(body, "token_id", max_len=200)
                    secret = _get_str(body, "secret", max_len=200) or None
                    if not secret and not proxmox.action_config()["secret"]:
                        raise RequestError(400, "Enter the action token's secret")
                    proxmox.save_action_token(tid, secret)
                    note = f"Saved the Proxmox action token {tid.split('!')[0]}"
            except proxmox.ProxmoxError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("proxmox", note, f"By {self.user.username}")
            self._send_json(200, {"success": True, "actions": proxmox.actions_ready()})
            return
        if path == "/api/unifi/never":
            try:
                unifi.set_never_list(_get_str(self._read_json(), "never", max_len=4000))
            except unifi.UnifiError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("system", "Changed the never-reconnect list", f"By {self.user.username}")
            self._send_json(200, {"success": True, "never": unifi.never_list()})
            return
        if path in ("/api/pihole/config", "/api/unifi/config"):
            which = "Pi-hole" if "pihole" in path else "UniFi"
            mod = pihole if which == "Pi-hole" else unifi
            payload = self._read_json()
            if set(payload) == {"enabled"} and isinstance(payload["enabled"], bool):
                mod.set_enabled(payload["enabled"])
                database.add_audit("system", f"{which} switched {'on' if payload['enabled'] else 'off'}", f"By {self.user.username}")
                self._send_json(200, {"success": True, "config": mod.public_config()})
                return
            if payload.get("disconnect") is True:
                if which == "Pi-hole":
                    pihole.save_config("", "", "", None, "")
                else:
                    unifi.save_config("", "", "", "", "")
                database.add_audit("system", f"Removed the {which} connection", f"By {self.user.username}")
                self._send_json(200, {"success": True, "config": mod.public_config()})
                return
            new_secret = _get_str(payload, "secret", max_len=300) or None
            try:
                if which == "Pi-hole":
                    cfg = self._pihole_payload(payload)
                    pihole.save_config(cfg["url"], new_secret, cfg["fingerprint"],
                                       int(cfg["device_id"]) if cfg["device_id"] else None, cfg["test_name"])
                else:
                    cfg = self._unifi_payload(payload)
                    unifi.save_config(cfg["url"], cfg["username"], new_secret, cfg["fingerprint"], cfg["site"])
                mod.set_enabled(True)
            except (pihole.PiholeError, unifi.UnifiError) as exc:
                raise RequestError(400, str(exc))
            database.add_audit("system", f"Saved the {which} connection", f"{cfg['url']}; by {self.user.username}")
            self._send_json(200, {"success": True, "config": mod.public_config()})
            return
        if path == "/api/tls":
            payload = self._read_json()
            choice = payload.get("mode")
            try:
                if choice == "off":
                    tls.set_off()
                    note, detail = "Switched HTTPS off", ""
                elif choice == "self-signed":
                    names = tls.clean_names(_get_str(payload, "extra_names", max_len=1200))
                    tls.set_self_signed(names)
                    note, detail = "Switched to HTTPS with a self-signed certificate", ", ".join(names)
                elif choice == "own":
                    info = tls.set_own(_get_str(payload, "certificate", max_len=tls.MAX_PEM),
                                       _get_str(payload, "key", max_len=tls.MAX_PEM))
                    note, detail = ("Switched to HTTPS with an uploaded certificate",
                                    f"{info['subject']}, issued by {info['issuer']}, expires {datetime.fromtimestamp(info['not_after']):%Y-%m-%d}")
                else:
                    raise RequestError(400, "mode is off, self-signed or own")
            except tls.TlsError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("system", note, f"{detail}; by {self.user.username}" if detail else f"By {self.user.username}")
            self._send_json(200, {"success": True, "tls": tls.public_state()})
            return
        if path == "/api/proxmox/config":
            payload = self._read_json()
            if set(payload) == {"enabled"} and isinstance(payload["enabled"], bool):
                # The on / off switch alone: the stored connection is kept either way.
                proxmox.set_enabled(payload["enabled"])
                database.add_audit("proxmox", f"Proxmox dashboard switched {'on' if payload['enabled'] else 'off'}",
                                   f"By {self.user.username}")
                self._send_json(200, {"success": True, "config": proxmox.public_config()})
                return
            if payload.get("disconnect") is True:
                proxmox.save_config("", "", "", "")
                database.add_audit("proxmox", "Removed the Proxmox connection", f"By {self.user.username}")
                self._send_json(200, {"success": True, "config": proxmox.public_config()})
                return
            cfg = self._proxmox_payload(payload)
            before = proxmox.load_config()
            try:
                proxmox.save_config(cfg["url"], cfg["token_id"], _get_str(payload, "secret", max_len=200) or None, cfg["fingerprint"])
                proxmox.set_enabled(True)
            except proxmox.ProxmoxError as exc:
                raise RequestError(400, str(exc))
            if proxmox.action_config()["secret"] and (before["url"].rstrip("/").lower(), before["fingerprint"]) != \
                    (cfg["url"].rstrip("/").lower(), cfg["fingerprint"]):
                # The action token would otherwise go to the new address with the next start or stop.
                proxmox.save_action_token("", "")
                database.add_audit("proxmox", "Removed the Proxmox action token", "The Proxmox address changed; add it again")
            database.add_audit("proxmox", "Saved the Proxmox connection",
                               f"{cfg['url']} as {cfg['token_id'].split('!')[0]}; by {self.user.username}")
            self._send_json(200, {"success": True, "config": proxmox.public_config()})
            return
        if path == "/api/taxonomy":
            body = self._read_json()
            kind, action = body.get("kind"), body.get("action")
            try:
                if kind == "group" and action == "add":
                    gid = taxonomy.add_group(body.get("name"))
                    note = f"Added group {body.get('name')}"
                elif kind == "group" and action == "rename":
                    taxonomy.rename_group(str(body.get("id") or ""), body.get("name"))
                    note = f"Renamed group {body.get('id')} to {body.get('name')}"
                elif kind == "group" and action == "delete":
                    moved = taxonomy.delete_group(str(body.get("id") or ""))
                    note = f"Deleted group {body.get('id')} ({moved} devices back to their template's group)"
                elif kind == "group" and action == "order":
                    taxonomy.order_groups(body.get("ids"))
                    note = "Reordered the groups"
                elif kind == "tag" and action == "add":
                    taxonomy.add_tag(body.get("name"), str(body.get("colour") or ""), str(body.get("description") or ""))
                    note = f"Added tag {body.get('name')}"
                elif kind == "tag" and action == "edit":
                    taxonomy.edit_tag(str(body.get("name") or ""), body.get("colour"), body.get("description"))
                    note = f"Changed tag {body.get('name')}"
                elif kind == "tag" and action == "rename":
                    taxonomy.rename_tag(str(body.get("name") or ""), body.get("new_name"))
                    note = f"Renamed tag {body.get('name')} to {body.get('new_name')} (devices and alert rules)"
                elif kind == "tag" and action == "delete":
                    gone = taxonomy.delete_tag(str(body.get("name") or ""))
                    note = f"Deleted tag {body.get('name')} (from {gone['devices']} devices, {gone['rules']} alert settings)"
                elif kind == "tag" and action == "order":
                    taxonomy.order_tags(body.get("names"))
                    note = "Reordered the tags"
                else:
                    raise RequestError(400, "kind is group or tag; action add, rename, delete, order (tags also edit)")
            except taxonomy.TaxonomyError as exc:
                raise RequestError(400, str(exc))
            database.add_audit("device", note, f"By {self.user.username}")
            self._send_json(200, dict(taxonomy.summary(), success=True))
            return
        if path == "/api/alert-rules":
            body = self._read_json()
            scope, target, changes = parse_alert_changes(body)
            if scope == "device" and not self.user.sees_id(int(target)):
                raise RequestError(404, "Device not found")
            if scope != "device" and self.user.scope is not None:
                raise RequestError(403, "Rules for all devices and templates need access to every device")
            database.set_alert_overrides(scope, target, changes)
            database.add_audit("alerts", f"Changed {len(changes)} alert rule setting(s) ({scope}{' ' + target if target else ''})",
                               "; ".join(f"{r} {f}={'inherit' if v is None else v}" for r, f, v in changes)[:1000])
            self._send_json(200, alert_rules_view(scope, target))
            return
        match_cred = re.fullmatch(r"/api/credentials/(\d+)", path)
        if match_cred:
            fields = parse_credential_payload(self._read_json(), require_secret=False)
            if not database.update_credential(int(match_cred.group(1)), fields["name"], fields["username"], fields["secret"],
                                              fields["passphrase"], fields["public_key"]):
                raise RequestError(404, "Credential not found")
            database.add_audit("credential", f"Updated credential {fields['name']}",
                               "Secret replaced" if fields["secret"] else "Name or username changed")
            security_alert("cred_changed", name=fields["name"])
            self._send_json(200, {"success": True, "public_key": fields["public_key"]})
            return
        match_wf = re.fullmatch(r"/api/workflows/(\d+)", path)
        if match_wf:
            wid = int(match_wf.group(1))
            wf = database.get_workflow(wid)
            if not wf or not workflows_in_scope(self.user, [wf]):
                raise RequestError(404, "Workflow not found")
            fields = self._checked_workflow(self._read_json())
            database.save_workflow(wid, fields)
            database.add_audit("workflow", f"Updated workflow {fields['name']}", f"{len(fields['steps'])} steps")
            self._send_json(200, {"success": True})
            return

        if path == "/api/map/positions":
            payload = self._read_json()
            positions = payload.get("positions")
            if not isinstance(positions, dict) or len(positions) > 500:
                raise RequestError(400, "positions must be an object of up to 500 nodes")
            clean = {}
            for k, v in positions.items():
                if not _MAP_NODE.fullmatch(str(k)) or not isinstance(v, list) or len(v) != 2 \
                        or not all(is_number(c) and -100000 <= c <= 100000 for c in v):
                    raise RequestError(400, f"Invalid position for {str(k)[:24]}")
                clean[k] = v
            database.save_map_positions(clean, replace=payload.get("replace") is True)
            self._send_json(200, {"success": True})
            return

        if path == "/api/dashboard":
            body = self._read_json()
            name = dashboard_name(body.get("name"))
            current = stored_dashboard(name)
            if current is None:
                raise RequestError(404, "Dashboard not found")
            layout = parse_dashboard_layout(body)
            layout.setdefault("title", current.get("title") or ("Overview" if name == "default" else name))
            database.save_dashboard(layout, name)
            self._send_json(200, {"success": True, "title": layout["title"]})
            return
        match_ov = re.fullmatch(r"/api/devices/(\d+)/overview", path)
        if match_ov:
            # The graphs on the device's Overview tab: a list of graph ids, or null for the default set.
            device_id = int(match_ov.group(1))
            if not database.get_device(device_id):
                raise RequestError(404, "Device not found")
            graphs = self._read_json().get("graphs")
            if graphs is not None and (not isinstance(graphs, list) or len(graphs) > OVERVIEW_MAX
                                       or not all(isinstance(g, str) and _GRAPH_ID.fullmatch(g) for g in graphs)):
                raise RequestError(400, f"graphs is a list of up to {OVERVIEW_MAX} graph ids, or null for the default")
            set_overview_graphs(device_id, list(dict.fromkeys(graphs)) if graphs is not None else None)
            self._send_json(200, {"success": True, "overview_graphs": overview_graphs(device_id)})
            return
        match = re.fullmatch(r"/api/devices/(\d+)", path)
        if not match:
            raise RequestError(404, "Endpoint not found")
        device_id = int(match.group(1))
        fields = parse_device_payload(self._read_json())
        extra = fields.pop("_extra", None)
        service = fields.pop("_service", None)
        tags = fields.pop("_tags", None)
        if extra and extra["upstream_device_id"] == device_id:
            raise RequestError(400, "A device cannot be its own upstream")
        before = database.get_device(device_id)
        snmp = finish_snmp_v3(fields.pop("_snmp", None), before)
        self._check_upstream(extra, before)
        if not database.update_device(device_id=device_id, **fields):
            raise RequestError(404, "Device not found")
        if snmp:
            database.set_device_snmp(device_id, snmp["version"], snmp["v3"])
            if before and (before.get("snmp_version"), before.get("snmp_v3") or {}) != (snmp["version"], snmp["v3"] or {}):
                said = f" (user {snmp['v3']['user']}, {snmp['v3']['level']})" if snmp["v3"] else ""
                database.add_audit("device", f"SNMP settings of {before['hostname']} changed to {snmp['version']}{said}",
                                   f"By {self.user.username}")
        if before and "ip_address" in fields and fields["ip_address"] != before["ip_address"]:
            # Approved host keys belong to the old address: another machine there must be approved anew.
            n = database.forget_host_keys(device_id)
            if n:
                database.add_audit("ssh", f"Forgot the SSH host key of {before['hostname']}",
                                   f"Address changed from {before['ip_address']} to {fields['ip_address']}; by {self.user.username}")
                security_alert("key_forgotten", device=before["hostname"])
        if extra:
            database.set_device_overrides(device_id, **extra)
        if tags is not None:
            try:
                taxonomy.set_device_tags(device_id, tags)
            except taxonomy.TaxonomyError as exc:
                raise RequestError(400, str(exc))
        database.set_service_check(device_id, **(service or {"service_kind": "tcp", "service_url": None, "service_expect": {}}))
        database.add_event(device_id, "info", "config", "Device configuration changed")
        scheduler.poll_now(device_id)
        self._send_json(200, {"success": True})

    def _delete(self, parsed) -> None:
        path = parsed.path.rstrip("/")
        match_dash = re.fullmatch(r"/api/dashboards/([a-z0-9][a-z0-9-]{0,39})", path)
        if match_dash:
            if len(database.list_dashboards()) <= 1:
                raise RequestError(400, "This is the only dashboard: add another before deleting it")
            if not database.delete_dashboard(match_dash.group(1)):
                raise RequestError(404, "Dashboard not found")
            database.add_audit("dashboard", "Dashboard deleted", match_dash.group(1))
            self._send_json(200, {"success": True, "dashboards": dashboards_list()})
            return
        match_inv = re.fullmatch(r"/api/inventory/([0-9a-fA-F:.-]{12,17})", path)
        if match_inv:
            if not inventory.forget(match_inv.group(1)):
                raise RequestError(404, "No such address in the inventory")
            self._send_json(200, {"success": True})
            return
        match_scan = re.fullmatch(r"/api/(?:setup|devices)/scan/([0-9a-f]{32})", path)
        if match_scan:
            # Stop a scan: what it found so far stays in its results.
            job = discovery.SCANNER.get(match_scan.group(1))
            if not job:
                raise RequestError(404, "Scan not found")
            job.stop()
            self._send_json(200, {"success": True})
            return
        match_wf = re.fullmatch(r"/api/workflows/(\d+)", path)
        if match_wf:
            wf = database.get_workflow(int(match_wf.group(1)))
            if wf and not workflows_in_scope(self.user, [wf]):
                wf = None
            if not wf or wf["id"] in workflows.MANAGER.running():
                raise RequestError(404 if not wf else 409, "Workflow not found" if not wf else "Cancel the running workflow first")
            database.delete_workflow(wf["id"])
            database.add_audit("workflow", f"Deleted workflow {wf['name']}", "")
            self._send_json(200, {"success": True})
            return
        match_coid = re.fullmatch(r"/api/custom-oids/(\d+)", path)
        if match_coid:
            defs = {d["id"]: d for d in customoids.all_defs()}
            d = defs.get(int(match_coid.group(1)))
            if not d or (d["scope"] == "device" and not self.user.sees_id(int(d["target"]))) or \
                    (d["scope"] == "template" and self.user.scope is not None):
                raise RequestError(404, "Custom OID not found")
            customoids.remove(d["id"])
            database.add_audit("snmp", f"Custom OID {d['label']} removed ({d['scope']} {d['target']})", d["oid"])
            self._send_json(200, {"success": True})
            return
        match_obj = re.fullmatch(r"/api/map/objects/(\d+)", path)
        if match_obj:
            if not database.delete_map_object(int(match_obj.group(1))):
                raise RequestError(404, "Map object not found")
            self._send_json(200, {"success": True})
            return
        match_hk = re.fullmatch(r"/api/devices/(\d+)/hostkey", path)
        if match_hk:
            known_device = database.get_device(int(match_hk.group(1)))
            n = database.forget_host_keys(int(match_hk.group(1)))
            database.add_audit("ssh", "Forgot SSH host key", f"Device ID: {match_hk.group(1)}, {n} key(s); by {self.user.username}")
            if n:
                security_alert("key_forgotten", device=known_device["hostname"] if known_device else f"device {match_hk.group(1)}")
            self._send_json(200, {"success": True})
            return
        match_cred = re.fullmatch(r"/api/credentials/(\d+)", path)
        if match_cred:
            gone = database.get_credential_public(int(match_cred.group(1)))
            if not database.delete_credential(int(match_cred.group(1))):
                raise RequestError(404, "Credential not found")
            database.add_audit("credential", "Deleted credential", f"Credential ID: {match_cred.group(1)}")
            security_alert("cred_deleted", name=gone["name"] if gone else f"credential {match_cred.group(1)}")
            self._send_json(200, {"success": True})
            return
        match = re.fullmatch(r"/api/devices/(\d+)", path)
        if not match:
            raise RequestError(404, "Endpoint not found")
        if not database.delete_device(int(match.group(1))):
            raise RequestError(404, "Device not found")
        set_overview_graphs(int(match.group(1)), None)
        self._send_json(200, {"success": True})


# --- Interface Grouping, AP Hosts and Dashboard Helpers ---

def interface_group(r: Dict[str, Any], ssid_by_iface: Dict[str, Dict[str, Any]]):
    """Returns (group label, rank) used to group the full interface list.

    VLAN sub-interfaces (eth0.20, switch0.20, br0.20) and the matching
    per-VLAN bridge (br20) share one "VLAN 20" group. SSID interfaces of
    both bands share one group per SSID name.
    """
    kind = r.get("kind")
    label = r.get("label") or ""
    if kind == "port":
        return "Physical ports", 0
    vid = re.search(r"\.(\d+)$", label)
    if kind == "vlan" and vid:
        return f"VLAN {int(vid.group(1))}", 100 + int(vid.group(1))
    bridge_vid = re.fullmatch(r"br(\d+)", label)
    if kind == "bridge" and bridge_vid and int(bridge_vid.group(1)) > 0:
        return f"VLAN {int(bridge_vid.group(1))}", 100 + int(bridge_vid.group(1))
    if kind == "bridge":
        return "Bridges (untagged LAN)", 5000
    if kind == "radio":
        return "Radios", 6000
    guest = re.fullmatch(r"(tap|veth)(\d+)i\d+", label)
    if kind == "guest" and guest:
        kind_name = "VM" if guest.group(1) == "tap" else "container"
        return f"Guest {guest.group(2)} ({kind_name})", 3000 + int(guest.group(2))
    if kind == "ssid":
        ssid = ssid_by_iface.get(label, {}).get("ssid") or label
        r["ssid"] = ssid
        return f"SSID {ssid}", 7000
    return "System and virtual", 9000


def ap_port_hosts(device: Dict[str, Any]) -> Dict[str, Any]:
    """Hosts learned on the monitored switch port an access point is plugged into.

    UniFi APs do not expose a station table over SNMP, so this approximates a
    client list from the switch FDB joined to router ARP. It is exact only
    when nothing else sits behind that port; the port name is returned so the
    UI can say which port the list came from.
    """
    arp = database.get_table_all_devices("arp")
    ap_mac = next((r["mac"] for r in arp if r["row_key"] == device["ip_address"]), None)
    if not ap_mac:
        return {"port": None, "hosts": []}
    fdb = database.get_table_all_devices("fdb")
    spot = next((r for r in fdb if r["row_key"] == ap_mac), None)
    if not spot:
        return {"port": None, "hosts": []}
    switch = database.get_device(spot["device_id"])
    iface = database.get_device_table(spot["device_id"], "interfaces").get(str(spot["if_index"]), {})
    mac_to_ip = {r["mac"]: r["row_key"] for r in arp}
    by_ip = {d["ip_address"]: d["hostname"] for d in database.list_devices() if not d.get("service_port")}
    hosts = []
    for r in fdb:
        if r["device_id"] == spot["device_id"] and r["if_index"] == spot["if_index"] and r["row_key"] != ap_mac:
            ip = mac_to_ip.get(r["row_key"])
            hosts.append({"mac": r["row_key"], "ip": ip, "vlan": r.get("vlan"), "device": by_ip.get(ip)})
    label = iface.get("label", str(spot["if_index"]))
    if iface.get("alias") and iface["alias"] != label:
        label += f" ({iface['alias']})"
    return {"port": f"{switch['hostname'] if switch else 'switch'} {label}",
            "port_macs": len(hosts) + 1, "hosts": hosts}


def top_interfaces(limit: int) -> list:
    """Busiest physical ports across all devices by current in+out rate."""
    names = {d["id"]: d["hostname"] for d in database.list_devices()}
    rows = []
    for r in database.get_table_all_devices("interfaces"):
        if r.get("kind") != "port" or r.get("oper") != 1 or r["device_id"] not in names:
            continue
        total = (r.get("in_bps") or 0) + (r.get("out_bps") or 0)
        speed = (r.get("speed_mbps") or 0) * 1e6
        rows.append({"device_id": r["device_id"], "hostname": names[r["device_id"]], "if_index": r["if_index"],
                     "label": r.get("label"), "alias": r.get("alias"), "in_bps": r.get("in_bps"),
                     "out_bps": r.get("out_bps"), "total_bps": total, "speed_mbps": r.get("speed_mbps"),
                     "util_pct": 100 * max(r.get("in_bps") or 0, r.get("out_bps") or 0) / speed if speed else None})
    return sorted(rows, key=lambda x: x["total_bps"], reverse=True)[:limit]


WIDGET_TYPES = {"summary", "problems", "availability", "events", "graph", "top_ports",
                "top_cpu", "wireless", "wan", "offline", "proxmox", "pihole", "storage", "host_actions",
                "workflows", "maintenance", "new_devices", "note"}
# Tiles whose data comes from GET /api/dashboard/extras (only fetched when a dashboard shows them).
EXTRA_WIDGETS = ("proxmox", "pihole", "storage", "host_actions", "workflows", "maintenance", "new_devices")
DASHBOARD_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
MAX_DASHBOARDS = 30
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


DASHBOARD_COLUMNS = (2, 3, 4, 6, 8, 12)
MAX_WIDGET_ROWS = 12


def parse_dashboard_layout(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validates a dashboard: grid column count plus widgets with width (span) and height (rows)."""
    columns = _get_int(payload, "columns", 4, 2, 12)
    if columns not in DASHBOARD_COLUMNS:
        raise RequestError(400, f"columns must be one of {', '.join(map(str, DASHBOARD_COLUMNS))}")
    layout = payload.get("layout")
    if not isinstance(layout, list) or len(layout) > 40:
        raise RequestError(400, "layout must be a list of at most 40 widgets")
    out = []
    for w in layout:
        if not isinstance(w, dict) or w.get("type") not in WIDGET_TYPES:
            raise RequestError(400, "Unknown widget type")
        wid = w.get("id")
        if not isinstance(wid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", wid):
            raise RequestError(400, "Invalid widget id")
        span = min(columns, _get_int(w, "span", 2, 1, 12))
        rows = _get_int(w, "rows", DEFAULT_WIDGET_ROWS.get(w["type"], 3), 1, MAX_WIDGET_ROWS)
        config = w.get("config") or {}
        if not isinstance(config, dict) or len(json.dumps(config)) > 2000:
            raise RequestError(400, "Invalid widget config")
        item = {"id": wid, "type": w["type"], "span": span, "rows": rows, "config": config}
        name = w.get("name")
        if isinstance(name, str) and name.strip():
            # The administrator's own title for the tile; plain text, shown escaped.
            item["name"] = _CONTROL.sub("", name).strip()[:60]
        out.append(item)
    result = {"columns": columns, "widgets": out}
    title = payload.get("title")
    if isinstance(title, str) and title.strip():
        result["title"] = _CONTROL.sub("", title).strip()[:60]
    return result


def dashboard_name(value: Any) -> str:
    name = value if isinstance(value, str) and value else "default"
    if not DASHBOARD_NAME.fullmatch(name):
        raise RequestError(400, "Invalid dashboard name")
    return name


def dashboards_list() -> List[Dict[str, Any]]:
    """The saved dashboards; before anything is saved, the built-in Overview."""
    return database.list_dashboards() or [{"name": "default", "title": "Overview", "updated_at": None}]


def create_dashboard(title: Any, template: Any) -> Dict[str, Any]:
    """A new dashboard, blank or copied from one of DASHBOARD_TEMPLATES. Returns its list entry."""
    if not isinstance(title, str) or not _CONTROL.sub("", title).strip():
        raise RequestError(400, "Give the dashboard a name")
    existing = database.list_dashboards()
    if len(existing) >= MAX_DASHBOARDS:
        raise RequestError(400, f"At most {MAX_DASHBOARDS} dashboards")
    if not existing:
        # The built-in Overview was never saved: keep it in the list beside the new one.
        database.save_dashboard(stored_dashboard())
    if template:
        tpl_def = next((t for t in DASHBOARD_TEMPLATES if t["id"] == template), None)
        if tpl_def is None:
            raise RequestError(400, "Unknown template")
        layout = {"columns": tpl_def["columns"], "widgets": json.loads(json.dumps(tpl_def["widgets"]))}
    else:
        layout = {"columns": 4, "widgets": []}
    layout = parse_dashboard_layout(dict(layout, layout=layout["widgets"], title=title))
    names = {d["name"] for d in database.list_dashboards()}
    n = 1
    while f"d{n}" in names:
        n += 1
    database.save_dashboard(layout, f"d{n}")
    return {"name": f"d{n}", "title": layout["title"]}


def dashboard_extras(want: List[str], user: Any) -> Dict[str, Any]:
    """Compact data for the newer tiles. Each part is filled only when asked for, and holds
    {"error": text} instead when this user may not see it or its source is not set up."""
    out: Dict[str, Any] = {}
    allowed = None if user.scope is None else set(user.allowed_ids or [])
    seen = lambda device_id: allowed is None or device_id in allowed
    for part in want:
        try:
            if part == "proxmox":
                if user.scope is not None:
                    out[part] = {"error": "Proxmox needs access to every device"}
                    continue
                if not proxmox.is_enabled():
                    out[part] = {"error": "Proxmox is not set up (Settings, Proxmox)"}
                    continue
                lay = proxmox.layout()
                out[part] = {"nodes": lay.get("nodes", []),
                             "guests": [{k: g.get(k) for k in ("vmid", "name", "node", "type", "status", "device_id", "onboot",
                                                                "mem", "maxmem", "uptime")} for g in lay.get("guests", [])]}
            elif part == "pihole":
                if user.scope is not None:
                    out[part] = {"error": "Pi-hole needs access to every device"}
                    continue
                v = pihole.view(database.list_devices())
                if not v.get("configured"):
                    out[part] = {"error": "Pi-hole is not set up (Settings, Pi-hole)"}
                    continue
                out[part] = {"device": v.get("device"), "metrics": {k: m["value"] for k, m in v.get("metrics", {}).items()}}
            elif part == "storage":
                names = {d["id"]: d["hostname"] for d in database.list_devices()}
                rows = [dict(f, device_id=dev, hostname=names.get(dev, "?"))
                        for dev, fs in forecast.cached().items() if dev in names and seen(dev) for f in fs]
                rows.sort(key=lambda r: (r["days"] is None, r["days"] if r["days"] is not None else 0, -(r.get("now") or 0)))
                out[part] = {"rows": [{k: r.get(k) for k in ("device_id", "hostname", "label", "now", "per_day", "days")} for r in rows[:30]]}
            elif part == "host_actions":
                if not (user.can("automation.run") or user.can("automation.edit")):
                    out[part] = {"error": "Needs permission to run automation"}
                    continue
                out[part] = {"runs": [r for r in database.list_action_runs(None, 20) if seen(r["device_id"])]}
            elif part == "workflows":
                if not (user.can("automation.run") or user.can("automation.edit")):
                    out[part] = {"error": "Needs permission to run automation"}
                    continue
                out[part] = {"runs": workflows_in_scope(user, database.list_workflow_runs(None, 20), "workflow_id")}
            elif part == "maintenance":
                out[part] = {"windows": maintenance_view(user, maintenance.windows())}
            elif part == "new_devices":
                if user.scope is not None:
                    out[part] = {"error": "The inventory needs access to every device"}
                    continue
                rows = [r for r in inventory.listing()["rows"] if not r["known"] and not r["hushed"]]
                rows.sort(key=lambda r: -(r.get("first_seen") or 0))
                out[part] = {"rows": [{k: r.get(k) for k in ("mac", "ip", "hostname", "vendor", "ssid", "first_seen", "last_seen")}
                                      for r in rows[:30]], "count": len(rows)}
        except Exception:
            log.exception("Dashboard data for %s failed", part)
            out[part] = {"error": "Could not read this right now"}
    return out


def stored_dashboard(name: str = "default") -> Optional[Dict[str, Any]]:
    """The saved dashboard, upgrading the original format (a bare widget list on a 4-column grid).
    None for a name that does not exist (the built-in Overview always does)."""
    saved = database.get_dashboard(name)
    if saved is None:
        if name != "default":
            return None
        return {"columns": 4, "widgets": json.loads(json.dumps(DEFAULT_DASHBOARD)), "title": "Overview"}
    if isinstance(saved, list):
        saved = {"columns": 4, "widgets": saved}
    for w in saved["widgets"]:
        w.setdefault("rows", DEFAULT_WIDGET_ROWS.get(w["type"], 3))
    return saved


# Default height of each tile type in grid rows (one row is 90 px).
DEFAULT_WIDGET_ROWS = {"summary": 2, "problems": 3, "availability": 3, "events": 4, "graph": 3,
                       "top_ports": 4, "top_cpu": 4, "wireless": 3, "wan": 4, "offline": 3, "proxmox": 4,
                       "pihole": 2, "storage": 3, "host_actions": 3, "workflows": 3, "maintenance": 2,
                       "new_devices": 3, "note": 2}

DEFAULT_DASHBOARD = [
    {"id": "w-summary", "type": "summary", "span": 4, "rows": 2, "config": {}},
    {"id": "w-problems", "type": "problems", "span": 2, "rows": 3, "config": {}},
    {"id": "w-availability", "type": "availability", "span": 2, "rows": 3, "config": {}},
    {"id": "w-wan", "type": "wan", "span": 2, "rows": 4, "config": {}},
    {"id": "w-top-ports", "type": "top_ports", "span": 2, "rows": 4, "config": {"limit": 8}},
    {"id": "w-wireless", "type": "wireless", "span": 2, "rows": 3, "config": {}},
    {"id": "w-top-cpu", "type": "top_cpu", "span": 2, "rows": 4, "config": {}},
    {"id": "w-events", "type": "events", "span": 4, "rows": 4, "config": {"limit": 12}},
]



def _w(kind: str, span: int, rows: int, name: str = "", **config: Any) -> Dict[str, Any]:
    w = {"id": f"w-{kind}", "type": kind, "span": span, "rows": rows, "config": config}
    if name:
        w["name"] = name
    return w


def _tpl(tid: str, title: str, description: str, columns: int, widgets: List[Dict[str, Any]]) -> Dict[str, Any]:
    seen: Dict[str, int] = {}
    for w in widgets:                      # unique ids within the template
        seen[w["id"]] = seen.get(w["id"], 0) + 1
        if seen[w["id"]] > 1:
            w["id"] = f"{w['id']}-{seen[w['id']]}"
    return {"id": tid, "title": title, "description": description, "columns": columns, "widgets": widgets}


# Ready-made dashboards offered by Add dashboard. Groups are the built-in device groups (taxonomy).
DASHBOARD_TEMPLATES = [
    _tpl("overview", "Overview", "The standard dashboard: status, problems, availability, internet, ports, Wi-Fi, load and events.", 4,
         json.loads(json.dumps(DEFAULT_DASHBOARD))),
    _tpl("problems-first", "Problems first", "Open problems large, with what is offline beside them and the event log below.", 4,
         [_w("summary", 4, 2), _w("problems", 3, 5), _w("offline", 1, 5, "Offline now"), _w("events", 4, 4, limit=15)]),
    _tpl("wall", "Wall screen", "For a TV or a spare monitor: big status tiles and every device at a glance.", 4,
         [_w("summary", 4, 2), _w("availability", 3, 5), _w("problems", 1, 5)]),
    _tpl("morning", "Morning check", "What changed overnight: problems, offline devices, disks filling up, new devices and maintenance.", 6,
         [_w("summary", 6, 2), _w("problems", 3, 4), _w("offline", 3, 2), _w("storage", 3, 2, "Disks filling up"),
          _w("new_devices", 3, 3), _w("maintenance", 3, 3), _w("events", 6, 4, "Overnight events", limit=20)]),
    _tpl("outage", "Outage", "When something is down: what is offline, open problems, availability and the latest events.", 4,
         [_w("offline", 2, 4, "Offline now"), _w("problems", 2, 4), _w("availability", 4, 3), _w("events", 4, 4, limit=20)]),
    _tpl("minimal", "Minimal", "Just the status line and open problems.", 4,
         [_w("summary", 4, 2), _w("problems", 4, 4)]),
    _tpl("network", "Network", "Gateways and switches: internet, the busiest ports, port problems and availability.", 4,
         [_w("wan", 2, 4), _w("top_ports", 2, 4, limit=10), _w("availability", 2, 3, "Switches", filter="group:switch"),
          _w("problems", 2, 3, "Network problems", filter="group:switch"), _w("availability", 4, 2, "Gateways", filter="group:gateway")]),
    _tpl("internet", "Internet", "Your internet connection first: WAN traffic, gateway problems and its events.", 4,
         [_w("wan", 4, 4), _w("problems", 2, 3, "Gateway problems", filter="group:gateway"),
          _w("events", 2, 3, "Gateway events", filter="group:gateway", limit=10)]),
    _tpl("wifi", "Wi-Fi", "Access points, wireless clients, weak signals and new devices joining.", 4,
         [_w("wireless", 2, 4), _w("availability", 2, 2, "Access points", filter="group:wireless_ap"),
          _w("problems", 2, 2, "Wi-Fi problems", filter="group:wireless_ap"), _w("new_devices", 4, 3)]),
    _tpl("proxmox", "Proxmox", "Nodes and guests, guest problems, server load, disks filling up and recent host actions.", 6,
         [_w("proxmox", 3, 5), _w("problems", 3, 3, "Server problems", filter="group:server"),
          _w("top_cpu", 3, 2, "Server load", filter="group:server"), _w("storage", 3, 3), _w("host_actions", 3, 3)]),
    _tpl("servers", "Servers", "Servers and hypervisors: availability, load, storage and problems.", 4,
         [_w("availability", 2, 3, "Servers", filter="group:server"), _w("top_cpu", 2, 3, "Load", filter="group:server"),
          _w("storage", 2, 3), _w("problems", 2, 3, "Server problems", filter="group:server"),
          _w("events", 4, 3, "Server events", filter="group:server", limit=12)]),
    _tpl("storage", "Storage and NAS", "Disks and volumes filling up, NAS availability, load and problems.", 4,
         [_w("storage", 2, 4, "Filling up"), _w("availability", 2, 2, "NAS", filter="group:nas"),
          _w("top_cpu", 2, 2, "NAS load", filter="group:nas"), _w("problems", 4, 3, "Storage problems", filter="group:nas")]),
    _tpl("dns", "DNS and Pi-hole", "Pi-hole queries and blocking, DNS problems and events.", 4,
         [_w("pihole", 2, 3), _w("problems", 2, 3), _w("events", 4, 4, limit=12)]),
    _tpl("automation", "Automation", "Workflow runs and host actions, with the problems they are there to fix.", 4,
         [_w("workflows", 2, 4), _w("host_actions", 2, 4), _w("problems", 2, 3), _w("maintenance", 2, 3)]),
    _tpl("maintenance", "Maintenance", "Maintenance windows, host actions and workflows that ran, and the events around them.", 4,
         [_w("maintenance", 2, 3), _w("host_actions", 2, 3), _w("workflows", 2, 3), _w("events", 2, 3, limit=12)]),
    _tpl("security", "New and unknown devices", "Devices on the network you have not marked known, new arrivals and offline devices.", 4,
         [_w("new_devices", 2, 5), _w("events", 2, 5, limit=20), _w("offline", 4, 2)]),
    _tpl("capacity", "Capacity", "What is running out: disks filling up, busy devices, busy ports and internet use.", 4,
         [_w("storage", 2, 4), _w("top_cpu", 2, 4), _w("top_ports", 2, 4, limit=10), _w("wan", 2, 4)]),
    _tpl("services", "Websites and services", "Port and website checks: availability, problems and events.", 4,
         [_w("availability", 4, 3, "Services", filter="group:service"), _w("problems", 2, 3, "Service problems", filter="group:service"),
          _w("events", 2, 3, "Service events", filter="group:service", limit=12)]),
    _tpl("homelab", "Homelab at a glance", "A bit of everything on a wide grid: status, Proxmox, Pi-hole, Wi-Fi, storage and problems.", 6,
         [_w("summary", 6, 2), _w("proxmox", 2, 4), _w("pihole", 2, 2), _w("wireless", 2, 2), _w("storage", 2, 2),
          _w("problems", 4, 3), _w("offline", 2, 3)]),
    _tpl("power", "Power and printers", "UPS, PDUs and printers: availability, problems and events.", 4,
         [_w("availability", 2, 3, "Power", filter="group:power"), _w("problems", 2, 3, "Power problems", filter="group:power"),
          _w("availability", 2, 2, "Printers", filter="group:printer"), _w("events", 2, 2, "Power events", filter="group:power", limit=8)]),
]


# --- Live Mode ---

class LiveMonitor:
    """In-memory fast sampling for device pages that are open in a browser.

    The page renews a lease every few seconds. While the lease is valid the
    scheduler samples that device at live_interval; when it lapses the buffer
    is dropped. Nothing here touches the database, so retention and database
    size are independent of how long pages stay open.
    """

    LEASE_SECONDS = 30
    BUFFER_SECONDS = 900

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.leases: Dict[int, float] = {}
        self.state: Dict[int, Dict[str, Any]] = {}

    def touch(self, device_id: int, max_devices: int) -> bool:
        now = time.time()
        with self.lock:
            self._expire(now)
            if device_id not in self.leases and len(self.leases) >= max_devices:
                return False
            self.leases[device_id] = now + self.LEASE_SECONDS
            self.state.setdefault(device_id, {"metrics": {}, "rates": {}, "prev": None,
                                              "next": 0.0, "interval": None, "last_duration": None})
            return True

    def _expire(self, now: float) -> None:
        for device_id in [d for d, exp in self.leases.items() if exp < now]:
            del self.leases[device_id]
            self.state.pop(device_id, None)

    def due(self, base_interval: int) -> list:
        """Device ids whose next live sample is due."""
        now = time.time()
        with self.lock:
            self._expire(now)
            out = []
            for device_id in self.leases:
                st = self.state[device_id]
                if st["interval"] is None:
                    st["interval"] = base_interval
                if now >= st["next"]:
                    st["next"] = now + st["interval"]
                    out.append(device_id)
            return out

    def record(self, device_id: int, sample: Dict[str, Any], duration: float, base_interval: int) -> None:
        with self.lock:
            st = self.state.get(device_id)
            if st is None:
                return
            ts = sample["timestamp"]
            cutoff = ts - self.BUFFER_SECONDS
            for key, value in sample["metrics"].items():
                series = st["metrics"].setdefault(key, [])
                series.append((ts, value))
                while series and series[0][0] < cutoff:
                    series.pop(0)
            prev = st["prev"]
            if prev and sample["counters"]:
                dt = ts - prev["timestamp"]
                for idx, (cin, cout) in sample["counters"].items():
                    pin, pout = prev["counters"].get(idx, (None, None))
                    din, dout = poller.counter_delta(cin, pin), poller.counter_delta(cout, pout)
                    if dt <= 0 or din is None or dout is None:
                        continue
                    series = st["rates"].setdefault(idx, [])
                    series.append((ts, din * 8 / dt, dout * 8 / dt))
                    while series and series[0][0] < cutoff:
                        series.pop(0)
            if sample["counters"]:
                st["prev"] = sample
            # Back off when a sample takes most of the interval, so a slow agent is never saturated.
            st["last_duration"] = duration
            st["interval"] = base_interval if duration < base_interval * 0.7 else min(60, max(base_interval, duration * 2))

    def since(self, device_id: int, since: float) -> Dict[str, Any]:
        with self.lock:
            st = self.state.get(device_id)
            if st is None:
                return {"interval": None, "metrics": {}, "rates": {}}
            return {
                "interval": st["interval"],
                "last_duration": st["last_duration"],
                "metrics": {k: [p for p in v if p[0] > since] for k, v in st["metrics"].items()},
                "rates": {k: [p for p in v if p[0] > since] for k, v in st["rates"].items()},
            }

    def active(self) -> list:
        with self.lock:
            return sorted(self.leases)


# --- Background Polling Scheduler ---

class WanPeakSampler:
    """Short-interval WAN counter sampling that keeps the peak rate per flush period.

    The regular poll stores one average per poll interval, which flattens a
    30 s burst into a fraction of line rate. Only the two 64-bit octet
    counters of each WAN interface are read, and only the peaks are written.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last: Dict[tuple, tuple] = {}
        self.peaks: Dict[tuple, list] = {}
        self.targets: list = []
        self.targets_at = 0.0

    def sample(self, timeout: float) -> None:
        now = time.time()
        if now - self.targets_at > 60:
            self.targets = wan_interfaces()
            self.targets_at = now
        for w in self.targets:
            device = database.get_device(w["device_id"])
            if not device or device["status"] == "offline":
                continue
            oids = [f"{poller.LIVE_IF_COLUMNS['in_octets']}.{w['if_index']}", f"{poller.LIVE_IF_COLUMNS['out_octets']}.{w['if_index']}"]
            got = poller.snmp_get_many(device["ip_address"], oids, poller.snmp_target(device),
                                       device.get("snmp_port") or 161, timeout, 0)
            if len(got) != 2:
                continue
            key = (w["device_id"], w["if_index"])
            now = time.time()
            counters = (now, got[oids[0]], got[oids[1]])
            ceiling = (w.get("speed_mbps") or 0) * 1e6 or None
            with self.lock:
                prev = self.last.get(key)
                self.last[key] = counters
                if not prev:
                    continue
                rate_in = poller._rate_bps(counters[1], prev[1], now - prev[0], ceiling)
                rate_out = poller._rate_bps(counters[2], prev[2], now - prev[0], ceiling)
                peak = self.peaks.setdefault(key, [None, None])
                if rate_in is not None and (peak[0] is None or rate_in > peak[0]):
                    peak[0] = rate_in
                if rate_out is not None and (peak[1] is None or rate_out > peak[1]):
                    peak[1] = rate_out

    def flush(self) -> None:
        """Writes the peaks collected since the last flush as if.<n>.in_peak_bps / out_peak_bps."""
        with self.lock:
            peaks, self.peaks = self.peaks, {}
        now = int(time.time())
        for (device_id, if_index), (pin, pout) in peaks.items():
            values = {}
            if pin is not None:
                values[f"if.{if_index}.in_peak_bps"] = pin
            if pout is not None:
                values[f"if.{if_index}.out_peak_bps"] = pout
            if values:
                database.record_metrics(device_id, values, timestamp=now)


class PollScheduler:
    """Runs ICMP and SNMP polls per device on their own intervals.

    Each device has independent next-due times for ping and SNMP, using its
    override or the global default. Jobs run on a small thread pool so one
    unreachable host does not delay the others, and a device never has two
    jobs of the same kind in flight. The problem engine runs every 30s,
    hourly rollups every 5 minutes and retention purges hourly.
    """

    TICK_SECONDS = 1.0
    PURGE_INTERVAL = 3600
    ROLLUP_INTERVAL = 300
    LAN_INTERVAL = 60          # Pi-hole and UniFi
    INVENTORY_INTERVAL = 300
    TLS_INTERVAL = 6 * 3600  # certificate renewal and expiry warnings (tls.daily_check limits the messages)
    ROOT_WATCH_INTERVAL = 60  # restore and update results root wrote (watch_root_results)
    PROBLEM_INTERVAL = 30

    def __init__(self, workers: int = 8) -> None:
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="poll")
        # Re-entrant: tick() holds it across the due-time loop and _submit() re-acquires it.
        self.lock = threading.RLock()
        self.next_ping: Dict[int, float] = {}
        self.next_snmp: Dict[int, float] = {}
        self.in_flight: set = set()
        self.profiles: Dict[str, Any] = {}
        self.profiles_loaded = 0.0
        self.last_purge = 0.0
        self.last_root_watch = time.time()   # start_server checks once at start
        self.last_rollup = 0.0
        self.last_tls = time.time() - self.TLS_INTERVAL + 120  # first check two minutes after start
        self.last_problems = 0.0
        self.last_lan = 0.0
        self.last_inventory = time.time() - self.INVENTORY_INTERVAL + 90   # first pass after the first polls
        self.wifi_clients: Optional[list] = None
        self.last_tick = 0.0
        self.last_tick_minute = 0.0
        self.live = LiveMonitor()
        self.wan = WanPeakSampler()
        self.last_wan_sample = 0.0
        self.last_wan_flush = time.time()

    def poll_now(self, device_id: int) -> None:
        """Makes a device due for both ping and SNMP on the next tick."""
        with self.lock:
            self.next_ping[device_id] = 0.0
            self.next_snmp[device_id] = 0.0

    def _submit(self, kind: str, key_id: int, fn, *args) -> bool:
        """Runs fn in the pool unless the same job is still running. False when it was skipped."""
        key = (kind, key_id)
        with self.lock:
            if key in self.in_flight:
                return False
            self.in_flight.add(key)

        def run() -> None:
            try:
                fn(*args)
            except Exception:
                log.exception("%s job failed (id %s)", kind, key_id)
            finally:
                with self.lock:
                    self.in_flight.discard(key)

        self.pool.submit(run)
        return True

    def refresh_device(self, device_id: int) -> None:
        """Polls one device now (ping, then SNMP and tables) and re-evaluates problems straight after,
        so a fixed condition clears in seconds. Used after Fix SNMP."""
        def job() -> None:
            device = database.get_device(device_id)
            if not device:
                return
            settings = database.get_all_settings()
            timeout, retries = get_setting(settings, "default_timeout"), get_setting(settings, "default_retries")
            self._ping_job(device, min(timeout, 2.0))
            if profile_uses_snmp(device.get("profile_id"), self.profiles):
                self._snmp_job(device, timeout, retries)
            self._problem_job(get_setting(settings, "problem_resolve_minutes"))
        self._submit("refresh", device_id, job)

    def _ping_job(self, device: Dict[str, Any], timeout: float) -> Any:
        """The reachability check (ping, plus the port or HTTP test for service checks), recorded
        as one availability beat. A failure to record never fails the check itself."""
        result = poller.ping_device(device, timeout)
        try:
            status, ping_ms = result
            availability.record(device["id"], status == "online", availability.response_ms(device["id"], ping_ms),
                                planned=maintenance_window(device) is not None)
        except Exception:
            log.exception("Could not record availability for device %s", device.get("id"))
        return result

    def _snmp_job(self, device: Dict[str, Any], timeout: float, retries: int) -> None:
        # Skip SNMP for hosts that just failed ICMP: each OID would wait out the full timeout.
        current = database.get_device(device["id"])
        if current and current["status"] == "offline":
            return
        profile = self.profiles.get(device.get("profile_id", "generic_device"))
        poller.poll_snmp_metrics(device, profile, timeout, retries)
        customoids.poll(device, timeout, retries)
        poller.collect_tables(device, profile, timeout, retries)

    def _live_job(self, device: Dict[str, Any], timeout: float, base_interval: int) -> None:
        start = time.time()
        profile = self.profiles.get(device.get("profile_id", "generic_device"))
        if not device.get("service_port") and not profile_uses_snmp(device.get("profile_id"), self.profiles):
            # Ping only: the live sample is the echo alone.
            alive, ms = poller.ping_host(device["ip_address"], min(timeout, 2.0))
            sample = {"timestamp": time.time(), "alive": alive, "metrics": {"icmp_ping_ms": ms or 0.0} if alive else {}, "counters": {}}
        else:
            sample = poller.live_sample(device, profile, timeout, 0)
        self.live.record(device["id"], sample, time.time() - start, base_interval)

    def _start_scheduled(self, wf: Dict[str, Any], trigger: str) -> None:
        """Starts a scheduled run unless something would stop it at once; each blocker is logged as an event."""
        problem = workflow_author_problem(wf)
        if problem:
            # Recorded as a failed run (the workflow's history) and an event, so the administrator sees why.
            run_id = database.start_workflow_run(wf["id"], trigger)
            message = f"Run skipped: {problem}. Open the workflow and save it again as someone allowed to run it."
            now = time.time()
            database.update_workflow_run(run_id, "failed", json.dumps([{
                "step": 0, "node": None, "type": "check", "title": "Rights of the user who saved it", "host": None,
                "host_id": None, "status": "failed", "started": now, "finished": now, "detail": message}]), now)
            database.add_event(None, "warning", "action", f"Workflow {wf['name']}: {message}")
            return
        blockers = workflows.preflight(wf)
        for b in blockers:
            database.add_event(b["device_id"], "warning", "action", f"Scheduled run skipped. {b['message']}")
        if blockers:
            return
        try:
            workflows.MANAGER.start(wf, trigger)
        except workflows.WorkflowError:
            log.info("Workflow %s still running at its next scheduled time; skipped", wf["name"])

    def _due_workflows(self, now: float) -> None:
        minute = int(now // 60) * 60
        when = datetime.fromtimestamp(minute)
        for wf in database.list_workflows():
            if not wf["is_active"]:
                continue
            if wf["trigger_type"] == "once" and wf.get("run_at"):
                if now < wf["run_at"]:
                    continue
                # Marked done first, so a crash during the run cannot repeat a one-off.
                view = workflow_view(wf)
                sched = dict(view["schedule"], done=True)
                graph = view["graph"]
                for node in graph["nodes"]:
                    if node["type"] == "trigger":
                        node["schedule"] = sched
                database.finish_once_workflow(wf["id"], graph, sched)
                late = now - wf["run_at"]
                if late <= schedule.ONCE_GRACE_SECONDS:
                    self._start_scheduled(wf, "schedule")
                else:
                    database.add_event(None, "warning", "action",
                                       f"Workflow '{wf['name']}' missed its one-off run ({schedule.describe(sched)}): "
                                       f"the monitor was not running then. Run it by hand if it is still needed.")
                continue
            if wf["trigger_type"] != "schedule" or wf["last_scheduled"] == minute:
                continue
            try:
                due = ssh_runner.cron_matches(wf["trigger_cron"] or "", when)
            except ValueError:
                continue
            if due:
                database.mark_workflow_scheduled(wf["id"], minute)
                self._start_scheduled(wf, "schedule")

    def _problem_job(self, resolve_minutes: int) -> None:
        """Opens and resolves problems, logs both as events and sends the Telegram messages the rules allow.

        Info-level problems are not logged as events (the dashboard shows them).
        """
        # Configuration states, not fluctuating measurements: clear as soon as the condition does.
        # A Proxmox guest's state too: once Proxmox says it runs, "is stopped" goes (the next round, within a minute).
        immediate = {"unreachable", "snmp", "snmp_view", "service_down"}
        immediate_prefixes = ("workflow:", "pve_guest_down:")
        result = database.sync_problems(
            evaluate_problems(),
            resolve_after=lambda key: 0 if key in immediate or key.startswith(immediate_prefixes) else resolve_minutes * 60,
        )
        # Workflows started by "When something happens" look at the problems just synced.
        try:
            workflows.TRIGGERS.evaluate(time.time(), self._start_scheduled)
        except Exception:
            log.exception("Workflow trigger evaluation failed")
        settings = database.get_all_settings()
        min_sev = settings.get("notify_min_severity", "warning")
        repeat = get_setting(settings, "notify_repeat_hours") if settings.get("telegram_enabled") == "on" else 0
        if not (result["opened"] or result["resolved"] or repeat or PENDING_SETTLE):
            return
        devices = {d["id"]: d for d in database.list_devices()}
        now = time.time()
        policy = alert_policy()
        windows = maintenance.windows()
        down = {p["device_id"] for p in database.list_active_problems() if p["problem_key"] == "unreachable"} if result["opened"] else set()
        for p in result["opened"]:
            device = devices.get(p["device_id"])
            window = maintenance_window(device, windows)
            behind = p["key"] == "unreachable" and p["device_id"] in BEHIND
            # Another problem on a device that is offline (a Proxmox guest stopped, say): the offline
            # message already covers it, and its "resolved" stays quiet too.
            covered = p["key"] != "unreachable" and (p["device_id"] in down or p["device_id"] in BEHIND)
            if p["severity"] != "info":
                note = " (during maintenance)" if window else ""
                database.add_event(p["device_id"], p["severity"], "problem", f"Problem: {p['message']}{note}")
            if window or behind:
                # Maintenance: planned. Behind a failed device: that device's message names it.
                HELD_BACK.add((p["device_id"], p["key"]))
                continue
            if covered:
                HELD_BACK.add((p["device_id"], p["key"]))
                if p["severity"] != "info":
                    database.add_event(p["device_id"], "info", "problem",
                                       f"Not sent to Telegram: {p['message']} (the device is offline; that message covers it)")
                continue
            if p["key"] in SETTLE_KEYS and device is not None:
                PENDING_SETTLE[(p["device_id"], p["key"])] = {"at": now, "p": p}     # see release_settled
                continue
            if alerts.should_send(p, p["severity"], min_sev) and not in_new_device_quiet(device, settings):
                notify_problem(device, p["key"], p["severity"], p["message"], opened=True,
                               sound=p.get("sound", "default"))
        for p in result["resolved"]:
            lasted = format_duration(time.time() - p["since"])
            if p["severity"] != "info":
                database.add_event(p["device_id"], "info", "problem", f"Resolved: {p['message']} (lasted {lasted})")
            device = devices.get(p["device_id"])
            if device is None:
                continue
            held = (p["device_id"], p["problem_key"]) in HELD_BACK
            HELD_BACK.discard((p["device_id"], p["problem_key"]))
            # Over before its held message went: neither is sent.
            settled_away = PENDING_SETTLE.pop((p["device_id"], p["problem_key"]), None) is not None
            if held or settled_away or maintenance_window(device, windows):
                continue
            r = policy.for_device(device)(alerts.rule_id_for_key(p["problem_key"], device["profile_id"]))
            if r["resolved"] == "on" and alerts.should_send(r, p["severity"], min_sev) and not in_new_device_quiet(device, settings):
                notify_problem(device, p["problem_key"], p["severity"], p["message"], opened=False, lasted=lasted,
                               sound=r.get("sound", "default"))
        release_settled(now, devices, settings, min_sev)
        if repeat:
            self._reminders(devices, policy, repeat, settings.get("notify_repeat_severity", "critical"))

    def _lan_job(self) -> None:
        """Pi-hole figures and the DNS check; UniFi's Wi-Fi clients (kept for the inventory)."""
        devices = database.list_devices()
        try:
            pihole.run(devices)
        except Exception:
            log.exception("Pi-hole round failed")
        try:
            error = proxmox.refresh(devices, database.get_table_all_devices("arp"))
            if error:
                log.warning("Proxmox round: %s", error)
        except Exception:
            log.exception("Proxmox round failed")
        # The all-devices threshold: the figure per access point counts against one line.
        weak = alert_policy().resolve("wifi_weak", upto="global")[0]["threshold"] or -75
        try:
            rows = unifi.run(devices, weak)
            if rows is not None:
                self.wifi_clients = rows
        except Exception:
            log.exception("UniFi round failed")

    def _inventory_job(self) -> None:
        """Every address on the network into the inventory; a new one is an event and a message."""
        labels: Dict[int, Dict[int, str]] = {}
        if_rows = database.get_table_all_devices("interfaces")
        for r in if_rows:
            labels.setdefault(r["device_id"], {})[r["if_index"]] = r.get("label") or str(r["if_index"])
        devices, arp = database.list_devices(), database.get_table_all_devices("arp")
        seen = inventory.gather(devices, database.get_table_all_devices("fdb"), arp, if_rows, labels,
                                self.wifi_clients if unifi.is_enabled() else None)

        def tell(s: Dict[str, Any]) -> None:
            if s.get("summary"):
                text = f"{s['summary']} more new devices on the network (see Inventory)"
            else:
                text = inventory.describe(s)
            database.add_event(None, "warning", "new_device", f"New device on the network: {text}")
            NOTIFIER.event("new_device", {"what": text})

        inventory.update(seen, tell, drop=inventory.extra_macs(devices, arp, if_rows))

    def _reminders(self, devices: Dict[int, Dict[str, Any]], policy: alerts.Policy, hours: int, from_severity: str) -> None:
        """Resends open, unacknowledged problems at or above from_severity every `hours` hours."""
        now = int(time.time())
        windows = maintenance.windows()
        for p in database.list_active_problems():
            device = devices.get(p["device_id"])
            if device is None or p["acknowledged_at"] or alerts.RANK.get(p["severity"], 0) < alerts.RANK.get(from_severity, 3):
                continue
            if (p["device_id"], p["problem_key"]) in HELD_BACK or maintenance_window(device, windows):
                continue
            if now - (p["last_notified"] or p["raised_at"]) < hours * 3600:
                continue
            r = policy.for_device(device)(alerts.rule_id_for_key(p["problem_key"], device["profile_id"]))
            if r["telegram"] == "never":
                continue
            NOTIFIER.event("reminder", dict(device_values(device), severity=p["severity"], problem=p["message"],
                                            duration=format_duration(now - p["since"])), critical=p["severity"] == "critical",
                           sound=r.get("sound", "default"))
            database.mark_problem_notified(p["device_id"], p["problem_key"], now)

    def tick(self) -> None:
        now = time.time()
        self.last_tick = now
        if now - self.profiles_loaded > 60:
            self.profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
            self.profiles_loaded = now

        settings = database.get_all_settings()
        default_poll = get_setting(settings, "default_poll_interval")
        default_ping = get_setting(settings, "default_ping_interval")
        timeout = get_setting(settings, "default_timeout")
        retries = get_setting(settings, "default_retries")
        live_interval = get_setting(settings, "live_interval")

        devices = database.list_devices()
        by_id = {d["id"]: d for d in devices}
        with self.lock:
            for table in (self.next_ping, self.next_snmp):
                for stale in set(table) - set(by_id):
                    del table[stale]

            for d in devices:
                # The next time is set only when the job was accepted: a "poll now" that arrives while
                # the previous poll still runs is kept until that poll ends, not dropped until the next interval.
                if now >= self.next_ping.get(d["id"], 0.0) and \
                        self._submit("icmp", d["id"], self._ping_job, d, min(timeout, 2.0)):
                    self.next_ping[d["id"]] = now + (d["ping_interval"] or default_ping)
                # Templates without SNMP (port checks) only get the ping-interval check above.
                if self.profiles.get(d.get("profile_id"), {}).get("snmp", True) is False:
                    continue
                if now >= self.next_snmp.get(d["id"], 0.0) and \
                        self._submit("snmp", d["id"], self._snmp_job, d, timeout, retries):
                    self.next_snmp[d["id"]] = now + (d["poll_interval"] or default_poll)

            for device_id in self.live.due(live_interval):
                if device_id in by_id:
                    self._submit("live", device_id, self._live_job, by_id[device_id], timeout, live_interval)

        wan_interval = get_setting(settings, "wan_sample_interval")
        if wan_interval and now - self.last_wan_sample >= wan_interval:
            self.last_wan_sample = now
            self._submit("wan", 0, self.wan.sample, min(timeout, 2.0))
        if now - self.last_wan_flush >= default_poll:
            self.last_wan_flush = now
            self._submit("wan_flush", 0, self.wan.flush)

        if int(now // 60) != int(self.last_tick_minute):
            self.last_tick_minute = now // 60
            self._submit("schedule", 0, self._due_workflows, now)
            self._submit("digest", 0, digest.run, settings, lambda text: NOTIFIER.message(text, kind="digest"))

        if now - self.last_lan >= self.LAN_INTERVAL:
            self.last_lan = now
            self._submit("lan", 0, self._lan_job)
        if now - self.last_inventory >= self.INVENTORY_INTERVAL:
            self.last_inventory = now
            self._submit("inventory", 0, self._inventory_job)

        if now - self.last_problems >= self.PROBLEM_INTERVAL:
            self.last_problems = now
            self._submit("problems", 0, self._problem_job, get_setting(settings, "problem_resolve_minutes"))

        if now - self.last_rollup >= self.ROLLUP_INTERVAL:
            self.last_rollup = now
            self._submit("rollup", 0, lambda: database.rollup_hourly(exclude=short_term_metric_keys()))

        if now - self.last_tls >= self.TLS_INTERVAL:
            self.last_tls = now
            self._submit("tls", 0, tls.daily_check,
                         lambda days, date: NOTIFIER.event("certificate", {"days": days, "date": date}, critical=days <= 7))

        if now - self.last_root_watch >= self.ROOT_WATCH_INTERVAL:
            self.last_root_watch = now
            self._submit("root_results", 0, watch_root_results)

        if now - self.last_purge > self.PURGE_INTERVAL:
            self.last_purge = now
            deleted = database.purge_expired(
                get_setting(settings, "raw_retention_days"),
                get_setting(settings, "audit_retention_days"),
                get_setting(settings, "metric_retention_days"),
                get_setting(settings, "event_retention_days"),
            )
            if deleted["metrics"] or deleted["audit"]:
                log.info("Retention purge removed %d metric and %d audit rows", deleted["metrics"], deleted["audit"])
            availability.purge()

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            jobs: Dict[str, int] = {}
            for kind, _ in self.in_flight:
                jobs[kind] = jobs.get(kind, 0) + 1
        return {"last_tick": self.last_tick, "jobs_in_flight": jobs, "live_devices": self.live.active(),
                "profiles_loaded": len(self.profiles)}

    def run_forever(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("Scheduler tick failed")
            time.sleep(self.TICK_SECONDS)


def cleanup_untracked_history() -> None:
    """Drops stored history for metrics that are now latest-only, and legacy keys.

    Idempotent: after the first run there is nothing left to delete.
    """
    removed = database.delete_metric_history(None, ["port1_in_octets", "port1_out_octets", "port1_status"], drop_latest=True)
    for d in database.list_devices():
        removed += database.delete_metric_history(d["id"], untracked_keys(d))
    if removed:
        log.info("Removed %d history rows for latest-only metrics", removed)


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


scheduler = PollScheduler()
APP_VERSION = "0.14.0"
# When the installer that delivered this code was built (deploy/build.py writes BUILD beside it);
# empty when running from the source tree.
try:
    with open(os.path.join(BASE_DIR, "BUILD"), encoding="ascii") as _f:
        BUILT = _f.read().strip()[:20]
except OSError:
    BUILT = ""
STARTED_AT = time.time()


class RedirectToHttps(_TimedRequest, http.server.BaseHTTPRequestHandler):
    """Plain HTTP from another machine while HTTPS is on: one redirect to the same address over https."""

    server_version = "HomelabMonitor"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _redirect(self) -> None:
        host = self.headers.get("Host", "")
        # Only to this server's own name (the same Host check as every request), so it is never an open redirect.
        if not host_allowed(host) or not self.path.startswith("/"):
            self.send_error(421, "Misdirected request")
            return
        self.send_response(308)
        self.send_header("Location", f"https://{host}{self.path}")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _redirect


class ThreadingServer(socketserver.ThreadingTCPServer):
    """One port for both: a connection that opens with a TLS handshake is served over HTTPS while it
    is on (tls.SERVER.context); plain HTTP from another machine is redirected to https, plain HTTP
    from this machine (health checks, the installer, the shell scripts) is served as before."""

    daemon_threads = True
    # Linux: lets a restarted monitor take its port while connections the previous one closed are still
    # winding down (TIME_WAIT, about a minute). It never lets a second program take a port that is in
    # use. Without it, an update (the browser polling all the while) could not start the new version.
    # Windows: off, because there it would let two programs share the port.
    allow_reuse_address = os.name != "nt"
    HANDSHAKE_SECONDS = 10

    def finish_request(self, request, client_address) -> None:
        ctx = tls.SERVER.context
        if ctx is None:
            return super().finish_request(request, client_address)
        try:
            request.settimeout(self.HANDSHAKE_SECONDS)
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if not first:
            return
        if first == b"":
            try:
                conn = ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return  # a browser that refused the certificate, or a scanner: nothing to answer
            try:
                self.RequestHandlerClass(conn, client_address, self)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            return
        if self.local_client(client_address):
            return super().finish_request(request, client_address)
        RedirectToHttps(request, client_address, self)

    # --- Connection cap ---

    def _slots(self) -> Dict[str, Any]:
        slots = vars(self).get("_slot_state")
        if slots is None:
            slots = vars(self).setdefault("_slot_state", {"lock": threading.Lock(), "open": 0, "per": {},
                                                          "warned": 0.0})
        return slots

    def _take_slot(self, client_address) -> Optional[str]:
        """A slot for this connection: the address it counts against ("" for this machine), or None
        when the cap is full."""
        slots = self._slots()
        local = self.local_client(client_address)
        key = "" if local else client_address[0]
        with slots["lock"]:
            if local:
                if slots["open"] >= MAX_CONNECTIONS + LOCAL_EXTRA_CONNECTIONS:
                    return None
            elif slots["open"] >= MAX_CONNECTIONS or slots["per"].get(key, 0) >= MAX_PER_ADDRESS:
                return None
            slots["open"] += 1
            if key:
                slots["per"][key] = slots["per"].get(key, 0) + 1
        return key

    def _give_slot(self, key: str) -> None:
        slots = self._slots()
        with slots["lock"]:
            slots["open"] -= 1
            if key:
                left = slots["per"].get(key, 0) - 1
                if left > 0:
                    slots["per"][key] = left
                else:
                    slots["per"].pop(key, None)

    def open_connections(self) -> int:
        return self._slots()["open"]

    def _refuse(self, request, why: str) -> None:
        """Answers 503 without waiting and closes. A TLS client sees a failed handshake, the same as a close."""
        slots = self._slots()
        now = time.monotonic()
        if now - slots["warned"] >= 60:
            slots["warned"] = now
            log.warning("Web server: %s, new connections are refused for now", why)
        body = json.dumps({"error": BUSY_TEXT}).encode()
        reply = (b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8\r\n"
                 b"Retry-After: 5\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode()
                 + b"\r\n\r\n" + body)
        try:
            request.setblocking(False)
            request.send(reply)
        except OSError:
            pass
        self.shutdown_request(request)

    def process_request(self, request, client_address) -> None:
        """Serves the connection in its own thread while a slot is free. The accept loop never waits:
        a full cap is answered at once."""
        key = self._take_slot(client_address)
        if key is None:
            self._refuse(request, "too many connections are open")
            return
        if self.block_on_close:
            vars(self).setdefault("_threads", socketserver._Threads())
        t = threading.Thread(target=self._serve_in_slot, args=(request, client_address, key))
        t.daemon = self.daemon_threads
        try:
            t.start()
        except RuntimeError:
            # No thread could start (the service's task limit): give the slot back and close.
            self._give_slot(key)
            self._refuse(request, "no thread could be started")
            return
        self._threads.append(t)

    def _serve_in_slot(self, request, client_address, key: str) -> None:
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._give_slot(key)

    def handle_error(self, request, client_address) -> None:
        # A browser closing a kept-alive connection (common when a page switches to https) is not an error.
        if isinstance(sys.exc_info()[1], (ConnectionError, ssl.SSLError, TimeoutError)):
            return
        super().handle_error(request, client_address)

    @staticmethod
    def local_client(client_address) -> bool:
        return ipaddress.ip_address(client_address[0].split("%")[0]).is_loopback


# Alert thresholds that used to be settings: (old key, rule id, old default).
LEGACY_THRESHOLDS = [("threshold_cpu_pct", "cpu", "90"), ("threshold_mem_pct", "mem", "90"),
                     ("threshold_disk_pct", "disk_full", "90"), ("threshold_radio_util_pct", "radio", "70"),
                     ("threshold_disk_temp_c", "disk_temp", "55"), ("threshold_sensor_temp_c", "sensor_temp", "80")]


def migrate_alert_settings(existing: Dict[str, str]) -> None:
    """Moves changed thresholds into global alert rule overrides and drops settings the schema no longer has.

    Problem notifications used to be switched per event; they now follow the alert
    rules, so an event that was switched off becomes "never" on the matching rules.
    """
    changes = []
    for key, rule_id, old_default in LEGACY_THRESHOLDS:
        if key in existing and existing[key] != old_default:
            try:
                changes.append((rule_id, "threshold", alerts.encode("threshold", float(existing[key]))))
            except ValueError:
                pass
    off = {k for k in ("device_offline", "watch") if existing.get(f"notify_on_{k}") == "off"}
    if "device_offline" in off:
        changes.append(("unreachable", "telegram", "never"))
    if "watch" in off:
        changes.append(("watch", "telegram", "never"))
    if changes:
        database.set_alert_overrides("global", "", changes)
        log.info("Moved %d alert setting(s) into the alert rules", len(changes))
    stale = [k for k in existing if (k.startswith("threshold_") or k.startswith("notify_on_")) and k not in SETTINGS]
    if stale:
        database.delete_settings(stale)


def initialise() -> None:
    """Loads the vault, migrates the database and settings. Used by start_server and the tests."""
    VAULT.load(os.path.dirname(os.path.abspath(database.DB_FILE)))
    database.init_db()
    customoids.ensure_schema()
    availability.init()
    # Re-encrypt before anything reads a secret, so the rest of startup sees one key.
    if VAULT.rekey_pending:
        moved = database.rekey_secrets()
        VAULT.finish_rekey()
        log.info("Vault key moved to %s; re-encrypted %d secret(s) with a new key", VAULT.key_path, moved)

    existing = database.get_all_settings()
    if "raw_retention_days" not in existing and existing.get("metric_retention_days") == "30":
        # metric_retention_days used to mean raw retention; it now means hourly trend retention.
        database.update_setting("metric_retention_days", SETTINGS["metric_retention_days"]["default"])
    migrate_alert_settings(existing)
    moved = migrate_tasks_to_workflows()
    if moved:
        log.info("Converted %d SSH task(s) into workflows", moved)
    given = migrate_credentials_use()
    if given:
        log.info("Gave %d user(s) the Use stored credentials permission", given)
    skipped = check_workflow_scope()
    if skipped:
        log.info("%d saved workflow(s) reach past their author's device access", skipped)
    raised = migrate_retention(existing)
    security_notice(existing, database.get_account() is not None, raised)
    database.ensure_settings([(s["key"], s["default"], s["help"] or s["label"]) for s in SETTINGS.values()])
    tls.first_run(existing, database.get_account() is not None)
    changelog.first_run(existing, database.get_account() is not None)
    cleanup_untracked_history()
    encrypted = database.encrypt_existing_secrets()
    if encrypted:
        log.info("Encrypted %d plaintext secret(s) with the vault key", encrypted)
    if not setup.is_completed() and database.list_devices():
        setup.mark_completed()
    if encrypted or database.plaintext_residue_possible():
        # Rewrite the file so plaintext from before encryption does not survive in free pages or the WAL.
        database.compact_secure()
        log.info("Database compacted to remove pre-encryption plaintext from free pages")
    # Last: the file now has every table and column of this build.
    database.mark_schema()


def open_listener(tries: int = 90, wait: float = 2.0) -> "ThreadingServer":
    """The web port, opened before anything else starts. Still taken (a previous copy shutting down):
    wait and try again for up to three minutes, rather than fail and be restarted over and over. A
    version before 0.11.1 opened the port without address reuse, so the connections it leaves behind
    keep the port from this one for a minute or two after it stops."""
    import errno
    for attempt in range(tries):
        try:
            return ThreadingServer((LISTEN_HOST, LISTEN_PORT), ApiRequestHandler)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE or attempt == tries - 1:
                raise
            if attempt == 0:
                log.warning("Port %s is still in use (the previous copy is stopping?): waiting for it", LISTEN_PORT)
            time.sleep(wait)
    raise RuntimeError("unreachable")


def start_server() -> None:
    """Initializes the database and starts the scheduler and HTTP server."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    initialise()
    # The port first: when it cannot be opened, nothing else has started (no polling, no messages).
    httpd = open_listener()
    NOTIFIER.start()
    BOT.start()

    tls.load()
    try:
        watch_root_results()
    except Exception:
        log.exception("Could not read the restore and update results")
    threading.Thread(target=scheduler.run_forever, daemon=True, name="scheduler").start()
    threading.Thread(target=_auto_update_loop, daemon=True, name="update-check").start()
    logging.getLogger().addHandler(RECENT_LOG)

    print(f"Server listening on {'https' if tls.SERVER.context else 'http'}://{LISTEN_HOST}:{LISTEN_PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == "__main__":
    start_server()
