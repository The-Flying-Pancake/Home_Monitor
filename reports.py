"""Reports: ready-made templates the user can adjust, laid out as a proper report, as CSV or PDF.

A report is a spec:
  {"template": "devices", "period": "7d", "filter": {"group": "", "tag": "", "device": 0},
   "columns": ["name", "ip", ...], "sort": {"column": "name", "desc": false}, "limit": 0, "title": ""}

The server decides which devices the user may see, applies the group, tag or device filter and
hands run() the devices that are left, already described in plain words (DeviceInfo below). This
module never sees another user's devices and never a secret: a v3 device shows its user and
security level, never a password.

Every report has the same layout, on the page and in the PDF:
  1. a header band: the title, what the report is for, the period, what it covers (a single
     device adds its details) and when it was made
  2. three to six key figures (KPI tiles), each with a status edge and, where the data allows,
     the change on the previous period of the same length
  3. a short summary in plain words, written from the data
  4. one main chart that answers the report's question, then supporting charts two to a row
  5. the detail tables, with status shown as coloured pills
  6. a footer naming where the data comes from (times are local)

Each template lists every column of its main table; the user picks which and in what order (the
customizer). Rows hold raw values (numbers, Unix times) with a type per column, so the table, the
CSV and the PDF each format them their own way. The CSV is the main table only.

Colours: green, amber and red only for status ("good", "warn", "bad"), blue for neutral figures
("info") and grey for no data ("none"); ordinary series take the app's blue, teal and purple.
"""

import bisect
import csv
import io
import math
import re
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

import database

PERIODS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400}
PERIOD_NAMES = {"24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days", "90d": "the last 90 days"}
PREVIOUS_NAMES = {"24h": "the previous 24 hours", "7d": "the previous 7 days", "30d": "the previous 30 days",
                  "90d": "the previous 90 days"}
MAX_ROWS = 5000
PREVIEW_ROWS = 500

# Targets and thresholds the reports judge against (the owner's guide: say what good looks like).
UPTIME_TARGET = 99.9          # percent of checks answered
PING_TARGET_MS = 50.0         # typical (median) ping
LOAD_WARN, LOAD_BAD = 80.0, 90.0        # processor, memory and disk use, percent
LINK_WARN, LINK_BAD = 70.0, 90.0        # interface utilisation at the 95th percentile, percent
WEAK_SIGNAL_DBM = -70

# Pill colours for the values of the "pill" columns (anything else is grey).
PILL_TONES = {
    "Online": "good", "Up": "good", "Degraded": "warn", "Offline": "bad", "Down": "bad", "Unknown": "none",
    "Answers": "good", "No answer": "bad",
    "Met": "good", "At risk": "warn", "Breached": "bad", "No data": "none",
    "Critical": "bad", "High": "bad", "Warning": "warn", "Info": "info",
    "Still open": "bad", "Resolved": "good",
    "OK": "good", "Watch": "warn", "Strained": "bad", "Nearly full": "warn", "Full soon": "bad",
    "Good": "good", "Fair": "warn", "Weak": "bad", "Spiky": "warn", "Slow": "bad",
    "Quiet": "good", "Busy": "warn", "Saturated": "bad", "No speed": "none",
    "Running": "good", "Paused": "warn", "Stopped": "none",
    "On": "good", "Off": "bad", "Yes": "good", "No": "warn",
    "Finished": "good", "Failed": "bad", "Acknowledged": "info", "Open": "bad",
}


class ReportError(ValueError):
    """A spec that cannot be run, in words for the user."""


# DeviceInfo (a dict the server makes for each visible device):
#   id, name, ip, group, tags (list), kind (template name), snmp ("v2c", "v3" or "" when not read over
#   SNMP), snmp_security ("user monitor, signed and encrypted, SHA and AES" or ""), snmp_answer
#   ("Answers", "No answer" or ""), status, last_seen, ping_ms, check ("Port 443" for a service check).

# Column: (key, label, type). Types: text, num, pct, ms, time, bytes, duration, mbps, dbm, bps,
# pill (a status word shown as a coloured label) and spark (a small trend line; not in the CSV).
Column = Tuple[str, str, str]


def _col(key: str, label: str, kind: str = "text") -> Column:
    return (key, label, kind)


DEVICE_COLS = [_col("name", "Name"), _col("ip", "Address"), _col("group", "Group"), _col("tags", "Tags")]
SEVERITY_COLS = [_col("severity", "Severity", "pill")]

TEMPLATES: Dict[str, Dict[str, Any]] = {
    "monthly": {
        "title": "Monthly health summary",
        "description": "The month at a glance for anyone who wants the short version: availability, typical ping, problems and the devices now, with the top issues.",
        "purpose": "How the network did over the period, in a few figures and the issues that came up most.",
        "sources": "ping and service checks, SNMP and the problem log",
        "period": True, "default_period": "30d", "all_devices": False,
        "columns": [_col("problem", "Issue"), SEVERITY_COLS[0], _col("count", "Times", "num"), _col("devices", "Devices", "num"),
                    _col("where", "Where"), _col("last", "Last seen", "time"), _col("state", "Now", "pill")],
        "default": ["problem", "severity", "count", "devices", "where", "last", "state"],
        "sort": "count", "desc": True, "table_title": "Top issues",
    },
    "status": {
        "title": "Status now",
        "description": "A one page handover: what is up, down or has a problem right now, the open problems and the busiest processors to keep an eye on.",
        "purpose": "Where things stand right now, for a handover or a quick look before changes.",
        "sources": "ping and service checks, SNMP and the open problems",
        "period": False, "all_devices": False,
        "columns": [_col("name", "Device"), _col("ip", "Address"), _col("group", "Group"), SEVERITY_COLS[0],
                    _col("problem", "Problem"), _col("since", "Since", "time"), _col("ack", "Handled", "pill")],
        "default": ["name", "severity", "problem", "since", "ack"],
        "sort": "since", "table_title": "Open problems",
    },
    "availability": {
        "title": "Availability",
        "description": "Uptime, time down and how often each device went down over the period, against a 99.9% target.",
        "purpose": "Whether each device was reachable when it should be, measured against a 99.9% target.",
        "sources": "ping and service checks",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("uptime", "Uptime", "pct"), _col("down", "Time down", "duration"),
                                  _col("outages", "Outages", "num"), _col("avg_ms", "Average response", "ms"),
                                  _col("target", "Against 99.9%", "pill"), _col("status", "Status now", "pill")],
        "default": ["name", "ip", "group", "uptime", "down", "outages", "avg_ms", "target"],
        "sort": "uptime", "table_title": "Uptime per device",
    },
    "latency": {
        "title": "Latency (ping)",
        "description": "How fast each device answers ping: typical (median) and 95th percentile, against a 50 ms target.",
        "purpose": "How quickly devices answer, so slow or uneven links stand out.",
        "sources": "ping",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("min", "Fastest", "ms"), _col("median", "Typical (median)", "ms"),
                                  _col("p95", "95th percentile", "ms"), _col("max", "Slowest", "ms"),
                                  _col("trend", "Trend", "spark"), _col("state", "Against 50 ms", "pill")],
        "default": ["name", "ip", "min", "median", "p95", "max", "trend", "state"],
        "sort": "p95", "desc": True, "table_title": "Ping per device",
    },
    "bandwidth": {
        "title": "Interface bandwidth",
        "description": "The busiest network interfaces by 95th percentile, the internet link in and out, when it is busiest and how full each link runs.",
        "purpose": "Which links carry the most traffic and whether any of them is running full.",
        "sources": "SNMP interface counters",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("interface", "Interface"), _col("speed", "Speed", "mbps"), _col("in_p95", "In (95th pct)", "bps"),
                                  _col("out_p95", "Out (95th pct)", "bps"), _col("peak", "Peak", "bps"),
                                  _col("util", "Use (95th pct)", "pct"), _col("state", "Load", "pill")],
        "default": ["name", "interface", "speed", "in_p95", "out_p95", "peak", "util", "state"],
        "sort": "util", "desc": True, "table_title": "Interfaces",
    },
    "alerts": {
        "title": "Alerts and events summary",
        "description": "How noisy the period was: events per day by severity, the noisiest devices, the busiest hours and the most common problems.",
        "purpose": "Where the alerts and events came from, so noisy devices and repeat problems can be dealt with.",
        "sources": "the event log and the problem log",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("events", "Events", "num"), _col("problems", "Problems", "num"),
                                  _col("critical", "Critical", "num"), _col("warnings", "Warnings", "num"),
                                  _col("last", "Last event", "time"), _col("worst", "Worst", "pill")],
        "default": ["name", "ip", "events", "problems", "critical", "warnings", "last", "worst"],
        "sort": "events", "desc": True, "table_title": "Events per device",
    },
    "device": {
        "title": "Single device",
        "description": "Everything about one device: its details, availability, processor and memory against their limits, ping, interfaces and storage.",
        "purpose": "A close look at one device over the period.",
        "sources": "ping and service checks, SNMP and the problem log",
        "period": True, "all_devices": False, "one_device": True,
        "columns": [_col("interface", "Interface"), _col("speed", "Speed", "mbps"), _col("in_p95", "In (95th pct)", "bps"),
                    _col("out_p95", "Out (95th pct)", "bps"), _col("peak", "Peak", "bps"), _col("util", "Use (95th pct)", "pct"),
                    _col("state", "Load", "pill")],
        "default": ["interface", "speed", "in_p95", "out_p95", "peak", "util", "state"],
        "sort": "in_p95", "desc": True, "table_title": "Interfaces",
    },
    "health": {
        "title": "Device health",
        "description": "Processor and memory over the period (average and 95th percentile) and the fullest disk now, against 80% and 90% limits.",
        "purpose": "Which devices are working hard or running short of memory or disk space.",
        "sources": "SNMP",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("cpu_avg", "CPU average", "pct"), _col("cpu_p95", "CPU 95th pct", "pct"),
                                  _col("cpu_max", "CPU highest", "pct"), _col("mem_avg", "Memory average", "pct"),
                                  _col("mem_p95", "Memory 95th pct", "pct"), _col("mem_max", "Memory highest", "pct"),
                                  _col("disk_max", "Fullest disk", "pct"), _col("disk_name", "Which disk"), _col("state", "Load", "pill")],
        "default": ["name", "group", "cpu_avg", "cpu_p95", "mem_avg", "mem_p95", "disk_max", "disk_name", "state"],
        "sort": "cpu_p95", "desc": True, "table_title": "Load per device",
    },
    "storage": {
        "title": "Storage and when it fills up",
        "description": "Every disk, volume and storage pool: size, use and the date it is expected to be full at the current rate.",
        "purpose": "How full each disk and volume is and which ones will run out of space soon.",
        "sources": "SNMP and the storage forecast",
        "period": False, "all_devices": False,
        "columns": [_col("name", "Device"), _col("ip", "Address"), _col("group", "Group"), _col("storage", "Storage"),
                    _col("size", "Size", "bytes"), _col("used", "Used", "bytes"), _col("used_pct", "Used %", "pct"),
                    _col("full_on", "Full around", "time"), _col("state", "State", "pill")],
        "default": ["name", "storage", "size", "used", "used_pct", "full_on", "state"],
        "sort": "used_pct", "desc": True, "table_title": "Disks and volumes",
    },
    "problems": {
        "title": "Problems",
        "description": "Every problem that opened in the period: when, on which device, how serious and whether it is still open.",
        "purpose": "Every problem that opened in the period and whether it has been fixed.",
        "sources": "the problem log",
        "period": True, "all_devices": False,
        "columns": [_col("time", "Opened", "time"), _col("name", "Device"), _col("ip", "Address"), _col("group", "Group"),
                    SEVERITY_COLS[0], _col("problem", "Problem"), _col("state", "Now", "pill")],
        "default": ["time", "name", "severity", "problem", "state"],
        "sort": "time", "desc": True, "table_title": "Problems",
    },
    "events": {
        "title": "Events",
        "description": "Everything that happened to the devices in the period: problems, recoveries, restarts, changes and messages.",
        "purpose": "A record of everything that happened to the devices in the period.",
        "sources": "the event log",
        "period": True, "all_devices": False,
        "columns": [_col("time", "When", "time"), _col("name", "Device"), _col("ip", "Address"), SEVERITY_COLS[0],
                    _col("type", "Type"), _col("message", "What happened")],
        "default": ["time", "name", "severity", "type", "message"],
        "sort": "time", "desc": True, "table_title": "Events",
    },
    "devices": {
        "title": "Devices and SNMP settings",
        "description": "Every device with its group, tags, template and how it is read: SNMP v2c or v3, and whether it answers. Handy before moving devices to SNMPv3.",
        "purpose": "How each device is read and which ones still use SNMP v2c.",
        "sources": "the device list and SNMP",
        "period": False, "all_devices": False,
        "columns": DEVICE_COLS + [_col("kind", "Template"), _col("snmp", "SNMP"), _col("snmp_security", "SNMPv3 settings"),
                                  _col("snmp_answer", "SNMP answers", "pill"), _col("status", "Status", "pill"), _col("ping_ms", "Ping", "ms"),
                                  _col("last_seen", "Last seen", "time")],
        "default": ["name", "ip", "group", "kind", "snmp", "snmp_security", "snmp_answer", "status"],
        "sort": "name", "table_title": "Devices",
    },
    "wifi": {
        "title": "Wi-Fi devices",
        "description": "Every device on Wi-Fi (from UniFi): access point, network, band, signal and experience.",
        "purpose": "Who is on Wi-Fi right now and how good their connection is.",
        "sources": "UniFi",
        "period": False, "all_devices": False,
        "columns": [_col("client", "Device"), _col("mac", "MAC address"), _col("client_ip", "Address"), _col("vendor", "Maker"),
                    _col("name", "Access point"), _col("ssid", "Network"), _col("band", "Band"), _col("signal", "Signal", "dbm"),
                    _col("quality", "Signal quality", "pill"), _col("experience", "Experience", "pct"), _col("tx_mbps", "Link speed", "mbps"),
                    _col("uptime", "Connected for", "duration")],
        "default": ["client", "name", "ssid", "band", "signal", "quality", "experience"],
        "sort": "signal", "table_title": "Wi-Fi devices",
    },
    "proxmox": {
        "title": "Proxmox guests",
        "description": "Virtual machines and containers: where they run, state, memory and disk, and whether they start with the host.",
        "purpose": "The virtual machines and containers, whether they run and what they use.",
        "sources": "Proxmox",
        "period": False, "all_devices": True,
        "columns": [_col("guest", "Guest"), _col("vmid", "ID", "num"), _col("type", "Kind"), _col("node", "Node"),
                    _col("state", "State", "pill"), _col("mem", "Memory used", "bytes"), _col("maxmem", "Memory", "bytes"),
                    _col("maxdisk", "Disk", "bytes"), _col("uptime", "Running for", "duration"), _col("onboot", "Starts with host"),
                    _col("name", "Monitored as")],
        "default": ["guest", "vmid", "type", "node", "state", "mem", "maxmem", "maxdisk", "onboot"],
        "sort": "vmid", "table_title": "Guests",
    },
    "pihole": {
        "title": "Pi-hole",
        "description": "Each Pi-hole: queries and blocked today, clients, block list size and age, and the most blocked domains.",
        "purpose": "What the Pi-holes answered and blocked today and whether their lists are fresh.",
        "sources": "Pi-hole",
        "period": False, "all_devices": False,
        "columns": [_col("name", "Pi-hole"), _col("ip", "Address"), _col("blocking", "Blocking", "pill"), _col("queries", "Queries today", "num"),
                    _col("blocked", "Blocked today", "num"), _col("blocked_pct", "Blocked %", "pct"), _col("clients", "Clients", "num"),
                    _col("domains", "Domains on the lists", "num"), _col("gravity_days", "Lists updated (days ago)", "num"),
                    _col("dns_ms", "Answer time", "ms")],
        "default": ["name", "blocking", "queries", "blocked", "blocked_pct", "clients", "domains", "gravity_days"],
        "sort": "name", "table_title": "Pi-holes",
    },
    "new_devices": {
        "title": "New and changed devices on the network",
        "description": "Devices first seen on the network in the period (Inventory), with maker, address and where they were seen.",
        "purpose": "Which devices joined the network in the period and whether they are known.",
        "sources": "the inventory (UniFi and the network scan)",
        "period": True, "all_devices": True,
        "columns": [_col("first_seen", "First seen", "time"), _col("client", "Name"), _col("mac", "MAC address"),
                    _col("client_ip", "Address"), _col("vendor", "Maker"), _col("where", "Seen on"), _col("ssid", "Network"),
                    _col("known", "Known", "pill"), _col("last_seen", "Last seen", "time")],
        "default": ["first_seen", "client", "mac", "client_ip", "vendor", "where", "known"],
        "sort": "first_seen", "desc": True, "table_title": "New devices",
    },
    "updates": {
        "title": "Monitor updates",
        "description": "Updates, upgrades and undos of the monitor itself, with the result of each.",
        "purpose": "The updates of the monitor itself and whether each one worked.",
        "sources": "the monitor's update history",
        "period": True, "all_devices": True,
        "columns": [_col("time", "When", "time"), _col("kind", "What"), _col("from", "From"), _col("to", "To"),
                    _col("result", "Result", "pill"), _col("error", "Error")],
        "default": ["time", "kind", "from", "to", "result", "error"],
        "sort": "time", "desc": True, "table_title": "Updates",
    },
}
TEMPLATE_ORDER = ["monthly", "status", "availability", "latency", "bandwidth", "alerts", "device", "health", "storage",
                  "problems", "events", "devices", "wifi", "proxmox", "pihole", "new_devices", "updates"]


def template_list(all_devices: bool) -> List[Dict[str, Any]]:
    """The templates this user can run, for the Reports page. Network-wide ones need every device."""
    out = []
    for tid in TEMPLATE_ORDER:
        t = TEMPLATES[tid]
        if t["all_devices"] and not all_devices:
            continue
        out.append({"id": tid, "title": t["title"], "description": t["description"], "period": t["period"],
                    "default_period": t.get("default_period", "7d"), "one_device": bool(t.get("one_device")),
                    "columns": [{"key": k, "label": l, "type": ty} for k, l, ty in t["columns"]],
                    "default": t["default"], "sort": t["sort"], "desc": bool(t.get("desc"))})
    return out


def parse_spec(raw: Any, all_devices: bool) -> Dict[str, Any]:
    """Checks a spec from the browser or a saved report; unknown parts fall back to the template's own."""
    if not isinstance(raw, dict):
        raise ReportError("A report needs a template")
    tid = raw.get("template")
    if tid not in TEMPLATES:
        raise ReportError("Choose a report template")
    t = TEMPLATES[tid]
    if t["all_devices"] and not all_devices:
        raise ReportError("This report needs access to every device")
    keys = [c[0] for c in t["columns"]]
    cols = raw.get("columns")
    cols = [c for c in cols if c in keys] if isinstance(cols, list) else []
    cols = list(dict.fromkeys(cols)) or list(t["default"])
    period = raw.get("period") if raw.get("period") in PERIODS else t.get("default_period", "7d")
    flt = raw.get("filter") if isinstance(raw.get("filter"), dict) else {}
    device = flt.get("device")
    out_filter = {"group": str(flt.get("group") or "")[:64], "tag": str(flt.get("tag") or "")[:64],
                  "device": device if isinstance(device, int) and not isinstance(device, bool) and device > 0 else 0}
    sort = raw.get("sort") if isinstance(raw.get("sort"), dict) else {}
    column = sort.get("column") if sort.get("column") in keys else t["sort"]
    desc = bool(sort.get("desc")) if "desc" in sort else bool(t.get("desc"))
    limit = raw.get("limit")
    limit = limit if isinstance(limit, int) and not isinstance(limit, bool) and 0 < limit <= MAX_ROWS else 0
    title = " ".join(str(raw.get("title") or "").split())[:120]
    return {"template": tid, "period": period, "filter": out_filter, "columns": cols,
            "sort": {"column": column, "desc": desc}, "limit": limit, "title": title}


# --- Words and numbers ------------------------------------------------------------------------------

def _and(items: List[str]) -> str:
    """A list in words, without a comma before the last one: "a, b and c"."""
    items = [i for i in items if i]
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _plural(n: float, one: str, many: str = "") -> str:
    n = int(n)
    return f"{n} {one if n == 1 else (many or one + 's')}"


WORDS = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve"]


def _count(n: float, one: str, many: str = "") -> str:
    """A count to start a sentence with a capital: "Seven problems", "In all 41 events"."""
    n = int(n)
    noun = one if n == 1 else (many or one + "s")
    return f"{WORDS[n]} {noun}" if 0 <= n < len(WORDS) else f"In all {n} {noun}"


def _pct_text(v: Optional[float]) -> str:
    if v is None:
        return "No data"
    return f"{v:.2f}%" if 99 <= v < 100 else f"{v:.1f}%"


def _minutes(seconds: float) -> str:
    m = seconds / 60.0
    if m < 1:
        return "under a minute" if seconds > 0 else "0 minutes"
    if m < 120:
        return _plural(round(m), "minute")
    if m < 48 * 60:
        return f"{m / 60:.1f} hours"
    return f"{m / 1440:.1f} days"


def _ms(v: Optional[float]) -> str:
    return "No data" if v is None else (f"{v:.0f} ms" if v >= 10 else f"{v:.1f} ms")


def _bps(v: Optional[float]) -> str:
    if v is None:
        return "No data"
    units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
    i = 0
    while abs(v) >= 1000 and i < len(units) - 1:
        v /= 1000.0
        i += 1
    return f"{v:.0f} {units[i]}" if i == 0 or v >= 100 else f"{v:.1f} {units[i]}"


def _on_day(ts: float, span: int) -> str:
    """When something happened, as fits the period: "at 14:05", "on Tuesday" or "on 3 Nov"."""
    d = datetime.fromtimestamp(ts)
    if span <= 86400:
        return "at " + d.strftime("%H:%M")
    if span <= 7 * 86400:
        return "on " + d.strftime("%A")
    return "on " + f"{d.day} {d.strftime('%b')}"


def _date(ts: float, with_time: bool = True) -> str:
    d = datetime.fromtimestamp(ts)
    return f"{d.day} {d.strftime('%b %Y')}" + (d.strftime(" %H:%M") if with_time else "")


def _tz() -> str:
    off = time.strftime("%z")
    return f"UTC{off[:3]}:{off[3:]}" if len(off) == 5 else "local time"


def _tone_at(value: Optional[float], warn: float, bad: float, high_is_bad: bool = True) -> str:
    """good, warn or bad against two limits (none without a value)."""
    if value is None:
        return "none"
    if high_is_bad:
        return "bad" if value >= bad else "warn" if value >= warn else "good"
    return "bad" if value < bad else "warn" if value < warn else "good"


def _uptime_tone(v: Optional[float]) -> str:
    return _tone_at(v, UPTIME_TARGET, 99.0, high_is_bad=False)


def _kpi(label: str, value: str, tone: str = "info", sub: str = "", note: str = "", trend: Optional[str] = None) -> Dict[str, Any]:
    return {"label": label, "value": value, "tone": tone if tone in ("good", "warn", "bad", "info", "none") else "info",
            "sub": sub, "note": note, "trend": trend}


def _change(cur: Optional[float], prev: Optional[float], period: str, kind: str, better: str) -> Tuple[str, Optional[str]]:
    """The change on the previous period in words and whether it is good: ("Up 0.03 points on the
    previous 7 days", "good"). kind: points, ms, count, minutes or bps. better: up or down."""
    if cur is None or prev is None:
        return "", None
    d = cur - prev
    small = {"points": 0.005, "ms": 0.5, "count": 0.5, "minutes": 0.5, "bps": 1.0}[kind]
    where = PREVIOUS_NAMES[period]
    if abs(d) < small:
        return f"Same as {where}", "neutral"
    size = abs(d)
    amount = {"points": f"{size:.2f} points" if size < 10 else f"{size:.0f} points",
              "ms": f"{size:.0f} ms" if size >= 10 else f"{size:.1f} ms",
              "count": f"{size:.0f}", "minutes": _minutes(size * 60), "bps": _bps(size)}[kind]
    good = (d > 0) == (better == "up")
    return f"{'Up' if d > 0 else 'Down'} {amount} on {where}", "good" if good else "bad"


def _quantile(values: List[float], q: float) -> Optional[float]:
    """Nearest-rank percentile (q from 0 to 1)."""
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, max(0, int(math.ceil(q * len(v))) - 1))]


def _median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    mid = len(v) // 2
    return v[mid] if len(v) % 2 else (v[mid - 1] + v[mid]) / 2


def _mean(values: List[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


# --- Reading the stored data ------------------------------------------------------------------------

def _series(device_id: int, key: str, start: int, end: int, positive: bool = False) -> List[Tuple[int, float, float]]:
    """(time, value, peak) samples of one metric: raw samples where they are still kept, hourly
    averages before that. positive drops zero readings (a ping that got no answer is stored as 0),
    and the hours that held one."""
    with database.get_connection() as conn:
        oldest = conn.execute("SELECT MIN(timestamp) FROM metrics WHERE device_id = ? AND metric_key = ?;",
                              (device_id, key)).fetchone()[0]
        boundary = end if oldest is None else max(start, oldest - oldest % 3600 + 3600)
        out: List[Tuple[int, float, float]] = []
        if boundary > start:
            sql = ("SELECT hour, avg, max FROM metrics_hourly WHERE device_id = ? AND metric_key = ? AND hour >= ? AND hour < ?"
                   + (" AND min > 0" if positive else "") + " ORDER BY hour;")
            out = [(r[0], r[1], r[2]) for r in conn.execute(sql, (device_id, key, start - start % 3600, boundary))]
        sql = ("SELECT timestamp, value FROM metrics WHERE device_id = ? AND metric_key = ? AND timestamp >= ? AND timestamp <= ?"
               + (" AND value > 0" if positive else "") + " ORDER BY timestamp;")
        out += [(r[0], r[1], r[1]) for r in conn.execute(sql, (device_id, key, max(start, boundary), end))]
    return out


def _thin(samples: List[Tuple[int, float, float]], start: int, end: int, count: int = 150,
          how: Callable[[List[float]], Optional[float]] = _mean) -> List[Tuple[int, Optional[float]]]:
    """Samples averaged into at most count even steps for a chart; an empty step is None (a gap)."""
    if not samples:
        return []
    size = max(60, (end - start) // count)
    steps: Dict[int, List[float]] = {}
    for t, v, _ in samples:
        steps.setdefault((t - start) // size, []).append(v)
    out = []
    last = max(steps)
    for n in range(min(steps), last + 1):
        vals = steps.get(n)
        out.append((start + n * size + size // 2, round(how(vals), 3) if vals else None))
    return out


def _hourly_avgs(ids: List[int], key: str, start: int, end: int, positive: bool = False) -> Dict[int, List[float]]:
    """The hourly averages of one metric per device (cheap, for comparing two periods alike)."""
    out: Dict[int, List[float]] = {}
    if not ids:
        return out
    marks = ",".join("?" * len(ids))
    with database.get_connection() as conn:
        for r in conn.execute(f"SELECT device_id, avg FROM metrics_hourly WHERE device_id IN ({marks}) AND metric_key = ? "
                              f"AND hour >= ? AND hour < ?" + (" AND min > 0" if positive else "") + ";",
                              (*ids, key, start - start % 3600, end)):
            out.setdefault(r[0], []).append(r[1])
    return out


def _avail(ids: List[int], start: int, end: int) -> Dict[int, List[Tuple[int, int, int, float, int]]]:
    """Per device: the hours of checks (hour, checks, up checks, response sum, responses) in the window."""
    out: Dict[int, List[Tuple[int, int, int, float, int]]] = {i: [] for i in ids}
    if not ids:
        return out
    marks = ",".join("?" * len(ids))
    with database.get_connection() as conn:
        for r in conn.execute(f"SELECT device_id, hour, checks, ups, ms_sum, ms_count FROM avail_hourly WHERE device_id IN ({marks}) "
                              "AND hour >= ? AND hour < ? ORDER BY hour;", (*ids, start - start % 3600, end)):
            out[r[0]].append((r[1], r[2], r[3], r[4], r[5]))
    return out


def _uptime(hours: List[Tuple[int, int, int, float, int]]) -> Optional[float]:
    checks = sum(h[1] for h in hours)
    return round(100.0 * sum(h[2] for h in hours) / checks, 3) if checks else None


def _avg_response(hours: List[Tuple[int, int, int, float, int]]) -> Optional[float]:
    n = sum(h[4] for h in hours)
    return round(sum(h[3] for h in hours) / n, 2) if n else None


def _incidents(ids: List[int], start: int, end: int) -> Dict[int, List[Tuple[int, int]]]:
    """Per device: the down periods inside the window (start, seconds), cut to the window."""
    out: Dict[int, List[Tuple[int, int]]] = {}
    if not ids:
        return out
    marks = ",".join("?" * len(ids))
    with database.get_connection() as conn:
        for r in conn.execute(f"SELECT device_id, started, ended FROM avail_incidents WHERE device_id IN ({marks}) "
                              "AND (ended IS NULL OR ended >= ?) AND started <= ?;", (*ids, start, end)):
            a, b = max(r["started"], start), min(r["ended"] or end, end)
            out.setdefault(r["device_id"], []).append((r["started"], max(0, b - a)))
    return out


def _slots(start: int, end: int) -> Tuple[List[int], str]:
    """Steps for per-day charts: hours for a day or less, else local days. Returns their starts and
    a strftime pattern for their labels."""
    if end - start <= 86400 + 3600:
        first = start - start % 3600
        return list(range(first, end, 3600)), "%H:00"
    day = datetime.fromtimestamp(start).replace(hour=0, minute=0, second=0, microsecond=0)
    out = []
    while day.timestamp() < end:
        out.append(int(day.timestamp()))
        day = (day + timedelta(days=1, hours=2)).replace(hour=0)
    return out, "%a %d" if end - start <= 8 * 86400 else "%d %b"


def _slot_of(starts: List[int], ts: float) -> int:
    return max(0, bisect.bisect_right(starts, ts) - 1)


def _slot_labels(starts: List[int], fmt: str) -> List[str]:
    return [datetime.fromtimestamp(s).strftime(fmt).replace(" 0", " ") for s in starts]


def _stem(message: str) -> str:
    """A problem's text up to its first number, so a changing value is still the same problem."""
    return re.split(r"\d", message, maxsplit=1)[0].strip().rstrip(":(,").strip()


def _key(message: str) -> str:
    """A problem's text with its numbers taken out: the same problem with other values groups together."""
    return re.sub(r"\d+(?:[.,]\d+)?", "#", message).strip()


def _common(texts: List[str]) -> List[Tuple[str, int]]:
    """The problems that came up most, each shown by its first text (the newest, as events come newest first)."""
    groups: Dict[str, List[Any]] = {}
    for t in texts:
        g = groups.setdefault(_key(t), [t, 0])
        g[1] += 1
    return sorted(((t, n) for t, n in groups.values()), key=lambda p: -p[1])


def _sev(value: Any) -> str:
    """A severity as shown: Critical, High, Warning or Info."""
    return str(value or "info").capitalize()


def _problem_events(ids: List[int], start: int, end: int) -> List[Dict[str, Any]]:
    if not ids:
        return []
    events, _ = database.list_events_filtered(event_type="problem", since=start, until=end, device_ids=set(ids), limit=MAX_ROWS)
    return [e for e in events if str(e["message"]).startswith("Problem: ")]


def _severity_columns(events: List[Dict[str, Any]], start: int, end: int, title: str, note: str) -> Dict[str, Any]:
    """Events per day (or hour), stacked by severity: critical and high red, warning amber, info blue."""
    starts, fmt = _slots(start, end)
    groups = [("Critical and high", "bad", ("critical", "high")), ("Warning", "warn", ("warning",)), ("Info", "info", ("info",))]
    values = {name: [0] * len(starts) for name, _, _ in groups}
    for e in events:
        sev = str(e["severity"]).lower()
        for name, _, members in groups:
            if sev in members:
                values[name][_slot_of(starts, e["timestamp"])] += 1
    series = [{"name": name, "tone": tone, "values": values[name]} for name, tone, _ in groups if any(values[name])]
    return {"kind": "columns", "title": title, "note": note, "labels": _slot_labels(starts, fmt), "series": series,
            "stacked": True, "unit": "", "whole": True}


def _hour_of_day(times: List[float], title: str, note: str) -> Dict[str, Any]:
    counts = [0] * 24
    for t in times:
        counts[datetime.fromtimestamp(t).hour] += 1
    return {"kind": "columns", "title": title, "note": note, "labels": [f"{h:02d}" for h in range(24)],
            "series": [{"name": "Events", "values": counts}], "unit": "", "whole": True}


def _bars(title: str, note: str, pairs: List[Tuple[str, float]], unit: str = "", top: int = 8, **extra: Any) -> Dict[str, Any]:
    return dict({"kind": "bar", "title": title, "note": note, "unit": unit, "bars": [[l, v] for l, v in pairs[:top]]}, **extra)


def _bar_counts(title: str, values: List[str], top: int = 12, note: str = "") -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    bars = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {"kind": "bar", "title": title, "note": note, "unit": "", "bars": [[l, n] for l, n in bars]}


def _capacity(title: str, note: str, items: List[Tuple[str, Optional[float]]], warn: float, bad: float, top: int = 8) -> Dict[str, Any]:
    """Bars from 0 to 100%, each coloured by its limit, with the limits drawn as lines."""
    shown = sorted([(l, v) for l, v in items if v is not None], key=lambda p: -p[1])[:top]
    return {"kind": "bar", "title": title, "note": note, "unit": "%", "max": 100,
            "bars": [[l, round(v, 1), _tone_at(v, warn, bad)] for l, v in shown],
            "thresholds": [{"value": warn, "tone": "warn", "label": f"{warn:.0f}%"}, {"value": bad, "tone": "bad", "label": f"{bad:.0f}%"}]}


def _donut(title: str, note: str, segments: List[Tuple[str, float, Optional[str]]], total_label: str) -> Dict[str, Any]:
    segs = [{"label": l, "value": v, "tone": t} for l, v, t in segments if v]
    return {"kind": "donut", "title": title, "note": note, "segments": segs, "total": sum(s["value"] for s in segs),
            "total_label": total_label}


def _status_word(d: Dict[str, Any]) -> str:
    s = str(d.get("status") or "").lower()
    return {"online": "Online", "degraded": "Degraded", "offline": "Offline"}.get(s, "Unknown")


def _now_state(devices: List[Dict[str, Any]]) -> Dict[int, Tuple[str, str, str]]:
    """Per device: (Up, Problems, Down or Not monitored), its tone and a short line for a status tile."""
    open_by: Dict[int, List[Dict[str, Any]]] = {}
    for p in database.list_active_problems():
        open_by.setdefault(p["device_id"], []).append(p)
    out = {}
    for d in devices:
        s = str(d.get("status") or "").lower()
        probs = open_by.get(d["id"], [])
        if s == "offline":
            out[d["id"]] = ("Down", "bad", "Down" + (f" since {datetime.fromtimestamp(d['last_seen']).strftime('%d %b %H:%M')}" if d.get("last_seen") else ""))
        elif s not in ("online", "degraded") or not d.get("last_seen"):
            out[d["id"]] = ("Not monitored", "none", "No checks yet")
        elif probs or s == "degraded":
            out[d["id"]] = ("Problems", "warn", probs[0]["message"] if probs else "Service not answering")
        else:
            out[d["id"]] = ("Up", "good", f"Up, {_ms(d['ping_ms'])}" if d.get("ping_ms") else "Up")
    return out


def _base(d: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": d["name"], "ip": d["ip"], "group": d["group"], "tags": ", ".join(d.get("tags") or [])}


def _result(rows: List[Dict[str, Any]], kpis: Optional[List[Dict[str, Any]]] = None, summary: str = "",
            main: Optional[Dict[str, Any]] = None, charts: Optional[List[Optional[Dict[str, Any]]]] = None,
            tables: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"rows": rows, "kpis": kpis or [], "summary": summary, "main": main, "charts": [c for c in charts or [] if c],
            "tables": tables or []}


def _table(title: str, note: str, columns: List[Column], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A fixed detail table (not the customizable main one)."""
    return {"title": title, "note": note, "columns": [{"key": k, "label": l, "type": t} for k, l, t in columns],
            "rows": [[r.get(k) for k, _, _ in columns] for r in rows[:PREVIEW_ROWS]]}


# --- The templates ----------------------------------------------------------------------------------

def _devices(devices, period, now, ctx):
    rows = [dict(_base(d), kind=d.get("kind") or "", snmp=d.get("snmp") or "Not read over SNMP",
                 snmp_security=d.get("snmp_security") or "", snmp_answer=d.get("snmp_answer") or "",
                 status=_status_word(d), ping_ms=d.get("ping_ms"), last_seen=d.get("last_seen")) for d in devices]
    v3 = [d for d in devices if d.get("snmp") == "v3"]
    v2 = [d for d in devices if d.get("snmp") and d.get("snmp") != "v3"]
    silent = [d["name"] for d in devices if d.get("snmp_answer") == "No answer"]
    offline = [d for d in devices if _status_word(d) == "Offline"]
    kpis = [_kpi("Devices", str(len(devices)), sub=f"{len(devices) - len(offline)} online now"),
            _kpi("Read over SNMP", str(len(v3) + len(v2)), sub=f"v3: {len(v3)}, v2c: {len(v2)}"),
            _kpi("Still on SNMP v2c", str(len(v2)), "warn" if v2 else "good", sub="Move these to v3" if v2 else "All on v3"),
            _kpi("Not answering SNMP", str(len(silent)), "bad" if silent else "good"),
            _kpi("Offline now", str(len(offline)), "bad" if offline else "good")]
    parts = [f"There are {_plural(len(devices), 'device')} in this report."]
    if v3 or v2:
        parts.append(f"Of these {len(v3) + len(v2)} are read over SNMP: {len(v3)} with v3 and {len(v2)} with v2c.")
        parts.append("Every SNMP device already uses v3." if not v2 else
                     f"Moving the {_plural(len(v2), 'device')} on v2c to v3 adds signing and encryption.")
    if silent:
        parts.append(f"Not answering SNMP: {_and(silent[:5])}" + (" and others." if len(silent) > 5 else "."))
    main = _donut("Devices by SNMP version", "How each device is read. SNMP v3 signs and encrypts; v2c sends its community in plain text.",
                  [("SNMP v3", len(v3), None), ("SNMP v2c", len(v2), None), ("Not read over SNMP", len(devices) - len(v3) - len(v2), "none")],
                  "devices")
    return _result(rows, kpis, " ".join(parts), main, [
        _bar_counts("Devices per template", [d.get("kind") or "Unknown" for d in devices], top=8, note="The device templates in use, most used first."),
        _bar_counts("Devices per group", [d.get("group") or "No group" for d in devices], top=8, note="How the devices are spread over the groups.")])


def _target_word(uptime: Optional[float], down_s: float, span: int) -> str:
    """Met, At risk (more than half of the 0.1% downtime allowance used) or Breached."""
    if uptime is None:
        return "No data"
    if uptime < UPTIME_TARGET:
        return "Breached"
    return "At risk" if down_s > span * (100 - UPTIME_TARGET) / 100 / 2 else "Met"


def _availability(devices, period, now, ctx):
    span = PERIODS[period]
    start, prev_start = now - span, now - 2 * span
    ids = [d["id"] for d in devices]
    cur, prev = _avail(ids, start, now), _avail(ids, prev_start, start)
    inc, prev_inc = _incidents(ids, start, now), _incidents(ids, prev_start, start)
    rows = []
    for d in devices:
        up = _uptime(cur[d["id"]])
        down = sum(s for _, s in inc.get(d["id"], [])) if up is not None else None
        rows.append(dict(_base(d), id=d["id"], uptime=up, down=down, outages=len(inc.get(d["id"], [])),
                         avg_ms=_avg_response(cur[d["id"]]), status=_status_word(d),
                         target=_target_word(up, down or 0, span)))
    measured = [r for r in rows if r["uptime"] is not None]
    overall = _uptime([h for hs in cur.values() for h in hs])
    overall_prev = _uptime([h for hs in prev.values() for h in hs])
    down_s = sum(r["down"] or 0 for r in measured)
    prev_down = sum(s for v in prev_inc.values() for _, s in v) if overall_prev is not None else None
    outages = sum(r["outages"] for r in measured)
    prev_outages = sum(len(v) for v in prev_inc.values()) if overall_prev is not None else None
    below = [r for r in measured if r["uptime"] < UPTIME_TARGET]
    prev_below = sum(1 for i in ids if (_uptime(prev[i]) or 100) < UPTIME_TARGET) if overall_prev is not None else None
    allowance = span * (100 - UPTIME_TARGET) / 100 * max(1, len(measured))
    note, trend = _change(overall, overall_prev, period, "points", "up")
    kpis = [_kpi("Overall uptime", _pct_text(overall), _uptime_tone(overall) if overall is not None else "none",
                 sub=f"Target {UPTIME_TARGET}%", note=note, trend=trend)]
    note, trend = _change(down_s / 60, prev_down / 60 if prev_down is not None else None, period, "minutes", "down")
    kpis.append(_kpi("Downtime", _minutes(down_s) if measured else "No data",
                     "none" if not measured else "good" if down_s <= allowance / 2 else "warn" if down_s <= allowance else "bad",
                     sub="All devices together", note=note, trend=trend))
    note, trend = _change(outages, prev_outages, period, "count", "down")
    kpis.append(_kpi("Outages", str(outages), "good" if not outages else "warn", note=note, trend=trend))
    note, trend = _change(len(below), prev_below, period, "count", "down")
    kpis.append(_kpi(f"Below {UPTIME_TARGET}%", str(len(below)), "good" if not below else "bad" if len(below) * 4 > len(measured) else "warn",
                     sub=f"Of {_plural(len(measured), 'device')} measured", note=note, trend=trend))
    # Summary
    if not measured:
        summary = f"There are no checks recorded for {PERIOD_NAMES[period]} yet, so there is nothing to measure."
    else:
        who = "The device was" if len(measured) == 1 else f"All {len(measured)} devices together were"
        parts = [f"{who} reachable {_pct_text(overall)} of the time over {PERIOD_NAMES[period]}."]
        went = sorted([r for r in measured if r["down"]], key=lambda r: -r["down"])
        if not went:
            parts.append("No device went down.")
        else:
            bits = []
            for r in went[:3]:
                first = min(inc[r["id"]], key=lambda x: x[0])[0]
                bits.append(f"{r['name']} for {_minutes(r['down'])}" + (f" {_on_day(first, span)}" if r["outages"] == 1 else f" over {r['outages']} outages"))
            parts.append(f"{_count(len(went), 'device')} went down: {_and(bits)}"
                         + (f", and {_plural(len(went) - 3, 'more device')}." if len(went) > 3 else "."))
        parts.append("Every device met the 99.9% target." if not below else
                     f"{_count(len(below), 'device')} fell below the 99.9% target.")
        summary = " ".join(parts)
    # Main: uptime strips for the devices with the least uptime.
    starts, fmt = _slots(start, now)
    worst = sorted(measured, key=lambda r: (r["uptime"], r["name"]))[:12]
    strip_rows = []
    for r in worst:
        per: List[List[int]] = [[0, 0] for _ in starts]
        for h in cur[r["id"]]:
            s = per[_slot_of(starts, h[0])]
            s[0] += h[1]
            s[1] += h[2]
        cells = []
        for checks, ups in per:
            v = round(100.0 * ups / checks, 3) if checks else None
            cells.append([v, _uptime_tone(v)])
        strip_rows.append({"name": r["name"], "value_text": _pct_text(r["uptime"]), "cells": cells})
    step = "hour" if fmt == "%H:00" else "day"
    main = {"kind": "strips", "title": "Uptime by " + step + ", devices with the least uptime first",
            "note": f"One bar per {step}. Green meets 99.9%, amber is 99% to 99.9%, red is below 99% and grey had no checks.",
            "rows": strip_rows, "start_text": _date(starts[0], fmt == "%H:00"), "end_text": _date(now)} if strip_rows else None
    per_slot = [0] * len(starts)
    for v in inc.values():
        for t, _ in v:
            if t >= start:
                per_slot[_slot_of(starts, t)] += 1
    down_bars = [(r["name"], round((r["down"] or 0) / 60, 1)) for r in sorted(measured, key=lambda r: -(r["down"] or 0)) if r["down"]]
    charts = [_bars("Most time down", "Minutes each device was down in the period.", down_bars, "min") if down_bars else None,
              {"kind": "columns", "title": f"Outages per {step}", "note": "When outages started. Each outage counts once, however long it lasted.",
               "labels": _slot_labels(starts, fmt), "series": [{"name": "Outages", "values": per_slot}], "unit": "", "whole": True} if any(per_slot) else None]
    for r in rows:
        r.pop("id", None)
    return _result(rows, kpis, summary, main, charts)


def _problems(devices, period, now, ctx):
    by_id = {d["id"]: d for d in devices}
    span = PERIODS[period]
    events = _problem_events(list(by_id), now - span, now + 1)
    prev_count = len(_problem_events(list(by_id), now - 2 * span, now - span))
    active: Dict[int, set] = {}
    for p in database.list_active_problems():
        active.setdefault(p["device_id"], set()).add(_stem(p["message"]))
    rows = []
    for e in events:
        d = by_id.get(e["device_id"])
        if not d:
            continue
        text = e["message"][len("Problem: "):]
        rows.append(dict(_base(d), time=e["timestamp"], severity=_sev(e["severity"]), problem=text,
                         state="Still open" if _stem(text) in active.get(d["id"], set()) else "Resolved"))
    still = [r for r in rows if r["state"] == "Still open"]
    serious = [r for r in rows if r["severity"] in ("Critical", "High")]
    note, trend = _change(len(rows), prev_count, period, "count", "down")
    kpis = [_kpi("Problems opened", str(len(rows)), "good" if not rows else "warn", note=note, trend=trend),
            _kpi("Still open", str(len(still)), "bad" if still else "good"),
            _kpi("Critical or high", str(len(serious)), "bad" if serious else "good"),
            _kpi("Devices affected", str(len({r["name"] for r in rows})), sub=f"Of {len(devices)}")]
    common = _bars("Most common problems", "The same problem on any device counts together.", _common([r["problem"] for r in rows]))
    if not rows:
        summary = f"No problems opened over {PERIOD_NAMES[period]}."
    else:
        summary = (f"There {'was' if len(rows) == 1 else 'were'} {_plural(len(rows), 'new problem')} over {PERIOD_NAMES[period]}"
                   f" ({prev_count} in {PREVIOUS_NAMES[period]}). " +
                   (f"{_count(len(still), 'problem')} {'is' if len(still) == 1 else 'are'} still open. " if still else "All of them are resolved. ") +
                   f"Seen most often, {_plural(common['bars'][0][1], 'time')}: {common['bars'][0][0]}.")
    main = _severity_columns([e for e in events], now - span, now, "Problems opened over time",
                             "New problems per day (per hour for 24 hours), by how serious they were.") if rows else None
    return _result(rows, kpis, summary, main, [
        _bar_counts("Problems per device", [r["name"] for r in rows], top=8, note="Devices with the most new problems.") if rows else None,
        common if rows else None])


def _cpu(device_id: int, start: int, end: int) -> List[Tuple[int, float, float]]:
    s = _series(device_id, "cpu_usage_pct", start, end)
    if s:
        return s
    return [(t, 100.0 - v, 100.0 - p) for t, v, p in _series(device_id, "cpu_idle_pct", start, end)]


def _disks(device_id: int) -> List[Dict[str, Any]]:
    """The device's disks, volumes and storage pools now (memory rows left out)."""
    out = []
    for table in ("volumes", "storage"):
        for idx, s in database.get_device_table(device_id, table).items():
            if table == "storage" and s.get("kind") not in ("disk", "flash"):
                continue
            out.append({"table": table, "idx": idx, "name": str(s.get("descr") or idx), "size": s.get("size_bytes"),
                        "used": s.get("used_bytes"), "used_pct": s.get("used_pct") if isinstance(s.get("used_pct"), (int, float)) else None})
    return out


def _load_word(*values: Optional[float]) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "No data"
    top = max(vals)
    return "Strained" if top >= LOAD_BAD else "Watch" if top >= LOAD_WARN else "OK"


def _health(devices, period, now, ctx):
    span = PERIODS[period]
    start = now - span
    rows, lines = [], []
    for d in devices:
        cpu = _cpu(d["id"], start, now)
        mem = _series(d["id"], "mem_used_pct", start, now)
        disks = [x for x in _disks(d["id"]) if x["used_pct"] is not None]
        disk = max(disks, key=lambda x: x["used_pct"]) if disks else None
        if not cpu and not mem and not disk:
            continue
        cv, mv = [v for _, v, _ in cpu], [v for _, v, _ in mem]
        row = dict(_base(d), cpu_avg=_mean(cv), cpu_p95=_quantile(cv, 0.95), cpu_max=max((p for _, _, p in cpu), default=None),
                   mem_avg=_mean(mv), mem_p95=_quantile(mv, 0.95), mem_max=max((p for _, _, p in mem), default=None),
                   disk_max=disk["used_pct"] if disk else None, disk_name=disk["name"] if disk else "")
        row["state"] = _load_word(row["cpu_p95"], row["mem_p95"], row["disk_max"])
        rows.append(row)
        lines.append((d, cpu, mem))
    ids = [d["id"] for d in devices]

    def overall(key: str, a: int, b: int) -> Optional[float]:
        vals = [v for vs in _hourly_avgs(ids, key, a, b).values() for v in vs]
        return _mean(vals)
    cpu_now, cpu_prev = overall("cpu_usage_pct", start, now), overall("cpu_usage_pct", start - span, start)
    mem_now, mem_prev = overall("mem_used_pct", start, now), overall("mem_used_pct", start - span, start)
    if cpu_now is None:
        cpu_now = _mean([r["cpu_avg"] for r in rows if r["cpu_avg"] is not None])
    if mem_now is None:
        mem_now = _mean([r["mem_avg"] for r in rows if r["mem_avg"] is not None])
    busiest = max((r for r in rows if r["cpu_p95"] is not None), key=lambda r: r["cpu_p95"], default=None)
    fullest = max((r for r in rows if r["disk_max"] is not None), key=lambda r: r["disk_max"], default=None)
    watch = [r for r in rows if r["state"] in ("Watch", "Strained")]
    kpis = []
    note, trend = _change(cpu_now, cpu_prev, period, "points", "down")
    kpis.append(_kpi("Average CPU", _pct_text(cpu_now), _tone_at(cpu_now, LOAD_WARN, LOAD_BAD), note=note, trend=trend))
    kpis.append(_kpi("Busiest CPU (95th pct)", _pct_text(busiest["cpu_p95"]) if busiest else "No data",
                     _tone_at(busiest["cpu_p95"] if busiest else None, LOAD_WARN, LOAD_BAD), sub=busiest["name"] if busiest else ""))
    note, trend = _change(mem_now, mem_prev, period, "points", "down")
    kpis.append(_kpi("Average memory", _pct_text(mem_now), _tone_at(mem_now, LOAD_WARN, LOAD_BAD), note=note, trend=trend))
    kpis.append(_kpi("Fullest disk", _pct_text(fullest["disk_max"]) if fullest else "No data",
                     _tone_at(fullest["disk_max"] if fullest else None, LOAD_WARN, LOAD_BAD),
                     sub=f"{fullest['name']}: {fullest['disk_name']}" if fullest else ""))
    kpis.append(_kpi("Devices to watch", str(len(watch)), "good" if not watch else "bad" if any(r["state"] == "Strained" for r in watch) else "warn",
                     sub=f"Over {LOAD_WARN:.0f}% somewhere"))
    if not rows:
        summary = f"No processor, memory or disk readings were recorded for {PERIOD_NAMES[period]}."
    else:
        parts = [f"Across {_plural(len(rows), 'device')} the processors averaged {_pct_text(cpu_now)} and memory {_pct_text(mem_now)}."]
        if busiest:
            parts.append(f"The busiest processor was {busiest['name']} at {_pct_text(busiest['cpu_p95'])} (95th percentile).")
        parts.append("No device went over 80%." if not watch else
                     f"Worth a look: {_and([r['name'] for r in watch[:4]])}" + (" and others." if len(watch) > 4 else "."))
        summary = " ".join(parts)
    bands = [{"from": LOAD_WARN, "to": LOAD_BAD, "tone": "warn"}, {"from": LOAD_BAD, "to": 100, "tone": "bad"}]
    marks = [{"value": LOAD_WARN, "tone": "warn", "label": "Watch 80%"}, {"value": LOAD_BAD, "tone": "bad", "label": "Strained 90%"}]
    charts: List[Optional[Dict[str, Any]]] = []
    if len(devices) == 1 and lines:
        _, cpu, mem = lines[0]
        main = {"kind": "line", "title": "Processor and memory", "unit": "%", "y_max": 100, "start": start, "end": now,
                "note": "Amber from 80% and red from 90%: time spent there is worth a look.", "bands": bands, "thresholds": marks,
                "series": [{"name": "CPU", "points": _thin(cpu, start, now)}, {"name": "Memory", "points": _thin(mem, start, now)}]}
        d = devices[0]
        charts.append(_capacity("Storage", "How full each disk and volume is now.",
                                [(x["name"], x["used_pct"]) for x in _disks(d["id"])], LOAD_WARN, LOAD_BAD))
    else:
        main = _capacity("Busiest processors (95th percentile)", "95% of the time the processor was at or below this. Lines at 80% and 90%.",
                         [(r["name"], r["cpu_p95"]) for r in rows], LOAD_WARN, LOAD_BAD, top=10) if busiest else None
        charts.append(_capacity("Memory use (95th percentile)", "Memory in use, 95th percentile over the period.",
                                [(r["name"], r["mem_p95"]) for r in rows], LOAD_WARN, LOAD_BAD))
        charts.append(_capacity("Fullest disks now", "The fullest disk or volume of each device.",
                                [(f"{r['name']}: {r['disk_name']}", r["disk_max"]) for r in rows], LOAD_WARN, LOAD_BAD))
    return _result(rows, kpis, summary, main, [c for c in charts if c and c.get("bars")])


def _storage(devices, period, now, ctx):
    import forecast
    fc = forecast.cached(now)
    rows = []
    for d in devices:
        full = {f["key"]: f.get("full_on") for f in fc.get(d["id"], [])}
        for x in _disks(d["id"]):
            prefix = "vol" if x["table"] == "volumes" else "stor"
            full_on = full.get(f"{prefix}.{x['idx']}.used_pct")
            pct = x["used_pct"]
            days = (full_on - now) / 86400 if full_on else None
            state = ("No data" if pct is None else "Full soon" if pct >= LOAD_BAD or (days is not None and days <= 30)
                     else "Nearly full" if pct >= LOAD_WARN or (days is not None and days <= 90) else "OK")
            rows.append(dict(_base(d), storage=x["name"], size=x["size"], used=x["used"], used_pct=pct, full_on=full_on, state=state))
    sized = [r for r in rows if isinstance(r["size"], (int, float)) and isinstance(r["used"], (int, float))]
    total, used = sum(r["size"] for r in sized), sum(r["used"] for r in sized)
    overall = 100.0 * used / total if total else None
    over = [r for r in rows if r["used_pct"] is not None and r["used_pct"] >= LOAD_BAD]
    soon = sorted([r for r in rows if r["full_on"] and r["full_on"] - now <= 30 * 86400], key=lambda r: r["full_on"])
    first = min((r for r in rows if r["full_on"]), key=lambda r: r["full_on"], default=None)
    kpis = [_kpi("Disks and volumes", str(len(rows)), sub=f"{format_cell('bytes', total)} in all" if total else ""),
            _kpi("Space used", _pct_text(overall), _tone_at(overall, LOAD_WARN, LOAD_BAD), sub=f"{format_cell('bytes', used)} used" if total else ""),
            _kpi("Over 90% full", str(len(over)), "bad" if over else "good"),
            _kpi("Full within 30 days", str(len(soon)), "bad" if soon else "good"),
            _kpi("Soonest full", _date(first["full_on"], False) if first else "Not expected",
                 "bad" if first and first["full_on"] - now <= 30 * 86400 else "warn" if first and first["full_on"] - now <= 90 * 86400 else "good",
                 sub=f"{first['name']}: {first['storage']}" if first else "No disk is filling up")]
    if not rows:
        summary = "No disks or volumes were reported by these devices."
    else:
        summary = (f"There are {_plural(len(rows), 'disk or volume', 'disks and volumes')}" + (f" holding {format_cell('bytes', total)}, {_pct_text(overall)} of it in use." if total else ".")
                   + (f" Over 90% full: {_and([r['name'] + ' ' + r['storage'] for r in over[:4]])}." if over else " None is over 90% full.")
                   + (f" At the current rate {soon[0]['name']} {soon[0]['storage']} is full around {_date(soon[0]['full_on'], False)}." if soon else
                      " None is expected to fill up within 30 days."))
    main = _capacity("Fullest storage", "How full each disk and volume is now. Lines at 80% and 90%.",
                     [(f"{r['name']}: {r['storage']}", r["used_pct"]) for r in rows], LOAD_WARN, LOAD_BAD, top=10) if any(r["used_pct"] is not None for r in rows) else None
    left = sorted([(f"{r['name']}: {r['storage']}", round((r["full_on"] - now) / 86400, 1)) for r in rows if r["full_on"]], key=lambda p: p[1])
    states = {}
    for r in rows:
        states[r["state"]] = states.get(r["state"], 0) + 1
    return _result(rows, kpis, summary, main, [
        _bars("Days until full", "At the current rate of growth (from the last 14 days). Disks that are not growing are left out.", left, "d") if left else None,
        _donut("Storage by state", "Full soon: over 90% or full within 30 days. Nearly full: over 80% or full within 90 days.",
               [(k, states.get(k, 0), PILL_TONES.get(k)) for k in ("OK", "Nearly full", "Full soon", "No data")], "disks") if rows else None])


def _wifi(devices, period, now, ctx):
    rows = []
    for d in devices:
        for mac, c in database.get_device_table(d["id"], "wifi_clients").items():
            sig = c.get("signal")
            quality = "No data" if not isinstance(sig, (int, float)) else "Good" if sig >= -60 else "Fair" if sig >= WEAK_SIGNAL_DBM else "Weak"
            rows.append(dict(_base(d), client=c.get("name") or mac, mac=mac, client_ip=c.get("ip") or "", vendor=c.get("vendor") or "",
                             ssid=c.get("ssid") or "", band=c.get("band") or "", signal=sig, quality=quality,
                             experience=c.get("experience"), tx_mbps=c.get("tx_mbps"), uptime=c.get("uptime")))
    weak = [r for r in rows if r["quality"] == "Weak"]
    exp = _mean([r["experience"] for r in rows if isinstance(r["experience"], (int, float))])
    kpis = [_kpi("Devices on Wi-Fi", str(len(rows))),
            _kpi("Weak signal", str(len(weak)), "good" if not weak else "warn", sub=f"Below {WEAK_SIGNAL_DBM} dBm"),
            _kpi("Average experience", _pct_text(exp), _tone_at(exp, 90, 70, high_is_bad=False)),
            _kpi("Networks", str(len({r["ssid"] for r in rows if r["ssid"]}))),
            _kpi("Access points", str(len({r["name"] for r in rows})))]
    summary = (f"There are {_plural(len(rows), 'device')} on Wi-Fi across {_plural(len({r['name'] for r in rows}), 'access point')}." +
               (f" {_count(len(weak), 'device')} {'has' if len(weak) == 1 else 'have'} a weak signal: moving closer or adding an access point helps." if weak else
                " Every device has a usable signal.")) if rows else "No Wi-Fi devices were reported (UniFi lists them when it is set up)."
    return _result(rows, kpis, summary,
                   _bar_counts("Devices per access point", [r["name"] for r in rows], top=10, note="How the Wi-Fi devices are spread over the access points.") if rows else None,
                   [_donut("Devices per band", "Which radio band the devices use.", [(b or "Unknown", n, None) for b, n in
                                                                                     sorted(_counts([r["band"] for r in rows]).items())], "devices") if rows else None,
                    _bar_counts("Devices per network", [r["ssid"] or "Unknown" for r in rows], top=8, note="Wi-Fi networks (SSIDs), busiest first.") if rows else None])


def _counts(values: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def _proxmox(devices, period, now, ctx):
    import proxmox
    names = {d["id"]: d["name"] for d in devices}
    rows = []
    for g in proxmox.layout().get("guests", []):
        if ctx.get("filtered") and g.get("device_id") not in names:
            continue
        rows.append({"guest": g.get("name") or str(g.get("vmid")), "vmid": g.get("vmid"),
                     "type": "Container" if g.get("type") == "lxc" else "Virtual machine", "node": g.get("node") or "",
                     "state": str(g.get("status") or "Unknown").capitalize(), "mem": g.get("mem"), "maxmem": g.get("maxmem"),
                     "maxdisk": g.get("maxdisk"), "uptime": g.get("uptime") if g.get("status") == "running" else None,
                     "onboot": "Yes" if g.get("onboot") else "No", "name": names.get(g.get("device_id"), ""),
                     "ip": "", "group": "", "tags": ""})
    running = [r for r in rows if r["state"] == "Running"]
    stopped_boot = [r for r in rows if r["state"] != "Running" and r["onboot"] == "Yes"]
    mem = sum(r["mem"] or 0 for r in running)
    maxmem = sum(r["maxmem"] or 0 for r in running)
    kpis = [_kpi("Guests", str(len(rows)), sub=f"{sum(1 for r in rows if r['type'] == 'Container')} containers"),
            _kpi("Running", str(len(running)), "good" if rows and len(running) == len(rows) else "info"),
            _kpi("Stopped but set to start", str(len(stopped_boot)), "bad" if stopped_boot else "good"),
            _kpi("Memory in use", format_cell("bytes", mem) if maxmem else "No data", sub=f"Of {format_cell('bytes', maxmem)} given" if maxmem else "")]
    summary = (f"There are {_plural(len(rows), 'guest')} and {len(running)} {'is' if len(running) == 1 else 'are'} running." +
               (f" Set to start with the host but not running: {_and([r['guest'] for r in stopped_boot[:5]])}." if stopped_boot else "")) if rows else \
        "No Proxmox guests were found (Proxmox lists them when it is set up)."
    states = _counts([r["state"] for r in rows])
    return _result(rows, kpis, summary,
                   _donut("Guests by state", "Running, stopped or paused right now.", [(s, n, PILL_TONES.get(s, "none")) for s, n in states.items()], "guests") if rows else None,
                   [_bars("Memory used by guest", "Running guests using the most memory now.",
                          sorted([(r["guest"], r["mem"]) for r in running if r["mem"]], key=lambda p: -p[1]), "B") if running else None])


PIHOLE_KEYS = ["pihole.queries", "pihole.blocked", "pihole.blocked_pct", "pihole.clients", "pihole.domains",
               "pihole.blocking", "pihole.gravity_days", "dns.ms"]


def _pihole(devices, period, now, ctx):
    latest = database.get_latest_metrics_all(PIHOLE_KEYS)
    rows, bars = [], []
    for d in devices:
        m = latest.get(d["id"])
        if not m or "pihole.queries" not in m:
            continue
        rows.append(dict(_base(d), blocking="On" if m.get("pihole.blocking") else "Off", queries=m.get("pihole.queries"),
                         blocked=m.get("pihole.blocked"), blocked_pct=m.get("pihole.blocked_pct"), clients=m.get("pihole.clients"),
                         domains=m.get("pihole.domains"), gravity_days=m.get("pihole.gravity_days"), dns_ms=m.get("dns.ms")))
        for _, b in database.get_device_table(d["id"], "pihole_blocked").items():
            if isinstance(b.get("count"), (int, float)):
                bars.append((str(b.get("domain") or ""), b["count"]))
    bars.sort(key=lambda b: -b[1])
    queries = sum(r["queries"] or 0 for r in rows)
    blocked = sum(r["blocked"] or 0 for r in rows)
    off = [r for r in rows if r["blocking"] == "Off"]
    oldest = max((r["gravity_days"] for r in rows if isinstance(r["gravity_days"], (int, float))), default=None)
    kpis = [_kpi("Queries today", f"{queries:,.0f}"),
            _kpi("Blocked", _pct_text(100.0 * blocked / queries) if queries else "No data", sub=f"{blocked:,.0f} queries"),
            _kpi("Clients", f"{max((r['clients'] or 0 for r in rows), default=0):,.0f}"),
            _kpi("Lists updated", f"{oldest:.0f} days ago" if oldest is not None else "No data", _tone_at(oldest, 8, 31)),
            _kpi("Blocking off", str(len(off)), "bad" if off else "good")]
    summary = (f"The {_plural(len(rows), 'Pi-hole')} answered {queries:,.0f} queries today and blocked {blocked:,.0f} of them." +
               (f" Blocking is off on {_and([r['name'] for r in off])}." if off else " Blocking is on everywhere.") +
               (" The block lists are more than a week old: updating them (gravity) keeps them current." if oldest is not None and oldest > 7 else "")) \
        if rows else "No Pi-hole readings were found (a Pi-hole shows up here once it is added as a device)."
    return _result(rows, kpis, summary,
                   _bars("Most blocked domains today", "The domains blocked most often across the Pi-holes.", bars, top=10) if bars else None,
                   [_bars("Queries per Pi-hole", "Queries answered today.", [(r["name"], r["queries"] or 0) for r in rows]) if len(rows) > 1 else None])


def _new_devices(devices, period, now, ctx):
    span = PERIODS[period]
    since = now - span
    with database.get_connection() as conn:
        found = [dict(r) for r in conn.execute(
            "SELECT i.*, d.hostname AS device_name FROM inventory i LEFT JOIN devices d ON d.id = i.device_id "
            "WHERE i.first_seen >= ? AND i.quiet = 0 ORDER BY i.first_seen DESC LIMIT ?;", (since, MAX_ROWS))]
        prev = conn.execute("SELECT COUNT(*) FROM inventory WHERE first_seen >= ? AND first_seen < ? AND quiet = 0;",
                            (since - span, since)).fetchone()[0]
    rows = [{"first_seen": r["first_seen"], "client": r.get("name") or r.get("seen_name") or r.get("device_name") or "",
             "mac": r["mac"], "client_ip": r.get("ip") or "", "vendor": r.get("vendor") or "", "where": r.get("where_seen") or "",
             "ssid": r.get("ssid") or "", "known": "Yes" if r.get("known") else "No", "last_seen": r.get("last_seen")} for r in found]
    unknown = [r for r in rows if r["known"] == "No"]
    note, trend = _change(len(rows), prev, period, "count", "down")
    kpis = [_kpi("New devices", str(len(rows)), note=note, trend="neutral" if trend else None),
            _kpi("Not yet marked known", str(len(unknown)), "warn" if unknown else "good"),
            _kpi("Makers", str(len({r["vendor"] for r in rows if r["vendor"]}))),
            _kpi("On Wi-Fi", str(sum(1 for r in rows if r["ssid"])))]
    summary = (f"{_count(len(rows), 'new device')} joined the network over {PERIOD_NAMES[period]} ({prev} in {PREVIOUS_NAMES[period]})." +
               (f" Not marked as known yet: {_plural(len(unknown), 'device')}. Inventory is where to check them." if unknown else
                " All of them are marked as known.")) \
        if rows else f"No new devices joined the network over {PERIOD_NAMES[period]}."
    starts, fmt = _slots(since, now)
    per = [0] * len(starts)
    for r in rows:
        per[_slot_of(starts, r["first_seen"])] += 1
    return _result(rows, kpis, summary,
                   {"kind": "columns", "title": "New devices over time", "note": "When each device was first seen.",
                    "labels": _slot_labels(starts, fmt), "series": [{"name": "New devices", "values": per}], "unit": "", "whole": True} if rows else None,
                   [_bar_counts("By maker", [r["vendor"] or "Unknown" for r in rows], top=8, note="From the first part of the MAC address.") if rows else None,
                    _bar_counts("Where they were seen", [r["where"] or "Unknown" for r in rows], top=8, note="The switch port, access point or scan that found them.") if rows else None])


def _events(devices, period, now, ctx):
    by_id = {d["id"]: d for d in devices}
    span = PERIODS[period]
    if not by_id:
        return _result([], [], "There are no devices in this report.")
    events, _ = database.list_events_filtered(since=now - span, until=now + 1, device_ids=set(by_id), limit=MAX_ROWS)
    _, prev_total = database.list_events_filtered(since=now - 2 * span, until=now - span, device_ids=set(by_id), limit=1)
    events = [e for e in events if e["device_id"] in by_id]
    rows = [dict(_base(by_id[e["device_id"]]), time=e["timestamp"], severity=_sev(e["severity"]),
                 type=str(e["event_type"]).replace("_", " ").capitalize(), message=e["message"]) for e in events]
    crit = [r for r in rows if r["severity"] in ("Critical", "High")]
    warn = [r for r in rows if r["severity"] == "Warning"]
    note, trend = _change(len(rows), prev_total, period, "count", "down")
    kpis = [_kpi("Events", str(len(rows)), note=note, trend=trend),
            _kpi("Critical or high", str(len(crit)), "bad" if crit else "good"),
            _kpi("Warnings", str(len(warn)), "warn" if warn else "good"),
            _kpi("Devices with events", str(len({r["name"] for r in rows})), sub=f"Of {len(devices)}")]
    types = _counts([r["type"] for r in rows])
    summary = (f"There {'was' if len(rows) == 1 else 'were'} {_plural(len(rows), 'event')} over {PERIOD_NAMES[period]} ({prev_total} in {PREVIOUS_NAMES[period]})."
               + (f" Critical or high: {len(crit)}." if crit else " None was critical.") +
               f" The most common kind was {max(types, key=types.get).lower()}.") if rows else f"Nothing happened to these devices over {PERIOD_NAMES[period]}."
    return _result(rows, kpis, summary,
                   _severity_columns(events, now - span, now, "Events over time", "Events per day (per hour for 24 hours), by severity.") if rows else None,
                   [_bar_counts("Events by type", [r["type"] for r in rows], top=8, note="Problems, recoveries, restarts, changes and messages.") if rows else None,
                    _hour_of_day([r["time"] for r in rows], "Events by hour of day", "Which hours of the day are busiest (all days together).") if rows else None])


def _updates(devices, period, now, ctx):
    since = now - PERIODS[period]
    history: Callable[[], List[Dict[str, Any]]] = ctx.get("update_history") or (lambda: [])
    rows = [{"time": h["time"], "kind": str(h["kind"] or "update").replace("-", " ").capitalize(), "from": h["from"],
             "to": h["to"], "result": "Finished" if h["ok"] else "Failed", "error": h["error"][:300]}
            for h in history() if h["time"] >= since]
    failed = [r for r in rows if r["result"] == "Failed"]
    last = max(rows, key=lambda r: r["time"]) if rows else None
    kpis = [_kpi("Updates", str(len(rows))), _kpi("Failed", str(len(failed)), "bad" if failed else "good"),
            _kpi("Last one", _date(last["time"], False) if last else "None", sub=f"To {last['to']}" if last and last["to"] else "")]
    summary = (f"The monitor was updated {_plural(len(rows), 'time')} over {PERIOD_NAMES[period]}." +
               (f" {_count(len(failed), 'update')} failed and {'was' if len(failed) == 1 else 'were'} undone." if failed else " Every update finished.")) \
        if rows else f"The monitor was not updated over {PERIOD_NAMES[period]}."
    return _result(rows, kpis, summary,
                   _donut("Results", "Finished or failed.", [("Finished", len(rows) - len(failed), "good"), ("Failed", len(failed), "bad")], "updates") if rows else None)


# New templates ---------------------------------------------------------------------------------------

def _monthly(devices, period, now, ctx):
    span = PERIODS[period]
    start = now - span
    ids = [d["id"] for d in devices]
    cur, prev = _avail(ids, start, now), _avail(ids, start - span, start)
    all_cur = [h for hs in cur.values() for h in hs]
    all_prev = [h for hs in prev.values() for h in hs]
    up, up_prev = _uptime(all_cur), _uptime(all_prev)
    ms, ms_prev = _avg_response(all_cur), _avg_response(all_prev)
    events = _problem_events(ids, start, now + 1)
    prev_events = _problem_events(ids, start - span, start)
    state = _now_state(devices)
    online = sum(1 for s in state.values() if s[0] in ("Up", "Problems"))
    kpis = []
    note, trend = _change(up, up_prev, period, "points", "up")
    kpis.append(_kpi("Availability", _pct_text(up), _uptime_tone(up), sub=f"Target {UPTIME_TARGET}%", note=note, trend=trend))
    note, trend = _change(ms, ms_prev, period, "ms", "down")
    kpis.append(_kpi("Average response", _ms(ms), _tone_at(ms, PING_TARGET_MS, PING_TARGET_MS * 2) if ms is not None else "none",
                     sub="Ping and service checks", note=note, trend=trend))
    note, trend = _change(len(events), len(prev_events), period, "count", "down")
    kpis.append(_kpi("Problems opened", str(len(events)), "good" if not events else "warn", note=note, trend=trend))
    kpis.append(_kpi("Devices monitored", str(len(devices)), sub=f"{online} up now"))
    # Days
    starts, fmt = _slots(start, now)
    per = [[0, 0] for _ in starts]
    for h in all_cur:
        s = per[_slot_of(starts, h[0])]
        s[0] += h[1]
        s[1] += h[2]
    daily = [round(100.0 * u / c, 3) if c else None for c, u in per]
    measured = [v for v in daily if v is not None]
    floor = min([UPTIME_TARGET - 0.4] + measured)
    y_min = next((v for v in (99.5, 99.0, 98.0, 95.0, 90.0) if v <= floor), 0.0)
    step = "hour" if fmt == "%H:00" else "day"
    main = {"kind": "columns", "title": f"Availability per {step}", "unit": "%", "y_min": y_min, "y_max": 100,
            "note": (f"The axis starts at {y_min:g}% so small dips show. " if y_min else "") +
                    f"Green {step}s met the {UPTIME_TARGET}% target (dashed line), amber ones were above 99%, red ones below.",
            "labels": _slot_labels(starts, fmt), "series": [{"name": "Availability", "values": daily}],
            "bar_tones": [_uptime_tone(v) for v in daily],
            "target": {"value": UPTIME_TARGET, "label": f"Target {UPTIME_TARGET}%", "tone": "none"}} if measured else None
    counts = _counts([s[0] for s in state.values()])
    donut = _donut("Devices now", "Up, with an open problem, down or not checked yet.",
                   [(k, counts.get(k, 0), t) for k, t in (("Up", "good"), ("Problems", "warn"), ("Down", "bad"), ("Not monitored", "none"))],
                   "devices")
    # Top issues
    active: Dict[str, set] = {}
    for p in database.list_active_problems():
        if p["device_id"] in state:
            active.setdefault(_stem(p["message"]), set()).add(p["device_id"])
    names = {d["id"]: d["name"] for d in devices}
    issues: Dict[str, Dict[str, Any]] = {}
    order = {"Critical": 3, "High": 2, "Warning": 1, "Info": 0}
    for e in events:
        text = e["message"][len("Problem: "):]
        i = issues.setdefault(_key(text), {"problem": text, "count": 0, "ids": set(), "last": 0, "severity": "Info"})
        i["count"] += 1
        i["ids"].add(e["device_id"])
        i["last"] = max(i["last"], e["timestamp"])
        if order.get(_sev(e["severity"]), 0) > order.get(i["severity"], 0):
            i["severity"] = _sev(e["severity"])
    rows = []
    for i in issues.values():
        where = sorted(names.get(x, "") for x in i["ids"])
        rows.append({"problem": i["problem"], "severity": i["severity"], "count": i["count"], "devices": len(i["ids"]),
                     "where": ", ".join(where[:3]) + (f" and {len(where) - 3} more" if len(where) > 3 else ""), "last": i["last"],
                     "state": "Still open" if i["ids"] & active.get(_stem(i["problem"]), set()) else "Resolved"})
    rows.sort(key=lambda r: -r["count"])
    if up is None:
        summary = f"There are no checks recorded for {PERIOD_NAMES[period]} yet."
    else:
        worst_day = min(((v, s) for v, s in zip(daily, starts) if v is not None), default=None)
        parts = [f"The {_plural(len(devices), 'device')} were available {_pct_text(up)} of the time over {PERIOD_NAMES[period]}"
                 + (f", {'meeting' if up >= UPTIME_TARGET else 'short of'} the {UPTIME_TARGET}% target." )]
        if worst_day and worst_day[0] < UPTIME_TARGET:
            parts.append(f"The weakest {step} was {datetime.fromtimestamp(worst_day[1]).strftime('%H:00' if step == 'hour' else '%A %d %B').replace(' 0', ' ')} at {_pct_text(worst_day[0])}.")
        parts.append(f"{_count(len(events), 'problem')} opened." + (f" Seen most often, {_plural(rows[0]['count'], 'time')}: {rows[0]['problem']}." if rows else ""))
        if ms is not None:
            parts.append(f"Devices answered in {_ms(ms)} on average.")
        summary = " ".join(parts)
    return _result(rows, kpis, summary, main, [
        donut if devices else None,
        _severity_columns(events, start, now, f"Problems opened per {step}", "New problems, by how serious they were.") if events else None])


def _interfaces(device: Dict[str, Any], start: int, end: int, wan: set) -> List[Dict[str, Any]]:
    """The device's physical ports and WAN links that have traffic readings in the window."""
    out = []
    for idx, r in database.get_device_table(device["id"], "interfaces").items():
        try:
            if_index = int(r.get("if_index") or idx)
        except (TypeError, ValueError):
            if_index = 0
        is_wan = (device["id"], if_index) in wan or "wan" in re.split(r"[^a-z0-9]+", str(r.get("alias") or "").lower())
        if r.get("kind") != "port" and not is_wan:
            continue
        ins = _series(device["id"], f"if.{idx}.in_bps", start, end)
        outs = _series(device["id"], f"if.{idx}.out_bps", start, end)
        if not ins and not outs:
            continue
        speed = r.get("speed_mbps") if isinstance(r.get("speed_mbps"), (int, float)) and r.get("speed_mbps") else None
        in_p95 = _quantile([v for _, v, _ in ins], 0.95)
        out_p95 = _quantile([v for _, v, _ in outs], 0.95)
        peak = max([p for _, _, p in ins + outs], default=None)
        util = 100.0 * max(in_p95 or 0, out_p95 or 0) / (speed * 1e6) if speed else None
        state = "No speed" if util is None else "Saturated" if util >= LINK_BAD else "Busy" if util >= LINK_WARN else "OK"
        label = str(r.get("label") or r.get("descr") or idx) + (f" ({r['alias']})" if r.get("alias") else "")
        out.append(dict(_base(device), device_id=device["id"], idx=idx, wan=is_wan, interface=label, speed=speed,
                        in_p95=in_p95, out_p95=out_p95, peak=peak, util=round(util, 1) if util is not None else None,
                        state=state, _in=ins, _out=outs))
    return out


def _heatmap(samples: List[Tuple[int, float]], title: str, note: str, unit: str) -> Optional[Dict[str, Any]]:
    """Average by weekday (rows, Monday first) and hour (columns)."""
    cells: Dict[Tuple[int, int], List[float]] = {}
    for t, v in samples:
        d = datetime.fromtimestamp(t)
        cells.setdefault((d.weekday(), d.hour), []).append(v)
    if not cells:
        return None
    values = [[round(_mean(cells[(w, h)]), 1) if (w, h) in cells else None for h in range(24)] for w in range(7)]
    return {"kind": "heatmap", "title": title, "note": note, "unit": unit,
            "rows": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "values": values,
            "max": max(v for row in values for v in row if v is not None)}


def _mirror(i: Dict[str, Any], start: int, end: int, title: str, note: str) -> Dict[str, Any]:
    peak = i["peak"] or 0
    speed_bps = i["speed"] * 1e6 if i.get("speed") else None
    return {"kind": "mirror", "title": title, "note": note, "unit": "bps", "start": start, "end": end,
            "in": _thin(i["_in"], start, end), "out": _thin(i["_out"], start, end),
            "in_label": "In (download)" if i.get("wan") else "In", "out_label": "Out (upload)" if i.get("wan") else "Out",
            "line": speed_bps if speed_bps and peak > speed_bps * 0.5 else None,
            "line_label": f"Link speed {format_cell('mbps', i['speed'])}" if speed_bps else ""}


def _bandwidth(devices, period, now, ctx):
    span = PERIODS[period]
    start = now - span
    wan = ctx["wan"]() if callable(ctx.get("wan")) else set()
    ifaces = [i for d in devices for i in _interfaces(d, start, now, wan)]
    rows = [{k: v for k, v in i.items() if not k.startswith("_") and k not in ("device_id", "idx", "wan")} for i in ifaces]

    def load(i: Dict[str, Any]) -> float:
        return max(i["in_p95"] or 0, i["out_p95"] or 0)
    busiest = max(ifaces, key=load, default=None)
    wans = [i for i in ifaces if i["wan"]]
    focus = max(wans, key=load) if wans else busiest
    busy = [i for i in ifaces if i["state"] in ("Busy", "Saturated")]
    top_util = max((i for i in ifaces if i["util"] is not None), key=lambda i: i["util"], default=None)
    kpis = []
    if focus:
        prev_in = _quantile([v for _, v, _ in _series(focus["device_id"], f"if.{focus['idx']}.in_bps", start - span, start)], 0.95)
        note, trend = _change(focus["in_p95"], prev_in, period, "bps", "down")
        kpis.append(_kpi("Internet download" if focus["wan"] else "Busiest link in", _bps(focus["in_p95"]),
                         sub=f"95th pct, {focus['name']} {focus['interface']}", note=note, trend="neutral" if trend else None))
        kpis.append(_kpi("Internet upload" if focus["wan"] else "Busiest link out", _bps(focus["out_p95"]), sub="95th percentile"))
    kpis.append(_kpi("Highest use", _pct_text(top_util["util"]) if top_util else "No data",
                     _tone_at(top_util["util"] if top_util else None, LINK_WARN, LINK_BAD),
                     sub=f"{top_util['name']} {top_util['interface']}" if top_util else "Needs the link speed"))
    kpis.append(_kpi("Busy links", str(len(busy)), "good" if not busy else "bad" if any(i["state"] == "Saturated" for i in busy) else "warn",
                     sub=f"Over {LINK_WARN:.0f}% at the 95th pct"))
    kpis.append(_kpi("Interfaces measured", str(len(ifaces))))
    if not ifaces:
        summary = f"No interface traffic was recorded for {PERIOD_NAMES[period]} (it comes from SNMP on switches, routers and hosts)."
    else:
        parts = []
        if focus and focus["wan"]:
            parts.append(f"The internet link, {focus['name']} {focus['interface']}, carried up to {_bps(focus['in_p95'])} down and {_bps(focus['out_p95'])} up"
                         f" 95% of the time, peaking at {_bps(focus['peak'])}.")
        if busiest and busiest is not focus:
            parts.append(f"The busiest interface was {busiest['name']} {busiest['interface']} at {_bps(load(busiest))} (95th percentile).")
        elif busiest and not parts:
            parts.append(f"The busiest interface was {busiest['name']} {busiest['interface']} at {_bps(load(busiest))} (95th percentile).")
        parts.append("No link ran over 70% of its speed." if not busy else
                     f"Running over 70% of their speed: {_and([i['name'] + ' ' + i['interface'] for i in busy[:4]])}.")
        summary = " ".join(parts)
    main = _mirror(focus, start, now, f"Traffic on {focus['name']} {focus['interface']}",
                   "Inbound above the line, outbound below it.") if focus else None
    heat = None
    if focus:
        both: Dict[int, float] = {}
        for t, v, _ in focus["_in"] + focus["_out"]:
            both[t] = max(both.get(t, 0.0), v)
        heat = _heatmap(sorted(both.items()), f"When {focus['interface']} is busiest",
                        "Average load (the larger of in and out) by weekday and hour. Darker is busier.", "bps")
    return _result(rows, kpis, summary, main, [
        _bars("Busiest interfaces (95th percentile)", "The larger of in and out, 95% of the time at or below this.",
              sorted([(f"{i['name']} {i['interface']}", load(i)) for i in ifaces], key=lambda p: -p[1]), "bps") if ifaces else None,
        heat,
        _capacity("How full the links run", "Use at the 95th percentile against the link speed. Lines at 70% and 90%.",
                  [(f"{i['name']} {i['interface']}", i["util"]) for i in ifaces], LINK_WARN, LINK_BAD) if top_util else None])


def _latency(devices, period, now, ctx):
    span = PERIODS[period]
    start = now - span
    rows, per_dev = [], {}
    for d in devices:
        s = _series(d["id"], "icmp_ping_ms", start, now, positive=True)
        vals = [v for _, v, _ in s]
        if vals:
            per_dev[d["id"]] = s
        med, p95 = _median(vals), _quantile(vals, 0.95)
        state = ("No answer" if med is None else "Slow" if med > PING_TARGET_MS else "Spiky" if (p95 or 0) > PING_TARGET_MS else "Good")
        trend = [v for _, v in _thin(s, start, now, 24, _median)] if s else []
        rows.append(dict(_base(d), id=d["id"], min=min(vals) if vals else None, median=med, p95=p95,
                         max=max((p for _, _, p in s), default=None), trend=trend, state=state))
    ids = [d["id"] for d in devices]

    def typical(a: int, b: int) -> Optional[float]:
        return _median([v for vs in _hourly_avgs(ids, "icmp_ping_ms", a, b, positive=True).values() for v in vs])
    cur, prev = typical(start, now), typical(start - span, start)
    if cur is None:
        cur = _median([r["median"] for r in rows if r["median"] is not None])
    pooled = [v for s in per_dev.values() for _, v, _ in s]
    p95_all = _quantile(pooled, 0.95)
    over = [r for r in rows if r["state"] in ("Slow", "Spiky")]
    slowest = max((r for r in rows if r["p95"] is not None), key=lambda r: r["p95"], default=None)
    note, trend = _change(cur, prev, period, "ms", "down")
    kpis = [_kpi("Typical ping", _ms(cur), _tone_at(cur, PING_TARGET_MS, PING_TARGET_MS * 2), sub="Median, all devices", note=note, trend=trend),
            _kpi("95th percentile", _ms(p95_all), _tone_at(p95_all, PING_TARGET_MS, PING_TARGET_MS * 2), sub="All devices together"),
            _kpi(f"Over {PING_TARGET_MS:.0f} ms", str(len(over)), "good" if not over else "bad" if any(r["state"] == "Slow" for r in over) else "warn",
                 sub="Slow or spiky devices"),
            _kpi("Slowest device", _ms(slowest["p95"]) if slowest else "No data", _tone_at(slowest["p95"] if slowest else None, PING_TARGET_MS, PING_TARGET_MS * 2),
                 sub=f"{slowest['name']} (95th pct)" if slowest else "")]
    if not per_dev:
        summary = f"No ping answers were recorded for {PERIOD_NAMES[period]}."
    else:
        parts = [f"Devices typically answered ping in {_ms(cur)}, and 95% of answers came within {_ms(p95_all)}."]
        parts.append(f"Every device stayed within the {PING_TARGET_MS:.0f} ms target." if not over else
                     f"Over the {PING_TARGET_MS:.0f} ms target at times: {_and([r['name'] for r in sorted(over, key=lambda r: -(r['p95'] or 0))[:4]])}"
                     + (" and others." if len(over) > 4 else "."))
        silent = [r["name"] for r in rows if r["state"] == "No answer"]
        if silent:
            parts.append(f"No answer at all: {_and(silent[:4])}" + (" and others." if len(silent) > 4 else "."))
        summary = " ".join(parts)
    # Typical ping over time: the median across devices in each step, and the 95th percentile.
    size = max(60, span // 150)
    steps: Dict[int, List[float]] = {}
    for s in per_dev.values():
        for t, v, _ in s:
            steps.setdefault((t - start) // size, []).append(v)
    med_line, p95_line = [], []
    if steps:
        for n in range(min(steps), max(steps) + 1):
            vals = steps.get(n)
            t = start + n * size + size // 2
            med_line.append((t, round(_median(vals), 2) if vals else None))
            p95_line.append((t, round(_quantile(vals, 0.95), 2) if vals else None))
    main = {"kind": "line", "title": "Typical ping over time", "unit": "ms", "start": start, "end": now,
            "note": f"The median across all devices and the 95th percentile. The dashed line is the {PING_TARGET_MS:.0f} ms target.",
            "series": [{"name": "Median", "points": med_line}, {"name": "95th percentile", "points": p95_line}],
            "thresholds": [{"value": PING_TARGET_MS, "tone": "warn", "label": f"Target {PING_TARGET_MS:.0f} ms"}]} if med_line else None
    hours: Dict[int, List[float]] = {}
    for s in per_dev.values():
        for t, v, _ in s:
            hours.setdefault(datetime.fromtimestamp(t).hour, []).append(v)
    by_hour = [round(_median(hours[h]), 2) if h in hours else None for h in range(24)]
    for r in rows:
        r.pop("id", None)
    return _result(rows, kpis, summary, main, [
        _bars("Slowest devices (95th percentile)", f"Dashed line at the {PING_TARGET_MS:.0f} ms target.",
              sorted([(r["name"], round(r["p95"], 1)) for r in rows if r["p95"] is not None], key=lambda p: -p[1]), "ms",
              thresholds=[{"value": PING_TARGET_MS, "tone": "warn", "label": "Target"}]) if per_dev else None,
        {"kind": "columns", "title": "Typical ping by hour of day", "note": "The median of all answers in each hour, all days together.",
         "labels": [f"{h:02d}" for h in range(24)], "series": [{"name": "Median", "values": by_hour}], "unit": "ms",
         "target": {"value": PING_TARGET_MS, "label": f"Target {PING_TARGET_MS:.0f} ms", "tone": "warn"}} if per_dev else None])


def _alerts(devices, period, now, ctx):
    by_id = {d["id"]: d for d in devices}
    span = PERIODS[period]
    start = now - span
    if not by_id:
        return _result([], [], "There are no devices in this report.")
    events, _ = database.list_events_filtered(since=start, until=now + 1, device_ids=set(by_id), limit=MAX_ROWS)
    _, prev_total = database.list_events_filtered(since=start - span, until=start, device_ids=set(by_id), limit=1)
    events = [e for e in events if e["device_id"] in by_id]
    problems = [e for e in events if e["event_type"] == "problem" and str(e["message"]).startswith("Problem: ")]
    prev_problems = len(_problem_events(list(by_id), start - span, start))
    order = {"Critical": 3, "High": 2, "Warning": 1, "Info": 0}
    per: Dict[int, Dict[str, Any]] = {}
    for e in events:
        r = per.setdefault(e["device_id"], dict(_base(by_id[e["device_id"]]), events=0, problems=0, critical=0, warnings=0, last=0, worst="Info"))
        sev = _sev(e["severity"])
        r["events"] += 1
        r["problems"] += 1 if e in problems else 0
        r["critical"] += 1 if sev in ("Critical", "High") else 0
        r["warnings"] += 1 if sev == "Warning" else 0
        r["last"] = max(r["last"], e["timestamp"])
        if order.get(sev, 0) > order.get(r["worst"], 0):
            r["worst"] = sev
    rows = sorted(per.values(), key=lambda r: -r["events"])
    crit = sum(r["critical"] for r in rows)
    noisiest = rows[0] if rows else None
    kpis = []
    note, trend = _change(len(events), prev_total, period, "count", "down")
    kpis.append(_kpi("Events", str(len(events)), note=note, trend=trend))
    note, trend = _change(len(problems), prev_problems, period, "count", "down")
    kpis.append(_kpi("Problems opened", str(len(problems)), "good" if not problems else "warn", note=note, trend=trend))
    kpis.append(_kpi("Critical or high", str(crit), "bad" if crit else "good"))
    kpis.append(_kpi("Noisiest device", str(noisiest["events"]) if noisiest else "0", sub=noisiest["name"] if noisiest else "None"))
    common: Dict[str, Dict[str, Any]] = {}
    for e in problems:
        text = e["message"][len("Problem: "):]
        c = common.setdefault(_key(text), {"problem": text, "count": 0, "ids": set(), "last": 0})
        c["count"] += 1
        c["ids"].add(e["device_id"])
        c["last"] = max(c["last"], e["timestamp"])
    top = sorted(common.values(), key=lambda c: -c["count"])
    if not events:
        summary = f"It was quiet: no events over {PERIOD_NAMES[period]}."
    else:
        share = round(100 * noisiest["events"] / len(events)) if noisiest else 0
        parts = [f"There {'was' if len(events) == 1 else 'were'} {_plural(len(events), 'event')} over {PERIOD_NAMES[period]} ({prev_total} in {PREVIOUS_NAMES[period]})"
                 f" and {_plural(len(problems), 'problem')} opened."]
        if noisiest:
            parts.append(f"The noisiest device was {noisiest['name']} with {_plural(noisiest['events'], 'event')} ({share}% of all).")
        if top:
            parts.append(f"Seen most often, {_plural(top[0]['count'], 'time')} on {_plural(len(top[0]['ids']), 'device')}: {top[0]['problem']}.")
        summary = " ".join(parts)
    tables = [_table("Most common problems", "The same problem on any device counts together.",
                     [_col("problem", "Problem"), _col("count", "Times", "num"), _col("devices", "Devices", "num"), _col("last", "Last seen", "time")],
                     [{"problem": c["problem"], "count": c["count"], "devices": len(c["ids"]), "last": c["last"]} for c in top[:15]])] if top else []
    res = _result(rows, kpis, summary,
                  _severity_columns(events, start, now, "Events over time", "Events per day (per hour for 24 hours), by severity.") if events else None,
                  [_bars("Noisiest devices", "Devices with the most events of any kind.", [(r["name"], r["events"]) for r in rows]) if rows else None,
                   _hour_of_day([e["timestamp"] for e in events], "Events by hour of day", "Which hours of the day are busiest (all days together).") if events else None,
                   _bars("Most common problems", "Problems that opened most often.", [(c["problem"], c["count"]) for c in top]) if top else None],
                  tables)
    return res


def _device(devices, period, now, ctx):
    span = PERIODS[period]
    start = now - span
    if not devices:
        return _result([], [], "There is no device to report on.")
    d = devices[0]
    cur, prev = _avail([d["id"]], start, now)[d["id"]], _avail([d["id"]], start - span, start)[d["id"]]
    inc = _incidents([d["id"]], start, now).get(d["id"], [])
    up, up_prev = _uptime(cur), _uptime(prev)
    down = sum(s for _, s in inc)
    cpu, mem = _cpu(d["id"], start, now), _series(d["id"], "mem_used_pct", start, now)
    cpu_p95, mem_p95 = _quantile([v for _, v, _ in cpu], 0.95), _quantile([v for _, v, _ in mem], 0.95)
    cpu_prev = _quantile([v for _, v, _ in _cpu(d["id"], start - span, start)], 0.95)
    ping = _series(d["id"], "icmp_ping_ms", start, now, positive=True)
    ping_med = _median([v for _, v, _ in ping])
    ping_prev = _median([v for vs in _hourly_avgs([d["id"]], "icmp_ping_ms", start - span, start, positive=True).values() for v in vs])
    ping_cur_h = _median([v for vs in _hourly_avgs([d["id"]], "icmp_ping_ms", start, now, positive=True).values() for v in vs])
    probs = _problem_events([d["id"]], start, now + 1)
    probs_prev = _problem_events([d["id"]], start - span, start)
    kpis = []
    note, trend = _change(up, up_prev, period, "points", "up")
    kpis.append(_kpi("Availability", _pct_text(up), _uptime_tone(up), sub=f"{_minutes(down)} down" if up is not None else "", note=note, trend=trend))
    note, trend = _change(cpu_p95, cpu_prev, period, "points", "down")
    kpis.append(_kpi("CPU (95th pct)", _pct_text(cpu_p95), _tone_at(cpu_p95, LOAD_WARN, LOAD_BAD), note=note, trend=trend))
    kpis.append(_kpi("Memory (95th pct)", _pct_text(mem_p95), _tone_at(mem_p95, LOAD_WARN, LOAD_BAD)))
    note, trend = _change(ping_cur_h, ping_prev, period, "ms", "down")
    kpis.append(_kpi("Typical ping", _ms(ping_med), _tone_at(ping_med, PING_TARGET_MS, PING_TARGET_MS * 2), sub="Median", note=note, trend=trend))
    note, trend = _change(len(probs), len(probs_prev), period, "count", "down")
    kpis.append(_kpi("Problems opened", str(len(probs)), "good" if not probs else "warn", note=note, trend=trend))
    wan = ctx["wan"]() if callable(ctx.get("wan")) else set()
    ifaces = _interfaces(d, start, now, wan)
    rows = [{k: v for k, v in i.items() if not k.startswith("_") and k not in ("device_id", "idx", "wan")} for i in ifaces]
    disks = _disks(d["id"])
    import forecast
    full = {f["key"]: f.get("full_on") for f in forecast.cached(now).get(d["id"], [])}
    parts = []
    if up is not None:
        parts.append(f"The device {d['name']} was reachable {_pct_text(up)} of the time over {PERIOD_NAMES[period]}"
                     + (f" and was down for {_minutes(down)} in {_plural(len(inc), 'outage')}." if inc else " without going down."))
    else:
        parts.append(f"There are no checks of {d['name']} recorded for {PERIOD_NAMES[period]}.")
    if cpu_p95 is not None or mem_p95 is not None:
        parts.append(f"The processor stayed at or below {_pct_text(cpu_p95)} and memory at or below {_pct_text(mem_p95)} 95% of the time.")
    if ping_med is not None:
        parts.append(f"It answered ping in {_ms(ping_med)} typically.")
    fullest = max((x for x in disks if x["used_pct"] is not None), key=lambda x: x["used_pct"], default=None)
    if fullest:
        parts.append(f"Its fullest storage is {fullest['name']} at {_pct_text(fullest['used_pct'])}.")
    if probs:
        parts.append(f"{_count(len(probs), 'problem')} opened in the period.")
    bands = [{"from": LOAD_WARN, "to": LOAD_BAD, "tone": "warn"}, {"from": LOAD_BAD, "to": 100, "tone": "bad"}]
    main = {"kind": "line", "title": "Processor and memory", "unit": "%", "y_max": 100, "start": start, "end": now,
            "note": "Amber from 80% and red from 90%: time spent there is worth a look.", "bands": bands,
            "thresholds": [{"value": LOAD_WARN, "tone": "warn", "label": "Watch 80%"}, {"value": LOAD_BAD, "tone": "bad", "label": "Strained 90%"}],
            "series": [s for s in ({"name": "CPU", "points": _thin(cpu, start, now)}, {"name": "Memory", "points": _thin(mem, start, now)}) if s["points"]]} \
        if cpu or mem else None
    starts, fmt = _slots(start, now)
    per = [[0, 0] for _ in starts]
    for h in cur:
        s = per[_slot_of(starts, h[0])]
        s[0] += h[1]
        s[1] += h[2]
    daily = [round(100.0 * u / c, 3) if c else None for c, u in per]
    step = "hour" if fmt == "%H:00" else "day"
    busiest = max(ifaces, key=lambda i: max(i["in_p95"] or 0, i["out_p95"] or 0), default=None)
    charts = [
        {"kind": "line", "title": "Ping", "unit": "ms", "start": start, "end": now,
         "note": f"Typical answer time. The dashed line is the {PING_TARGET_MS:.0f} ms target.",
         "series": [{"name": "Ping", "points": _thin(ping, start, now, 150, _median)}],
         "thresholds": [{"value": PING_TARGET_MS, "tone": "warn", "label": f"Target {PING_TARGET_MS:.0f} ms"}]} if ping else None,
        {"kind": "strips", "title": f"Uptime by {step}", "note": "Green meets 99.9%, amber is 99% to 99.9%, red is below 99% and grey had no checks.",
         "rows": [{"name": d["name"], "value_text": _pct_text(up), "cells": [[v, _uptime_tone(v)] for v in daily]}],
         "start_text": _date(starts[0], fmt == "%H:00"), "end_text": _date(now)} if up is not None else None,
        _capacity("Storage", "How full each disk and volume is now. Lines at 80% and 90%.",
                  [(x["name"], x["used_pct"]) for x in disks], LOAD_WARN, LOAD_BAD) if fullest else None,
        _mirror(busiest, start, now, f"Traffic on {busiest['interface']}", "The busiest interface. Inbound above the line, outbound below it.") if busiest else None,
    ]
    tables = [_table("Storage", "Size and use now, and when it is expected to be full at the current rate.",
                     [_col("storage", "Storage"), _col("size", "Size", "bytes"), _col("used", "Used", "bytes"), _col("used_pct", "Used %", "pct"),
                      _col("full_on", "Full around", "time")],
                     [{"storage": x["name"], "size": x["size"], "used": x["used"], "used_pct": x["used_pct"],
                       "full_on": full.get(f"{'vol' if x['table'] == 'volumes' else 'stor'}.{x['idx']}.used_pct")} for x in disks])] if disks else []
    if probs:
        tables.append(_table("Problems in the period", "", [_col("time", "Opened", "time"), SEVERITY_COLS[0], _col("problem", "Problem")],
                             [{"time": e["timestamp"], "severity": _sev(e["severity"]), "problem": e["message"][len("Problem: "):]} for e in probs]))
    return _result(rows, kpis, " ".join(parts), main, charts, tables)


def _status(devices, period, now, ctx):
    state = _now_state(devices)
    counts = _counts([s[0] for s in state.values()])
    by_id = {d["id"]: d for d in devices}
    rows = []
    for p in database.list_active_problems():
        d = by_id.get(p["device_id"])
        if d:
            rows.append(dict(_base(d), severity=_sev(p["severity"]), problem=p["message"], since=p["since"],
                             ack="Acknowledged" if p.get("acknowledged_at") else "Open"))
    latest = database.get_latest_metrics_all(["cpu_usage_pct", "cpu_idle_pct", "mem_used_pct"])
    watch = []
    for d in devices:
        m = latest.get(d["id"]) or {}
        cpu = m.get("cpu_usage_pct", 100 - m["cpu_idle_pct"] if "cpu_idle_pct" in m else None)
        if cpu is not None:
            watch.append({"name": d["name"], "cpu": cpu, "mem": m.get("mem_used_pct"), "load": _load_word(cpu, m.get("mem_used_pct"))})
    watch.sort(key=lambda w: -w["cpu"])
    kpis = [_kpi("Up", str(counts.get("Up", 0)), "good", sub=f"Of {len(devices)}"),
            _kpi("With problems", str(counts.get("Problems", 0)), "warn" if counts.get("Problems") else "good"),
            _kpi("Down", str(counts.get("Down", 0)), "bad" if counts.get("Down") else "good"),
            _kpi("Not monitored", str(counts.get("Not monitored", 0)), "info", sub="No checks yet"),
            _kpi("Open problems", str(len(rows)), "bad" if any(r["severity"] in ("Critical", "High") for r in rows) else "warn" if rows else "good",
                 sub=f"{sum(1 for r in rows if r['ack'] == 'Acknowledged')} acknowledged")]
    down = [by_id[i]["name"] for i, s in state.items() if s[0] == "Down"]
    parts = [f"Of {_plural(len(devices), 'device')}, {counts.get('Up', 0)} {'is' if counts.get('Up', 0) == 1 else 'are'} up with nothing to report."]
    if down:
        parts.append(f"Down right now: {_and(down[:5])}" + (" and others." if len(down) > 5 else "."))
    if rows:
        parts.append(f"{_count(len(rows), 'problem')} {'is' if len(rows) == 1 else 'are'} open, the oldest since {_date(min(r['since'] for r in rows))}.")
    else:
        parts.append("No problems are open.")
    if watch and watch[0]["cpu"] >= LOAD_WARN:
        parts.append(f"The busiest processor is {watch[0]['name']} at {_pct_text(watch[0]['cpu'])}.")
    order = {"bad": 0, "warn": 1, "none": 2, "good": 3}
    tiles = sorted(([d["name"], state[d["id"]]] for d in devices), key=lambda x: (order[x[1][1]], x[0].lower()))
    main = {"kind": "grid", "title": "Every device now", "note": "Green is up, amber has an open problem, red is down and grey is not checked yet.",
            "tiles": [{"label": n, "tone": s[1], "sub": s[2]} for n, s in tiles]} if devices else None
    tables = [_table("Watch list", "The busiest processors right now, with their memory use.",
                     [_col("name", "Device"), _col("cpu", "CPU now", "pct"), _col("mem", "Memory now", "pct"), _col("load", "Load", "pill")],
                     watch[:10])] if watch else []
    return _result(rows, kpis, " ".join(parts), main, [
        _donut("Devices now", "How the devices are doing right now.",
               [(k, counts.get(k, 0), t) for k, t in (("Up", "good"), ("Problems", "warn"), ("Down", "bad"), ("Not monitored", "none"))], "devices") if devices else None,
        _capacity("Busiest processors now", "Processor use at the last reading. Lines at 80% and 90%.",
                  [(w["name"], w["cpu"]) for w in watch], LOAD_WARN, LOAD_BAD) if watch else None], tables)


GATHER = {"devices": _devices, "availability": _availability, "problems": _problems, "health": _health,
          "storage": _storage, "wifi": _wifi, "proxmox": _proxmox, "pihole": _pihole, "new_devices": _new_devices,
          "events": _events, "updates": _updates, "monthly": _monthly, "bandwidth": _bandwidth, "latency": _latency,
          "alerts": _alerts, "device": _device, "status": _status}


# --- Running and formatting -------------------------------------------------------------------------

def _sort_key(value: Any) -> Tuple[int, Any]:
    if value is None or value == "":
        return (1, 0)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0, value)
    return (0, str(value).lower())


def _device_facts(d: Dict[str, Any]) -> List[List[str]]:
    """A single device's details for the header band."""
    up = None
    for m in database.get_latest_metrics(d["id"]):
        if m["metric_key"] == "uptime_seconds":
            up = m["value"]
    return [["Device", d["name"]], ["Address", d["ip"]], ["Template", d.get("kind") or "Not set"], ["Group", d.get("group") or "None"],
            ["Tags", ", ".join(d.get("tags") or []) or "None"], ["SNMP", d.get("snmp") or "Not read over SNMP"],
            ["Up for", format_cell("duration", up) if up else "Not known"],
            ["Last seen", format_cell("time", d.get("last_seen")) if d.get("last_seen") else "Never"]]


def run(spec: Dict[str, Any], devices: List[Dict[str, Any]], ctx: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None) -> Dict[str, Any]:
    """Runs a checked spec over the devices given. Returns the report: its header (title, purpose,
    period, what it covers), key figures, summary, charts, the main table (chosen columns, every row
    as raw values) and any further tables."""
    ctx = ctx or {}
    now = int(now if now is not None else time.time())
    t = TEMPLATES[spec["template"]]
    covers = ctx.get("filter_text") or ""
    if t.get("one_device") and len(devices) > 1:
        devices = sorted(devices, key=lambda d: str(d["name"]).lower())[:1]
        covers = f"Device {devices[0]['name']} (choose another under Covers)"
    result = GATHER[spec["template"]](devices, spec["period"], now, ctx)
    rows = result["rows"]
    col = spec["sort"]["column"]
    nulls = [r for r in rows if r.get(col) in (None, "")]
    vals = sorted([r for r in rows if r.get(col) not in (None, "")], key=lambda r: _sort_key(r.get(col)), reverse=spec["sort"]["desc"])
    rows = vals + nulls
    total = len(rows)
    if spec["limit"]:
        rows = rows[:spec["limit"]]
    rows = rows[:MAX_ROWS]
    by_key = {c[0]: c for c in t["columns"]}
    columns = [{"key": k, "label": by_key[k][1], "type": by_key[k][2]} for k in spec["columns"]]
    span = PERIODS[spec["period"]]
    begin = datetime.fromtimestamp(now - span)
    period_text = (f"{begin.day} {begin.strftime('%b')}{begin.strftime(' %Y') if begin.year != datetime.fromtimestamp(now).year else ''}"
                   f"{begin.strftime(' %H:%M')} to {_date(now)}" if t["period"] else "Now")
    single = len(devices) == 1 and (spec["filter"].get("device") or t.get("one_device"))
    facts = [["Period", period_text + (f" ({PERIOD_NAMES[spec['period']]})" if t["period"] else "")],
             ["Covers", covers or "All devices"]]
    if not single:
        facts.append(["Devices", str(len(devices))])
    facts.append(["Made", _date(now)])
    if single:
        facts += _device_facts(devices[0])
    parts = []
    if covers:
        parts.append(covers)
    if t["period"]:
        parts.append(f"Covers {PERIOD_NAMES[spec['period']]}")
    parts.append(f"{total} row{'' if total == 1 else 's'}" + (f", the first {len(rows)} shown" if len(rows) < total else ""))
    parts.append("Made " + datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M"))
    tones = sorted({str(r.get(c["key"])) for r in rows for c in columns if c["type"] == "pill" and r.get(c["key"])}
                   | {str(v) for tb in result["tables"] for row in tb["rows"] for c, v in zip(tb["columns"], row) if c["type"] == "pill" and v})
    charts = [c for c in result["charts"] if _has_data(c)]
    main = result["main"] if result["main"] and _has_data(result["main"]) else None
    return {"title": spec["title"] or t["title"], "template": spec["template"], "subtitle": ". ".join(parts) + ".",
            "purpose": t["purpose"], "period": spec["period"] if t["period"] else "", "period_text": period_text,
            "covers": covers or "All devices", "facts": facts, "kpis": result["kpis"][:6], "summary": result["summary"],
            "main": main, "charts": charts, "table_title": t.get("table_title", "Details"),
            "columns": columns, "rows": [[r.get(c["key"]) for c in columns] for r in rows], "total": total,
            "tables": result["tables"], "tones": {v: PILL_TONES.get(v, "none") for v in tones},
            "sources": t["sources"], "footer": f"Data from {t['sources']}. Times are local ({_tz()}).", "made_at": now}


def _has_data(c: Dict[str, Any]) -> bool:
    """A chart with something to draw (an empty one is left out rather than shown blank)."""
    kind = c.get("kind")
    if kind == "line":
        return any(v is not None for s in c.get("series", []) for _, v in s.get("points", []))
    if kind == "mirror":
        return bool(c.get("in") or c.get("out"))
    if kind == "bar":
        return bool(c.get("bars"))
    if kind == "columns":
        return any(v for s in c.get("series", []) for v in s.get("values", []))
    if kind == "donut":
        return bool(c.get("segments"))
    if kind == "strips":
        return bool(c.get("rows"))
    if kind == "heatmap":
        return any(v is not None for row in c.get("values", []) for v in row)
    if kind == "grid":
        return bool(c.get("tiles"))
    return False


def _bytes(v: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(v) < 1024 or unit == "PB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024.0
    return str(v)


def _duration(s: float) -> str:
    s = int(s)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h {s % 3600 // 60} min"
    return f"{s // 86400} d {s % 86400 // 3600} h"


def format_cell(kind: str, value: Any) -> str:
    """A value as people read it, for the PDF (the page formats its own the same way)."""
    if value is None or value == "" or kind == "spark":
        return ""
    if kind in ("text", "pill") or not isinstance(value, (int, float)) or isinstance(value, bool):
        return str(value)
    if kind == "pct":
        return f"{value:.1f}%" if value < 99.95 or value >= 100 else f"{value:.2f}%"
    if kind == "ms":
        return f"{value:.0f} ms" if value >= 10 else f"{value:.1f} ms"
    if kind == "time":
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M") if value > 0 else ""
    if kind == "bytes":
        return _bytes(float(value))
    if kind == "duration":
        return _duration(value)
    if kind == "mbps":
        return f"{value / 1000:g} Gbps" if value >= 1000 else f"{value:.0f} Mbps"
    if kind == "bps":
        return _bps(float(value))
    if kind == "dbm":
        return f"{value:.0f} dBm"
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.2f}"


def _csv_value(kind: str, value: Any) -> str:
    """A CSV cell: numbers stay numbers (for a spreadsheet), times in a form spreadsheets read."""
    if value is None:
        return ""
    if kind == "time" and isinstance(value, (int, float)):
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S") if value > 0 else ""
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    text = str(value)
    # A cell starting with = + - @ would run as a formula in a spreadsheet.
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(report: Dict[str, Any]) -> bytes:
    """The main table as CSV (trend lines are left out: a spreadsheet draws its own)."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    keep = [i for i, c in enumerate(report["columns"]) if c["type"] != "spark"]
    w.writerow([report["columns"][i]["label"] for i in keep])
    kinds = [report["columns"][i]["type"] for i in keep]
    for row in report["rows"]:
        w.writerow([_csv_value(k, row[i]) for k, i in zip(kinds, keep)])
    # With a byte order mark, Excel opens it as UTF-8.
    return ("﻿" + out.getvalue()).encode("utf-8")


ALIGN_RIGHT = {"num", "pct", "ms", "bytes", "duration", "mbps", "dbm", "bps"}


def _pdf_cells(columns: List[Dict[str, Any]], rows: List[List[Any]]) -> List[List[Any]]:
    import pdfdoc
    out = []
    for row in rows:
        cells = []
        for c, v in zip(columns, row):
            if c["type"] == "pill":
                cells.append(pdfdoc.Pill(v, PILL_TONES.get(str(v), "none")) if v not in (None, "") else "")
            elif c["type"] == "spark":
                cells.append(pdfdoc.Spark(v or []))
            else:
                cells.append(format_cell(c["type"], v))
        out.append(cells)
    return out


def to_pdf(report: Dict[str, Any]) -> bytes:
    """The report as a PDF in the same layout as the page: header band, key figures, summary,
    the main chart, supporting charts two to a row, then the tables. Page N of M at the foot."""
    import pdfdoc
    cols = report["columns"]
    doc = pdfdoc.Document(title=report["title"], landscape=len(cols) > 7, footer=report.get("footer") or "Times are local.")
    doc.header_band(report["title"], report.get("purpose", ""), [tuple(f) for f in report.get("facts", [])])
    if report.get("kpis"):
        doc.kpi_tiles(report["kpis"])
    if report.get("summary"):
        doc.section("Summary")
        doc.text(report["summary"], size=9.5)
        doc.space(8)
    if report.get("main"):
        doc.chart(report["main"])
    if report.get("charts"):
        doc.chart_grid(report["charts"], columns=2)
    doc.section(report.get("table_title") or "Details",
                f"{report['total']} row{'' if report['total'] == 1 else 's'}" + (f", the first {len(report['rows'])} shown" if len(report["rows"]) < report["total"] else ""))
    doc.table([c["label"] for c in cols], _pdf_cells(cols, report["rows"]),
              align=["r" if c["type"] in ALIGN_RIGHT else "l" for c in cols])
    for tb in report.get("tables", []):
        doc.section(tb["title"], tb.get("note", ""))
        doc.table([c["label"] for c in tb["columns"]], _pdf_cells(tb["columns"], tb["rows"]),
                  align=["r" if c["type"] in ALIGN_RIGHT else "l" for c in tb["columns"]])
    return doc.render()


def file_name(report: Dict[str, Any], ext: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", report["title"].lower()).strip("-")[:60] or "report"
    return f"{slug}-{datetime.fromtimestamp(report['made_at']).strftime('%Y-%m-%d-%H%M')}.{ext}"
