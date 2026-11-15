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
    "Healthy": "good", "Done": "good", "Plan": "info", "Investigating": "warn", "Monitoring": "warn",
    "P1": "bad", "P2": "warn", "P3": "info", "Maintenance": "none", "Still down": "bad", "Busy now": "warn",
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
        "columns": DEVICE_COLS + [_col("interface", "Interface"), _col("description", "Description"), _col("speed", "Speed", "mbps"),
                                  _col("in_p95", "In (95th pct)", "bps"), _col("out_p95", "Out (95th pct)", "bps"), _col("peak", "Peak", "bps"),
                                  _col("util", "Use (95th pct)", "pct"), _col("state", "Load", "pill")],
        "default": ["name", "interface", "description", "speed", "in_p95", "out_p95", "peak", "util", "state"],
        "sort": "util", "desc": True, "table_title": "Interface detail (95th percentile, billing method)",
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
        "columns": [_col("interface", "Interface"), _col("description", "Description"), _col("speed", "Speed", "mbps"),
                    _col("in_p95", "In (95th pct)", "bps"), _col("out_p95", "Out (95th pct)", "bps"), _col("peak", "Peak", "bps"),
                    _col("util", "Use (95th pct)", "pct"), _col("state", "Load", "pill")],
        "default": ["interface", "description", "speed", "in_p95", "out_p95", "peak", "util", "state"],
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
        boundary = end if oldest is None else min(end, max(start, oldest - oldest % 3600 + 3600))
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
            tables: Optional[List[Optional[Dict[str, Any]]]] = None) -> Dict[str, Any]:
    """What a first-generation template gathers. Its parts keep their place in the call (chart.0,
    chart.1, tables.0...), so a template's block list can name them; a None part does not apply."""
    charts, tables = list(charts or []), list(tables or [])
    parts: Dict[str, Any] = {"kpis": kpis or [], "summary": summary, "main": main}
    parts.update({f"chart.{i}": ch for i, ch in enumerate(charts)})
    parts.update({f"tables.{i}": tb for i, tb in enumerate(tables)})
    return {"rows": rows, "kpis": kpis or [], "summary": summary, "main": main, "charts": [ch for ch in charts if ch],
            "tables": [tb for tb in tables if tb], "parts": parts}


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
                         + (f". {_count(len(went) - 3, 'more device')} went down too." if len(went) > 3 else "."))
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
        label = str(r.get("label") or r.get("descr") or idx)
        nums = {k: r.get(k) for k in ("in_errors", "out_errors", "in_discards", "out_discards", "in_ucast", "out_ucast")}
        out.append(dict(_base(device), device_id=device["id"], idx=idx, wan=is_wan, interface=label, description=str(r.get("alias") or ""),
                        speed=speed, in_p95=in_p95, out_p95=out_p95, peak=peak, util=round(util, 1) if util is not None else None,
                        state=state, _in=ins, _out=outs, _counters=nums))
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
        for label, key, direction in (("in", "in_p95", "in"), ("out", "out_p95", "out")):
            pct = 100.0 * focus[key] / (focus["speed"] * 1e6) if focus.get("speed") and focus.get(key) is not None else None
            kpis.append(_kpi(f"{'Internet' if focus['wan'] else 'Busiest link'} {label} (95th pct)", _bps(focus[key]),
                             _tone_at(pct, LINK_WARN, LINK_BAD) if pct is not None else "info",
                             sub=f"{pct:.0f}% of {format_cell('mbps', focus['speed'])}" if pct is not None else f"{focus['name']} {focus['interface']}"))
    full = [i for i in ifaces if i["util"] is not None and i["util"] >= LINK_BAD]
    prev_full = 0
    for i in ifaces:
        if not i.get("speed"):
            continue
        p_in = _quantile([v for _, v, _ in _series(i["device_id"], f"if.{i['idx']}.in_bps", start - span, start)], 0.95)
        p_out = _quantile([v for _, v, _ in _series(i["device_id"], f"if.{i['idx']}.out_bps", start - span, start)], 0.95)
        if p_in is not None or p_out is not None:
            prev_full += 1 if 100.0 * max(p_in or 0, p_out or 0) / (i["speed"] * 1e6) >= LINK_BAD else 0
    note, trend = _change(len(full), prev_full, period, "count", "down")
    kpis.append(_kpi(f"Interfaces over {LINK_BAD:.0f}%", str(len(full)), "bad" if full else "good",
                     sub="At the 95th percentile", note=note, trend=trend))
    errs = sum(sum(i["_counters"].get(k) or 0 for k in ("in_errors", "out_errors", "in_discards", "out_discards")) for i in ifaces)
    packets = sum((i["_counters"].get("in_ucast") or 0) + (i["_counters"].get("out_ucast") or 0) for i in ifaces)
    err_pct = 100.0 * errs / packets if packets else None
    kpis.append(_kpi("Errors and discards", f"{err_pct:.3f}%" if err_pct is not None and err_pct < 0.1 else _pct_text(err_pct),
                     _tone_at(err_pct, 0.01, 0.1), sub="Of packets, since the counters last reset"))
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
    main = _mirror(focus, start, now, f"{'Internet uplink' if focus['wan'] else 'Busiest link'} {focus['name']} {focus['interface']}, in and out",
                   "Inbound above the line, outbound below it. Averages per step of the chart.") if focus else None
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
        parts = [f"Devices typically answered ping in {_ms(cur)}; 95% of answers came within {_ms(p95_all)}."]
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
    tables: List[Optional[Dict[str, Any]]] = [_table("Storage", "Size and use now, and when it is expected to be full at the current rate.",
                     [_col("storage", "Storage"), _col("size", "Size", "bytes"), _col("used", "Used", "bytes"), _col("used_pct", "Used %", "pct"),
                      _col("full_on", "Full around", "time")],
                     [{"storage": x["name"], "size": x["size"], "used": x["used"], "used_pct": x["used_pct"],
                       "full_on": full.get(f"{'vol' if x['table'] == 'volumes' else 'stor'}.{x['idx']}.used_pct")} for x in disks])] if disks else [None]
    tables.append(_table("Problems in the period", "", [_col("time", "Opened", "time"), SEVERITY_COLS[0], _col("problem", "Problem")],
                         [{"time": e["timestamp"], "severity": _sev(e["severity"]), "problem": e["message"][len("Problem: "):]} for e in probs])
                  if probs else None)
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


# --- Blocks: one model for the templates and for custom reports -------------------------------------
#
# A report is a header and a list of blocks, read top to bottom. The page (reports.js) and the PDF
# (to_pdf) both draw the same rendered blocks, so a template and a custom report look alike:
#   kpi_row     key figures, up to six tiles, each compared with the previous period or a target
#   chart       one chart: a data source, a view of it (over time, per device, by hour...) and a chart
#               type that suits that view's shape (spec 11.3: only charts that make sense are offered)
#   table       rows of devices, interfaces, groups, problem types, open problems, resources or outages
#   text        words written by the user, or written from the data ("auto")
#   key_value   one device's details
#   two_column  two charts, texts or details side by side (one column on a narrow screen)
#   part        a piece of one of the first templates: its key figures, summary, a chart or its table
#
# Everything a definition names is checked against the lists below (parse_blocks), and every block
# reads only the devices the report covers, which the server has already limited to the user's own.

MAX_BLOCKS = 30            # blocks in a custom report, the two halves of a side by side row counted too
MAX_TEXT = 4000
MAX_TILES = 6
MAX_TOP = 50
MAX_COLUMNS = 16
MAX_SCOPE_DEVICES = 200
MAX_TABLE_ROWS = 500
BLOCK_TYPES = ("kpi_row", "chart", "table", "text", "key_value", "two_column", "part")
SIDE_TYPES = ("chart", "text", "key_value")
FAILED_WARN, FAILED_BAD = 0.5, 1.0       # failed checks, percent (the spec's packet loss limits)
TEMP_WARN, TEMP_BAD = 70.0, 85.0         # degrees C
FORECAST_MIN_DAYS = 14                   # days of daily peaks before a trend is drawn
FORECAST_GOOD_DAYS = 30                  # below this the forecast is marked as an early estimate
BASELINE_WEEKS = 4
BASELINE_K = 2.5
SCORE_WEIGHTS = (("availability", 40), ("ping", 30), ("failed", 15), ("headroom", 15))
PING_BAD_MS = PING_TARGET_MS * 4         # the ping that scores 0 in a health score

# The chart types (spec section 8 numbers), each drawn on the page and in the PDF.
CHARTS: Dict[str, Dict[str, Any]] = {
    "line": {"n": 1, "label": "Line"},
    "multi_line": {"n": 2, "label": "Several lines"},
    "mirror": {"n": 4, "label": "In and out, mirrored"},
    "step": {"n": 5, "label": "Step"},
    "threshold": {"n": 6, "label": "Line with limit zones"},
    "band": {"n": 7, "label": "Percentile band"},
    "baseline": {"n": 8, "label": "Against the usual (baseline)"},
    "forecast": {"n": 9, "label": "Trend forecast"},
    "multiples": {"n": 12, "label": "Small multiples"},
    "headline": {"n": 13, "label": "Sparkline with headline"},
    "sparktable": {"n": 14, "label": "Sparkline table"},
    "gauge": {"n": 16, "label": "Gauge"},
    "bullet": {"n": 17, "label": "Bullet"},
    "capacity": {"n": 18, "label": "Capacity bars"},
    "strips": {"n": 19, "label": "Uptime bars"},
    "grid": {"n": 20, "label": "Status grid"},
    "columns": {"n": 21, "label": "Columns"},
    "bar": {"n": 22, "label": "Top N bars"},
    "grouped": {"n": 23, "label": "Grouped columns"},
    "stacked": {"n": 24, "label": "Stacked columns"},
    "diverging": {"n": 25, "label": "Diverging bars"},
    "butterfly": {"n": 26, "label": "Butterfly"},
    "lollipop": {"n": 27, "label": "Lollipop"},
    "dumbbell": {"n": 28, "label": "Dumbbell"},
    "radar": {"n": 29, "label": "Radar"},
    "donut": {"n": 31, "label": "Donut with total"},
    "treemap": {"n": 33, "label": "Treemap"},
    "stack100": {"n": 35, "label": "100% stacked bars"},
    "waterfall": {"n": 36, "label": "Waterfall"},
    "pareto": {"n": 37, "label": "Pareto"},
    "histogram": {"n": 38, "label": "Histogram"},
    "box": {"n": 39, "label": "Box plot"},
    "cdf": {"n": 41, "label": "Cumulative (CDF)"},
    "heatmap": {"n": 44, "label": "Hour by weekday"},
    "calendar": {"n": 45, "label": "Calendar"},
    "clock": {"n": 46, "label": "Clock, by hour"},
    "gantt": {"n": 47, "label": "Outage timeline"},
    "scatter": {"n": 48, "label": "Scatter with quadrants"},
    "topology": {"n": 50, "label": "Network map"},
    "timeline": {"n": 0, "label": "Event timeline"},
}

# The shapes of data (spec 11.3), named for the builder.
SHAPES = {
    "series": "One series over time", "multi": "Several series over time", "inout": "In and out over time",
    "count_time": "A count over time", "state_time": "Down and up over time", "pct_time": "Percentiles over time",
    "current": "One value now", "category": "One value per device or group", "target": "A value against a target per device or group",
    "pair": "Two values per device or group", "composition": "Parts of a total", "distribution": "Every sample",
    "hour_week": "By hour and weekday", "days": "Day by day over weeks", "scatter": "Two figures per device",
    "profile": "A health profile", "status": "Every device now", "topology": "How devices connect",
    "timeline": "What happened when", "forecast": "Trend and forecast", "list": "A list with trend lines",
}

AGGS: Dict[str, Tuple[str, Callable[[List[float]], Optional[float]]]] = {
    "median": ("Median", _median), "avg": ("Average", _mean), "p95": ("95th percentile", lambda v: _quantile(v, 0.95)),
    "max": ("Highest", lambda v: max(v) if v else None), "min": ("Lowest", lambda v: min(v) if v else None),
}
SPLITS = {"auto": "Per group, or per device when there is one group", "device": "Per device", "group": "Per group",
          "interface": "Per interface", "rule": "Per problem type", "severity": "Per severity", "type": "Per kind of event"}


def _agg(values: List[float], how: str) -> Optional[float]:
    return AGGS.get(how, AGGS["median"])[1](values) if values else None


def _r(v: Optional[float], digits: int = 2) -> Optional[float]:
    return None if v is None else round(v, digits)


class Ctx:
    """What a report's blocks read: the devices it covers, its period and a cache the blocks share."""

    def __init__(self, devices: List[Dict[str, Any]], period: str, now: int, env: Dict[str, Any], all_devices: bool):
        self.all = devices
        self.period = period
        self.now = now
        self.env = env
        self.all_devices = all_devices
        self.cache: Dict[Any, Any] = {}
        self.focus: Optional[Tuple[int, int]] = None          # the outage review's window
        self.focus_info: Dict[str, Any] = {}

    def memo(self, key: Any, make: Callable[[], Any]) -> Any:
        if key not in self.cache:
            self.cache[key] = make()
        return self.cache[key]

    def window(self, b: Dict[str, Any]) -> Tuple[int, int, str]:
        """The block's window: the outage being reviewed, its own period or the report's."""
        if self.focus:
            return self.focus[0], self.focus[1], self.period
        p = b.get("period") if b.get("period") in PERIODS else self.period
        return self.now - PERIODS[p], self.now, p


def _gname(d: Dict[str, Any]) -> str:
    return d.get("group") or "No group"


def _scope(c: Ctx, b: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The block's devices: the report's, narrowed to a group, a tag or chosen devices. Only ever a
    subset of what the report covers (which the server limited to what the user may see)."""
    sc = b.get("scope") or {}
    kind = sc.get("kind")
    if kind == "group":
        return [d for d in c.all if sc.get("group") in (d.get("group_id"), d.get("group"))]
    if kind == "tag":
        return [d for d in c.all if sc.get("tag") in (d.get("tags") or [])]
    if kind == "devices":
        ids = set(sc.get("devices") or [])
        return [d for d in c.all if d["id"] in ids]
    return c.all


def _split(b: Dict[str, Any], devs: List[Dict[str, Any]], default: str = "auto") -> str:
    s = b.get("split") or default
    if s == "auto":
        return "group" if len({_gname(d) for d in devs}) > 1 else "device"
    return s


def _cats(devs: List[Dict[str, Any]], split: str) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """(label, devices) per device or per group, in name order."""
    if split == "group":
        out: Dict[str, List[Dict[str, Any]]] = {}
        for d in devs:
            out.setdefault(_gname(d), []).append(d)
        return sorted(out.items(), key=lambda kv: kv[0].lower())
    return [(str(d["name"]), [d]) for d in sorted(devs, key=lambda d: str(d["name"]).lower())]


def _limits(b: Dict[str, Any], warn: float, bad: float) -> Tuple[float, float, bool]:
    th = b.get("threshold") or {}
    if th.get("mode") == "override":
        w = th.get("warn") if isinstance(th.get("warn"), (int, float)) else warn
        x = th.get("bad") if isinstance(th.get("bad"), (int, float)) else bad
        return float(w), float(x), True
    return warn, bad, False


def _target(b: Dict[str, Any], default: float) -> float:
    th = b.get("threshold") or {}
    if th.get("mode") == "override" and isinstance(th.get("target"), (int, float)):
        return float(th["target"])
    return default


def _top(b: Dict[str, Any], default: int) -> int:
    t = b.get("top")
    return t if isinstance(t, int) and not isinstance(t, bool) and 0 < t <= MAX_TOP else default


def _unit_text(v: Optional[float], unit: str) -> str:
    if v is None:
        return "No data"
    if unit == "ms":
        return _ms(v)
    if unit == "%":
        return f"{v:g}%" if float(v).is_integer() else _pct_text(v)
    if unit == "bps":
        return _bps(v)
    if unit == "min":
        return _minutes(v * 60)
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:,.1f}"


# Reading the data, once per report ---------------------------------------------------------------------

def _hours(c: Ctx, start: int, end: int) -> Dict[int, List[Tuple[int, int, int, float, int]]]:
    return c.memo(("avail", start, end), lambda: _avail([d["id"] for d in c.all], start, end))


def _outages(c: Ctx, start: int, end: int) -> Dict[int, List[Tuple[int, Optional[int]]]]:
    """Per device: its outages overlapping the window as (started, ended or None while still down)."""
    def load() -> Dict[int, List[Tuple[int, Optional[int]]]]:
        out: Dict[int, List[Tuple[int, Optional[int]]]] = {}
        ids = [d["id"] for d in c.all]
        if not ids:
            return out
        marks = ",".join("?" * len(ids))
        with database.get_connection() as conn:
            for r in conn.execute(f"SELECT device_id, started, ended FROM avail_incidents WHERE device_id IN ({marks}) "
                                  "AND (ended IS NULL OR ended >= ?) AND started <= ? ORDER BY started;", (*ids, start, end)):
                out.setdefault(r["device_id"], []).append((r["started"], r["ended"]))
        return out
    return c.memo(("outages", start, end), load)


def _down_seconds(spans: List[Tuple[int, Optional[int]]], start: int, end: int) -> int:
    return sum(max(0, min(e or end, end) - max(s, start)) for s, e in spans)


def _pings(c: Ctx, d: Dict[str, Any], start: int, end: int) -> List[Tuple[int, float, float]]:
    return c.memo(("ping", d["id"], start, end), lambda: _series(d["id"], "icmp_ping_ms", start, end, positive=True))


def _metric(c: Ctx, d: Dict[str, Any], key: str, start: int, end: int) -> List[Tuple[int, float, float]]:
    if key == "ping":
        return _pings(c, d, start, end)
    if key == "cpu":
        return c.memo(("cpu", d["id"], start, end), lambda: _cpu(d["id"], start, end))
    return c.memo((key, d["id"], start, end), lambda: _series(d["id"], "mem_used_pct", start, end))


def _problem_log(c: Ctx, start: int, end: int) -> List[Dict[str, Any]]:
    """Problem events (opened, resolved, acknowledged) of the covered devices in the window, oldest first."""
    def load() -> List[Dict[str, Any]]:
        ids = {d["id"] for d in c.all}
        if not ids:
            return []
        events, _ = database.list_events_filtered(event_type="problem", since=start, until=end + 1, device_ids=ids, limit=MAX_ROWS)
        return sorted(events, key=lambda e: (e["timestamp"], e["id"]))
    return c.memo(("problems", start, end), load)


def _opened(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> List[Dict[str, Any]]:
    ids = {d["id"] for d in devs}
    return [e for e in _problem_log(c, start, end) if e["device_id"] in ids and str(e["message"]).startswith("Problem: ")]


def _all_events(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> List[Dict[str, Any]]:
    def load() -> List[Dict[str, Any]]:
        ids = {d["id"] for d in c.all}
        if not ids:
            return []
        events, _ = database.list_events_filtered(since=start, until=end + 1, device_ids=ids, limit=MAX_ROWS)
        return events
    ids = {d["id"] for d in devs}
    return [e for e in c.memo(("events", start, end), load) if e["device_id"] in ids]


_LASTED = re.compile(r"\(lasted ((?:\d+[dhms] ?)+)\)\s*$")


def _lasted_seconds(message: str) -> Optional[int]:
    """The duration in a "Resolved: ... (lasted 1h 5m)" event, in seconds."""
    m = _LASTED.search(message)
    if not m:
        return None
    unit = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    return sum(int(n) * unit[u] for n, u in re.findall(r"(\d+)([dhms])", m.group(1)))


def _problem_types(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> List[Dict[str, Any]]:
    """Problems grouped by type (the text with its numbers taken out): how often, on how many
    devices, how long they lasted, how many cleared within 5 minutes without anyone acknowledging
    them, and whether one is still open."""
    ids = {d["id"] for d in devs}
    log = [e for e in _problem_log(c, start, end) if e["device_id"] in ids]
    active = {(p["device_id"], _stem(p["message"])) for p in database.list_active_problems() if p["device_id"] in ids}
    acked: set = set()
    types: Dict[str, Dict[str, Any]] = {}
    for e in log:
        msg = str(e["message"])
        if msg.startswith("Acknowledged: "):
            acked.add((e["device_id"], _stem(msg[len("Acknowledged: "):])))
            continue
        if msg.startswith("Problem: "):
            text = re.sub(r" \(during maintenance\)$", "", msg[len("Problem: "):])
            t = types.setdefault(_key(text), {"problem": text, "count": 0, "ids": set(), "last": 0, "durations": [], "quick": 0,
                                              "open": False, "severity": "Info", "first": e["timestamp"]})
            t["count"] += 1
            t["ids"].add(e["device_id"])
            t["last"] = max(t["last"], e["timestamp"])
            if {"Critical": 3, "High": 2, "Warning": 1}.get(_sev(e["severity"]), 0) > {"Critical": 3, "High": 2, "Warning": 1}.get(t["severity"], 0):
                t["severity"] = _sev(e["severity"])
            if (e["device_id"], _stem(text)) in active:
                t["open"] = True
        elif msg.startswith("Resolved: "):
            body = _LASTED.sub("", msg[len("Resolved: "):]).strip()
            t = types.get(_key(body))
            secs = _lasted_seconds(msg)
            if t is not None and secs is not None:
                t["durations"].append(secs)
                if secs < 300 and (e["device_id"], _stem(body)) not in acked:
                    t["quick"] += 1
    return sorted(types.values(), key=lambda t: (-t["count"], t["problem"].lower()))


def _ack_times(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> List[int]:
    """Seconds from a problem opening to its acknowledgement in the app, for those acknowledged."""
    ids = {d["id"] for d in devs}
    opened: Dict[Tuple[int, str], int] = {}
    out = []
    for e in _problem_log(c, start, end):
        if e["device_id"] not in ids:
            continue
        msg = str(e["message"])
        if msg.startswith("Problem: "):
            opened[(e["device_id"], _stem(msg[len("Problem: "):]))] = e["timestamp"]
        elif msg.startswith("Acknowledged: "):
            t = opened.pop((e["device_id"], _stem(msg[len("Acknowledged: "):])), None)
            if t is not None:
                out.append(e["timestamp"] - t)
    return out


def _all_interfaces(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> List[Dict[str, Any]]:
    wan = c.memo("wan", lambda: c.env["wan"]() if callable(c.env.get("wan")) else set())
    return [i for d in devs for i in c.memo(("ifaces", d["id"], start, end), lambda d=d: _interfaces(d, start, end, wan))]


def _ifload(i: Dict[str, Any]) -> float:
    return max(i["in_p95"] or 0, i["out_p95"] or 0)


def _focus_interface(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> Optional[Dict[str, Any]]:
    ifaces = _all_interfaces(c, devs, start, end)
    wans = [i for i in ifaces if i["wan"]]
    return max(wans or ifaces, key=_ifload, default=None)


def _now_words(c: Ctx) -> Dict[int, Tuple[str, str, str]]:
    return c.memo("now", lambda: _now_state(c.all))


def _maint_spans(c: Ctx, d: Dict[str, Any], start: int, end: int) -> List[Tuple[int, int]]:
    """Maintenance windows over the device inside the window (the monitor keeps ended ones a week)."""
    def load() -> List[Dict[str, Any]]:
        import maintenance
        return maintenance.windows(c.now)
    probe = {"id": d["id"], "group": d.get("group_id") or "", "tags": d.get("tags") or []}
    out = []
    import maintenance
    for w in c.memo("maint", load):
        if w["end"] > start and w["start"] < end and maintenance.covers(w, probe):
            out.append((max(w["start"], start), min(w["end"], end)))
    return out


def _bucket(span: int) -> int:
    """Bucket size for a percentile band: about 100 buckets, never under 15 minutes."""
    for size in (900, 3600, 3 * 3600, 6 * 3600, 86400):
        if span / size <= 120:
            return size
    return 86400


def _bucket_text(size: int) -> str:
    return {900: "15 minutes", 3600: "hour", 3 * 3600: "3 hours", 6 * 3600: "6 hours", 86400: "day"}.get(size, f"{size // 60} minutes")


def _step_name(fmt: str) -> str:
    return "hour" if fmt == "%H:00" else "day"


def _slot_mid(starts: List[int], fmt: str) -> List[int]:
    half = 1800 if fmt == "%H:00" else 43200
    return [s + half for s in starts]


def _health_scores(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> Dict[str, Optional[float]]:
    """Each figure turned into a 0 to 100 score where 100 is best (spec 4.11):
    availability 100 at 100% falling to 0 at 99%; ping 100 at 0 ms falling to 0 at PING_BAD_MS
    (median); processor and memory 100 minus the 95th percentile; failed checks 100 at none
    falling to 0 at 2%; disk 100 minus the fullest disk now; problems 100 with none, 10 less for each."""
    hrs = _hours(c, start, end) if end - start <= 400 * 86400 else {}
    up = _uptime([h for d in devs for h in hrs.get(d["id"], [])])
    pings = [v for d in devs for _, v, _ in _pings(c, d, start, end)]
    cpu = [v for d in devs for _, v, _ in _metric(c, d, "cpu", start, end)]
    mem = [v for d in devs for _, v, _ in _metric(c, d, "memory", start, end)]
    disks = [x["used_pct"] for d in devs for x in _disks(d["id"]) if x["used_pct"] is not None]
    probs = len(_opened(c, devs, start, end))
    med = _median(pings)
    clamp = lambda v: None if v is None else round(max(0.0, min(100.0, v)), 1)
    return {"Availability": clamp(100 - (100 - up) * 100) if up is not None else None,
            "Ping": clamp(100 - med / PING_BAD_MS * 100) if med is not None else None,
            "Processor": clamp(100 - _quantile(cpu, 0.95)) if cpu else None,
            "Memory": clamp(100 - _quantile(mem, 0.95)) if mem else None,
            "Failed checks": clamp(100 - (100 - up) * 50) if up is not None else None,
            "Disk": clamp(100 - max(disks)) if disks else None,
            "Problems": clamp(100 - 10 * probs) if (up is not None or pings or cpu) else None}


SCORE_NOTE = ("Scores run from 0 to 100, 100 is best: availability 100 at 100% and 0 at 99%; ping 100 at 0 ms and 0 at "
              f"{PING_BAD_MS:.0f} ms (median); processor and memory 100 minus the 95th percentile; failed checks 0 at 2%; "
              "disk 100 minus the fullest disk; problems 10 less for each one opened.")


def _group_score(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int) -> Dict[str, Any]:
    """A weighted score for a group (spec report 9): availability, median ping, failed checks and the
    headroom left on its busiest link. A figure without data drops out and the others share its weight."""
    hrs = _hours(c, start, end)
    up = _uptime([h for d in devs for h in hrs.get(d["id"], [])])
    med = _median([v for d in devs for _, v, _ in _pings(c, d, start, end)])
    utils = [i["util"] for i in _all_interfaces(c, devs, start, end) if i["util"] is not None]
    peak = max(utils) if utils else None
    parts = {"availability": max(0.0, min(100.0, 100 - (100 - up) * 100)) if up is not None else None,
             "ping": max(0.0, min(100.0, 100 - med / PING_BAD_MS * 100)) if med is not None else None,
             "failed": max(0.0, min(100.0, 100 - (100 - up) * 50)) if up is not None else None,
             "headroom": max(0.0, 100 - peak) if peak is not None else None}
    weights = [(parts[k], w) for k, w in SCORE_WEIGHTS if parts[k] is not None]
    score = sum(v * w for v, w in weights) / sum(w for _, w in weights) if weights else None
    return {"score": round(score) if score is not None else None, "availability": up, "ping": med,
            "failed": round(100 - up, 3) if up is not None else None, "util": peak}


SCORE_TEXT = ("Score = " + ", ".join(f"{w}% {n}" for n, w in (("availability", 40), ("ping", 30), ("failed checks", 15)))
              + " and 15% headroom on the busiest link. Availability scores 0 at 99%, ping 0 at "
              + f"{PING_BAD_MS:.0f} ms, failed checks 0 at 2%. A figure without data drops out and the others share its weight.")


def _score_word(score: Optional[float]) -> str:
    return "No data" if score is None else "Healthy" if score >= 80 else "At risk" if score >= 60 else "Breached"


# Views: one way of looking at a source. Each returns a chart spec (kind and data) for both renderers.
# A view with nothing to show still returns its chart, which draws its "No data" state (spec 5.6).

def _per_slot(hours_by_dev: Dict[int, List[Tuple[int, int, int, float, int]]], devs: List[Dict[str, Any]],
              starts: List[int]) -> List[Optional[float]]:
    per = [[0, 0] for _ in starts]
    for d in devs:
        for h in hours_by_dev.get(d["id"], []):
            s = per[_slot_of(starts, h[0])]
            s[0] += h[1]
            s[1] += h[2]
    return [round(100.0 * u / k, 3) if k else None for k, u in per]


def _zoom_floor(values: List[float], target: float) -> float:
    floor = min([target - 0.4] + values)
    return next((v for v in (99.5, 99.0, 98.0, 95.0, 90.0) if v <= floor), 0.0)


def _avail_tone(v: Optional[float], target: float) -> str:
    return _tone_at(v, target, min(99.0, target - 0.5), high_is_bad=False)


def _v_avail_time(c, b, devs, start, end, period):
    target = _target(b, UPTIME_TARGET)
    starts, fmt = _slots(start, end)
    vals = _per_slot(_hours(c, start, end), devs, starts)
    step = _step_name(fmt)
    measured = [v for v in vals if v is not None]
    y_min = _zoom_floor(measured, target)
    zoom = f"The axis starts at {y_min:g}% so small dips show. " if y_min else ""
    if b["chart"] == "columns":
        return {"kind": "columns", "title": f"Availability per {step}", "unit": "%", "y_min": y_min, "y_max": 100,
                "note": zoom + f"Bars below the {target:g}% target (dashed line) are red or amber. Planned maintenance is left out.",
                "labels": _slot_labels(starts, fmt), "series": [{"name": "Availability", "values": vals}],
                "bar_tones": [_avail_tone(v, target) for v in vals],
                "target": {"value": target, "label": f"Target {target:g}%", "tone": "bad"}}
    spec = {"kind": "line", "title": f"Availability per {step}", "unit": "%", "y_min": y_min, "y_max": 100, "start": start, "end": end,
            "note": zoom + "Planned maintenance is left out.",
            "series": [{"name": "Availability", "points": list(zip(_slot_mid(starts, fmt), vals))}],
            "thresholds": [{"value": target, "tone": "bad", "label": f"Target {target:g}%"}]}
    if b["chart"] == "threshold":
        low = min(99.0, target - 0.5)
        spec["bands"] = [{"from": y_min, "to": low, "tone": "bad"}, {"from": low, "to": target, "tone": "warn"}]
    return spec


def _cat_avail(c, devs, start, end, split):
    hrs = _hours(c, start, end)
    return [(label, _uptime([h for d in members for h in hrs.get(d["id"], [])])) for label, members in _cats(devs, split)]


def _category_chart(b: Dict[str, Any], title: str, note: str, pairs: List[Tuple[str, Optional[float]]], unit: str,
                    tone: Callable[[Optional[float]], Optional[str]], worst_high: bool, top: int,
                    marks: Optional[List[Dict[str, Any]]] = None, max_value: Optional[float] = None) -> Dict[str, Any]:
    """One value per category as bars, columns, a lollipop, capacity bars or a treemap. Worst first;
    a category without data shows "n/a" rather than a zero bar (spec 21)."""
    known = sorted([(l, v) for l, v in pairs if v is not None], key=lambda p: -p[1] if worst_high else p[1])[:top]
    missing = [l for l, v in pairs if v is None]
    chart = b["chart"]
    extra = f" No data for {_plural(len(missing), 'more')}." if missing and len(known) < top else ""
    if chart == "lollipop":
        return {"kind": "lollipop", "title": title, "note": note + extra, "unit": unit, "max": max_value,
                "items": [[l, round(v, 3), tone(v)] for l, v in known], "thresholds": marks or []}
    if chart == "columns":
        return {"kind": "columns", "title": title, "note": note + extra, "unit": unit, "labels": [l for l, _ in known],
                "series": [{"name": title, "values": [round(v, 3) for _, v in known]}], "bar_tones": [tone(v) for _, v in known],
                "y_max": max_value, "target": marks[0] if marks else None}
    if chart == "treemap":
        return _treemap(title, note + extra, [(l, v, None) for l, v in known if v > 0], unit)
    out = {"kind": "bar", "title": title, "note": note + extra, "unit": unit, "bars": [[l, round(v, 3), tone(v)] for l, v in known],
           "thresholds": marks or []}
    if chart == "capacity" or max_value:
        out["max"] = max_value or 100
    return out


def _v_avail_per(c, b, devs, start, end, period):
    split = _split(b, devs)
    target = _target(b, UPTIME_TARGET)
    pairs = _cat_avail(c, devs, start, end, split)
    who = "group" if split == "group" else "device"
    if b["chart"] == "bullet":
        known = sorted([(l, v) for l, v in pairs if v is not None], key=lambda p: p[1])[:_top(b, 10)]
        low = min([v for _, v in known] + [99.0])
        low = next((x for x in (99.0, 98.0, 95.0, 90.0, 0.0) if x <= low), 0.0)
        return {"kind": "bullet", "title": f"Availability per {who}", "unit": "%", "min": low, "max": 100.0,
                "note": f"The axis starts at {low:g}%. The red tick is the {target:g}% target; the grey shades run from poor to good.",
                "rows": [[l, round(v, 3), _pct_text(v)] for l, v in known], "target": target, "target_label": f"Target {target:g}%",
                "bands": [low, (low + target) / 2 if low < target else low, target]}
    if b["chart"] == "diverging":
        rows = sorted([(l, round(target - v, 3)) for l, v in pairs if v is not None], key=lambda p: -p[1])[:_top(b, 10)]
        return {"kind": "diverging", "title": f"Distance from the {target:g}% target", "unit": "points",
                "note": "Points of availability below the target go right (worse), above it go left (better).",
                "rows": [[l, d, f"{abs(d):.2f} points {'below' if d > 0 else 'above'}"] for l, d in rows],
                "left_text": "Better than the target", "right_text": "Worse than the target"}
    return _category_chart(b, f"Availability per {who}", f"Lowest first. Bars start at 0%. Planned maintenance is left out.",
                           pairs, "%", lambda v: _avail_tone(v, target), False, _top(b, 10),
                           [{"value": target, "tone": "bad", "label": f"Target {target:g}%"}], 100.0)


def _v_avail_days(c, b, devs, start, end, period):
    target = _target(b, UPTIME_TARGET)
    starts, fmt = _slots(start, end)
    hrs = _hours(c, start, end)
    step = _step_name(fmt)
    if b["chart"] == "calendar":
        vals = _per_slot(hrs, devs, starts) if step == "day" else _per_slot(hrs, devs, _slots(start - 6 * 86400, end)[0])
        days = starts if step == "day" else _slots(start - 6 * 86400, end)[0]
        down = _outages(c, days[0], end)
        cells, months = [], []
        first = datetime.fromtimestamp(days[0])
        offset = first.weekday()
        for i, (ts, v) in enumerate(zip(days, vals)):
            d = datetime.fromtimestamp(ts)
            week = (i + offset) // 7
            if d.day == 1 or i == 0:
                months.append([week, d.strftime("%b")])
            nxt = ts + 86400
            mins = sum(_down_seconds(spans, ts, nxt) for dev in devs for spans in [down.get(dev["id"], [])]) / 60
            tone = "none" if v is None else "good" if v >= 100 else "good" if v >= target else "warn" if v >= 99 else "bad"
            text = f"{d.day} {d.strftime('%b')}: " + ("no checks" if v is None else f"{_pct_text(v)}, {_minutes(mins * 60)} down")
            cells.append([week, d.weekday(), v, tone, v is not None and target <= v < 100, text])
        return {"kind": "calendar", "title": "Availability day by day", "cells": cells, "months": months,
                "note": f"One square per day, all devices together. Green 100%, light green at or above {target:g}%, amber from 99%, red below, grey no checks.",
                "legend": [["100%", "good", False], [f"{target:g}% or more", "good", True], ["99% or more", "warn", False],
                           ["Below 99%", "bad", False], ["No checks", "none", False]]}
    split = _split(b, devs)
    rows = []
    for label, members in _cats(devs, split):
        vals = _per_slot(hrs, members, starts)
        if not any(v is not None for v in vals):
            continue
        total = _uptime([h for d in members for h in hrs.get(d["id"], [])])
        rows.append((total, label, vals))
    rows.sort(key=lambda r: (r[0], r[1].lower()))
    return {"kind": "strips", "title": f"Uptime by {step}" + (", per group" if split == "group" else ""),
            "note": f"One bar per {step}. Green meets {target:g}%, amber is 99% to {target:g}%, red is below 99% and grey had no checks.",
            "rows": [{"name": l, "value_text": _pct_text(t), "cells": [[v, _avail_tone(v, target)] for v in vals]} for t, l, vals in rows[:_top(b, 12)]],
            "start_text": _date(starts[0], step == "hour"), "end_text": _date(end)}


def _v_avail_budget(c, b, devs, start, end, period):
    target = _target(b, UPTIME_TARGET)
    hrs = _hours(c, start, end)
    measured = [d for d in devs if hrs.get(d["id"])]
    budget = (end - start) / 60 * (100 - target) / 100 * len(measured)
    down = _outages(c, start, end)
    names = {d["id"]: d["name"] for d in measured}
    used = []
    for did, spans in down.items():
        if did not in names:
            continue
        for s, e in spans:
            secs = _down_seconds([(s, e)], start, end)
            if secs > 0:
                used.append((f"{names[did]} {datetime.fromtimestamp(s).strftime('%d %b').lstrip('0')}", secs / 60))
    used.sort(key=lambda p: -p[1])
    steps = [["Budget", round(budget, 1), "start"]] + [[l, round(m, 1), "minus"] for l, m in used[:6]]
    if len(used) > 6:
        steps.append(["Others", round(sum(m for _, m in used[6:]), 1), "minus"])
    steps.append(["Left", round(budget - sum(m for _, m in used), 1), "end"])
    return {"kind": "waterfall", "title": "Downtime budget", "unit": "min", "steps": steps if measured else [],
            "note": f"The downtime the {target:g}% target allows over the period for {_plural(len(measured), 'device')}, then each outage, largest first."}


def _v_previous(c, b, devs, start, end, period, value: Callable[[List[Dict[str, Any]], int, int], Optional[float]],
                title: str, unit: str):
    span = end - start
    split = _split(b, devs)
    rows = []
    for label, members in _cats(devs, split):
        before, after = value(members, start - span, start), value(members, start, end)
        if before is not None or after is not None:
            rows.append([label, _r(before, 3), _r(after, 3)])
    rows.sort(key=lambda r: -abs((r[2] or 0) - (r[1] or 0)))
    return {"kind": "dumbbell", "title": title, "unit": unit, "rows": rows[:_top(b, 10)],
            "before_label": PREVIOUS_NAMES.get(period, "before").replace("the ", "The ", 1),
            "after_label": PERIOD_NAMES.get(period, "now").replace("the ", "The ", 1),
            "note": "Grey is the period before, blue this period. The biggest changes come first."}


def _v_avail_previous(c, b, devs, start, end, period):
    def value(members, a, z):
        hrs = _hours(c, a, z)
        return _uptime([h for d in members for h in hrs.get(d["id"], [])])
    return _v_previous(c, b, devs, start, end, period, value, "Availability, this period and the one before", "%")


def _v_down_per(c, b, devs, start, end, period):
    split = _split(b, devs)
    down = _outages(c, start, end)
    hrs = _hours(c, start, end)
    pairs = []
    for label, members in _cats(devs, split):
        if not any(hrs.get(d["id"]) for d in members):
            pairs.append((label, None))
            continue
        pairs.append((label, round(sum(_down_seconds(down.get(d["id"], []), start, end) for d in members) / 60, 1)))
    pairs = [(l, v) for l, v in pairs if v is None or v > 0] or pairs
    return _category_chart(b, "Time down", "Minutes down in the period, most first. Planned maintenance is left out.",
                           pairs, "min", lambda v: None, True, _top(b, 10))


def _v_down_time(c, b, devs, start, end, period):
    starts, fmt = _slots(start, end)
    down = _outages(c, start, end)
    per = [0] * len(starts)
    for d in devs:
        for s, _ in down.get(d["id"], []):
            if s >= start:
                per[_slot_of(starts, s)] += 1
    return {"kind": "columns", "title": f"Outages per {_step_name(fmt)}", "unit": "", "whole": True,
            "note": "When outages started. Each outage counts once, however long it lasted.",
            "labels": _slot_labels(starts, fmt), "series": [{"name": "Outages", "values": per}]}


def _gantt(c: Ctx, devs: List[Dict[str, Any]], start: int, end: int, top: int, title: str) -> Dict[str, Any]:
    down = _outages(c, start, end)
    rows = []
    for d in devs:
        spans = [[max(s, start), min(e or end, end), "bad", f"Down {_date(s)} for {_minutes(min(e or end, end) - s)}" + ("" if e else ", still down")]
                 for s, e in down.get(d["id"], [])]
        spans += [[a, z, "maint", f"Maintenance {_date(a)} to {_date(z)}"] for a, z in _maint_spans(c, d, start, end)]
        if spans:
            rows.append((sum(z - a for a, z, t, _ in spans if t == "bad"), d["name"], spans))
    rows.sort(key=lambda r: (-r[0], r[1].lower()))
    marks, fmt = _slots(start, end)
    return {"kind": "gantt", "title": title, "start": start, "end": end,
            "note": "Red is down, hatched grey is planned maintenance (the monitor keeps maintenance windows a week after they end).",
            "rows": [{"name": n, "spans": s} for _, n, s in rows[:top]],
            "marks": [[t, l] for t, l in zip(marks, _slot_labels(marks, fmt))]}


def _v_down_gantt(c, b, devs, start, end, period):
    return _gantt(c, devs, start, end, _top(b, 12), "Outage timeline")


def _v_down_worst_week(c, b, devs, start, end, period):
    """The 7 days in the period with the most downtime (the whole period when shorter)."""
    if end - start <= 7 * 86400:
        return _gantt(c, devs, start, end, _top(b, 12), "Outage timeline")
    down = _outages(c, start, end)
    best, best_start = -1, end - 7 * 86400
    day0 = datetime.fromtimestamp(start).replace(hour=0, minute=0, second=0, microsecond=0)
    t = int(day0.timestamp())
    while t + 7 * 86400 <= end + 86400:
        total = sum(_down_seconds(down.get(d["id"], []), t, t + 7 * 86400) for d in devs)
        if total > best:
            best, best_start = total, t
        t += 86400
    a = max(start, best_start)
    week = datetime.fromtimestamp(a).isocalendar()[1]
    return _gantt(c, devs, a, min(end, a + 7 * 86400), _top(b, 12), f"Outage timeline, worst week (week {week})")


# Ping ---------------------------------------------------------------------------------------------------

def _pool(c, devs, key, start, end):
    return [s for d in devs for s in _metric(c, d, key, start, end)]


def _bucketed(samples, start, end, how, count=150):
    size = max(60, (end - start) // count)
    steps: Dict[int, List[float]] = {}
    for t, v, _ in samples:
        steps.setdefault((t - start) // size, []).append(v)
    return [(start + n * size + size // 2, _r(_agg(steps[n], how), 2) if n in steps else None) for n in range(0, (end - start) // size + 1)]


METRIC_INFO = {"ping": ("Ping", "ms"), "cpu": ("Processor use", "%"), "memory": ("Memory use", "%")}


def _metric_limits(key: str, b: Dict[str, Any]) -> Tuple[float, float, str]:
    if key == "ping":
        t = _target(b, PING_TARGET_MS)
        w, x, _ = _limits(b, t, t * 2)
        return w, x, f"Target {w:g} ms"
    w, x, own = _limits(b, LOAD_WARN, LOAD_BAD)
    return w, x, ""


def _v_metric_time(c, b, devs, start, end, period, key):
    name, unit = METRIC_INFO[key]
    how = b.get("agg") or ("median" if key == "ping" else "avg")
    pts = _bucketed(_pool(c, devs, key, start, end), start, end, how)
    warn, bad, _ = _metric_limits(key, b)
    title = f"{name} over time" + (f", {AGGS[how][0].lower()}" if len(devs) > 1 else "")
    spec = {"kind": "line", "title": title, "unit": unit, "start": start, "end": end, "series": [{"name": name, "points": pts}],
            "note": f"{AGGS[how][0]} of all readings in each step" + (" across the devices." if len(devs) > 1 else "."),
            "y_max": 100 if unit == "%" else None}
    if b["chart"] == "columns":
        starts, fmt = _slots(start, end)
        groups: Dict[int, List[float]] = {}
        for t, v, _ in _pool(c, devs, key, start, end):
            groups.setdefault(_slot_of(starts, t), []).append(v)
        vals = [_r(_agg(groups[i], how), 2) if i in groups else None for i in range(len(starts))]
        return {"kind": "columns", "title": f"{name} per {_step_name(fmt)}", "unit": unit, "labels": _slot_labels(starts, fmt),
                "series": [{"name": name, "values": vals}], "note": spec["note"], "y_max": 100 if unit == "%" else None,
                "target": {"value": warn, "label": f"{'Target' if key == 'ping' else 'Watch'} {_unit_text(warn, unit)}", "tone": "warn"}}
    marks = [{"value": warn, "tone": "warn", "label": f"{'Target' if key == 'ping' else 'Watch'} {_unit_text(warn, unit)}"}]
    if b["chart"] == "threshold":
        top = 100 if unit == "%" else max([bad * 1.5] + [v for _, v in pts if v is not None])
        spec["bands"] = [{"from": warn, "to": bad, "tone": "warn"}, {"from": bad, "to": top, "tone": "bad"}]
        marks.append({"value": bad, "tone": "bad", "label": f"{'Slow' if key == 'ping' else 'Strained'} {_unit_text(bad, unit)}"})
        spec["note"] += f" Amber from {_unit_text(warn, unit)}, red from {_unit_text(bad, unit)}; red dots mark readings in the red."
        spec["dots"] = [[t, v] for t, v in pts if v is not None and v >= bad]
    spec["thresholds"] = marks
    return spec


def _v_metric_multi(c, b, devs, start, end, period, key):
    name, unit = METRIC_INFO[key]
    how = b.get("agg") or ("median" if key == "ping" else "avg")
    warn, bad, _ = _metric_limits(key, b)
    ranked = []
    for d in devs:
        s = _metric(c, d, key, start, end)
        if s:
            ranked.append((_agg([v for _, v, _ in s], "p95") or 0, d, s))
    ranked.sort(key=lambda r: (-r[0], str(r[1]["name"]).lower()))
    if b["chart"] == "multi_line":
        ranked = ranked[:min(5, _top(b, 5))]
        return {"kind": "line", "title": f"{name} of the busiest {_plural(len(ranked), 'device')}", "unit": unit, "start": start, "end": end,
                "note": f"{AGGS[how][0]} per step; at most five lines so they stay readable.", "y_max": 100 if unit == "%" else None,
                "series": [{"name": d["name"], "points": _bucketed(s, start, end, how, 100)} for _, d, s in ranked],
                "thresholds": [{"value": warn, "tone": "warn", "label": f"{_unit_text(warn, unit)}"}]}
    panels = []
    for _, d, s in ranked[:_top(b, 12)]:
        pts = _bucketed(s, start, end, how, 60)
        panels.append({"name": d["name"], "points": pts, "bad": any(v is not None and v >= warn for _, v in pts)})
    names = {p["name"] for p in panels}
    panels += [{"name": d["name"], "points": [], "bad": False} for d in devs if d["name"] not in names][:max(0, _top(b, 12) - len(panels))]
    top = 100 if unit == "%" else max([warn * 1.2] + [v for p in panels for _, v in p["points"] if v is not None])
    return {"kind": "multiples", "title": f"{name} per device", "unit": unit, "start": start, "end": end, "y_max": top,
            "note": f"Every panel shares the same scale. Red panels went over {_unit_text(warn, unit)} (dotted line).",
            "panels": panels, "threshold": {"value": warn, "label": _unit_text(warn, unit)}}


def _v_metric_per(c, b, devs, start, end, period, key):
    name, unit = METRIC_INFO[key]
    how = b.get("agg") or ("median" if key == "ping" else "p95")
    split = _split(b, devs)
    warn, bad, _ = _metric_limits(key, b)
    pairs = [(label, _agg([v for d in members for _, v, _ in _metric(c, d, key, start, end)], how)) for label, members in _cats(devs, split)]
    who = "group" if split == "group" else "device"
    if b["chart"] == "diverging":
        rows = sorted([(l, round(v - warn, 2)) for l, v in pairs if v is not None], key=lambda p: -p[1])[:_top(b, 10)]
        return {"kind": "diverging", "title": f"Distance from the {_unit_text(warn, unit)} target", "unit": unit,
                "note": f"{AGGS[how][0]} {name.lower()} per {who} minus the target: right is worse, left is better.",
                "rows": [[l, d, f"{_unit_text(abs(d), unit)} {'over' if d > 0 else 'under'}"] for l, d in rows],
                "left_text": "Better than the target", "right_text": "Worse than the target"}
    if b["chart"] == "dumbbell":
        return _v_metric_previous(c, b, devs, start, end, period, key)
    return _category_chart(b, f"{name} per {who}, {AGGS[how][0].lower()}",
                           f"Highest first. Lines at {_unit_text(warn, unit)} and {_unit_text(bad, unit)}." if unit == "%" else
                           f"Slowest first. The dashed line is the {_unit_text(warn, unit)} target.",
                           pairs, unit, lambda v: _tone_at(v, warn, bad), True, _top(b, 10),
                           [{"value": warn, "tone": "warn", "label": _unit_text(warn, unit)}] + ([{"value": bad, "tone": "bad", "label": _unit_text(bad, unit)}] if unit == "%" else []),
                           100.0 if unit == "%" else None)


def _v_metric_previous(c, b, devs, start, end, period, key):
    name, unit = METRIC_INFO[key]
    how = b.get("agg") or ("median" if key == "ping" else "p95")

    def value(members, a, z):
        return _agg([v for d in members for _, v, _ in _metric(c, d, key, a, z)], how)
    return _v_previous(c, b, devs, start, end, period, value, f"{name}, this period and the one before ({AGGS[how][0].lower()})", unit)


def _v_metric_now(c, b, devs, start, end, period, key):
    name, unit = METRIC_INFO[key]
    warn, bad, _ = _metric_limits(key, b)
    latest = c.memo("latest", lambda: database.get_latest_metrics_all(["cpu_usage_pct", "cpu_idle_pct", "mem_used_pct", "icmp_ping_ms"]))
    vals = []
    for d in devs:
        m = latest.get(d["id"]) or {}
        v = (m.get("cpu_usage_pct", 100 - m["cpu_idle_pct"] if "cpu_idle_pct" in m else None) if key == "cpu"
             else m.get("mem_used_pct") if key == "memory" else m.get("icmp_ping_ms"))
        vals.append((d, v))
    vals.sort(key=lambda p: -(p[1] if p[1] is not None else -1))
    if b["chart"] == "headline":
        items = []
        for d, v in vals[:_top(b, 4)]:
            s = _bucketed(_metric(c, d, key, start, end), start, end, "avg", 40)
            items.append({"label": d["name"], "value_text": _unit_text(v, unit), "values": [p for _, p in s], "better": "down"})
        return {"kind": "headline", "title": f"{name} now", "items": items,
                "note": "The latest reading, with its line over the period: green dot lowest, red dot highest, dark dot the latest."}
    return {"kind": "gauge", "title": f"{name} now", "note": f"Amber from {_unit_text(warn, unit)}, red from {_unit_text(bad, unit)}.",
            "gauges": [{"label": d["name"] if len(devs) > 1 else name, "value": _r(v, 1), "text": _unit_text(v, unit),
                        "max": 100 if unit == "%" else max(bad * 1.5, v or 0), "warn": warn, "bad": bad} for d, v in vals[:min(4, _top(b, 4))]]}


def _v_metric_hour_week(c, b, devs, start, end, period, key):
    name, unit = METRIC_INFO[key]
    how = b.get("agg") or ("median" if key == "ping" else "avg")
    samples = [(t, v) for t, v, _ in _pool(c, devs, key, start, end)]
    if b["chart"] == "clock":
        hours: Dict[int, List[float]] = {}
        for t, v in samples:
            hours.setdefault(datetime.fromtimestamp(t).hour, []).append(v)
        warn, bad, _ = _metric_limits(key, b)
        return {"kind": "clock", "title": f"{name} by hour of day", "unit": unit, "warn": warn, "bad": bad,
                "values": [_r(_agg(hours[h], how), 2) if h in hours else None for h in range(24)],
                "note": f"{AGGS[how][0]} per hour, all days together. Midnight at the top; amber and red past the limits."}
    cells: Dict[Tuple[int, int], List[float]] = {}
    for t, v in samples:
        dt = datetime.fromtimestamp(t)
        cells.setdefault((dt.weekday(), dt.hour), []).append(v)
    values = [[_r(_agg(cells[(w, h)], how), 1) if (w, h) in cells else None for h in range(24)] for w in range(7)]
    flat = [v for row in values for v in row if v is not None]
    return {"kind": "heatmap", "title": f"When {name.lower()} is highest", "unit": unit, "rows": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "values": values, "max": max(flat) if flat else 0,
            "note": f"{AGGS[how][0]} by weekday and hour. Darker is higher; grey had no readings."}


def _v_ping_band(c, b, devs, start, end, period):
    size = _bucket(end - start)
    buckets: Dict[int, List[float]] = {}
    for t, v, _ in _pool(c, devs, "ping", start, end):
        buckets.setdefault((t - start) // size, []).append(v)
    pts = []
    for n in range(0, (end - start) // size + 1):
        vals = buckets.get(n) or []
        t = start + n * size + size // 2
        if len(vals) < 10:
            pts.append([t, None, None, None, None, None])
        else:
            pts.append([t] + [_r(_quantile(vals, q), 2) for q in (0.05, 0.25, 0.5, 0.75, 0.95)])
    warn = _target(b, PING_TARGET_MS)
    return {"kind": "band", "title": "Ping, typical and spread", "unit": "ms", "start": start, "end": end, "points": pts,
            "thresholds": [{"value": warn, "tone": "warn", "label": f"Target {warn:g} ms"}],
            "note": f"Per {_bucket_text(size)}, from every answer: the line is the median, the dark band the middle half (25th to 75th percentile), "
                    "the light band 5th to 95th. Gaps had fewer than 10 answers."}


def _dist_cats(c, b, devs, start, end):
    split = _split(b, devs)
    out = []
    for label, members in _cats(devs, split):
        vals = [v for d in members for _, v, _ in _pings(c, d, start, end)]
        if vals:
            out.append((label, vals))
    return out, split


def _v_ping_dist(c, b, devs, start, end, period):
    warn = _target(b, PING_TARGET_MS)
    if b["chart"] == "histogram":
        vals = sorted(v for _, v, _ in _pool(c, devs, "ping", start, end))
        if not vals:
            return {"kind": "histogram", "title": "How ping answers spread", "bins": [], "unit": "ms", "marks": []}
        hi = _quantile(vals, 0.995) or vals[-1]
        lo = vals[0]
        n = 40
        width = max((hi - lo) / n, 0.01)
        counts = [0] * n
        for v in vals:
            counts[min(n - 1, int((min(v, hi) - lo) / width))] += 1
        p50, p95, p99 = (_quantile(vals, q) for q in (0.5, 0.95, 0.99))
        return {"kind": "histogram", "title": "How ping answers spread", "unit": "ms",
                "bins": [[round(lo + i * width, 2), round(lo + (i + 1) * width, 2), k] for i, k in enumerate(counts)],
                "marks": [{"value": p50, "label": f"Median {_ms(p50)}", "tone": "s5"}, {"value": p95, "label": f"95th {_ms(p95)}", "tone": "s3"},
                          {"value": p99, "label": f"99th {_ms(p99)}", "tone": "bad"}],
                "note": f"Every answer in the period ({len(vals):,}), in {n} bins; the slowest half percent is counted in the last bin."}
    cats, split = _dist_cats(c, b, devs, start, end)
    if b["chart"] == "cdf":
        cats.sort(key=lambda p: -(_median(p[1]) or 0))
        cats = cats[:min(4, _top(b, 3))]
        series = []
        for label, vals in cats:
            vals = sorted(vals)
            step = max(1, len(vals) // 60)
            pts = [[vals[i], round((i + 1) / len(vals), 4)] for i in range(0, len(vals), step)]
            if pts[-1][0] != vals[-1]:
                pts.append([vals[-1], 1.0])
            series.append({"name": label, "points": pts})
        return {"kind": "cdf", "title": "Cumulative ping" + (", slowest groups" if split == "group" else ", slowest devices"),
                "unit": "ms", "series": series, "mark": 0.95, "target": warn,
                "note": "How many answers came within each time: further left is better. The dotted line marks 95% of answers."}
    rows = []
    for label, vals in cats:
        vals = sorted(vals)
        q1, med, q3 = _quantile(vals, 0.25), _median(vals), _quantile(vals, 0.75)
        iqr = (q3 or 0) - (q1 or 0)
        lo_lim, hi_lim = (q1 or 0) - 1.5 * iqr, (q3 or 0) + 1.5 * iqr
        inside = [v for v in vals if lo_lim <= v <= hi_lim] or vals
        outliers = [v for v in vals if v < lo_lim or v > hi_lim]
        step = max(1, len(outliers) // 12)
        rows.append({"label": label, "lo": inside[0], "q1": q1, "med": med, "q3": q3, "hi": inside[-1], "n": len(vals),
                     "outliers": [round(v, 2) for v in sorted(outliers)[::step]][:12]})
    rows.sort(key=lambda r: -(r["med"] or 0))
    return {"kind": "box", "title": "Ping spread per " + ("group" if split == "group" else "device"), "unit": "ms",
            "rows": rows[:_top(b, 12)], "target": warn, "target_label": f"Target {warn:g} ms",
            "note": "The box runs from the 25th to the 75th percentile with the median inside; whiskers reach 1.5 box lengths, dots are answers beyond them."}


def _v_ping_stddev(c, b, devs, start, end, period):
    import statistics
    split = _split(b, devs)
    pairs = []
    for label, members in _cats(devs, split):
        vals = [v for d in members for _, v, _ in _pings(c, d, start, end)]
        pairs.append((label, round(statistics.pstdev(vals), 2) if len(vals) > 1 else None))
    return _category_chart(b, "RTT standard deviation", "How much ping varies from one check to the next (standard deviation of the answers). "
                           "This is not jitter: the monitor sends one ping per check.", pairs, "ms", lambda v: None, True, _top(b, 10))


def _failed_pairs(c, devs, start, end, split):
    return [(l, round(100 - v, 3) if v is not None else None) for l, v in _cat_avail(c, devs, start, end, split)]


def _v_failed_per(c, b, devs, start, end, period):
    split = _split(b, devs)
    warn, bad, _ = _limits(b, FAILED_WARN, FAILED_BAD)
    return _category_chart(b, "Failed checks per " + ("group" if split == "group" else "device"),
                           f"Share of checks that got no answer. Not packet loss: the monitor sends one ping per check. Amber from {warn:g}%, red from {bad:g}%.",
                           _failed_pairs(c, devs, start, end, split), "%", lambda v: _tone_at(v, warn, bad), True, _top(b, 10),
                           [{"value": warn, "tone": "warn", "label": f"{warn:g}%"}, {"value": bad, "tone": "bad", "label": f"{bad:g}%"}])


def _v_failed_time(c, b, devs, start, end, period):
    starts, fmt = _slots(start, end)
    vals = [round(100 - v, 3) if v is not None else None for v in _per_slot(_hours(c, start, end), devs, starts)]
    warn, bad, _ = _limits(b, FAILED_WARN, FAILED_BAD)
    if b["chart"] == "columns":
        return {"kind": "columns", "title": f"Failed checks per {_step_name(fmt)}", "unit": "%", "labels": _slot_labels(starts, fmt),
                "series": [{"name": "Failed checks", "values": vals}], "bar_tones": [_tone_at(v, warn, bad) for v in vals],
                "note": "Share of checks that got no answer (one ping per check, so not packet loss).",
                "target": {"value": warn, "label": f"{warn:g}%", "tone": "warn"}}
    return {"kind": "line", "title": f"Failed checks per {_step_name(fmt)}", "unit": "%", "start": start, "end": end,
            "series": [{"name": "Failed checks", "points": list(zip(_slot_mid(starts, fmt), vals))}],
            "thresholds": [{"value": warn, "tone": "warn", "label": f"{warn:g}%"}],
            "note": "Share of checks that got no answer (one ping per check, so not packet loss)."}


def _v_cpu_mem(c, b, devs, start, end, period):
    warn, bad, _ = _limits(b, LOAD_WARN, LOAD_BAD)
    pts, missing = [], 0
    for d in devs:
        cv, mv = _metric(c, d, "cpu", start, end), _metric(c, d, "memory", start, end)
        if not cv or not mv:
            missing += 1
            continue
        x, y = _quantile([v for _, v, _ in cv], 0.95), _quantile([v for _, v, _ in mv], 0.95)
        over = (x >= warn) + (y >= warn)
        pts.append([d["name"], round(x, 1), round(y, 1), "bad" if over == 2 else "warn" if over else "info", over > 0])
    return {"kind": "scatter", "title": "Processor and memory per device", "points": pts, "x_label": "Processor, 95th percentile (%)",
            "y_label": "Memory, 95th percentile (%)", "x_line": warn, "y_line": warn, "max": 100,
            "note": f"Dotted lines at {warn:g}%. Red is over on both, amber on one."
                    + (f" {_count(missing, 'device')} without both readings {'is' if missing == 1 else 'are'} left out." if missing else "")}


def _temps_now(c, devs):
    def load():
        out = {}
        for d in c.all:
            temps = [m["value"] for m in database.get_latest_metrics(d["id"]) if str(m["metric_key"]).endswith(".temp_c")
                     and isinstance(m["value"], (int, float))]
            if temps:
                out[d["id"]] = max(temps)
        return out
    t = c.memo("temps", load)
    return [(d, t.get(d["id"])) for d in devs]


def _v_temp(c, b, devs, start, end, period):
    warn, bad, _ = _limits(b, TEMP_WARN, TEMP_BAD)
    vals = sorted(_temps_now(c, devs), key=lambda p: -(p[1] if p[1] is not None else -999))
    if b["chart"] == "gauge":
        return {"kind": "gauge", "title": "Temperature now", "note": f"The hottest sensor. Amber from {warn:g} C, red from {bad:g} C.",
                "gauges": [{"label": d["name"] if len(devs) > 1 else "Temperature", "value": _r(v, 1), "text": f"{v:.0f} C" if v is not None else "No data",
                            "max": max(100.0, bad + 10), "warn": warn, "bad": bad} for d, v in vals[:min(4, _top(b, 4))]]}
    return _category_chart(b, "Hottest sensor per device", f"Degrees C now. Amber from {warn:g}, red from {bad:g}.",
                           [(d["name"], v) for d, v in vals], "C", lambda v: _tone_at(v, warn, bad), True, _top(b, 10),
                           [{"value": warn, "tone": "warn", "label": f"{warn:g} C"}, {"value": bad, "tone": "bad", "label": f"{bad:g} C"}])


def _v_storage_per(c, b, devs, start, end, period):
    warn, bad, _ = _limits(b, LOAD_WARN, LOAD_BAD)
    items = [(f"{d['name']}: {x['name']}", x["used_pct"], x.get("used")) for d in devs for x in _disks(d["id"]) if x["used_pct"] is not None]
    if b["chart"] == "treemap":
        return _treemap("Storage used", "Each tile is sized by the space in use, coloured by how full it is.",
                        [(l, u, _tone_at(p, warn, bad)) for l, p, u in items if isinstance(u, (int, float)) and u > 0], "B")
    return _category_chart(b, "Fullest storage", f"How full each disk and volume is now. Lines at {warn:g}% and {bad:g}%.",
                           [(l, p) for l, p, _ in items], "%", lambda v: _tone_at(v, warn, bad), True, _top(b, 10),
                           [{"value": warn, "tone": "warn", "label": f"{warn:g}%"}, {"value": bad, "tone": "bad", "label": f"{bad:g}%"}], 100.0)


# Capacity forecast (spec 4.10): one value per day (the daily peak), a straight line by least squares,
# a cone from the residual standard error that widens with distance, days until the limit.

def _daily_peaks(device_id: int, key: str, end: int, days: int = 90) -> List[Tuple[int, float]]:
    start = end - days * 86400
    with database.get_connection() as conn:
        rows = conn.execute("SELECT hour, max FROM metrics_hourly WHERE device_id = ? AND metric_key = ? AND hour >= ? AND hour < ? "
                            "ORDER BY hour;", (device_id, key, start, end)).fetchall()
    peaks: Dict[int, float] = {}
    for hour, top in rows:
        day = int(datetime.fromtimestamp(hour).replace(hour=12, minute=0, second=0, microsecond=0).timestamp())
        peaks[day] = max(peaks.get(day, top), top)
    return sorted(peaks.items())


def _fit_line(points: List[Tuple[int, float]]) -> Optional[Dict[str, float]]:
    n = len(points)
    if n < 2:
        return None
    xs = [p[0] / 86400.0 for p in points]
    ys = [p[1] for p in points]
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= 0:
        return None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    icpt = my - slope * mx
    resid = [y - (icpt + slope * x) for x, y in zip(xs, ys)]
    se = math.sqrt(sum(r * r for r in resid) / max(1, n - 2))
    return {"slope": slope, "icpt": icpt, "se": se, "mx": mx, "sxx": sxx, "n": n}


def _resources(c: Ctx, devs: List[Dict[str, Any]], now: int) -> List[Dict[str, Any]]:
    """Every finite resource with a daily peak history: disks and volumes, memory, and link use
    (the larger of in and out against the link speed). Each with its fit and days until the limit."""
    def load():
        out = []
        wan = c.memo("wan", lambda: c.env["wan"]() if callable(c.env.get("wan")) else set())
        for d in devs:
            keys = []
            for x in _disks(d["id"]):
                prefix = "vol" if x["table"] == "volumes" else "stor"
                keys.append((f"{prefix}.{x['idx']}.used_pct", x["name"], "Disk", x["used_pct"], LOAD_BAD))
            keys.append(("mem_used_pct", "Memory", "Memory", None, LOAD_BAD))
            for key, name, kind, current, limit in keys:
                peaks = _daily_peaks(d["id"], key, now)
                if not peaks:
                    continue
                out.append(_forecast_row(d, name, kind, peaks, current, limit, now))
            for i in _interfaces(d, now - 7 * 86400, now, wan):
                if not i.get("speed"):
                    continue
                speed = i["speed"] * 1e6
                ins, outs = _daily_peaks(d["id"], f"if.{i['idx']}.in_bps", now), dict(_daily_peaks(d["id"], f"if.{i['idx']}.out_bps", now))
                peaks = [(t, round(100.0 * max(v, outs.get(t, 0)) / speed, 2)) for t, v in ins]
                if peaks:
                    out.append(_forecast_row(d, f"Link {i['interface']}", "Link", peaks, i["util"], LINK_BAD, now))
        return out
    key = ("resources", tuple(d["id"] for d in devs), now)
    return c.memo(key, load)


def _forecast_row(d, name, kind, peaks, current, limit, now) -> Dict[str, Any]:
    fit = _fit_line(peaks) if len(peaks) >= FORECAST_MIN_DAYS else None
    now_v = current if current is not None else peaks[-1][1]
    days = None
    state = "short"
    if fit:
        state = "flat"
        if fit["slope"] > 0.01:
            today = now / 86400.0
            days = (limit - fit["icpt"]) / fit["slope"] - today
            state = "passed" if now_v >= limit or days <= 0 else "growing"
    return {"device": d["name"], "device_id": d["id"], "resource": name, "kind": kind, "now": now_v, "limit": limit, "peaks": peaks,
            "fit": fit, "days": max(0.0, days) if days is not None else None, "state": "passed" if now_v >= limit else state,
            "growth": round(fit["slope"] * 30, 2) if fit else None}


def _priority(r: Dict[str, Any]) -> str:
    if r["state"] == "passed" or (r["days"] is not None and r["days"] < 30):
        return "P1"
    if r["days"] is not None and r["days"] < 90:
        return "P2"
    return "P3"


def _days_text(r: Dict[str, Any]) -> str:
    if r["state"] == "passed":
        return "Passed"
    if r["state"] == "short":
        return f"Needs {FORECAST_MIN_DAYS} days of history"
    if r["days"] is None:
        return "Not growing"
    return "Over a year" if r["days"] > 365 else _plural(round(r["days"]), "day")


def _v_forecast(c, b, devs, start, end, period):
    rows = [r for r in _resources(c, devs, c.now) if r["fit"]] or _resources(c, devs, c.now)
    if not rows:
        return {"kind": "forecast", "title": "Projected exhaustion", "observed": [], "unit": "%",
                "empty_text": f"No resource has a daily history yet (a forecast needs {FORECAST_MIN_DAYS} days)."}
    r = min(rows, key=lambda r: (0 if r["state"] == "passed" else 1, r["days"] if r["days"] is not None else 1e9, -(r["now"] or 0)))
    limit = _limits(b, LOAD_WARN, r["limit"])[1]
    obs = [[t, round(v, 2)] for t, v in r["peaks"]]
    spec = {"kind": "forecast", "title": f"{r['device']} {r['resource']}: projected use", "unit": "%", "observed": obs, "limit": limit,
            "limit_label": f"Limit {limit:g}%", "start": obs[0][0], "end": c.now}
    fit = r["fit"]
    if not fit:
        spec.update(note=f"Daily peaks so far. The forecast is drawn after {FORECAST_MIN_DAYS} days of history.", end=obs[-1][0])
        return spec
    horizon = max(30, min(365, int((r["days"] or 60) * 1.2) + 7)) if r["state"] != "passed" else 30
    future = [c.now + k * 86400 for k in range(0, horizon + 1, max(1, horizon // 40))]
    proj, cone = [], []
    for t in future:
        x = t / 86400.0
        y = fit["icpt"] + fit["slope"] * x
        spread = 1.645 * fit["se"] * math.sqrt(1 + 1 / fit["n"] + (x - fit["mx"]) ** 2 / fit["sxx"])
        proj.append([t, round(y, 2)])
        cone.append([t, round(y - spread, 2), round(y + spread, 2)])
    full_at = int(c.now + r["days"] * 86400) if r["days"] is not None and r["days"] <= horizon else None
    early = len(r["peaks"]) < FORECAST_GOOD_DAYS
    spec.update(projection=proj, cone=cone, end=future[-1], full_at=full_at,
                full_text=(f"Limit around {_date(full_at, False)}" if full_at else ""),
                note=f"Linear trend on daily peaks over {len(r['peaks'])} days; the shaded cone is about 90% confidence; seasons are not modelled."
                     + (f" Early estimate: under {FORECAST_GOOD_DAYS} days of history." if early else "")
                     + ("" if r["days"] is not None else " Not growing towards the limit."))
    return spec


# Traffic -------------------------------------------------------------------------------------------------

def _v_traffic_inout(c, b, devs, start, end, period):
    i = _focus_interface(c, devs, start, end)
    if not i:
        return {"kind": "mirror", "title": "Traffic in and out", "in": [], "out": [], "unit": "bps"}
    return _mirror(i, start, end, f"{'Internet uplink' if i['wan'] else 'Busiest link'} {i['name']} {i['interface']}, in and out",
                   "Inbound above the line, outbound below it.")


def _traffic_cats(c, devs, start, end, split):
    ifaces = _all_interfaces(c, devs, start, end)
    if split == "interface":
        return [(f"{i['name']} {i['interface']}", [i]) for i in ifaces]
    key = (lambda i: i["group"] or "No group") if split == "group" else (lambda i: i["name"])
    out: Dict[str, List[Dict[str, Any]]] = {}
    for i in ifaces:
        out.setdefault(key(i), []).append(i)
    return sorted(out.items(), key=lambda kv: kv[0].lower())


def _v_traffic_per(c, b, devs, start, end, period):
    split = _split(b, devs, "interface")
    cats = _traffic_cats(c, devs, start, end, split)
    if b["chart"] == "treemap":
        items = []
        for label, ifs in cats:
            avg = sum((_mean([v for _, v, _ in i["_in"]]) or 0) + (_mean([v for _, v, _ in i["_out"]]) or 0) for i in ifs)
            items.append((label, avg, None))
        return _treemap("Traffic share", "Each tile is sized by its average traffic in and out together (averages add up; percentiles do not).",
                        [p for p in items if p[1] > 0], "bps")
    pairs = [(label, max(_ifload(i) for i in ifs)) for label, ifs in cats]
    who = {"interface": "interfaces", "device": "devices", "group": "groups"}[split]
    return _category_chart(b, f"Busiest {who} (95th percentile)", "The larger of in and out: 95% of the time traffic was at or below this"
                           + ("" if split == "interface" else ", on the busiest interface") + ".", pairs, "bps", lambda v: None, True, _top(b, 10))


def _v_traffic_pair(c, b, devs, start, end, period):
    split = _split(b, devs, "interface")
    cats = _traffic_cats(c, devs, start, end, split)
    rows = [(label, max(i["in_p95"] or 0 for i in ifs), max(i["out_p95"] or 0 for i in ifs)) for label, ifs in cats]
    rows.sort(key=lambda r: -max(r[1], r[2]))
    rows = rows[:_top(b, 10)]
    if b["chart"] == "grouped":
        return {"kind": "columns", "grouped": True, "stacked": False, "title": "Peak traffic in and out", "unit": "bps",
                "labels": [r[0] for r in rows], "series": [{"name": "In", "values": [r[1] for r in rows]}, {"name": "Out", "values": [r[2] for r in rows]}],
                "note": "95th percentile per direction" + ("" if split == "interface" else ", the busiest interface") + "."}
    return {"kind": "butterfly", "title": "In and out per " + {"interface": "interface", "device": "device", "group": "group"}[split], "unit": "bps",
            "rows": [list(r) for r in rows], "left_label": "In", "right_label": "Out",
            "note": "95th percentile per direction: inbound to the left, outbound to the right. Lopsided links stand out."}


UTIL_BANDS = [("0 to 25%", None, 25), ("25 to 50%", None, 50), ("50 to 75%", None, 75), ("75 to 90%", "warn", 90), ("Over 90%", "bad", 1e9)]


def _v_traffic_bands(c, b, devs, start, end, period):
    split = _split(b, devs)
    split = "device" if split == "interface" else split
    rows, nospeed = [], 0
    for label, ifs in _traffic_cats(c, devs, start, end, split):
        counts = [0] * len(UTIL_BANDS)
        for i in ifs:
            if i["util"] is None:
                nospeed += 1
                continue
            counts[next(k for k, (_, _, top) in enumerate(UTIL_BANDS) if i["util"] < top)] += 1
        if sum(counts):
            rows.append({"label": label, "values": counts})
    return {"kind": "stack100", "title": "How hard the interfaces work", "rows": rows[:_top(b, 12)],
            "parts": [{"name": n, "tone": t} for n, t, _ in UTIL_BANDS],
            "note": "Share of each " + ("group's" if split == "group" else "device's") + " interfaces in each band of use (95th percentile against link speed)."
                    + (f" {_count(nospeed, 'interface')} without a known speed {'is' if nospeed == 1 else 'are'} left out." if nospeed else "")}


def _v_traffic_hour(c, b, devs, start, end, period):
    i = _focus_interface(c, devs, start, end)
    both: Dict[int, float] = {}
    for t, v, _ in (i["_in"] + i["_out"]) if i else []:
        both[t] = max(both.get(t, 0.0), v)
    if b["chart"] == "clock":
        hours: Dict[int, List[float]] = {}
        for t, v in both.items():
            hours.setdefault(datetime.fromtimestamp(t).hour, []).append(v)
        return {"kind": "clock", "title": f"When {i['interface'] if i else 'the link'} is busiest, by hour", "unit": "bps",
                "values": [_r(_mean(hours[h]), 0) if h in hours else None for h in range(24)],
                "note": "Average load per hour of the day (the larger of in and out). Midnight at the top."}
    heat = _heatmap(sorted(both.items()), f"When {i['interface'] if i else 'the link'} is busiest",
                    "Average load (the larger of in and out) by weekday and hour. Darker is busier.", "bps")
    return heat or {"kind": "heatmap", "title": "When the link is busiest", "values": [], "unit": "bps"}


def _v_util_per(c, b, devs, start, end, period):
    warn, bad, _ = _limits(b, LINK_WARN, LINK_BAD)
    pairs = [(f"{i['name']} {i['interface']}", i["util"]) for i in _all_interfaces(c, devs, start, end) if i["util"] is not None]
    return _category_chart(b, "How full the links run", f"Use at the 95th percentile against the link speed. Lines at {warn:g}% and {bad:g}%.",
                           pairs, "%", lambda v: _tone_at(v, warn, bad), True, _top(b, 10),
                           [{"value": warn, "tone": "warn", "label": f"{warn:g}%"}, {"value": bad, "tone": "bad", "label": f"{bad:g}%"}], 100.0)


def _v_util_watch(c, b, devs, start, end, period):
    warn, bad, _ = _limits(b, LINK_WARN, LINK_BAD)
    rows = []
    for i in _all_interfaces(c, devs, start, end):
        speed = (i["speed"] or 0) * 1e6
        both: Dict[int, float] = {}
        for t, v, _ in i["_in"] + i["_out"]:
            both[t] = max(both.get(t, 0.0), v)
        series = _thin([(t, v, v) for t, v in sorted(both.items())], start, end, 30)
        vals = [(_r(100 * v / speed, 1) if speed else v) if v is not None else None for _, v in series]
        now_v = i["util"] if speed else _ifload(i)
        tone = _tone_at(i["util"], warn, bad) if i["util"] is not None else "none"
        rows.append({"name": f"{i['interface']}" + (f" ({i['description']})" if i.get("description") else "") + ("" if len(devs) == 1 else f", {i['name']}"),
                     "values": vals, "now": _pct_text(now_v) if speed else _bps(now_v), "tone": tone, "rank": (i["util"] or 0)})
    order = {"bad": 0, "warn": 1, "good": 2, "none": 3}
    rows.sort(key=lambda r: (order.get(r["tone"], 3), -r["rank"]))
    return {"kind": "sparktable", "title": "Key interfaces", "header": ["Interface", "Use over the period", "95th pct", ""],
            "rows": rows[:_top(b, 10)], "note": "Sorted by status, then by use. The figure is the 95th percentile against the link speed."}


# Problems and events ------------------------------------------------------------------------------------

def _v_problems_time(c, b, devs, start, end, period):
    events = _opened(c, devs, start, end)
    if b["chart"] == "columns":
        starts, fmt = _slots(start, end)
        per = [0] * len(starts)
        for e in events:
            per[_slot_of(starts, e["timestamp"])] += 1
        return {"kind": "columns", "title": f"Problems per {_step_name(fmt)}", "unit": "", "whole": True, "labels": _slot_labels(starts, fmt),
                "series": [{"name": "Problems", "values": per}], "note": "Problems opened, all kinds together."}
    return _severity_columns(events, start, end, "Problems per day by severity", "Problems opened per day (per hour for 24 hours), critical at the bottom.")


def _v_events_time(c, b, devs, start, end, period):
    events = _all_events(c, devs, start, end)
    if b["chart"] == "columns":
        starts, fmt = _slots(start, end)
        per = [0] * len(starts)
        for e in events:
            per[_slot_of(starts, e["timestamp"])] += 1
        return {"kind": "columns", "title": f"Events per {_step_name(fmt)}", "unit": "", "whole": True, "labels": _slot_labels(starts, fmt),
                "series": [{"name": "Events", "values": per}], "note": "Every event, all kinds together."}
    return _severity_columns(events, start, end, "Events over time", "Events per day (per hour for 24 hours), by severity.")


def _count_split(items: List[Tuple[str, str, str, str]], split: str) -> List[Tuple[str, int]]:
    """items: (device name, group, severity, type text). Counts per the split."""
    idx = {"device": 0, "group": 1, "severity": 2, "rule": 3, "type": 3}[split]
    counts: Dict[str, int] = {}
    shown: Dict[str, str] = {}
    for it in items:
        key = _key(it[idx]) if split == "rule" else it[idx]
        counts[key] = counts.get(key, 0) + 1
        shown.setdefault(key, it[idx])
    return sorted(((shown[k], n) for k, n in counts.items()), key=lambda p: (-p[1], p[0].lower()))


def _composition_chart(b, title, note, counts: List[Tuple[str, int]], tones: Optional[Dict[str, str]] = None):
    top = _top(b, 10)
    chart = b["chart"]
    if chart == "pareto":
        total = sum(n for _, n in counts) or 1
        shown = counts[:top]
        if len(counts) > top:
            shown.append(("Others", sum(n for _, n in counts[top:])))
        run, cum = 0, []
        for _, n in shown:
            run += n
            cum.append(round(100.0 * run / total, 1))
        return {"kind": "pareto", "title": title, "note": note + " The orange line adds them up; the dotted line marks 80%.",
                "bars": [[l, n] for l, n in shown], "cumulative": cum}
    if chart == "donut":
        shown = counts[:6]
        if len(counts) > 6:
            shown.append(("Others", sum(n for _, n in counts[6:])))
        return _donut(title, note, [(l, n, (tones or {}).get(l)) for l, n in shown], "in all")
    if chart == "treemap":
        return _treemap(title, note, [(l, n, (tones or {}).get(l)) for l, n in counts[:MAX_TOP]], "")
    if chart == "columns":
        shown = counts[:top]
        return {"kind": "columns", "title": title, "note": note, "unit": "", "whole": True, "labels": [l for l, _ in shown],
                "series": [{"name": title, "values": [n for _, n in shown]}]}
    return {"kind": "bar", "title": title, "note": note, "unit": "", "bars": [[l, n, (tones or {}).get(l)] for l, n in counts[:top]]}


SEV_TONES = {"Critical": "bad", "High": "bad", "Warning": "warn", "Info": "info"}


def _v_problems_per(c, b, devs, start, end, period):
    split = b.get("split") or "rule"
    split = "rule" if split == "auto" else split
    events = _opened(c, devs, start, end)
    names = {d["id"]: (d["name"], _gname(d)) for d in devs}
    items = [(names[e["device_id"]][0], names[e["device_id"]][1], _sev(e["severity"]),
              re.sub(r" \(during maintenance\)$", "", e["message"][len("Problem: "):])) for e in events]
    title = {"rule": "Which problems come up most", "device": "Problems per device", "group": "Problems per group", "severity": "Problems by severity"}[split]
    return _composition_chart(b, title, "Problems opened in the period" + (", the same problem on any device counted together." if split == "rule" else "."),
                              _count_split(items, split), SEV_TONES if split == "severity" else None)


def _v_events_per(c, b, devs, start, end, period):
    split = b.get("split") or "type"
    split = "type" if split in ("auto", "rule") else split
    events = _all_events(c, devs, start, end)
    names = {d["id"]: (d["name"], _gname(d)) for d in devs}
    items = [(names[e["device_id"]][0], names[e["device_id"]][1], _sev(e["severity"]), str(e["event_type"]).replace("_", " ").capitalize())
             for e in events if e["device_id"] in names]
    title = {"type": "Events by kind", "device": "Events per device", "group": "Events per group", "severity": "Events by severity"}[split]
    return _composition_chart(b, title, "Every event in the period.", _count_split(items, split), SEV_TONES if split == "severity" else None)


def _hour_chart(b, times, title, warn_share: float = 0.08):
    counts = [0] * 24
    for t in times:
        counts[datetime.fromtimestamp(t).hour] += 1
    if b["chart"] == "columns":
        return {"kind": "columns", "title": title, "unit": "", "whole": True, "labels": [f"{h:02d}" for h in range(24)],
                "series": [{"name": "Count", "values": counts}], "note": "All days together."}
    total = sum(counts) or 1
    warn, bad, _ = _limits(b, max(2, round(total * warn_share)), max(3, round(total * warn_share * 2)))
    return {"kind": "clock", "title": title, "unit": "", "values": counts, "warn": warn, "bad": bad,
            "note": f"All days together, midnight at the top. Amber from {warn:g} in an hour, red from {bad:g}."}


def _v_problems_hour(c, b, devs, start, end, period):
    return _hour_chart(b, [e["timestamp"] for e in _opened(c, devs, start, end)], "Problems by hour of day")


def _v_events_hour(c, b, devs, start, end, period):
    return _hour_chart(b, [e["timestamp"] for e in _all_events(c, devs, start, end)], "Events by hour of day")


def _v_problems_week(c, b, devs, start, end, period):
    cells: Dict[Tuple[int, int], int] = {}
    for e in _opened(c, devs, start, end):
        dt = datetime.fromtimestamp(e["timestamp"])
        cells[(dt.weekday(), dt.hour)] = cells.get((dt.weekday(), dt.hour), 0) + 1
    values = [[cells.get((w, h), 0) for h in range(24)] for w in range(7)]
    return {"kind": "heatmap", "title": "When problems open", "unit": "", "rows": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "values": values, "max": max([v for row in values for v in row] + [0]), "note": "Problems opened by weekday and hour. Darker is more."}


def _v_problems_noisy(c, b, devs, start, end, period):
    starts, fmt = _slots(start, end)
    per: Dict[int, List[int]] = {}
    for e in _opened(c, devs, start, end):
        per.setdefault(e["device_id"], [0] * len(starts))[_slot_of(starts, e["timestamp"])] += 1
    open_now = {p["device_id"] for p in database.list_active_problems()}
    names = {d["id"]: d["name"] for d in devs}
    rows = sorted(((sum(v), did, v) for did, v in per.items()), key=lambda r: (-r[0], names.get(r[1], "")))
    return {"kind": "sparktable", "title": "Noisiest devices", "header": ["Device", f"Problems per {_step_name(fmt)}", "Count", ""],
            "rows": [{"name": names[did], "values": v, "now": str(n), "tone": "bad" if did in open_now else "good"} for n, did, v in rows[:_top(b, 8)]],
            "note": "Count in the period. The dot is red while the device has an open problem."}


def _v_cpu_watch(c, b, devs, start, end, period, key="cpu"):
    name, unit = METRIC_INFO[key]
    warn, bad, _ = _limits(b, LOAD_WARN, LOAD_BAD)
    latest = c.memo("latest", lambda: database.get_latest_metrics_all(["cpu_usage_pct", "cpu_idle_pct", "mem_used_pct", "icmp_ping_ms"]))
    rows = []
    for d in devs:
        s = _metric(c, d, key, start, end)
        if not s:
            continue
        m = latest.get(d["id"]) or {}
        now_v = (m.get("cpu_usage_pct", 100 - m["cpu_idle_pct"] if "cpu_idle_pct" in m else None) if key == "cpu" else m.get("mem_used_pct"))
        tone = _tone_at(now_v, warn, bad)
        rows.append({"name": d["name"], "values": [v for _, v in _thin(s, start, end, 30)], "now": _pct_text(now_v), "tone": tone,
                     "rank": now_v or 0})
    order = {"bad": 0, "warn": 1, "good": 2, "none": 3}
    rows.sort(key=lambda r: (order.get(r["tone"], 3), -r["rank"]))
    return {"kind": "sparktable", "title": f"Watch list ({name.lower()})", "header": ["Device", f"{name} over the period", "Now", ""],
            "rows": rows[:_top(b, 8)], "note": f"Worst first. Amber from {warn:g}%, red from {bad:g}%."}


def _v_ping_watch(c, b, devs, start, end, period):
    warn = _target(b, PING_TARGET_MS)
    rows = []
    for d in devs:
        s = _pings(c, d, start, end)
        if not s:
            continue
        med = _median([v for _, v, _ in s])
        rows.append({"name": d["name"], "values": [v for _, v in _thin(s, start, end, 30, _median)], "now": _ms(med),
                     "tone": _tone_at(med, warn, warn * 2), "rank": med or 0})
    rows.sort(key=lambda r: -r["rank"])
    return {"kind": "sparktable", "title": "Ping per device", "header": ["Device", "Ping over the period", "Median", ""],
            "rows": rows[:_top(b, 10)], "note": f"Slowest first. Amber over the {warn:g} ms target."}


def _v_status(c, b, devs, start, end, period):
    state = _now_words(c)
    counts = _counts([state[d["id"]][0] for d in devs if d["id"] in state])
    order = (("Up", "good"), ("Problems", "warn"), ("Down", "bad"), ("Not monitored", "none"))
    if b["chart"] == "donut":
        return _donut("Devices now", "Up, with an open problem, down or not checked yet.", [(k, counts.get(k, 0), t) for k, t in order], "devices")
    rank = {"bad": 0, "warn": 1, "none": 2, "good": 3}
    tiles = sorted(([d, state[d["id"]]] for d in devs if d["id"] in state), key=lambda x: (_gname(x[0]).lower(), rank[x[1][1]], str(x[0]["name"]).lower()))
    return {"kind": "grid", "title": "Every device now", "note": "One tile per device, by group. Green is up, amber has an open problem, red is down, grey is not checked yet.",
            "tiles": [{"label": d["name"], "tone": s[1], "sub": s[2], "id": d["id"]} for d, s in tiles],
            "counts": [[k, t, counts.get(k, 0)] for k, t in order]}


def _v_reachable(c, b, devs, start, end, period):
    """Devices answering over time: every device checked in the window, less those inside an outage."""
    hrs = _hours(c, start, end)
    checked = [d for d in devs if hrs.get(d["id"])]
    down = _outages(c, start, end)
    changes: List[Tuple[int, int]] = []
    for d in checked:
        for s, e in down.get(d["id"], []):
            changes.append((max(s, start), -1))
            if e is not None and e <= end:
                changes.append((e, 1))
    level = len(checked) - sum(1 for d in checked for s, e in down.get(d["id"], []) if s < start)
    pts = [[start, level]]
    for t, delta in sorted(changes):
        if t <= start:
            continue
        level += delta
        pts.append([t, level])
    pts.append([end, level])
    return {"kind": "step", "title": "Devices answering", "unit": "", "start": start, "end": end, "points": pts if checked else [],
            "expected": len(checked), "expected_label": f"Expected {len(checked)}",
            "note": "How many of the checked devices were answering, changing the moment one went down or came back."}


def _v_health(c, b, devs, start, end, period):
    span = end - start
    now_s = _health_scores(c, devs, start, end)
    before = _health_scores(c, devs, max(start - 4 * span, c.now - 360 * 86400), start)
    axes = [k for k in now_s if now_s[k] is not None or before[k] is not None]
    return {"kind": "radar", "title": "Health profile", "axes": axes,
            "series": [{"name": "This period", "values": [now_s[a] for a in axes]},
                       {"name": "The four periods before", "values": [before[a] for a in axes]}],
            "note": SCORE_NOTE + " Figures without data are left out rather than drawn as zero."}


def _v_topology(c, b, devs, start, end, period):
    view = c.env["map"]() if callable(c.env.get("map")) else {"nodes": [], "links": [], "parent": {}, "root": None}
    ids = {d["id"] for d in devs}
    state = _now_words(c)
    nodes = [n for n in view.get("nodes", []) if n.get("device_id") in ids]
    keys = {n["key"] for n in nodes}
    parent = view.get("parent") or {}
    children: Dict[str, int] = {}
    for k in keys:
        p = parent.get(k)
        if p in keys:
            children[p] = children.get(p, 0) + 1
    # The core: the root, devices with others behind them and their parents; access devices only when few.
    core = {k for k in keys if children.get(k) or view.get("root") == k}
    core |= {parent.get(k) for k in list(core) if parent.get(k) in keys}
    shown = keys if len(keys) <= 24 else core
    depth: Dict[str, int] = {}

    def level(k: str, seen: int = 0) -> int:
        if k in depth:
            return depth[k]
        p = parent.get(k)
        depth[k] = 0 if p not in shown or seen > 30 else level(p, seen + 1) + 1
        return depth[k]
    for k in shown:
        level(k)
    tiers: Dict[int, List[str]] = {}
    for k in sorted(shown, key=lambda k: next((str(n["label"]).lower() for n in nodes if n["key"] == k), k)):
        tiers.setdefault(depth[k], []).append(k)
    rows = max(tiers) + 1 if tiers else 1
    out_nodes = []
    by_key = {n["key"]: n for n in nodes}
    for t, ks in tiers.items():
        for i, k in enumerate(ks):
            n = by_key[k]
            tone = state.get(n["device_id"], ("", "none", ""))[1]
            out_nodes.append({"key": k, "label": n["label"], "tone": tone, "x": round((i + 0.5) / len(ks), 4),
                              "y": round((t + 0.5) / rows, 4), "core": bool(children.get(k)), "alt": len(ks) > 5 and i % 2 == 1})
    links = []
    for l in view.get("links", []):
        if l.get("hidden") or l["a"] not in shown or l["b"] not in shown:
            continue
        rate = l.get("rate") or {}
        util = None
        if isinstance(rate.get("speed"), (int, float)) and rate["speed"]:
            util = 100.0 * max(rate.get("in") or 0, rate.get("out") or 0) / (rate["speed"] * 1e6)
        down = any(state.get(by_key[x]["device_id"], ("", ""))[1] == "bad" for x in (l["a"], l["b"]))
        links.append({"a": l["a"], "b": l["b"], "tone": "bad" if down else _tone_at(util, LINK_WARN, LINK_BAD) if util is not None else "none",
                      "dashed": down, "util": _r(util, 1)})
    return {"kind": "topology", "title": "Core of the network" if shown is not keys else "Network map", "nodes": out_nodes, "links": links,
            "note": "Devices by tier from the internet side. Node colour is the device state; a link turns amber over 70% use, red over 90%, dashed red when an end is down."
                    + (" Only devices with others behind them are shown." if shown is not keys else "")}


def _v_timeline(c, b, devs, start, end, period):
    events = []
    ids = {d["id"] for d in devs}
    names = {d["id"]: d["name"] for d in devs}
    for e in _all_events(c, devs, start, end):
        msg = str(e["message"])
        tone = ("bad" if msg.startswith("Problem: ") and _sev(e["severity"]) in ("Critical", "High") else "warn" if msg.startswith("Problem: ")
                else "good" if msg.startswith("Resolved: ") or "back online" in msg.lower() or "recovered" in msg.lower()
                else "info" if msg.startswith("Acknowledged: ") else "warn" if _sev(e["severity"]) == "Warning" else "bad" if _sev(e["severity"]) in ("Critical", "High") else "info")
        events.append([e["timestamp"], f"{names.get(e['device_id'], '')}: {msg}", tone])
    events.sort(key=lambda x: x[0])
    down = _outages(c, start, end)
    spans = [(max(s, start), min(e or end, end)) for d in ids for s, e in down.get(d, [])]
    impact = None
    if spans:
        a, z = min(s for s, _ in spans), max(e for _, e in spans)
        impact = [a, z, f"Devices down ({_minutes(z - a)})"]
    step = max(1, len(events) // 14)
    return {"kind": "timeline", "title": "Timeline", "start": start, "end": end, "impact": impact, "events": events[::step][:16],
            "note": f"Times are local ({_tz()}). Red is a failure, amber an alert, blue an action, green a recovery; the shaded band is when devices were down."
                    + (f" Every {step}th event of {len(events)} is shown." if step > 1 else "")}


def _v_baseline(c, b, devs, start, end, period, key="cpu"):
    """Against the usual (spec 4.9): for each hour of the week, the median and spread over the weeks
    before. With too little history it falls back to the line with limit zones."""
    if key == "traffic":
        i = _focus_interface(c, devs, start, end)
        if not i:
            return {"kind": "baseline", "title": "Traffic against the usual", "points": [], "unit": "bps"}
        hist_start = start - BASELINE_WEEKS * 7 * 86400
        with database.get_connection() as conn:
            rows = conn.execute("SELECT hour, avg FROM metrics_hourly WHERE device_id = ? AND metric_key IN (?, ?) AND hour >= ? AND hour < ?;",
                                (i["device_id"], f"if.{i['idx']}.in_bps", f"if.{i['idx']}.out_bps", hist_start, start)).fetchall()
        hist: Dict[int, float] = {}
        for h, v in rows:
            hist[h] = max(hist.get(h, 0.0), v)
        both: Dict[int, float] = {}
        for t, v, _ in i["_in"] + i["_out"]:
            both[t] = max(both.get(t, 0.0), v)
        samples = sorted(both.items())
        title, unit = f"Traffic on {i['name']} {i['interface']} against the usual", "bps"
    else:
        name, unit = METRIC_INFO[key]
        hist_start = start - BASELINE_WEEKS * 7 * 86400
        hist = {}
        ids = [d["id"] for d in devs]
        if ids:
            keyname = {"cpu": "cpu_usage_pct", "memory": "mem_used_pct", "ping": "icmp_ping_ms"}[key]
            marks = ",".join("?" * len(ids))
            with database.get_connection() as conn:
                for h, v in conn.execute(f"SELECT hour, AVG(avg) FROM metrics_hourly WHERE device_id IN ({marks}) AND metric_key = ? "
                                         "AND hour >= ? AND hour < ? GROUP BY hour;", (*ids, keyname, hist_start, start)):
                    hist[h] = v
        samples = [(t, v) for t, v, _ in _pool(c, devs, key, start, end)]
        title = f"{name} against the usual"
    weeks = (max(hist) - min(hist)) / (7 * 86400) if hist else 0
    if weeks < 2:
        fb = dict(b, chart="threshold")
        if key == "traffic":
            i = _focus_interface(c, devs, start, end)
            spec = _mirror(i, start, end, title, "") if i else {"kind": "mirror", "in": [], "out": [], "unit": "bps", "title": title}
        else:
            spec = _v_metric_time(c, fb, devs, start, end, period, key)
            spec["title"] = title
        spec["note"] = (spec.get("note") or "") + f" The usual range is drawn once {BASELINE_WEEKS} weeks of history are kept (2 at least); fixed limits until then."
        return spec
    slots: Dict[int, List[float]] = {}
    for h, v in hist.items():
        dt = datetime.fromtimestamp(h)
        slots.setdefault(dt.weekday() * 24 + dt.hour, []).append(v)
    band: Dict[int, Tuple[float, float]] = {}
    for k, vals in slots.items():
        med = _median(vals) or 0
        mad = _median([abs(v - med) for v in vals]) or 0
        spread = max(mad * 1.4826, abs(med) * 0.05)
        band[k] = (max(0.0, med - BASELINE_K * spread), med + BASELINE_K * spread)
    pts = _bucketed([(t, v, v) for t, v in samples], start, end, "avg", 120)
    lo_hi, anomalies = [], []
    for t, v in pts:
        dt = datetime.fromtimestamp(t)
        rng = band.get(dt.weekday() * 24 + dt.hour)
        lo_hi.append([t, _r(rng[0], 2) if rng else None, _r(rng[1], 2) if rng else None])
        if rng and v is not None and (v < rng[0] or v > rng[1]):
            anomalies.append([t, v])
    return {"kind": "baseline", "title": title, "unit": unit, "start": start, "end": end, "points": pts, "band": lo_hi, "anomalies": anomalies[:60],
            "note": f"Grey is the usual range for that hour of the week over the {weeks:.0f} weeks before (median, {BASELINE_K:g} times the spread). "
                    "Red dots leave it, high or low: a sudden drop matters as much as a spike."}


def _treemap(title: str, note: str, items: List[Tuple[str, float, Optional[str]]], unit: str) -> Dict[str, Any]:
    """Tiles sized by value, laid out here once (squarified) so the page and the PDF agree."""
    items = sorted([(l, float(v), t) for l, v, t in items if v and v > 0], key=lambda p: -p[1])[:MAX_TOP]
    total = sum(v for _, v, _ in items)
    out: List[Dict[str, Any]] = []

    def worst(row: List[float], side: float) -> float:
        s = sum(row)
        return max(max(side * side * r / (s * s), s * s / (side * side * r)) for r in row) if s and side else 1e9

    def layout(rest: List[Tuple[str, float, Optional[str]]], x: float, y: float, w: float, h: float) -> None:
        while rest:
            side = min(w, h)
            row: List[Tuple[str, float, Optional[str]]] = []
            while rest:
                areas = [a for _, a, _ in row]
                trial = areas + [rest[0][1]]
                if row and worst(trial, side) > worst(areas, side):
                    break
                row.append(rest.pop(0))
            s = sum(a for _, a, _ in row)
            if w >= h:
                cw = s / h if h else 0
                yy = y
                for l, a, t in row:
                    ch = a / cw if cw else 0
                    out.append({"label": l, "x": x, "y": yy, "w": cw, "h": ch, "tone": t})
                    yy += ch
                x, w = x + cw, w - cw
            else:
                rh = s / w if w else 0
                xx = x
                for l, a, t in row:
                    cw2 = a / rh if rh else 0
                    out.append({"label": l, "x": xx, "y": y, "w": cw2, "h": rh, "tone": t})
                    xx += cw2
                y, h = y + rh, h - rh
    if total > 0:
        layout([(l, v / total, t) for l, v, t in items], 0.0, 0.0, 1.0, 1.0)
    values = {l: v for l, v, _ in items}
    for o in out:
        o.update({k: round(o[k], 4) for k in ("x", "y", "w", "h")})
        o["text"] = _unit_text(values[o["label"]], unit) if unit not in ("B",) else format_cell("bytes", values[o["label"]])
    return {"kind": "treemap", "title": title, "note": note, "items": out}


def _v_device_gauges(c, b, devs, start, end, period):
    """Processor, memory and temperature of one device now (the first one the block covers)."""
    d = devs[0] if devs else None
    latest = c.memo("latest", lambda: database.get_latest_metrics_all(["cpu_usage_pct", "cpu_idle_pct", "mem_used_pct", "icmp_ping_ms"]))
    m = (latest.get(d["id"]) or {}) if d else {}
    cpu = m.get("cpu_usage_pct", 100 - m["cpu_idle_pct"] if "cpu_idle_pct" in m else None)
    temp = _temps_now(c, [d])[0][1] if d else None
    gauges = [{"label": "Processor", "value": _r(cpu, 1), "text": _pct_text(cpu), "max": 100, "warn": LOAD_WARN, "bad": LOAD_BAD},
              {"label": "Memory", "value": _r(m.get("mem_used_pct"), 1), "text": _pct_text(m.get("mem_used_pct")), "max": 100, "warn": LOAD_WARN, "bad": LOAD_BAD}]
    if temp is not None:
        gauges.append({"label": "Temperature", "value": round(temp, 1), "text": f"{temp:.0f} C", "max": 100, "warn": TEMP_WARN, "bad": TEMP_BAD})
    when = max((x["timestamp"] for x in database.get_latest_metrics(d["id"])), default=None) if d else None
    return {"kind": "gauge", "title": "Right now", "gauges": gauges,
            "note": (f"Read {_date(when)}. " if when else "") + f"Amber from {LOAD_WARN:.0f}% and red from {LOAD_BAD:.0f}%"
                    + (f"; temperature in C, amber from {TEMP_WARN:.0f} and red from {TEMP_BAD:.0f}." if temp is not None else ".")}


def _v_capacity_now(c, b, devs, start, end, period):
    warn, bad, _ = _limits(b, LOAD_WARN, LOAD_BAD)
    rows = _resources(c, devs, c.now)
    items = [(f"{r['device']} {r['resource'].lower() if r['kind'] == 'Memory' else r['resource']}", r["now"]) for r in rows]
    return _category_chart(b, "Current use, highest first", f"Disks, memory and links (95th percentile against link speed). Lines at {warn:g}% and {bad:g}%.",
                           items, "%", lambda v: _tone_at(v, warn, bad), True, _top(b, 10),
                           [{"value": warn, "tone": "warn", "label": f"{warn:g}%"}, {"value": bad, "tone": "bad", "label": f"{bad:g}%"}], 100.0)


def _view(label: str, shape: str, charts: List[str], fn: Callable[..., Dict[str, Any]], aggs: Optional[List[str]] = None,
          splits: Optional[List[str]] = None, top: Optional[int] = None, limits: str = "", all_devices: bool = False,
          one: bool = False) -> Dict[str, Any]:
    return {"label": label, "shape": shape, "charts": charts, "fn": fn, "aggs": aggs or [], "splits": splits or [], "top": top,
            "limits": limits, "all_devices": all_devices, "one": one}


def _metric_views(key: str) -> Dict[str, Dict[str, Any]]:
    aggs = ["avg", "median", "p95", "max"] if key != "ping" else ["median", "avg", "p95", "max"]
    per_aggs = ["p95", "avg", "median", "max"] if key != "ping" else ["median", "p95", "avg", "max"]
    lim = "target" if key == "ping" else "warn_bad"
    cat = ["device", "group", "auto"]
    return {
        "time": _view("Over time", "series", ["threshold", "line", "columns"] if key != "ping" else ["line", "threshold", "columns"],
                      lambda c, b, d, s, e, p: _v_metric_time(c, b, d, s, e, p, key), aggs, limits=lim),
        "multi": _view("Several devices over time", "multi", ["multiples", "multi_line"], lambda c, b, d, s, e, p: _v_metric_multi(c, b, d, s, e, p, key),
                       aggs, top=12, limits=lim),
        "per": _view("Per device or group", "category", ["bar", "capacity", "lollipop", "columns", "diverging"] if key != "ping" else ["bar", "lollipop", "columns", "diverging"],
                     lambda c, b, d, s, e, p: _v_metric_per(c, b, d, s, e, p, key), per_aggs, cat, 10, lim),
        "previous": _view("This period against the one before", "pair", ["dumbbell"], lambda c, b, d, s, e, p: _v_metric_previous(c, b, d, s, e, p, key),
                          per_aggs, cat, 10),
        "hour_week": _view("By hour and weekday", "hour_week", ["heatmap", "clock"], lambda c, b, d, s, e, p: _v_metric_hour_week(c, b, d, s, e, p, key),
                           aggs, limits=lim),
        "baseline": _view("Against the usual", "series", ["baseline"], lambda c, b, d, s, e, p: _v_baseline(c, b, d, s, e, p, key), limits=lim),
    }


SOURCES: Dict[str, Dict[str, Any]] = {
    "availability": {"label": "Availability", "about": "Share of checks answered (ping or service checks); planned maintenance is left out.", "views": {
        "time": _view("Over time", "series", ["columns", "line", "threshold"], _v_avail_time, limits="target"),
        "per": _view("Per device or group", "category", ["bar", "lollipop", "columns", "bullet", "diverging"], _v_avail_per,
                     splits=["auto", "device", "group"], top=10, limits="target"),
        "days": _view("Day by day", "days", ["strips", "calendar"], _v_avail_days, splits=["auto", "device", "group"], top=12, limits="target"),
        "budget": _view("Downtime budget", "composition", ["waterfall"], _v_avail_budget, limits="target"),
        "previous": _view("This period against the one before", "pair", ["dumbbell"], _v_avail_previous, splits=["auto", "device", "group"], top=10)}},
    "downtime": {"label": "Time down and outages", "about": "Outages from the checks: when a device stopped answering and when it came back.", "views": {
        "per": _view("Per device or group", "category", ["bar", "columns", "lollipop", "treemap"], _v_down_per, splits=["device", "group", "auto"], top=10),
        "time": _view("Outages over time", "series", ["columns"], _v_down_time),
        "timeline": _view("Outage timeline", "state_time", ["gantt"], _v_down_gantt, top=12),
        "worst_week": _view("Outage timeline, worst week", "state_time", ["gantt"], _v_down_worst_week, top=12)}},
    "ping": {"label": "Ping", "about": "How long devices take to answer ping, in milliseconds.", "views": dict(_metric_views("ping"), **{
        "band": _view("Typical and spread over time", "pct_time", ["band"], _v_ping_band, limits="target"),
        "distribution": _view("Every answer", "distribution", ["box", "histogram", "cdf"], _v_ping_dist, splits=["auto", "device", "group"], top=12, limits="target"),
        "stddev": _view("How much it varies (standard deviation)", "category", ["bar", "lollipop", "columns"], _v_ping_stddev, splits=["auto", "device", "group"], top=10),
        "watch": _view("List with trend lines", "list", ["sparktable"], _v_ping_watch, top=10, limits="target")})},
    "failed": {"label": "Failed checks", "about": "Share of checks that got no answer. The monitor sends one ping per check, so this is not packet loss.", "views": {
        "per": _view("Per device or group", "category", ["lollipop", "bar", "columns"], _v_failed_per, splits=["auto", "device", "group"], top=10, limits="warn_bad"),
        "time": _view("Over time", "series", ["line", "columns"], _v_failed_time, limits="warn_bad")}},
    "cpu": {"label": "Processor use", "about": "Processor use read over SNMP or from the host, in percent.", "views": dict(_metric_views("cpu"), **{
        "now": _view("Now", "current", ["gauge", "headline"], lambda c, b, d, s, e, p: _v_metric_now(c, b, d, s, e, p, "cpu"), top=4, limits="warn_bad"),
        "watch": _view("Watch list with trend lines", "list", ["sparktable"], _v_cpu_watch, top=8, limits="warn_bad")})},
    "memory": {"label": "Memory use", "about": "Memory in use, in percent.", "views": dict(_metric_views("memory"), **{
        "now": _view("Now", "current", ["gauge", "headline"], lambda c, b, d, s, e, p: _v_metric_now(c, b, d, s, e, p, "memory"), top=4, limits="warn_bad"),
        "watch": _view("Watch list with trend lines", "list", ["sparktable"], lambda c, b, d, s, e, p: _v_cpu_watch(c, b, d, s, e, p, "memory"), top=8, limits="warn_bad")})},
    "cpu_mem": {"label": "Processor and memory together", "about": "Each device placed by its processor and its memory use.", "views": {
        "scatter": _view("Processor against memory", "scatter", ["scatter"], _v_cpu_mem, limits="warn_bad")}},
    "temperature": {"label": "Temperature", "about": "The hottest sensor of each device now, in degrees C.", "views": {
        "now": _view("Now", "current", ["gauge", "bar", "lollipop"], _v_temp, top=10, limits="warn_bad")}},
    "storage": {"label": "Disks and volumes", "about": "How full each disk, volume and storage pool is now.", "views": {
        "per": _view("How full now", "category", ["capacity", "bar", "treemap"], _v_storage_per, top=10, limits="warn_bad")}},
    "capacity": {"label": "Capacity", "about": "Disks, memory and link use, with a trend on the daily peaks.", "views": {
        "now": _view("Current use", "category", ["capacity", "bar", "lollipop"], _v_capacity_now, top=10, limits="warn_bad"),
        "forecast": _view("Trend and forecast (most urgent)", "forecast", ["forecast"], _v_forecast, limits="warn_bad")}},
    "traffic": {"label": "Interface traffic", "about": "Bits per second in and out, from the SNMP interface counters.", "views": {
        "inout": _view("In and out over time (busiest or internet link)", "inout", ["mirror"], _v_traffic_inout),
        "per": _view("Per interface, device or group", "category", ["bar", "columns", "treemap"], _v_traffic_per, splits=["interface", "device", "group"], top=10),
        "pair": _view("In and out per interface, device or group", "pair", ["butterfly", "grouped"], _v_traffic_pair, splits=["interface", "device", "group"], top=10),
        "bands": _view("How hard interfaces work, per group or device", "composition", ["stack100"], _v_traffic_bands, splits=["auto", "group", "device"], top=12),
        "hour_week": _view("By hour and weekday (busiest link)", "hour_week", ["heatmap", "clock"], _v_traffic_hour),
        "baseline": _view("Against the usual (busiest link)", "series", ["baseline"], lambda c, b, d, s, e, p: _v_baseline(c, b, d, s, e, p, "traffic"))}},
    "utilisation": {"label": "Link use", "about": "Traffic against the link speed, at the 95th percentile.", "views": {
        "per": _view("Per interface", "category", ["capacity", "bar", "lollipop"], _v_util_per, top=10, limits="warn_bad"),
        "watch": _view("Key interfaces with trend lines", "list", ["sparktable"], _v_util_watch, top=10, limits="warn_bad")}},
    "problems": {"label": "Problems (alerts)", "about": "Problems the monitor opened, from the problem log.", "views": {
        "time": _view("Over time", "composition", ["stacked", "columns"], _v_problems_time),
        "per": _view("By type, device, group or severity", "composition", ["pareto", "bar", "donut", "treemap", "columns"], _v_problems_per,
                     splits=["rule", "device", "group", "severity"], top=10),
        "hour": _view("By hour of day", "hour_week", ["clock", "columns"], _v_problems_hour, limits="warn_bad"),
        "hour_week": _view("By hour and weekday", "hour_week", ["heatmap"], _v_problems_week),
        "noisy": _view("Noisiest devices with trend lines", "list", ["sparktable"], _v_problems_noisy, top=8)}},
    "events": {"label": "Events", "about": "Everything in the event log: problems, recoveries, restarts, changes and messages.", "views": {
        "time": _view("Over time", "composition", ["stacked", "columns"], _v_events_time),
        "per": _view("By kind, device or severity", "composition", ["bar", "donut", "pareto", "treemap"], _v_events_per, splits=["type", "device", "group", "severity"], top=10),
        "hour": _view("By hour of day", "hour_week", ["clock", "columns"], _v_events_hour, limits="warn_bad")}},
    "status": {"label": "Devices now", "about": "Whether each device is up, has a problem or is down right now.", "views": {
        "now": _view("Every device now", "status", ["grid", "donut"], _v_status)}},
    "reachable": {"label": "Devices answering", "about": "How many devices answered, over time.", "views": {
        "time": _view("Over time", "count_time", ["step"], _v_reachable)}},
    "health": {"label": "Health", "about": "Scores from 0 to 100 for availability, ping, processor, memory, disk and problems.", "views": {
        "profile": _view("Health profile against the periods before", "profile", ["radar"], _v_health),
        "now": _view("Processor, memory and temperature now (one device)", "current", ["gauge"], _v_device_gauges, one=True)}},
    "topology": {"label": "Network map", "about": "How the devices connect, from the map.", "views": {
        "map": _view("Devices by tier", "topology", ["topology"], _v_topology, all_devices=True)}},
    "timeline": {"label": "Event timeline", "about": "What happened when, from the event log, with the time devices were down.", "views": {
        "events": _view("What happened when", "timeline", ["timeline"], _v_timeline)}},
}

CHART_SHAPES = {"line": "series", "threshold": "series", "baseline": "series", "forecast": "forecast", "headline": "current", "columns": "category",
                "multi_line": "multi", "multiples": "multi", "mirror": "inout", "step": "count_time", "gantt": "state_time", "band": "pct_time",
                "gauge": "current", "bar": "category", "lollipop": "category", "capacity": "category", "treemap": "category", "bullet": "target",
                "diverging": "target", "grouped": "pair", "butterfly": "pair", "dumbbell": "pair", "stacked": "composition", "donut": "composition",
                "pareto": "composition", "stack100": "composition", "waterfall": "composition", "histogram": "distribution", "box": "distribution",
                "cdf": "distribution", "heatmap": "hour_week", "clock": "hour_week", "strips": "days", "calendar": "days", "scatter": "scatter",
                "radar": "profile", "grid": "status", "topology": "topology", "timeline": "timeline", "sparktable": "list"}


# Key figures ------------------------------------------------------------------------------------------
# Each metric: label, unit, how a change is told (_change kinds), which way is better, whether it is a
# "now" figure (no previous period to compare with) and the function: (c, devs, start, end, tile) ->
# {"v": number or None, "text": shown value, "sub": small line, "tone": its own status when it has one}.

def _km(v: Optional[float], text: str, sub: str = "", tone: Optional[str] = None) -> Dict[str, Any]:
    return {"v": v, "text": text, "sub": sub, "tone": tone}


def _k_avail(c, devs, s, e, t):
    hrs = _hours(c, s, e)
    v = _uptime([h for d in devs for h in hrs.get(d["id"], [])])
    target = t.get("target") if isinstance(t.get("target"), (int, float)) else UPTIME_TARGET
    return _km(v, _pct_text(v), f"Target {target:g}%", _avail_tone(v, target) if v is not None else "none")


def _k_down(c, devs, s, e, t):
    hrs = _hours(c, s, e)
    measured = [d for d in devs if hrs.get(d["id"])]
    if not measured:
        return _km(None, "No data")
    down = _outages(c, s, e)
    secs = sum(_down_seconds(down.get(d["id"], []), s, e) for d in measured)
    target = t.get("target") if isinstance(t.get("target"), (int, float)) else UPTIME_TARGET
    allowed = (e - s) * (100 - target) / 100 * len(measured)
    return _km(secs / 60, _minutes(secs), f"Of {_minutes(allowed)} allowed at {target:g}%",
               "good" if secs <= allowed / 2 else "warn" if secs <= allowed else "bad")


def _k_outages(c, devs, s, e, t):
    hrs = _hours(c, s, e)
    if not any(hrs.get(d["id"]) for d in devs):
        return _km(None, "No data")
    down = _outages(c, s, e)
    n = sum(1 for d in devs for st, _ in down.get(d["id"], []) if st >= s)
    return _km(n, str(n), "Started in the period", "good" if not n else "warn")


def _k_mttr(c, devs, s, e, t):
    down = _outages(c, s, e)
    spans = [en - st for d in devs for st, en in down.get(d["id"], []) if en is not None and s <= en <= e]
    if not spans:
        return _km(None, "None", "No outage ended in the period")
    return _km(_mean(spans) / 60, _minutes(_mean(spans)), f"Median {_minutes(_median(spans))}, over {_plural(len(spans), 'outage')}")


def _k_ping(c, devs, s, e, t):
    how = t.get("agg") or "median"
    v = _agg([x for d in devs for _, x, _ in _pings(c, d, s, e)], how)
    return _km(v, _ms(v), AGGS[how][0] + (", all devices" if len(devs) > 1 else ""), _tone_at(v, PING_TARGET_MS, PING_TARGET_MS * 2))


def _k_failed(c, devs, s, e, t):
    hrs = _hours(c, s, e)
    up = _uptime([h for d in devs for h in hrs.get(d["id"], [])])
    v = None if up is None else round(100 - up, 3)
    return _km(v, _pct_text(v) if v is None or v >= 0.1 else f"{v:.3f}%", "Not packet loss: one ping per check", _tone_at(v, FAILED_WARN, FAILED_BAD))


def _k_stddev(c, devs, s, e, t):
    import statistics
    vals = [x for d in devs for _, x, _ in _pings(c, d, s, e)]
    v = statistics.pstdev(vals) if len(vals) > 1 else None
    return _km(v, _ms(v), "RTT standard deviation, not jitter")


def _k_load(key: str):
    def fn(c, devs, s, e, t):
        how = t.get("agg") or "p95"
        v = _agg([x for d in devs for _, x, _ in _metric(c, d, key, s, e)], how)
        return _km(v, _pct_text(v), AGGS[how][0], _tone_at(v, LOAD_WARN, LOAD_BAD))
    return fn


def _checked(c, devs, s, e) -> bool:
    """Whether the monitor recorded checks of these devices in the window (else a count of 0 means nothing)."""
    hrs = _hours(c, s, e)
    return any(hrs.get(d["id"]) for d in devs)


def _k_problems(c, devs, s, e, t):
    if not _checked(c, devs, s, e):
        return _km(None, "No data")
    n = len(_opened(c, devs, s, e))
    return _km(n, str(n), "Opened", "good" if not n else "warn")


def _k_critical(c, devs, s, e, t):
    if not _checked(c, devs, s, e):
        return _km(None, "No data")
    n = sum(1 for x in _opened(c, devs, s, e) if _sev(x["severity"]) in ("Critical", "High"))
    return _km(n, str(n), "Critical or high", "good" if not n else "bad")


def _k_events(c, devs, s, e, t):
    if not _checked(c, devs, s, e):
        return _km(None, "No data")
    n = len(_all_events(c, devs, s, e))
    return _km(n, str(n), "Every kind")


def _open_now(devs):
    ids = {d["id"] for d in devs}
    return [p for p in database.list_active_problems() if p["device_id"] in ids]


def _k_open(c, devs, s, e, t):
    probs = _open_now(devs)
    crit = sum(1 for p in probs if p["severity"] in ("critical", "high"))
    return _km(len(probs), str(len(probs)), f"{crit} critical or high" if probs else "None open",
               "bad" if crit else "warn" if probs else "good")


def _k_unacked(c, devs, s, e, t):
    old = [p for p in _open_now(devs) if not p.get("acknowledged_at") and p["since"] < c.now - 86400]
    return _km(len(old), str(len(old)), "Open over 24 hours, not acknowledged", "bad" if old else "good")


def _k_state(word: str, tone: str):
    def fn(c, devs, s, e, t):
        state = _now_words(c)
        n = sum(1 for d in devs if state.get(d["id"], ("",))[0] == word)
        return _km(n, str(n), f"Of {len(devs)}", tone if n else ("good" if tone != "good" else "none"))
    return fn


def _k_devices(c, devs, s, e, t):
    return _km(len(devs), str(len(devs)), "In this report", "info")


def _k_fullest(c, devs, s, e, t):
    disks = [(d["name"], x["name"], x["used_pct"]) for d in devs for x in _disks(d["id"]) if x["used_pct"] is not None]
    top = max(disks, key=lambda x: x[2], default=None)
    return _km(top[2] if top else None, _pct_text(top[2]) if top else "No data", f"{top[0]}: {top[1]}" if top else "", _tone_at(top[2] if top else None, LOAD_WARN, LOAD_BAD))


def _k_traffic(c, devs, s, e, t):
    i = _focus_interface(c, devs, s, e)
    return _km(_ifload(i) if i else None, _bps(_ifload(i)) if i else "No data", f"95th pct, {i['name']} {i['interface']}" if i else "")


def _k_busy_links(c, devs, s, e, t):
    n = sum(1 for i in _all_interfaces(c, devs, s, e) if i["util"] is not None and i["util"] >= LINK_BAD)
    return _km(n, str(n), f"Over {LINK_BAD:.0f}% at the 95th percentile", "bad" if n else "good")


def _k_quick(c, devs, s, e, t):
    types = _problem_types(c, devs, s, e)
    total = sum(x["count"] for x in types)
    quick = sum(x["quick"] for x in types)
    v = 100.0 * quick / total if total else None
    return _km(v, f"{v:.0f}%" if v is not None else "None", "Likely noise: cleared without anyone acknowledging", _tone_at(v, 30, 60))


def _k_mtta(c, devs, s, e, t):
    times = _ack_times(c, devs, s, e)
    if not times:
        return _km(None, "None", "No problem was acknowledged in the app")
    return _km(_mean(times) / 60, _minutes(_mean(times)), f"Over {_plural(len(times), 'acknowledgement')}", _tone_at(_mean(times) / 60, 15, 60))


def _k_resources(c, devs, s, e, t):
    rows = _resources(c, devs, c.now)
    kinds = sorted({r["kind"] for r in rows})
    return _km(len(rows), str(len(rows)), _and([k.lower() + "s" if k != "Memory" else "memory" for k in kinds]).capitalize() or "None yet", "info")


def _k_full(days: int, word: str):
    def fn(c, devs, s, e, t):
        n = sum(1 for r in _resources(c, devs, c.now) if r["state"] == "passed" or (r["days"] is not None and r["days"] < days))
        return _km(n, str(n), word, ("bad" if days <= 30 else "warn") if n else "good")
    return fn


def _k_growth(c, devs, s, e, t):
    g = [r["growth"] for r in _resources(c, devs, c.now) if r["growth"] is not None]
    v = _mean(g)
    return _km(v, f"{v:+.1f} points" if v is not None else "No data", "Average change a month, from the trends", "warn" if v and v > 1 else "info")


def _groups(devs):
    return _cats(devs, "group")


def _k_groups_below(c, devs, s, e, t):
    target = t.get("target") if isinstance(t.get("target"), (int, float)) else UPTIME_TARGET
    hrs = _hours(c, s, e)
    cats = _cats(devs, _split({"split": "auto"}, devs))
    vals = [(l, _uptime([h for d in m for h in hrs.get(d["id"], [])])) for l, m in cats]
    vals = [(l, v) for l, v in vals if v is not None]
    if not vals:
        return _km(None, "No data")
    below = [l for l, v in vals if v < target]
    who = "groups" if len({_gname(d) for d in devs}) > 1 else "devices"
    return _km(len(below), f"{len(below)} of {len(vals)}", (_and(below[:3]) + (" and more" if len(below) > 3 else "")) if below else f"Every one of the {who} met {target:g}%",
               "bad" if below else "good")


def _k_over_ping(c, devs, s, e, t):
    target = t.get("target") if isinstance(t.get("target"), (int, float)) else PING_TARGET_MS
    cats = _cats(devs, _split({"split": "auto"}, devs))
    vals = [(l, _median([v for d in m for _, v, _ in _pings(c, d, s, e)])) for l, m in cats]
    vals = [(l, v) for l, v in vals if v is not None]
    if not vals:
        return _km(None, "No data")
    over = [l for l, v in vals if v > target]
    return _km(len(over), f"{len(over)} of {len(vals)}", (_and(over[:3]) + (" and more" if len(over) > 3 else "")) if over else f"Every median under {target:g} ms",
               "bad" if over else "good")


def _scores(c, devs, s, e):
    return c.memo(("scores", s, e, tuple(d["id"] for d in devs)), lambda: [(l, _group_score(c, m, s, e)) for l, m in _cats(devs, _split({"split": "auto"}, devs))])


def _k_best(best: bool):
    def fn(c, devs, s, e, t):
        sc = [(l, x["score"]) for l, x in _scores(c, devs, s, e) if x["score"] is not None]
        if not sc:
            return _km(None, "No data")
        l, v = (max if best else min)(sc, key=lambda p: p[1])
        return _km(None, l, f"Score {v:.0f} of 100", "good" if best else _tone_at(v, 80, 60, high_is_bad=False))
    return fn


def _k_avg_score(c, devs, s, e, t):
    sc = [x["score"] for _, x in _scores(c, devs, s, e) if x["score"] is not None]
    v = _mean(sc)
    return _km(v, f"{v:.0f}" if v is not None else "No data", "Of 100, all groups", _tone_at(v, 80, 60, high_is_bad=False) if v is not None else "none")


def _k_groups(c, devs, s, e, t):
    n = len({_gname(d) for d in devs})
    return _km(n, str(n), f"{_plural(len(devs), 'device')} in all", "info")


def _k_maint(c, devs, s, e, t):
    import maintenance
    day0 = int(datetime.fromtimestamp(c.now).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    wins = [w for w in maintenance.windows(c.now) if w["start"] < day0 + 86400 and w["end"] > day0]
    when = ", ".join(datetime.fromtimestamp(w["start"]).strftime("%H:%M") for w in sorted(wins, key=lambda w: w["start"])[:3])
    return _km(len(wins), str(len(wins)), f"Planned changes{': ' + when if when else ''}", "info")


def _k_focus_duration(c, devs, s, e, t):
    f = c.focus_info
    if not f:
        return _km(None, "No outage", "None in the period")
    detect = f.get("detected")
    return _km(f["seconds"] / 60, _minutes(f["seconds"]), f"Detected in {_minutes(detect)}" if detect is not None else "No problem was raised for it",
               "bad" if f["seconds"] >= 3600 else "warn")


def _k_affected(c, devs, s, e, t):
    down = _outages(c, s, e)
    hit = [d["name"] for d in devs if any(_down_seconds([x], s, e) > 0 for x in down.get(d["id"], []))]
    return _km(len(hit), str(len(hit)), _and(hit[:3]) + (" and more" if len(hit) > 3 else "") if hit else "None went down", "bad" if hit else "good")


def _k_peak_down(c, devs, s, e, t):
    down = _outages(c, s, e)
    marks = sorted([(max(a, s), 1) for d in devs for a, z in down.get(d["id"], [])] + [(min(z or e, e), -1) for d in devs for a, z in down.get(d["id"], [])],
                   key=lambda x: (x[0], x[1]))
    level = peak = 0
    for _, delta in marks:
        level += delta
        peak = max(peak, level)
    return _km(peak, str(peak), "Down at the same time", "bad" if peak > 1 else "warn" if peak else "good")


KPI_METRICS: Dict[str, Dict[str, Any]] = {
    "availability": {"label": "Availability", "kind": "points", "better": "up", "fn": _k_avail, "target": UPTIME_TARGET},
    "downtime": {"label": "Time down", "kind": "minutes", "better": "down", "fn": _k_down},
    "outages": {"label": "Outages", "kind": "count", "better": "down", "fn": _k_outages},
    "mttr": {"label": "Mean time to repair", "kind": "minutes", "better": "down", "fn": _k_mttr},
    "ping": {"label": "Ping", "kind": "ms", "better": "down", "fn": _k_ping, "aggs": ["median", "p95", "avg", "max"], "target": PING_TARGET_MS},
    "failed": {"label": "Failed checks", "kind": "points", "better": "down", "fn": _k_failed, "target": FAILED_WARN},
    "rtt_sd": {"label": "RTT standard deviation", "kind": "ms", "better": "down", "fn": _k_stddev},
    "cpu": {"label": "Processor", "kind": "points", "better": "down", "fn": _k_load("cpu"), "aggs": ["p95", "avg", "max", "median"], "target": LOAD_WARN},
    "memory": {"label": "Memory", "kind": "points", "better": "down", "fn": _k_load("memory"), "aggs": ["p95", "avg", "max", "median"], "target": LOAD_WARN},
    "problems": {"label": "Problems opened", "kind": "count", "better": "down", "fn": _k_problems},
    "critical": {"label": "Critical problems", "kind": "count", "better": "down", "fn": _k_critical},
    "events": {"label": "Events", "kind": "count", "better": "down", "fn": _k_events},
    "quick": {"label": "Cleared within 5 minutes", "kind": "points", "better": "down", "fn": _k_quick},
    "mtta": {"label": "Mean time to acknowledge", "kind": "minutes", "better": "down", "fn": _k_mtta},
    "open_problems": {"label": "Open problems", "kind": "count", "better": "down", "fn": _k_open, "now": True},
    "unacked": {"label": "Not acknowledged", "kind": "count", "better": "down", "fn": _k_unacked, "now": True},
    "devices": {"label": "Devices", "kind": "count", "better": "", "fn": _k_devices, "now": True},
    "devices_up": {"label": "Up", "kind": "count", "better": "up", "fn": _k_state("Up", "good"), "now": True},
    "devices_warn": {"label": "With problems", "kind": "count", "better": "down", "fn": _k_state("Problems", "warn"), "now": True},
    "devices_down": {"label": "Down", "kind": "count", "better": "down", "fn": _k_state("Down", "bad"), "now": True},
    "fullest": {"label": "Fullest disk", "kind": "points", "better": "down", "fn": _k_fullest, "now": True},
    "traffic": {"label": "Busiest link (95th pct)", "kind": "bps", "better": "", "fn": _k_traffic},
    "busy_links": {"label": f"Links over {LINK_BAD:.0f}%", "kind": "count", "better": "down", "fn": _k_busy_links},
    "resources": {"label": "Resources tracked", "kind": "count", "better": "", "fn": _k_resources, "now": True},
    "full_30": {"label": "Full within 30 days", "kind": "count", "better": "down", "fn": _k_full(30, "Act now"), "now": True},
    "full_90": {"label": "Full within 90 days", "kind": "count", "better": "down", "fn": _k_full(90, "Plan for this quarter"), "now": True},
    "growth": {"label": "Average growth a month", "kind": "points", "better": "down", "fn": _k_growth, "now": True},
    "groups_below": {"label": "Below the target", "kind": "count", "better": "down", "fn": _k_groups_below, "target": UPTIME_TARGET},
    "over_ping": {"label": "Over the ping target", "kind": "count", "better": "down", "fn": _k_over_ping, "target": PING_TARGET_MS},
    "best_group": {"label": "Best group", "kind": "count", "better": "", "fn": _k_best(True), "now": True},
    "worst_group": {"label": "Worst group", "kind": "count", "better": "", "fn": _k_best(False), "now": True},
    "avg_score": {"label": "Average score", "kind": "points", "better": "up", "fn": _k_avg_score},
    "groups": {"label": "Groups", "kind": "count", "better": "", "fn": _k_groups, "now": True},
    "maintenance": {"label": "Maintenance today", "kind": "count", "better": "", "fn": _k_maint, "now": True},
    "outage_duration": {"label": "Duration", "kind": "minutes", "better": "down", "fn": _k_focus_duration, "now": True},
    "affected": {"label": "Devices affected", "kind": "count", "better": "down", "fn": _k_affected, "now": True},
    "peak_down": {"label": "Most down at once", "kind": "count", "better": "down", "fn": _k_peak_down, "now": True},
}


def _tile(c: Ctx, t: Dict[str, Any], devs: List[Dict[str, Any]], start: int, end: int, period: str) -> Dict[str, Any]:
    m = KPI_METRICS[t["metric"]]
    how = t.get("agg") or (m.get("aggs") or [""])[0]
    tt = dict(t, agg=how)
    cur = m["fn"](c, devs, start, end, tt)
    label = t.get("label") or (m["label"] + (f" ({AGGS[how][0].lower()})" if how and how != (m.get("aggs") or [""])[0] else ""))
    better = t.get("better") or m["better"]
    compare = t.get("compare") or ("none" if m.get("now") else "previous")
    tone, note, trend, sub = cur.get("tone") or "info", "", None, cur.get("sub") or ""
    if compare == "previous" and not m.get("now"):
        prev = m["fn"](c, devs, start - (end - start), start, tt)
        note, trend = _change(cur["v"], prev["v"], period, m["kind"], better or "down")
        if cur["v"] is not None and prev["v"] is None:
            note = "No comparison: no data for the period before"
        if not better:
            trend = "neutral" if trend else None
        elif not cur.get("tone"):
            tone = "none" if cur["v"] is None else "warn" if trend == "bad" else "good"
    elif compare == "target":
        target = t.get("target") if isinstance(t.get("target"), (int, float)) else m.get("target")
        if target is not None and cur["v"] is not None:
            met = cur["v"] >= target if better != "down" else cur["v"] <= target
            tone = "good" if met else "bad"
            sub = f"Target {_unit_text(target, {'ms': 'ms', 'points': '%', 'bps': 'bps', 'minutes': 'min'}.get(m['kind'], ''))}, {'met' if met else 'missed'}"
    if cur["v"] is None and cur.get("tone") is None and compare != "none":
        tone = "none"
    return _kpi(label, cur["text"], tone, sub=sub, note=note, trend=trend)


# Tables ------------------------------------------------------------------------------------------------
# Each entity: its columns (key, label, type), the default ones, status rules (a pill column named
# "status") and trend lines (a spark column named "trend"). Rows hold raw values; the page, the PDF
# and the CSV format them their own way.

TABLES: Dict[str, Dict[str, Any]] = {
    "device": {"label": "Devices", "columns": [
        _col("name", "Device"), _col("ip", "Address"), _col("group", "Group"), _col("tags", "Tags"), _col("model", "Model"),
        _col("now", "Now", "pill"), _col("availability", "Availability", "pct"), _col("downtime", "Time down", "duration"),
        _col("outages", "Outages", "num"), _col("ping_min", "Fastest ping", "ms"), _col("ping_median", "Median ping", "ms"),
        _col("ping_p95", "95th pct ping", "ms"), _col("ping_max", "Slowest ping", "ms"), _col("failed", "Failed checks", "pct"),
        _col("rtt_sd", "RTT std dev", "ms"), _col("cpu_p95", "CPU 95th pct", "pct"), _col("mem_p95", "Memory 95th pct", "pct"),
        _col("disk", "Fullest disk", "pct"), _col("problems", "Problems", "num")],
        "default": ["name", "group", "availability", "downtime", "outages", "ping_median", "status"], "sort": "availability", "desc": False,
        "status": {"availability": "Against the target", "load": "Load", "ping": "Against the ping target", "now": "Now"},
        "sparks": {"ping": "Ping", "cpu": "Processor", "memory": "Memory", "availability": "Availability"}},
    "group": {"label": "Groups (or devices when there is one group)", "columns": [
        _col("group", "Group"), _col("devices", "Devices", "num"), _col("availability", "Availability", "pct"),
        _col("downtime", "Time down", "duration"), _col("outages", "Outages", "num"), _col("ping_min", "Fastest ping", "ms"),
        _col("ping_median", "Median ping", "ms"), _col("ping_p95", "95th pct ping", "ms"), _col("ping_max", "Slowest ping", "ms"),
        _col("rtt_sd", "RTT std dev", "ms"), _col("failed", "Failed checks", "pct"), _col("util", "Busiest link", "pct"),
        _col("score", "Score", "num"), _col("rank", "Rank", "num")],
        "default": ["group", "devices", "availability", "ping_median", "failed", "status"], "sort": "availability", "desc": False,
        "status": {"availability": "Against the target", "ping": "Against the ping target", "score": "Status"}, "sparks": {}},
    "interface": {"label": "Interfaces", "columns": [
        _col("name", "Device"), _col("interface", "Interface"), _col("description", "Description"), _col("speed", "Speed", "mbps"),
        _col("in_p95", "In (95th pct)", "bps"), _col("out_p95", "Out (95th pct)", "bps"), _col("peak", "Peak", "bps"), _col("util", "Use (95th pct)", "pct")],
        "default": ["name", "interface", "description", "speed", "in_p95", "out_p95", "util", "status"], "sort": "util", "desc": True,
        "status": {"load": "Load"}, "sparks": {"traffic": "Traffic"}},
    "rule": {"label": "Problem types", "columns": [
        _col("problem", "Problem"), _col("severity", "Severity", "pill"), _col("count", "Times", "num"), _col("devices", "Devices", "num"),
        _col("quick", "Cleared within 5 min", "pct"), _col("median", "Median duration", "duration"), _col("last", "Last seen", "time"),
        _col("hint", "Suggested tuning")],
        "default": ["problem", "count", "quick", "median", "hint", "status"], "sort": "count", "desc": True,
        "status": {"tuning": "Status"}, "sparks": {}},
    "problem": {"label": "Open problems now", "columns": [
        _col("priority", "Priority", "pill"), _col("name", "Device"), _col("problem", "Problem"), _col("since", "Since", "time"),
        _col("handled", "Handled")],
        "default": ["priority", "name", "problem", "since", "handled", "status"], "sort": "", "desc": False,
        "status": {"state": "Status"}, "sparks": {}},
    "resource": {"label": "Resources (capacity)", "columns": [
        _col("resource", "Resource"), _col("device", "Device"), _col("now", "Now", "pct"), _col("growth", "Growth a month"),
        _col("limit", "Limit", "pct"), _col("days", "Days left"), _col("advice", "Recommendation")],
        "default": ["resource", "device", "now", "growth", "limit", "days", "advice", "status"], "sort": "", "desc": False,
        "status": {"priority": "Priority"}, "sparks": {}},
    "outage": {"label": "Outages", "columns": [
        _col("name", "Device"), _col("group", "Group"), _col("started", "Went down", "time"), _col("ended", "Came back", "time"),
        _col("duration", "Down for", "duration")],
        "default": ["name", "group", "started", "ended", "duration", "status"], "sort": "started", "desc": True,
        "status": {"state": "Now"}, "sparks": {}},
    "event": {"label": "Events", "columns": [
        _col("time", "When", "time"), _col("name", "Device"), _col("severity", "Severity", "pill"), _col("type", "Type"), _col("message", "What happened")],
        "default": ["time", "name", "severity", "type", "message"], "sort": "time", "desc": True, "status": {}, "sparks": {}},
}


def _table_columns(entity: str) -> List[Column]:
    t = TABLES[entity]
    cols = list(t["columns"])
    if t["status"]:
        cols.append(_col("status", "Status", "pill"))
    if t["sparks"]:
        cols.append(_col("trend", "Trend", "spark"))
    return cols


def _spark(c, d, key, start, end):
    if key == "availability":
        starts, _ = _slots(start, end)
        return _per_slot(_hours(c, start, end), [d], starts)
    return [v for _, v in _thin(_metric(c, d, key, start, end), start, end, 24, _median if key == "ping" else _mean)]


def _rows_device(c, b, devs, start, end, keys):
    span = end - start
    hrs = _hours(c, start, end)
    down = _outages(c, start, end)
    state = _now_words(c) if "now" in keys or b.get("status") == "now" else {}
    target = _target(b, UPTIME_TARGET)
    ping_t = PING_TARGET_MS if b.get("status") != "ping" else _target(b, PING_TARGET_MS)
    rows = []
    for d in devs:
        r: Dict[str, Any] = dict(_base(d), model=d.get("model") or "", _id=d["id"])
        up = _uptime(hrs.get(d["id"], []))
        secs = _down_seconds(down.get(d["id"], []), start, end) if up is not None else None
        r.update(availability=up, downtime=secs, outages=sum(1 for s, _ in down.get(d["id"], []) if s >= start) if up is not None else None,
                 failed=round(100 - up, 3) if up is not None else None)
        if keys & {"ping_min", "ping_median", "ping_p95", "ping_max", "rtt_sd"} or b.get("status") == "ping":
            pv = [v for _, v, _ in _pings(c, d, start, end)]
            import statistics
            r.update(ping_min=min(pv) if pv else None, ping_median=_median(pv), ping_p95=_quantile(pv, 0.95), ping_max=max(pv) if pv else None,
                     rtt_sd=round(statistics.pstdev(pv), 2) if len(pv) > 1 else None)
        if keys & {"cpu_p95"} or b.get("status") == "load":
            r["cpu_p95"] = _quantile([v for _, v, _ in _metric(c, d, "cpu", start, end)], 0.95)
        if keys & {"mem_p95"} or b.get("status") == "load":
            r["mem_p95"] = _quantile([v for _, v, _ in _metric(c, d, "memory", start, end)], 0.95)
        if keys & {"disk"} or b.get("status") == "load":
            r["disk"] = max((x["used_pct"] for x in _disks(d["id"]) if x["used_pct"] is not None), default=None)
        if "problems" in keys:
            r["problems"] = len(_opened(c, [d], start, end))
        if state:
            r["now"] = state.get(d["id"], ("Unknown",))[0]
        rule = b.get("status") or "availability"
        if rule == "availability":
            r["status"] = _target_status(up, secs or 0, span, target)
        elif rule == "load":
            r["status"] = _load_word(r.get("cpu_p95"), r.get("mem_p95"), r.get("disk"))
        elif rule == "ping":
            r["status"] = "No answer" if r.get("ping_median") is None else "Slow" if r["ping_median"] > ping_t else "Spiky" if (r.get("ping_p95") or 0) > ping_t else "Good"
        else:
            r["status"] = state.get(d["id"], ("Unknown",))[0] if state else "Unknown"
        if "trend" in keys:
            r["trend"] = _spark(c, d, b.get("spark") or "ping", start, end)
        rows.append(r)
    return rows


def _target_status(up: Optional[float], down_s: float, span: int, target: float) -> str:
    if up is None:
        return "No data"
    if up < target:
        return "Breached"
    return "At risk" if down_s > span * (100 - target) / 100 / 2 else "Met"


def _rows_group(c, b, devs, start, end, keys):
    span = end - start
    split = _split({"split": b.get("split") or "auto"}, devs)
    hrs = _hours(c, start, end)
    down = _outages(c, start, end)
    target = _target(b, UPTIME_TARGET)
    rows = []
    import statistics
    for label, members in _cats(devs, split):
        up = _uptime([h for d in members for h in hrs.get(d["id"], [])])
        secs = sum(_down_seconds(down.get(d["id"], []), start, end) for d in members) if up is not None else None
        pv = [v for d in members for _, v, _ in _pings(c, d, start, end)] if keys & {"ping_min", "ping_median", "ping_p95", "ping_max", "rtt_sd"} or b.get("status") == "ping" else []
        r = {"group": label, "devices": len(members), "availability": up, "downtime": secs,
             "outages": sum(1 for d in members for s, _ in down.get(d["id"], []) if s >= start) if up is not None else None,
             "ping_min": min(pv) if pv else None, "ping_median": _median(pv), "ping_p95": _quantile(pv, 0.95), "ping_max": max(pv) if pv else None,
             "rtt_sd": round(statistics.pstdev(pv), 2) if len(pv) > 1 else None, "failed": round(100 - up, 3) if up is not None else None}
        if keys & {"util", "score", "rank"} or b.get("status") == "score":
            sc = _group_score(c, members, start, end)
            r.update(util=sc["util"], score=sc["score"])
        rule = b.get("status") or "availability"
        r["status"] = (_target_status(up, (secs or 0) / max(1, len(members)), span, target) if rule == "availability"
                       else _score_word(r.get("score")) if rule == "score"
                       else "No answer" if r["ping_median"] is None else "Slow" if r["ping_median"] > _target(b, PING_TARGET_MS)
                       else "Spiky" if (r["ping_p95"] or 0) > _target(b, PING_TARGET_MS) else "Good")
        rows.append(r)
    if any(r.get("score") is not None for r in rows):
        for n, r in enumerate(sorted([r for r in rows if r.get("score") is not None], key=lambda r: -r["score"]), start=1):
            r["rank"] = n
    if split == "device":
        b["_first_label"] = "Device"
    return rows


def _rows_interface(c, b, devs, start, end, keys):
    warn, bad, _ = _limits(b, LINK_WARN, LINK_BAD)
    rows = []
    for i in _all_interfaces(c, devs, start, end):
        r = {k: v for k, v in i.items() if not k.startswith("_")}
        r["status"] = "No speed" if i["util"] is None else "Saturated" if i["util"] >= bad else "Busy" if i["util"] >= warn else "OK"
        if "trend" in keys:
            both: Dict[int, float] = {}
            for t, v, _ in i["_in"] + i["_out"]:
                both[t] = max(both.get(t, 0.0), v)
            r["trend"] = [v for _, v in _thin([(t, v, v) for t, v in sorted(both.items())], start, end, 24)]
        rows.append(r)
    return rows


def _hint(t: Dict[str, Any]) -> Tuple[str, str]:
    """A tuning suggestion and a status from simple rules (spec report 7)."""
    share = t["quick"] / t["count"] if t["count"] else 0
    med = _median(t["durations"])
    if t["open"]:
        return "Still open: a real issue, not noise", "Open"
    if t["count"] >= 3 and share >= 0.5 and (med is None or med < 300):
        return "Most clear within minutes: wait longer before alerting (raise its minutes)", "Plan"
    if t["count"] >= 10 and len(t["ids"]) == 1:
        return "One device raises nearly all of these: look at that device or raise its limit", "Investigating"
    if t["count"] >= 10:
        return "Comes up often on several devices: check the limit is right for them", "Investigating"
    return "No change needed", "OK"


def _rows_rule(c, b, devs, start, end, keys):
    rows = []
    for t in _problem_types(c, devs, start, end):
        hint, status = _hint(t)
        rows.append({"problem": t["problem"], "severity": t["severity"], "count": t["count"], "devices": len(t["ids"]),
                     "quick": round(100.0 * t["quick"] / t["count"], 1) if t["count"] else None, "median": _median(t["durations"]),
                     "last": t["last"], "hint": hint, "status": status})
    return rows


def _rows_problem(c, b, devs, start, end, keys):
    names = {d["id"]: d["name"] for d in devs}
    rows = []
    rank = {"critical": "P1", "high": "P1", "warning": "P2"}
    for p in database.list_active_problems():
        if p["device_id"] not in names:
            continue
        rows.append({"priority": rank.get(p["severity"], "P3"), "name": names[p["device_id"]], "problem": p["message"], "since": p["since"],
                     "handled": ("Acknowledged" + (f": {p['ack_note']}" if p.get("ack_note") else "")) if p.get("acknowledged_at") else "Not yet",
                     "status": "Investigating" if p.get("acknowledged_at") else "Open"})
    rows.sort(key=lambda r: (r["priority"], r["since"]))
    return rows


ADVICE = {"Disk": "Free space or add a larger disk", "Memory": "Add memory or move some work elsewhere", "Link": "Plan a faster link or move traffic"}


def _rows_resource(c, b, devs, start, end, keys):
    rows = []
    for r in _resources(c, devs, c.now):
        pri = _priority(r)
        rows.append({"resource": r["resource"], "device": r["device"], "now": _r(r["now"], 1), "limit": r["limit"],
                     "growth": f"{r['growth']:+.1f} points" if r["growth"] is not None else "Not known yet", "days": _days_text(r),
                     "advice": ADVICE.get(r["kind"], "Keep an eye on it") if pri != "P3" else "Monitor", "status": pri,
                     "_order": (0 if r["state"] == "passed" else 1, r["days"] if r["days"] is not None else 1e9, -(r["now"] or 0))})
    rows.sort(key=lambda r: r["_order"])
    return rows


def _rows_outage(c, b, devs, start, end, keys):
    down = _outages(c, start, end)
    rows = []
    for d in devs:
        for s, e in down.get(d["id"], []):
            rows.append({"name": d["name"], "group": _gname(d), "started": s, "ended": e, "duration": (e or c.now) - s,
                         "status": "Resolved" if e else "Still down"})
    return rows


def _rows_event(c, b, devs, start, end, keys):
    names = {d["id"]: d["name"] for d in devs}
    return [{"time": e["timestamp"], "name": names.get(e["device_id"], ""), "severity": _sev(e["severity"]),
             "type": str(e["event_type"]).replace("_", " ").capitalize(), "message": e["message"]} for e in _all_events(c, devs, start, end)]


TABLE_ROWS = {"device": _rows_device, "group": _rows_group, "interface": _rows_interface, "rule": _rows_rule,
              "problem": _rows_problem, "resource": _rows_resource, "outage": _rows_outage, "event": _rows_event}
TABLE_EMPTY = {"device": "No devices to show.", "group": "No groups to show.", "interface": "No interface traffic was recorded.",
               "rule": "No problems opened in the period.", "problem": "No problems are open. Nothing to hand over here.",
               "resource": "No resource has a daily history yet.", "outage": "No device went down in the period.",
               "event": "Nothing happened in the period."}


# Written from the data ----------------------------------------------------------------------------------

def _auto_sla(c, devs, s, e, period):
    hrs = _hours(c, s, e)
    up = _uptime([h for d in devs for h in hrs.get(d["id"], [])])
    if up is None:
        return f"There are no checks recorded for {PERIOD_NAMES[period]} yet."
    down = _outages(c, s, e)
    worst = sorted(((_down_seconds(down.get(d["id"], []), s, e), d["name"]) for d in devs), reverse=True)
    worst = [w for w in worst if w[0] > 0]
    parts = [f"All devices together were reachable {_pct_text(up)} of the time over {PERIOD_NAMES[period]}, "
             f"{'meeting' if up >= UPTIME_TARGET else 'short of'} the {UPTIME_TARGET:g}% target. Planned maintenance is left out."]
    parts.append("No device went down." if not worst else
                 f"Most time down: {_and([f'{n} ({_minutes(x)})' for x, n in worst[:3]])}.")
    return " ".join(parts)


def _auto_latency(c, devs, s, e, period):
    vals = [v for d in devs for _, v, _ in _pings(c, d, s, e)]
    if not vals:
        return f"No ping answers were recorded for {PERIOD_NAMES[period]}."
    med, p95 = _median(vals), _quantile(vals, 0.95)
    hrs = _hours(c, s, e)
    up = _uptime([h for d in devs for h in hrs.get(d["id"], [])])
    parts = [f"Half of all ping answers came within {_ms(med)} and 95% within {_ms(p95)} over {PERIOD_NAMES[period]}."]
    if up is not None:
        parts.append(f"Of all checks, {f'{100 - up:.3f}%' if 100 - up < 0.1 else _pct_text(100 - up)} got no answer.")
        parts.append("The monitor sends one ping per check, so this counts failed checks, not packet loss; "
                     "the spread is shown as the standard deviation of the answers, not jitter.")
    return " ".join(parts)


def _auto_capacity(c, devs, s, e, period):
    rows = _resources(c, devs, c.now)
    if not rows:
        return "No disk, memory or link has a daily history yet, so there is nothing to forecast."
    soon = [r for r in rows if _priority(r) == "P1"]
    plan = [r for r in rows if _priority(r) == "P2"]
    parts = [f"The monitor tracks {_plural(len(rows), 'resource')}."]
    if soon:
        parts.append(f"Act now: {_and([r['device'] + ' ' + r['resource'] for r in soon[:3]])}.")
    if plan:
        parts.append(f"Plan for this quarter: {_and([r['device'] + ' ' + r['resource'] for r in plan[:3]])}.")
    if not soon and not plan:
        parts.append("Nothing is expected to reach its limit within 90 days.")
    return " ".join(parts)


def _auto_method(c, devs, s, e, period):
    return (f"One value per day: the daily peak (the highest hourly average of the day; for links the larger of in and out against the link speed). "
            f"A straight line is fitted to up to 90 days of these by least squares; days left are when that line reaches the limit. "
            f"A forecast needs {FORECAST_MIN_DAYS} days of history and is marked as early under {FORECAST_GOOD_DAYS}. "
            "The cone is about 90% confidence from how far the days sit from the line, widening into the future. "
            "Seasons and one-off steps (an upgrade, a clean-up) are not modelled: after one, the line takes a while to catch up.")


def _auto_alerts(c, devs, s, e, period):
    types = _problem_types(c, devs, s, e)
    total = sum(t["count"] for t in types)
    if not total:
        return f"It was quiet: no problems opened over {PERIOD_NAMES[period]}."
    quick = sum(t["quick"] for t in types)
    top = types[0]
    parts = [f"The monitor opened {_plural(total, 'problem')} over {PERIOD_NAMES[period]}, of {_plural(len(types), 'kind')}."]
    parts.append(f"Seen most often, {_plural(top['count'], 'time')}: {top['problem']}.")
    if quick:
        parts.append(f"{_count(quick, 'problem')} cleared within 5 minutes without anyone acknowledging {'it' if quick == 1 else 'them'}: likely noise worth tuning.")
    return " ".join(parts)


def _auto_outage(c, devs, s, e, period):
    f = c.focus_info
    if not f:
        return f"No device went down over {PERIOD_NAMES[period]}, so there is no outage to review."
    parts = [f"The device {f['device']} went down {_date(f['started'])} and " + (f"came back after {_minutes(f['seconds'])}." if f.get("ended") else f"is still down after {_minutes(f['seconds'])}.")]
    others = _k_affected(c, devs, s, e, {})["v"] or 0
    if others > 1:
        parts.append(f"{_count(others, 'device')} went down in the window shown.")
    if f.get("detected") is not None:
        parts.append(f"The monitor raised a problem {_minutes(f['detected'])} after the first failed check.")
    return " ".join(parts)


def _auto_groups(c, devs, s, e, period):
    sc = [(l, x["score"]) for l, x in _scores(c, devs, s, e) if x["score"] is not None]
    if not sc:
        return "There is not enough data yet to compare the groups."
    best, worst = max(sc, key=lambda p: p[1]), min(sc, key=lambda p: p[1])
    who = "groups" if len({_gname(d) for d in devs}) > 1 else "devices (there is one group, so devices are compared)"
    return (f"Of {len(sc)} {who}, {best[0]} scored best ({best[1]:.0f} of 100) and {worst[0]} lowest ({worst[1]:.0f}). "
            "The score weighs availability, ping, failed checks and the headroom on the busiest link; the weights are under the ranking.")


def _auto_handover(c, devs, s, e, period):
    state = _now_words(c)
    down = [d["name"] for d in devs if state.get(d["id"], ("",))[0] == "Down"]
    probs = _open_now(devs)
    parts = [f"Of {_plural(len(devs), 'device')}, {sum(1 for d in devs if state.get(d['id'], ('',))[0] == 'Up')} {'is' if len(devs) == 1 else 'are'} up with nothing to report."]
    parts.append(f"Down right now: {_and(down[:5])}." if down else "Nothing is down.")
    parts.append(f"{_count(len(probs), 'problem')} {'is' if len(probs) == 1 else 'are'} open." if probs else "No problems are open.")
    return " ".join(parts)


def _auto_device(c, devs, s, e, period):
    if not devs:
        return "There is no device to report on."
    d = sorted(devs, key=lambda x: str(x["name"]).lower())[0]
    hrs = _hours(c, s, e)
    up = _uptime(hrs.get(d["id"], []))
    secs = _down_seconds(_outages(c, s, e).get(d["id"], []), s, e)
    parts = [f"The device {d['name']} was reachable {_pct_text(up)} of the time over {PERIOD_NAMES[period]}"
             + (f" and was down for {_minutes(secs)}." if secs else " without going down.") if up is not None
             else f"There are no checks of {d['name']} recorded for {PERIOD_NAMES[period]}."]
    cpu = _quantile([v for _, v, _ in _metric(c, d, "cpu", s, e)], 0.95)
    mem = _quantile([v for _, v, _ in _metric(c, d, "memory", s, e)], 0.95)
    if cpu is not None or mem is not None:
        parts.append(f"The processor stayed at or below {_pct_text(cpu)} and memory at or below {_pct_text(mem)} 95% of the time.")
    med = _median([v for _, v, _ in _pings(c, d, s, e)])
    if med is not None:
        parts.append(f"It answered ping in {_ms(med)} typically.")
    probs = len(_opened(c, [d], s, e))
    parts.append(f"{_count(probs, 'problem')} opened in the period." if probs else "No problem opened in the period.")
    return " ".join(parts)


AUTO_TEXTS = {"device": ("The device in brief", _auto_device), "sla": ("Availability against the target", _auto_sla), "latency": ("Ping and failed checks", _auto_latency),
              "capacity": ("What fills up", _auto_capacity), "method": ("How the forecast works", _auto_method),
              "alerts": ("What the monitor raised", _auto_alerts), "outage": ("The outage in brief", _auto_outage),
              "groups": ("How the groups compare", _auto_groups), "handover": ("Where things stand", _auto_handover)}

# Fields of the device details panel.
KV_FIELDS = ["name", "model", "ip", "group", "tags", "location", "firmware", "snmp", "uptime", "interfaces", "last_seen"]


# The templates as block lists ----------------------------------------------------------------------------

def _P(tid: str, part: str) -> Dict[str, Any]:
    return {"type": "part", "template": tid, "part": part}


def _two(left: Optional[Dict[str, Any]], right: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"type": "two_column", "left": left, "right": right}


def _C(source: str, view: str, chart: str, **kw: Any) -> Dict[str, Any]:
    return dict({"type": "chart", "source": source, "view": view, "chart": chart}, **kw)


def _K(*tiles: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "kpi_row", "tiles": list(tiles)}


def _tl(metric: str, **kw: Any) -> Dict[str, Any]:
    return dict({"metric": metric}, **kw)


def _T(entity: str, title: str, **kw: Any) -> Dict[str, Any]:
    return dict({"type": "table", "entity": entity, "title": title}, **kw)


def _X(title: str, text: str = "", auto: str = "") -> Dict[str, Any]:
    return {"type": "text", "title": title, "text": text, "auto": auto}


NOT_WRITTEN = "Not written yet. Use Start from this template, write it here and save the report: the words are kept with it."

# The first templates' parts, named for the builder (the charts' titles change with the data).
CLASSIC_PARTS: Dict[str, Tuple[List[str], List[str]]] = {
    "monthly": (["Devices now", "Problems opened per day"], []),
    "status": (["Devices now", "Busiest processors now"], ["Watch list"]),
    "availability": (["Most time down", "Outages per day"], []),
    "latency": (["Slowest devices", "Typical ping by hour of day"], []),
    "bandwidth": (["Busiest interfaces", "When the link is busiest", "How full the links run"], []),
    "alerts": (["Noisiest devices", "Events by hour of day", "Most common problems (chart)"], ["Most common problems"]),
    "device": (["Ping", "Uptime by day", "Storage (chart)", "Traffic on the busiest interface"], ["Storage", "Problems in the period"]),
    "health": (["Memory use (storage for one device)", "Fullest disks"], []),
    "storage": (["Days until full", "Storage by state"], []),
    "problems": (["Problems per device", "Most common problems"], []),
    "events": (["Events by type", "Events by hour of day"], []),
    "devices": (["Devices per template", "Devices per group"], []),
    "wifi": (["Devices per band", "Devices per network"], []),
    "proxmox": (["Memory used by guest"], []),
    "pihole": (["Queries per Pi-hole"], []),
    "new_devices": (["By maker", "Where they were seen"], []),
    "updates": ([], []),
}
CLASSIC_LAYOUT = {"bandwidth": [(1, 0), (2, None)]}


def _classic_blocks(tid: str) -> List[Dict[str, Any]]:
    charts, tables = CLASSIC_PARTS[tid]
    out = [_P(tid, "kpis"), _P(tid, "summary"), _P(tid, "main")]
    pairs = CLASSIC_LAYOUT.get(tid) or [(i, i + 1 if i + 1 < len(charts) else None) for i in range(0, len(charts), 2)]
    for a, b in pairs:
        out.append(_two(_P(tid, f"chart.{a}"), _P(tid, f"chart.{b}")) if b is not None else _P(tid, f"chart.{a}"))
    out.append(_P(tid, "table"))
    out += [_P(tid, f"tables.{i}") for i in range(len(tables))]
    return out


def _part_names(tid: str) -> Dict[str, str]:
    charts, tables = CLASSIC_PARTS[tid]
    out = {"kpis": "Key figures", "summary": "Summary", "main": "Main chart", "table": TEMPLATES[tid].get("table_title", "Table")}
    out.update({f"chart.{i}": n for i, n in enumerate(charts)})
    out.update({f"tables.{i}": n for i, n in enumerate(tables)})
    return out


NEW_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "handover": {
        "title": "Shift handover",
        "description": "Everything the next person on duty needs on one page: what is up or down, the open problems, what to watch and notes.",
        "purpose": "Where things stand right now and what to keep an eye on, for whoever takes over.",
        "sources": "ping and service checks, SNMP, the open problems and the map",
        "period": True, "default_period": "24h", "all_devices": False,
        "blocks": [
            _K(_tl("devices_up"), _tl("devices_warn"), _tl("devices_down"), _tl("open_problems"),
               _tl("problems", label="Problems", compare="previous"), _tl("maintenance")),
            _X("Summary", auto="handover"),
            _two(_C("status", "now", "grid", title="Every device now"), _C("topology", "map", "topology", title="Core of the network")),
            _T("problem", "Open problems", note="Priority from the severity: critical and high P1, warning P2, the rest P3. Acknowledged counts as being looked at."),
            _two(_C("cpu", "watch", "sparktable", title="Watch list (processor)"), _X("Handover notes", NOT_WRITTEN)),
        ]},
    "group_compare": {
        "title": "Group comparison",
        "description": "Groups ranked on availability, ping, failed checks and link headroom, with peak traffic, before and after and how hard the links work.",
        "purpose": "How the groups compare, to decide where an upgrade or a closer look pays off most.",
        "sources": "ping and service checks and SNMP interface counters",
        "period": True, "default_period": "30d", "all_devices": False,
        "blocks": [
            _K(_tl("best_group"), _tl("worst_group"), _tl("groups"), _tl("avg_score", compare="previous")),
            _X("Summary", auto="groups"),
            _two(_C("traffic", "pair", "grouped", split="group", title="Peak traffic in and out"),
                 _C("ping", "previous", "dumbbell", split="auto", title="Ping, this period and the one before")),
            _two(_C("ping", "distribution", "box", split="auto", title="Ping spread per group (in place of jitter)"),
                 _C("traffic", "bands", "stack100", split="auto", title="How hard the interfaces work")),
            _T("group", "Group ranking", columns=["rank", "group", "devices", "availability", "ping_median", "failed", "util", "score", "status"],
               status="score", sort={"column": "score", "desc": True}, note=SCORE_TEXT),
        ]},
    "sla": {
        "title": "Availability and SLA",
        "description": "Proof of the availability target: uptime per group day by day, a calendar, the worst week's outages with maintenance, and the least available devices.",
        "purpose": "Whether the availability target was met, group by group, and which devices were the least reliable.",
        "sources": "ping and service checks and the maintenance windows",
        "period": True, "default_period": "90d", "all_devices": False,
        "blocks": [
            _K(_tl("availability", label="Overall availability", compare="target"), _tl("downtime"),
               _tl("groups_below", label="Groups below the target"), _tl("outages", label="Outages", compare="previous")),
            _X("Summary", auto="sla"),
            _C("availability", "days", "strips", split="auto", title="Uptime, one bar per day"),
            _two(_C("availability", "days", "calendar"), _C("downtime", "worst_week", "gantt")),
            _T("device", "Least available devices", columns=["name", "group", "tags", "availability", "downtime", "outages", "status"],
               status="availability", sort={"column": "availability", "desc": False}, limit=10, note="Planned maintenance is left out."),
        ]},
    "outage": {
        "title": "Outage review",
        "description": "One outage looked at closely: a timeline from the event log, devices answering, traffic against the usual, and room for the cause and impact.",
        "purpose": "What happened during an outage, how long it lasted and what it affected, with your notes on the cause.",
        "sources": "the checks, the event log and SNMP", "focus": "outage",
        "period": True, "default_period": "7d", "all_devices": False,
        "blocks": [
            _K(_tl("outage_duration"), _tl("affected"), _tl("problems", label="Problems raised", compare="none"), _tl("peak_down")),
            _X("Summary", auto="outage"),
            _C("timeline", "events", "timeline"),
            _two(_C("traffic", "baseline", "baseline"), _C("reachable", "time", "step")),
            _two(_X("Root cause", NOT_WRITTEN), _X("Impact", NOT_WRITTEN)),
            _T("outage", "Outages in the window", columns=["name", "group", "started", "ended", "duration", "status"]),
            _X("Actions", NOT_WRITTEN),
        ]},
    "latency_review": {
        "title": "Latency and failed checks",
        "description": "Ping quality per group against a 50 ms target: median and spread over time, box plots, distance from the target, failed checks and cumulative curves.",
        "purpose": "How quick and steady the answers are per group, for a review of the network or a talk with the internet provider.",
        "sources": "ping and service checks",
        "period": True, "default_period": "7d", "all_devices": False,
        "blocks": [
            _K(_tl("ping", agg="median", label="Median ping"), _tl("ping", agg="p95", label="95th percentile"),
               _tl("failed", compare="target", label="Failed checks"), _tl("rtt_sd", compare="none"), _tl("over_ping")),
            _X("Summary", auto="latency"),
            _C("ping", "band", "band"),
            _two(_C("ping", "distribution", "box", split="auto"), _C("ping", "per", "diverging", split="auto")),
            _two(_C("failed", "per", "lollipop", split="auto"), _C("ping", "distribution", "cdf", split="auto", top=3)),
            _T("group", "Per group", columns=["group", "devices", "ping_min", "ping_median", "ping_p95", "ping_max", "rtt_sd", "failed", "status"],
               status="ping", sort={"column": "ping_median", "desc": True},
               note="RTT std dev in place of jitter and failed checks in place of packet loss: the monitor sends one ping per check."),
        ]},
    "capacity": {
        "title": "Capacity planning forecast",
        "description": "Disks, memory and links with a trend on their daily peaks: the most urgent forecast, current use, processor against memory and when each fills up.",
        "purpose": "Which resources will run out and roughly when, so the work and the money can be planned.",
        "sources": "SNMP and the hourly history",
        "period": True, "default_period": "90d", "all_devices": False,
        "blocks": [
            _K(_tl("resources"), _tl("full_30"), _tl("full_90"), _tl("growth")),
            _X("Summary", auto="capacity"),
            _C("capacity", "forecast", "forecast"),
            _two(_C("capacity", "now", "capacity"), _C("cpu_mem", "scatter", "scatter")),
            _T("resource", "Resources needing attention", limit=20, note="P1: past the limit or within 30 days. P2: within 90 days. P3: keep monitoring."),
            _X("Method notes", auto="method"),
        ]},
    "alert_week": {
        "title": "Weekly alert and event summary",
        "description": "What the monitor raised and what was noise: problems per day by severity, the few types behind most of them, busy hours, noisy devices and tuning hints.",
        "purpose": "What the monitoring raised, how quickly it was handled and which alerts are noise worth tuning.",
        "sources": "the problem log and the event log",
        "period": True, "default_period": "7d", "all_devices": False,
        "blocks": [
            _K(_tl("problems", label="Problems raised"), _tl("critical", label="Critical or high"), _tl("quick", compare="none"),
               _tl("mtta", compare="none"), _tl("unacked")),
            _X("Summary", auto="alerts"),
            _two(_C("problems", "time", "stacked"), _C("problems", "per", "pareto", split="rule")),
            _two(_C("problems", "hour", "clock"), _C("problems", "noisy", "sparktable")),
            _T("rule", "Top problem types and tuning hints",
               note="Cleared within 5 minutes: closed by itself without anyone acknowledging it. Hints come from simple rules."),
        ]},
    "deep_dive": {
        "title": "Device deep dive",
        "description": "One device on one page: its details, gauges now, processor against its limits, uplink traffic, a health profile and its key interfaces.",
        "purpose": "Everything about one device over the period.",
        "sources": "ping, SNMP and the problem log", "one_device": True,
        "period": True, "default_period": "7d", "all_devices": False,
        "blocks": [
            _two({"type": "key_value", "title": "Device details"}, _C("health", "now", "gauge")),
            _X("Summary", auto="device"),
            _C("cpu", "time", "threshold", agg="avg", title="Processor over the period"),
            _two(_C("traffic", "inout", "mirror"), _C("health", "profile", "radar")),
            _C("utilisation", "watch", "sparktable", title="Key interfaces"),
            _T("interface", "Interfaces", columns=["interface", "description", "speed", "in_p95", "out_p95", "util", "status"]),
        ]},
}

TEMPLATE_GROUPS: List[Dict[str, Any]] = [
    {"id": "overview", "title": "Overview", "about": "The big picture on a page.", "templates": ["monthly", "status", "handover", "group_compare"]},
    {"id": "availability", "title": "Availability", "about": "Whether devices were reachable against a target, and what went down.",
     "templates": ["sla", "availability", "outage"]},
    {"id": "performance", "title": "Performance and latency", "about": "How quickly devices answer and how hard they work.",
     "templates": ["latency_review", "latency", "health"]},
    {"id": "capacity", "title": "Capacity", "about": "What is filling up and when it runs out.", "templates": ["capacity", "storage", "bandwidth"]},
    {"id": "alerts", "title": "Alerts and events", "about": "What the monitor raised, and what was noise.", "templates": ["alert_week", "alerts", "problems", "events"]},
    {"id": "devices", "title": "Devices", "about": "One device in depth, or every device and how it is read.", "templates": ["deep_dive", "device", "devices"]},
    {"id": "network", "title": "Network and integrations", "about": "Wi-Fi, Proxmox, Pi-hole, new devices and the monitor itself.",
     "templates": ["wifi", "proxmox", "pihole", "new_devices", "updates"]},
]

AUDIENCE = {"monthly": "Management and anyone who wants the short version", "status": "Whoever is on duty", "handover": "The next person on duty",
            "group_compare": "Whoever plans upgrades", "sla": "Service owners and anyone promised a target", "availability": "Whoever looks after the devices",
            "outage": "Whoever reviews what went wrong", "latency_review": "Whoever reviews the network or talks to the provider",
            "latency": "Whoever looks after the network", "health": "Whoever looks after the devices", "capacity": "Whoever plans and budgets",
            "storage": "Whoever looks after storage", "bandwidth": "Whoever looks after the network", "alert_week": "Whoever handles the alerts",
            "alerts": "Whoever handles the alerts", "problems": "Whoever handles the alerts", "events": "Whoever handles the alerts",
            "deep_dive": "Network engineers", "device": "Network engineers", "devices": "The administrator", "wifi": "The administrator",
            "proxmox": "The administrator", "pihole": "The administrator", "new_devices": "The administrator", "updates": "The administrator"}

for _tid, _t in NEW_TEMPLATES.items():
    TEMPLATES[_tid] = _t
for _tid, _t in TEMPLATES.items():
    if "blocks" not in _t:
        _t["blocks"] = _classic_blocks(_tid)
        _t["classic"] = True
    else:
        # The customizer's columns come from the template's first table.
        _first = next((b for b in _t["blocks"] if b["type"] == "table"), None)
        _cols = _table_columns(_first["entity"]) if _first else []
        _t.update(columns=_cols, default=list(_first.get("columns") or TABLES[_first["entity"]]["default"]) if _first else [],
                  sort=(_first.get("sort") or {}).get("column", TABLES[_first["entity"]]["sort"]) if _first else "",
                  desc=bool((_first.get("sort") or {}).get("desc", TABLES[_first["entity"]]["desc"])) if _first else False,
                  table_title=_first["title"] if _first else "")
    _t["audience"] = AUDIENCE.get(_tid, "")
    _t["group"] = next(g["id"] for g in TEMPLATE_GROUPS if _tid in g["templates"])
TEMPLATE_ORDER = [tid for g in TEMPLATE_GROUPS for tid in g["templates"]]

# "What do you want to know?" (spec section 10): suggested templates and charts.
QUESTIONS: List[Dict[str, Any]] = [
    {"id": "change", "text": "How has something changed over time?", "templates": ["deep_dive", "health", "latency"],
     "charts": [("cpu", "time", "threshold"), ("ping", "time", "line"), ("availability", "time", "columns"), ("cpu", "now", "headline")]},
    {"id": "balance", "text": "Is traffic balanced in and out?", "templates": ["bandwidth", "group_compare"],
     "charts": [("traffic", "inout", "mirror"), ("traffic", "pair", "grouped"), ("traffic", "pair", "butterfly")]},
    {"id": "broken", "text": "Is anything broken right now?", "templates": ["status", "handover"],
     "charts": [("status", "now", "grid"), ("status", "now", "donut"), ("cpu", "watch", "sparktable"), ("topology", "map", "topology")]},
    {"id": "target", "text": "Are we meeting our availability target?", "templates": ["sla", "availability", "monthly"],
     "charts": [("availability", "per", "bullet"), ("ping", "per", "diverging"), ("availability", "budget", "waterfall"),
                ("availability", "days", "strips"), ("availability", "days", "calendar")]},
    {"id": "capacity", "text": "When will we run out of room?", "templates": ["capacity", "storage", "bandwidth"],
     "charts": [("capacity", "forecast", "forecast"), ("capacity", "now", "capacity"), ("traffic", "bands", "stack100")]},
    {"id": "worst", "text": "Which are the busiest or the worst?", "templates": ["bandwidth", "alert_week", "capacity"],
     "charts": [("traffic", "per", "bar"), ("problems", "per", "pareto"), ("cpu_mem", "scatter", "scatter")]},
    {"id": "steady", "text": "How steady is the ping?", "templates": ["latency_review", "latency"],
     "charts": [("ping", "band", "band"), ("ping", "distribution", "histogram"), ("ping", "distribution", "box"), ("ping", "distribution", "cdf")]},
    {"id": "when", "text": "When during the week is it busy?", "templates": ["bandwidth", "alert_week"],
     "charts": [("traffic", "hour_week", "heatmap"), ("problems", "hour", "clock"), ("traffic", "hour_week", "clock")]},
    {"id": "outage", "text": "What happened during an outage?", "templates": ["outage", "sla"],
     "charts": [("traffic", "baseline", "baseline"), ("reachable", "time", "step"), ("downtime", "timeline", "gantt"), ("timeline", "events", "timeline")]},
    {"id": "compare", "text": "How do the groups compare overall?", "templates": ["group_compare", "latency_review"],
     "charts": [("health", "profile", "radar"), ("ping", "previous", "dumbbell"), ("ping", "distribution", "box")]},
    {"id": "where", "text": "Where does the traffic go?", "templates": ["bandwidth"],
     "charts": [("traffic", "per", "treemap"), ("traffic", "pair", "grouped")],
     "gap": "Who talks to whom needs flow records, which the monitor does not collect: these show traffic per interface, device or group instead."},
    {"id": "noise", "text": "Which alerts make the most noise?", "templates": ["alert_week", "alerts", "problems"],
     "charts": [("problems", "per", "pareto"), ("problems", "time", "stacked")]},
]


def catalog(all_devices: bool) -> Dict[str, Any]:
    """What the builder may offer, for the Reports page: sources and their views (with the chart
    types that suit each view's shape), key figures, tables, written texts and the questions."""
    sources = []
    for sid, s in SOURCES.items():
        views = [{"id": vid, "label": v["label"], "shape": v["shape"], "charts": v["charts"], "aggs": v["aggs"], "splits": v["splits"],
                  "top": v["top"], "limits": v["limits"], "one": v["one"]}
                 for vid, v in s["views"].items() if all_devices or not v["all_devices"]]
        if views:
            sources.append({"id": sid, "label": s["label"], "about": s["about"], "views": views})
    return {"sources": sources,
            "charts": {k: {"n": v["n"], "label": v["label"], "shape": CHART_SHAPES.get(k, "")} for k, v in CHARTS.items()},
            "shapes": SHAPES, "aggs": {k: v[0] for k, v in AGGS.items()}, "splits": SPLITS,
            "kpis": [{"id": k, "label": m["label"], "aggs": m.get("aggs") or [], "better": m["better"], "now": bool(m.get("now")),
                      "target": m.get("target")} for k, m in KPI_METRICS.items()],
            "tables": [{"id": k, "label": t["label"], "columns": [{"key": a, "label": b, "type": ty} for a, b, ty in _table_columns(k)],
                        "default": t["default"], "status": t["status"], "sparks": t["sparks"], "sort": t["sort"], "desc": t["desc"]}
                       for k, t in TABLES.items()],
            "auto": {k: v[0] for k, v in AUTO_TEXTS.items()},
            "kv_fields": KV_FIELDS,
            "questions": [{"id": q["id"], "text": q["text"], "templates": q["templates"], "gap": q.get("gap", ""),
                           "charts": [{"source": s, "view": v, "chart": ch} for s, v, ch in q["charts"]
                                      if all_devices or not SOURCES[s]["views"][v]["all_devices"]]} for q in QUESTIONS],
            "groups": [{"id": g["id"], "title": g["title"], "about": g["about"]} for g in TEMPLATE_GROUPS],
            "limits": {"blocks": MAX_BLOCKS, "text": MAX_TEXT, "tiles": MAX_TILES, "top": MAX_TOP, "columns": MAX_COLUMNS, "rows": MAX_TABLE_ROWS}}


def template_list(all_devices: bool) -> List[Dict[str, Any]]:
    """The templates this user can run, in their groups, for the Reports page. Network-wide ones need every device."""
    out = []
    for tid in TEMPLATE_ORDER:
        t = TEMPLATES[tid]
        if t["all_devices"] and not all_devices:
            continue
        out.append({"id": tid, "title": t["title"], "description": t["description"], "period": t["period"],
                    "default_period": t.get("default_period", "7d"), "one_device": bool(t.get("one_device")),
                    "group": t["group"], "audience": t["audience"], "focus": t.get("focus", ""),
                    "columns": [{"key": k, "label": l, "type": ty} for k, l, ty in t["columns"]],
                    "default": t["default"], "sort": t["sort"], "desc": bool(t.get("desc")),
                    "blocks": t["blocks"], "parts": _part_names(tid) if t.get("classic") else {}})
    return out


# Checking a definition ---------------------------------------------------------------------------------
# Whatever the browser sends is read here into a fresh structure: only known names survive, numbers
# are bounded, texts are cut to length. Device ids are only ever compared with the devices the server
# already allows the user; nothing here reaches a query or a path.

def _text(v: Any, n: int, lines: bool = False) -> str:
    s = str(v or "")
    if lines:
        s = "\n".join(" ".join(line.split()) for line in s.replace("\r\n", "\n").split("\n"))
        s = re.sub(r"\n{3,}", "\n\n", s).strip()
    else:
        s = " ".join(s.split())
    return s[:n]


def _num(v: Any, lo: float = -1e12, hi: float = 1e12) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not lo <= v <= hi:
        return None
    return float(v)


def _int(v: Any, lo: int, hi: int) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None


def _parse_scope(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("kind") not in ("group", "tag", "devices"):
        return {"kind": "all"}
    if raw["kind"] == "devices":
        ids = [i for i in (raw.get("devices") or []) if _int(i, 1, 2 ** 31) is not None] if isinstance(raw.get("devices"), list) else []
        ids = list(dict.fromkeys(ids))[:MAX_SCOPE_DEVICES]
        return {"kind": "devices", "devices": ids} if ids else {"kind": "all"}
    value = _text(raw.get(raw["kind"]), 64)
    return {"kind": raw["kind"], raw["kind"]: value} if value else {"kind": "all"}


def _parse_threshold(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("mode") != "override":
        return {"mode": "inherit"}
    out: Dict[str, Any] = {"mode": "override"}
    for k in ("warn", "bad", "target"):
        v = _num(raw.get(k))
        if v is not None:
            out[k] = v
    return out


def _parse_block(raw: Any, all_devices: bool, depth: int = 0) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("type") not in BLOCK_TYPES:
        raise ReportError("A block has a type this report builder does not know")
    kind = raw["type"]
    b: Dict[str, Any] = {"type": kind}
    if kind != "two_column":
        b["title"] = _text(raw.get("title"), 120)
        b["note"] = _text(raw.get("note"), 300)
    if kind == "two_column":
        if depth:
            raise ReportError("A side by side row cannot hold another one")
        for side in ("left", "right"):
            child = raw.get(side)
            if child is None:
                b[side] = None
                continue
            if not isinstance(child, dict) or child.get("type") not in SIDE_TYPES + ("part",) or (
                    child.get("type") == "part" and str(child.get("part")).startswith("table")):
                raise ReportError("A side by side row holds charts, text or device details")
            b[side] = _parse_block(child, all_devices, depth + 1)
        if not b["left"] and not b["right"]:
            raise ReportError("A side by side row needs something on at least one side")
        return b
    if kind == "chart":
        src = SOURCES.get(raw.get("source"))
        if not src:
            raise ReportError("A chart's data source is not one the builder offers")
        view = src["views"].get(raw.get("view"))
        if not view:
            raise ReportError(f"{src['label']} cannot be shown that way")
        if view["all_devices"] and not all_devices:
            raise ReportError(f"{src['label']} covers the whole network and needs access to every device")
        if raw.get("chart") not in view["charts"]:
            raise ReportError(f"That chart does not suit {src['label'].lower()} {view['label'].lower()}")
        b.update(source=raw["source"], view=raw["view"], chart=raw["chart"])
        if view["aggs"]:
            b["agg"] = raw.get("agg") if raw.get("agg") in view["aggs"] else view["aggs"][0]
        if view["splits"]:
            b["split"] = raw.get("split") if raw.get("split") in view["splits"] else view["splits"][0]
        if view["top"]:
            b["top"] = _int(raw.get("top"), 1, MAX_TOP) or view["top"]
        b["scope"] = _parse_scope(raw.get("scope"))
        b["period"] = raw.get("period") if raw.get("period") in PERIODS else ""
        b["threshold"] = _parse_threshold(raw.get("threshold")) if view["limits"] else {"mode": "inherit"}
        return b
    if kind == "kpi_row":
        tiles = raw.get("tiles")
        if not isinstance(tiles, list) or not tiles:
            raise ReportError("Key figures need at least one tile")
        if len(tiles) > MAX_TILES:
            raise ReportError(f"Key figures hold at most {MAX_TILES} tiles")
        b["tiles"] = []
        for t in tiles:
            if not isinstance(t, dict) or t.get("metric") not in KPI_METRICS:
                raise ReportError("A key figure names a figure the builder does not know")
            m = KPI_METRICS[t["metric"]]
            tile = {"metric": t["metric"], "label": _text(t.get("label"), 40),
                    "compare": t.get("compare") if t.get("compare") in ("previous", "target", "none") else ("none" if m.get("now") else "previous"),
                    "better": t.get("better") if t.get("better") in ("up", "down") else m["better"]}
            if m.get("aggs"):
                tile["agg"] = t.get("agg") if t.get("agg") in m["aggs"] else m["aggs"][0]
            target = _num(t.get("target"))
            if target is not None:
                tile["target"] = target
            b["tiles"].append(tile)
        b["scope"] = _parse_scope(raw.get("scope"))
        b["period"] = raw.get("period") if raw.get("period") in PERIODS else ""
        return b
    if kind == "table":
        ent = TABLES.get(raw.get("entity"))
        if not ent:
            raise ReportError("A table lists something the builder does not know")
        keys = [k for k, _, _ in _table_columns(raw["entity"])]
        cols = raw.get("columns") if isinstance(raw.get("columns"), list) else []
        cols = list(dict.fromkeys(k for k in cols if k in keys))[:MAX_COLUMNS] or list(ent["default"])
        sort = raw.get("sort") if isinstance(raw.get("sort"), dict) else {}
        b.update(entity=raw["entity"], columns=cols,
                 status=raw.get("status") if raw.get("status") in ent["status"] else next(iter(ent["status"]), ""),
                 spark=raw.get("spark") if raw.get("spark") in ent["sparks"] else next(iter(ent["sparks"]), ""),
                 sort={"column": sort.get("column") if sort.get("column") in keys else ent["sort"],
                       "desc": bool(sort["desc"]) if "desc" in sort else ent["desc"]},
                 limit=_int(raw.get("limit"), 1, MAX_TABLE_ROWS) or 0,
                 split=raw.get("split") if raw.get("split") in ("auto", "group", "device") else "auto",
                 scope=_parse_scope(raw.get("scope")), period=raw.get("period") if raw.get("period") in PERIODS else "",
                 threshold=_parse_threshold(raw.get("threshold")))
        return b
    if kind == "text":
        b["text"] = _text(raw.get("text"), MAX_TEXT, lines=True)
        b["auto"] = raw.get("auto") if raw.get("auto") in AUTO_TEXTS else ""
        if not b["text"] and not b["auto"] and not b["title"]:
            raise ReportError("A text block needs a title or some words")
        return b
    if kind == "key_value":
        fields = raw.get("fields") if isinstance(raw.get("fields"), list) else []
        b["fields"] = [f for f in dict.fromkeys(fields) if f in KV_FIELDS] or list(KV_FIELDS)
        b["scope"] = _parse_scope(raw.get("scope"))
        return b
    tid, part = raw.get("template"), raw.get("part")
    t = TEMPLATES.get(tid)
    if not t or not t.get("classic") or part not in _part_names(tid):
        raise ReportError("A ready-made block names a template part that does not exist")
    if t["all_devices"] and not all_devices:
        raise ReportError("That ready-made block needs access to every device")
    b.update(template=tid, part=part)
    if part == "table":
        keys = [c[0] for c in t["columns"]]
        cols = raw.get("columns") if isinstance(raw.get("columns"), list) else []
        b["columns"] = list(dict.fromkeys(k for k in cols if k in keys)) or list(t["default"])
        sort = raw.get("sort") if isinstance(raw.get("sort"), dict) else {}
        b["sort"] = {"column": sort.get("column") if sort.get("column") in keys else t["sort"],
                     "desc": bool(sort["desc"]) if "desc" in sort else bool(t.get("desc"))}
        b["limit"] = _int(raw.get("limit"), 1, MAX_ROWS) or 0
    return b


def parse_blocks(raw: Any, all_devices: bool) -> List[Dict[str, Any]]:
    """Checks a custom report's blocks (see the block model above). Raises ReportError in plain words."""
    if not isinstance(raw, list) or not raw:
        raise ReportError("Add at least one block to the report")
    count = sum(1 + (2 if isinstance(b, dict) and b.get("type") == "two_column" else 0) for b in raw)
    if len(raw) > MAX_BLOCKS or count > MAX_BLOCKS + 10:
        raise ReportError(f"A report holds at most {MAX_BLOCKS} blocks")
    return [_parse_block(b, all_devices) for b in raw]


def parse_spec(raw: Any, all_devices: bool) -> Dict[str, Any]:
    """Checks a spec from the browser or a saved report; unknown parts fall back to the template's own.
    A custom report ("template": "custom") carries its own blocks, checked by parse_blocks."""
    if not isinstance(raw, dict):
        raise ReportError("A report needs a template")
    tid = raw.get("template")
    flt = raw.get("filter") if isinstance(raw.get("filter"), dict) else {}
    device = flt.get("device")
    out_filter = {"group": _text(flt.get("group"), 64), "tag": _text(flt.get("tag"), 64),
                  "device": device if isinstance(device, int) and not isinstance(device, bool) and device > 0 else 0}
    title = _text(raw.get("title"), 120)
    if tid == "custom":
        return {"template": "custom", "period": raw.get("period") if raw.get("period") in PERIODS else "7d", "filter": out_filter,
                "title": title, "subtitle": _text(raw.get("subtitle"), 200), "audience": _text(raw.get("audience"), 80),
                "based_on": raw.get("based_on") if raw.get("based_on") in TEMPLATES else "",
                "blocks": parse_blocks(raw.get("blocks"), all_devices), "columns": [], "sort": {"column": "", "desc": False}, "limit": 0}
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
    sort = raw.get("sort") if isinstance(raw.get("sort"), dict) else {}
    column = sort.get("column") if sort.get("column") in keys else t["sort"]
    desc = bool(sort.get("desc")) if "desc" in sort else bool(t.get("desc"))
    limit = raw.get("limit")
    limit = limit if isinstance(limit, int) and not isinstance(limit, bool) and 0 < limit <= MAX_ROWS else 0
    out = {"template": tid, "period": period, "filter": out_filter, "columns": cols,
           "sort": {"column": column, "desc": desc}, "limit": limit, "title": title}
    if t.get("focus") == "outage":
        focus = raw.get("focus") if isinstance(raw.get("focus"), dict) else {}
        out["focus"] = {"outage": _int(focus.get("outage"), 1, 2 ** 62) or 0}
    return out


# Running a report ---------------------------------------------------------------------------------------

def _set_focus(c: Ctx, spec: Dict[str, Any]) -> None:
    """The outage review's window: the chosen outage (only among the covered devices) or the longest
    in the period, with some time before and after it."""
    ids = {d["id"]: d for d in c.all}
    if not ids:
        return
    want = (spec.get("focus") or {}).get("outage") or 0
    marks = ",".join("?" * len(ids))
    start = c.now - PERIODS[c.period]
    with database.get_connection() as conn:
        row = None
        if want:
            row = conn.execute(f"SELECT id, device_id, started, ended FROM avail_incidents WHERE id = ? AND device_id IN ({marks});",
                               (want, *ids)).fetchone()
        if row is None:
            row = conn.execute(f"SELECT id, device_id, started, ended FROM avail_incidents WHERE device_id IN ({marks}) "
                               "AND (ended IS NULL OR ended >= ?) ORDER BY COALESCE(ended, ?) - MAX(started, ?) DESC LIMIT 1;",
                               (*ids, start, c.now, start)).fetchone()
    if row is None:
        return
    a, z = row["started"], row["ended"] or c.now
    pad = max(1800, (z - a) // 4)
    c.focus = (a - pad, min(c.now, z + pad))
    first = next((e["timestamp"] for e in _problem_log(c, a - 900, a + 7200) if e["device_id"] == row["device_id"]
                  and str(e["message"]).startswith("Problem: ")), None)
    c.focus_info = {"id": row["id"], "device": ids[row["device_id"]]["name"], "started": a, "ended": row["ended"], "seconds": z - a,
                    "detected": max(0, first - a) if first is not None else None}


def outages(devices: List[Dict[str, Any]], now: Optional[int] = None, days: int = 90, limit: int = 40) -> List[Dict[str, Any]]:
    """The longest outages of these devices in the last days, for the outage review's choice."""
    now = int(now if now is not None else time.time())
    names = {d["id"]: d["name"] for d in devices}
    if not names:
        return []
    marks = ",".join("?" * len(names))
    with database.get_connection() as conn:
        rows = conn.execute(f"SELECT id, device_id, started, ended FROM avail_incidents WHERE device_id IN ({marks}) AND started >= ? "
                            "ORDER BY COALESCE(ended, ?) - started DESC LIMIT ?;", (*names, now - days * 86400, now, limit)).fetchall()
    return [{"id": r["id"], "device": names[r["device_id"]], "started": r["started"], "ended": r["ended"],
             "seconds": (r["ended"] or now) - r["started"]} for r in rows]


def _device_pairs(d: Dict[str, Any], fields: List[str]) -> List[List[str]]:
    up = None
    for m in database.get_latest_metrics(d["id"]):
        if m["metric_key"] == "uptime_seconds":
            up = m["value"]
    ifs = database.get_device_table(d["id"], "interfaces")
    shown = {"name": ["Name", d["name"]], "model": ["Model", d.get("model") or "Not known"], "ip": ["Address", d["ip"]],
             "group": ["Group", d.get("group") or "None"], "tags": ["Tags", ", ".join(d.get("tags") or []) or "None"],
             "location": ["Location", d.get("location") or "Not set"], "firmware": ["Software", d.get("firmware") or "Not known"],
             "snmp": ["SNMP", d.get("snmp") or "Not read over SNMP"], "uptime": ["Up for", format_cell("duration", up) if up else "Not known"],
             "interfaces": ["Interfaces", f"{len(ifs)} in all, {sum(1 for r in ifs.values() if r.get('oper') == 1)} up" if ifs else "None read"],
             "last_seen": ["Last seen", format_cell("time", d.get("last_seen")) if d.get("last_seen") else "Never"]}
    return [shown[f] for f in fields if f in shown]


def _render_table(c: Ctx, b: Dict[str, Any], main: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """A table block: its rows (raw values), the chosen columns, sorted and cut to its limit. main:
    the template's spec, whose column choice, sort and limit apply to the template's main table."""
    devs = _scope(c, b)
    start, end, period = c.window(b)
    b = dict(b)
    if main is not None:
        b.update(columns=main["columns"], sort=main["sort"], limit=main["limit"] or b.get("limit") or 0)
    allcols = {k: (k, l, ty) for k, l, ty in _table_columns(b["entity"])}
    keys = [k for k in b["columns"] if k in allcols]
    rows = TABLE_ROWS[b["entity"]](c, b, devs, start, end, set(keys))
    col = b["sort"]["column"]
    if col:
        nulls = [r for r in rows if r.get(col) in (None, "")]
        vals = sorted([r for r in rows if r.get(col) not in (None, "")], key=lambda r: _sort_key(r.get(col)), reverse=b["sort"]["desc"])
        rows = vals + nulls
    total = len(rows)
    rows = rows[:b["limit"]] if b["limit"] else rows
    rows = rows[:MAX_ROWS if main is not None else MAX_TABLE_ROWS]
    ent = TABLES[b["entity"]]
    columns = []
    for k in keys:
        key, label, ty = allcols[k]
        if k == "status":
            label = ent["status"].get(b.get("status"), "Status")
        elif k == "trend":
            label = ent["sparks"].get(b.get("spark"), "Trend")
        elif k == "group" and b.get("_first_label"):
            label = b["_first_label"]
        columns.append({"key": key, "label": label, "type": ty})
    return {"type": "table", "title": b.get("title") or ent["label"], "note": b.get("note") or "", "columns": columns,
            "rows": [[r.get(k) for k in keys] for r in rows], "total": total, "count": len(rows), "empty": TABLE_EMPTY.get(b["entity"], "Nothing to show."),
            "main": main is not None, "_raw": rows}


def _render_part(c: Ctx, b: Dict[str, Any], spec: Dict[str, Any], is_main: bool) -> Optional[Dict[str, Any]]:
    tid, part = b["template"], b["part"]
    t = TEMPLATES[tid]
    if t["all_devices"] and not c.all_devices:
        return None
    devices = c.all
    if t.get("one_device") and len(devices) > 1:
        devices = sorted(devices, key=lambda d: str(d["name"]).lower())[:1]
    period = spec["period"] if t["period"] else spec["period"]
    got = c.memo(("part", tid, period), lambda: GATHER[tid](devices, period, c.now, dict(c.env, filtered=c.env.get("filtered"))))
    if part == "kpis":
        return {"type": "kpi_row", "tiles": got["kpis"][:6]} if got["kpis"] else None
    if part == "summary":
        return {"type": "text", "title": b.get("title") or "Summary", "text": got["summary"], "box": False} if got["summary"] else None
    if part == "table":
        opts = spec if is_main and spec["template"] != "custom" else b
        rows = got["rows"]
        col = opts["sort"]["column"]
        nulls = [r for r in rows if r.get(col) in (None, "")]
        vals = sorted([r for r in rows if r.get(col) not in (None, "")], key=lambda r: _sort_key(r.get(col)), reverse=opts["sort"]["desc"])
        rows = vals + nulls
        total = len(rows)
        rows = (rows[:opts["limit"]] if opts["limit"] else rows)[:MAX_ROWS]
        by_key = {k: (k, l, ty) for k, l, ty in t["columns"]}
        cols = [{"key": k, "label": by_key[k][1], "type": by_key[k][2]} for k in opts["columns"] if k in by_key]
        return {"type": "table", "title": b.get("title") or t.get("table_title", "Details"), "note": b.get("note") or "", "columns": cols,
                "rows": [[r.get(x["key"]) for x in cols] for r in rows], "total": total, "count": len(rows), "empty": "Nothing to show for this choice.",
                "main": is_main, "_raw": rows}
    value = got["parts"].get(part)
    if not value:
        return None
    if part.startswith("tables."):
        return dict(type="table", empty="Nothing to show.", total=len(value["rows"]), main=False, **value)
    if not _has_data(value):
        return None
    chart = dict(value)
    if b.get("title"):
        chart["title"] = b["title"]
    if b.get("note"):
        chart["note"] = b["note"]
    return {"type": "chart", "chart": chart}


def _render(c: Ctx, b: Dict[str, Any], spec: Dict[str, Any], state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = b["type"]
    if kind == "two_column":
        left = _render(c, b["left"], spec, state) if b.get("left") else None
        right = _render(c, b["right"], spec, state) if b.get("right") else None
        if left and right:
            return {"type": "two_column", "left": left, "right": right}
        return left or right
    if kind == "part":
        main = b["part"] == "table" and not state.get("main")
        out = _render_part(c, b, spec, main)
        if out and out["type"] == "table" and out.get("main"):
            state["main"] = out
        return out
    if kind == "chart":
        view = SOURCES[b["source"]]["views"][b["view"]]
        if view["all_devices"] and not c.all_devices:
            return None
        devs = _scope(c, b)
        start, end, period = c.window(b)
        chart = view["fn"](c, b, devs, start, end, period)
        if b.get("title"):
            chart["title"] = b["title"]
        if b.get("note"):
            chart["note"] = b["note"]
        th = b.get("threshold") or {}
        if th.get("mode") == "override":
            chart["note"] = (chart.get("note") or "") + " Limits set for this report."
        if b.get("period") and b["period"] != c.period and not c.focus:
            chart["note"] = (chart.get("note") or "") + f" Covers {PERIOD_NAMES[b['period']]}."
        chart["ref"] = CHARTS.get(b["chart"], {}).get("n", 0)
        return {"type": "chart", "chart": chart}
    if kind == "kpi_row":
        devs = _scope(c, b)
        start, end, period = c.window(b)
        return {"type": "kpi_row", "tiles": [_tile(c, t, devs, start, end, period) for t in b["tiles"]]}
    if kind == "table":
        main = None
        if not state.get("main") and spec["template"] != "custom":
            main = spec
        out = _render_table(c, b, main)
        if not state.get("main"):
            out["main"] = True
            state["main"] = out
        return out
    if kind == "text":
        if b.get("auto"):
            devs = c.all
            start, end, period = c.window(b)
            text = AUTO_TEXTS[b["auto"]][1](c, devs, start, end, period)
        else:
            text = b.get("text") or ""
        return {"type": "text", "title": b.get("title") or "", "text": text, "box": True}
    if kind == "key_value":
        devs = _scope(c, b)
        if not devs:
            return {"type": "key_value", "title": b.get("title") or "Device details", "pairs": [["Device", "No device in this report"]]}
        d = sorted(devs, key=lambda d: str(d["name"]).lower())[0]
        return {"type": "key_value", "title": b.get("title") or "Device details", "pairs": _device_pairs(d, b.get("fields") or KV_FIELDS)}
    return None


def run(spec: Dict[str, Any], devices: List[Dict[str, Any]], ctx: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None) -> Dict[str, Any]:
    """Runs a checked spec over the devices given. Returns the report: its header (title, purpose,
    audience, period, what it covers), the rendered blocks in order, and for the CSV and older callers
    the main table (chosen columns, every row as raw values), key figures, summary and charts."""
    ctx = ctx or {}
    now = int(now if now is not None else time.time())
    custom = spec["template"] == "custom"
    t = TEMPLATES[spec["template"]] if not custom else {
        "title": "Custom report", "purpose": "", "period": True, "sources": "the monitor's checks, SNMP readings and logs",
        "audience": "", "blocks": spec["blocks"]}
    covers = ctx.get("filter_text") or ""
    if not custom and t.get("one_device") and len(devices) > 1:
        devices = sorted(devices, key=lambda d: str(d["name"]).lower())[:1]
        covers = f"Device {devices[0]['name']} (choose another under Covers)"
    c = Ctx(devices, spec["period"], now, ctx, bool(ctx.get("all_devices")))
    if t.get("focus") == "outage":
        _set_focus(c, spec)
    state: Dict[str, Any] = {}
    blocks = [r for r in (_render(c, b, spec, state) for b in (spec["blocks"] if custom else t["blocks"])) if r]
    main = state.get("main")
    # Older callers and the CSV: the main table, the first key figures, the summary and the charts.
    flat = [x for b in blocks for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b])]
    charts = [b["chart"] for b in flat if b["type"] == "chart"]
    first_full = next((b["chart"] for b in blocks if b["type"] == "chart"), None)
    span = PERIODS[spec["period"]]
    begin = datetime.fromtimestamp(now - span)
    period_text = (f"{begin.day} {begin.strftime('%b')}{begin.strftime(' %Y') if begin.year != datetime.fromtimestamp(now).year else ''}"
                   f"{begin.strftime(' %H:%M')} to {_date(now)}" if t["period"] else "Now")
    if c.focus:
        period_text = f"{_date(c.focus[0])} to {_date(c.focus[1])}"
    single = len(devices) == 1 and (spec["filter"].get("device") or t.get("one_device"))
    # A report with its own device details panel does not repeat them in the header.
    panel = any(x["type"] == "key_value" for b in blocks for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b]))
    facts = [["Period", period_text + (f" ({PERIOD_NAMES[spec['period']]})" if t["period"] and not c.focus else "")],
             ["Covers", covers or "All devices"]]
    if c.focus_info:
        facts.append(["Outage", f"{c.focus_info['device']}, {_minutes(c.focus_info['seconds'])}"])
    if not single:
        facts.append(["Devices", str(len(devices))])
    audience = spec.get("audience") if custom else t.get("audience")
    if audience:
        facts.append(["Audience", audience])
    facts.append(["Made", _date(now)])
    if single and not panel:
        facts += _device_facts(devices[0])
    total = main["total"] if main else 0
    shown = len(main["rows"]) if main else 0
    parts = []
    if covers:
        parts.append(covers)
    if t["period"]:
        parts.append(f"Covers {PERIOD_NAMES[spec['period']]}")
    if main:
        parts.append(f"{total} row{'' if total == 1 else 's'}" + (f", the first {shown} shown" if shown < total else ""))
    parts.append("Made " + datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M"))
    tables = [b for b in flat if b["type"] == "table"]
    tones = sorted({str(v) for tb in tables for row in tb["rows"] for col, v in zip(tb["columns"], row) if col["type"] == "pill" and v})
    for b in tables:
        b.pop("_raw", None)
    title = spec.get("title") or t["title"]
    purpose = (spec.get("subtitle") or "A report put together on the Reports page.") if custom else t["purpose"]
    return {"title": title, "template": spec["template"], "subtitle": ". ".join(parts) + ".", "purpose": purpose,
            "audience": audience or "", "period": spec["period"] if t["period"] else "", "period_text": period_text,
            "covers": covers or "All devices", "facts": facts, "blocks": blocks,
            "kpis": next((b["tiles"] for b in blocks if b["type"] == "kpi_row"), []),
            "summary": next((b["text"] for b in flat if b["type"] == "text" and b["text"]), ""),
            "main": first_full, "charts": [ch for ch in charts if ch is not first_full],
            "table_title": main["title"] if main else "", "columns": main["columns"] if main else [], "rows": main["rows"] if main else [],
            "total": total, "tables": [{"title": b["title"], "note": b["note"], "columns": b["columns"], "rows": b["rows"]} for b in tables if not b.get("main")],
            "tones": {v: PILL_TONES.get(v, "none") for v in tones}, "sources": t["sources"],
            "footer": f"Data from {t['sources']}. Times are local ({_tz()}).", "made_at": now}


def preview(report: Dict[str, Any], rows: int = PREVIEW_ROWS) -> Dict[str, Any]:
    """The report for the page: the main table cut to its first rows (the files hold them all)."""
    out = dict(report, rows=report["rows"][:rows])
    blocks = []
    for b in report["blocks"]:
        if b["type"] == "table" and b.get("main"):
            b = dict(b, rows=b["rows"][:rows])
        blocks.append(b)
    out["blocks"] = blocks
    return out


def _has_data(c: Dict[str, Any]) -> bool:
    """A first-template chart with something to draw (one with nothing does not apply and is left out)."""
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
    return True


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
        if 0 < value < 1:
            return f"{value:.2f}%"
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


def _pdf_side(b: Dict[str, Any]) -> Dict[str, Any]:
    """A block as a chart cell, so a side by side row is drawn by the chart grid."""
    if b["type"] == "chart":
        return b["chart"]
    if b["type"] == "text":
        return {"kind": "textbox", "title": b.get("title") or "", "text": b.get("text") or ""}
    if b["type"] == "key_value":
        return {"kind": "keyvalue", "title": b.get("title") or "", "pairs": b.get("pairs") or []}
    if b["type"] == "kpi_row":
        return {"kind": "textbox", "title": "Key figures", "text": "  ".join(f"{t['label']}: {t['value']}." for t in b["tiles"])}
    return {"kind": "textbox", "title": b.get("title") or "", "text": ""}


def to_pdf(report: Dict[str, Any]) -> bytes:
    """The report as a PDF in the same layout as the page: the header band, then every block in
    order (key figures, text boxes, charts full width or two to a row, tables). Page N of M at the foot."""
    import pdfdoc
    cols = report["columns"]
    doc = pdfdoc.Document(title=report["title"], landscape=len(cols) > 7, footer=report.get("footer") or "Times are local.")
    doc.header_band(report["title"], report.get("purpose", ""), [tuple(f) for f in report.get("facts", [])])
    for b in report.get("blocks") or []:
        kind = b["type"]
        if kind == "kpi_row":
            doc.kpi_tiles(b["tiles"])
        elif kind == "text":
            if b.get("box"):
                doc.text_box(b.get("title") or "", b.get("text") or "")
            else:
                doc.section(b.get("title") or "Summary")
                doc.text(b.get("text") or "", size=9.5)
                doc.space(8)
        elif kind == "chart":
            doc.chart(b["chart"])
        elif kind == "key_value":
            doc.chart(_pdf_side(b))
        elif kind == "two_column":
            doc.chart_grid([_pdf_side(b["left"]), _pdf_side(b["right"])], columns=2)
        elif kind == "table":
            total = b.get("total", len(b["rows"]))
            note = b.get("note") or ""
            if b.get("main"):
                note = (note + " " if note else "") + f"{total} row{'' if total == 1 else 's'}" + (f", the first {len(b['rows'])} shown" if len(b["rows"]) < total else "")
            doc.section(b.get("title") or "Details", note)
            if b["rows"]:
                doc.table([c["label"] for c in b["columns"]], _pdf_cells(b["columns"], b["rows"]),
                          align=["r" if c["type"] in ALIGN_RIGHT else "l" for c in b["columns"]])
            else:
                doc.text(b.get("empty") or "Nothing to show.", size=9, color=pdfdoc.GREY)
                doc.space(8)
    return doc.render()


def file_name(report: Dict[str, Any], ext: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", report["title"].lower()).strip("-")[:60] or "report"
    return f"{slug}-{datetime.fromtimestamp(report['made_at']).strftime('%Y-%m-%d-%H%M')}.{ext}"
