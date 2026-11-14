"""Reports: ready-made templates the user can adjust, as a table with charts, CSV or PDF.

A report is a spec:
  {"template": "devices", "period": "7d", "filter": {"group": "", "tag": "", "device": 0},
   "columns": ["name", "ip", ...], "sort": {"column": "name", "desc": false}, "limit": 0, "title": ""}

The server decides which devices the user may see, applies the group, tag or device filter and
hands run() the devices that are left, already described in plain words (DeviceInfo below). This
module never sees another user's devices and never a secret: a v3 device shows its user and
security level, never a password.

Each template lists every column it can give; the user picks which and in what order (the
customizer). Rows hold raw values (numbers, Unix times) with a type per column, so the table, the
CSV and the PDF each format them their own way.
"""

import csv
import io
import re
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import database

PERIODS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400}
PERIOD_NAMES = {"24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days", "90d": "the last 90 days"}
MAX_ROWS = 5000
PREVIEW_ROWS = 500


class ReportError(ValueError):
    """A spec that cannot be run, in words for the user."""


# DeviceInfo (a dict the server makes for each visible device):
#   id, name, ip, group, tags (list), kind (template name), snmp ("v2c", "v3" or "" when not read over
#   SNMP), snmp_security ("user monitor, signed and encrypted, SHA and AES" or ""), snmp_answer
#   ("Answers", "No answer" or ""), status, last_seen, ping_ms, check ("Port 443" for a service check).

# Column: (key, label, type). Types: text, num, pct, ms, time, bytes, duration, mbps, dbm.
Column = Tuple[str, str, str]


def _col(key: str, label: str, kind: str = "text") -> Column:
    return (key, label, kind)


DEVICE_COLS = [_col("name", "Name"), _col("ip", "Address"), _col("group", "Group"), _col("tags", "Tags")]

TEMPLATES: Dict[str, Dict[str, Any]] = {
    "devices": {
        "title": "Devices and SNMP settings",
        "description": "Every device with its group, tags, template and how it is read: SNMP v2c or v3, and whether it answers. Handy before moving devices to SNMPv3.",
        "period": False, "all_devices": False,
        "columns": DEVICE_COLS + [_col("kind", "Template"), _col("snmp", "SNMP"), _col("snmp_security", "SNMPv3 settings"),
                                  _col("snmp_answer", "SNMP answers"), _col("status", "Status"), _col("ping_ms", "Ping", "ms"),
                                  _col("last_seen", "Last seen", "time")],
        "default": ["name", "ip", "group", "kind", "snmp", "snmp_security", "snmp_answer", "status"],
        "sort": "name",
    },
    "availability": {
        "title": "Availability",
        "description": "Uptime, time down and how often each device went down over the period, with the average response time.",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("uptime", "Uptime", "pct"), _col("down", "Time down", "duration"),
                                  _col("outages", "Outages", "num"), _col("avg_ms", "Average response", "ms"),
                                  _col("status", "Status now")],
        "default": ["name", "ip", "group", "uptime", "down", "outages", "avg_ms"],
        "sort": "uptime",
    },
    "problems": {
        "title": "Problems",
        "description": "Every problem that opened in the period: when, on which device, how serious and whether it is still open.",
        "period": True, "all_devices": False,
        "columns": [_col("time", "Opened", "time"), _col("name", "Device"), _col("ip", "Address"), _col("group", "Group"),
                    _col("severity", "Severity"), _col("problem", "Problem"), _col("state", "Now")],
        "default": ["time", "name", "severity", "problem", "state"],
        "sort": "time", "desc": True,
    },
    "health": {
        "title": "Device health",
        "description": "Processor and memory, average and highest over the period, and the fullest disk now. One device adds graphs over time.",
        "period": True, "all_devices": False,
        "columns": DEVICE_COLS + [_col("cpu_avg", "CPU average", "pct"), _col("cpu_max", "CPU highest", "pct"),
                                  _col("mem_avg", "Memory average", "pct"), _col("mem_max", "Memory highest", "pct"),
                                  _col("disk_max", "Fullest disk", "pct"), _col("disk_name", "Which disk")],
        "default": ["name", "group", "cpu_avg", "cpu_max", "mem_avg", "mem_max", "disk_max", "disk_name"],
        "sort": "cpu_avg", "desc": True,
    },
    "storage": {
        "title": "Storage and when it fills up",
        "description": "Every disk, volume and storage pool: size, use and the date it is expected to be full at the current rate.",
        "period": False, "all_devices": False,
        "columns": [_col("name", "Device"), _col("ip", "Address"), _col("group", "Group"), _col("storage", "Storage"),
                    _col("size", "Size", "bytes"), _col("used", "Used", "bytes"), _col("used_pct", "Used %", "pct"),
                    _col("full_on", "Full around", "time")],
        "default": ["name", "storage", "size", "used", "used_pct", "full_on"],
        "sort": "used_pct", "desc": True,
    },
    "wifi": {
        "title": "Wi-Fi devices",
        "description": "Every device on Wi-Fi (from UniFi): access point, network, band, signal and experience.",
        "period": False, "all_devices": False,
        "columns": [_col("client", "Device"), _col("mac", "MAC address"), _col("client_ip", "Address"), _col("vendor", "Maker"),
                    _col("name", "Access point"), _col("ssid", "Network"), _col("band", "Band"), _col("signal", "Signal", "dbm"),
                    _col("experience", "Experience", "pct"), _col("tx_mbps", "Link speed", "mbps"), _col("uptime", "Connected for", "duration")],
        "default": ["client", "name", "ssid", "band", "signal", "experience"],
        "sort": "signal",
    },
    "proxmox": {
        "title": "Proxmox guests",
        "description": "Virtual machines and containers: where they run, state, memory and disk, and whether they start with the host.",
        "period": False, "all_devices": True,
        "columns": [_col("guest", "Guest"), _col("vmid", "ID", "num"), _col("type", "Kind"), _col("node", "Node"),
                    _col("state", "State"), _col("mem", "Memory used", "bytes"), _col("maxmem", "Memory", "bytes"),
                    _col("maxdisk", "Disk", "bytes"), _col("uptime", "Running for", "duration"), _col("onboot", "Starts with host"),
                    _col("name", "Monitored as")],
        "default": ["guest", "vmid", "type", "node", "state", "mem", "maxmem", "maxdisk", "onboot"],
        "sort": "vmid",
    },
    "pihole": {
        "title": "Pi-hole",
        "description": "Each Pi-hole: queries and blocked today, clients, block list size and age, and the most blocked domains.",
        "period": False, "all_devices": False,
        "columns": [_col("name", "Pi-hole"), _col("ip", "Address"), _col("blocking", "Blocking"), _col("queries", "Queries today", "num"),
                    _col("blocked", "Blocked today", "num"), _col("blocked_pct", "Blocked %", "pct"), _col("clients", "Clients", "num"),
                    _col("domains", "Domains on the lists", "num"), _col("gravity_days", "Lists updated (days ago)", "num"),
                    _col("dns_ms", "Answer time", "ms")],
        "default": ["name", "blocking", "queries", "blocked", "blocked_pct", "clients", "domains", "gravity_days"],
        "sort": "name",
    },
    "new_devices": {
        "title": "New and changed devices on the network",
        "description": "Devices first seen on the network in the period (Inventory), with maker, address and where they were seen.",
        "period": True, "all_devices": True,
        "columns": [_col("first_seen", "First seen", "time"), _col("client", "Name"), _col("mac", "MAC address"),
                    _col("client_ip", "Address"), _col("vendor", "Maker"), _col("where", "Seen on"), _col("ssid", "Network"),
                    _col("known", "Known"), _col("last_seen", "Last seen", "time")],
        "default": ["first_seen", "client", "mac", "client_ip", "vendor", "where", "known"],
        "sort": "first_seen", "desc": True,
    },
    "events": {
        "title": "Events",
        "description": "Everything that happened to the devices in the period: problems, recoveries, restarts, changes and messages.",
        "period": True, "all_devices": False,
        "columns": [_col("time", "When", "time"), _col("name", "Device"), _col("ip", "Address"), _col("severity", "Severity"),
                    _col("type", "Type"), _col("message", "What happened")],
        "default": ["time", "name", "severity", "type", "message"],
        "sort": "time", "desc": True,
    },
    "updates": {
        "title": "Monitor updates",
        "description": "Updates, upgrades and undos of the monitor itself, with the result of each.",
        "period": True, "all_devices": True,
        "columns": [_col("time", "When", "time"), _col("kind", "What"), _col("from", "From"), _col("to", "To"),
                    _col("result", "Result"), _col("error", "Error")],
        "default": ["time", "kind", "from", "to", "result", "error"],
        "sort": "time", "desc": True,
    },
}
TEMPLATE_ORDER = ["devices", "availability", "problems", "health", "storage", "wifi", "proxmox", "pihole", "new_devices",
                  "events", "updates"]


def template_list(all_devices: bool) -> List[Dict[str, Any]]:
    """The templates this user can run, for the Reports page. Network-wide ones need every device."""
    out = []
    for tid in TEMPLATE_ORDER:
        t = TEMPLATES[tid]
        if t["all_devices"] and not all_devices:
            continue
        out.append({"id": tid, "title": t["title"], "description": t["description"], "period": t["period"],
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
    period = raw.get("period") if raw.get("period") in PERIODS else "7d"
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


# --- Gathering rows --------------------------------------------------------------------------------

def _stem(message: str) -> str:
    """A problem's text up to its first number, so a changing value is still the same problem."""
    return re.split(r"\d", message, maxsplit=1)[0].strip()


def _base(d: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": d["name"], "ip": d["ip"], "group": d["group"], "tags": ", ".join(d.get("tags") or [])}


def _devices(devices, period, now, ctx):
    return [dict(_base(d), kind=d.get("kind") or "", snmp=d.get("snmp") or "Not read over SNMP",
                 snmp_security=d.get("snmp_security") or "", snmp_answer=d.get("snmp_answer") or "",
                 status=d.get("status") or "", ping_ms=d.get("ping_ms"), last_seen=d.get("last_seen")) for d in devices], \
        [_bar_counts("Devices by SNMP version", [d.get("snmp") or "No SNMP" for d in devices])]


def _availability(devices, period, now, ctx):
    import availability
    span = PERIODS[period]
    ids = [d["id"] for d in devices]
    ranged = availability.ranged(ids, period, now=now) if ids else {}
    down: Dict[int, List[float]] = {}
    if ids:
        marks = ",".join("?" * len(ids))
        with database.get_connection() as conn:
            for r in conn.execute(f"SELECT device_id, started, ended FROM avail_incidents WHERE device_id IN ({marks}) "
                                  "AND (ended IS NULL OR ended >= ?) AND started <= ?;", (*ids, now - span, now)):
                start, end = max(r["started"], now - span), min(r["ended"] or now, now)
                down.setdefault(r["device_id"], []).append(max(0, end - start))
    rows = []
    for d in devices:
        a = ranged.get(d["id"]) or {}
        rows.append(dict(_base(d), uptime=a.get("uptime"), down=sum(down.get(d["id"], [])) if a.get("uptime") is not None else None,
                         outages=len(down.get(d["id"], [])), avg_ms=a.get("avg_ms"), status=d.get("status") or ""))
    worst = sorted([r for r in rows if r["uptime"] is not None], key=lambda r: r["uptime"])[:10]
    charts = [{"kind": "bar", "title": "Lowest uptime", "unit": "%", "bars": [(r["name"], r["uptime"]) for r in worst]}] if worst else []
    return rows, charts


def _problems(devices, period, now, ctx):
    by_id = {d["id"]: d for d in devices}
    if not by_id:
        return [], []
    events, _ = database.list_events_filtered(event_type="problem", since=now - PERIODS[period], until=now,
                                              device_ids=set(by_id), limit=MAX_ROWS)
    active: Dict[int, set] = {}
    for p in database.list_active_problems():
        active.setdefault(p["device_id"], set()).add(_stem(p["message"]))
    rows = []
    for e in events:
        d = by_id.get(e["device_id"])
        if not d or not str(e["message"]).startswith("Problem: "):
            continue
        text = e["message"][len("Problem: "):]
        rows.append(dict(_base(d), time=e["timestamp"], severity=e["severity"].capitalize(), problem=text,
                         state="Still open" if _stem(text) in active.get(d["id"], set()) else "Resolved"))
    return rows, [_bar_counts("Problems per device", [r["name"] for r in rows], top=10)]


def _series_stats(device_id: int, keys: List[str], start: int, end: int, invert: bool = False):
    """(average, highest, points) of the first key with data; points for a graph."""
    for key in keys:
        pts = database.get_metric_history_bucketed(device_id, key, start, end, max_points=120)
        if pts:
            def val(v):
                return None if v is None else (100.0 - v if invert else v)
            avgs = [val(p["value"]) for p in pts if p.get("value") is not None]
            highs = [val(p.get("min") if invert else p.get("max")) for p in pts if p.get("max") is not None]
            line = [(p["timestamp"], val(p.get("value"))) for p in pts]
            return (sum(avgs) / len(avgs) if avgs else None, max(highs) if highs else None, line)
    return None, None, []


def _health(devices, period, now, ctx):
    start = now - PERIODS[period]
    rows, lines = [], []
    for d in devices:
        cpu = _series_stats(d["id"], ["cpu_usage_pct"], start, now)
        if cpu[0] is None:
            cpu = _series_stats(d["id"], ["cpu_idle_pct"], start, now, invert=True)
        mem = _series_stats(d["id"], ["mem_used_pct"], start, now)
        disk_max, disk_name = None, ""
        for table in ("storage", "volumes"):
            for idx, s in database.get_device_table(d["id"], table).items():
                pct = s.get("used_pct")
                if isinstance(pct, (int, float)) and (disk_max is None or pct > disk_max) and s.get("kind", "disk") in ("disk", "other", None, "fixed"):
                    disk_max, disk_name = pct, str(s.get("descr") or idx)
        if cpu[0] is None and mem[0] is None and disk_max is None:
            continue
        rows.append(dict(_base(d), cpu_avg=cpu[0], cpu_max=cpu[1], mem_avg=mem[0], mem_max=mem[1], disk_max=disk_max, disk_name=disk_name))
        lines.append((d, cpu[2], mem[2]))
    charts = []
    if len(devices) == 1 and lines:
        _, cpu_line, mem_line = lines[0]
        charts.append({"kind": "line", "title": "Processor and memory", "unit": "%",
                       "series": [{"name": "CPU", "points": cpu_line}, {"name": "Memory", "points": mem_line}]})
    else:
        top = sorted([r for r in rows if r["cpu_avg"] is not None], key=lambda r: -r["cpu_avg"])[:10]
        if top:
            charts.append({"kind": "bar", "title": "Busiest processors (average)", "unit": "%", "bars": [(r["name"], r["cpu_avg"]) for r in top]})
    return rows, charts


def _storage(devices, period, now, ctx):
    import forecast
    fc = forecast.cached(now)
    rows = []
    for d in devices:
        full = {f["key"]: f.get("full_on") for f in fc.get(d["id"], [])}
        for table, prefix in (("volumes", "vol"), ("storage", "stor")):
            for idx, s in database.get_device_table(d["id"], table).items():
                if table == "storage" and s.get("kind") not in ("disk", "other", None):
                    continue
                size = s.get("size_bytes")
                rows.append(dict(_base(d), storage=str(s.get("descr") or idx), size=size, used=s.get("used_bytes"),
                                 used_pct=s.get("used_pct"), full_on=full.get(f"{prefix}.{idx}.used_pct")))
    top = sorted([r for r in rows if isinstance(r["used_pct"], (int, float))], key=lambda r: -r["used_pct"])[:10]
    return rows, ([{"kind": "bar", "title": "Fullest storage", "unit": "%",
                    "bars": [(f"{r['name']}: {r['storage']}", r["used_pct"]) for r in top]}] if top else [])


def _wifi(devices, period, now, ctx):
    rows = []
    for d in devices:
        for mac, c in database.get_device_table(d["id"], "wifi_clients").items():
            rows.append(dict(_base(d), client=c.get("name") or mac, mac=mac, client_ip=c.get("ip") or "", vendor=c.get("vendor") or "",
                             ssid=c.get("ssid") or "", band=c.get("band") or "", signal=c.get("signal"),
                             experience=c.get("experience"), tx_mbps=c.get("tx_mbps"), uptime=c.get("uptime")))
    return rows, [_bar_counts("Devices per network", [r["ssid"] or "Unknown" for r in rows])] if rows else []


def _proxmox(devices, period, now, ctx):
    import proxmox
    names = {d["id"]: d["name"] for d in devices}
    rows = []
    for g in proxmox.layout().get("guests", []):
        if ctx.get("filtered") and g.get("device_id") not in names:
            continue
        rows.append({"guest": g.get("name") or str(g.get("vmid")), "vmid": g.get("vmid"),
                     "type": "Container" if g.get("type") == "lxc" else "Virtual machine", "node": g.get("node") or "",
                     "state": str(g.get("status") or "").capitalize(), "mem": g.get("mem"), "maxmem": g.get("maxmem"),
                     "maxdisk": g.get("maxdisk"), "uptime": g.get("uptime") if g.get("status") == "running" else None,
                     "onboot": "Yes" if g.get("onboot") else "No", "name": names.get(g.get("device_id"), ""),
                     "ip": "", "group": "", "tags": ""})
    return rows, [_bar_counts("Guests by state", [r["state"] or "Unknown" for r in rows])] if rows else []


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
    return rows, ([{"kind": "bar", "title": "Most blocked domains today", "unit": "", "bars": bars[:10]}] if bars else [])


def _new_devices(devices, period, now, ctx):
    since = now - PERIODS[period]
    with database.get_connection() as conn:
        found = [dict(r) for r in conn.execute(
            "SELECT i.*, d.hostname AS device_name FROM inventory i LEFT JOIN devices d ON d.id = i.device_id "
            "WHERE i.first_seen >= ? AND i.quiet = 0 ORDER BY i.first_seen DESC LIMIT ?;", (since, MAX_ROWS))]
    rows = [{"first_seen": r["first_seen"], "client": r.get("name") or r.get("seen_name") or r.get("device_name") or "",
             "mac": r["mac"], "client_ip": r.get("ip") or "", "vendor": r.get("vendor") or "", "where": r.get("where_seen") or "",
             "ssid": r.get("ssid") or "", "known": "Yes" if r.get("known") else "No", "last_seen": r.get("last_seen")} for r in found]
    return rows, [_bar_counts("New devices by maker", [r["vendor"] or "Unknown" for r in rows], top=10)] if rows else []


def _events(devices, period, now, ctx):
    by_id = {d["id"]: d for d in devices}
    if not by_id:
        return [], []
    events, _ = database.list_events_filtered(since=now - PERIODS[period], until=now, device_ids=set(by_id), limit=MAX_ROWS)
    rows = [dict(_base(by_id[e["device_id"]]), time=e["timestamp"], severity=str(e["severity"]).capitalize(),
                 type=str(e["event_type"]).replace("_", " "), message=e["message"]) for e in events if e["device_id"] in by_id]
    return rows, [_bar_counts("Events by severity", [r["severity"] for r in rows])] if rows else []


def _updates(devices, period, now, ctx):
    since = now - PERIODS[period]
    history: Callable[[], List[Dict[str, Any]]] = ctx.get("update_history") or (lambda: [])
    rows = [{"time": h["time"], "kind": str(h["kind"] or "update").replace("-", " ").capitalize(), "from": h["from"],
             "to": h["to"], "result": "Finished" if h["ok"] else "Failed", "error": h["error"][:300]}
            for h in history() if h["time"] >= since]
    return rows, []


GATHER = {"devices": _devices, "availability": _availability, "problems": _problems, "health": _health,
          "storage": _storage, "wifi": _wifi, "proxmox": _proxmox, "pihole": _pihole, "new_devices": _new_devices,
          "events": _events, "updates": _updates}


def _bar_counts(title: str, values: List[str], top: int = 12) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    bars = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {"kind": "bar", "title": title, "unit": "", "bars": bars}


# --- Running and formatting -------------------------------------------------------------------------

def _sort_key(value: Any) -> Tuple[int, Any]:
    if value is None or value == "":
        return (1, 0)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0, value)
    return (0, str(value).lower())


def run(spec: Dict[str, Any], devices: List[Dict[str, Any]], ctx: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None) -> Dict[str, Any]:
    """Runs a checked spec over the devices given. Returns the title, a line saying what it covers,
    the chosen columns, every row (raw values) and the charts."""
    ctx = ctx or {}
    now = int(now if now is not None else time.time())
    t = TEMPLATES[spec["template"]]
    rows, charts = GATHER[spec["template"]](devices, spec["period"], now, ctx)
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
    parts = []
    if ctx.get("filter_text"):
        parts.append(ctx["filter_text"])
    if t["period"]:
        parts.append(f"Covers {PERIOD_NAMES[spec['period']]}")
    parts.append(f"{total} row{'' if total == 1 else 's'}" + (f", the first {len(rows)} shown" if len(rows) < total else ""))
    parts.append("Made " + datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M"))
    return {"title": spec["title"] or t["title"], "template": spec["template"], "subtitle": ". ".join(parts) + ".",
            "columns": columns, "rows": [[r.get(c["key"]) for c in columns] for r in rows], "total": total,
            "charts": [c for c in charts if c.get("bars") or c.get("series")], "made_at": now}


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
    if value is None or value == "":
        return ""
    if kind == "text" or not isinstance(value, (int, float)) or isinstance(value, bool):
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
        return f"{value:.0f} Mbps"
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
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow([c["label"] for c in report["columns"]])
    kinds = [c["type"] for c in report["columns"]]
    for row in report["rows"]:
        w.writerow([_csv_value(k, v) for k, v in zip(kinds, row)])
    # With a byte order mark, Excel opens it as UTF-8.
    return ("﻿" + out.getvalue()).encode("utf-8")


ALIGN_RIGHT = {"num", "pct", "ms", "bytes", "duration", "mbps", "dbm"}


def to_pdf(report: Dict[str, Any]) -> bytes:
    import pdfdoc
    cols = report["columns"]
    doc = pdfdoc.Document(title=report["title"], landscape=len(cols) > 6)
    doc.heading(report["title"])
    doc.text(report["subtitle"], size=9, color=(0.4, 0.4, 0.4))
    doc.space(6)
    for c in report["charts"]:
        if c["kind"] == "line":
            doc.line_chart(c["title"], c["series"], y_unit=c.get("unit") or "")
        else:
            doc.bar_chart(c["title"], [(str(l), float(v)) for l, v in c["bars"]], unit=c.get("unit") or "")
        doc.space(6)
    doc.table([c["label"] for c in cols], [[format_cell(c["type"], v) for c, v in zip(cols, row)] for row in report["rows"]],
              align=["r" if c["type"] in ALIGN_RIGHT else "l" for c in cols])
    return doc.render()


def file_name(report: Dict[str, Any], ext: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", report["title"].lower()).strip("-")[:60] or "report"
    return f"{slug}-{datetime.fromtimestamp(report['made_at']).strftime('%Y-%m-%d-%H%M')}.{ext}"
