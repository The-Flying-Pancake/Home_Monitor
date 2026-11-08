"""Your own Telegram commands (Settings, Notifications, Commands): a name, what it shows and
how the reply is written.

A command is
  name         lowercase letters, digits and _, up to 32 (Telegram's rule), not a built-in name
  description  one line, shown in /help and in Telegram's command menu
  source       what it is about: a key of SOURCES (devices, Wi-Fi SSIDs, Proxmox guests, ...)
  pick         the items it covers (ids from choices()); empty means all. For devices also
               "tag:<name>" and "group:<id>"
  only         a filter of the source (down, running, weak, ...); "" means none
  sort, desc   sort the items by one of the line's placeholders (numbers by value), highest first
               with desc; "" keeps the source's order
  limit        at most this many lines (0: all)
  header, line, footer
               the reply: header and footer once, line once per item, each with placeholders.
               An argument narrows the items by name: /wifi guest lists the SSIDs with "guest".

Everything here reads data the monitor already has (the database, the Proxmox and Pi-hole caches,
the UniFi tables): a command cannot run anything or reach anything new. Stored as one internal
setting, {"custom": [...], "off": [names of commands switched off, built-in ones included]}.
"""

import json
import re
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import availability
import customoids
import database
import forecast
import pihole
import proxmox
import taxonomy
import tpl

KEY = "bot_commands"
MAX_COMMANDS = 95          # Telegram's menu holds 100: these, the 4 built-in ones and /help
MAX_LIMIT = 200
MAX_TEMPLATE = 800
BUILTIN = ("status", "problems", "device", "changes", "help", "start")
NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
STATE_WORD = {"online": "up", "offline": "down", "degraded": "degraded"}

# Set by server.py: the Wi-Fi page's data (access points and their clients) and the weak line.
wifi_view: Callable[[], Dict[str, Any]] = lambda: {"aps": [], "clients": [], "weak_dbm": -75}


class CommandError(Exception):
    pass


# --- Formatting ---

def ago(seconds: Optional[float]) -> str:
    if seconds is None:
        return ""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


def pct(part: Any, whole: Any) -> str:
    try:
        return f"{100.0 * float(part) / float(whole):.0f}%" if whole else ""
    except (TypeError, ValueError):
        return ""


def gb(value: Any) -> str:
    try:
        return f"{float(value) / 1e9:.1f} GB"
    except (TypeError, ValueError):
        return ""


def num(value: Any, digits: int = 1) -> str:
    if value is None:
        return ""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    return str(int(v)) if v == int(v) and abs(v) < 1e15 else f"{v:.{digits}f}"


def _now_values(now: float) -> Dict[str, Any]:
    return {"time": f"{datetime.fromtimestamp(now):%H:%M}", "date": f"{datetime.fromtimestamp(now):%d %b}"}


# --- Sources ---
# Each source: label, help, item placeholders, summary placeholders (header and footer), filters,
# choices() for the picker and gather(cmd, now) -> (summary values, items). An item is a dict of
# its placeholder values plus "_id" (what pick holds) and "_name" (what an argument matches).

COMMON_SUMMARY = {"time": "Time of the answer (HH:MM)", "date": "Today's date (04 Nov)", "count": "How many items are listed",
                  "total_items": "How many there were before the limit", "more": "How many the limit left out",
                  "empty": "'Nothing to show.' when no item is listed, else empty"}


def _devices_all() -> List[Dict[str, Any]]:
    return database.list_devices()


def _device_pick(cmd: Dict[str, Any], devices: List[Dict[str, Any]], group_of: Callable[[Dict[str, Any]], str]) -> List[Dict[str, Any]]:
    pick = cmd.get("pick") or []
    if not pick:
        return devices
    ids = {int(p) for p in pick if str(p).isdigit()}
    tags = {p[4:].lower() for p in pick if str(p).startswith("tag:")}
    groups = {p[6:] for p in pick if str(p).startswith("group:")}
    out = []
    for d in devices:
        dtags = {t.lower() for t in taxonomy.device_tags(d)}
        if d["id"] in ids or tags & dtags or (groups and group_of(d) in groups):
            out.append(d)
    return out


def _metric_labels() -> Dict[str, str]:
    labels = {"cpu_usage_pct": "CPU use %", "mem_used_pct": "Memory used %", "mem_pct": "Memory used %",
              "uptime_seconds": "Uptime (seconds)", "ping_ms": "Ping ms"}
    for d in customoids.all_defs():
        labels[customoids.metric_key(d["id"])] = f"Custom: {d.get('name') or d['id']}"
    return labels


# server.py sets this to its device_group (devices sources pick by group).
device_group: Callable[[Dict[str, Any]], str] = lambda d: d.get("device_group") or ""


def devices_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    devices = _device_pick(cmd, _devices_all(), device_group)
    problems: Dict[int, List[Dict[str, Any]]] = {}
    for p in database.list_active_problems():
        if p["severity"] != "info":
            problems.setdefault(p["device_id"], []).append(p)
    only = cmd.get("only") or ""
    if only == "down":
        devices = [d for d in devices if d["status"] == "offline"]
    elif only == "problems":
        devices = [d for d in devices if problems.get(d["id"])]
    elif only == "up":
        devices = [d for d in devices if d["status"] == "online"]
    ids = [d["id"] for d in devices]
    day = availability.ranged(ids, "24h", now=int(now)) if ids else {}
    week = availability.ranged(ids, "7d", now=int(now)) if ids else {}
    items = []
    for d in devices:
        latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(d["id"])}
        down = d["status"] == "offline"
        mine = problems.get(d["id"], [])
        mem = next((latest[k] for k in ("mem_used_pct", "mem_pct") if latest.get(k) is not None), None)
        v = {"device": d["hostname"], "ip": d["ip_address"], "state": STATE_WORD.get(d["status"], d["status"] or "not checked"),
             "mark": "🔴" if down else "🟡" if mine or d["status"] == "degraded" else "🟢",
             "template": d["profile_id"], "group": device_group(d), "tags": ", ".join(taxonomy.device_tags(d)),
             "ping": f"{d['last_ping_ms']:.0f} ms" if d.get("last_ping_ms") is not None and not down else "",
             "cpu": f"{latest['cpu_usage_pct']:.0f}%" if latest.get("cpu_usage_pct") is not None else "",
             "memory": f"{mem:.0f}%" if mem is not None else "",
             "uptime": ago(latest.get("uptime_seconds")) if latest.get("uptime_seconds") and not down else "",
             "last_seen": ago(now - d["last_seen"]) + " ago" if down and d.get("last_seen") else "",
             "problems": len(mine), "problem": mine[0]["message"] if mine else "",
             "uptime_24h": num((day.get(d["id"]) or {}).get("uptime"), 2) + "%" if (day.get(d["id"]) or {}).get("uptime") is not None else "",
             "uptime_7d": num((week.get(d["id"]) or {}).get("uptime"), 2) + "%" if (week.get(d["id"]) or {}).get("uptime") is not None else "",
             "_id": str(d["id"]), "_name": d["hostname"]}
        for k, val in latest.items():
            v[f"metric:{k}"] = num(val)
        items.append(v)
    summary = {"up": sum(1 for d in devices if d["status"] == "online"), "down": sum(1 for d in devices if d["status"] == "offline"),
               "total": len(devices), "problems": sum(len(problems.get(i, [])) for i in ids)}
    return summary, items


def devices_choices() -> Dict[str, Any]:
    devices = _devices_all()
    tags = sorted({t for d in devices for t in taxonomy.device_tags(d)}, key=str.lower)
    groups = sorted({device_group(d) for d in devices})
    names = {g["id"]: g["name"] for g in taxonomy.groups()}
    keys: Dict[str, str] = {}
    labels = _metric_labels()
    with database.get_connection() as conn:
        for r in conn.execute("SELECT DISTINCT metric_key FROM metric_latest ORDER BY metric_key LIMIT 400;"):
            keys[r["metric_key"]] = labels.get(r["metric_key"], "")
    return {"choices": [{"id": f"tag:{t}", "label": f"Tag: {t}"} for t in tags]
                       + [{"id": f"group:{g}", "label": f"Group: {names.get(g, g)}"} for g in groups]
                       + [{"id": str(d["id"]), "label": f"{d['hostname']} ({d['ip_address']})"} for d in devices],
            "metrics": [{"key": f"metric:{k}", "label": v} for k, v in keys.items()]}


def _wifi() -> Dict[str, Any]:
    try:
        return wifi_view()
    except Exception:
        return {"aps": [], "clients": [], "weak_dbm": -75}


def _picked(cmd: Dict[str, Any], items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pick = {str(p) for p in cmd.get("pick") or []}
    return [i for i in items if i["_id"] in pick] if pick else items


def ssid_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    w = _wifi()
    weak = w.get("weak_dbm", -75)
    by: Dict[str, List[Dict[str, Any]]] = {}
    for c in w["clients"]:
        by.setdefault(c.get("ssid") or "(hidden)", []).append(c)
    items = []
    for ssid, cs in sorted(by.items(), key=lambda kv: kv[0].lower()):
        sig = [c["signal"] for c in cs if isinstance(c.get("signal"), (int, float))]
        exp = [c["experience"] for c in cs if isinstance(c.get("experience"), (int, float))]
        bands: Dict[str, int] = {}
        for c in cs:
            bands[c.get("band") or "?"] = bands.get(c.get("band") or "?", 0) + 1
        nweak = sum(1 for s in sig if s < weak)
        items.append({"ssid": ssid, "clients": len(cs), "weak": nweak, "weakest": f"{min(sig)} dBm" if sig else "",
                      "signal_avg": f"{sum(sig) / len(sig):.0f} dBm" if sig else "",
                      "experience": f"{sum(exp) / len(exp):.0f}%" if exp else "",
                      "bands": ", ".join(f"{b} {n}" for b, n in sorted(bands.items())),
                      "aps": ", ".join(sorted({c.get("ap_name") or "" for c in cs} - {""})),
                      "names": ", ".join(sorted((c.get("name") or c.get("ip") or c.get("mac") or "?") for c in cs)[:15]),
                      "mark": "🟡" if nweak else "🟢", "_id": ssid, "_name": ssid})
    items = _picked(cmd, items)
    if cmd.get("only") == "weak":
        items = [i for i in items if i["weak"]]
    return {"clients": sum(i["clients"] for i in items), "weak": sum(i["weak"] for i in items), "weak_line": f"{weak} dBm"}, items


def ssid_choices() -> Dict[str, Any]:
    ssids = sorted({c.get("ssid") or "(hidden)" for c in _wifi()["clients"]}, key=str.lower)
    return {"choices": [{"id": s, "label": s} for s in ssids]}


def ap_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    w = _wifi()
    items = []
    for a in w["aps"]:
        cs = [c for c in w["clients"] if c.get("ap_id") == a["device_id"]]
        items.append({"ap": a["name"], "ip": a["ip"], "state": STATE_WORD.get(a["status"], a["status"] or ""),
                      "clients": a["clients"], "weak": a["weak"],
                      "experience": f"{a['experience']}%" if a.get("experience") is not None else "",
                      "bands": ", ".join(f"{b} {n}" for b, n in sorted((a.get("bands") or {}).items())),
                      "ssids": ", ".join(sorted({c.get("ssid") or "(hidden)" for c in cs})),
                      "mark": "🔴" if a["status"] == "offline" else "🟡" if a["weak"] else "🟢",
                      "_id": str(a["device_id"]), "_name": a["name"]})
    items = _picked(cmd, items)
    if cmd.get("only") == "weak":
        items = [i for i in items if i["weak"]]
    return {"clients": sum(i["clients"] for i in items), "weak": sum(i["weak"] for i in items)}, items


def ap_choices() -> Dict[str, Any]:
    return {"choices": [{"id": str(a["device_id"]), "label": a["name"]} for a in _wifi()["aps"]]}


def client_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    w = _wifi()
    weak = w.get("weak_dbm", -75)
    items = []
    for c in sorted(w["clients"], key=lambda c: c["signal"] if isinstance(c.get("signal"), (int, float)) else 0):
        sig = c.get("signal")
        is_weak = isinstance(sig, (int, float)) and sig < weak
        items.append({"client": c.get("name") or c.get("vendor") or c.get("mac") or "?", "ip": c.get("ip") or "",
                      "mac": c.get("mac") or "", "vendor": c.get("vendor") or "", "ssid": c.get("ssid") or "",
                      "ap": c.get("ap_name") or "", "band": c.get("band") or "", "channel": num(c.get("channel")),
                      "signal": f"{sig} dBm" if sig is not None else "", "rate": f"{num(c.get('tx_mbps'))} Mbps" if c.get("tx_mbps") else "",
                      "experience": f"{num(c.get('experience'), 0)}%" if c.get("experience") is not None else "",
                      "roams": num(c.get("roams")), "connected": ago(c.get("uptime")),
                      "mark": "🟡" if is_weak else "🟢", "_id": c.get("mac") or "", "_name": f"{c.get('name') or ''} {c.get('ip') or ''} {c.get('ssid') or ''}",
                      "_weak": is_weak})
    items = _picked(cmd, items)
    if cmd.get("only") == "weak":
        items = [i for i in items if i["_weak"]]
    return {"weak": sum(1 for i in items if i["_weak"]), "weak_line": f"{weak} dBm"}, items


def client_choices() -> Dict[str, Any]:
    return {"choices": [{"id": c.get("mac") or "", "label": f"{c.get('name') or c.get('mac')} ({c.get('ssid') or '?'})"}
                        for c in sorted(_wifi()["clients"], key=lambda c: (c.get("name") or c.get("mac") or "").lower()) if c.get("mac")]}


def _pve() -> Dict[str, Any]:
    if not proxmox.is_enabled():
        return {}
    try:
        data = proxmox.overview(_devices_all())
    except Exception:
        return {}
    return data if data.get("configured") else {}


def guest_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    data = _pve()
    items = []
    for g in sorted(data.get("guests", []), key=lambda g: (g.get("node") or "", g.get("vmid") or 0)):
        if g.get("template"):
            continue
        running = g.get("status") == "running"
        items.append({"name": g.get("name") or str(g.get("vmid")), "vmid": g.get("vmid"), "node": g.get("node") or "",
                      "kind": "VM" if g.get("type") == "qemu" else "container", "state": g.get("status") or "",
                      "cpu": f"{100 * float(g['cpu']):.0f}%" if running and g.get("cpu") is not None else "",
                      "cores": num(g.get("maxcpu")),
                      "memory": pct(g.get("mem"), g.get("maxmem")) if running else "",
                      "memory_used": gb(g.get("mem")) if running else "", "memory_total": gb(g.get("maxmem")),
                      "disk": pct(g.get("disk"), g.get("maxdisk")) if g.get("type") == "lxc" and g.get("disk") else "",
                      "disk_total": gb(g.get("maxdisk")), "uptime": ago(g.get("uptime")) if running else "",
                      "ip": ", ".join(g.get("ips") or []), "onboot": "starts at boot" if g.get("onboot") else "",
                      "tags": ", ".join(g.get("tags") or []),
                      "mark": "🟢" if running else "⚪" if not g.get("onboot") else "🔴",
                      "_id": f"{g.get('node')}/{g.get('vmid')}", "_name": g.get("name") or str(g.get("vmid")), "_running": running})
    items = _picked(cmd, items)
    if cmd.get("only") == "running":
        items = [i for i in items if i["_running"]]
    elif cmd.get("only") == "stopped":
        items = [i for i in items if not i["_running"]]
    return {"running": sum(1 for i in items if i["_running"]), "stopped": sum(1 for i in items if not i["_running"]),
            "connected": "yes" if data else "no"}, items


def guest_choices() -> Dict[str, Any]:
    return {"choices": [{"id": f"{g.get('node')}/{g.get('vmid')}", "label": f"{g.get('name') or g.get('vmid')} ({g.get('vmid')}, {g.get('node')})"}
                        for g in _pve().get("guests", []) if not g.get("template")]}


def node_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    data = _pve()
    guests = data.get("guests", [])
    items = []
    for n in data.get("nodes", []):
        mine = [g for g in guests if g.get("node") == n.get("node") and not g.get("template")]
        items.append({"node": n.get("node") or "", "state": n.get("status") or "",
                      "cpu": f"{100 * float(n['cpu']):.0f}%" if n.get("cpu") is not None else "", "cores": num(n.get("maxcpu")),
                      "memory": pct(n.get("mem"), n.get("maxmem")), "memory_used": gb(n.get("mem")), "memory_total": gb(n.get("maxmem")),
                      "disk": pct(n.get("disk"), n.get("maxdisk")), "uptime": ago(n.get("uptime")),
                      "guests": len(mine), "running": sum(1 for g in mine if g.get("status") == "running"),
                      "mark": "🟢" if n.get("status") == "online" else "🔴", "_id": n.get("node") or "", "_name": n.get("node") or ""})
    items = _picked(cmd, items)
    failed = data.get("failed_tasks") or []
    backups = data.get("backups") or []
    last = max((b.get("end") or b.get("start") or 0 for b in backups), default=0)
    return {"version": data.get("version") or "", "failed_tasks": len(failed),
            "last_backup": ago(now - last) + " ago" if last else ""}, items


def node_choices() -> Dict[str, Any]:
    return {"choices": [{"id": n.get("node") or "", "label": n.get("node") or ""} for n in _pve().get("nodes", [])]}


def storage_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    data = _pve()
    items = []
    for s in data.get("storage", []):
        free = (s.get("maxdisk") or 0) - (s.get("disk") or 0)
        items.append({"storage": s.get("storage") or "", "node": s.get("node") or "", "state": s.get("status") or "",
                      "type": s.get("type") or "", "used": pct(s.get("disk"), s.get("maxdisk")), "used_gb": gb(s.get("disk")),
                      "total": gb(s.get("maxdisk")), "free": gb(free) if s.get("maxdisk") else "",
                      "mark": "🟢" if s.get("status") == "available" else "🔴",
                      "_id": f"{s.get('node')}/{s.get('storage')}", "_name": s.get("storage") or ""})
    return {}, _picked(cmd, items)


def storage_choices() -> Dict[str, Any]:
    return {"choices": [{"id": f"{s.get('node')}/{s.get('storage')}", "label": f"{s.get('storage')} on {s.get('node')}"}
                        for s in _pve().get("storage", [])]}


def pihole_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    v = pihole.view(_devices_all())
    m = {k: x["value"] for k, x in (v.get("metrics") or {}).items()}
    summary = {"connected": "yes" if v.get("device") else "no",
               "queries": num(m.get("pihole.queries"), 0), "blocked": num(m.get("pihole.blocked"), 0),
               "blocked_pct": f"{m['pihole.blocked_pct']:.1f}%" if m.get("pihole.blocked_pct") is not None else "",
               "clients": num(m.get("pihole.clients"), 0),
               "blocking": "" if m.get("pihole.blocking") is None else ("on" if m.get("pihole.blocking") == 1.0 else "off"),
               "dns_ms": f"{m['dns.ms']:.0f} ms" if m.get("dns.ms") is not None else "",
               "lists_age": f"{m['pihole.gravity_days']:.0f} days" if m.get("pihole.gravity_days") is not None else "",
               "domains": num(m.get("pihole.domains"), 0)}
    items = [{"domain": b.get("domain") or "", "hits": num(b.get("count"), 0), "_id": b.get("domain") or "", "_name": b.get("domain") or ""}
             for b in sorted(v.get("blocked") or [], key=lambda b: -(b.get("count") or 0))[:10]]
    return summary, items


def forecast_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    devices = {d["id"]: d for d in _devices_all()}
    items = []
    for device_id, rows in forecast.cached(now).items():
        if device_id not in devices:
            continue
        for f in rows:
            items.append({"device": devices[device_id]["hostname"], "volume": f["label"], "used": f"{f['now']:.0f}%",
                          "per_day": f"{f['per_day']:+.2f}% a day",
                          "days": num(f["days"], 0) if f["days"] is not None else "",
                          "full_on": f"{datetime.fromtimestamp(f['full_on']):%d %b %Y}" if f.get("full_on") else "",
                          "_id": f"{device_id}/{f['key']}", "_name": f"{devices[device_id]['hostname']} {f['label']}",
                          "_days": f["days"]})
    items.sort(key=lambda i: i["_days"] if i["_days"] is not None else 1e9)
    items = _picked(cmd, items)
    if cmd.get("only") == "soon":
        items = [i for i in items if i["_days"] is not None and i["_days"] <= 60]
    return {}, items


def forecast_choices() -> Dict[str, Any]:
    _, items = forecast_gather({}, time.time())
    return {"choices": [{"id": i["_id"], "label": f"{i['device']}: {i['volume']}"} for i in items]}


def problems_gather(cmd: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    marks = {"critical": "🔴", "high": "🟠", "warning": "🟡"}
    rows = [p for p in database.list_active_problems() if p["severity"] != "info"]
    only = cmd.get("only") or ""
    if only in marks:
        order = list(marks)
        rows = [p for p in rows if order.index(p["severity"]) <= order.index(only)]
    elif only == "unacknowledged":
        rows = [p for p in rows if not p["acknowledged_at"]]
    pick = {str(p) for p in cmd.get("pick") or []}
    if pick:
        devices = {str(d["id"]) for d in _device_pick(cmd, _devices_all(), device_group)}
        rows = [p for p in rows if str(p["device_id"]) in devices]
    items = [{"mark": marks.get(p["severity"], ""), "severity": p["severity"], "device": p["hostname"], "problem": p["message"],
              "duration": ago(now - p["since"]), "acknowledged": "acknowledged" if p["acknowledged_at"] else "",
              "_id": str(p["device_id"]), "_name": f"{p['hostname']} {p['message']}"} for p in rows]
    return {"critical": sum(1 for p in rows if p["severity"] == "critical")}, items


SOURCES: Dict[str, Dict[str, Any]] = {
    "devices": {"label": "Devices", "help": "Monitored devices: pick devices, a tag or a group, or leave it on all.",
                "gather": devices_gather, "choices": devices_choices,
                "only": [["", "All of them"], ["down", "Only those down"], ["up", "Only those up"], ["problems", "Only those with problems"]],
                "summary": {"up": "Devices up (all it covers, before the limit)", "down": "Devices down (likewise)", "total": "Devices covered", "problems": "Their open problems"},
                "item": {"mark": "🟢 up, 🟡 problems, 🔴 down", "device": "Name", "ip": "Address", "state": "up, down or degraded",
                         "template": "Template", "group": "Group", "tags": "Tags", "ping": "Last ping", "cpu": "CPU use",
                         "memory": "Memory use", "uptime": "How long it has been up", "last_seen": "When it last answered (while down)",
                         "problems": "Open problems (number)", "problem": "Its worst open problem",
                         "uptime_24h": "Availability over 24 hours", "uptime_7d": "Availability over 7 days"},
                "default": {"header": "{count} devices: {up} up, {down} down", "line": "{mark} {device}: {state}, ping {ping}, CPU {cpu}",
                            "footer": ""}},
    "problems": {"label": "Problems", "help": "Open problems, most severe first.", "gather": problems_gather, "choices": devices_choices,
                 "only": [["", "All of them"], ["critical", "Only critical"], ["high", "High and critical"], ["warning", "Warning and above"],
                          ["unacknowledged", "Only not acknowledged"]],
                 "summary": {"critical": "Critical problems"},
                 "item": {"mark": "Colour dot", "severity": "critical, high or warning", "device": "Device", "problem": "Problem text",
                          "duration": "How long it has been open", "acknowledged": "'acknowledged' when it is"},
                 "default": {"header": "{count} open problems", "line": "{mark} {device}: {problem} ({duration})", "footer": "{empty}"}},
    "wifi_ssid": {"label": "Wi-Fi networks (SSIDs)", "help": "One line per SSID, from UniFi.", "gather": ssid_gather, "choices": ssid_choices,
                  "only": [["", "All of them"], ["weak", "Only with weak devices"]],
                  "summary": {"clients": "Wi-Fi devices in all", "weak": "Weak devices in all", "weak_line": "The weak signal line"},
                  "item": {"mark": "🟢, or 🟡 with weak devices", "ssid": "Network name", "clients": "Devices on it", "weak": "Weak devices",
                           "weakest": "Weakest signal", "signal_avg": "Average signal", "experience": "Average UniFi experience",
                           "bands": "Devices per band", "aps": "Access points it is on", "names": "Names of the devices (up to 15)"},
                  "default": {"header": "📶 Wi-Fi at {time}", "line": "{mark} {ssid}: {clients} devices, {weak} weak ({bands})", "footer": ""}},
    "wifi_ap": {"label": "Wi-Fi access points", "help": "One line per access point.", "gather": ap_gather, "choices": ap_choices,
                "only": [["", "All of them"], ["weak", "Only with weak devices"]],
                "summary": {"clients": "Wi-Fi devices in all", "weak": "Weak devices in all"},
                "item": {"mark": "🟢, 🟡 weak devices, 🔴 down", "ap": "Name", "ip": "Address", "state": "up or down", "clients": "Devices on it",
                         "weak": "Weak devices", "experience": "Average UniFi experience", "bands": "Devices per band", "ssids": "SSIDs on it"},
                "default": {"header": "", "line": "{mark} {ap}: {clients} devices, {weak} weak, {experience}", "footer": ""}},
    "wifi_client": {"label": "Wi-Fi devices", "help": "One line per Wi-Fi device, weakest signal first.", "gather": client_gather,
                    "choices": client_choices, "only": [["", "All of them"], ["weak", "Only weak signal"]],
                    "summary": {"weak": "Weak devices", "weak_line": "The weak signal line"},
                    "item": {"mark": "🟢, or 🟡 when weak", "client": "Name", "ip": "Address", "mac": "MAC", "vendor": "Maker", "ssid": "SSID",
                             "ap": "Access point", "band": "Band", "channel": "Channel", "signal": "Signal", "rate": "Link rate",
                             "experience": "UniFi experience", "roams": "Roams", "connected": "Connected for"},
                    "default": {"header": "{weak} weak of {count}", "line": "{mark} {client} on {ap}: {signal}, {rate}", "footer": ""}},
    "proxmox_guest": {"label": "Proxmox VMs and containers", "help": "One line per guest you pick, or all of them.", "gather": guest_gather,
                      "choices": guest_choices, "only": [["", "All of them"], ["running", "Only running"], ["stopped", "Only stopped"]],
                      "summary": {"running": "Running", "stopped": "Stopped", "connected": "yes when Proxmox answers"},
                      "item": {"mark": "🟢 running, 🔴 stopped but starts at boot, ⚪ stopped", "name": "Name", "vmid": "ID", "node": "Node",
                               "kind": "VM or container", "state": "running or stopped", "cpu": "CPU use", "cores": "Cores",
                               "memory": "Memory use %", "memory_used": "Memory used", "memory_total": "Memory given",
                               "disk": "Disk use % (containers)", "disk_total": "Disk size", "uptime": "Up for", "ip": "Addresses",
                               "onboot": "'starts at boot' when it does", "tags": "Proxmox tags"},
                      "default": {"header": "🖥️ {running} running, {stopped} stopped",
                                  "line": "{mark} {name} ({vmid}): {state}, CPU {cpu}, memory {memory}, up {uptime}", "footer": ""}},
    "proxmox_node": {"label": "Proxmox nodes", "help": "The Proxmox hosts.", "gather": node_gather, "choices": node_choices, "only": [],
                     "summary": {"version": "Proxmox version", "failed_tasks": "Failed tasks", "last_backup": "Since the last backup"},
                     "item": {"mark": "🟢 online, 🔴 not", "node": "Name", "state": "online or not", "cpu": "CPU use", "cores": "Cores",
                              "memory": "Memory use %", "memory_used": "Memory used", "memory_total": "Memory", "disk": "Root disk use",
                              "uptime": "Up for", "guests": "Guests", "running": "Guests running"},
                     "default": {"header": "", "line": "{mark} {node}: CPU {cpu}, memory {memory}, {running}/{guests} guests running, up {uptime}",
                                 "footer": "Last backup {last_backup}, {failed_tasks} failed tasks"}},
    "proxmox_storage": {"label": "Proxmox storage", "help": "Storage pools.", "gather": storage_gather, "choices": storage_choices, "only": [],
                        "summary": {},
                        "item": {"mark": "🟢 available, 🔴 not", "storage": "Name", "node": "Node", "state": "available or not", "type": "Type",
                                 "used": "Used %", "used_gb": "Used", "total": "Size", "free": "Free"},
                        "default": {"header": "", "line": "{mark} {storage} on {node}: {used} used, {free} free", "footer": ""}},
    "pihole": {"label": "Pi-hole", "help": "Today's Pi-hole figures; lines are the most blocked domains.", "gather": pihole_gather,
               "choices": None, "only": [],
               "summary": {"connected": "yes when Pi-hole answers", "queries": "Queries today", "blocked": "Blocked today",
                           "blocked_pct": "Blocked %", "clients": "Clients", "blocking": "on or off", "dns_ms": "DNS answer time",
                           "lists_age": "Since the block lists were updated", "domains": "Domains on the block lists"},
               "item": {"domain": "A blocked domain", "hits": "Times blocked"},
               "default": {"header": "🛡️ Pi-hole: {queries} queries, {blocked_pct} blocked, DNS {dns_ms}, blocking {blocking}",
                           "line": "", "footer": ""}},
    "forecasts": {"label": "Storage forecasts", "help": "Volumes, disks and pools, soonest full first.", "gather": forecast_gather,
                  "choices": forecast_choices, "only": [["", "All of them"], ["soon", "Only full within 60 days"]],
                  "summary": {},
                  "item": {"device": "Device", "volume": "Volume", "used": "Used now", "per_day": "Growth a day",
                           "days": "Days until full", "full_on": "Date it will be full"},
                  "default": {"header": "", "line": "{device} {volume}: {used}, full in {days} days ({full_on})", "footer": "{empty}"}},
}


# --- Stored commands ---

def load() -> Dict[str, Any]:
    try:
        data = json.loads(database.get_all_settings().get(KEY) or "{}")
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {"custom": [c for c in data.get("custom") or [] if isinstance(c, dict)], "off": list(data.get("off") or [])}


def clean(raw: Dict[str, Any]) -> Dict[str, Any]:
    """One command as the administrator sent it, checked. Raises CommandError."""
    name = str(raw.get("name") or "").strip().lstrip("/").lower()
    if not NAME_RE.fullmatch(name):
        raise CommandError("A command name is lowercase letters, digits and _, starting with a letter, up to 32 long")
    if name in BUILTIN:
        raise CommandError(f"/{name} is a built-in command; edit its reply instead")
    source = str(raw.get("source") or "")
    if source not in SOURCES:
        raise CommandError(f"/{name}: choose what it shows")
    spec = SOURCES[source]
    only = str(raw.get("only") or "")
    if only and only not in [o[0] for o in spec["only"]]:
        raise CommandError(f"/{name}: unknown filter")
    pick = raw.get("pick") or []
    if not isinstance(pick, list) or len(pick) > 200:
        raise CommandError(f"/{name}: too many items picked")
    sort = str(raw.get("sort") or "")
    if sort and sort not in spec["item"] and not sort.startswith("metric:"):
        raise CommandError(f"/{name}: cannot sort by {sort}")
    try:
        limit = int(raw.get("limit") or 0)
    except (TypeError, ValueError):
        raise CommandError(f"/{name}: the limit is a whole number")
    if not 0 <= limit <= MAX_LIMIT:
        raise CommandError(f"/{name}: the limit is 0 (all) to {MAX_LIMIT}")
    out = {"name": name, "description": str(raw.get("description") or "").strip()[:100], "source": source, "only": only,
           "pick": [str(p)[:120] for p in pick if str(p).strip()], "sort": sort, "desc": bool(raw.get("desc")), "limit": limit}
    for part in ("header", "line", "footer"):
        text = str(raw.get(part) or "").replace("\r\n", "\n")
        if len(text) > MAX_TEMPLATE:
            raise CommandError(f"/{name}: the {part} is longer than {MAX_TEMPLATE} characters")
        out[part] = text
    if not (out["header"].strip() or out["line"].strip() or out["footer"].strip()):
        raise CommandError(f"/{name}: write what it answers")
    if not out["description"]:
        out["description"] = spec["label"]
    return out


def save(custom: List[Dict[str, Any]], off: List[str]) -> Dict[str, Any]:
    if len(custom) > MAX_COMMANDS:
        raise CommandError(f"At most {MAX_COMMANDS} commands of your own")
    cleaned, seen = [], set()
    for raw in custom:
        c = clean(raw)
        if c["name"] in seen:
            raise CommandError(f"/{c['name']} is there twice")
        seen.add(c["name"])
        cleaned.append(c)
    known = seen | {"status", "problems", "device", "changes"}
    data = {"custom": cleaned, "off": sorted({str(o) for o in off if str(o) in known})}
    database.set_internal_setting(KEY, json.dumps(data))
    return data


def find(name: str) -> Optional[Dict[str, Any]]:
    data = load()
    if name in data["off"]:
        return None
    return next((c for c in data["custom"] if c["name"] == name), None)


def render(cmd: Dict[str, Any], arg: str = "", now: Optional[float] = None,
           fill: Callable[[str, Dict[str, Any]], str] = None) -> str:
    """The reply to one of your own commands."""
    import telebot
    fill = fill or telebot.fill
    now = now if now is not None else time.time()
    spec = SOURCES[cmd["source"]]
    try:
        summary, items = spec["gather"](cmd, now)
    except Exception as exc:                       # a source that is not connected: say so, do not fail the bot
        return f"/{cmd['name']}: could not read {spec['label']} ({type(exc).__name__})."
    q = arg.strip().lower()
    if q:
        items = [i for i in items if q in str(i.get("_name", "")).lower()]
    if cmd.get("sort"):
        key = cmd["sort"]

        def order(i: Dict[str, Any]):
            v = i.get(key)
            n = tpl.number(v)
            # Empty values last either way.
            empty = v is None or str(v).strip() == ""
            return (empty != bool(cmd.get("desc")), 0 if n is not None else 1, n if n is not None else 0, str(v or "").lower())
        items = sorted(items, key=order, reverse=bool(cmd.get("desc")))
    total = len(items)
    if cmd.get("limit"):
        items = items[:int(cmd["limit"])]
    base = dict(_now_values(now), **summary, count=len(items), total_items=total, more=total - len(items),
                empty="Nothing to show." if not items else "")
    parts = []
    if cmd.get("header", "").strip():
        parts.append(fill(cmd["header"], base))
    if cmd.get("line", "").strip():
        for i in items:
            values = dict(base, **{k: v for k, v in i.items() if not k.startswith("_")})
            line = fill(cmd["line"], values)
            if line.strip():
                parts.append(line)
    if cmd.get("footer", "").strip():
        parts.append(fill(cmd["footer"], base))
    text = "\n".join(p for p in parts if p.strip())
    return telebot._clip(text.split("\n")) if text.strip() else "Nothing to show."


def placeholders(source: str) -> Dict[str, Any]:
    spec = SOURCES[source]
    return {"summary": dict(COMMON_SUMMARY, **spec["summary"]), "item": spec["item"]}


def sources_view() -> Dict[str, Any]:
    return {k: {"label": v["label"], "help": v["help"], "only": v["only"], "pickable": v["choices"] is not None,
                "default": v["default"], **placeholders(k)} for k, v in SOURCES.items()}


def choices(source: str) -> Dict[str, Any]:
    spec = SOURCES.get(source)
    if not spec:
        raise CommandError("Unknown source")
    if spec["choices"] is None:
        return {"choices": []}
    return spec["choices"]()
