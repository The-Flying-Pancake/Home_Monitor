"""Custom SNMP OIDs: extra values to poll for one template (every device using it) or one device.

The typical case: a switch whose template reads no CPU or memory, although
the device publishes them under its vendor's enterprise OID. MIB files only
map names to these numeric OIDs (and need their imported MIBs to resolve),
so definitions use the numbers directly; the walk browser on the device page
shows what a device answers under a subtree, to pick them from.

Kinds:
  gauge      the value as reported, times scale (temperatures, percentages)
  counter    a per-second rate from two polls (octets, packets); a decrease is a reset
  timeticks  hundredths of a second, stored as seconds
  string     text, shown in Latest Data only (no history, no graph)

Numeric values are stored as metrics "custom.<id>", so they appear in Latest
Data, get graphs and history like profile metrics. An optional threshold
(above or below, with a severity) opens a problem "custom:<id>".
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple

import database
import poller

KINDS = ("gauge", "counter", "timeticks", "string")
SEVERITIES = ("info", "warning", "high", "critical")
_OID = re.compile(r"^\.?(\d+)(\.\d+){3,127}$")
_last: Dict[Tuple[int, int], Tuple[float, float]] = {}   # (device_id, def_id) -> (time, raw counter)


def ensure_schema() -> None:
    with database.get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_oids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                target TEXT NOT NULL,
                oid TEXT NOT NULL,
                label TEXT NOT NULL,
                unit TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT 'gauge',
                scale REAL NOT NULL DEFAULT 1,
                alert_op TEXT,
                alert_value REAL,
                alert_severity TEXT,
                created_at INTEGER NOT NULL,
                UNIQUE (scope, target, oid)
            );""")
        conn.commit()


def normalise_oid(oid: str) -> Optional[str]:
    oid = (oid or "").strip()
    return oid.lstrip(".") if _OID.match(oid) else None


def parse(payload: Dict[str, Any], profiles: List[str], device_ids: List[int]) -> Dict[str, Any]:
    """Validates a definition. Raises ValueError with a message for the administrator."""
    scope = payload.get("scope")
    target = str(payload.get("target") or "")
    if scope == "template":
        if target not in profiles:
            raise ValueError("Unknown template")
    elif scope == "device":
        if not target.isdigit() or int(target) not in device_ids:
            raise ValueError("Unknown device")
    else:
        raise ValueError("scope must be template or device")
    oid = normalise_oid(str(payload.get("oid") or ""))
    if not oid:
        raise ValueError("Enter a numeric OID, for example 1.3.6.1.4.1.4413.1.1.1.1.4.9.0")
    label = str(payload.get("label") or "").strip()[:60]
    if not label:
        raise ValueError("Give the value a name")
    kind = payload.get("kind") or "gauge"
    if kind not in KINDS:
        raise ValueError("Type must be gauge, counter, timeticks or string")
    try:
        scale = float(payload.get("scale") if payload.get("scale") not in (None, "") else 1)
    except (TypeError, ValueError):
        raise ValueError("Scale must be a number, for example 0.1")
    if not -1e9 < scale < 1e9 or scale == 0:
        raise ValueError("Scale must be a number other than 0")
    op = payload.get("alert_op") or None
    value = payload.get("alert_value")
    severity = payload.get("alert_severity") or "warning"
    if op is not None:
        if op not in ("above", "below") or kind == "string":
            raise ValueError("A threshold is above or below, on a number")
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValueError("The threshold needs a number")
        if severity not in SEVERITIES:
            raise ValueError("Unknown severity")
    else:
        value = severity = None
    return {"scope": scope, "target": target, "oid": oid, "label": label, "unit": str(payload.get("unit") or "").strip()[:16],
            "kind": kind, "scale": scale, "alert_op": op, "alert_value": value, "alert_severity": severity}


def add(d: Dict[str, Any]) -> int:
    with database.get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO custom_oids (scope, target, oid, label, unit, kind, scale, alert_op, alert_value, alert_severity, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (d["scope"], d["target"], d["oid"], d["label"], d["unit"], d["kind"], d["scale"], d["alert_op"],
             d["alert_value"], d["alert_severity"], int(time.time())))
        conn.commit()
        return cur.lastrowid


def remove(def_id: int) -> Optional[Dict[str, Any]]:
    with database.get_connection() as conn:
        row = conn.execute("SELECT * FROM custom_oids WHERE id = ?;", (def_id,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM custom_oids WHERE id = ?;", (def_id,))
        conn.execute("DELETE FROM metric_latest WHERE metric_key = ?;", (f"custom.{def_id}",))
        conn.commit()
        return dict(row)


def for_device(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Definitions that apply to a device: its own, then its template's (a device entry wins on the same OID)."""
    with database.get_connection() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM custom_oids WHERE (scope = 'device' AND target = ?) OR (scope = 'template' AND target = ?) "
            "ORDER BY scope = 'template', id;", (str(device["id"]), device.get("profile_id") or ""))]
    seen, out = set(), []
    for r in rows:
        if r["oid"] not in seen:
            seen.add(r["oid"])
            out.append(r)
    return out


def all_defs() -> List[Dict[str, Any]]:
    with database.get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM custom_oids ORDER BY scope, target, id;")]


def metric_key(def_id: int) -> str:
    return f"custom.{def_id}"


def poll(device: Dict[str, Any], timeout: float = 2.0, retries: int = 0, store: bool = True,
         now: Optional[float] = None) -> Dict[str, float]:
    """GETs the device's custom OIDs; stores numbers as metrics and text in the device table "custom"."""
    defs = for_device(device)
    if not defs:
        return {}
    answers = poller.snmp_get_many(device["ip_address"], [d["oid"] for d in defs], poller.snmp_target(device),
                                   device.get("snmp_port") or 161, timeout, retries)
    now = now if now is not None else time.time()
    metrics: Dict[str, float] = {}
    texts: Dict[str, Dict[str, Any]] = {}
    for d in defs:
        raw = answers.get(d["oid"])
        if raw is None:
            continue
        if d["kind"] == "string":
            texts[str(d["id"])] = {"label": d["label"], "value": str(raw)[:200], "oid": d["oid"]}
            continue
        try:
            num = float(raw)
        except (TypeError, ValueError):
            continue
        if d["kind"] == "timeticks":
            metrics[metric_key(d["id"])] = round(num / 100.0, 2)
        elif d["kind"] == "counter":
            prev = _last.get((device["id"], d["id"]))
            _last[(device["id"], d["id"])] = (now, num)
            if prev and now > prev[0] and num >= prev[1]:
                metrics[metric_key(d["id"])] = round((num - prev[1]) / (now - prev[0]) * d["scale"], 4)
        else:
            metrics[metric_key(d["id"])] = round(num * d["scale"], 4)
    if store:
        database.record_metrics(device["id"], metrics)
        database.replace_device_table(device["id"], "custom", texts)
    return metrics


def metric_info(device: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Labels for the UI, in the shape server.metric_info gives profile metrics."""
    out = {}
    for d in for_device(device):
        if d["kind"] != "string":
            label = f"{d['label']} ({d['unit']})" if d["unit"] else d["label"]
            out[metric_key(d["id"])] = {"label": label, "unit": d["unit"], "group": "Custom OIDs", "custom": True}
    return out


def problems(device: Dict[str, Any], latest: Dict[str, float]) -> List[Dict[str, Any]]:
    """Threshold breaches: [{key, message, severity}] for the problem engine."""
    out = []
    for d in for_device(device):
        if not d["alert_op"]:
            continue
        v = latest.get(metric_key(d["id"]))
        if not isinstance(v, (int, float)):
            continue
        hit = v > d["alert_value"] if d["alert_op"] == "above" else v < d["alert_value"]
        if hit:
            unit = f" {d['unit']}" if d["unit"] else ""
            out.append({"key": f"custom:{d['id']}", "severity": d["alert_severity"] or "warning",
                        "message": f"{d['label']} is {v:g}{unit} ({d['alert_op']} {d['alert_value']:g}{unit})"})
    return out


def walk(device: Dict[str, Any], oid: str, max_rows: int = 500, timeout: float = 2.0) -> Dict[str, Any]:
    """The subtree under oid as rows {oid, type, value}, for the walk browser."""
    base = normalise_oid(oid) if oid.strip(".").count(".") >= 3 else None
    if not base:
        # Short prefixes (1.3.6.1) are allowed for the browser: anything numeric with at least two arcs.
        base = oid.strip().lstrip(".") if re.fullmatch(r"\.?\d+(\.\d+)+", oid.strip()) else None
    if not base:
        raise ValueError("Enter a numeric OID to walk, for example 1.3.6.1.4.1")
    rows = poller.snmp_walk(device["ip_address"], base, poller.snmp_target(device),
                            device.get("snmp_port") or 161, timeout, 0, max_repetitions=30, max_rows=max_rows + 1)
    out = []
    for suffix, value in list(rows.items())[:max_rows]:
        kind = "number" if isinstance(value, int) and not isinstance(value, bool) else "text"
        out.append({"oid": f"{base}.{suffix}", "type": kind, "value": value if kind == "number" else str(value)[:200]})
    return {"base": base, "rows": out, "truncated": len(rows) > max_rows}


def enterprise_root(device: Dict[str, Any]) -> str:
    """The vendor subtree (1.3.6.1.4.1.<vendor>) from sysObjectID, the usual place for CPU and memory."""
    obj = str((device.get("inventory") or {}).get("sys_object_id") or "").lstrip(".")
    m = re.match(r"^(1\.3\.6\.1\.4\.1\.\d+)", obj)
    return m.group(1) if m else "1.3.6.1.4.1"
