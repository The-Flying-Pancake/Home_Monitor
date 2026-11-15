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

Capacity readings: a gauge can be marked as the use of a limited resource (a DHCP scope, firewall
sessions, licences) with its limit, a fixed number or a second OID that holds the maximum. Its
used percent is stored as "custom.<id>.used_pct" and joins the disks, memory and links in the
capacity bars, the forecasts (forecast.py) and the capacity reports, amber from cap_warn and red
from cap_crit (75 and 90 unless set).
"""

import math
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import database
import poller

KINDS = ("gauge", "counter", "timeticks", "string")
CAP_WARN, CAP_CRIT = 75.0, 90.0
# Capacity columns, added to custom_oids (fixed names, never from outside).
CAP_COLUMNS = (("cap_resource", "TEXT"), ("cap_limit", "REAL"), ("cap_limit_oid", "TEXT"), ("cap_warn", "REAL"), ("cap_crit", "REAL"))
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
        have = {r[1] for r in conn.execute("PRAGMA table_info(custom_oids);")}
        for name, decl in CAP_COLUMNS:
            if name not in have:
                conn.execute(f"ALTER TABLE custom_oids ADD COLUMN {name} {decl};")
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
    out = {"scope": scope, "target": target, "oid": oid, "label": label, "unit": str(payload.get("unit") or "").strip()[:16],
           "kind": kind, "scale": scale, "alert_op": op, "alert_value": value, "alert_severity": severity,
           "cap_resource": None, "cap_limit": None, "cap_limit_oid": None, "cap_warn": None, "cap_crit": None}
    if any(payload.get(k) not in (None, "") for k in ("cap_resource", "cap_limit", "cap_limit_oid")):
        out.update(_parse_capacity(payload, oid, kind))
    return out


def _number(raw: Any, what: str) -> float:
    try:
        v = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a number")
    if not math.isfinite(v):
        raise ValueError(f"{what} must be a number")
    return v


def _parse_capacity(payload: Dict[str, Any], oid: str, kind: str) -> Dict[str, Any]:
    """A capacity reading: the resource name, one limit (a number or an OID) and the warn and critical percents."""
    if kind != "gauge":
        raise ValueError("A capacity reading is a gauge: the amount in use now")
    resource = str(payload.get("cap_resource") or "").strip()[:40]
    if not resource or not all(ch.isprintable() for ch in resource):
        raise ValueError("Name the resource, for example DHCP scope")
    has_num = payload.get("cap_limit") not in (None, "")
    has_oid = payload.get("cap_limit_oid") not in (None, "")
    if has_num == has_oid:
        raise ValueError("Give the limit as a number or as the OID that holds it, not both")
    limit = limit_oid = None
    if has_num:
        limit = _number(payload.get("cap_limit"), "The limit")
        if not 0 < limit < 1e15:
            raise ValueError("The limit must be more than 0")
    else:
        limit_oid = normalise_oid(str(payload.get("cap_limit_oid")))
        if not limit_oid:
            raise ValueError("Enter the limit OID as numbers, for example 1.3.6.1.4.1.9.9.1.0")
        if limit_oid == oid:
            raise ValueError("The limit OID must differ from the value's OID")
    warn = _number(payload["cap_warn"], "The warning level") if payload.get("cap_warn") not in (None, "") else CAP_WARN
    crit = _number(payload["cap_crit"], "The critical level") if payload.get("cap_crit") not in (None, "") else CAP_CRIT
    if not 0 < warn < crit <= 100:
        raise ValueError("The warning level must be below the critical level, both between 1 and 100 percent")
    return {"cap_resource": resource, "cap_limit": limit, "cap_limit_oid": limit_oid, "cap_warn": warn, "cap_crit": crit}


def add(d: Dict[str, Any]) -> int:
    with database.get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO custom_oids (scope, target, oid, label, unit, kind, scale, alert_op, alert_value, alert_severity, created_at, "
            "cap_resource, cap_limit, cap_limit_oid, cap_warn, cap_crit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (d["scope"], d["target"], d["oid"], d["label"], d["unit"], d["kind"], d["scale"], d["alert_op"],
             d["alert_value"], d["alert_severity"], int(time.time()), d.get("cap_resource"), d.get("cap_limit"),
             d.get("cap_limit_oid"), d.get("cap_warn"), d.get("cap_crit")))
        conn.commit()
        return cur.lastrowid


def remove(def_id: int) -> Optional[Dict[str, Any]]:
    with database.get_connection() as conn:
        row = conn.execute("SELECT * FROM custom_oids WHERE id = ?;", (def_id,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM custom_oids WHERE id = ?;", (def_id,))
        conn.execute("DELETE FROM metric_latest WHERE metric_key IN (?, ?);", (f"custom.{def_id}", used_key(def_id)))
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


def used_key(def_id: int) -> str:
    """The used percent of a capacity reading."""
    return f"custom.{def_id}.used_pct"


def capacity_readings(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The device's capacity readings: id, metric key of the used percent, resource, label, warn and critical."""
    return [{"id": d["id"], "key": used_key(d["id"]), "resource": d["cap_resource"], "label": d["label"],
             "warn": d.get("cap_warn") or CAP_WARN, "crit": d.get("cap_crit") or CAP_CRIT,
             "limit": d.get("cap_limit"), "limit_oid": d.get("cap_limit_oid")}
            for d in for_device(device) if d.get("cap_resource")]


def poll(device: Dict[str, Any], timeout: float = 2.0, retries: int = 0, store: bool = True,
         now: Optional[float] = None) -> Dict[str, float]:
    """GETs the device's custom OIDs; stores numbers as metrics and text in the device table "custom"."""
    defs = for_device(device)
    if not defs:
        return {}
    oids = [d["oid"] for d in defs] + [d["cap_limit_oid"] for d in defs if d.get("cap_resource") and d.get("cap_limit_oid")]
    answers = poller.snmp_get_many(device["ip_address"], list(dict.fromkeys(oids)), poller.snmp_target(device),
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
            if d.get("cap_resource"):
                pct = used_pct(d, num, answers.get(d.get("cap_limit_oid")) if d.get("cap_limit_oid") else None)
                if pct is not None:
                    metrics[used_key(d["id"])] = pct
    if store:
        database.record_metrics(device["id"], metrics)
        database.replace_device_table(device["id"], "custom", texts)
    return metrics


def used_pct(d: Dict[str, Any], raw: float, raw_limit: Any = None) -> Optional[float]:
    """How much of the limit is in use, in percent. A limit OID is read in the same units as the
    value (the same scale applies to both); a fixed limit is in the shown units (after the scale)."""
    value = raw * d["scale"]
    if d.get("cap_limit_oid"):
        try:
            limit = float(raw_limit) * d["scale"]
        except (TypeError, ValueError):
            return None
    else:
        limit = d.get("cap_limit")
    if not isinstance(limit, (int, float)) or not math.isfinite(limit) or limit <= 0 or not math.isfinite(value):
        return None
    return round(max(0.0, 100.0 * value / limit), 2)


def metric_info(device: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Labels for the UI, in the shape server.metric_info gives profile metrics."""
    out = {}
    for d in for_device(device):
        if d["kind"] != "string":
            label = f"{d['label']} ({d['unit']})" if d["unit"] else d["label"]
            out[metric_key(d["id"])] = {"label": label, "unit": d["unit"], "group": "Custom OIDs", "custom": True}
            if d.get("cap_resource"):
                out[used_key(d["id"])] = {"label": f"{d['cap_resource']} used (%)", "unit": "%", "group": "Custom OIDs",
                                          "custom": True, "capacity": True}
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
