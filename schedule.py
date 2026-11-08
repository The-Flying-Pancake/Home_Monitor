"""Workflow schedules entered as a date and time, not as cron.

The editor sends a schedule object; this module validates it, turns the
recurring kinds into a cron expression for the scheduler (ssh_runner.cron_matches)
and describes any schedule in plain English. Times are the server's local time.

Kinds:
  manual    never runs on its own
  once      {date: YYYY-MM-DD, time: HH:MM}: one run at that moment (run_at)
  daily     {time}
  weekly    {weekdays: [0..6], time}       0 = Sunday
  monthly   {day: 1..31, time}             months without that day are skipped
  interval  {every: N, unit: minutes|hours}, N divides the hour or the day so runs stay evenly spaced
  cron      {cron}: an expression kept from an older workflow ("Custom")
  event     {when: {...}, cooldown_minutes}: "When something happens" on one device; evaluated by
            workflows.TriggerWatcher after every problem pass, not by the clock. when.type:
              metric     {metric, op: above|below, value, for_minutes}
              snmp_down  {for_minutes}   ping answers, SNMP does not
              offline    {for_minutes}
              online     {}              fires when the device comes back
              watch      {name}          a watched service or process stops ("" = any)
              problem    {rule, min_severity}  a problem opens ("" rule = any)
            The device id is checked against the devices by workflows.parse_graph.
"""

import re
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import ssh_runner

KINDS = ("manual", "once", "daily", "weekly", "monthly", "interval", "cron", "event")
EVENT_TYPES = ("metric", "snmp_down", "offline", "online", "watch", "problem")
SEVERITIES = ("info", "warning", "high", "critical")
_METRIC_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
MINUTE_STEPS = (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30)
HOUR_STEPS = (1, 2, 3, 4, 6, 8, 12)
DAY_NAMES = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
# A one-off run missed while the monitor was stopped still runs if it is at most this late.
ONCE_GRACE_SECONDS = 3600

_TIME = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


class ScheduleError(ValueError):
    pass


def _time(raw: Dict[str, Any]) -> str:
    t = raw.get("time")
    if not isinstance(t, str) or not _TIME.fullmatch(t):
        raise ScheduleError("choose a time")
    return t


def once_timestamp(date: str, at: str) -> int:
    """Local date and time to a Unix timestamp. Raises ScheduleError for an impossible date."""
    m = _DATE.fullmatch(date or "")
    if not m or not _TIME.fullmatch(at or ""):
        raise ScheduleError("choose a date and a time")
    try:
        when = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(at[:2]), int(at[3:]))
    except ValueError:
        raise ScheduleError("that date does not exist")
    return int(time.mktime(when.timetuple()))


def parse(raw: Any, now: Optional[float] = None, allow_past_once: bool = False) -> Dict[str, Any]:
    """Validates and normalises a schedule object. A new one-off run must be in the future."""
    if raw is None:
        return {"kind": "manual"}
    if not isinstance(raw, dict) or raw.get("kind") not in KINDS:
        raise ScheduleError("unknown schedule type")
    kind = raw["kind"]
    if kind == "manual":
        return {"kind": "manual"}
    if kind == "event":
        return parse_event(raw)
    if kind == "once":
        out = {"kind": "once", "date": raw.get("date"), "time": raw.get("time")}
        ts = once_timestamp(out["date"], out["time"])
        if raw.get("done") is True:
            out["done"] = True
        elif not allow_past_once and ts < (now if now is not None else time.time()) - 60:
            raise ScheduleError("that date and time has already passed")
        return out
    if kind == "daily":
        return {"kind": "daily", "time": _time(raw)}
    if kind == "weekly":
        days = raw.get("weekdays")
        if not isinstance(days, list) or not days or \
                not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in days):
            raise ScheduleError("tick at least one day")
        return {"kind": "weekly", "weekdays": sorted(set(days)), "time": _time(raw)}
    if kind == "monthly":
        day = raw.get("day")
        if not isinstance(day, int) or isinstance(day, bool) or not 1 <= day <= 31:
            raise ScheduleError("choose a day of the month from 1 to 31")
        return {"kind": "monthly", "day": day, "time": _time(raw)}
    if kind == "interval":
        unit, every = raw.get("unit"), raw.get("every")
        allowed = MINUTE_STEPS if unit == "minutes" else HOUR_STEPS if unit == "hours" else ()
        if every not in allowed or isinstance(every, bool):
            raise ScheduleError("choose how often")
        return {"kind": "interval", "every": every, "unit": unit}
    cron = raw.get("cron")
    if not isinstance(cron, str) or len(cron) > 100:
        raise ScheduleError("custom schedule must be a cron expression")
    try:
        ssh_runner.parse_cron(cron.strip())
    except ValueError as exc:
        raise ScheduleError(f"custom schedule: {exc}")
    return {"kind": "cron", "cron": " ".join(cron.split())}


def _minutes(raw: Dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    v = raw.get(key, default)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ScheduleError(f"{key.replace('_', ' ')} must be {lo} to {hi}")
    return v


def parse_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Validates an event trigger's shape (not whether its device exists)."""
    when = raw.get("when")
    if not isinstance(when, dict) or when.get("type") not in EVENT_TYPES:
        raise ScheduleError("choose what should start the workflow")
    dev = when.get("device_id")
    if not isinstance(dev, int) or isinstance(dev, bool) or dev < 1:
        raise ScheduleError("choose the device to watch")
    out: Dict[str, Any] = {"type": when["type"], "device_id": dev}
    t = when["type"]
    if t == "metric":
        metric, op, value = when.get("metric"), when.get("op"), when.get("value")
        if not isinstance(metric, str) or not _METRIC_KEY.fullmatch(metric):
            raise ScheduleError("choose a measurement")
        if op not in ("above", "below"):
            raise ScheduleError("choose above or below")
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not -1e12 < value < 1e12:
            raise ScheduleError("enter the threshold as a number")
        out.update(metric=metric, op=op, value=float(value), for_minutes=_minutes(when, "for_minutes", 0, 0, 1440))
    elif t in ("snmp_down", "offline"):
        out["for_minutes"] = _minutes(when, "for_minutes", 0, 0, 1440)
    elif t == "watch":
        name = when.get("name", "")
        if not isinstance(name, str) or len(name) > 128:
            raise ScheduleError("the watched name is up to 128 characters")
        out["name"] = name.strip()
    elif t == "problem":
        rule, sev = when.get("rule", ""), when.get("min_severity", "warning")
        if not isinstance(rule, str) or len(rule) > 80:
            raise ScheduleError("unknown alert rule")
        if sev not in SEVERITIES:
            raise ScheduleError("choose a minimum severity")
        out.update(rule=rule.strip(), min_severity=sev)
    return {"kind": "event", "when": out, "cooldown_minutes": _minutes(raw, "cooldown_minutes", 30, 1, 1440)}


def to_trigger(s: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[int]]:
    """(trigger_type, cron, run_at) stored on the workflow row for the scheduler."""
    kind = s["kind"]
    if kind == "event":
        return "event", None, None
    if kind == "once":
        if s.get("done"):
            return "manual", None, None
        return "once", None, once_timestamp(s["date"], s["time"])
    if kind == "manual":
        return "manual", None, None
    if kind == "cron":
        return "schedule", s["cron"], None
    if kind == "interval":
        cron = f"*/{s['every']} * * * *" if s["unit"] == "minutes" else f"0 */{s['every']} * * *"
        return "schedule", cron, None
    hh, mm = int(s["time"][:2]), int(s["time"][3:])
    if kind == "daily":
        return "schedule", f"{mm} {hh} * * *", None
    if kind == "weekly":
        return "schedule", f"{mm} {hh} * * {','.join(str(d) for d in s['weekdays'])}", None
    return "schedule", f"{mm} {hh} {s['day']} * *", None


def from_cron(cron: Optional[str]) -> Dict[str, Any]:
    """Best-effort picker form of an existing cron expression; "cron" kind when it does not map."""
    if not cron:
        return {"kind": "manual"}
    f = cron.split()
    if len(f) != 5:
        return {"kind": "cron", "cron": cron}
    mi, hr, dom, mon, dow = f
    num = re.compile(r"\d{1,2}")
    if mon == "*" and num.fullmatch(mi) and num.fullmatch(hr) and int(mi) < 60 and int(hr) < 24:
        t = f"{int(hr):02d}:{int(mi):02d}"
        if dom == "*" and dow == "*":
            return {"kind": "daily", "time": t}
        if dom == "*" and re.fullmatch(r"[0-7](,[0-7])*", dow):
            return {"kind": "weekly", "weekdays": sorted({int(d) % 7 for d in dow.split(",")}), "time": t}
        if dow == "*" and num.fullmatch(dom) and 1 <= int(dom) <= 31:
            return {"kind": "monthly", "day": int(dom), "time": t}
    m = re.fullmatch(r"\*/(\d+)", mi)
    if m and hr == dom == mon == dow == "*" and int(m.group(1)) in MINUTE_STEPS:
        return {"kind": "interval", "every": int(m.group(1)), "unit": "minutes"}
    m = re.fullmatch(r"\*/(\d+)", hr)
    if m and mi == "0" and dom == mon == dow == "*" and int(m.group(1)) in HOUR_STEPS:
        return {"kind": "interval", "every": int(m.group(1)), "unit": "hours"}
    return {"kind": "cron", "cron": cron}


def _ordinal(n: int) -> str:
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def describe(s: Optional[Dict[str, Any]]) -> str:
    """Plain English, for example "Every Sunday at 04:00"."""
    kind = (s or {}).get("kind", "manual")
    if kind == "manual":
        return "Manual"
    if kind == "event":
        return "When something happens"
    if kind == "once":
        return f"Once on {s['date']} at {s['time']}" + (" (done)" if s.get("done") else "")
    if kind == "daily":
        return f"Every day at {s['time']}"
    if kind == "weekly":
        days = s["weekdays"]
        if days == [1, 2, 3, 4, 5]:
            names = "weekday"
        elif days == [0, 6]:
            names = "Saturday and Sunday"
        elif len(days) == 7:
            return f"Every day at {s['time']}"
        else:
            parts = [DAY_NAMES[d] for d in days]
            names = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
        return f"Every {names} at {s['time']}"
    if kind == "monthly":
        return f"Monthly on the {_ordinal(s['day'])} at {s['time']}"
    if kind == "interval":
        n, unit = s["every"], s["unit"]
        return f"Every {unit[:-1]}" if n == 1 else f"Every {n} {unit}"
    return f"Custom (cron {s['cron']})"
