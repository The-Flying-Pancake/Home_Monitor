"""Maintenance windows: planned work during which alerts stay quiet.

A window covers every device, one device, one group or one tag, from a start to an end
(start in the future = scheduled). While a device is inside one:
  - its problems still open and are listed (the dashboard tells the truth), marked "during
    maintenance", but no Telegram message is sent for them, nor reminders, nor the matching
    "resolved" message;
  - a failed reachability check is recorded as planned downtime: it does not count against
    uptime and opens no incident (availability.record, planned=True).

Stored as one internal setting (a JSON list); ended windows are kept a week for the record,
then dropped. A normal backup carries them.
"""

import json
import time
from typing import Any, Dict, List, Optional

import database

KEY = "maintenance_windows"
SCOPES = ("all", "device", "group", "tag")
KEEP_ENDED_SECONDS = 7 * 86400
MAX_SECONDS = 14 * 86400
MAX_WINDOWS = 100


class MaintenanceError(ValueError):
    pass


def _load() -> List[Dict[str, Any]]:
    try:
        value = json.loads(database.get_all_settings().get(KEY) or "[]")
        return value if isinstance(value, list) else []
    except ValueError:
        return []


def _save(windows: List[Dict[str, Any]], now: float) -> None:
    keep = [w for w in windows if w["end"] > now - KEEP_ENDED_SECONDS]
    database.set_internal_setting(KEY, json.dumps(keep[-MAX_WINDOWS:]))


def windows(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every stored window, newest start first, with its state (scheduled, active, ended)."""
    now = now if now is not None else time.time()
    out = []
    for w in _load():
        state = "scheduled" if w["start"] > now else "active" if w["end"] > now else "ended"
        out.append(dict(w, state=state))
    return sorted(out, key=lambda w: -w["start"])


def add(scope: str, target: str, start: float, end: float, note: str, by: str, now: Optional[float] = None) -> Dict[str, Any]:
    now = now if now is not None else time.time()
    if scope not in SCOPES:
        raise MaintenanceError("Cover every device, one device, one group or one tag")
    if scope != "all" and not str(target or "").strip():
        raise MaintenanceError("Choose what the window covers")
    start, end = float(start), float(end)
    if end <= start:
        raise MaintenanceError("The window must end after it starts")
    if end <= now:
        raise MaintenanceError("The window has already ended")
    if end - start > MAX_SECONDS:
        raise MaintenanceError("A window can last at most 14 days")
    stored = _load()
    w = {"id": max([x["id"] for x in stored] or [0]) + 1, "scope": scope, "target": "" if scope == "all" else str(target).strip(),
         "start": int(start), "end": int(end), "note": str(note or "").strip()[:200], "by": by}
    stored.append(w)
    _save(stored, now)
    return w


def end(window_id: int, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Ends a window now (a scheduled one is removed). Returns it, or None when unknown."""
    now = now if now is not None else time.time()
    stored = _load()
    hit = next((w for w in stored if w["id"] == window_id), None)
    if not hit:
        return None
    if hit["start"] > now:
        stored = [w for w in stored if w["id"] != window_id]
    else:
        hit["end"] = int(min(hit["end"], now))
    _save(stored, now)
    return hit


def end_at(window_id: int, when: float, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Brings a window's end forward to when (never later than it was). For a workflow that lifts
    its quiet when it finishes, a few minutes on."""
    now = now if now is not None else time.time()
    stored = _load()
    hit = next((w for w in stored if w["id"] == window_id), None)
    if not hit:
        return None
    hit["end"] = int(max(hit["start"], min(hit["end"], when)))
    _save(stored, now)
    return hit


def covers(w: Dict[str, Any], device: Dict[str, Any]) -> bool:
    if w["scope"] == "all":
        return True
    if w["scope"] == "device":
        return str(device.get("id")) == w["target"]
    if w["scope"] == "group":
        return device.get("group") == w["target"] or device.get("device_group") == w["target"]
    tags = device.get("tags") or []
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except ValueError:
            tags = []
    return any(str(t).lower() == w["target"].lower() for t in tags)


def active_for(device: Optional[Dict[str, Any]], now: Optional[float] = None,
               current: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """The window the device is in right now, or None. current: windows() already loaded."""
    if not device:
        return None
    now = now if now is not None else time.time()
    for w in current if current is not None else windows(now):
        if w["start"] <= now < w["end"] and covers(w, device):
            return w
    return None
