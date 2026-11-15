"""Maintenance windows: planned work during which alerts stay quiet.

A window covers every device, one device, one group or one tag, from a start to an end
(start in the future = scheduled). While a device is inside one:
  - its problems still open and are listed (the dashboard tells the truth), marked "during
    maintenance", but no Telegram message is sent for them, nor reminders, nor the matching
    "resolved" message;
  - a failed reachability check is recorded as planned downtime: it does not count against
    uptime and opens no incident (availability.record, planned=True).

Stored as one internal setting (a JSON list); ended windows stay in it a week, then move to the
maintenance_history table, where they are kept a year (the change log and the outage timeline read
both). A window can be marked as a change, with a short description of what was changed. A normal
backup carries them.
"""

import json
import time
from typing import Any, Dict, List, Optional

import database

KEY = "maintenance_windows"
SCOPES = ("all", "device", "group", "tag")
KEEP_ENDED_SECONDS = 7 * 86400          # in the short list (Settings, the dashboard)
KEEP_HISTORY_SECONDS = 365 * 86400      # in the history table, for the change log and the reports
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
    keep = [w for w in windows if w["end"] > now - KEEP_ENDED_SECONDS][-MAX_WINDOWS:]
    kept = {w["id"] for w in keep}
    # Windows that leave the short list are kept in the history (only those that began: a cancelled
    # scheduled one never happened).
    database.archive_maintenance_windows([w for w in windows if w["id"] not in kept and w["start"] <= now])
    database.purge_maintenance_history(int(now - KEEP_HISTORY_SECONDS))
    database.set_internal_setting(KEY, json.dumps(keep))


def _next_id(stored: List[Dict[str, Any]]) -> int:
    """Ids are never reused: the history holds older ones."""
    return max([x["id"] for x in stored] + [database.max_maintenance_history_id()]) + 1


def windows(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every stored window, newest start first, with its state (scheduled, active, ended)."""
    now = now if now is not None else time.time()
    out = []
    for w in _load():
        state = "scheduled" if w["start"] > now else "active" if w["end"] > now else "ended"
        out.append(dict(w, state=state))
    return sorted(out, key=lambda w: -w["start"])


def add(scope: str, target: str, start: float, end: float, note: str, by: str, now: Optional[float] = None,
        change_note: str = "") -> Dict[str, Any]:
    """Adds a window. change_note: what is being changed, which marks the window as a change."""
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
    change_note = str(change_note or "").strip()[:200]
    w = {"id": _next_id(stored), "scope": scope, "target": "" if scope == "all" else str(target).strip(),
         "start": int(start), "end": int(end), "note": str(note or "").strip()[:200], "by": by,
         "change": bool(change_note), "change_note": change_note}
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


def _state(w: Dict[str, Any], now: float) -> str:
    return "scheduled" if w["start"] > now else "active" if w["end"] > now else "ended"


def history(since: Optional[float] = None, until: Optional[float] = None, now: Optional[float] = None,
            changes_only: bool = False) -> List[Dict[str, Any]]:
    """Every window kept (the short list and the year of history) that overlaps since..until, newest
    start first, each with its state and change fields. changes_only: those marked as a change."""
    now = now if now is not None else time.time()
    out: Dict[int, Dict[str, Any]] = {}
    for w in database.list_maintenance_history(None if since is None else int(since), None if until is None else int(until)):
        out[w["id"]] = w
    for w in _load():
        if (since is None or w["end"] >= since) and (until is None or w["start"] <= until):
            out[w["id"]] = dict(w, change=bool(w.get("change")), change_note=w.get("change_note") or "")
    rows = [dict(w, state=_state(w, now)) for w in out.values() if not changes_only or w.get("change")]
    return sorted(rows, key=lambda w: (-w["start"], -w["id"]))


def set_change(window_id: int, change_note: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Marks a window as a change with what was changed, or clears the mark when change_note is
    empty. Works on the short list and on the history. Returns the window, or None when unknown."""
    now = now if now is not None else time.time()
    note = str(change_note or "").strip()[:200]
    stored = _load()
    hit = next((w for w in stored if w["id"] == window_id), None)
    if hit:
        hit["change"], hit["change_note"] = bool(note), note
        database.set_internal_setting(KEY, json.dumps(stored))
        return dict(hit, state=_state(hit, now))
    if database.set_maintenance_history_change(window_id, bool(note), note):
        return next((w for w in history(now=now) if w["id"] == window_id), None)
    return None


def members(w: Dict[str, Any], devices: List[Dict[str, Any]]) -> List[int]:
    """Ids of the devices (each with its effective group under "group") the window covers."""
    return [d["id"] for d in devices if covers(w, d)]
