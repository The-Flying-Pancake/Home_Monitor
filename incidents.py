"""Incident records: a light, person-written record of something that went wrong.

Sized for a home lab, not a service desk. An incident (INC-0001) has a title, a priority (P1, P2,
P3), a status (Open, Investigating, Monitoring, Resolved), an owner (free text, often a user's
name), when it started and was resolved, the devices it touched, the problems it grew from, a
summary, the root cause, the impact, the next step, a timeline of notes and follow-up actions
(each with an owner, a due date and Plan, In progress or Done).

One can be made from scratch or from an open problem (its device, start and the problem are filled
in). Who may see one follows device access: an incident is visible to a user limited to some
devices only when it has devices and every one of them is inside that access (server.py checks).
This module checks the fields and keeps the timeline; database.py stores them.
"""

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import database

PRIORITIES = ("P1", "P2", "P3")
STATUSES = ("Open", "Investigating", "Monitoring", "Resolved")
ACTION_STATUSES = ("Plan", "In progress", "Done")
TEXT_FIELDS = {"summary": 4000, "root_cause": 4000, "impact": 4000, "next_step": 500}
MAX_TITLE = 120
MAX_OWNER = 64
MAX_NOTE = 2000
MAX_ACTION = 300
MAX_DEVICES = 50
MAX_NOTES = 500
MAX_ACTIONS = 50
DUE = re.compile(r"\d{4}-\d{2}-\d{2}")


class IncidentError(ValueError):
    """A field that cannot be used, in words for the person."""


def ref(incident_id: int) -> str:
    return f"INC-{int(incident_id):04d}"


def priority_for(severity: str) -> str:
    """The priority an incident made from a problem starts with: critical and high P1, warning P2."""
    return {"critical": "P1", "high": "P1", "warning": "P2"}.get(str(severity or ""), "P3")


def _text(payload: Dict[str, Any], key: str, limit: int, required: str = "") -> str:
    value = payload.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise IncidentError(f"{key.replace('_', ' ').capitalize()} must be text")
    value = value.replace("\r\n", "\n").strip()
    if required and not value:
        raise IncidentError(required)
    if len(value) > limit:
        raise IncidentError(f"{key.replace('_', ' ').capitalize()} can be at most {limit} characters")
    return value


def _time(payload: Dict[str, Any], key: str, now: int) -> Optional[int]:
    value = payload.get(key)
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IncidentError("A time must be a number of seconds")
    value = int(value)
    if value < 946684800 or value > now + 86400:
        raise IncidentError("That time is not one the monitor can use")
    return value


def clean_fields(payload: Dict[str, Any], partial: bool, now: Optional[int] = None) -> Dict[str, Any]:
    """The incident fields in the payload, checked. partial: only those present (an update)."""
    now = int(now if now is not None else time.time())
    out: Dict[str, Any] = {}
    if not partial or "title" in payload:
        out["title"] = _text(payload, "title", MAX_TITLE, required="Give the incident a short title")
    if not partial or "priority" in payload:
        p = payload.get("priority") or "P3"
        if p not in PRIORITIES:
            raise IncidentError("Priority is P1, P2 or P3")
        out["priority"] = p
    if not partial or "status" in payload:
        s = payload.get("status") or "Open"
        if s not in STATUSES:
            raise IncidentError("Status is Open, Investigating, Monitoring or Resolved")
        out["status"] = s
    if not partial or "owner" in payload:
        out["owner"] = _text(payload, "owner", MAX_OWNER)
    for key, limit in TEXT_FIELDS.items():
        if not partial or key in payload:
            out[key] = _text(payload, key, limit)
    if not partial or "started_at" in payload:
        out["started_at"] = _time(payload, "started_at", now) or now
    if "resolved_at" in payload:
        out["resolved_at"] = _time(payload, "resolved_at", now)
    return out


def clean_action(payload: Dict[str, Any], partial: bool) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not partial or "description" in payload:
        out["description"] = _text(payload, "description", MAX_ACTION, required="Describe the action")
    if not partial or "owner" in payload:
        out["owner"] = _text(payload, "owner", MAX_OWNER)
    if not partial or "due" in payload:
        due = _text(payload, "due", 10)
        if due:
            if not DUE.fullmatch(due):
                raise IncidentError("A due date looks like 2026-11-30")
            try:
                datetime.strptime(due, "%Y-%m-%d")
            except ValueError:
                raise IncidentError("That due date does not exist")
        out["due"] = due
    if not partial or "status" in payload:
        s = payload.get("status") or "Plan"
        if s not in ACTION_STATUSES:
            raise IncidentError("An action is Plan, In progress or Done")
        out["status"] = s
    return out


def _resolve_times(fields: Dict[str, Any], before: Optional[Dict[str, Any]], now: int) -> None:
    """Resolved gets its time when the status becomes Resolved and loses it when it leaves."""
    status = fields.get("status", (before or {}).get("status", "Open"))
    if status == "Resolved":
        if not fields.get("resolved_at") and not (before or {}).get("resolved_at"):
            fields["resolved_at"] = now
        start = fields.get("started_at", (before or {}).get("started_at") or now)
        if fields.get("resolved_at") and fields["resolved_at"] < start:
            raise IncidentError("An incident cannot be resolved before it started")
    elif before is None or "status" in fields:
        fields["resolved_at"] = None


def view(inc: Dict[str, Any], open_problems: Optional[set] = None, now: Optional[int] = None) -> Dict[str, Any]:
    """The incident for the page and the reports: its reference, duration, open actions and which
    linked problems are still open (open_problems: a set of (device_id, problem_key))."""
    now = int(now if now is not None else time.time())
    end = inc.get("resolved_at") or now
    out = dict(inc, ref=ref(inc["id"]), seconds=max(0, end - inc["started_at"]),
               open_actions=sum(1 for a in inc.get("actions", []) if a["status"] != "Done"))
    if open_problems is not None:
        out["problems"] = [dict(p, open=(p["device_id"], p["problem_key"]) in open_problems) for p in inc.get("problems", [])]
    return out


def create(fields: Dict[str, Any], devices: List[Tuple[int, str]], by: str, problem: Optional[Dict[str, Any]] = None,
           now: Optional[int] = None) -> Dict[str, Any]:
    """Adds an incident (fields from clean_fields) with its devices and, when given, the open problem
    it grew from. Returns it."""
    now = int(now if now is not None else time.time())
    if len(devices) > MAX_DEVICES:
        raise IncidentError(f"An incident lists at most {MAX_DEVICES} devices")
    fields = dict(fields)
    _resolve_times(fields, None, now)
    incident_id = database.add_incident(fields, devices, by, now=now)
    database.add_incident_note(incident_id, f"Opened by {by}" + (f" from the problem: {problem['message']}" if problem else ""),
                               by, kind="status", now=now)
    if problem:
        database.link_incident_problem(incident_id, problem["device_id"], problem["problem_key"], problem.get("message") or "",
                                       problem.get("since"), now=now)
    return database.get_incident(incident_id)


def update(incident_id: int, fields: Dict[str, Any], devices: Optional[List[Tuple[int, str]]], by: str,
           now: Optional[int] = None) -> Tuple[Dict[str, Any], List[str]]:
    """Changes an incident. Returns it and the names of what changed. A status change is written to
    its timeline."""
    now = int(now if now is not None else time.time())
    before = database.get_incident(incident_id)
    if before is None:
        raise IncidentError("No such incident")
    if devices is not None and len(devices) > MAX_DEVICES:
        raise IncidentError(f"An incident lists at most {MAX_DEVICES} devices")
    fields = {k: v for k, v in fields.items() if before.get(k) != v}
    _resolve_times(fields, before, now)
    fields = {k: v for k, v in fields.items() if before.get(k) != v}
    if devices is not None and sorted(d for d, _ in devices) == sorted(d["id"] for d in before["devices"]):
        devices = None
    database.update_incident(incident_id, fields, devices, now=now)
    changed = list(fields) + (["devices"] if devices is not None else [])
    if "status" in fields:
        database.add_incident_note(incident_id, f"Status {before['status']} to {fields['status']} by {by}", by, kind="status", now=now)
    elif "priority" in fields:
        database.add_incident_note(incident_id, f"Priority {before['priority']} to {fields['priority']} by {by}", by, kind="status", now=now)
    return database.get_incident(incident_id), changed


def add_note(incident_id: int, text: Any, by: str, now: Optional[int] = None) -> int:
    inc = database.get_incident(incident_id)
    if inc is None:
        raise IncidentError("No such incident")
    text = _text({"note": text}, "note", MAX_NOTE, required="Write the note first")
    if len(inc["notes"]) >= MAX_NOTES:
        raise IncidentError(f"An incident holds at most {MAX_NOTES} notes")
    return database.add_incident_note(incident_id, text, by, now=now)


def add_action(incident_id: int, payload: Dict[str, Any], now: Optional[int] = None) -> int:
    inc = database.get_incident(incident_id)
    if inc is None:
        raise IncidentError("No such incident")
    if len(inc["actions"]) >= MAX_ACTIONS:
        raise IncidentError(f"An incident holds at most {MAX_ACTIONS} actions")
    a = clean_action(payload, partial=False)
    return database.add_incident_action(incident_id, a["description"], a["owner"], a["due"], a["status"], now=now)


def update_action(incident_id: int, action_id: int, payload: Dict[str, Any], now: Optional[int] = None) -> bool:
    fields = clean_action(payload, partial=True)
    if not fields:
        raise IncidentError("Nothing to change")
    return database.update_incident_action(incident_id, action_id, fields, now=now)


def link_problem(incident_id: int, problem: Dict[str, Any], now: Optional[int] = None) -> bool:
    return database.link_incident_problem(incident_id, problem["device_id"], problem["problem_key"], problem.get("message") or "",
                                          problem.get("since"), now=now)


def from_problem(problem: Dict[str, Any], hostname: str) -> Dict[str, Any]:
    """The fields of an incident made from an open problem: its text, priority and start."""
    title = f"{hostname}: {problem.get('message') or problem.get('problem_key')}"
    if len(title) > MAX_TITLE:
        title = title[:MAX_TITLE - 3].rstrip() + "..."
    return {"title": title, "priority": priority_for(problem.get("severity")), "status": "Open", "owner": "",
            "summary": "", "root_cause": "", "impact": "", "next_step": "",
            "started_at": int(problem.get("since") or time.time())}


def visible_to(inc: Dict[str, Any], unscoped: bool, sees_id) -> bool:
    """Whether a user may see the incident: everyone who sees every device; otherwise only when it
    has devices and every one is inside the user's device access (sees_id)."""
    if unscoped:
        return True
    ids = [d["id"] for d in inc.get("devices", [])]
    return bool(ids) and all(sees_id(i) for i in ids)


def message_values(inc: Dict[str, Any], now: Optional[int] = None) -> Dict[str, Any]:
    """Values for the Telegram texts (notify.EVENTS incident_opened and incident_resolved)."""
    now = int(now if now is not None else time.time())
    secs = max(0, (inc.get("resolved_at") or now) - inc["started_at"])
    hours, rest = divmod(secs // 60, 60)
    duration = f"{hours}h {rest}m" if hours else f"{rest}m"
    return {"incident": ref(inc["id"]), "title": inc["title"], "priority": inc["priority"], "status": inc["status"],
            "owner": inc.get("owner") or "", "duration": duration,
            "device": ", ".join(d["name"] for d in inc.get("devices", [])[:5])}
