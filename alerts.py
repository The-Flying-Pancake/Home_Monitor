"""Alert rules: the catalogue of conditions that open problems, and the administrator's overrides.

Every rule has defaults in code (built-in rules below, or a profile's
"alerts"). The administrator can override any field at three levels, each one
inheriting from the one above:

  global    all devices
  template  devices using one hardware profile (e.g. every QNAP NAS)
  device    one device

Fields:
  enabled      the rule raises problems at all
  severity     info, warning, high or critical ("" on the health rule means
               "as reported by the device")
  threshold    the limit, for rules that have one
  for_minutes  the condition must hold this long before the problem opens
               (0 = at once); a condition that clears while pending opens nothing
  telegram     default (send when the severity reaches the Notifications
               minimum), always or never
  resolved     on or off: also send a message when the problem clears

Overrides are stored one field per row (database.alert_overrides) so a
template can change only the threshold and still inherit the severity.
"""

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

SEVERITIES = ("info", "warning", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
SCOPES = ("global", "template", "device")
FIELDS = ("enabled", "severity", "threshold", "for_minutes", "telegram", "resolved", "sound")
TELEGRAM = ("default", "always", "never")
# Sound on the phone: default follows the silent window (notify_silent), always rings, silent never rings.
SOUND = ("default", "always", "silent")

# id, group, label, severity, threshold, unit, min, max, for_minutes, resolved message, help
BUILTIN: List[Tuple] = [
    ("unreachable", "Reachability", "Device unreachable", "critical", None, "", None, None, 0, "on",
     "No reply to ping. The resolved message is the 'back online' message."),
    ("service_down", "Reachability", "Service port not answering", "critical", None, "", None, None, 0, "on",
     "Port checks: the host answers ping but the service port refuses or times out. The resolved message is sent when it answers again."),
    ("service_slow", "Reachability", "Service slow to connect", "warning", 500.0, "ms", 1, 60000, 5, "off",
     "Port checks: the TCP connection takes longer than this."),
    ("snmp", "Reachability", "SNMP agent not responding", "warning", None, "", None, None, 0, "off",
     "The host answers ping but not SNMP: wrong community or the agent stopped."),
    ("snmp_view", "Reachability", "SNMP restricted view", "warning", None, "", None, None, 0, "off",
     "The agent only shows basic system information. Fix SNMP widens it."),
    ("restarted", "Reachability", "Device restarted", "info", None, "", None, None, 0, "off",
     "Under Active problems for a minute after it is seen; on the device for the first hour."),
    ("cert_expiry", "Reachability", "Certificate expiring", "warning", 21, "days", 1, 365, 0, "on",
     "Website checks on https:// addresses: the certificate the site presents runs out within this many days."),
    ("dns_down", "DNS", "DNS not answering", "critical", None, "", None, None, 2, "on",
     "Pi-hole: the test lookup got no answer. Every device in the house that uses it cannot reach anything by name."),
    ("dns_slow", "DNS", "DNS slow", "warning", 300, "ms", 10, 10000, 5, "off", "Pi-hole: the test lookup took longer than this."),
    ("pihole_blocking", "DNS", "Pi-hole blocking switched off", "warning", None, "", None, None, 5, "on",
     "Someone switched blocking off in Pi-hole (it may have a timer)."),
    ("pihole_lists", "DNS", "Pi-hole blocklists out of date", "info", 14, "days", 1, 365, 0, "off",
     "The blocklists (gravity) were last updated longer ago than this."),
    ("cpu", "Performance", "CPU usage", "warning", 90, "%", 1, 100, 10, "off", ""),
    ("mem", "Performance", "Memory used", "warning", 90, "%", 1, 100, 10, "off", "Excludes buffers and cache."),
    ("disk_full", "Storage", "Disk or volume full", "warning", 90, "%", 1, 100, 0, "off", ""),
    ("volume_state", "Storage", "Volume or RAID not healthy", "critical", None, "", None, None, 0, "on",
     "Degraded, crashed or offline volumes and pools."),
    ("disk_smart", "Storage", "Disk failing (SMART)", "critical", None, "", None, None, 0, "on", ""),
    ("forecast_full", "Storage", "Volume or disk filling up", "warning", 14, "days", 1, 365, 0, "off",
     "Opens when a volume or disk is at least 80% full and forecast to be full within this many days, from the way it grew over the last two weeks."),
    ("disk_temp", "Temperature", "Disk temperature", "warning", 55, "C", 30, 80, 5, "off",
     "Most NAS drives are rated to 60-65 C."),
    ("sensor_temp", "Temperature", "Host sensor temperature", "warning", 80, "C", 40, 110, 10, "off",
     "Linux host sensors: CPU package, NVMe, board."),
    ("health", "Hardware", "Hardware component or supply fault", "", None, "", None, None, 0, "on",
     "Fans, power supplies, toner and other components the device reports. Severity 'as reported' keeps the device's own level."),
    ("radio", "Network", "Wi-Fi channel utilisation", "warning", 70, "%", 1, 100, 15, "off", ""),
    ("wifi_weak", "Network", "Wi-Fi devices on weak signal", "warning", -75, "dBm", -95, -40, 15, "off",
     "UniFi: an access point has devices whose signal is weaker than this (-67 dBm is good for calls, below -80 barely works)."),
    ("port_errors", "Network", "Port errors", "warning", 1, "per poll", 1, 1000000, 0, "off",
     "Errors counted on a switch or host port since the previous poll."),
    ("pve_guest_down", "Proxmox", "Guest not running", "warning", None, "", None, None, 5, "on",
     "A VM or container set to start at boot is not running. Shown on the guest when it is monitored, otherwise on its node."),
    ("pve_guest_restarts", "Proxmox", "Guest keeps restarting", "warning", 3, "per hour", 2, 60, 0, "off",
     "A VM or container restarted this many times within an hour."),
    ("pve_guest_memory", "Proxmox", "Guest memory nearly full", "warning", 95, "%", 50, 100, 15, "off",
     "Memory a running VM or container uses, of what Proxmox gives it."),
    ("pve_guest_disk", "Proxmox", "Container disk nearly full", "warning", 90, "%", 50, 100, 0, "off",
     "A container's root disk (Proxmox cannot see inside a VM's disk without its guest agent)."),
    ("watch", "Services", "Watched service or process stopped", "warning", None, "", None, None, 0, "on",
     "Only for names ticked Watch on a device's Processes tab."),
    ("workflow", "Automation", "Workflow step failed", "warning", None, "", None, None, 0, "off",
     "Raised on the host where a step failed, until the workflow's next run gets past it. "
     "The Telegram message for a run is the 'Workflow finished' notification."),
]

# Problem key prefix -> built-in rule, where they differ.
KEY_RULE = {"storage": "disk_full", "volume_full": "disk_full"}


def rule_id_for_key(problem_key: str, profile_id: str) -> str:
    """The rule a stored problem belongs to (problem keys are "rule" or "rule:detail")."""
    head, _, rest = problem_key.partition(":")
    if head == "alert":
        return f"p:{profile_id}:{rest}"
    return KEY_RULE.get(head, head)


def profile_rules(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A profile's "alerts" as rules. An alert's id is its metric key, numbered when a key has several."""
    alerts = profile.get("alerts", [])
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a["key"]] = counts.get(a["key"], 0) + 1
    seen: Dict[str, int] = {}
    words = {s["key"]: s.get("values", {}) for s in profile.get("metrics", [])}
    labels = {s["key"]: s.get("label", s["key"]) for s in profile.get("metrics", [])}
    units = {s["key"]: s.get("unit", "") for s in profile.get("metrics", [])}
    out = []
    for a in alerts:
        n = seen[a["key"]] = seen.get(a["key"], 0) + 1
        aid = a.get("id") or (a["key"] if counts[a["key"]] == 1 else f"{a['key']}.{n}")
        op = next((k for k in ("below", "above") if k in a), None)
        word = words.get(a["key"], {})
        if op:
            label = f"{labels[a['key']]} {op}"
        else:
            states = " or ".join(word.get(str(v), str(v)) for v in a.get("in", a.get("not_in", [])))
            label = f"{labels[a['key']]} {'is not' if 'not_in' in a else 'is'} {states}"
        out.append({
            "id": f"p:{profile['profile_id']}:{aid}", "alert_id": aid, "profile_id": profile["profile_id"],
            "group": profile.get("name", profile["profile_id"]),
            "label": label,
            "severity": a.get("severity", "warning"), "threshold": a.get(op) if op else None,
            "unit": {"percent": "%", "celsius": "C", "minutes": "min"}.get(units.get(a["key"], ""), units.get(a["key"], "")),
            "min": None if not op else -1000000, "max": None if not op else 1000000,
            "for_minutes": 0, "resolved": "on" if a.get("severity") == "critical" else "off", "help": "",
            "key": a["key"], "op": op, "values": a.get("in", a.get("not_in")), "negate": "not_in" in a,
            "message": a["message"], "words": word,
        })
    return out


def builtin_rules() -> List[Dict[str, Any]]:
    names = ("id", "group", "label", "severity", "threshold", "unit", "min", "max", "for_minutes", "resolved", "help")
    return [dict(zip(names, row)) for row in BUILTIN]


def catalogue(profiles: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Every rule by id: built-in first, then each profile's rules."""
    rules = {r["id"]: r for r in builtin_rules()}
    for p in profiles:
        for r in profile_rules(p):
            rules[r["id"]] = r
    return rules


def defaults(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {"enabled": True, "severity": rule["severity"], "threshold": rule["threshold"],
            "for_minutes": rule["for_minutes"], "telegram": "default", "resolved": rule["resolved"], "sound": "default"}


def parse_value(rule: Dict[str, Any], field: str, raw: Any) -> Any:
    """Validates one override value. Raises ValueError with a message for the administrator."""
    if field == "enabled":
        if not isinstance(raw, bool):
            raise ValueError("enabled must be true or false")
        return raw
    if field == "severity":
        allowed = SEVERITIES + (("",) if rule["id"] == "health" else ())
        if raw not in allowed:
            raise ValueError(f"severity must be one of {', '.join(s or 'as reported' for s in allowed)}")
        return raw
    if field == "threshold":
        if rule["threshold"] is None:
            raise ValueError(f"{rule['label']} has no threshold")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError("threshold must be a number")
        if not rule["min"] <= raw <= rule["max"]:
            raise ValueError(f"threshold must be {rule['min']} to {rule['max']}")
        return float(raw)
    if field == "for_minutes":
        if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= 1440:
            raise ValueError("for_minutes must be a whole number of minutes from 0 to 1440")
        return raw
    if field == "telegram":
        if raw not in TELEGRAM:
            raise ValueError("telegram must be default, always or never")
        return raw
    if field == "resolved":
        if raw not in ("on", "off"):
            raise ValueError("resolved must be on or off")
        return raw
    if field == "sound":
        if raw not in SOUND:
            raise ValueError("sound must be default, always or silent")
        return raw
    raise ValueError(f"unknown field {field}")


def decode(field: str, text: str) -> Any:
    """Stored override text back to its value."""
    if field == "enabled":
        return text == "1"
    if field == "threshold":
        return float(text)
    if field == "for_minutes":
        return int(text)
    return text


def encode(field: str, value: Any) -> str:
    if field == "enabled":
        return "1" if value else "0"
    return str(value)


# Where a value can be set, widest first; each one overrides the ones before it.
SCOPES = ("default", "global", "template", "tag", "device")


def _tags_of(device: Dict[str, Any]) -> List[str]:
    raw = device.get("tags")
    if isinstance(raw, list):
        return [str(t) for t in raw]
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [str(t) for t in value] if isinstance(value, list) else []


class Policy:
    """Effective rule settings, built once per evaluation from the stored overrides.

    Chain: defaults, all devices (global), the device's template, each of its tags (in the tag
    list's order, so the lowest tag wins a conflict), the device itself."""

    def __init__(self, rules: Dict[str, Dict[str, Any]], overrides: List[Dict[str, Any]],
                 tag_rank: Optional[Dict[str, int]] = None) -> None:
        self.rules = rules
        self.tag_rank = tag_rank or {}
        self.layers: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = {}
        for o in overrides:
            if o["rule_id"] in rules and o["field"] in FIELDS:
                try:
                    value = decode(o["field"], o["value"])
                except ValueError:
                    continue
                self.layers.setdefault((o["scope"], o["target"]), {}).setdefault(o["rule_id"], {})[o["field"]] = value

    def ordered_tags(self, tags: List[str]) -> List[str]:
        return sorted(tags, key=lambda t: (self.tag_rank.get(t.lower(), len(self.tag_rank)), t.lower()))

    def resolve(self, rule_id: str, profile_id: str = "", device_id: Optional[int] = None,
                upto: str = "device", tags: Optional[List[str]] = None) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """(effective values, where each value came from: default, global, template, tag:<name> or device).

        upto stops the chain at a scope ("default" applies no overrides), which gives
        the value a field would inherit without that scope's own override. tags are the
        device's tags (or the one tag being edited).
        """
        rule = self.rules[rule_id]
        values = defaults(rule)
        source = {f: "default" for f in FIELDS}
        level = SCOPES.index(upto)
        chain = [("global", "")] if level >= 1 else []
        if level >= 2 and profile_id:
            chain.append(("template", profile_id))
        if level >= 3:
            chain += [("tag", t) for t in self.ordered_tags(list(tags or []))]
        if level >= 4 and device_id is not None:
            chain.append(("device", str(device_id)))
        for scope, target in chain:
            for field, value in self.layers.get((scope, target), {}).get(rule_id, {}).items():
                values[field] = value
                source[field] = f"tag:{target}" if scope == "tag" else scope
        return values, source

    def for_device(self, device: Dict[str, Any]) -> Callable[[str], Dict[str, Any]]:
        """rule_id -> effective values for this device. Unknown ids get the defaults of a warning rule."""
        cache: Dict[str, Dict[str, Any]] = {}

        def get(rule_id: str) -> Dict[str, Any]:
            if rule_id not in cache:
                if rule_id in self.rules:
                    cache[rule_id] = self.resolve(rule_id, device.get("profile_id", ""), device.get("id"),
                                                  tags=_tags_of(device))[0]
                else:
                    cache[rule_id] = {"enabled": True, "severity": "warning", "threshold": None, "for_minutes": 0,
                                      "telegram": "default", "resolved": "off", "sound": "default"}
            return cache[rule_id]
        return get

    def overridden_here(self, rule_id: str, scope: str, target: str) -> Dict[str, Any]:
        return dict(self.layers.get((scope, target), {}).get(rule_id, {}))


def default_policy(profiles: Optional[List[Dict[str, Any]]] = None) -> Policy:
    return Policy(catalogue(profiles or []), [])


def should_send(rule: Dict[str, Any], severity: str, min_severity: str) -> bool:
    """Telegram decision for one problem: the rule's own choice, else the minimum severity."""
    if rule.get("telegram") == "always":
        return True
    if rule.get("telegram") == "never":
        return False
    return RANK.get(severity, 0) >= RANK.get(min_severity, 1)
