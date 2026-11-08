"""Device groups and tags.

Groups: every device sits in exactly one. The built-in groups follow the template's category
(a switch template puts a device in Switches); the administrator can add groups of their own, rename
any group, put them in any order, and move a device to any group in Edit device (the
device_group column; empty means "as the template says"). Deleting a custom group sends its
devices back to their template's group.

Tags: any number per device (the devices.tags column, a JSON list), for whatever cuts across
groups: a room, an owner, "critical", "lab". The catalogue keeps each tag's colour,
description and order; a tag used on a device is added to it automatically. Tags are an
alert rule scope (alerts.py): between the template and the device, applied in catalogue
order, so a lower tag in the list wins when two tags set the same field. Renaming a tag
renames it on every device and in its alert rules; deleting it removes both.

Storage: settings rows (internal, not in the settings schema): taxonomy_groups (custom
groups and renamed built-ins), taxonomy_group_order, taxonomy_tags.
"""

import json
import re
from typing import Any, Dict, List, Optional

import database

# id -> (label, default order). The template category decides which of these a device is in.
BUILTIN_GROUPS = {
    "gateway": ("Gateways and routers", 10), "switch": ("Switches", 20), "wireless_ap": ("Access points", 30),
    "nas": ("NAS and storage", 40), "server": ("Servers and hypervisors", 50), "workstation": ("Computers", 60),
    "power": ("Power (UPS and PDU)", 65), "printer": ("Printers", 68), "service": ("Services (port checks)", 70),
    "other": ("Other devices", 90),
}
GROUPS_KEY, ORDER_KEY, TAGS_KEY = "taxonomy_groups", "taxonomy_group_order", "taxonomy_tags"
TAG_COLOURS = ("blue", "green", "yellow", "red", "purple", "teal", "orange", "grey")
# Colours given to new tags in turn. Red only when chosen: it reads as an alarm.
AUTO_COLOURS = ("blue", "green", "purple", "teal", "orange", "yellow")
MAX_GROUPS, MAX_TAGS, MAX_TAGS_PER_DEVICE = 50, 200, 20
_TAG = re.compile(r"^[\w][\w .:/+-]{0,31}$", re.UNICODE)


class TaxonomyError(ValueError):
    pass


def _load(key: str, default: Any) -> Any:
    raw = database.get_all_settings().get(key)
    try:
        value = json.loads(raw) if raw else default
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def _save(key: str, value: Any) -> None:
    database.set_internal_setting(key, json.dumps(value, sort_keys=True))


# --- Groups ---

def groups() -> List[Dict[str, Any]]:
    """Every group in display order: [{id, name, builtin}]."""
    stored = _load(GROUPS_KEY, {})            # id -> {"name": ..., "custom": bool}
    out = {gid: {"id": gid, "name": (stored.get(gid) or {}).get("name") or label, "builtin": True, "rank": rank}
           for gid, (label, rank) in BUILTIN_GROUPS.items()}
    for gid, g in stored.items():
        if g.get("custom") and gid not in BUILTIN_GROUPS:
            out[gid] = {"id": gid, "name": g.get("name") or gid, "builtin": False, "rank": 80}
    order = [gid for gid in _load(ORDER_KEY, []) if gid in out]
    ranked = sorted(out.values(), key=lambda g: (g["rank"], g["name"].lower()))
    listed = order + [g["id"] for g in ranked if g["id"] not in order]
    return [dict(out[gid], rank=(i + 1) * 10) for i, gid in enumerate(listed)]


def group_ids() -> set:
    return {g["id"] for g in groups()}


def _group_name(name: Any) -> str:
    name = " ".join(str(name or "").split())
    if not 1 <= len(name) <= 48:
        raise TaxonomyError("A group name is 1 to 48 characters")
    return name


def add_group(name: str) -> str:
    name = _group_name(name)
    stored = _load(GROUPS_KEY, {})
    if any(g["name"].lower() == name.lower() for g in groups()):
        raise TaxonomyError(f"There is already a group called {name}")
    if sum(1 for g in stored.values() if g.get("custom")) >= MAX_GROUPS:
        raise TaxonomyError(f"At most {MAX_GROUPS} groups of your own")
    base = "c_" + (re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "group")[:24]
    gid, n = base, 2
    while gid in stored or gid in BUILTIN_GROUPS:
        gid, n = f"{base}_{n}", n + 1
    stored[gid] = {"name": name, "custom": True}
    _save(GROUPS_KEY, stored)
    return gid


def rename_group(gid: str, name: str) -> None:
    name = _group_name(name)
    if gid not in group_ids():
        raise TaxonomyError("Unknown group")
    if any(g["name"].lower() == name.lower() and g["id"] != gid for g in groups()):
        raise TaxonomyError(f"There is already a group called {name}")
    stored = _load(GROUPS_KEY, {})
    entry = stored.get(gid) or {"custom": gid not in BUILTIN_GROUPS}
    entry["name"] = name
    stored[gid] = entry
    _save(GROUPS_KEY, stored)


def delete_group(gid: str) -> int:
    """Removes a custom group; its devices go back to their template's group. Returns how many moved."""
    stored = _load(GROUPS_KEY, {})
    if gid in BUILTIN_GROUPS:
        raise TaxonomyError("The built-in groups stay (rename them if the name does not suit)")
    if gid not in stored:
        raise TaxonomyError("Unknown group")
    del stored[gid]
    _save(GROUPS_KEY, stored)
    _save(ORDER_KEY, [g for g in _load(ORDER_KEY, []) if g != gid])
    with database.get_connection() as conn:
        moved = conn.execute("UPDATE devices SET device_group = NULL WHERE device_group = ?;", (gid,)).rowcount
        conn.commit()
    return moved


def order_groups(ids: List[str]) -> None:
    known = group_ids()
    if not isinstance(ids, list) or set(ids) != known or len(ids) != len(known):
        raise TaxonomyError("The order must list every group once")
    _save(ORDER_KEY, ids)


# --- Tags ---

def normalise_tag(name: Any) -> str:
    name = " ".join(str(name or "").split())
    if not _TAG.fullmatch(name):
        raise TaxonomyError(f"'{name}' is not a tag: 1 to 32 letters, digits, spaces and . : / + - _")
    return name


def tags() -> List[Dict[str, Any]]:
    """The catalogue in order: [{name, colour, description}]."""
    out = []
    for t in _load(TAGS_KEY, []):
        if isinstance(t, dict) and t.get("name"):
            out.append({"name": str(t["name"]), "colour": t.get("colour") if t.get("colour") in TAG_COLOURS else "blue",
                        "description": str(t.get("description") or "")})
    return out


def tag_rank() -> Dict[str, int]:
    """Lower-case tag name -> its position (alert layers apply in this order)."""
    return {t["name"].lower(): i for i, t in enumerate(tags())}


def _find(name: str) -> Optional[str]:
    low = name.lower()
    return next((t["name"] for t in tags() if t["name"].lower() == low), None)


def device_tags(device: Dict[str, Any]) -> List[str]:
    raw = device.get("tags")
    if isinstance(raw, list):
        return [str(t) for t in raw]
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [str(t) for t in value] if isinstance(value, list) else []


def ensure_tags(names: List[str]) -> List[str]:
    """Normalised names, the catalogue spelling when known; unknown ones are added to the catalogue."""
    out, cat, added = [], tags(), False
    for n in names:
        name = normalise_tag(n)
        known = next((t["name"] for t in cat if t["name"].lower() == name.lower()), None)
        if known is None:
            if len(cat) >= MAX_TAGS:
                raise TaxonomyError(f"At most {MAX_TAGS} tags")
            cat.append({"name": name, "colour": AUTO_COLOURS[len(cat) % len(AUTO_COLOURS)], "description": ""})
            known, added = name, True
        if known.lower() not in (o.lower() for o in out):
            out.append(known)
    if added:
        _save(TAGS_KEY, cat)
    return out


def set_device_tags(device_id: int, names: List[str]) -> List[str]:
    if not isinstance(names, list):
        raise TaxonomyError("tags must be a list")
    clean = ensure_tags(names)
    if len(clean) > MAX_TAGS_PER_DEVICE:
        raise TaxonomyError(f"At most {MAX_TAGS_PER_DEVICE} tags on one device")
    with database.get_connection() as conn:
        conn.execute("UPDATE devices SET tags = ? WHERE id = ?;", (json.dumps(clean), device_id))
        conn.commit()
    return clean


def tag_devices(device_ids: List[int], add: List[str], remove: List[str]) -> int:
    """Adds and removes tags on several devices at once. Returns how many devices changed."""
    add_clean = ensure_tags(add) if add else []
    drop = {normalise_tag(n).lower() for n in remove or []}
    changed = 0
    for did in device_ids:
        dev = database.get_device(did)
        if not dev:
            continue
        current = device_tags(dev)
        new = [t for t in current if t.lower() not in drop]
        new += [t for t in add_clean if t.lower() not in (x.lower() for x in new)]
        if new != current:
            if len(new) > MAX_TAGS_PER_DEVICE:
                raise TaxonomyError(f"{dev['hostname']} would have more than {MAX_TAGS_PER_DEVICE} tags")
            with database.get_connection() as conn:
                conn.execute("UPDATE devices SET tags = ? WHERE id = ?;", (json.dumps(new), did))
                conn.commit()
            changed += 1
    return changed


def add_tag(name: str, colour: str = "", description: str = "") -> str:
    name = normalise_tag(name)
    if _find(name):
        raise TaxonomyError(f"There is already a tag called {_find(name)}")
    ensure_tags([name])
    edit_tag(name, colour or None, description)
    return name


def edit_tag(name: str, colour: Optional[str], description: Optional[str]) -> None:
    cat = tags()
    t = next((t for t in cat if t["name"].lower() == normalise_tag(name).lower()), None)
    if t is None:
        raise TaxonomyError("Unknown tag")
    if colour is not None:
        if colour not in TAG_COLOURS:
            raise TaxonomyError("Unknown colour")
        t["colour"] = colour
    if description is not None:
        t["description"] = " ".join(str(description).split())[:200]
    _save(TAGS_KEY, cat)


def _each_device_with(name: str):
    low = name.lower()
    for d in database.list_devices():
        tg = device_tags(d)
        if any(t.lower() == low for t in tg):
            yield d, tg


def rename_tag(old: str, new: str) -> None:
    """Renames a tag in the catalogue, on every device and in its alert rules."""
    current = _find(normalise_tag(old))
    if current is None:
        raise TaxonomyError("Unknown tag")
    new = normalise_tag(new)
    clash = _find(new)
    if clash and clash.lower() != current.lower():
        raise TaxonomyError(f"There is already a tag called {clash}")
    cat = tags()
    for t in cat:
        if t["name"] == current:
            t["name"] = new
    _save(TAGS_KEY, cat)
    with database.get_connection() as conn:
        for d, tg in list(_each_device_with(current)):
            conn.execute("UPDATE devices SET tags = ? WHERE id = ?;",
                         (json.dumps([new if t.lower() == current.lower() else t for t in tg]), d["id"]))
        conn.execute("UPDATE alert_overrides SET target = ? WHERE scope = 'tag' AND target = ?;", (new, current))
        conn.commit()


def delete_tag(name: str) -> Dict[str, int]:
    """Removes a tag from the catalogue, every device and its alert rules."""
    current = _find(normalise_tag(name))
    if current is None:
        raise TaxonomyError("Unknown tag")
    _save(TAGS_KEY, [t for t in tags() if t["name"] != current])
    devices = 0
    with database.get_connection() as conn:
        for d, tg in list(_each_device_with(current)):
            conn.execute("UPDATE devices SET tags = ? WHERE id = ?;",
                         (json.dumps([t for t in tg if t.lower() != current.lower()]), d["id"]))
            devices += 1
        rules = conn.execute("DELETE FROM alert_overrides WHERE scope = 'tag' AND target = ?;", (current,)).rowcount
        conn.commit()
    return {"devices": devices, "rules": rules}


def order_tags(names: List[str]) -> None:
    cat = tags()
    by_low = {t["name"].lower(): t for t in cat}
    if not isinstance(names, list) or sorted(n.lower() for n in names) != sorted(by_low):
        raise TaxonomyError("The order must list every tag once")
    _save(TAGS_KEY, [by_low[n.lower()] for n in names])


def summary() -> Dict[str, Any]:
    """Groups and tags with how many devices use each (and how many alert fields each tag sets)."""
    devices = database.list_devices()
    with database.get_connection() as conn:
        rule_counts = {r["target"]: r["n"] for r in conn.execute(
            "SELECT target, COUNT(*) AS n FROM alert_overrides WHERE scope = 'tag' GROUP BY target;")}
    tag_counts: Dict[str, int] = {}
    for d in devices:
        for t in device_tags(d):
            tag_counts[t.lower()] = tag_counts.get(t.lower(), 0) + 1
    return {"groups": groups(), "tags": [dict(t, devices=tag_counts.get(t["name"].lower(), 0),
                                               rules=rule_counts.get(t["name"], 0)) for t in tags()],
            "colours": list(TAG_COLOURS)}
