"""Inventory: every hardware (MAC) address seen on the network, and "a new device joined".

Sources, merged every few minutes from what the polls already collected:
  switches' MAC tables (fdb)    where a device is plugged in: the switch and port. A MAC is
                                learned on every port towards it; the port with the fewest
                                addresses is the one it is actually on (an edge port).
  ARP tables (arp)              which IP address a MAC uses (mostly the gateway's).
  interface MACs (interfaces)   links an address to a monitored device.
  UniFi (unifi.py, optional)    the name the device gave, its maker, the access point and signal.

The administrator adds a name, a note, a location and a purchase date; those never change by
themselves. New addresses: for the first LEARN_SECONDS after the inventory first runs, everything
seen is recorded quietly as known (the network as it is). After that a new address is logged as
an event, sent to Telegram ("New device on the network", see notify.EVENTS) and listed as new until
someone marks it known. Phones and laptops often use a private (randomised) address, recognised by
its second hex digit (2, 6, A or E); those are named as such in the message.

Weak Wi-Fi, per device (WIFI_ALERT_KEY): an access point's "Wi-Fi devices on weak signal" problem
lists every device below the weak line. One that is always weak (a sensor at the far end of the
garden) can be left out ("off") or given a lower line of its own (a dBm figure), from the
Inventory's Edit window. Kept by MAC, so it follows the device from one access point to another.
A whole Wi-Fi network can have such a rule too (WIFI_NET_ALERT_KEY), for a guest network whose
phones change their address; a device's own rule wins over its network's.

Quiet (kept, not announced): a device can be marked quiet, and whole Wi-Fi networks can be
(QUIET_SSIDS_KEY, for example a tenant's SSID). A quiet device is still recorded and kept up to
date, but it is never announced as new, not counted as new (page, digest, /changes) and not marked
known by "Mark all new as known". The Inventory page hides quiet devices unless asked.

Devices can also be added by hand (add), as known, before or while they are offline.
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import database

STARTED_KEY = "inventory_started"
LEARN_SECONDS = 24 * 3600
MAX_MESSAGES_PER_RUN = 5
EDIT_FIELDS = {"name": 60, "note": 500, "location": 60, "purchased": 10}
WIFI_ALERT_KEY = "inventory_wifi_alert"     # {mac: "off" | dBm}, internal setting
WIFI_LINE_RANGE = (-95, -40)
QUIET_SSIDS_KEY = "inventory_quiet_ssids"   # JSON list of SSIDs, internal setting
MAX_QUIET_SSIDS = 20
WIFI_NET_ALERT_KEY = "inventory_wifi_net_alert"   # {network name: "off" | dBm}, internal setting


class InventoryError(ValueError):
    pass


def normalise_mac(mac: str) -> Optional[str]:
    hexs = "".join(ch for ch in str(mac or "").lower() if ch in "0123456789abcdef")
    if len(hexs) != 12:
        return None
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def is_unicast(mac: str) -> bool:
    """A real device's address: not multicast or broadcast (lowest bit of the first byte) and not zero."""
    return mac != "00:00:00:00:00:00" and int(mac[:2], 16) & 1 == 0


def is_private(mac: str) -> bool:
    """A locally administered address: phones and laptops hiding their real one."""
    return bool(int(mac[:2], 16) & 2)


def gather(devices: List[Dict[str, Any]], fdb_rows: List[Dict[str, Any]], arp_rows: List[Dict[str, Any]],
           if_rows: List[Dict[str, Any]], port_labels: Dict[int, Dict[int, str]],
           wifi: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    """What the network shows right now, by MAC: ip, device_id, where_seen, via, seen_name, vendor.
    A monitored device is one row, under its main address (see extra_macs)."""
    names = {d["id"]: d["hostname"] for d in devices}
    # A host and a service check on one address: the address (and its MAC) is the host's.
    by_ip = {d["ip_address"]: d["id"] for d in sorted(devices, key=lambda d: 0 if d.get("service_port") else 1)}
    out: Dict[str, Dict[str, Any]] = {}
    extra = extra_macs(devices, arp_rows, if_rows)

    def row(mac: str) -> Optional[Dict[str, Any]]:
        mac = normalise_mac(mac)
        if not mac or not is_unicast(mac) or mac in extra:
            return None
        return out.setdefault(mac, {"mac": mac, "ip": "", "device_id": None, "where_seen": "", "via": "",
                                    "seen_name": "", "vendor": "", "ssid": ""})

    # The port each MAC is on: of every (switch, port) that learned it, the one with fewest addresses.
    per_port: Dict[tuple, int] = {}
    for r in fdb_rows:
        per_port[(r["device_id"], r.get("if_index"))] = per_port.get((r["device_id"], r.get("if_index")), 0) + 1
    best: Dict[str, tuple] = {}
    for r in fdb_rows:
        mac = normalise_mac(r.get("row_key") or r.get("mac"))
        if not mac:
            continue
        place = (r["device_id"], r.get("if_index"))
        if mac not in best or per_port[place] < per_port[best[mac]]:
            best[mac] = place
    for mac, (sw, port) in best.items():
        x = row(mac)
        if x is not None:
            label = port_labels.get(sw, {}).get(port, str(port))
            x["where_seen"], x["via"] = f"{names.get(sw, 'switch')} port {label}", "cable"
    for r in arp_rows:
        x = row(r.get("mac"))
        ip = r.get("row_key") or r.get("ip")
        if x is not None and ip:
            x["ip"] = str(ip)
            if ip in by_ip:
                x["device_id"] = by_ip[ip]
    for r in if_rows:
        x = row(r.get("mac"))
        if x is not None and x["device_id"] is None:
            x["device_id"] = r["device_id"]
    for c in wifi or []:
        x = row(c.get("mac"))
        if x is None:
            continue
        if c.get("ip"):
            x["ip"] = c["ip"]
            x["device_id"] = x["device_id"] or by_ip.get(c["ip"])
        x["seen_name"] = c.get("name") or x["seen_name"]
        x["vendor"] = c.get("vendor") or x["vendor"]
        if c.get("ap"):
            signal = f", {c['signal']} dBm" if c.get("signal") is not None else ""
            x["where_seen"], x["via"] = f"{c['ap']} (Wi-Fi{signal})", "wifi"
            x["ssid"] = str(c.get("ssid") or "")[:64]
        elif c.get("wired_on") and not x["where_seen"]:
            x["where_seen"], x["via"] = c["wired_on"], "cable"
    return out


def extra_macs(devices: List[Dict[str, Any]], arp_rows: List[Dict[str, Any]], if_rows: List[Dict[str, Any]]) -> set:
    """The addresses of monitored devices that are not their main one. An access point has one per
    radio and Wi-Fi network, a gateway one per VLAN, a Proxmox host one per guest's host side: listed
    one by one they made each device appear many times. The main address is the one its IP uses
    (the ARP table), or else the lowest of its own."""
    own: Dict[int, set] = {}
    for r in if_rows:
        mac = normalise_mac(r.get("mac"))
        if mac and is_unicast(mac):
            own.setdefault(r["device_id"], set()).add(mac)
    ip_mac = {}
    for r in arp_rows:
        mac, ip = normalise_mac(r.get("mac")), r.get("row_key") or r.get("ip")
        if mac and ip:
            ip_mac[str(ip)] = mac
    extra = set()
    for d in devices:
        macs = own.get(d["id"], set())
        if not macs:
            continue
        main = ip_mac.get(d["ip_address"])
        main = main if main else min(macs)
        extra |= macs - {main}
    return extra


def update(seen: Dict[str, Dict[str, Any]], notify: Callable[[Dict[str, Any]], None],
           now: Optional[float] = None, drop: Optional[set] = None) -> List[Dict[str, Any]]:
    """Stores what was seen; returns the addresses that are new (and not learned quietly).
    drop: addresses folded into a monitored device (extra_macs); their old rows go, unless the
    administrator wrote something on them."""
    now = int(now if now is not None else time.time())
    settings = database.get_all_settings()
    started = int(settings.get(STARTED_KEY) or 0)
    if not started:
        started = now
        database.set_internal_setting(STARTED_KEY, str(now))
    learning = now - started < LEARN_SECONDS
    quiet_nets = quiet_ssids()
    new = []
    with database.get_connection() as conn:
        for mac in drop or ():
            conn.execute("DELETE FROM inventory WHERE mac = ? AND name = '' AND note = '' AND location = '' AND purchased = '';", (mac,))
        stored = {r["mac"]: dict(r) for r in conn.execute("SELECT * FROM inventory;")}
        for mac, s in seen.items():
            old = stored.get(mac)
            ssid = s.get("ssid") or ""
            if old is None:
                conn.execute("INSERT INTO inventory (mac, ip, seen_name, vendor, where_seen, via, device_id, first_seen, last_seen, known, ssid) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                             (mac, s["ip"], s["seen_name"], s["vendor"], s["where_seen"], s["via"], s["device_id"], now, now,
                              1 if learning or s["device_id"] else 0, ssid))
                # On a quiet network: recorded (and left new), but not announced.
                if not learning and not s["device_id"] and ssid.lower() not in quiet_nets:
                    new.append(s)
            else:
                # What the network says replaces the old view; empty readings keep what was known.
                # The SSID follows the device: on a cable it has none, unseen it keeps the last one.
                if s["via"] != "wifi":
                    ssid = "" if s["via"] == "cable" else old["ssid"]
                conn.execute("UPDATE inventory SET ip = ?, seen_name = ?, vendor = ?, where_seen = ?, via = ?, device_id = ?, "
                             "last_seen = ?, ssid = ? WHERE mac = ?;",
                             (s["ip"] or old["ip"], s["seen_name"] or old["seen_name"], s["vendor"] or old["vendor"],
                              s["where_seen"] or old["where_seen"], s["via"] or old["via"],
                              s["device_id"] if s["device_id"] is not None else old["device_id"], now, ssid, mac))
        conn.commit()
    for s in new[:MAX_MESSAGES_PER_RUN]:
        notify(s)
    if len(new) > MAX_MESSAGES_PER_RUN:
        notify({"mac": "", "summary": len(new) - MAX_MESSAGES_PER_RUN})
    return new


def describe(s: Dict[str, Any]) -> str:
    """One line for the event and the message: what it is, its address and where it is."""
    what = s.get("seen_name") or s.get("vendor") or "unknown device"
    private = " (private address: a phone or laptop hiding its real one)" if s.get("mac") and is_private(s["mac"]) else ""
    where = f" on {s['where_seen']}" if s.get("where_seen") else ""
    ip = f" at {s['ip']}" if s.get("ip") else ""
    return f"{what}, {s['mac']}{private}{ip}{where}"


def listing(now: Optional[float] = None) -> Dict[str, Any]:
    now = int(now if now is not None else time.time())
    started = int(database.get_all_settings().get(STARTED_KEY) or 0)
    with database.get_connection() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT i.*, d.hostname AS device_name FROM inventory i LEFT JOIN devices d ON d.id = i.device_id "
            "ORDER BY i.known, i.last_seen DESC;")]
    alerts = wifi_alerts()
    quiet_nets = quiet_ssids()
    ssids: Dict[str, int] = {}
    for r in rows:
        r["private"] = is_private(r["mac"])
        r["known"] = bool(r["known"])
        r["wifi_alert"] = alerts.get(r["mac"], "")
        r["quiet"] = bool(r["quiet"])
        r["quiet_net"] = bool(r["ssid"]) and r["ssid"].lower() in quiet_nets
        r["hushed"] = r["quiet"] or r["quiet_net"]
        if r["ssid"]:
            ssids[r["ssid"]] = ssids.get(r["ssid"], 0) + 1
    return {"rows": rows, "learning_until": started + LEARN_SECONDS if started and now - started < LEARN_SECONDS else None,
            "now": now, "ssids": [{"ssid": k, "count": v, "quiet": k.lower() in quiet_nets} for k, v in sorted(ssids.items(), key=lambda kv: kv[0].lower())],
            "quiet_ssids": quiet_ssid_list(), "wifi_net_alerts": wifi_net_alerts()}


def edit(mac: str, fields: Dict[str, Any]) -> None:
    mac = normalise_mac(mac)
    if not mac:
        raise InventoryError("Not a MAC address")
    sets, args = [], []
    for k, limit in EDIT_FIELDS.items():
        if k in fields:
            v = str(fields[k] or "").strip()
            if len(v) > limit:
                raise InventoryError(f"{k} is at most {limit} characters")
            if k == "purchased" and v and not (len(v) == 10 and v[4] == "-" and v[7] == "-" and v.replace("-", "").isdigit()):
                raise InventoryError("Purchase date is YYYY-MM-DD")
            sets.append(f"{k} = ?")
            args.append(v)
    for flag in ("known", "quiet"):
        if flag in fields:
            sets.append(f"{flag} = ?")
            args.append(1 if fields[flag] else 0)
    alert = clean_wifi_alert(fields["wifi_alert"]) if "wifi_alert" in fields else None
    if not sets and alert is None:
        raise InventoryError("Nothing to change")
    with database.get_connection() as conn:
        if sets:
            found = conn.execute(f"UPDATE inventory SET {', '.join(sets)} WHERE mac = ?;", (*args, mac)).rowcount
        else:
            found = conn.execute("SELECT 1 FROM inventory WHERE mac = ?;", (mac,)).fetchone() is not None
        conn.commit()
    if not found:
        raise InventoryError("No such address in the inventory")
    if alert is not None:
        set_wifi_alert(mac, alert)


def wifi_alerts() -> Dict[str, Any]:
    """Each device's own weak Wi-Fi rule: {mac: "off" | dBm}. Devices not listed follow the usual line."""
    try:
        raw = json.loads(database.get_all_settings().get(WIFI_ALERT_KEY) or "{}")
    except ValueError:
        return {}
    out: Dict[str, Any] = {}
    for k, v in (raw.items() if isinstance(raw, dict) else ()):
        mac = normalise_mac(k)
        try:
            v = clean_wifi_alert(v)
        except InventoryError:
            continue
        if mac and v != "":
            out[mac] = v
    return out


def clean_wifi_alert(v: Any) -> Any:
    """"" (as usual), "off" (never) or a whole dBm figure within WIFI_LINE_RANGE."""
    if v is None or str(v).strip() in ("", "usual"):
        return ""
    if str(v).strip().lower() == "off":
        return "off"
    try:
        n = int(float(str(v).strip()))
    except ValueError:
        raise InventoryError("Weak Wi-Fi is as usual, off, or a signal line in dBm") from None
    lo, hi = WIFI_LINE_RANGE
    if not lo <= n <= hi:
        raise InventoryError(f"The signal line is between {lo} and {hi} dBm")
    return n


def set_wifi_alert(mac: str, value: Any) -> None:
    mac = normalise_mac(mac)
    if not mac:
        raise InventoryError("Not a MAC address")
    value = clean_wifi_alert(value)
    alerts = wifi_alerts()
    if value == "":
        alerts.pop(mac, None)
    else:
        alerts[mac] = value
    database.set_internal_setting(WIFI_ALERT_KEY, json.dumps(alerts, sort_keys=True))


def wifi_net_alerts() -> Dict[str, Any]:
    """Each Wi-Fi network's own weak Wi-Fi rule: {network name: "off" | dBm}. A guest network full of
    phones that change their address is set here once, instead of per device."""
    try:
        raw = json.loads(database.get_all_settings().get(WIFI_NET_ALERT_KEY) or "{}")
    except ValueError:
        return {}
    out: Dict[str, Any] = {}
    for k, v in (raw.items() if isinstance(raw, dict) else ()):
        try:
            v = clean_wifi_alert(v)
        except InventoryError:
            continue
        if isinstance(k, str) and k.strip() and v != "":
            out[k.strip()] = v
    return out


def set_wifi_net_alerts(rules: Any) -> Dict[str, Any]:
    """Replaces every network's rule: {network name: "" (as usual) | "off" | dBm}."""
    if not isinstance(rules, dict):
        raise InventoryError("Weak Wi-Fi rules per network name")
    out: Dict[str, Any] = {}
    for name, value in rules.items():
        name = str(name or "").strip()
        if not name:
            continue
        if len(name) > 32 or any(ord(c) < 32 for c in name):
            raise InventoryError("A Wi-Fi network name is at most 32 characters")
        value = clean_wifi_alert(value)
        if value != "" and name.lower() not in {k.lower() for k in out}:
            out[name] = value
    if len(out) > MAX_QUIET_SSIDS:
        raise InventoryError(f"Weak Wi-Fi rules for up to {MAX_QUIET_SSIDS} networks")
    database.set_internal_setting(WIFI_NET_ALERT_KEY, json.dumps(out, sort_keys=True))
    return out


def weak_line(mac: Any, usual: float, alerts: Optional[Dict[str, Any]] = None, ssid: Any = None,
              nets: Optional[Dict[str, Any]] = None) -> Optional[float]:
    """The weak line for this device: its own, else its network's, else the usual one; None when it is
    never reported."""
    own = (alerts if alerts is not None else wifi_alerts()).get(normalise_mac(mac) or "")
    if own in ("", None) and ssid:
        rules = nets if nets is not None else wifi_net_alerts()
        own = next((v for k, v in rules.items() if k.lower() == str(ssid).lower()), "")
    if own == "off":
        return None
    return float(own) if isinstance(own, int) else usual


def mark_all_known() -> int:
    """Every new device becomes known, except quiet ones (they stay as they are, out of sight)."""
    loud, args = loud_sql()
    with database.get_connection() as conn:
        n = conn.execute(f"UPDATE inventory SET known = 1 WHERE known = 0 AND {loud};", args).rowcount
        conn.commit()
    return n


def add(mac: str, fields: Dict[str, Any], now: Optional[float] = None) -> str:
    """A device added by hand, as known: it need not be online (or ever have been seen)."""
    mac = normalise_mac(mac)
    if not mac or not is_unicast(mac):
        raise InventoryError("Enter the device's MAC address, for example aa:bb:cc:dd:ee:ff")
    now = int(now if now is not None else time.time())
    with database.get_connection() as conn:
        if conn.execute("SELECT 1 FROM inventory WHERE mac = ?;", (mac,)).fetchone():
            raise InventoryError("That address is already in the inventory: use Edit on its row")
        conn.execute("INSERT INTO inventory (mac, first_seen, last_seen, known) VALUES (?, ?, ?, 1);", (mac, now, now))
        conn.commit()
    rest = {k: v for k, v in fields.items() if k in EDIT_FIELDS or k == "quiet"}
    if rest:
        try:
            edit(mac, rest)
        except InventoryError:
            forget(mac)
            raise
    return mac


def quiet_ssid_list() -> List[str]:
    try:
        raw = json.loads(database.get_all_settings().get(QUIET_SSIDS_KEY) or "[]")
    except ValueError:
        return []
    return [str(x) for x in raw if isinstance(x, str) and x.strip()] if isinstance(raw, list) else []


def quiet_ssids() -> set:
    """The quiet Wi-Fi networks, lower case (UniFi and phones disagree about case)."""
    return {x.lower() for x in quiet_ssid_list()}


def set_quiet_ssids(names: Any) -> List[str]:
    if not isinstance(names, list):
        raise InventoryError("A list of Wi-Fi network names")
    out: List[str] = []
    for n in names:
        n = str(n or "").strip()
        if not n:
            continue
        if len(n) > 32:
            raise InventoryError("A Wi-Fi network name is at most 32 characters")
        if n.lower() not in {x.lower() for x in out}:
            out.append(n)
    if len(out) > MAX_QUIET_SSIDS:
        raise InventoryError(f"Up to {MAX_QUIET_SSIDS} quiet networks")
    database.set_internal_setting(QUIET_SSIDS_KEY, json.dumps(out))
    return out


def loud_sql() -> Tuple[str, tuple]:
    """A WHERE fragment (with its arguments) for devices that are not quiet: not marked quiet and not
    on a quiet network. Used wherever new devices are counted."""
    nets = sorted(quiet_ssids())
    if not nets:
        return "quiet = 0", ()
    return f"quiet = 0 AND lower(ssid) NOT IN ({', '.join('?' for _ in nets)})", tuple(nets)


def forget(mac: str) -> bool:
    mac = normalise_mac(mac)
    with database.get_connection() as conn:
        n = conn.execute("DELETE FROM inventory WHERE mac = ?;", (mac,)).rowcount
        conn.commit()
    if n and mac in wifi_alerts():
        set_wifi_alert(mac, "")
    return bool(n)
