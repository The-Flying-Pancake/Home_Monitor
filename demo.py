"""Demo mode: simulated devices for trying the app without a network, testing and screenshots.

Demo mode is on after the installer's "start with demo data" (or demo.py seed) until Settings, Demo
data removes it again; MONITOR_DEMO=1 also switches it on (development). While it is on the poller answers for every device whose address is in a documentation
range (192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, RFC 5737) from the simulation here
instead of the network: ping, port and web checks, the profile's SNMP metrics and the tables
(interfaces, storage, sensors, disks and volumes). Devices with any other address are polled
normally, and while demo mode is off nothing in this module is used by the poller.

Values follow a daily curve plus smooth noise. Every random draw is a hash of the device id,
a purpose and a time bucket, so the same device at the same moment always gets the same value:
the backfilled history and the live poll agree, and tests can check exact behaviour. Now and
then a device drops off the network for a few minutes (and restarts), a backup disk fills up
until a clean-up and the printer asks for paper, so events, problems and availability have
something to show.

  py -3.15 demo.py seed [--force]     create the demo devices and 7 days of history

The seed writes to the database MONITOR_DB_PATH names (the app's normal one when unset). It
refuses a database holding any device outside the documentation ranges unless --force is
given, so real data is never mixed in. It never creates a user account: the first account
is made in the browser as usual. It records what it made, so remove() takes away exactly that:
the demo devices (only while they still have their made-up addresses) with their history, and
the groups and tags it added when nothing else uses them.
"""

import argparse
import contextlib
import functools
import hashlib
import ipaddress
import math
import os
import sqlite3
import sys
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import database

DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
# Reserved example domains (RFC 2606): a web check of one is simulated too in demo mode.
EXAMPLE_DOMAINS = ("example.com", "example.net", "example.org")

DAY = 86400
OUTAGE_SLOT = 6 * 3600          # At most one outage per device in each six hours
REBOOT_PERIOD = 30 * DAY        # Planned restarts (updates): one per device in each 30 days


# --- When demo mode applies ---

MODE_KEY = "demo_mode"          # internal setting: "on" from the seed until remove()
SEED_KEY = "demo_seed"          # internal setting: what the seed made, as JSON
_cache = {"at": 0.0, "on": False}


def enabled() -> bool:
    if os.environ.get("MONITOR_DEMO") == "1":
        return True
    now = time.monotonic()
    if now - _cache["at"] > 10:              # the poller asks for every device: read the flag at most every 10 s
        try:
            _cache["on"] = database.get_all_settings().get(MODE_KEY) == "on"
        except Exception:  # noqa: BLE001 (no database yet: not in demo mode)
            _cache["on"] = False
        _cache["at"] = now
    return bool(_cache["on"])


def _forget() -> None:
    _cache["at"] = 0.0


def is_demo_address(host: Any) -> bool:
    """Whether host is an IPv4 address in one of the documentation ranges."""
    try:
        ip = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return False
    return any(ip in net for net in DOC_NETS)


def handles(host: Any) -> bool:
    """Whether the poller should simulate this address instead of contacting it."""
    return enabled() and is_demo_address(host)


def handles_url(url: str) -> bool:
    """Whether a web check of url is simulated: a documentation address or an example domain."""
    if not enabled():
        return False
    host = (urlparse(str(url or "")).hostname or "").lower()
    return is_demo_address(host) or any(host == d or host.endswith("." + d) for d in EXAMPLE_DOMAINS)


# --- Deterministic noise ---

def _u(*parts: Any) -> float:
    """A uniform number in [0, 1) fixed by parts."""
    digest = hashlib.blake2b("|".join(str(p) for p in parts).encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") / 2 ** 64


def _smooth(t: float, period: float, *parts: Any) -> float:
    """Value noise in [-1, 1]: random knots every period seconds joined by a smooth curve."""
    k = math.floor(t / period)
    f = t / period - k
    a, b = _u(*parts, k) * 2 - 1, _u(*parts, k + 1) * 2 - 1
    return a + (b - a) * f * f * (3 - 2 * f)


def _local_hour(t: float) -> float:
    lt = time.localtime(t)
    return lt.tm_hour + lt.tm_min / 60 + lt.tm_sec / 3600


def _daily(t: float, peak_hour: float) -> float:
    """A daily sine in [-1, 1] that peaks at peak_hour local time."""
    return math.cos(2 * math.pi * (_local_hour(t) - peak_hour) / 24)


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


# --- Device character ---

KINDS = {
    "ubiquiti_edgeos": "router", "unifi_gateway": "router", "bsd_firewall": "router", "fortigate": "router",
    "mikrotik": "router", "unifi_switch": "switch", "managed_switch": "switch", "hp_aruba_switch": "switch",
    "cisco": "switch", "unifi_ap": "ap", "synology_dsm": "nas", "qnap_nas": "nas", "truenas": "nas",
    "vmware_esxi": "hypervisor", "dell_idrac": "hypervisor", "hpe_ilo": "hypervisor", "linux_host": "server",
    "windows_host": "desktop", "printer": "printer", "apc_ups": "ups", "cyberpower_ups": "ups",
    "ups_standard": "ups", "apc_pdu": "ups", "ping_only": "other", "service_check": "service",
    "generic_device": "other",
}
# kind: (cpu %, memory %, memory KB, cores, ping ms)
BASES = {
    "router": (8, 38, 512 * 1024, 2, 0.4), "switch": (6, 46, 512 * 1024, 1, 0.6), "ap": (9, 55, 256 * 1024, 2, 1.2),
    "nas": (12, 32, 4 * 1024 ** 2, 4, 0.5), "hypervisor": (30, 64, 128 * 1024 ** 2, 16, 0.3),
    "server": (10, 42, 8 * 1024 ** 2, 4, 0.4), "desktop": (14, 52, 32 * 1024 ** 2, 8, 0.7),
    "printer": (3, 40, 256 * 1024, 1, 1.8), "ups": (2, 30, 64 * 1024, 1, 2.2), "other": (5, 40, 512 * 1024, 1, 2.5),
    "service": (5, 40, 512 * 1024, 1, 0.5),
}


@functools.lru_cache(maxsize=512)
def _traits(device_id: Any, hostname: str, profile_id: str, ip: str) -> Dict[str, Any]:
    kind = KINDS.get(profile_id, "server")
    cpu, mem, mem_kb, cores, ping = BASES[kind]

    def jitter(key: str, v: float, spread: float = 0.2) -> float:
        return v * (1 + spread * (_u("trait", device_id, key) * 2 - 1))

    name = hostname.lower()
    # Most devices drop off now and then; one in four never does.
    flaky = _u("trait", device_id, "flaky")
    outage_chance = 0.0 if flaky < 0.25 else 0.03 if flaky < 0.8 else 0.07
    remote = not ip.startswith("192.0.2.")
    return {
        "kind": kind, "cpu": jitter("cpu", cpu), "mem": jitter("mem", mem, 0.12), "mem_kb": mem_kb, "cores": cores,
        "ping": jitter("ping", 18.0 if remote else ping, 0.3), "outage_chance": outage_chance,
        # The backup target fills up between clean-ups; other disks grow slowly.
        "disk_creep": "backup" in name, "media": "media" in name, "traffic": jitter("traffic", 1.0, 0.5),
    }


def traits(device: Dict[str, Any]) -> Dict[str, Any]:
    return _traits(device.get("id"), str(device.get("hostname") or ""), str(device.get("profile_id") or ""),
                   str(device.get("ip_address") or ""))


# --- Outages and restarts ---

@functools.lru_cache(maxsize=65536)
def _slot_outage(device_id: Any, chance: float, slot: int) -> Optional[Tuple[int, int]]:
    """The outage in one six-hour slot, if any: (start, end). Three to 25 minutes, inside the slot."""
    if chance <= 0 or _u("down", device_id, slot) >= chance:
        return None
    start = slot * OUTAGE_SLOT + int(_u("down-at", device_id, slot) * (OUTAGE_SLOT - 1800))
    return start, start + 180 + int(_u("down-for", device_id, slot) * 1320)


def outage(device: Dict[str, Any], t: float) -> Optional[Tuple[int, int]]:
    """The outage the device is in at time t, or None when it is up."""
    o = _slot_outage(device.get("id"), traits(device)["outage_chance"], int(t // OUTAGE_SLOT))
    return o if o and o[0] <= t < o[1] else None


def outages_between(device: Dict[str, Any], start: float, end: float) -> List[Tuple[int, int]]:
    chance = traits(device)["outage_chance"]
    found = []
    for slot in range(int(start // OUTAGE_SLOT), int(end // OUTAGE_SLOT) + 1):
        o = _slot_outage(device.get("id"), chance, slot)
        if o and o[0] < end and o[1] > start:
            found.append(o)
    return found


def last_boot(device: Dict[str, Any], t: float) -> int:
    """When the device last started: the end of its last outage or its last planned restart."""
    offset = int(_u("boot", device.get("id")) * REBOOT_PERIOD)
    planned = ((int(t) - offset) // REBOOT_PERIOD) * REBOOT_PERIOD + offset
    chance = traits(device)["outage_chance"]
    slot = int(t // OUTAGE_SLOT)
    while slot * OUTAGE_SLOT + OUTAGE_SLOT > planned:
        o = _slot_outage(device.get("id"), chance, slot)
        if o and o[1] <= t:
            return max(o[1], planned)
        slot -= 1
    return planned


# --- Reachability ---

def ping(device: Dict[str, Any], t: Optional[float] = None) -> Tuple[bool, Optional[float]]:
    """(answered, round trip ms), like poller.ping_host."""
    t = time.time() if t is None else t
    if outage(device, t):
        return False, None
    tr = traits(device)
    ms = tr["ping"] * (1 + 0.25 * _smooth(t, 900, "ping", device.get("id")) + 0.15 * _u("ping-j", device.get("id"), int(t // 60)))
    if _u("ping-spike", device.get("id"), int(t // 60)) < 0.02:
        ms *= 4 + 6 * _u("ping-spike-x", device.get("id"), int(t // 60))
    return True, round(max(0.1, ms), 2)


def _device_for_address(ip: str) -> Dict[str, Any]:
    """The device on ip (the one without a service port first), or a stand-in keyed by the address."""
    # A lookup failure (no schema yet, locked vault) falls back to the address alone.
    with contextlib.suppress(Exception):
        matches = [d for d in database.list_devices() if d["ip_address"] == ip]
        if matches:
            return sorted(matches, key=lambda d: (bool(d.get("service_port")), d["id"]))[0]
    return {"id": f"ip:{ip}", "hostname": ip, "profile_id": "generic_device", "ip_address": ip}


def ping_address(ip: str, t: Optional[float] = None) -> Tuple[bool, Optional[float]]:
    """A ping of a bare address (the Ping button, the add-device test, workflows)."""
    return ping(_device_for_address(ip), t)


def tcp(host: str, port: int, t: Optional[float] = None) -> Tuple[bool, Optional[float]]:
    """A TCP connect to a bare address, like poller.tcp_check."""
    alive, ms = ping_address(host, t)
    return (True, round((ms or 1.0) * 1.3 + 0.2, 2)) if alive else (False, None)


def http(url: str, expect: Optional[Dict[str, Any]] = None, t: Optional[float] = None) -> Dict[str, Any]:
    """A web check, like poller.http_check: up with HTTP 200 unless the host is in an outage."""
    host = urlparse(url).hostname or ""
    device = _device_for_address(host) if is_demo_address(host) else {"id": f"url:{host}", "hostname": host,
                                                                         "profile_id": "service_check", "ip_address": "203.0.113.1"}
    return _web(device, url, t if t is not None else time.time())


def _web(device: Dict[str, Any], url: str, t: float) -> Dict[str, Any]:
    if outage(device, t):
        return {"up": False, "status": None, "ms": None, "error": "timed out", "redirect": None}
    ms = 60 + 40 * _daily(t, 20) + 25 * _smooth(t, 600, "web", device.get("id")) + 10 * _u("web-j", device.get("id"), int(t // 60))
    return {"up": True, "status": 200, "ms": round(max(8.0, ms), 2), "error": None, "redirect": None}


def service(device: Dict[str, Any], t: Optional[float] = None) -> Tuple[bool, Optional[float], Dict[str, float]]:
    """A port or web check, like poller.service_check: (up, response ms, extra metrics)."""
    t = time.time() if t is None else t
    if device.get("service_kind") == "http" and device.get("service_url"):
        r = _web(device, device["service_url"], t)
        extra = {"http_status": float(r["status"])} if r["status"] is not None else {}
        if str(device["service_url"]).lower().startswith("https://"):
            # A 90 day certificate renewed every 60 days.
            extra["tls_days_left"] = round(90 - ((t / DAY + 60 * _u("cert", device.get("id"))) % 60), 1)
        return r["up"], r["ms"], extra
    alive, ms = ping(device, t)
    return (True, round((ms or 1.0) * 1.3 + 0.2, 2), {}) if alive else (False, None, {})


# --- SNMP metrics ---

def _counter(t: float, boot: float, mean_bps: float, swing: float, peak_hour: float) -> int:
    """Octets since boot for a rate of mean_bps * (1 + swing * daily curve): the closed-form integral."""
    w = 2 * math.pi / DAY

    def bits(x: float) -> float:
        # The curve of _daily: cos(w * (local seconds - peak)), local seconds being x - time.timezone.
        return mean_bps * (x + swing / w * math.sin(w * (x - time.timezone - peak_hour * 3600)))
    return int(max(0.0, bits(t) - bits(boot)) / 8)


def values(device: Dict[str, Any], t: Optional[float] = None) -> Dict[str, float]:
    """Every metric key the profiles use, simulated for this device at time t (final units, after scale)."""
    t = time.time() if t is None else t
    did = device.get("id")
    tr = traits(device)
    kind = tr["kind"]
    day_peak = 21 if tr["media"] or kind in ("ap", "router") else 14

    cpu = tr["cpu"] * (1 + 0.6 * _daily(t, day_peak)) + tr["cpu"] * 0.35 * _smooth(t, 1200, "cpu", did)
    cpu += 6 * _u("cpu-j", did, int(t // 60))
    if _u("cpu-burst", did, int(t // 1800)) < 0.04:       # A busy half hour (backups, updates)
        cpu += 35 + 25 * _u("cpu-burst-x", did, int(t // 1800))
    cpu = _clamp(cpu, 0.5, 99.0)
    mem = _clamp(tr["mem"] + 4 * _daily(t, day_peak) + 3 * _smooth(t, 3 * 3600, "mem", did), 5.0, 97.0)
    total_kb = tr["mem_kb"]
    free_kb = total_kb * (1 - mem / 100)
    cached_kb, buffer_kb = free_kb * 0.45, total_kb * 0.02
    load = tr["cores"] * cpu / 100
    temp = 38 + 5 * _daily(t, 15) + 2 * _smooth(t, 1800, "temp", did) + cpu * 0.15
    clients = max(0, round(9 + 7 * _daily(t, 21) + 3 * _smooth(t, 1800, "clients", did)))
    ups_load = _clamp(28 + 4 * _daily(t, 14) + 2 * _smooth(t, 900, "ups", did), 5, 95)
    printing = 8 <= _local_hour(t) < 19 and _u("print", did, int(t // 600)) < 0.15
    # The printer asks for paper for a couple of hours about once a week.
    paper = _u("paper", did, int(t // (2 * 3600))) < 0.012
    boot = last_boot(device, t)
    bw = tr["traffic"]
    v = {
        "uptime_seconds": float(int(t) - boot),
        "cpu_usage_pct": round(cpu), "cpu_idle_pct": round(100 - cpu), "cpu_core_max_pct": round(min(100, cpu * 1.6)),
        "cpu_load_1m": round(load, 2), "cpu_load_5m": round(load * 0.95, 2), "cpu_load_15m": round(load * 0.9, 2),
        "mem_total_kb": float(total_kb), "mem_avail_kb": round(free_kb - cached_kb - buffer_kb),
        "mem_buffer_kb": round(buffer_kb), "mem_cached_kb": round(cached_kb),
        "mem_hr_size_units": float(total_kb // 4), "mem_hr_used_units": round(total_kb // 4 * mem / 100),
        "mem_total_mb": round(total_kb / 1024), "mem_free_mb": round(free_kb / 1024),
        "mem_total_bytes": float(total_kb * 1024), "mem_used_bytes": round(total_kb * 1024 * mem / 100),
        "mem_free_bytes": round(free_kb * 1024), "mem_used_pct": round(mem),
        "tcp_established": round(40 + 30 * _daily(t, 14) + 10 * _smooth(t, 900, "tcp", did)),
        "system_temp_c": round(temp, 1), "cpu_temp_c": round(temp + 8, 1), "fan_rpm": round(1100 + 15 * temp),
        "supply_volts": 24.1, "pf_states": round(800 + 500 * _daily(t, 21)), "pf_running": 1,
        "fw_sessions": round(900 + 600 * _daily(t, 21)), "ports_up": float(sum(1 for r in interface_plan(device) if r[3])),
        "clients_total": clients, "clients_2g": clients // 3, "clients_5g": clients - clients // 3,
        "radio_2g_channel": 6, "radio_5g_channel": 36, "radio_2g_tx_power_dbm": 20, "radio_5g_tx_power_dbm": 23,
        "radio_2g_util_pct": round(_clamp(22 + 10 * _daily(t, 21) + 6 * _smooth(t, 900, "u2", did), 1, 95)),
        "radio_5g_util_pct": round(_clamp(12 + 8 * _daily(t, 21) + 5 * _smooth(t, 900, "u5", did), 1, 95)),
        "uplink_in_octets": _counter(t, boot, 4e6 * bw, 0.8, 21), "uplink_out_octets": _counter(t, boot, 1e6 * bw, 0.8, 21),
        "wan_in_octets": _counter(t, boot, 9e6 * bw, 0.7, 21), "wan_out_octets": _counter(t, boot, 1.5e6 * bw, 0.6, 21),
        "wan_status": 1,
        "ups_charge_pct": 100, "ups_runtime_s": round(3600 * 30 / ups_load), "ups_runtime_min": round(60 * 30 / ups_load),
        "ups_load_pct": round(ups_load), "ups_battery_temp_c": round(26 + 1.5 * _daily(t, 16), 1),
        "ups_input_volts": round(230 + 3 * _smooth(t, 600, "volts", did)), "ups_output_status": 2,
        "ups_battery_replace": 1, "ups_self_test": 1, "ups_on_battery_s": 0, "ups_alarms": 0,
        "ups_battery_status": 2, "ups_output_source": 3,
        "pdu_load_amps": round(ups_load / 10, 1), "pdu_power_w": round(ups_load * 22), "pdu_load_state": 1,
        "printer_pages": float(12000 + int((t - 1.7e9) / DAY * 18)), "printer_state": 4 if printing else 3,
        "printer_device_status": 3 if paper else 2,
        "syno_system_status": 1, "syno_power_status": 1, "syno_system_fan": 1, "syno_cpu_fan": 1, "syno_update": 2,
        "idrac_status": 3, "idrac_power": 4, "ilo_health": 2,
    }
    return {k: float(x) for k, x in v.items()}


def snmp_metrics(device: Dict[str, Any], specs: List[Dict[str, Any]], t: Optional[float] = None) -> Dict[str, float]:
    """The values poll_snmp_metrics would read for these profile specs; empty during an outage."""
    t = time.time() if t is None else t
    if outage(device, t):
        return {}
    v = values(device, t)
    return {s["key"]: v[s["key"]] for s in specs if s.get("key") in v}


# --- Tables ---

def interface_plan(device: Dict[str, Any]) -> List[Tuple[str, int, str, bool, float, int]]:
    """(name, ifType, alias, link up, mean bits per second, Mbps) for each interface of the device."""
    tr = traits(device)
    kind, did = tr["kind"], device.get("id")
    if kind == "router":
        return [("eth0", 6, "WAN", True, 9e6, 1000), ("eth1", 6, "LAN", True, 8e6, 1000),
                ("eth2", 6, "", False, 0, 1000), ("lo", 24, "", True, 1e4, 0)]
    if kind == "switch":
        n = 16 if _u("ports", did) < 0.5 else 8
        rows = []
        for i in range(1, n + 1):
            up = i == 1 or _u("port-up", did, i) < 0.7
            mean = 25e6 if i == 1 else 0.3e6 + 8e6 * _u("port-bps", did, i) ** 2
            rows.append((f"Port {i}", 6, "Uplink" if i == 1 else "", up, mean if up else 0, 1000))
        return rows
    if kind == "ap":
        return [("eth0", 6, "Uplink", True, 5e6, 1000), ("wifi0", 71, "2.4 GHz", True, 1.5e6, 0),
                ("wifi1", 71, "5 GHz", True, 4e6, 0), ("lo", 24, "", True, 1e4, 0)]
    if kind in ("nas", "server", "hypervisor", "desktop"):
        mean = {"nas": 6e6, "server": 2e6, "hypervisor": 12e6, "desktop": 3e6}[kind] * (4 if tr["media"] else 1)
        return [("eth0", 6, "", True, mean, 1000), ("eth1", 6, "", kind == "nas", mean / 3 if kind == "nas" else 0, 1000),
                ("lo", 24, "", True, 2e4, 0)]
    return [("eth0", 6, "", True, 0.2e6, 100)]


def _mac(did: Any, i: int) -> str:
    raw = int(_u("mac", did, i) * 2 ** 40)
    return "02:" + ":".join(f"{(raw >> s) & 0xff:02x}" for s in (32, 24, 16, 8, 0))


def interfaces(device: Dict[str, Any], t: float) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, float]]:
    """Interface rows shaped as poller.TableCollector.collect_interfaces writes them, plus rate metrics."""
    import poller
    did = device.get("id")
    tr = traits(device)
    peak = 21 if tr["kind"] in ("ap", "router") or tr["media"] else 14
    boot = last_boot(device, t)
    rows, metrics = {}, {}
    for i, (name, if_type, alias, up, mean, mbps) in enumerate(interface_plan(device), start=1):
        idx = str(i)
        mean *= tr["traffic"]
        rate_in = max(0.0, mean * (1 + 0.7 * _daily(t, peak) + 0.25 * _smooth(t, 600, "if-in", did, i)))
        rate_out = max(0.0, mean * 0.3 * (1 + 0.5 * _daily(t, peak) + 0.3 * _smooth(t, 600, "if-out", did, i)))
        label = name
        r = {"descr": name, "if_type": if_type, "mtu": 1500, "mac": _mac(did, i), "admin": 1, "oper": 1 if up else 2,
             "in_octets": _counter(t, boot, mean, 0.7, peak), "out_octets": _counter(t, boot, mean * 0.3, 0.5, peak),
             "in_discards": 0, "in_errors": 0, "out_discards": 0, "out_errors": 0, "name": name,
             "in_ucast": _counter(t, boot, mean / 6000, 0.7, peak), "out_ucast": _counter(t, boot, mean / 20000, 0.5, peak),
             "speed_mbps": mbps if up else 0, "alias": alias, "if_index": i, "oper_text": "up" if up else "down",
             "admin_text": "up", "label": label, "kind": poller.classify_interface(label, if_type),
             "in_bps": round(rate_in) if up else 0, "out_bps": round(rate_out) if up else 0,
             "in_errors_delta": 0, "out_errors_delta": 0, "in_discards_delta": 0, "out_discards_delta": 0}
        rows[idx] = r
        if up and r["kind"] in poller.GRAPHED_IF_KINDS:
            metrics[f"if.{idx}.in_bps"] = float(r["in_bps"])
            metrics[f"if.{idx}.out_bps"] = float(r["out_bps"])
    return rows, metrics


def disk_used_pct(device: Dict[str, Any], t: float, n: int) -> float:
    """Disk n's fill level. The backup target climbs about 1.6 points a day from 76% and is cleaned
    up every ten days, so it spends a day or so above the 90% threshold; other disks grow slowly."""
    did = device.get("id")
    if traits(device)["disk_creep"] and n == 1:
        days = (t / DAY + 10 * _u("creep", did)) % 10
        return round(76 + 1.6 * days + 0.2 * _smooth(t, 3600, "disk", did, n), 2)
    base = 25 + 40 * _u("disk-base", did, n)
    days = (t / DAY + 60 * _u("disk-cycle", did, n)) % 60
    return round(base + 0.08 * days + 0.1 * _smooth(t, 3600, "disk", did, n), 2)


def storage(device: Dict[str, Any], t: float) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, float]]:
    """hrStorage rows (memory and disks) and the stor.<n>.used_pct metrics of the disks."""
    tr = traits(device)
    mounts = {"nas": [("/volume1", 8 * 2 ** 40)], "hypervisor": [("datastore1", 4 * 2 ** 40)],
              "desktop": [("C:\\", 2 ** 40)], "router": [("/root.dev", 2 ** 30)]}.get(tr["kind"], [("/", 120 * 2 ** 30)])
    if tr["disk_creep"]:
        mounts = [("/mnt/backup", 12 * 2 ** 40), ("/", 64 * 2 ** 30)]
    elif tr["media"]:
        mounts = [("/", 120 * 2 ** 30), ("/srv/media", 6 * 2 ** 40)]
    mem_pct = values(device, t)["mem_used_pct"]
    rows = {"1": {"descr": "Physical memory", "kind": "ram", "size_bytes": tr["mem_kb"] * 1024,
                  "used_bytes": int(tr["mem_kb"] * 1024 * mem_pct / 100), "used_pct": mem_pct}}
    metrics = {}
    for n, (descr, size) in enumerate(mounts, start=1):
        pct = disk_used_pct(device, t, n)
        idx = str(30 + n)
        rows[idx] = {"descr": descr, "kind": "flash" if tr["kind"] == "router" else "disk", "size_bytes": size,
                     "used_bytes": int(size * pct / 100), "used_pct": pct}
        metrics[f"stor.{idx}.used_pct"] = pct
    return rows, metrics


def sensors(device: Dict[str, Any], t: float) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, float]]:
    import poller
    temp = values(device, t)["system_temp_c"]
    rows, metrics = {}, {}
    for i, (name, offset) in enumerate((("Package id 0", 12), ("Composite", 4), ("acpitz", -6)), start=1):
        slug = poller.metric_slug(name)
        value = round(temp + offset + 0.5 * _smooth(t, 900, "sensor", device.get("id"), i), 1)
        rows[str(i)] = {"name": name, "slug": slug, "temp_c": value}
        metrics[f"sensor.{slug}.temp_c"] = value
    return rows, metrics


def nas_tables(device: Dict[str, Any], profile: Dict[str, Any], t: float) -> Dict[str, Tuple[Dict[str, Any], Dict[str, float]]]:
    """Disks and volumes for profiles that define them (Synology, TrueNAS)."""
    did = device.get("id")
    wanted = {d.get("table") for d in profile.get("table_defs", [])}
    out: Dict[str, Tuple[Dict[str, Any], Dict[str, float]]] = {}
    if "disks" in wanted:
        rows, metrics = {}, {}
        for i in range(1, 5):
            temp = round(34 + 3 * _daily(t, 16) + 1.5 * _smooth(t, 1800, "disk-t", did, i) + i * 0.5, 1)
            rows[str(i)] = {"name": f"Disk {i}", "model": "NAS HDD 8TB", "smart": "Normal", "health": "Normal",
                            "temp_c": temp, "ok": True}
            metrics[f"disk.{i}.temp_c"] = temp
        out["disks"] = (rows, metrics)
    if "volumes" in wanted:
        size = 8 * 2 ** 40 if not traits(device)["disk_creep"] else 12 * 2 ** 40
        pct = disk_used_pct(device, t, 1)
        row = {"descr": "volume1" if profile.get("profile_id") != "truenas" else "tank", "ok": True,
               "status": "Normal" if profile.get("profile_id") != "truenas" else "Online",
               "size_bytes": size, "used_bytes": int(size * pct / 100), "free_bytes": int(size * (1 - pct / 100)),
               "used_pct": pct}
        out["volumes"] = ({"1": row}, {"vol.1.used_pct": pct})
    return out


def inventory(device: Dict[str, Any]) -> Dict[str, str]:
    model = {"router": "Demo Router R4", "switch": "Demo Switch S16", "ap": "Demo Access Point AC",
             "nas": "Demo NAS 4-bay", "hypervisor": "Demo Server 2U", "server": "Virtual machine",
             "desktop": "Demo Desktop", "printer": "Demo Laser 200", "ups": "Demo UPS 1500"}.get(traits(device)["kind"], "Demo device")
    return {"sys_descr": f"{model} (simulated by demo mode)", "sys_name": str(device.get("hostname") or ""),
            "sys_location": "Demo lab", "sys_contact": "admin@example.com", "model": model, "firmware": "1.0.0-demo"}


def tables(device: Dict[str, Any], profile: Optional[Dict[str, Any]],
           t: float) -> Dict[str, Tuple[Dict[str, Dict[str, Any]], Dict[str, float]]]:
    """Every table the profile collects that the simulation covers: {name: (rows, metrics)}."""
    profile = profile or {}
    wanted = profile.get("tables", ["interfaces"])
    out = {}
    if "interfaces" in wanted:
        out["interfaces"] = interfaces(device, t)
    if "storage" in wanted:
        out["storage"] = storage(device, t)
    if "sensors" in wanted:
        out["sensors"] = sensors(device, t)
    out.update(nas_tables(device, profile, t))
    return out


def collect_tables(device: Dict[str, Any], profile: Optional[Dict[str, Any]], t: Optional[float] = None) -> List[str]:
    """Stands in for poller.collect_tables: writes the inventory and tables. Returns the tables written."""
    t = time.time() if t is None else t
    if outage(device, t):
        return []
    now = int(t)
    database.update_inventory(device["id"], inventory(device))
    written = []
    for name, (rows, metrics) in tables(device, profile, t).items():
        database.replace_device_table(device["id"], name, rows, now)
        if metrics:
            database.record_metrics(device["id"], metrics, now)
        written.append(name)
    return written


def live_sample(device: Dict[str, Any], profile: Optional[Dict[str, Any]], t: Optional[float] = None) -> Dict[str, Any]:
    """Stands in for poller.live_sample: the same shape, nothing written."""
    t = time.time() if t is None else t
    sample: Dict[str, Any] = {"timestamp": t, "alive": False, "metrics": {}, "counters": {}}
    alive, ping_ms = ping(device, t)
    sample["alive"] = alive
    if device.get("service_port"):
        open_, connect_ms, _ = service(device, t)
        sample["alive"] = alive or open_
        sample["metrics"]["service_up"] = 1.0 if open_ else 0.0
        if alive:
            sample["metrics"]["icmp_ping_ms"] = ping_ms or 0.0
        if open_:
            sample["metrics"]["tcp_connect_ms"] = connect_ms
        return sample
    if not alive:
        return sample
    import poller
    specs = list((profile or {}).get("metrics", [])) or [{"key": "uptime_seconds"}]
    sample["metrics"]["icmp_ping_ms"] = ping_ms or 0.0
    metrics = snmp_metrics(device, specs, t)
    metrics.update(poller.derive_metrics(metrics))
    sample["metrics"].update(metrics)
    rows, _ = interfaces(device, t)
    sample["counters"] = {idx: (r["in_octets"], r["out_octets"]) for idx, r in rows.items()}
    return sample


# --- Seed ---

# (hostname, address, profile, service port, web check URL, upstream hostname, group, tags)
DEMO_DEVICES = [
    ("edge-router", "192.0.2.1", "ubiquiti_edgeos", 0, None, None, None, ["critical"]),
    ("core-switch", "192.0.2.2", "unifi_switch", 0, None, "edge-router", None, ["critical"]),
    ("switch-office", "192.0.2.3", "hp_aruba_switch", 0, None, "core-switch", None, []),
    ("wifi-ap-livingroom", "192.0.2.10", "unifi_ap", 0, None, "core-switch", "Living room", []),
    ("wifi-ap-office", "192.0.2.11", "unifi_ap", 0, None, "switch-office", None, []),
    ("nas-01", "192.0.2.20", "synology_dsm", 0, None, "core-switch", None, ["critical", "backup"]),
    ("nas-01-web", "192.0.2.20", "service_check", 5001, None, "nas-01", None, []),
    ("backup-nas", "192.0.2.21", "truenas", 0, None, "core-switch", None, ["backup"]),
    ("hypervisor-01", "192.0.2.30", "vmware_esxi", 0, None, "core-switch", "Lab", ["lab"]),
    ("media-server", "192.0.2.31", "linux_host", 0, None, "hypervisor-01", "Lab", ["lab"]),
    ("pihole", "192.0.2.53", "linux_host", 0, None, "hypervisor-01", None, ["critical", "dns"]),
    ("desktop-01", "192.0.2.60", "windows_host", 0, None, "switch-office", None, []),
    ("printer", "192.0.2.70", "printer", 0, None, "switch-office", None, []),
    ("ups", "192.0.2.80", "apc_ups", 0, None, "core-switch", None, ["critical"]),
    ("smart-tv", "198.51.100.40", "ping_only", 0, None, "wifi-ap-livingroom", "Living room", []),
    ("web-check", "203.0.113.10", "service_check", 443, "https://www.example.com/", None, None, []),
]
SEED_DAYS = 7


class SeedRefused(RuntimeError):
    pass


@contextlib.contextmanager
def _batched_writes() -> Iterator[None]:
    """Routes database.get_connection through one connection without a disk flush per commit.

    The backfill makes tens of thousands of small writes through the app's own functions; a
    fresh connection and a synced commit for each would take minutes. The file is flushed and
    checkpointed once at the end."""
    conn = sqlite3.connect(database.DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA synchronous = OFF;")

    @contextlib.contextmanager
    def shared() -> Iterator[sqlite3.Connection]:
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise

    original = database.get_connection
    database.get_connection = shared
    try:
        yield
    finally:
        database.get_connection = original
        conn.commit()
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.close()


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < DAY:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // DAY}d {seconds % DAY // 3600}h"


def _layout(ids: Dict[str, int], parents: Dict[str, Optional[str]]) -> Dict[str, List[float]]:
    """A top-down tree for the network map, in the map's own units (196 x 64 boxes)."""
    kids: Dict[Optional[str], List[str]] = {}
    for name in ids:
        kids.setdefault(parents.get(name), []).append(name)
    pos: Dict[str, List[float]] = {}

    def width(name: str) -> int:
        return max(1, sum(width(k) for k in kids.get(name, [])))

    def place(name: str, left: int, depth: int) -> None:
        w = width(name)
        pos[f"d:{ids[name]}"] = [float(left + (w - 1) * 120), float(depth * 140)]
        x = left
        for k in kids.get(name, []):
            place(k, x, depth + 1)
            x += width(k) * 240

    x = 0
    for root in kids.get(None, []):
        place(root, x, 0)
        x += width(root) * 240
    return pos


def _profiles() -> Dict[str, Dict[str, Any]]:
    import poller
    return {p["profile_id"]: p for p in poller.load_hardware_profiles()}


def _snmp_specs(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    specs = list(profile.get("metrics", []))
    if not any(s.get("key") == "uptime_seconds" for s in specs):
        specs.insert(0, {"key": "uptime_seconds", "history": "none"})
    return specs


def _backfill(device: Dict[str, Any], profile: Dict[str, Any], start: int, now: int) -> int:
    """Writes SEED_DAYS of history for one device through the app's own functions. Returns samples."""
    import availability
    import poller
    did = device["id"]
    uses_snmp = profile.get("snmp", True) and bool(profile.get("metrics"))
    specs = _snmp_specs(profile)
    history = {s["key"]: s["history"] for s in specs if s.get("history")}
    samples = 0
    t = start
    while t <= now:
        port = device.get("service_port") or 0
        alive, ping_ms = ping(device, t)
        if port:
            up, ms, extra = service(device, t)
            m = {"service_up": 1.0 if up else 0.0, **extra}
            if alive:
                m["icmp_ping_ms"] = ping_ms or 0.0
            if up:
                m["http_response_ms" if device.get("service_kind") == "http" else "tcp_connect_ms"] = ms
            database.record_metrics(did, m, timestamp=t)
            availability.record(did, up, ms if up else None, ts=t)
        else:
            if alive:
                database.record_metrics(did, {"icmp_ping_ms": ping_ms or 0.0}, timestamp=t)
            availability.record(did, alive, ping_ms, ts=t)
        if uses_snmp and alive:
            m = snmp_metrics(device, specs, t)
            m.update(poller.derive_metrics(m))
            database.record_metrics(did, m, timestamp=t, history=history)
            extra: Dict[str, float] = {}
            for _rows, metrics in tables(device, profile, t).values():
                extra.update(metrics)
            database.record_metrics(did, extra, timestamp=t)
        samples += 1
        # Five minutes apart over the last two days, fifteen before that.
        t += 300 if now - t <= 2 * DAY else 900
    return samples


def _past_events(device: Dict[str, Any], profile: Dict[str, Any], start: int, now: int) -> int:
    """Events the problem engine and poller would have logged over the backfilled week."""
    did, events = device["id"], []
    port = device.get("service_port") or 0
    web = device.get("service_kind") == "http" and device.get("service_url")
    what = device["service_url"] if web else f"port {port}"
    down_text = f"Unreachable: no ping reply and {what} not answering" if port else "Device unreachable (no ICMP reply)"
    uses_snmp = profile.get("snmp", True) and bool(profile.get("metrics"))
    events.append((start, "info", "config", f"Device added to monitoring ({device['ip_address']}, profile {device['profile_id']})"))
    for a, b in outages_between(device, start, now):
        events.append((a + 60, "critical", "problem", f"Problem: {down_text}"))
        if b <= now:
            events.append((b, "info", "problem", f"Resolved: {down_text} (lasted {_duration(b - a - 60)})"))
            if uses_snmp:
                before = values(device, a - 1)["uptime_seconds"]
                events.append((b + 120, "warning", "reboot", f"Device restarted (uptime reset from {before / DAY:.1f} days)"))
    if traits(device)["disk_creep"] and "storage" in profile.get("tables", []):
        full, since = False, 0
        for t in range(start, now, 900):
            pct = disk_used_pct(device, t, 1)
            if pct >= 90 and not full:
                full, since = True, t
                events.append((t, "warning", "problem", f"Problem: Storage /mnt/backup {pct:.0f}% full"))
            elif pct < 90 and full:
                full = False
                events.append((t, "info", "problem", f"Resolved: Storage /mnt/backup 90% full (lasted {_duration(t - since)})"))
    for ts, severity, kind, message in sorted(events):
        database.add_event(did, severity, kind, message, ts)
    return len(events)


def existing_real_devices() -> List[Dict[str, Any]]:
    return [d for d in database.list_devices() if not is_demo_address(d["ip_address"])]


def seed(force: bool = False, days: int = SEED_DAYS, now: Optional[int] = None, log=print) -> Dict[str, Any]:
    """Creates the demo devices with groups, tags, a map layout, history and past events.

    Raises SeedRefused when the database holds a device outside the documentation ranges and
    force is not set, or when the demo devices are already there. Creates no user account."""
    import server
    import taxonomy
    os.makedirs(os.path.dirname(os.path.abspath(database.DB_FILE)), exist_ok=True)
    server.initialise()
    real = existing_real_devices()
    if real and not force:
        names = ", ".join(f"{d['hostname']} ({d['ip_address']})" for d in real[:5])
        raise SeedRefused(f"The database at {database.DB_FILE} holds devices outside the documentation ranges: {names}. "
                          "Seed a fresh database (set MONITOR_DB_PATH) or pass --force to add the demo devices anyway.")
    present = {(d["hostname"], d["ip_address"]) for d in database.list_devices()}
    if any((h, ip) in present for h, ip, *_ in DEMO_DEVICES):
        raise SeedRefused("The demo devices are already in this database. Delete the database file to seed it again.")

    profiles = _profiles()
    groups_before = taxonomy.group_ids()
    tags_before = {x["name"].lower() for x in taxonomy.tags()}
    now = int(now if now is not None else time.time())
    start = now - days * DAY
    start -= start % 300
    ids: Dict[str, int] = {}
    groups: Dict[str, str] = {}
    totals = {"devices": 0, "samples": 0, "events": 0}
    with _batched_writes():
        for host, ip, profile_id, port, url, up, group, tags in DEMO_DEVICES:
            ids[host] = database.add_device(host, ip, profile_id, snmp_community="public", service_port=port)
            if url:
                database.set_service_check(ids[host], "http", url, {"status": "200-399"})
            if group and group not in groups:
                groups[group] = taxonomy.add_group(group)
            database.set_device_overrides(ids[host], groups.get(group) if group else None,
                                          ids.get(up) if up else None, None, {})
            if tags:
                taxonomy.set_device_tags(ids[host], tags)
        database.save_map_positions(_layout(ids, {h: u for h, _ip, _p, _port, _url, u, _g, _t in DEMO_DEVICES}), replace=True)
        for device in database.list_devices():
            if device["id"] not in ids.values():
                continue
            profile = profiles.get(device["profile_id"], {})
            log(f"Backfilling {device['hostname']} ({device['ip_address']}, {device['profile_id']})")
            totals["samples"] += _backfill(device, profile, start, now)
            totals["events"] += _past_events(device, profile, start, now)
            alive, ping_ms = ping(device, now)
            up = service(device, now)[0] if device.get("service_port") else alive
            database.update_device_status(device["id"], "online" if up else "degraded" if alive else "offline", ping_ms)
            if profile.get("snmp", True) and profile.get("metrics"):
                database.set_snmp_status(device["id"], "ok" if alive else "no_response")
                collect_tables(device, profile, now)
            totals["devices"] += 1
        database.rollup_hourly(now)
    import json
    made = {"devices": sorted(ids.values()), "groups": sorted(set(groups.values()) - groups_before),
            "tags": sorted({tg for *_x, tg_list in DEMO_DEVICES for tg in (tg_list or []) if tg.lower() not in tags_before})}
    database.set_internal_setting(SEED_KEY, json.dumps(made))
    database.set_internal_setting(MODE_KEY, "on")
    _forget()
    import setup
    setup.mark_completed()           # straight to the dashboard; removing the demo brings the setup guide back
    database.add_audit("device", f"Demo devices seeded ({totals['devices']} devices, {days} days of history)")
    log(f"Seeded {totals['devices']} demo devices, {totals['samples']} poll rounds and {totals['events']} events "
        f"into {database.DB_FILE}")
    return dict(totals, ids=ids)


def status() -> Dict[str, Any]:
    """Whether demo mode is on and how many of its devices are still there (Settings, Demo data)."""
    import json
    try:
        made = json.loads(database.get_all_settings().get(SEED_KEY) or "{}")
    except ValueError:
        made = {}
    present = {d["id"] for d in database.list_devices() if is_demo_address(d["ip_address"])}
    on = database.get_all_settings().get(MODE_KEY) == "on"
    return {"on": on, "devices": len(present & set(made.get("devices") or []))}


def remove(log=print) -> Dict[str, int]:
    """Takes the demo away: its devices (with their history, events and map places), then the groups
    and tags it added when no other device uses them, and turns demo mode off. A device the seed
    made but someone has since moved to a real address is left alone."""
    import json
    import taxonomy
    try:
        made = json.loads(database.get_all_settings().get(SEED_KEY) or "{}")
    except ValueError:
        made = {}
    by_id = {d["id"]: d for d in database.list_devices()}
    gone = 0
    for did in made.get("devices") or []:
        d = by_id.get(int(did))
        if d and is_demo_address(d["ip_address"]) and database.delete_device(d["id"]):
            gone += 1
    left = database.list_devices()
    groups = 0
    for gid in made.get("groups") or []:
        if gid in taxonomy.group_ids() and not any(d.get("device_group") == gid for d in left):
            taxonomy.delete_group(gid)
            groups += 1
    in_use = {tg.lower() for d in left for tg in taxonomy.device_tags(d)}
    tags = 0
    for name in made.get("tags") or []:
        if name.lower() not in in_use and any(x["name"].lower() == name.lower() for x in taxonomy.tags()):
            taxonomy.delete_tag(name)
            tags += 1
    database.set_internal_setting(MODE_KEY, "off")
    database.set_internal_setting(SEED_KEY, "")
    _forget()
    database.add_audit("device", f"Demo data removed ({gone} devices, {groups} groups, {tags} tags)")
    log(f"Removed {gone} demo devices, {groups} groups and {tags} tags; demo mode is off")
    return {"devices": gone, "groups": groups, "tags": tags}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Homelab Monitor demo mode: seed a database with simulated devices.")
    parser.add_argument("command", nargs="?", choices=["seed"], help="seed: create the demo devices and history")
    parser.add_argument("--seed", action="store_true", help="The same as the seed command")
    parser.add_argument("--force", action="store_true", help="Seed even when the database holds devices with real addresses")
    parser.add_argument("--days", type=int, default=SEED_DAYS, help="Days of history to backfill (default 7)")
    args = parser.parse_args(argv)
    if args.command != "seed" and not args.seed:
        parser.print_help()
        return 2
    try:
        seed(force=args.force, days=max(1, min(30, args.days)))
    except SeedRefused as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    print("Demo mode is on: the running monitor keeps these devices supplied with made-up readings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
