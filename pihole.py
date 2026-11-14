"""Pi-hole: query and blocking figures from its own web API, and whether DNS answers.

Pi-hole has no SNMP. It has an HTTP API on the local network:
  Pi-hole 6  POST /api/auth with the password or an app password gives a session id (sid),
             reused until it expires; then /api/stats/summary, /api/stats/upstreams,
             /api/stats/top_domains?blocked=true and /api/dns/blocking.
  Pi-hole 5  /admin/api.php?summaryRaw, ?getForwardDestinations and ?topItems, each with
             &auth=<API token> (Settings, API, Show API token).
The version is found on the first connection. The password or token is stored vault-encrypted
(setting pihole_secret) and never sent to the browser.

The DNS check asks the Pi-hole itself (UDP 53, a plain A query for a test name, standard library
only) and times the answer. The monitor talks only to the Pi-hole; any lookup further out is the
Pi-hole's own doing, exactly as for every other device in the house.

Figures are stored as metrics on the monitored device that is the Pi-hole (chosen in Settings,
found by address by default), so they get graphs, history and alert rules like any other value:
  pihole.queries        queries today          pihole.blocked_pct   share blocked today (%)
  pihole.blocked        blocked today          pihole.clients       active clients
  pihole.blocking       1 on, 0 off            pihole.gravity_days  age of the blocklists (days)
  pihole.domains        domains on the lists   dns.ms               DNS answer time (ms)
  dns.ok                1 answered, 0 failed
Tables on that device: pihole_upstreams (where queries go, how fast), pihole_blocked (top blocked),
pihole_allowed (most asked), pihole_clients (busiest clients) and pihole_types (query types, Pi-hole 6).

Pause (the Pi-hole page): blocking off for a few minutes, then back on by itself (v6 /api/dns/blocking
with a timer, v5 ?disable=<seconds>), or on again now. A pause with a timer is reported as
pihole.paused = 1, which the "blocking switched off" rule leaves alone: only blocking that was
switched off with no end in sight is a problem.
"""

import os
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import database
import lanhttp
from lanhttp import LanError

KEYS = {"url": "pihole_url", "secret": "pihole_secret", "fingerprint": "pihole_fingerprint",
        "device_id": "pihole_device_id", "test_name": "pihole_test_name"}
ENABLED_KEY = "pihole_enabled"
DEFAULT_TEST_NAME = "example.com"
PAUSED_KEY = "pihole_paused_until"     # set by a pause from the monitor (Pi-hole 5 reports no timer)
MAX_PAUSE = 24 * 3600
DNS_TIMEOUT = 2.0


class PiholeError(Exception):
    pass


def load_config() -> Dict[str, str]:
    s = database.get_all_settings()
    return {k: s.get(v, "") or "" for k, v in KEYS.items()}


def is_enabled() -> bool:
    return database.get_all_settings().get(ENABLED_KEY) == "on"


def is_configured() -> bool:
    c = load_config()
    return bool(c["url"] and c["secret"])


def set_enabled(on: bool) -> None:
    database.set_internal_setting(ENABLED_KEY, "on" if on else "off")


def save_config(url: str, secret: Optional[str], fingerprint: str, device_id: Optional[int], test_name: str) -> None:
    """secret None keeps the stored one. url '' removes everything (disconnect)."""
    from vault import VAULT
    if not url:
        for v in KEYS.values():
            database.set_internal_setting(v, "")
        SESSION.clear()
        return
    try:
        lanhttp.parse_url(url, "the Pi-hole")
        fp = lanhttp.normalise_fingerprint(fingerprint)
    except LanError as exc:
        raise PiholeError(str(exc))
    database.set_internal_setting(KEYS["url"], url.strip().rstrip("/"))
    database.set_internal_setting(KEYS["fingerprint"], fp)
    database.set_internal_setting(KEYS["device_id"], str(device_id) if device_id else "")
    database.set_internal_setting(KEYS["test_name"], (test_name or "").strip() or DEFAULT_TEST_NAME)
    if secret is not None:
        database.set_internal_setting(KEYS["secret"], VAULT.encrypt(secret.strip(), f"setting:{KEYS['secret']}") if secret else "")
    SESSION.clear()


def public_config() -> Dict[str, Any]:
    c = load_config()
    return {"enabled": is_enabled(), "configured": is_configured(), "url": c["url"], "secret_set": bool(c["secret"]),
            "fingerprint": lanhttp.pretty_fingerprint(c["fingerprint"]) if c["fingerprint"] else "",
            "device_id": int(c["device_id"]) if c["device_id"].isdigit() else None,
            "test_name": c["test_name"] or DEFAULT_TEST_NAME, "version": SESSION.version, "last": LAST.copy()}


class Session:
    """The Pi-hole 6 session id, reused until it expires (Pi-hole allows only a few at once)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.clear()

    def clear(self) -> None:
        self.sid, self.until, self.version = "", 0.0, None


SESSION = Session()
LAST: Dict[str, Any] = {"at": None, "error": None}


def _v6_auth(cfg: Dict[str, str]) -> str:
    with SESSION.lock:
        if SESSION.sid and time.time() < SESSION.until - 30:
            return SESSION.sid
        r = lanhttp.request(cfg["url"], "POST", "/api/auth", cfg["fingerprint"], body={"password": cfg["secret"]})
        if r.status == 404:
            raise PiholeError("v5")
        data = r.json() or {}
        sess = data.get("session") or {}
        if r.status == 401 or not sess.get("valid"):
            raise PiholeError("Pi-hole refused the password. In Pi-hole 6 use the web interface password or an app "
                              "password (Settings, Web interface / API, Configure app password).")
        if r.status >= 400:
            raise PiholeError(f"Pi-hole answered {r.status} to the login")
        SESSION.sid = sess.get("sid") or ""
        SESSION.until = time.time() + float(sess.get("validity") or 300)
        SESSION.version = 6
        return SESSION.sid


def _v6_get(cfg: Dict[str, str], path: str) -> Any:
    for attempt in (1, 2):
        sid = _v6_auth(cfg)
        r = lanhttp.request(cfg["url"], "GET", path, cfg["fingerprint"], headers={"X-FTL-SID": sid})
        if r.status == 401 and attempt == 1:
            SESSION.clear()
            continue
        if r.status >= 400:
            raise PiholeError(f"Pi-hole answered {r.status} for {path}")
        return r.json()
    raise PiholeError("Pi-hole did not accept the session")


def _v5_get(cfg: Dict[str, str], query: str) -> Any:
    r = lanhttp.request(cfg["url"], "GET", f"/admin/api.php?{query}&auth={quote(cfg['secret'])}", cfg["fingerprint"])
    if r.status >= 400:
        raise PiholeError(f"Pi-hole answered {r.status}")
    data = r.json()
    if data in ([], None) or (isinstance(data, dict) and not data):
        raise PiholeError("Pi-hole 5 gave an empty answer: the API token is wrong (Settings, API, Show API token)")
    SESSION.version = 5
    return data


def collect(cfg: Dict[str, str], now: Optional[float] = None) -> Dict[str, Any]:
    """The figures, upstreams and top blocked domains, for either version."""
    now = now if now is not None else time.time()
    try:
        if SESSION.version != 5:
            try:
                return _collect_v6(cfg, now)
            except PiholeError as exc:
                if str(exc) != "v5":
                    raise
        return _collect_v5(cfg, now)
    except LanError as exc:
        raise PiholeError(str(exc))


def _collect_v6(cfg: Dict[str, str], now: float) -> Dict[str, Any]:
    s = _v6_get(cfg, "/api/stats/summary") or {}
    q, g = s.get("queries") or {}, s.get("gravity") or {}
    state = _v6_get(cfg, "/api/dns/blocking") or {}
    blocking = state.get("blocking")
    metrics = {"pihole.queries": q.get("total"), "pihole.blocked": q.get("blocked"),
               "pihole.blocked_pct": q.get("percent_blocked"), "pihole.clients": (s.get("clients") or {}).get("active"),
               "pihole.domains": g.get("domains_being_blocked"), "pihole.blocking": 1.0 if blocking == "enabled" else 0.0,
               "pihole.cached": q.get("cached"), "pihole.forwarded": q.get("forwarded"),
               "pihole.unique_domains": q.get("unique_domains"), "pihole.qps": q.get("frequency")}
    if blocking != "enabled" and isinstance(state.get("timer"), (int, float)) and state["timer"] > 0:
        metrics["pihole.paused"] = 1.0
        metrics["pihole.pause_left"] = float(state["timer"])
    if g.get("last_update"):
        metrics["pihole.gravity_days"] = round((now - float(g["last_update"])) / 86400, 1)
    ups = []
    for u in (_v6_get(cfg, "/api/stats/upstreams") or {}).get("upstreams") or []:
        resp = (u.get("statistics") or {}).get("response")
        ups.append({"name": u.get("name") or u.get("ip"), "ip": u.get("ip"), "port": u.get("port"), "count": u.get("count"),
                    "response_ms": round(float(resp) * 1000, 1) if isinstance(resp, (int, float)) else None})
    top = [{"domain": d.get("domain"), "count": d.get("count")}
           for d in (_v6_get(cfg, "/api/stats/top_domains?blocked=true&count=10") or {}).get("domains") or []]
    allowed = [{"domain": d.get("domain"), "count": d.get("count")}
               for d in _optional(_v6_get, cfg, "/api/stats/top_domains?blocked=false&count=10").get("domains") or []]
    clients = [{"name": c.get("name") or "", "ip": c.get("ip") or "", "count": c.get("count")}
               for c in _optional(_v6_get, cfg, "/api/stats/top_clients?count=10").get("clients") or []]
    types = [{"type": k, "count": v} for k, v in ((q.get("types") or {}).items()) if isinstance(v, (int, float)) and v > 0]
    types.sort(key=lambda t: -t["count"])
    return {"version": 6, "metrics": {k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))},
            "upstreams": ups, "blocked": top, "allowed": allowed, "clients": clients, "types": types[:10]}


def _optional(get: Any, cfg: Dict[str, str], path: str) -> Any:
    """An extra list (most asked, busiest clients): one Pi-hole cannot give does not stop the rest."""
    try:
        return get(cfg, path) or {}
    except PiholeError:
        return {}


def _num(v: Any) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _collect_v5(cfg: Dict[str, str], now: float) -> Dict[str, Any]:
    s = _v5_get(cfg, "summaryRaw")
    metrics = {"pihole.queries": s.get("dns_queries_today"), "pihole.blocked": s.get("ads_blocked_today"),
               "pihole.blocked_pct": s.get("ads_percentage_today"), "pihole.clients": s.get("unique_clients"),
               "pihole.domains": s.get("domains_being_blocked"), "pihole.blocking": 1.0 if s.get("status") == "enabled" else 0.0,
               "pihole.cached": s.get("queries_cached"), "pihole.forwarded": s.get("queries_forwarded"),
               "pihole.unique_domains": s.get("unique_domains")}
    last = (s.get("gravity_last_updated") or {}).get("absolute")
    if last:
        metrics["pihole.gravity_days"] = round((now - float(last)) / 86400, 1)
    fwd = (_v5_get(cfg, "getForwardDestinations") or {}).get("forward_destinations") or {}
    ups = [{"name": k.split("|")[0], "ip": k.split("|")[-1], "port": None, "count": None, "share_pct": _num(v), "response_ms": None}
           for k, v in fwd.items()]
    items = _v5_get(cfg, "topItems=10") or {}
    top = [{"domain": d, "count": c} for d, c in (items.get("top_ads") or {}).items()]
    allowed = [{"domain": d, "count": c} for d, c in (items.get("top_queries") or {}).items()] if isinstance(items.get("top_queries"), dict) else []
    sources = _optional(_v5_get, cfg, "topClients=10").get("top_sources") or {}
    if not isinstance(sources, dict):
        sources = {}
    clients = [{"name": k.split("|")[0] if "|" in k else "", "ip": k.split("|")[-1], "count": v} for k, v in sources.items()]
    return {"version": 5, "metrics": {k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))},
            "upstreams": ups, "blocked": top, "allowed": allowed, "clients": clients, "types": []}


# --- DNS check ---------------------------------------------------------------

def _dns_query(name: str) -> bytes:
    qid = int.from_bytes(os.urandom(2), "big")
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".") if p)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def dns_check(server: str, name: str = DEFAULT_TEST_NAME, timeout: float = DNS_TIMEOUT) -> Dict[str, Any]:
    """Asks server for name's A record. {"ok", "ms", "error"}; ok means an answer without an error code
    (NXDOMAIN counts as answered: the resolver works, the name just does not exist)."""
    try:
        packet = _dns_query(name)
    except (UnicodeError, ValueError):
        return {"ok": False, "ms": None, "error": "The test name is not a valid host name"}
    sock = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.sendto(packet, (server, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if data[:2] == packet[:2]:
                break
        ms = round((time.perf_counter() - start) * 1000, 2)
    except (OSError, socket.timeout):
        return {"ok": False, "ms": None, "error": "no answer"}
    finally:
        sock.close()
    rcode = data[3] & 0x0F if len(data) >= 4 else 2
    if rcode in (0, 3):
        return {"ok": True, "ms": ms, "error": None}
    return {"ok": False, "ms": ms, "error": {2: "server failure", 5: "refused"}.get(rcode, f"error code {rcode}")}


def pihole_device(cfg: Dict[str, str], devices: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The monitored device the figures belong to: the one chosen, or the one with the Pi-hole's address."""
    if cfg["device_id"].isdigit():
        hit = next((d for d in devices if d["id"] == int(cfg["device_id"])), None)
        if hit:
            return hit
    try:
        _, host, _ = lanhttp.parse_url(cfg["url"])
    except LanError:
        return None
    return next((d for d in devices if d["ip_address"] == host), None)


def run(devices: List[Dict[str, Any]], now: Optional[float] = None) -> Optional[str]:
    """One round (the scheduler calls it every poll): figures, DNS check, stored on the Pi-hole device.
    Returns an error for the settings page, or None."""
    now = now if now is not None else time.time()
    if not is_enabled() or not is_configured():
        return None
    cfg = load_config()
    device = pihole_device(cfg, devices)
    error = None
    metrics: Dict[str, float] = {}
    try:
        data = collect(cfg, now)
        metrics.update(data["metrics"])
        if device:
            database.replace_device_table(device["id"], "pihole_upstreams", {str(i): u for i, u in enumerate(data["upstreams"])}, int(now))
            database.replace_device_table(device["id"], "pihole_blocked", {str(i): b for i, b in enumerate(data["blocked"])}, int(now))
            for table, key in (("pihole_allowed", "allowed"), ("pihole_clients", "clients"), ("pihole_types", "types")):
                database.replace_device_table(device["id"], table, {str(i): r for i, r in enumerate(data.get(key) or [])}, int(now))
    except PiholeError as exc:
        error = str(exc)
    try:
        _, host, _ = lanhttp.parse_url(cfg["url"])
        server = device["ip_address"] if device else host
        d = dns_check(server, cfg["test_name"] or DEFAULT_TEST_NAME)
        metrics["dns.ok"] = 1.0 if d["ok"] else 0.0
        if d["ms"] is not None:
            metrics["dns.ms"] = d["ms"]
    except LanError:
        pass
    # A pause started here (Pi-hole 5 cannot say it has a timer).
    until = float(database.get_all_settings().get(PAUSED_KEY) or 0)
    if metrics.get("pihole.blocking") == 0 and until > now:
        metrics["pihole.paused"] = 1.0
        metrics.setdefault("pihole.pause_left", round(until - now))
    elif "pihole.blocking" in metrics:
        metrics.setdefault("pihole.paused", 0.0)
    if device and metrics:
        database.record_metrics(device["id"], metrics, int(now))
    elif not device and error is None:
        error = "No monitored device has the Pi-hole's address: add it (Ping only is enough) or choose it below."
    LAST.update(at=int(now), error=error)
    return error


def set_blocking(enabled: bool, seconds: Optional[int] = None, now: Optional[float] = None) -> None:
    """Blocking on, or off for `seconds` (then on again by itself). Raises PiholeError."""
    now = now if now is not None else time.time()
    if not is_enabled() or not is_configured():
        raise PiholeError("Pi-hole is not connected (Settings, Pi-hole)")
    if not enabled and not (seconds and 0 < seconds <= MAX_PAUSE):
        raise PiholeError("A pause lasts from a second to a day")
    cfg = load_config()
    try:
        if SESSION.version != 5:
            try:
                sid = _v6_auth(cfg)
                r = lanhttp.request(cfg["url"], "POST", "/api/dns/blocking", cfg["fingerprint"], headers={"X-FTL-SID": sid},
                                    body={"blocking": bool(enabled), "timer": None if enabled else int(seconds)})
                if r.status >= 400:
                    raise PiholeError(f"Pi-hole answered {r.status}: the app password may only read. Use one that may change settings.")
                _remember_pause(enabled, seconds, now)
                return
            except PiholeError as exc:
                if str(exc) != "v5":
                    raise
        _v5_get(cfg, "enable" if enabled else f"disable={int(seconds)}")
        _remember_pause(enabled, seconds, now)
    except LanError as exc:
        raise PiholeError(str(exc))


def _remember_pause(enabled: bool, seconds: Optional[int], now: float) -> None:
    database.set_internal_setting(PAUSED_KEY, "" if enabled else str(int(now + seconds)))


def view(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The Pi-hole page: the figures last read, the tables and the pause state."""
    cfg = load_config()
    device = pihole_device(cfg, devices) if is_configured() else None
    out: Dict[str, Any] = {"configured": is_configured() and is_enabled(), "device": None, "metrics": {}, "upstreams": [],
                           "blocked": [], "allowed": [], "clients": [], "types": [], "last": LAST.copy(), "version": SESSION.version}
    if not device:
        return out
    latest = {m["metric_key"]: m for m in database.get_latest_metrics(device["id"])}
    out["device"] = {"id": device["id"], "hostname": device["hostname"], "ip": device["ip_address"]}
    out["metrics"] = {k: {"value": m["value"], "at": m["timestamp"]} for k, m in latest.items() if k.startswith(("pihole.", "dns."))}
    out["upstreams"] = list(database.get_device_table(device["id"], "pihole_upstreams").values())
    out["blocked"] = list(database.get_device_table(device["id"], "pihole_blocked").values())
    for table, key in (("pihole_allowed", "allowed"), ("pihole_clients", "clients"), ("pihole_types", "types")):
        rows = list(database.get_device_table(device["id"], table).values())
        out[key] = sorted(rows, key=lambda r: -(r.get("count") or 0))
    return out


def test(cfg: Dict[str, str]) -> Dict[str, Any]:
    """Settings, Test connection: version, a few figures and the DNS answer time."""
    SESSION.clear()
    data = collect(cfg)
    _, host, _ = lanhttp.parse_url(cfg["url"])
    d = dns_check(host, cfg.get("test_name") or DEFAULT_TEST_NAME)
    m = data["metrics"]
    return {"version": data["version"], "queries": m.get("pihole.queries"), "blocked_pct": m.get("pihole.blocked_pct"),
            "blocking": m.get("pihole.blocking") == 1.0, "upstreams": len(data["upstreams"]), "dns": d}
