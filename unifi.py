"""UniFi: what each Wi-Fi device experiences, from the UniFi Network application.

The access points' SNMP only gives totals per radio. Per-device detail (signal, access point,
band, rate, retries, roaming, UniFi's own experience score) lives in the Network application,
which on a UniFi OS gateway (UCG, UDM, Cloud Key) runs on the gateway itself. The monitor logs
in with a local account made for it (role View Only, no 2FA, local access only) and reads:
  UniFi OS        POST /api/auth/login, then /proxy/network/api/s/<site>/stat/sta and stat/device
  older software  POST /api/login, then /api/s/<site>/stat/sta and stat/device
Everything stays on the local network; nothing is changed on the UniFi side. The password is
stored vault-encrypted (setting unifi_secret) and never sent to the browser. The login cookie is
kept in memory and reused until UniFi asks for a new login.

Results:
  wifi_clients table on each monitored access point (matched by address or MAC): one row per
               Wi-Fi device with its name, signal, band, channel, rates, retries, roams, experience
  metrics on the access point: wifi.weak (devices below the weak-signal line), wifi.experience
               (average experience score, 0 to 100)
  every client (wired too) for the inventory: name, maker, address, where it is connected
  the layout (setting unifi_topology): each UniFi device's uplink (device and port) and port names,
               and where each client is connected; the map uses it (server.map_view)

Reconnect (the Wi-Fi page and the workflow step "Reconnect weak Wi-Fi devices"): UniFi's
kick-sta command, which drops a device so it joins again, ideally to a nearer access point. It
needs an account that may make changes. Guard rails: at most once an hour per device, and never
for the devices listed in Settings, UniFi (printers and gadgets often handle it badly).
"""

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import database
import lanhttp
from lanhttp import LanError

KEYS = {"url": "unifi_url", "username": "unifi_username", "secret": "unifi_secret",
        "fingerprint": "unifi_fingerprint", "site": "unifi_site"}
ENABLED_KEY = "unifi_enabled"
TOPOLOGY_KEY = "unifi_topology"
NEVER_KEY = "unifi_never_reconnect"      # names or MACs, comma separated
RECONNECTED_KEY = "unifi_reconnected"    # {mac: last reconnect time}
RECONNECT_EVERY = 3600
BANDS = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}


class UnifiError(Exception):
    pass


def load_config() -> Dict[str, str]:
    s = database.get_all_settings()
    c = {k: s.get(v, "") or "" for k, v in KEYS.items()}
    c["site"] = c["site"] or "default"
    return c


def is_enabled() -> bool:
    return database.get_all_settings().get(ENABLED_KEY) == "on"


def is_configured() -> bool:
    c = load_config()
    return bool(c["url"] and c["username"] and c["secret"])


def set_enabled(on: bool) -> None:
    database.set_internal_setting(ENABLED_KEY, "on" if on else "off")


def save_config(url: str, username: str, secret: Optional[str], fingerprint: str, site: str) -> None:
    from vault import VAULT
    if not url:
        for v in KEYS.values():
            database.set_internal_setting(v, "")
        SESSION.clear()
        return
    try:
        scheme, _, _ = lanhttp.parse_url(url, "the UniFi gateway")
        fp = lanhttp.normalise_fingerprint(fingerprint)
    except LanError as exc:
        raise UnifiError(str(exc))
    if scheme != "https":
        raise UnifiError("UniFi only answers over https://, for example https://192.168.1.1")
    if not username.strip():
        raise UnifiError("Enter the username of the local UniFi account made for the monitor")
    if len(site or "") > 40 or not all(ch.isalnum() or ch in "-_ " for ch in (site or "default")):
        raise UnifiError("The site is its name or id: letters, digits, spaces, - and _ (usually default)")
    database.set_internal_setting(KEYS["url"], url.strip().rstrip("/"))
    database.set_internal_setting(KEYS["username"], username.strip())
    database.set_internal_setting(KEYS["fingerprint"], fp)
    database.set_internal_setting(KEYS["site"], site or "default")
    if secret is not None:
        database.set_internal_setting(KEYS["secret"], VAULT.encrypt(secret, f"setting:{KEYS['secret']}") if secret else "")
    SESSION.clear()


def public_config() -> Dict[str, Any]:
    c = load_config()
    return {"enabled": is_enabled(), "configured": is_configured(), "url": c["url"], "username": c["username"],
            "secret_set": bool(c["secret"]), "site": c["site"],
            "fingerprint": lanhttp.pretty_fingerprint(c["fingerprint"]) if c["fingerprint"] else "", "last": LAST.copy()}


class Session:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.clear()

    def clear(self) -> None:
        self.cookie, self.csrf, self.prefix, self.site = "", "", None, None


SESSION = Session()
LAST: Dict[str, Any] = {"at": None, "error": None, "clients": None, "aps": None}


def _login(cfg: Dict[str, str]) -> None:
    body = {"username": cfg["username"], "password": cfg["secret"], "rememberMe": False}
    r = lanhttp.request(cfg["url"], "POST", "/api/auth/login", cfg["fingerprint"], body=body)
    prefix = "/proxy/network"
    if r.status == 404:
        r = lanhttp.request(cfg["url"], "POST", "/api/login", cfg["fingerprint"], body=body)
        prefix = ""
    if r.status in (401, 403):
        raise UnifiError("UniFi refused the login. Use a local account (not a UI.com cloud account) without "
                         "two-step login: UniFi, Admins & Users, Create New Admin, Restrict to local access only.")
    if r.status == 429:
        raise UnifiError("UniFi is limiting logins for a while after too many attempts: wait a few minutes")
    if r.status >= 400:
        raise UnifiError(f"UniFi answered {r.status} to the login")
    cookie = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
    if not cookie:
        raise UnifiError("UniFi accepted the login but sent no session")
    # UniFi OS wants its CSRF token on every request. Most versions send it as a header with the
    # login; others only carry it inside the TOKEN cookie (a JWT, field csrfToken).
    csrf = r.headers.get("x-csrf-token") or r.headers.get("x-updated-csrf-token") or _csrf_from_jwt(r.cookies.get("TOKEN", ""))
    SESSION.cookie, SESSION.csrf, SESSION.prefix = cookie, csrf, prefix
    SESSION.site = _resolve_site(cfg)


def _request(cfg: Dict[str, str], path: str) -> lanhttp.Response:
    headers = {"Cookie": SESSION.cookie}
    if SESSION.csrf:
        headers["X-CSRF-Token"] = SESSION.csrf
    r = lanhttp.request(cfg["url"], "GET", f"{SESSION.prefix}{path}", cfg["fingerprint"], headers=headers)
    # UniFi OS may hand out a new CSRF token with any answer.
    SESSION.csrf = r.headers.get("x-updated-csrf-token") or SESSION.csrf
    return r


def _resolve_site(cfg: Dict[str, str]) -> str:
    """The site's internal id. The address uses the id (almost always "default"), while UniFi shows its
    name ("Home"): either is accepted. An unknown site answers 401 on UniFi OS, which looks like a
    permission problem, so it is checked here against the site list and named plainly."""
    wanted = (cfg.get("site") or "default").strip()
    r = _request(cfg, "/api/self/sites")
    if r.status >= 400:
        return wanted                      # older software without the list: use what was typed
    sites = [x for x in ((r.json() or {}).get("data") or []) if isinstance(x, dict) and x.get("name")]
    for x in sites:
        if wanted.lower() in (str(x["name"]).lower(), str(x.get("desc") or "").lower()):
            return str(x["name"])
    if sites:
        known = ", ".join(f"{x.get('desc') or x['name']} (id {x['name']})" for x in sites)
        raise UnifiError(f"UniFi has no site called '{wanted}'. Its sites: {known}. Enter the name or the id.")
    return wanted


def _csrf_from_jwt(token: str) -> str:
    """The csrfToken claim of a UniFi OS TOKEN cookie, or '' (read only, the signature is UniFi's business)."""
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return ""
    value = claims.get("csrfToken") if isinstance(claims, dict) else None
    return value if isinstance(value, str) else ""


def _get(cfg: Dict[str, str], path: str) -> List[Dict[str, Any]]:
    with SESSION.lock:
        for attempt in (1, 2):
            if not SESSION.cookie:
                _login(cfg)
            r = _request(cfg, f"/api/s/{quote(SESSION.site or cfg['site'], safe='')}{path}")
            if r.status == 401 and attempt == 1:
                SESSION.clear()
                continue
            if r.status in (401, 403):
                # Logged in (twice) but refused: the account has no access to the Network application.
                raise UnifiError("UniFi accepted the login but will not show the Network data: give the account access "
                                 "to the Network application. In UniFi, Admins & Users, open the account and set Network "
                                 "to View Only (not None).")
            if r.status == 400 or r.status == 404:
                raise UnifiError(f"UniFi does not know the site '{cfg['site']}' (its id is usually default)")
            if r.status >= 400:
                raise UnifiError(f"UniFi answered {r.status} for {path}")
            data = r.json() or {}
            return data.get("data") or []
    raise UnifiError("UniFi did not accept the session")


def _num(v: Any) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _channel(v: Any) -> Optional[int]:
    """A radio channel number, or None: never text from the controller passed on as is."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 1000 and not isinstance(v, bool) else None


def clients(cfg: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(clients, access points and switches) as UniFi lists them, reduced to what the monitor uses."""
    try:
        devs = _get(cfg, "/stat/device")
        stas = _get(cfg, "/stat/sta")
    except LanError as exc:
        raise UnifiError(str(exc))
    infra = []
    for d in devs:
        up = d.get("uplink") or {}
        infra.append({"mac": (d.get("mac") or "").lower(), "ip": d.get("ip"), "name": d.get("name") or d.get("model"),
                      "type": d.get("type"), "uplink_mac": (up.get("uplink_mac") or "").lower(),
                      "uplink_port": up.get("uplink_remote_port"), "uplink_type": up.get("type"),
                      "ports": {str(p.get("port_idx")): p.get("name") for p in d.get("port_table") or [] if p.get("port_idx")}})
    names = {d["mac"]: d["name"] for d in infra}
    out = []
    for s in stas:
        mac = (s.get("mac") or "").lower()
        wired = bool(s.get("is_wired"))
        ap = names.get((s.get("ap_mac") or "").lower()) if not wired else None
        sw = names.get((s.get("sw_mac") or "").lower()) if wired else None
        out.append({
            "mac": mac, "ip": s.get("ip") or s.get("last_ip"), "name": s.get("name") or s.get("hostname") or "",
            # UniFi writes a shrug for a maker it does not know.
            "vendor": "" if "(ツ)" in str(s.get("oui") or "") else s.get("oui") or "", "wired": wired, "ap": ap, "ap_mac": (s.get("ap_mac") or "").lower(),
            "wired_on": f"{sw} port {s.get('sw_port')}" if sw and s.get("sw_port") else (sw or ""),
            "ssid": s.get("essid"), "band": BANDS.get(s.get("radio"), s.get("radio")), "channel": _channel(s.get("channel")),
            "signal": _num(s.get("signal")), "tx_mbps": round(s["tx_rate"] / 1000, 1) if _num(s.get("tx_rate")) else None,
            "rx_mbps": round(s["rx_rate"] / 1000, 1) if _num(s.get("rx_rate")) else None,
            "retries": _num(s.get("tx_retries")), "roams": _num(s.get("roam_count")),
            "experience": _num(s.get("satisfaction")), "uptime": _num(s.get("uptime")),
            "sw_mac": (s.get("sw_mac") or "").lower(), "sw_port": s.get("sw_port"),
        })
    return out, infra


def ap_device(ap: Dict[str, Any], devices: List[Dict[str, Any]], macs: Dict[int, set]) -> Optional[Dict[str, Any]]:
    """The monitored device for a UniFi access point: same address, or one of its interface MACs."""
    hit = next((d for d in devices if ap.get("ip") and d["ip_address"] == ap["ip"]), None)
    if hit:
        return hit
    return next((d for d in devices if ap.get("mac") and ap["mac"] in macs.get(d["id"], set())), None)


def run(devices: List[Dict[str, Any]], weak_dbm: float, now: Optional[float] = None) -> Optional[List[Dict[str, Any]]]:
    """One round: the clients table and figures on each monitored access point. Returns every client
    (for the inventory), or None when switched off or failing (the error is kept for Settings)."""
    now = now if now is not None else time.time()
    if not is_enabled() or not is_configured():
        return None
    cfg = load_config()
    try:
        rows, infra = clients(cfg)
    except UnifiError as exc:
        LAST.update(at=int(now), error=str(exc))
        return None
    macs: Dict[int, set] = {}
    for r in database.get_table_all_devices("interfaces"):
        if r.get("mac"):
            macs.setdefault(r["device_id"], set()).add(str(r["mac"]).lower())
    aps = [a for a in infra if a.get("type") == "uap"]
    for ap in aps:
        dev = ap_device(ap, devices, macs)
        if not dev:
            continue
        mine = [c for c in rows if not c["wired"] and c["ap_mac"] == ap["mac"]]
        database.replace_device_table(dev["id"], "wifi_clients", {c["mac"]: c for c in mine}, int(now))
        scores = [c["experience"] for c in mine if c["experience"] is not None]
        metrics = {"wifi.weak": float(sum(1 for c in mine if c["signal"] is not None and c["signal"] < weak_dbm))}
        if scores:
            metrics["wifi.experience"] = round(sum(scores) / len(scores), 1)
        database.record_metrics(dev["id"], metrics, int(now))
    database.set_internal_setting(TOPOLOGY_KEY, json.dumps({
        "at": int(now), "devices": infra,
        "clients": [{k: c.get(k) for k in ("mac", "ip", "wired", "ap_mac", "sw_mac", "sw_port")} for c in rows]}))
    LAST.update(at=int(now), error=None, clients=len(rows), aps=len(aps))
    return rows


def topology() -> Dict[str, Any]:
    """The layout as last read: {"at", "devices", "clients"}; empty when UniFi is off."""
    if not is_enabled():
        return {}
    try:
        value = json.loads(database.get_all_settings().get(TOPOLOGY_KEY) or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


# --- Reconnect ---------------------------------------------------------------

def _post(cfg: Dict[str, str], path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    with SESSION.lock:
        for attempt in (1, 2):
            if not SESSION.cookie:
                _login(cfg)
            headers = {"Cookie": SESSION.cookie}
            if SESSION.csrf:
                headers["X-CSRF-Token"] = SESSION.csrf
            r = lanhttp.request(cfg["url"], "POST", f"{SESSION.prefix}/api/s/{quote(SESSION.site or cfg['site'], safe='')}{path}",
                                cfg["fingerprint"], headers=headers, body=body)
            SESSION.csrf = r.headers.get("x-updated-csrf-token") or SESSION.csrf
            if r.status == 401 and attempt == 1:
                SESSION.clear()
                continue
            if r.status in (401, 403):
                raise UnifiError("UniFi refused the change: the account may only look. Give it a role that may make "
                                 "changes (UniFi, Admins & Users) to use Reconnect.")
            if r.status >= 400:
                raise UnifiError(f"UniFi answered {r.status} to {path}")
            return r.json() or {}
    raise UnifiError("UniFi did not accept the session")


def never_list() -> List[str]:
    return [x.strip().lower() for x in (database.get_all_settings().get(NEVER_KEY) or "").split(",") if x.strip()]


def set_never_list(text: str) -> None:
    items = [x.strip() for x in (text or "").split(",") if x.strip()]
    if len(items) > 100 or any(len(x) > 60 for x in items):
        raise UnifiError("Up to 100 names or MAC addresses, comma separated")
    database.set_internal_setting(NEVER_KEY, ", ".join(items))


def _reconnected() -> Dict[str, float]:
    try:
        value = json.loads(database.get_all_settings().get(RECONNECTED_KEY) or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def why_not(client: Dict[str, Any], now: Optional[float] = None) -> Optional[str]:
    """Why a device may not be reconnected now (guard rails), or None."""
    now = now if now is not None else time.time()
    never = never_list()
    if client.get("mac", "").lower() in never or (client.get("name") or "").lower() in never:
        return "on the never-reconnect list"
    last = _reconnected().get(client.get("mac", "").lower())
    if last and now - float(last) < RECONNECT_EVERY:
        return f"reconnected {int((now - float(last)) // 60)} minutes ago (at most once an hour)"
    return None


def reconnect(mac: str, now: Optional[float] = None) -> None:
    """Drops one Wi-Fi device so it joins again (UniFi kick-sta). Raises UnifiError."""
    now = now if now is not None else time.time()
    if not is_enabled() or not is_configured():
        raise UnifiError("UniFi is not connected (Settings, UniFi)")
    mac = (mac or "").strip().lower()
    if len(mac) != 17 or mac.count(":") != 5:
        raise UnifiError("Not a MAC address")
    r = _post(load_config(), "/cmd/stamgr", {"cmd": "kick-sta", "mac": mac})
    if (r.get("meta") or {}).get("rc") not in (None, "ok"):
        raise UnifiError(f"UniFi did not reconnect it: {(r.get('meta') or {}).get('msg') or 'refused'}")
    done = _reconnected()
    done[mac] = int(now)
    done = {k: v for k, v in done.items() if now - float(v) < 7 * 86400}
    database.set_internal_setting(RECONNECTED_KEY, json.dumps(done))


def reconnect_weak(ap_device_id: int, weak_dbm: float, now: Optional[float] = None) -> Tuple[List[str], List[str]]:
    """The workflow step: reconnects the devices on one access point that are below the weak-signal
    line, within the guard rails. Returns (reconnected, skipped with the reason)."""
    now = now if now is not None else time.time()
    done, skipped = [], []
    rows = database.get_device_table(ap_device_id, "wifi_clients").values()
    for c in sorted(rows, key=lambda c: c.get("signal") if _num(c.get("signal")) is not None else 0):
        if _num(c.get("signal")) is None or c["signal"] >= weak_dbm:
            continue
        name = c.get("name") or c.get("mac")
        reason = why_not(c, now)
        if reason:
            skipped.append(f"{name}: {reason}")
            continue
        try:
            reconnect(c["mac"], now)
            done.append(f"{name} ({c['signal']:.0f} dBm)")
        except UnifiError as exc:
            skipped.append(f"{name}: {exc}")
    return done, skipped


def test(cfg: Dict[str, str]) -> Dict[str, Any]:
    SESSION.clear()
    rows, infra = clients(cfg)
    wifi = [c for c in rows if not c["wired"]]
    return {"clients": len(rows), "wifi": len(wifi), "aps": sum(1 for a in infra if a.get("type") == "uap"),
            "unifi_os": SESSION.prefix == "/proxy/network"}
