"""Proxmox VE dashboard: read-only API client, configuration and a 30-second cache.

Authentication is an API token (Authorization: PVEAPIToken=user@realm!name=secret) with the
PVEAuditor role, so the monitor can read everything and change nothing. The secret is stored
encrypted (settings table, vault context "setting:proxmox_token_secret") and never sent to
the browser.

TLS: verified against the system CA store by default. A Proxmox host usually presents its own
self-signed certificate; for that the administrator pins it: the SHA-256 fingerprint of the exact
certificate, shown by "Fetch fingerprint" and compared with the one in the Proxmox GUI
(node, System, Certificates). A pinned connection accepts that certificate and nothing else,
so verification is never switched off silently.

A switch in Settings, System, Proxmox turns the feature on: off, the page and its menu
entry are hidden and nothing is fetched; the stored connection is kept for turning it back on.

Permissions: /version answers for any valid token, but /cluster/resources only lists what the
token may see. A token with Privilege Separation and no permission of its own "connects", and
Proxmox still lists each node by name and status, with no figures, guests or storage. check()
reads the token's own permissions (/access/permissions) and names what is missing; collect()
treats nodes without figures the same way, instead of showing empty tables.

History graphs come from Proxmox's own RRD data (rrddata: about 70 points per hour, day, week
or month), so nothing is stored here.

Background (refresh, every minute while switched on): the layout is kept as setting
proxmox_layout, so the map, alerts and forecasts work without the page open. Each guest's
config gives its network MACs and "start at boot"; a MAC found in the gateway's ARP table gives
its address, which links a guest to a monitored device even when the names differ.
  map         a guest's monitored device hangs off its node's (virtual link, source proxmox)
  alerts      a guest that starts at boot but is not running; one that restarted several times in
              an hour; memory or a container's disk nearly full (server.proxmox_problems)
  forecasts   storage pools are recorded as pvs.<name>.used_pct on the node's device (forecast.py)

Actions (optional, a second token with VM.PowerMgmt and VM.Snapshot): start, shut down or reboot
a guest from the Proxmox page, and the workflow step "Snapshot a Proxmox guest" (before an update).
The read token never changes anything; the action token is stored the same way (vault-encrypted).

Everything here is standard library: http.client over ssl, json.
"""

import hashlib
import http.client
import json
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import database

KEYS = {"url": "proxmox_url", "token_id": "proxmox_token_id", "secret": "proxmox_token_secret",
        "fingerprint": "proxmox_fingerprint"}
ENABLED_KEY = "proxmox_enabled"
ACTION_KEYS = {"token_id": "proxmox_action_token_id", "secret": "proxmox_action_secret"}
LAYOUT_KEY = "proxmox_layout"
ACTIONS = ("start", "shutdown", "reboot")
CONFIG_SECONDS = 600          # a guest's config (MACs, start at boot) is read at most every 10 minutes
STORAGE_SECONDS = 300         # storage pool history every 5 minutes
TIMEFRAMES = ("hour", "day", "week", "month")
NEEDED = (("Sys.Audit", "nodes"), ("VM.Audit", "VMs and containers"), ("Datastore.Audit", "storage"))
NO_ACCESS = ("The token is valid but Proxmox shows it nothing: it has no permission of its own. In Proxmox, click "
             "Permissions itself in the left menu (not API Tokens or Roles under it), then Add, API Token Permission: "
             "Path /, the token, Role PVEAuditor, Propagate ticked. Or in the Proxmox host's shell: "
             "pveum acl modify / --tokens '<token id>' --roles PVEAuditor. (With Privilege Separation ticked, a "
             "permission given to the user does not reach the token.)")
CACHE_SECONDS = 30
TIMEOUT = 8
MAX_LXC_IP_LOOKUPS = 60


class ProxmoxError(Exception):
    pass


def devices_by_ip(devices: List[Dict[str, Any]]) -> Dict[str, int]:
    """Address to device. Where a host and a service check share an address (a media server VM and
    a web app check on its port 7878), the host is the one a guest is."""
    out: Dict[str, int] = {}
    for d in sorted(devices, key=lambda d: 0 if d.get("service_port") else 1):
        out[d["ip_address"]] = d["id"]
    return out


def normalise_fingerprint(text: str) -> str:
    """'AB:CD:...' or 'abcd...' to lower-case hex without separators; '' when empty."""
    hexs = "".join(ch for ch in (text or "").lower() if ch in "0123456789abcdef")
    if hexs and len(hexs) != 64:
        raise ProxmoxError("A SHA-256 fingerprint has 64 hex digits (32 pairs)")
    return hexs


def pretty_fingerprint(hexs: str) -> str:
    return ":".join(hexs[i:i + 2] for i in range(0, len(hexs), 2)).upper()


def parse_url(url: str) -> Tuple[str, int]:
    u = urlparse((url or "").strip())
    if u.scheme != "https" or not u.hostname:
        raise ProxmoxError("Use the address of the Proxmox web interface, e.g. https://192.168.1.250:8006")
    if u.path not in ("", "/") or u.query or u.username:
        raise ProxmoxError("Only the host and port: https://host:8006")
    return u.hostname, u.port or 8006


def load_config() -> Dict[str, str]:
    s = database.get_all_settings()
    return {k: s.get(v, "") or "" for k, v in KEYS.items()}


def is_enabled() -> bool:
    # A connection saved before the switch existed counts as switched on.
    value = database.get_all_settings().get(ENABLED_KEY)
    return value == "on" if value else is_configured()


def set_enabled(on: bool) -> None:
    database.set_internal_setting(ENABLED_KEY, "on" if on else "off")
    CACHE.clear()


def is_configured(cfg: Optional[Dict[str, str]] = None) -> bool:
    cfg = cfg if cfg is not None else load_config()
    return bool(cfg["url"] and cfg["token_id"] and cfg["secret"])


def public_config(cfg: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    cfg = cfg if cfg is not None else load_config()
    return {"url": cfg["url"], "token_id": cfg["token_id"], "secret_set": bool(cfg["secret"]),
            "fingerprint": pretty_fingerprint(cfg["fingerprint"]) if cfg["fingerprint"] else "",
            "configured": is_configured(cfg), "enabled": is_enabled()}


def save_config(url: str, token_id: str, secret: Optional[str], fingerprint: str) -> None:
    """secret None keeps the stored one; '' removes everything (disconnect)."""
    from vault import VAULT
    if not url:
        for v in KEYS.values():
            database.set_internal_setting(v, "")
        CACHE.clear()
        return
    parse_url(url)
    if not token_id or "!" not in token_id or "@" not in token_id.split("!")[0]:
        raise ProxmoxError("Token ID looks like user@realm!name, for example monitor@pve!dashboard")
    fp = normalise_fingerprint(fingerprint)
    database.set_internal_setting(KEYS["url"], url.strip().rstrip("/"))
    database.set_internal_setting(KEYS["token_id"], token_id.strip())
    database.set_internal_setting(KEYS["fingerprint"], fp)
    if secret is not None:
        database.set_internal_setting(KEYS["secret"], VAULT.encrypt(secret.strip(), f"setting:{KEYS['secret']}") if secret else "")
    CACHE.clear()


def _context(fingerprint: str) -> ssl.SSLContext:
    if fingerprint:
        # Pinned: the chain is not checked against a CA (the certificate is self-signed); the
        # exact certificate is checked after the handshake, before any request is sent.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def fetch_fingerprint(url: str) -> str:
    """The SHA-256 fingerprint of the certificate the host presents, for the administrator to compare and pin."""
    host, port = parse_url(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        raise ProxmoxError(f"Could not reach {host}:{port}: {exc}")
    return pretty_fingerprint(hashlib.sha256(der).hexdigest())


class Client:
    """GET-only client for /api2/json. opener(method, path, headers) can replace the network in tests."""

    def __init__(self, cfg: Dict[str, str], opener: Optional[Callable[[str, Dict[str, str]], Any]] = None) -> None:
        self.cfg = cfg
        self.host, self.port = parse_url(cfg["url"])
        self.opener = opener

    def post(self, path: str, body: Dict[str, Any], token: Tuple[str, str]) -> Any:
        """A change, with the action token (token id, secret). Form-encoded, as Proxmox expects."""
        from urllib.parse import urlencode
        headers = {"Authorization": f"PVEAPIToken={token[0]}={token[1]}", "Accept": "application/json",
                   "Content-Type": "application/x-www-form-urlencoded"}
        if self.opener:
            return self.opener(path, dict(headers, method="POST", body=urlencode(body)))
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=TIMEOUT, context=_context(self.cfg["fingerprint"]))
        try:
            conn.connect()
            if self.cfg["fingerprint"]:
                der = conn.sock.getpeercert(binary_form=True)
                if hashlib.sha256(der).hexdigest() != self.cfg["fingerprint"]:
                    raise ProxmoxError("The Proxmox certificate does not match the pinned fingerprint.")
            conn.request("POST", "/api2/json" + path, body=urlencode(body), headers=headers)
            resp = conn.getresponse()
            raw = resp.read(1024 * 1024)
            if resp.status in (401, 403):
                raise ProxmoxError("Proxmox refused the action token: it needs VM.PowerMgmt (start, shut down, reboot) "
                                   "and VM.Snapshot (snapshots) on the guests (path /vms)")
            if resp.status >= 400:
                raise ProxmoxError(f"Proxmox answered {resp.status}: {raw[:200].decode('utf-8', 'replace')}")
            return json.loads(raw.decode("utf-8") or "{}").get("data")
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise ProxmoxError(f"Could not reach Proxmox at {self.host}:{self.port}: {exc}")
        finally:
            conn.close()

    def get(self, path: str) -> Any:
        headers = {"Authorization": f"PVEAPIToken={self.cfg['token_id']}={self.cfg['secret']}", "Accept": "application/json"}
        if self.opener:
            return self.opener(path, headers)
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=TIMEOUT, context=_context(self.cfg["fingerprint"]))
        try:
            conn.connect()
            if self.cfg["fingerprint"]:
                der = conn.sock.getpeercert(binary_form=True)
                if hashlib.sha256(der).hexdigest() != self.cfg["fingerprint"]:
                    raise ProxmoxError("The Proxmox certificate does not match the pinned fingerprint. If the "
                                       "certificate was renewed, fetch the new fingerprint, compare it and save it.")
            conn.request("GET", "/api2/json" + path, headers=headers)
            resp = conn.getresponse()
            body = resp.read(4 * 1024 * 1024)
            if resp.status == 401:
                raise ProxmoxError("Proxmox refused the token (401): check the token ID and secret")
            if resp.status == 403:
                raise ProxmoxError(f"The token may not read {path} (403): give it the PVEAuditor role on /")
            if resp.status >= 400:
                raise ProxmoxError(f"Proxmox answered {resp.status} for {path}")
            return json.loads(body.decode("utf-8")).get("data")
        except ssl.SSLCertVerificationError:
            raise ProxmoxError("The certificate is not trusted. Proxmox uses a self-signed one by default: "
                               "fetch its fingerprint, compare it with the Proxmox GUI and pin it.")
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise ProxmoxError(f"Could not reach Proxmox at {self.host}:{self.port}: {exc}")
        finally:
            conn.close()


def _ips_of_lxc(client: Client, node: str, vmid: int) -> List[str]:
    try:
        rows = client.get(f"/nodes/{quote(node, safe='')}/lxc/{int(vmid)}/interfaces") or []
    except ProxmoxError:
        return []
    out = []
    for r in rows:
        for key in ("inet", "ip-address"):
            v = r.get(key)
            if v and not str(v).startswith("127."):
                out.append(str(v).split("/")[0])
    return out


def collect(client: Client, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Nodes, guests, storage and recent tasks in one view. devices link guests to monitored devices."""
    version = client.get("/version") or {}
    resources = client.get("/cluster/resources") or []
    # Without Sys.Audit a node is listed by name and status only (no maxcpu, no memory).
    if not any(r.get("type") == "node" and r.get("maxcpu") for r in resources):
        raise ProxmoxError(NO_ACCESS)
    nodes, guests, storage = [], [], []
    for r in resources:
        kind = r.get("type")
        if kind == "node":
            nodes.append({"node": r.get("node"), "status": r.get("status"), "cpu": r.get("cpu"), "maxcpu": r.get("maxcpu"),
                          "mem": r.get("mem"), "maxmem": r.get("maxmem"), "disk": r.get("disk"), "maxdisk": r.get("maxdisk"),
                          "uptime": r.get("uptime")})
        elif kind in ("qemu", "lxc"):
            guests.append({"vmid": r.get("vmid"), "name": r.get("name"), "type": kind, "node": r.get("node"),
                           "status": r.get("status"), "cpu": r.get("cpu"), "maxcpu": r.get("maxcpu"), "mem": r.get("mem"),
                           "maxmem": r.get("maxmem"), "disk": r.get("disk"), "maxdisk": r.get("maxdisk"),
                           "uptime": r.get("uptime"), "tags": [t for t in str(r.get("tags") or "").replace(",", ";").split(";") if t],
                           "template": bool(r.get("template"))})
        elif kind == "storage":
            storage.append({"storage": r.get("storage"), "node": r.get("node"), "status": r.get("status"),
                            "type": r.get("plugintype"), "shared": bool(r.get("shared")),
                            "disk": r.get("disk"), "maxdisk": r.get("maxdisk"), "content": r.get("content")})
    for n in nodes:
        if n["status"] != "online":
            continue
        try:
            st = client.get(f"/nodes/{quote(str(n['node']), safe='')}/status") or {}
        except ProxmoxError:
            continue
        n["loadavg"] = st.get("loadavg")
        n["pveversion"] = st.get("pveversion")
        n["kversion"] = st.get("kversion")
        n["cpu_model"] = (st.get("cpuinfo") or {}).get("model")
    try:
        tasks = client.get("/cluster/tasks") or []
    except ProxmoxError:
        tasks = []
    task_rows = [{"upid": t.get("upid"), "type": t.get("type"), "id": t.get("id"), "node": t.get("node"),
                  "user": t.get("user"), "status": t.get("status"), "start": t.get("starttime"), "end": t.get("endtime")}
                 for t in tasks]
    task_rows.sort(key=lambda t: t["start"] or 0, reverse=True)
    backups = [t for t in task_rows if t["type"] == "vzdump"][:20]
    # Running tasks have no status yet; "OK" is success, anything else (an error text) failed.
    failed = [t for t in task_rows if t["end"] and t["status"] not in (None, "", "OK")][:20]

    by_name = {str(d["hostname"]).lower(): d["id"] for d in devices}
    by_ip = devices_by_ip(devices)
    lookups = 0
    for g in guests:
        g["device_id"] = by_name.get(str(g["name"] or "").lower())
        if g["device_id"] is None and g["type"] == "lxc" and g["status"] == "running" and lookups < MAX_LXC_IP_LOOKUPS:
            lookups += 1
            g["ips"] = _ips_of_lxc(client, str(g["node"]), g["vmid"])
            g["device_id"] = next((by_ip[ip] for ip in g["ips"] if ip in by_ip), None)
    node_names = {str(n["node"]).lower(): n for n in nodes}
    for d in devices:
        n = node_names.get(str(d["hostname"]).lower())
        if n is not None:
            n["device_id"] = d["id"]
    guests.sort(key=lambda g: (g["template"], g["node"] or "", g["vmid"] or 0))
    return {"version": version.get("version"), "nodes": nodes, "guests": guests, "storage": storage,
            "backups": backups, "failed_tasks": failed, "fetched_at": int(time.time())}


def check(client: Client) -> Dict[str, Any]:
    """Test connection: the version and what the token can actually see."""
    version = client.get("/version") or {}
    perms = client.get("/access/permissions") or {}
    held = {p for privs in perms.values() if isinstance(privs, dict) for p, v in privs.items() if v}
    missing = [f"{priv} ({what})" for priv, what in NEEDED if priv not in held]
    if missing:
        raise ProxmoxError(NO_ACCESS + " Missing now: " + ", ".join(missing) + ".")
    resources = client.get("/cluster/resources") or []
    count = lambda *kinds: sum(1 for r in resources if r.get("type") in kinds)
    return {"version": version.get("version"), "nodes": count("node"), "guests": count("qemu", "lxc"),
            "storage": count("storage")}


def _num(v: Any) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) else None


def rrd(client: Client, node: str, kind: str, vmid: Optional[int], timeframe: str) -> List[Dict[str, Any]]:
    """CPU, memory, network and disk I/O history of a node or guest from Proxmox's RRD files."""
    if timeframe not in TIMEFRAMES:
        raise ProxmoxError("timeframe is hour, day, week or month")
    if kind == "node":
        path = f"/nodes/{quote(node, safe='')}/rrddata"
    elif kind in ("qemu", "lxc") and vmid is not None:
        path = f"/nodes/{quote(node, safe='')}/{kind}/{int(vmid)}/rrddata"
    else:
        raise ProxmoxError("type is node, qemu or lxc (with vmid)")
    rows = client.get(f"{path}?timeframe={timeframe}&cf=AVERAGE") or []
    out = []
    for r in rows:
        t = _num(r.get("time"))
        if t is None:
            continue
        mem, maxmem = _num(r.get("memused" if kind == "node" else "mem")), _num(r.get("memtotal" if kind == "node" else "maxmem"))
        out.append({"t": int(t), "cpu": _num(r.get("cpu")), "mem": mem, "maxmem": maxmem,
                    "netin": _num(r.get("netin")), "netout": _num(r.get("netout")),
                    "diskread": _num(r.get("diskread")), "diskwrite": _num(r.get("diskwrite")),
                    "iowait": _num(r.get("iowait")), "loadavg": _num(r.get("loadavg"))})
    return out


class Cache:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.value: Optional[Dict[str, Any]] = None
        self.at = 0.0

    def clear(self) -> None:
        with self.lock:
            self.value, self.at = None, 0.0

    def get(self, make: Callable[[], Dict[str, Any]], force: bool = False) -> Dict[str, Any]:
        with self.lock:
            if not force and self.value is not None and time.time() - self.at < CACHE_SECONDS:
                return self.value
        value = make()
        with self.lock:
            self.value, self.at = value, time.time()
        return value


CACHE = Cache()


# --- Background: layout, alerts, forecasts -------------------------------------

_configs: Dict[tuple, Tuple[float, Dict[str, Any]]] = {}


def _norm_mac(text: str) -> str:
    hexs = "".join(ch for ch in str(text or "").lower() if ch in "0123456789abcdef")
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)) if len(hexs) == 12 else ""


def parse_guest_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """MACs of a guest's network cards and whether it starts at boot, from /config.
    VM: net0 = "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0"; container: net0 = "name=eth0,hwaddr=BC:24:...,ip=dhcp"."""
    macs = []
    for k, v in cfg.items():
        if not (k.startswith("net") and k[3:].isdigit()):
            continue
        for part in str(v).split(","):
            key, _, val = part.partition("=")
            mac = _norm_mac(val) if key in ("hwaddr", "macaddr") or key in ("virtio", "e1000", "rtl8139", "vmxnet3", "e1000e") else ""
            if mac:
                macs.append(mac)
    return {"macs": macs, "onboot": str(cfg.get("onboot", "0")) == "1"}


def guest_config(client: Client, g: Dict[str, Any], now: float) -> Dict[str, Any]:
    key = (g["node"], g["type"], g["vmid"])
    hit = _configs.get(key)
    if hit and now - hit[0] < CONFIG_SECONDS:
        return hit[1]
    try:
        value = parse_guest_config(client.get(f"/nodes/{quote(str(g['node']), safe='')}/{g['type']}/{int(g['vmid'])}/config") or {})
    except ProxmoxError:
        value = hit[1] if hit else {"macs": [], "onboot": False}
    _configs[key] = (now, value)
    return value


def layout() -> Dict[str, Any]:
    if not is_enabled():
        return {}
    try:
        value = json.loads(database.get_all_settings().get(LAYOUT_KEY) or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def storage_slug(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(name))[:40]


def refresh(devices: List[Dict[str, Any]], arp_rows: List[Dict[str, Any]], now: Optional[float] = None) -> Optional[str]:
    """The minute's round: collect, match guests to devices by name, container address or MAC, keep
    the layout, count restarts, record storage pools. Returns an error, or None."""
    now = now if now is not None else time.time()
    cfg = load_config()
    if not is_enabled() or not is_configured(cfg):
        return None
    client = Client(cfg)
    try:
        data = CACHE.get(lambda: collect(client, devices), force=True)
    except ProxmoxError as exc:
        return str(exc)
    by_ip = devices_by_ip(devices)
    ip_of_mac = {_norm_mac(r.get("mac")): str(r.get("row_key") or r.get("ip") or "") for r in arp_rows}
    old = layout()
    old_guests = {(g["node"], g["vmid"]): g for g in old.get("guests", [])}
    restarts = {k: [t for t in v if now - t < 3600] for k, v in (old.get("restarts") or {}).items()}
    guests = []
    for g in data["guests"]:
        if g.get("template"):
            continue
        conf = guest_config(client, g, now)
        ips = list(g.get("ips") or []) + [ip_of_mac[m] for m in conf["macs"] if ip_of_mac.get(m)]
        device_id = g.get("device_id") or next((by_ip[ip] for ip in ips if ip in by_ip), None)
        key = f"{g['node']}/{g['vmid']}"
        prev = old_guests.get((g["node"], g["vmid"]))
        # Uptime went down while running: it restarted (a stop and start in between counts too).
        if prev and g["status"] == "running" and isinstance(g.get("uptime"), (int, float)) and isinstance(prev.get("uptime"), (int, float)) \
                and g["uptime"] < prev["uptime"] and g["uptime"] < 3600:
            restarts.setdefault(key, []).append(int(now))
        guests.append({"vmid": g["vmid"], "name": g.get("name"), "node": g["node"], "type": g["type"], "status": g["status"],
                       "device_id": device_id, "onboot": conf["onboot"], "macs": conf["macs"], "ips": sorted(set(ips)),
                       "uptime": g.get("uptime"), "mem": g.get("mem"), "maxmem": g.get("maxmem"),
                       "disk": g.get("disk"), "maxdisk": g.get("maxdisk")})
    nodes = [{"node": n["node"], "status": n["status"], "device_id": n.get("device_id")} for n in data["nodes"]]
    stor_at = old.get("stor_at", 0)
    if now - stor_at >= STORAGE_SECONDS:
        stor_at = now
        node_dev = {n["node"]: n.get("device_id") for n in data["nodes"]}
        per_dev: Dict[int, Dict[str, float]] = {}
        for s in data["storage"]:
            dev = node_dev.get(s.get("node"))
            if dev and s.get("maxdisk") and s.get("status") == "available":
                per_dev.setdefault(dev, {})[f"pvs.{storage_slug(s['storage'])}.used_pct"] = round(100.0 * (s.get("disk") or 0) / s["maxdisk"], 2)
        for dev, m in per_dev.items():
            database.record_metrics(dev, m, int(now))
    database.set_internal_setting(LAYOUT_KEY, json.dumps({
        "at": int(now), "nodes": nodes, "guests": guests, "restarts": {k: v for k, v in restarts.items() if v},
        "storage": [{"storage": s["storage"], "node": s["node"]} for s in data["storage"]], "stor_at": stor_at}))
    return None


# --- Actions (the optional action token) --------------------------------------

def action_config() -> Dict[str, str]:
    s = database.get_all_settings()
    return {k: s.get(v, "") or "" for k, v in ACTION_KEYS.items()}


def actions_ready() -> bool:
    a = action_config()
    return bool(is_enabled() and is_configured() and a["token_id"] and a["secret"])


def save_action_token(token_id: str, secret: Optional[str]) -> None:
    """token_id '' removes it. secret None keeps the stored one."""
    from vault import VAULT
    if not token_id:
        for v in ACTION_KEYS.values():
            database.set_internal_setting(v, "")
        return
    if "!" not in token_id or "@" not in token_id.split("!")[0]:
        raise ProxmoxError("Token ID looks like user@realm!name, for example root@pam!monitor-actions")
    database.set_internal_setting(ACTION_KEYS["token_id"], token_id.strip())
    if secret is not None:
        database.set_internal_setting(ACTION_KEYS["secret"], VAULT.encrypt(secret.strip(), f"setting:{ACTION_KEYS['secret']}") if secret else "")


def _guest_path(node: str, kind: str, vmid: int) -> str:
    if kind not in ("qemu", "lxc"):
        raise ProxmoxError("type is qemu or lxc")
    if not node or not all(ch.isalnum() or ch in "-_." for ch in node):
        raise ProxmoxError("Not a node name")
    return f"/nodes/{quote(node, safe='')}/{kind}/{int(vmid)}"


def _action_client() -> Tuple[Client, Tuple[str, str]]:
    if not actions_ready():
        raise ProxmoxError("Actions need the action token (Settings, Proxmox, Token for actions)")
    a = action_config()
    return Client(load_config()), (a["token_id"], a["secret"])


def guest_action(node: str, kind: str, vmid: int, action: str) -> str:
    """Start, shut down (clean, via the guest) or reboot. Returns Proxmox's task id."""
    if action not in ACTIONS:
        raise ProxmoxError("action is start, shutdown or reboot")
    client, token = _action_client()
    upid = client.post(f"{_guest_path(node, kind, vmid)}/status/{action}", {}, token)
    CACHE.clear()
    return str(upid or "")


def wait_task(client: Client, node: str, upid: str, timeout: float, stop=None) -> Tuple[bool, str]:
    """Waits for a Proxmox task to end. (ok, exit status)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if stop and stop():
            return False, "cancelled"
        st = client.get(f"/nodes/{quote(node, safe='')}/tasks/{quote(upid, safe='')}/status") or {}
        if st.get("status") == "stopped":
            return st.get("exitstatus") == "OK", str(st.get("exitstatus") or "")
        time.sleep(2)
    return False, f"still running after {int(timeout)} s"


def snapshot(node: str, kind: str, vmid: int, description: str, timeout: float = 600, stop=None) -> str:
    """Takes a snapshot named monitor-<date>-<time> and waits for it. Returns its name. Raises ProxmoxError."""
    client, token = _action_client()
    name = time.strftime("monitor-%Y%m%d-%H%M%S")
    upid = client.post(f"{_guest_path(node, kind, vmid)}/snapshot", {"snapname": name, "description": description[:200]}, token)
    ok, status = wait_task(client, node, str(upid or ""), timeout, stop)
    if not ok:
        raise ProxmoxError(f"The snapshot did not finish: {status}")
    return name


def overview(devices: List[Dict[str, Any]], force: bool = False) -> Dict[str, Any]:
    cfg = load_config()
    if not is_enabled() or not is_configured(cfg):
        return {"configured": False}
    data = CACHE.get(lambda: collect(Client(cfg), devices), force=force)
    # What the background round found (MACs, addresses, start at boot) for the page.
    extra = {(g["node"], g["vmid"]): g for g in layout().get("guests", [])}
    guests = []
    for g in data["guests"]:
        x = extra.get((g["node"], g["vmid"]), {})
        guests.append(dict(g, device_id=g.get("device_id") or x.get("device_id"), ips=x.get("ips") or g.get("ips") or [],
                           onboot=x.get("onboot")))
    return dict(data, guests=guests, configured=True, actions=actions_ready())
