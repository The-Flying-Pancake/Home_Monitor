"""Network discovery: find hosts on private subnets and identify them, or find open TCP ports.

Device scan: each address gets an ICMP echo and an SNMP GET of sysDescr,
sysObjectID and sysName in parallel (hosts that block ping can still answer
SNMP). Answering hosts get a reverse DNS lookup and an auto-detected template;
a host that answers ping but not SNMP is suggested as "Ping only".

Port scan (ports given: a list, ranges, "common" or "all" for 1 to 65535): TCP
connects through tcp_sweep, a single thread holding many non-blocking connects
at once (selectors, standard library), so the full range of a host takes
about a minute instead of hours. Small scans try every address. Large ones
(more than LIVE_FIRST_PORTS ports) first find the hosts that are up, by ping
or a common port, and scan only those: a /24 full of empty addresses would
otherwise wait out a timeout on every port of every empty address. Open ports
appear in the results as they are found; a scan can be stopped and keeps
what it found.

Addresses: private (RFC 1918) ranges only, at most MAX_ADDRESSES per scan, or
an explicit list of hosts (the setup's service step scans the devices picked).

A scan runs in the background; the community string lives only in the
running job and is never stored or returned.
"""

import concurrent.futures
import errno
import ipaddress
import selectors
import socket
import sys
import threading
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Union

import poller

MAX_ADDRESSES = 1024
WORKERS = 48
# Ports looked for by the "common" preset: web interfaces, remote access, file sharing, databases,
# home automation, media and homelab services.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 139, 143, 161, 389, 443, 445, 465, 515, 548, 554, 587, 631,
                636, 873, 993, 995, 1194, 1433, 1883, 1900, 2049, 2375, 2376, 3000, 3001, 3128, 3306, 3389, 3478, 4040,
                5000, 5001, 5060, 5201, 5432, 5672, 5900, 6379, 6443, 7878, 8000, 8006, 8008, 8080, 8081, 8083, 8086,
                8088, 8096, 8123, 8181, 8200, 8384, 8443, 8448, 8686, 8787, 8880, 8888, 8920, 8989, 9000, 9090, 9091,
                9100, 9443, 9696, 10000, 11434, 25565, 27017, 32400, 51413]
# Above this many ports the hosts that are up are found first, then only they are scanned.
LIVE_FIRST_PORTS = 1024
SWEEP_TIMEOUT = 0.6
# Connections in flight at once. Windows' select() takes at most 512 sockets.
SWEEP_CONCURRENCY = 400 if sys.platform == "win32" else 1000
SYS_OIDS = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"]
JOB_TTL_SECONDS = 3600


class DiscoveryError(ValueError):
    pass


def parse_subnet(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise DiscoveryError(f"'{text}' is not a subnet. Enter one such as 192.168.1.0/24")
    if net.version != 4:
        raise DiscoveryError("IPv4 subnets only")
    if not net.is_private or net.is_loopback or net.is_link_local:
        raise DiscoveryError(f"{net} is not a private LAN range")
    if net.num_addresses > MAX_ADDRESSES:
        raise DiscoveryError(f"{net} is too large: at most {MAX_ADDRESSES} addresses (/22)")
    return net


def parse_subnets(subnets: Union[str, Iterable[str]]) -> List[ipaddress.IPv4Network]:
    """One or more subnets; overlaps are merged and the total size is capped."""
    items = [subnets] if isinstance(subnets, str) else list(subnets)
    items = [s for s in (x.strip() for x in items if isinstance(x, str)) if s]
    if not items:
        raise DiscoveryError("Enter a subnet such as 192.168.1.0/24")
    if len(items) > 16:
        raise DiscoveryError("At most 16 subnets per scan")
    nets = list(ipaddress.collapse_addresses(parse_subnet(s) for s in items))
    if sum(n.num_addresses for n in nets) > MAX_ADDRESSES:
        raise DiscoveryError(f"Too many addresses: at most {MAX_ADDRESSES} per scan across all subnets")
    return nets


def parse_ports(text: Union[str, Iterable[int], None]) -> List[int]:
    """'22,80,443,8000-8010', 'common', 'all' (1 to 65535) or a list of numbers -> sorted unique ports."""
    if text is None or text == "":
        return []
    if isinstance(text, str) and text.strip().lower() in ("all", "1-65535"):
        return list(range(1, 65536))
    if isinstance(text, str) and text.strip().lower() == "common":
        return list(COMMON_PORTS)
    out = set()
    parts = text.replace(" ", "").split(",") if isinstance(text, str) else [str(p) for p in text]
    for part in parts:
        if not part:
            continue
        if part.lower() == "common":
            out.update(COMMON_PORTS)
            continue
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo > hi:
                    lo, hi = hi, lo
                out.update(range(lo, hi + 1))
            else:
                out.add(int(part))
        except ValueError:
            raise DiscoveryError(f"'{part}' is not a port or range (examples: 443, 8000-8010)")
    if not out or min(out) < 1 or max(out) > 65535:
        raise DiscoveryError("Ports must be 1 to 65535")
    return sorted(out)


def parse_hosts(hosts: Iterable[Any]) -> List[str]:
    """An explicit list of private IPv4 addresses (the setup's service scan of the devices picked)."""
    out = []
    for h in hosts:
        try:
            ip = ipaddress.ip_address(str(h).strip())
        except ValueError:
            raise DiscoveryError(f"'{h}' is not an IPv4 address")
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise DiscoveryError(f"{ip} is not a private LAN address")
        out.append(str(ip))
    out = sorted(set(out), key=lambda a: tuple(int(x) for x in a.split(".")))
    if not out:
        raise DiscoveryError("No addresses to scan")
    if len(out) > MAX_ADDRESSES:
        raise DiscoveryError(f"At most {MAX_ADDRESSES} addresses per scan")
    return out


def tcp_sweep(pairs: Iterable[Any], on_done: Any, cancelled: threading.Event, timeout: float = SWEEP_TIMEOUT,
              concurrency: int = SWEEP_CONCURRENCY) -> None:
    """Non-blocking TCP connects to (ip, port) pairs, many at a time; on_done(ip, port, open, ms) for each.

    A connect that completes within timeout is open; refused, unreachable and silent ones are not.
    Nothing is sent on an open port: the connection is closed as soon as it is established."""
    sel = selectors.DefaultSelector()
    it = iter(pairs)
    flying: Dict[Any, Any] = {}
    exhausted = False
    try:
        while True:
            while not exhausted and len(flying) < concurrency and not cancelled.is_set():
                try:
                    ip, port = next(it)
                except StopIteration:
                    exhausted = True
                    break
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                code = sock.connect_ex((ip, port))
                now = time.monotonic()
                if code == 0:
                    sock.close()
                    on_done(ip, port, True, 0.0)
                elif code in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, getattr(errno, "WSAEWOULDBLOCK", -1), 10035):
                    sel.register(sock, selectors.EVENT_WRITE, (ip, port, now))
                    flying[sock] = now
                else:
                    sock.close()
                    on_done(ip, port, False, None)
            if not flying:
                if exhausted or cancelled.is_set():
                    return
                continue
            for key, _ in sel.select(timeout=0.05):
                sock = key.fileobj
                ip, port, t0 = key.data
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                sel.unregister(sock)
                flying.pop(sock, None)
                sock.close()
                on_done(ip, port, err == 0, round((time.monotonic() - t0) * 1000, 1) if err == 0 else None)
            now = time.monotonic()
            for sock in [s_ for s_, t0 in flying.items() if now - t0 > timeout or cancelled.is_set()]:
                ip, port, _ = sel.get_key(sock).data
                sel.unregister(sock)
                flying.pop(sock)
                sock.close()
                on_done(ip, port, False, None)
    finally:
        for sock in list(flying):
            try:
                sel.unregister(sock)
            except (KeyError, ValueError):
                pass
            sock.close()
        sel.close()


def default_subnet(own_ip: Optional[str]) -> Optional[str]:
    if not own_ip:
        return None
    try:
        return str(ipaddress.ip_network(f"{own_ip}/24", strict=False))
    except ValueError:
        return None


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def probe(ip: str, community: str, profiles: List[Dict[str, Any]], timeout: float) -> Optional[Dict[str, Any]]:
    """One address: None when neither ping nor SNMP answers."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        ping = pool.submit(poller.ping_host, ip, timeout)
        snmp = pool.submit(poller.snmp_get_many, ip, SYS_OIDS, community, 161, timeout, 0)
        alive, latency = ping.result()
        system = snmp.result()
    if not alive and not system:
        return None
    if not system:
        # Answers ping but not SNMP: suggested as a ping-only device (reachability and response time).
        dns = _reverse_dns(ip)
        return {"ip": ip, "ping": alive, "latency_ms": latency, "snmp": False, "sys_name": "", "dns_name": dns,
                "name": dns.split(".")[0] if dns else "", "descr": "", "sys_object_id": "",
                "profile_id": "ping_only", "profile_name": "Ping only (no SNMP)"}
    descr = str(system.get(SYS_OIDS[0], ""))
    objid = str(system.get(SYS_OIDS[1], ""))
    sys_name = str(system.get(SYS_OIDS[2], ""))
    matched = poller.identify_device(ip, system, profiles, community, 161, timeout) if system else None
    dns = _reverse_dns(ip)
    return {"ip": ip, "ping": alive, "latency_ms": latency, "snmp": bool(system),
            "sys_name": sys_name, "dns_name": dns, "name": sys_name or (dns.split(".")[0] if dns else ""),
            "descr": descr[:160], "sys_object_id": objid, "profile_id": matched["profile_id"] if matched else "generic_device",
            "profile_name": matched["name"] if matched else "Generic Network Device (MIB-II)"}


class ScanJob:
    def __init__(self, nets: List[ipaddress.IPv4Network], community: str, known_ips: set,
                 ports: Optional[List[int]] = None, hosts: Optional[List[str]] = None,
                 known_ports: Optional[set] = None) -> None:
        self.id = uuid.uuid4().hex
        if isinstance(nets, ipaddress.IPv4Network):
            nets = [nets]          # the older single-network form
        self.subnets = [str(n) for n in nets] if nets else []
        self.hosts = hosts or [str(h) for n in nets for h in (n.hosts() if n.num_addresses > 2 else n)]
        self.subnet = ", ".join(self.subnets) if self.subnets else f"{len(self.hosts)} chosen hosts"
        self.community = community
        self.known = known_ips
        self.known_ports = known_ports or set()
        self.ports = ports or []
        self.done = 0
        self.total = len(self.hosts)
        self.phase = "hosts" if not self.ports else ("live" if len(self.ports) > LIVE_FIRST_PORTS else "ports")
        self.live_hosts: Optional[int] = None
        self.results: List[Dict[str, Any]] = []
        self.by_ip: Dict[str, Dict[str, Any]] = {}
        self.finished = False
        self.stopped = False
        self.started = time.time()
        self.phase_started = self.started
        self.phase_done = 0
        self.lock = threading.Lock()
        self.cancelled = threading.Event()

    def stop(self) -> None:
        self.cancelled.set()
        self.stopped = True

    def run(self) -> None:
        try:
            if self.ports:
                self._run_ports()
            else:
                self._run_hosts()
        finally:
            self.community = ""
            self.finished = True

    def _run_hosts(self) -> None:
        profiles = poller.load_hardware_profiles()
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="scan") as pool:
            futures = {pool.submit(self._one, ip, profiles): ip for ip in self.hosts}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                with self.lock:
                    self.done += 1
                    if r:
                        r["monitored"] = r["ip"] in self.known
                        self.results.append(r)

    def _one(self, ip: str, profiles):
        if self.cancelled.is_set():
            return None
        try:
            return probe(ip, self.community, profiles, 1.0)
        except Exception:
            return None

    def _found(self, ip: str, port: int, ms: Optional[float]) -> None:
        r = self.by_ip.get(ip)
        if r is None:
            r = {"ip": ip, "ping": None, "latency_ms": None, "open_ports": [], "dns_name": "", "name": "", "monitored_ports": []}
            self.by_ip[ip] = r
            self.results.append(r)
        if port not in r["open_ports"]:
            r["open_ports"].append(port)
            r["open_ports"].sort()
            if (ip, port) in self.known_ports:
                r["monitored_ports"].append(port)

    def _run_ports(self) -> None:
        hosts = self.hosts
        pings: Dict[str, Any] = {}
        if self.phase == "live":
            # Which hosts are up: ping, or a common port open (hosts that block ping).
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="scan-ping") as pool:
                for ip, res in zip(hosts, pool.map(lambda a: poller.ping_host(a, 1.0), hosts)):
                    pings[ip] = res
            alive = {ip for ip, (up, _) in pings.items() if up}
            seen = set()

            def live_done(ip, port, open_, ms):
                with self.lock:
                    self.phase_done += 1
                    if open_:
                        seen.add(ip)
                        self._found(ip, port, ms)
            self.total = len(hosts) * len(COMMON_PORTS)
            tcp_sweep(((ip, p) for ip in hosts if ip not in alive for p in COMMON_PORTS), live_done, self.cancelled)
            hosts = [ip for ip in hosts if ip in alive or ip in seen]
            with self.lock:
                self.live_hosts = len(hosts)
                self.phase = "ports"
                self.phase_started = time.time()
                self.phase_done = 0
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="scan-ping") as pool:
                for ip, res in zip(hosts, pool.map(lambda a: poller.ping_host(a, 1.0), hosts)):
                    pings[ip] = res
        with self.lock:
            self.total = len(hosts) * len(self.ports)
            self.done = 0

        def done(ip, port, open_, ms):
            with self.lock:
                self.done += 1
                self.phase_done += 1
                if open_:
                    self._found(ip, port, ms)
        if not self.cancelled.is_set():
            tcp_sweep(((ip, p) for ip in hosts for p in self.ports), done, self.cancelled)
        # Ping and a name for every host with an open port.
        for r in self.results:
            up, ms = pings.get(r["ip"], (False, None))
            r["ping"], r["latency_ms"] = up, ms
            r["dns_name"] = _reverse_dns(r["ip"])
            r["name"] = r["dns_name"].split(".")[0] if r["dns_name"] else ""

    def view(self) -> Dict[str, Any]:
        with self.lock:
            results = sorted(self.results, key=lambda r: tuple(int(p) for p in r["ip"].split(".")))
            results = [dict(r, open_ports=list(r.get("open_ports", []))) if "open_ports" in r else r for r in results]
            elapsed = time.time() - self.phase_started
            remaining = max(0, self.total - self.done) if self.phase == "ports" else None
            rate = self.phase_done / elapsed if elapsed > 2 and self.phase_done else None
            eta = round(remaining / rate) if rate and remaining is not None and not self.finished else None
            return {"id": self.id, "subnet": self.subnet, "subnets": self.subnets, "ports": len(self.ports),
                    "port_list": self.ports if len(self.ports) <= 200 else None,
                    "total": self.total, "done": self.done, "finished": self.finished, "stopped": self.stopped,
                    "phase": self.phase, "live_hosts": self.live_hosts, "hosts": len(self.hosts), "eta_seconds": eta,
                    "seconds": round(time.time() - self.started, 1), "results": results}


class Scanner:
    """Holds recent scan jobs in memory; one scan at a time."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.jobs: Dict[str, ScanJob] = {}

    def start(self, subnets: Union[str, Iterable[str], None], community: str, known_ips: set,
              ports: Union[str, Iterable[int], None] = None, hosts: Optional[Iterable[Any]] = None,
              known_ports: Optional[set] = None) -> ScanJob:
        host_list = parse_hosts(hosts) if hosts else None
        nets = [] if host_list else parse_subnets(subnets)
        port_list = parse_ports(ports)
        with self.lock:
            now = time.time()
            for k in [k for k, j in self.jobs.items() if now - j.started > JOB_TTL_SECONDS and j.finished]:
                del self.jobs[k]
            if any(not j.finished for j in self.jobs.values()):
                raise DiscoveryError("A scan is already running")
            job = ScanJob(nets, community, known_ips, port_list, host_list, known_ports)
            self.jobs[job.id] = job
        threading.Thread(target=job.run, name="discovery", daemon=True).start()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self.lock:
            return self.jobs.get(job_id)


SCANNER = Scanner()
