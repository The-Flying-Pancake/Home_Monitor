"""Network topology inferred from switch forwarding tables (FDB) and the gateway ARP table.

A switch learns the MAC of every host it forwards for, on the port that
leads towards that host. Device D hangs directly off switch S port p when S
learns D on p and no other switch X sits between them. X sits between when
S also learns X on p and X learns D on a different port from the one that
leads back to S. That rule turns per-switch "who is behind which port"
lists into point-to-point links without LLDP.

Proxmox guests (Proxmox's bc:24:11 MAC prefix) that appear on the same
switch port as a Proxmox host are attached to that host instead, since
their traffic leaves through its NIC.

Switches that speak LLDP report their neighbours exactly (lldp_links); those
links carry the port on both ends and replace the guesses for that port
(merge_lldp).

The result is a list of nodes and links. Pure functions, no database
access, so the rules can be tested with literal tables.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

PROXMOX_OUI = "bc:24:11"
MONITOR_KEY = "monitor"


def device_key(device_id: int) -> str:
    return f"d:{device_id}"


def infer(devices: List[Dict[str, Any]],
          fdb: Dict[int, Dict[str, int]],
          arp: Dict[str, str],
          interface_macs: Dict[int, Set[str]],
          monitor_ip: Optional[str] = None) -> Dict[str, Any]:
    """Builds {nodes, links, clients} from collected tables.

    devices: monitored devices (id, hostname, ip_address, profile_id, inventory).
    fdb: {switch_device_id: {mac: if_index}}.
    arp: {ip: mac} from routers.
    interface_macs: {device_id: {mac, ...}} from each device's ifPhysAddress.
    monitor_ip: this server's LAN address, placed on the map as its own node.
    clients: {node_key: {if_index: count}} of unmonitored MACs on edge ports.
    """
    # Port checks are services, not boxes on the wire: they take no part in MAC inference and
    # hang off the monitored device at the same address (see the end of this function).
    services = [d for d in devices if d.get("service_port")]
    devices = [d for d in devices if not d.get("service_port")]
    by_key: Dict[str, Dict[str, Any]] = {}
    macs: Dict[str, Set[str]] = {}
    for d in devices:
        k = device_key(d["id"])
        by_key[k] = d
        m = set(interface_macs.get(d["id"], set()))
        if arp.get(d["ip_address"]):
            m.add(arp[d["ip_address"]])
        macs[k] = {x.lower() for x in m if x and x != "00:00:00:00:00:00"}
    if monitor_ip and arp.get(monitor_ip):
        macs[MONITOR_KEY] = {arp[monitor_ip].lower()}

    owner: Dict[str, str] = {}
    for k, ms in macs.items():
        for mac in ms:
            owner.setdefault(mac, k)

    switches = {device_key(sid): table for sid, table in fdb.items() if device_key(sid) in by_key}
    # port_toward[S][K]: the port on switch S that leads to node K.
    port_toward: Dict[str, Dict[str, int]] = {}
    for s, table in switches.items():
        toward: Dict[str, int] = {}
        for mac, port in table.items():
            k = owner.get(mac.lower())
            if k and k != s:
                toward.setdefault(k, port)
        port_toward[s] = toward

    links: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def between(s: str, port: int, target: str) -> bool:
        for x in switches:
            if x in (s, target) or port_toward[s].get(x) != port:
                continue
            x_to_target = port_toward[x].get(target)
            if x_to_target is None:
                continue
            x_to_s = port_toward[x].get(s)
            # X cannot see S (no traffic from S's own MAC): X still sits between when it sees the target.
            if x_to_s is None or x_to_s != x_to_target:
                return True
        return False

    attached_at: Dict[str, Tuple[str, int]] = {}
    for s, toward in port_toward.items():
        for target, port in toward.items():
            if between(s, port, target):
                continue
            pair = tuple(sorted((s, target)))
            link = links.setdefault(pair, {"a": pair[0], "b": pair[1], "a_port": None, "b_port": None, "source": "auto"})
            link["a_port" if pair[0] == s else "b_port"] = port
            if target not in switches:
                attached_at[target] = (s, port)

    # Proxmox guests on the same switch port as a Proxmox host belong behind that host.
    hosts_at: Dict[Tuple[str, int], str] = {}
    for k, where in attached_at.items():
        d = by_key.get(k)
        if d and _is_proxmox_host(d, macs.get(k, set())):
            hosts_at[where] = k
    for k, where in list(attached_at.items()):
        host = hosts_at.get(where)
        if not host or host == k or not any(m.startswith(PROXMOX_OUI) for m in macs.get(k, set())):
            continue
        links.pop(tuple(sorted((where[0], k))), None)
        pair = tuple(sorted((host, k)))
        links[pair] = {"a": pair[0], "b": pair[1], "a_port": None, "b_port": None, "source": "auto", "kind": "virtual"}

    # Unmonitored hosts on ports where no switch is seen (end-user devices, TVs, phones).
    clients: Dict[str, Dict[int, int]] = {}
    for s, table in switches.items():
        switch_ports = {p for k, p in port_toward[s].items() if k in switches}
        for mac, port in table.items():
            if port in switch_ports or mac.lower() in owner:
                continue
            clients.setdefault(s, {})
            clients[s][port] = clients[s].get(port, 0) + 1

    nodes = [{"key": k, "device_id": d["id"], "label": d["hostname"], "ip": d["ip_address"],
              "profile_id": d["profile_id"], "status": d.get("status"), "kind": _kind(d)} for k, d in by_key.items()]
    if MONITOR_KEY in macs:
        nodes.append({"key": MONITOR_KEY, "device_id": None, "label": "This monitor", "ip": monitor_ip,
                      "profile_id": None, "status": "online", "kind": "monitor"})
    host_at = {d["ip_address"]: device_key(d["id"]) for d in devices}
    if monitor_ip and MONITOR_KEY in macs:
        host_at.setdefault(monitor_ip, MONITOR_KEY)
    for s in services:
        k = device_key(s["id"])
        nodes.append({"key": k, "device_id": s["id"], "label": s["hostname"], "ip": s["ip_address"],
                      "profile_id": s["profile_id"], "status": s.get("status"), "kind": "service",
                      "port": s["service_port"]})
        host = host_at.get(s["ip_address"])
        if host:
            pair = tuple(sorted((host, k)))
            links[pair] = {"a": pair[0], "b": pair[1], "a_port": None, "b_port": None, "source": "auto", "kind": "service"}
    return {"nodes": nodes, "links": list(links.values()), "clients": clients}


def _is_proxmox_host(d: Dict[str, Any], macs: Set[str]) -> bool:
    descr = str((d.get("inventory") or {}).get("sys_descr", ""))
    return "-pve" in descr and not any(m.startswith(PROXMOX_OUI) for m in macs)


def _kind(d: Dict[str, Any]) -> str:
    p = d.get("profile_id") or ""
    if "gateway" in p:
        return "gateway"
    if "switch" in p:
        return "switch"
    if p.endswith("_ap"):
        return "ap"
    if "nas" in p:
        return "nas"
    return "host"


def tree(nodes: List[str], links: List[Dict[str, Any]], root: str) -> Dict[str, Optional[str]]:
    """Parent of each node reachable from root (breadth first), root maps to None."""
    adj: Dict[str, List[str]] = {n: [] for n in nodes}
    for l in links:
        if l.get("hidden"):
            continue
        adj.setdefault(l["a"], []).append(l["b"])
        adj.setdefault(l["b"], []).append(l["a"])
    parent: Dict[str, Optional[str]] = {root: None}
    queue = [root]
    while queue:
        n = queue.pop(0)
        for m in sorted(adj.get(n, [])):
            if m not in parent:
                parent[m] = n
                queue.append(m)
    return parent


def downstream(parent: Dict[str, Optional[str]], node: str) -> List[str]:
    """Every node whose path to the root passes through node."""
    children: Dict[str, List[str]] = {}
    for n, p in parent.items():
        if p is not None:
            children.setdefault(p, []).append(n)
    out, stack = [], list(children.get(node, []))
    while stack:
        n = stack.pop()
        out.append(n)
        stack.extend(children.get(n, []))
    return sorted(out)


# --- LLDP neighbours ---
# A switch that speaks LLDP says, per port, which device is at the other end and on which of its
# ports. That is exact, so an LLDP link (both port names known) replaces the guess from forwarding
# tables for that port.

def _short(name: Any) -> str:
    return str(name or "").strip().lower().split(".")[0]


def lldp_links(devices: List[Dict[str, Any]], lldp: Dict[int, Dict[str, Dict[str, Any]]],
               macs: Dict[int, Set[str]], labels: Dict[int, Dict[int, str]]) -> List[Dict[str, Any]]:
    """Links from LLDP tables ({device_id: {key: row}}, rows as poller.parse_lldp builds them).

    The neighbour is matched to a monitored device by management address, chassis MAC (any MAC
    of its interfaces, macs) or system name (its SNMP sysName or its name in the monitor). Each
    link has a_port and b_port (port names on each end) and source "lldp". When both ends report
    each other, each end's own report names its port."""
    boxes = [d for d in devices if not d.get("service_port")]
    by_ip = {d["ip_address"]: d["id"] for d in boxes}
    by_mac: Dict[str, int] = {}
    for did, ms in macs.items():
        for m in ms:
            by_mac.setdefault(str(m).lower(), did)
    by_name: Dict[str, int] = {}
    for d in boxes:
        for n in ((d.get("inventory") or {}).get("sys_name"), d.get("hostname")):
            if _short(n):
                by_name.setdefault(_short(n), d["id"])
    known = {d["id"] for d in boxes}

    def match(row: Dict[str, Any]) -> Optional[int]:
        for ip in (row.get("mgmt_ip"), row.get("chassis_ip")):
            if ip and ip in by_ip:
                return by_ip[ip]
        mac = str(row.get("chassis_mac") or "").lower()
        if mac and mac in by_mac:
            return by_mac[mac]
        return by_name.get(_short(row.get("sys_name"))) if _short(row.get("sys_name")) else None

    def remote_label(dev: int, row: Dict[str, Any]) -> Optional[str]:
        own = labels.get(dev, {})
        for v in (row.get("port_id"), row.get("port_desc")):
            if not v:
                continue
            for idx, label in own.items():
                if str(label).lower() == str(v).lower() or str(idx) == str(v):
                    return str(label)
        return row.get("remote_port") or None

    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    reported: Set[Tuple[str, str]] = set()      # (node, other node) the node itself reported
    for dev_id in sorted(lldp):
        if dev_id not in known:
            continue
        for row in lldp[dev_id].values():
            other = match(row)
            if other is None or other == dev_id:
                continue
            me, them = device_key(dev_id), device_key(other)
            pair = tuple(sorted((me, them)))
            link = out.setdefault(pair, {"a": pair[0], "b": pair[1], "a_port": None, "b_port": None, "source": "lldp",
                                         "neighbour": True})
            mine, theirs = ("a_port", "b_port") if pair[0] == me else ("b_port", "a_port")
            if (me, them) not in reported:
                link[mine] = row.get("local_port") or None
                reported.add((me, them))
            if (them, me) not in reported and not link[theirs]:
                link[theirs] = remote_label(other, row)
    for link in out.values():
        link.pop("neighbour", None)
    return list(out.values())


def merge_lldp(links: Dict[Tuple[str, str], Dict[str, Any]], lldp: List[Dict[str, Any]]) -> None:
    """Puts LLDP links into links ({(a, b): link}) in place, over the forwarding-table guesses.

    A guessed link from the same port of either end to some other node X is wrong: X sits behind
    the LLDP neighbour. It goes, and X hangs off the neighbour instead (unless already linked)."""
    for l in lldp:
        pair = (l["a"], l["b"])
        old = links.get(pair) or {}
        links[pair] = dict(l, hidden=old.get("hidden", False))
    for l in lldp:
        for end, port, other in ((l["a"], l["a_port"], l["b"]), (l["b"], l["b_port"], l["a"])):
            if not port:
                continue
            for pair, g in list(links.items()):
                if g.get("source") != "auto" or g.get("kind") or end not in pair:
                    continue
                x = pair[1] if pair[0] == end else pair[0]
                my_port = g["a_port"] if pair[0] == end else g["b_port"]
                if x == other or str(my_port or "") != str(port):
                    continue
                links.pop(pair, None)
                if any(other in p and x in p for p in links):
                    continue
                new = tuple(sorted((other, x)))
                x_port = g["b_port"] if pair[0] == end else g["a_port"]
                links[new] = {"a": new[0], "b": new[1], "a_port": x_port if new[0] == x else None,
                              "b_port": x_port if new[1] == x else None, "source": "auto", "hidden": g.get("hidden", False)}
