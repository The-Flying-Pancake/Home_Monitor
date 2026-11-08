"""Topology inference from FDB and ARP tables, downstream impact, and the map API."""

import unittest

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import topology


def dev(i, name, ip, profile, descr=""):
    return {"id": i, "hostname": name, "ip_address": ip, "profile_id": profile, "status": "online",
            "inventory": {"sys_descr": descr}}


# gateway(1) - core switch(2) port 1; core p2 - edge switch(3) p8; edge p3 - NAS(4);
# core p5 - Proxmox host(5) with a guest(6) behind it; edge p4 - two unmonitored clients.
DEVICES = [dev(1, "gw", "10.0.0.1", "unifi_gateway"), dev(2, "core", "10.0.0.2", "unifi_switch"),
           dev(3, "edge", "10.0.0.3", "unifi_switch"), dev(4, "nas", "10.0.0.4", "qnap_nas"),
           dev(5, "pve", "10.0.0.5", "linux_host", "Linux pve 7.0.14-26-pve"),
           dev(6, "guest", "10.0.0.6", "linux_host", "Linux guest 7.0.14-26-pve")]
ARP = {"10.0.0.1": "aa:00:00:00:00:01", "10.0.0.2": "aa:00:00:00:00:02", "10.0.0.3": "aa:00:00:00:00:03",
       "10.0.0.4": "aa:00:00:00:00:04", "10.0.0.5": "aa:00:00:00:00:05", "10.0.0.6": "bc:24:11:00:00:06",
       "10.0.0.9": "aa:00:00:00:00:09"}
FDB = {
    2: {"aa:00:00:00:00:01": 1, "aa:00:00:00:00:03": 2, "aa:00:00:00:00:04": 2, "aa:00:00:00:00:05": 5,
        "bc:24:11:00:00:06": 5, "cc:00:00:00:00:01": 2, "aa:00:00:00:00:09": 2},
    3: {"aa:00:00:00:00:01": 8, "aa:00:00:00:00:02": 8, "aa:00:00:00:00:05": 8, "bc:24:11:00:00:06": 8,
        "aa:00:00:00:00:04": 3, "cc:00:00:00:00:01": 4, "cc:00:00:00:00:02": 4, "aa:00:00:00:00:09": 4},
}


class InferenceTests(unittest.TestCase):
    def setUp(self):
        self.t = topology.infer(DEVICES, FDB, ARP, {}, monitor_ip="10.0.0.9")
        self.pairs = {(l["a"], l["b"]): l for l in self.t["links"]}

    def test_direct_links_only(self):
        expected = {("d:1", "d:2"), ("d:2", "d:3"), ("d:3", "d:4"), ("d:2", "d:5"), ("d:5", "d:6"), ("d:3", "monitor")}
        self.assertEqual(set(self.pairs), expected)
        # The NAS is seen on core port 2 too, but the edge switch sits between.
        self.assertNotIn(("d:2", "d:4"), self.pairs)

    def test_ports_recorded_on_both_ends(self):
        link = self.pairs[("d:2", "d:3")]
        self.assertEqual((link["a_port"], link["b_port"]), (2, 8))

    def test_proxmox_guest_behind_host(self):
        self.assertEqual(self.pairs[("d:5", "d:6")].get("kind"), "virtual")
        self.assertNotIn(("d:2", "d:6"), self.pairs)

    def test_unmonitored_clients_counted_on_edge_ports(self):
        self.assertEqual(self.t["clients"]["d:3"], {4: 2})
        self.assertNotIn("d:2", self.t["clients"])   # core port 2 leads to a switch, not counted

    def test_downstream(self):
        parent = topology.tree([n["key"] for n in self.t["nodes"]], self.t["links"], "d:1")
        self.assertEqual(topology.downstream(parent, "d:2"), ["d:3", "d:4", "d:5", "d:6", "monitor"])
        self.assertEqual(topology.downstream(parent, "d:3"), ["d:4", "monitor"])
        self.assertEqual(topology.downstream(parent, "d:4"), [])
        # Hiding the core to edge link cuts the edge side off the tree.
        links = [dict(l, hidden=(l["a"], l["b"]) == ("d:2", "d:3")) for l in self.t["links"]]
        parent = topology.tree([n["key"] for n in self.t["nodes"]], links, "d:1")
        self.assertNotIn("d:3", parent)


class MapApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.a = add_device("map-a", "192.0.2.71")
        cls.b = add_device("map-b", "192.0.2.72")

    def test_objects_links_positions(self):
        status, body, _ = request("POST", "/api/map/objects", {"label": "Unmanaged switch", "kind": "switch"})
        self.assertEqual(status, 201)
        obj = body["key"]
        self.assertEqual(request("POST", "/api/map/objects", {"label": "x", "kind": "spaceship"})[0], 400)
        a, b = f"d:{self.a}", f"d:{self.b}"
        self.assertEqual(request("POST", "/api/map/links", {"a": a, "b": obj, "action": "add"})[0], 200)
        self.assertEqual(request("POST", "/api/map/links", {"a": obj, "b": b, "action": "add"})[0], 200)
        self.assertEqual(request("POST", "/api/map/links", {"a": a, "b": a, "action": "add"})[0], 400)
        self.assertEqual(request("POST", "/api/map/links", {"a": a, "b": "d:99999", "action": "add"})[0], 400)
        view = request("GET", "/api/map")[1]
        manual = {(l["a"], l["b"]) for l in view["links"] if l["source"] == "manual"}
        self.assertEqual(manual, {tuple(sorted((a, obj))), tuple(sorted((obj, b)))})

        self.assertEqual(request("PUT", "/api/map/positions", {"positions": {a: [10, 20], obj: [30.5, 40]}})[0], 200)
        self.assertEqual(request("PUT", "/api/map/positions", {"positions": {"'; DROP": [1, 2]}})[0], 400)
        self.assertEqual(request("PUT", "/api/map/positions", {"positions": {a: [1e9, 0]}})[0], 400)
        self.assertEqual(request("GET", "/api/map")[1]["positions"][a], [10.0, 20.0])

        self.assertEqual(request("DELETE", f"/api/map/objects/{obj[2:]}")[0], 200)
        view = request("GET", "/api/map")[1]
        self.assertFalse(any(obj in (l["a"], l["b"]) for l in view["links"]))
        self.assertNotIn(obj, view["positions"])

    def test_device_delete_cleans_map(self):
        c = add_device("map-c", "192.0.2.73")
        key = f"d:{c}"
        request("POST", "/api/map/links", {"a": key, "b": f"d:{self.a}", "action": "add"})
        request("PUT", "/api/map/positions", {"positions": {key: [1, 1]}})
        request("DELETE", f"/api/devices/{c}")
        self.assertFalse(any(key in (m["node_a"], m["node_b"]) for m in database.list_map_links()))
        self.assertNotIn(key, database.get_map_positions())


if __name__ == "__main__":
    unittest.main()
