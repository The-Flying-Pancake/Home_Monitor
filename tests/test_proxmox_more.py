"""Proxmox on top of the dashboard: guest configs (MACs, start at boot), the background layout
(guests matched to devices by MAC, restarts counted, storage pools recorded), guest alerts, the
map, forecasts for pools, the action token, guest actions, snapshots and the workflow step."""

import json
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import alerts
import database
import forecast
import proxmox
import server
import workflows

CFG = {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "secret": "s", "fingerprint": ""}


def data(status="running", uptime=5000):
    return {"version": "8.2", "fetched_at": 0,
            "nodes": [{"node": "pve", "status": "online", "device_id": None}],
            "guests": [{"vmid": 101, "name": "media-server-x", "node": "pve", "type": "qemu", "status": status, "uptime": uptime,
                        "mem": 7.8e9, "maxmem": 8e9, "maxdisk": 32e9, "template": False},
                       {"vmid": 102, "name": "box", "node": "pve", "type": "lxc", "status": "running", "uptime": 900,
                        "mem": 1e8, "maxmem": 1e9, "disk": 9.5e9, "maxdisk": 10e9, "template": False}],
            "storage": [{"storage": "local-lvm", "node": "pve", "status": "available", "disk": 40e9, "maxdisk": 100e9}],
            "backups": [], "failed_tasks": []}


class GuestConfigTests(unittest.TestCase):
    def test_parse(self):
        vm = proxmox.parse_guest_config({"net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1", "net1": "e1000=bc:24:11:00:00:01,bridge=vmbr1",
                                         "onboot": 1, "memory": 4096})
        self.assertEqual(vm, {"macs": ["bc:24:11:aa:bb:cc", "bc:24:11:00:00:01"], "onboot": True})
        ct = proxmox.parse_guest_config({"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:DD:EE:FF,ip=dhcp"})
        self.assertEqual(ct, {"macs": ["bc:24:11:dd:ee:ff"], "onboot": False})


class LayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.node = add_device("pve-more", "198.51.100.150", profile="linux_host")
        cls.vm = add_device("media-server-more", "198.51.100.151", profile="ping_only")

    def refresh(self, d, now):
        arp = [{"row_key": "198.51.100.151", "mac": "BC:24:11:AA:BB:CC"}]
        d["nodes"][0]["device_id"] = self.node
        configs = {101: {"macs": ["bc:24:11:aa:bb:cc"], "onboot": True}, 102: {"macs": [], "onboot": True}}
        with mock.patch.object(proxmox, "is_enabled", return_value=True), mock.patch.object(proxmox, "load_config", return_value=CFG), \
                mock.patch.object(proxmox.CACHE, "get", return_value=d), \
                mock.patch.object(proxmox, "guest_config", side_effect=lambda c, g, n: configs[g["vmid"]]):
            self.assertIsNone(proxmox.refresh(database.list_devices(), arp, now))

    def layout(self):
        return json.loads(database.get_all_settings()[proxmox.LAYOUT_KEY])

    def test_layout_alerts_map_and_forecast(self):
        database.set_internal_setting(proxmox.LAYOUT_KEY, "{}")
        now = time.time()
        self.refresh(data(uptime=5000), now)
        lay = self.layout()
        vm = next(g for g in lay["guests"] if g["vmid"] == 101)
        self.assertEqual(vm["device_id"], self.vm)                      # matched by MAC through the ARP table, not by name
        self.assertEqual(vm["ips"], ["198.51.100.151"])
        # A restart (uptime went down) is counted; three in an hour is a problem.
        for i, up in enumerate((60, 30, 10)):
            self.refresh(data(uptime=up + 1000 * (i % 1)), now + 60 * (i + 1))
            if i < 2:
                self.refresh(data(uptime=up + 500), now + 60 * (i + 1) + 30)
        lay = self.layout()
        self.assertGreaterEqual(len(lay["restarts"]["pve/101"]), 3)
        policy = server.alert_policy()
        with mock.patch.object(proxmox, "is_enabled", return_value=True):
            probs = {p["rule"]: p for p in server.proxmox_problems(database.list_devices(), policy, lay, now + 300)}
        self.assertIn("pve_guest_restarts", probs)
        self.assertEqual(probs["pve_guest_restarts"]["device_id"], self.vm)        # on the guest's own device
        self.assertIn("pve_guest_memory", probs)                                     # 7.8 of 8 GB
        self.assertEqual(probs["pve_guest_disk"]["device_id"], self.node)          # box is not monitored: on its node
        # Stopped although it starts at boot.
        self.refresh(data(status="stopped"), now + 400)
        with mock.patch.object(proxmox, "is_enabled", return_value=True):
            probs = {p["rule"]: p for p in server.proxmox_problems(database.list_devices(), policy, self.layout(), now + 400)}
        self.assertIn("starts at boot", probs["pve_guest_down"]["message"])
        # The storage pool is recorded on the node's device, for forecasts.
        latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(self.node)}
        self.assertEqual(latest["pvs.local-lvm.used_pct"], 40.0)
        self.assertTrue(forecast.KEY_RE.match("pvs.local-lvm.used_pct"))
        with mock.patch.object(proxmox, "is_enabled", return_value=True):
            self.assertEqual(forecast._labels(self.node)["pvs.local-lvm.used_pct"], "Proxmox storage local-lvm")
        # The map: the guest hangs off its node, as Proxmox says.
        with mock.patch.object(proxmox, "is_enabled", return_value=True):
            links = server.map_view()["links"]
        pair = tuple(sorted((f"d:{self.vm}", f"d:{self.node}")))
        hit = [l for l in links if (l["a"], l["b"]) == pair]
        self.assertEqual((hit[0]["source"], hit[0]["kind"]), ("proxmox", "virtual"), hit)


class ActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def tearDown(self):
        proxmox.save_action_token("", "")

    def test_token_and_api(self):
        self.assertEqual(request("PUT", "/api/proxmox/actions", {"token_id": "bad", "secret": "x"})[0], 400)
        self.assertEqual(request("PUT", "/api/proxmox/actions", {"token_id": "root@pam!act"})[0], 400)    # no secret yet
        status, body, _ = request("PUT", "/api/proxmox/actions", {"token_id": "root@pam!act", "secret": "sekret"})
        self.assertEqual(status, 200, body)
        with database.get_connection() as c:
            self.assertTrue(c.execute("SELECT value FROM settings WHERE key = 'proxmox_action_secret'").fetchone()["value"].startswith("enc1:"))
        cfg = request("GET", "/api/proxmox/config")[1]
        self.assertEqual(cfg["action_token_id"], "root@pam!act")
        self.assertNotIn("sekret", json.dumps(cfg))
        # Proxmox off: actions refused with the reason.
        status, body, _ = request("POST", "/api/proxmox/guest", {"node": "pve", "type": "qemu", "vmid": 101, "action": "reboot"})
        self.assertEqual(status, 400)
        self.assertEqual(request("POST", "/api/proxmox/guest", {"node": "pve", "type": "qemu", "vmid": 101, "action": "destroy"})[0], 400)

    def test_actions_and_snapshot(self):
        calls = []

        def opener(path, headers):
            calls.append((headers.get("method", "GET"), path, headers.get("body"), headers["Authorization"]))
            if path.endswith("/snapshot") or "/status/" in path:
                return "UPID:pve:1"
            if "/tasks/" in path:
                return {"status": "stopped", "exitstatus": "OK"}
            return None

        proxmox.save_action_token("root@pam!act", "sekret")
        real = proxmox.Client
        with mock.patch.object(proxmox, "is_enabled", return_value=True), mock.patch.object(proxmox, "load_config", return_value=CFG), \
                mock.patch.object(proxmox, "Client", side_effect=lambda cfg: real(cfg, opener=opener)):
            proxmox.guest_action("pve", "qemu", 101, "reboot")
            name = proxmox.snapshot("pve", "lxc", 102, "Before workflow 'Update'", 30)
            with self.assertRaises(proxmox.ProxmoxError):
                proxmox.guest_action("pve; rm", "qemu", 101, "start")                     # node names are checked
        self.assertEqual(calls[0][:2], ("POST", "/nodes/pve/qemu/101/status/reboot"))
        self.assertIn("root@pam!act=sekret", calls[0][3])                                  # the action token, not the read one
        self.assertTrue(name.startswith("monitor-"))
        snap = next(c for c in calls if c[1].endswith("/snapshot"))
        self.assertIn(f"snapname={name}", snap[2])
        self.assertTrue(any("/tasks/" in c[1] for c in calls))                              # waited for it

    def test_workflow_step(self):
        step = workflows._parse_step({"type": "pve_snapshot", "node": "pve", "guest_type": "lxc", "vmid": 102, "guest_name": "box"}, set(), set())
        self.assertEqual((step["node"], step["guest_type"], step["vmid"], step["timeout_s"]), ("pve", "lxc", 102, 600))
        self.assertEqual(workflows.describe(step, {}), "Snapshot box (102) on pve")
        for bad in ({"type": "pve_snapshot", "node": "pve", "guest_type": "x", "vmid": 1}, {"type": "pve_snapshot", "node": "", "guest_type": "lxc", "vmid": 1},
                    {"type": "pve_snapshot", "node": "pve", "guest_type": "lxc"}):
            with self.assertRaises(workflows.WorkflowError):
                workflows._parse_step(bad, set(), set())


if __name__ == "__main__":
    unittest.main()
