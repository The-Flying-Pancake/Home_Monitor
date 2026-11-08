"""Proxmox dashboard: client parsing, guest linking, config storage (secret encrypted, never returned), API."""

import http.server
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, raw_bytes, request, start_api_server

import database
import proxmox

SECRET = "1b9c1a2e-7f3d-4c51-9e0a-5f0d6f1a2b3c"
CFG = {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "secret": SECRET, "fingerprint": ""}

FAKE = {
    "/version": {"version": "8.2.4"},
    "/access/permissions": {"/": {"Sys.Audit": 1, "VM.Audit": 1, "Datastore.Audit": 1}},
    "/cluster/resources": [
        {"type": "node", "node": "pve", "status": "online", "cpu": 0.12, "maxcpu": 8, "mem": 4e9, "maxmem": 16e9, "uptime": 3600},
        {"type": "lxc", "vmid": 200, "name": "Media", "node": "pve", "status": "running", "cpu": 0.05, "maxcpu": 8,
         "mem": 1e9, "maxmem": 8e9, "disk": 5e9, "maxdisk": 50e9, "uptime": 1200, "tags": "media;arr"},
        {"type": "lxc", "vmid": 201, "name": "Monitor", "node": "pve", "status": "running", "maxcpu": 2},
        {"type": "qemu", "vmid": 100, "name": "win11", "node": "pve", "status": "stopped", "maxcpu": 4},
        {"type": "storage", "storage": "local-lvm", "node": "pve", "status": "available", "plugintype": "lvmthin",
         "disk": 10e9, "maxdisk": 100e9},
    ],
    "/nodes/pve/status": {"loadavg": ["0.10", "0.20", "0.30"], "pveversion": "pve-manager/8.2.4", "cpuinfo": {"model": "Ryzen"}},
    "/nodes/pve/lxc/201/interfaces": [{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": "192.0.2.251/24"}],
    "/cluster/tasks": [
        {"upid": "U1", "type": "vzdump", "id": "200", "node": "pve", "status": "OK", "starttime": 200, "endtime": 260},
        {"upid": "U2", "type": "qmstart", "id": "100", "node": "pve", "status": "start failed: no space", "starttime": 300, "endtime": 301},
        {"upid": "U3", "type": "vzdump", "id": "201", "node": "pve", "starttime": 400},
    ],
    "/nodes/pve/rrddata?timeframe=hour&cf=AVERAGE": [
        {"time": 1000, "cpu": 0.25, "memused": 4e9, "memtotal": 16e9, "netin": 10, "netout": 20, "loadavg": 0.4}],
    "/nodes/pve/lxc/200/rrddata?timeframe=day&cf=AVERAGE": [
        {"time": 2000, "cpu": 0.1, "mem": 1e9, "maxmem": 8e9, "netin": 100, "netout": 50}, {"cpu": 0.2}],
}


def fake_opener(calls):
    def opener(path, headers):
        calls.append((path, headers))
        if path not in FAKE:
            raise proxmox.ProxmoxError(f"no {path}")
        return FAKE[path]
    return opener


class ClientTests(unittest.TestCase):
    def test_collect_and_link(self):
        calls = []
        client = proxmox.Client(dict(CFG), opener=fake_opener(calls))
        devices = [{"id": 7, "hostname": "media", "ip_address": "192.0.2.50"},
                   {"id": 8, "hostname": "monitor-box", "ip_address": "192.0.2.251"},
                   {"id": 9, "hostname": "PVE", "ip_address": "192.0.2.250"}]
        data = proxmox.collect(client, devices)
        self.assertEqual(data["version"], "8.2.4")
        g = {x["vmid"]: x for x in data["guests"]}
        self.assertEqual(g[200]["device_id"], 7)                 # by name, case-insensitive
        self.assertEqual(g[201]["device_id"], 8)                 # by the container's address
        self.assertIsNone(g[100]["device_id"])
        self.assertEqual(g[200]["tags"], ["media", "arr"])
        self.assertEqual(data["nodes"][0]["device_id"], 9)
        self.assertEqual(data["nodes"][0]["loadavg"], ["0.10", "0.20", "0.30"])
        self.assertEqual([t["upid"] for t in data["backups"]], ["U3", "U1"])
        self.assertEqual([t["upid"] for t in data["failed_tasks"]], ["U2"])
        self.assertEqual(calls[0][1]["Authorization"], f"PVEAPIToken=monitor@pve!dash={SECRET}")
        self.assertEqual(data["storage"][0]["storage"], "local-lvm")

    def test_token_without_permission_is_explained(self):
        # Valid token, no ACL: /version answers, the cluster list is empty. Not "connected" with empty tables.
        # As a real token without permissions sees it: the node by name and status only.
        empty = {"/version": {"version": "8.2.4"}, "/access/permissions": {},
                 "/cluster/resources": [{"type": "node", "node": "pve", "status": "online", "id": "node/pve"}]}
        client = proxmox.Client(dict(CFG), opener=lambda path, headers: empty[path])
        for call in (lambda: proxmox.check(client), lambda: proxmox.collect(client, [])):
            with self.assertRaises(proxmox.ProxmoxError) as e:
                call()
            self.assertIn("PVEAuditor", str(e.exception))
        with self.assertRaises(proxmox.ProxmoxError) as e:
            proxmox.check(client)
        self.assertIn("Sys.Audit (nodes)", str(e.exception))
        self.assertEqual(proxmox.check(proxmox.Client(dict(CFG), opener=fake_opener([])))["guests"], 3)

    def test_rrd(self):
        client = proxmox.Client(dict(CFG), opener=fake_opener([]))
        pts = proxmox.rrd(client, "pve", "lxc", 200, "day")
        self.assertEqual((pts[0]["mem"], pts[0]["maxmem"], pts[0]["netin"]), (1e9, 8e9, 100.0))
        self.assertEqual(len(pts), 1)                 # rows without a time are skipped
        with self.assertRaises(proxmox.ProxmoxError):
            proxmox.rrd(client, "pve", "lxc", 200, "year")

    def test_validation(self):
        for bad in ("http://pve:8006", "https://", "https://pve:8006/api2", "pve"):
            with self.assertRaises(proxmox.ProxmoxError):
                proxmox.parse_url(bad)
        self.assertEqual(proxmox.parse_url("https://pve.lan"), ("pve.lan", 8006))
        fp = "AB:" * 31 + "CD"
        self.assertEqual(proxmox.normalise_fingerprint(fp), ("ab" * 31) + "cd")
        self.assertEqual(proxmox.pretty_fingerprint(proxmox.normalise_fingerprint(fp)), fp)
        with self.assertRaises(proxmox.ProxmoxError):
            proxmox.normalise_fingerprint("AB:CD")

    def test_cache(self):
        c = proxmox.Cache()
        n = []
        make = lambda: n.append(1) or {"v": len(n)}
        self.assertEqual(c.get(make), {"v": 1})
        self.assertEqual(c.get(make), {"v": 1})
        self.assertEqual(c.get(make, force=True), {"v": 2})


@unittest.skipUnless(shutil.which("openssl"), "openssl not available to make a test certificate")
class PinningTests(unittest.TestCase):
    """A real TLS server with a self-signed certificate: pinned is accepted, anything else refused."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="hm-pve-tls-")
        cert, key = os.path.join(cls.tmp, "c.pem"), os.path.join(cls.tmp, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pve-test",
                        "-keyout", key, "-out", cert], check=True, capture_output=True)

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                ok = self.headers.get("Authorization") == f"PVEAPIToken=monitor@pve!dash={SECRET}"
                body = json.dumps({"data": {"version": "8.2.4"}} if ok else {}).encode()
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.httpd.socket = ctx.wrap_socket(cls.httpd.socket, server_side=True)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.url = f"https://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_pinned_only(self):
        fp = proxmox.fetch_fingerprint(self.url)
        cfg = dict(CFG, url=self.url, fingerprint=proxmox.normalise_fingerprint(fp))
        self.assertEqual(proxmox.Client(cfg).get("/version"), {"version": "8.2.4"})
        with self.assertRaises(proxmox.ProxmoxError) as e:
            proxmox.Client(dict(cfg, fingerprint="00" * 32)).get("/version")
        self.assertIn("does not match the pinned fingerprint", str(e.exception))
        with self.assertRaises(proxmox.ProxmoxError) as e:
            proxmox.Client(dict(cfg, fingerprint="")).get("/version")
        self.assertIn("not trusted", str(e.exception))
        with self.assertRaises(proxmox.ProxmoxError) as e:
            proxmox.Client(dict(cfg, secret="wrong")).get("/version")
        self.assertIn("401", str(e.exception))


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_config_round_trip_and_secret_handling(self):
        self.assertFalse(request("GET", "/api/proxmox")[1]["configured"])
        status, body, _ = request("PUT", "/api/proxmox/config", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash",
                                                                 "secret": SECRET, "fingerprint": ""})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["config"]["secret_set"])
        self.assertNotIn(SECRET, str(body))
        # Stored encrypted: not in the database file, not in /api/settings.
        self.assertNotIn(SECRET.encode(), raw_bytes())
        self.assertNotIn(SECRET, str(request("GET", "/api/settings")[1]))
        self.assertEqual(proxmox.load_config()["secret"], SECRET)
        # Saving again without a secret keeps it.
        request("PUT", "/api/proxmox/config", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "secret": ""})
        self.assertEqual(proxmox.load_config()["secret"], SECRET)
        with mock.patch.object(proxmox, "Client", proxmox_client_with_fake):
            proxmox.CACHE.clear()
            status, body, _ = request("GET", "/api/proxmox")
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], "8.2.4")
        self.assertNotIn(SECRET, str(body))
        self.assertEqual(request("PUT", "/api/proxmox/config", {"url": "http://x", "token_id": "a@b!c", "secret": "s"})[0], 400)
        self.assertEqual(request("PUT", "/api/proxmox/config", {"disconnect": True})[0], 200)
        self.assertFalse(request("GET", "/api/proxmox")[1]["configured"])
        proxmox.CACHE.clear()

    def test_switch_hides_the_feature(self):
        request("PUT", "/api/proxmox/config", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "secret": SECRET})
        self.assertTrue(request("GET", "/api/features")[1]["proxmox"])        # saving a connection switches it on
        status, body, _ = request("PUT", "/api/proxmox/config", {"enabled": False})
        self.assertEqual(status, 200, body)
        self.assertFalse(body["config"]["enabled"])
        self.assertTrue(body["config"]["configured"])                        # the connection is kept
        self.assertFalse(request("GET", "/api/features")[1]["proxmox"])
        self.assertFalse(request("GET", "/api/proxmox")[1]["configured"])    # and nothing is fetched
        self.assertEqual(request("GET", "/api/proxmox/rrd?node=pve&type=node&timeframe=hour")[0], 409)
        request("PUT", "/api/proxmox/config", {"enabled": True})
        with mock.patch.object(proxmox, "Client", proxmox_client_with_fake):
            status, body, _ = request("GET", "/api/proxmox/rrd?node=pve&type=node&timeframe=hour")
            self.assertEqual(status, 200, body)
            self.assertEqual(body["points"][0]["cpu"], 0.25)
            self.assertEqual(request("GET", "/api/proxmox/rrd?node=../x&type=node")[0], 400)
            status, body, _ = request("POST", "/api/proxmox/test", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash"})
        self.assertEqual((status, body["nodes"], body["guests"]), (200, 1, 3), body)
        request("PUT", "/api/proxmox/config", {"disconnect": True})
        proxmox.CACHE.clear()

    def test_stored_secret_only_for_the_stored_address_and_token(self):
        import rbac
        self.assertEqual(rbac.route_tier("POST", "/api/proxmox/test"), 2)
        request("PUT", "/api/proxmox/config", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "secret": SECRET})
        made = []
        with mock.patch.object(proxmox, "Client", side_effect=lambda cfg: made.append(cfg) or proxmox_client_with_fake(cfg)):
            for body in ({"url": "https://198.51.100.68:8006", "token_id": "monitor@pve!dash"},
                         {"url": "https://192.0.2.250:8006", "token_id": "other@pve!dash"},
                         {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "fingerprint": "cd" * 32}):
                status, res, _ = request("POST", "/api/proxmox/test", dict(body, secret=""))
                self.assertEqual(status, 400, body)
                self.assertIn("Enter the token secret again", res["error"])
            self.assertEqual(made, [])
            status, res, _ = request("POST", "/api/proxmox/test", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash"})
            self.assertEqual(status, 200, res)
        self.assertEqual(made[0]["secret"], SECRET)
        self.assertEqual(request("PUT", "/api/proxmox/config", {"url": "https://198.51.100.68:8006", "token_id": "monitor@pve!dash",
                                                                "secret": ""})[0], 400)
        self.assertEqual(proxmox.load_config()["url"], "https://192.0.2.250:8006")
        # A new address (with its own secret) drops the action token, which would follow it otherwise.
        proxmox.save_action_token("root@pam!act", "action-secret")
        request("PUT", "/api/proxmox/config", {"url": "https://192.0.2.250:8006", "token_id": "monitor@pve!dash", "secret": ""})
        self.assertTrue(proxmox.action_config()["secret"])                                # same address: kept
        self.assertEqual(request("PUT", "/api/proxmox/config", {"url": "https://198.51.100.68:8006", "token_id": "monitor@pve!dash",
                                                                "secret": "new-secret"})[0], 200)
        self.assertEqual(proxmox.action_config()["secret"], "")
        request("PUT", "/api/proxmox/config", {"disconnect": True})
        proxmox.CACHE.clear()

    def test_node_names_are_quoted_whole(self):
        paths = []

        class C:
            def get(self, path):
                paths.append(path)
                return []
        proxmox._ips_of_lxc(C(), "pve/../../access", 101)
        self.assertEqual(paths, ["/nodes/pve%2F..%2F..%2Faccess/lxc/101/interfaces"])

    def test_unreachable_is_reported_not_raised(self):
        request("PUT", "/api/proxmox/config", {"url": "https://127.0.0.1:1", "token_id": "monitor@pve!dash", "secret": SECRET})
        proxmox.CACHE.clear()
        status, body, _ = request("GET", "/api/proxmox")
        self.assertEqual(status, 200)
        self.assertIn("Could not reach", body["error"])
        self.assertEqual(request("POST", "/api/proxmox/test", {"url": "https://127.0.0.1:1", "token_id": "monitor@pve!dash"})[0], 400)
        request("PUT", "/api/proxmox/config", {"disconnect": True})


_RealClient = proxmox.Client


def proxmox_client_with_fake(cfg):
    return _RealClient(cfg, opener=fake_opener([]))


if __name__ == "__main__":
    unittest.main()
