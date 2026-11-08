"""Port checks: TCP check, status, problems, API validation, map placement, device table migration."""

import os
import socket
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import poller
import server
import topology


class Listener:
    """A local TCP port that accepts connections, for checks that must find it open."""

    def __enter__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def _accept(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
                conn.close()
            except OSError:
                return

    def __exit__(self, *exc):
        self.stop = True
        self.sock.close()


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TcpCheckTests(unittest.TestCase):
    def test_open_and_closed(self):
        with Listener() as l:
            ok, ms = poller.tcp_check("127.0.0.1", l.port, 2.0)
        self.assertTrue(ok)
        self.assertGreaterEqual(ms, 0)
        self.assertEqual(poller.tcp_check("127.0.0.1", closed_port(), 1.0), (False, None))
        self.assertEqual(poller.tcp_check("", 80), (False, None))
        self.assertEqual(poller.tcp_check("127.0.0.1", 70000), (False, None))


class StatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = database.get_device(add_device("svc-status", "192.0.2.230"))

    def check(self, ping_ok, port_ok):
        d = dict(self.dev, service_port=8080)
        with mock.patch.object(poller, "ping_host", return_value=(ping_ok, 1.5 if ping_ok else None)), \
                mock.patch.object(poller, "tcp_check", return_value=(port_ok, 3.2 if port_ok else None)):
            status, _ = poller.ping_device(d)
        latest = {r["metric_key"]: r["value"] for r in database.get_latest_metrics(d["id"])}
        return status, latest

    def test_port_decides(self):
        status, m = self.check(True, True)
        self.assertEqual(status, "online")
        self.assertEqual((m["service_up"], m["tcp_connect_ms"]), (1.0, 3.2))
        self.assertEqual(self.check(False, True)[0], "online")      # ping blocked, service answers: up
        status, m = self.check(True, False)
        self.assertEqual((status, m["service_up"]), ("degraded", 0.0))
        self.assertEqual(self.check(False, False)[0], "offline")

    def test_problems(self):
        d = dict(self.dev, service_port=443, status="degraded")
        keys = {p["key"]: p for p in server.device_problems(d, {"service_up": 0.0}, {})}
        self.assertEqual(list(keys), ["service_down"])
        self.assertEqual(keys["service_down"]["severity"], "critical")
        self.assertIn("Port 443 not answering", keys["service_down"]["message"])
        d["status"] = "online"
        keys = {p["key"] for p in server.device_problems(d, {"service_up": 1.0, "tcp_connect_ms": 900.0}, {})}
        self.assertEqual(keys, {"service_slow"})
        self.assertEqual(server.device_problems(d, {"service_up": 1.0, "tcp_connect_ms": 20.0}, {}), [])
        d["status"] = "offline"
        msgs = [p["message"] for p in server.device_problems(d, {}, {})]
        self.assertEqual(msgs, ["Unreachable: no ping reply and port 443 not answering"])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_add_validate_and_share_an_address(self):
        snmp_id = add_device("svc-host", "192.0.2.231")
        status, body, _ = request("POST", "/api/devices", {"hostname": "web", "ip_address": "192.0.2.231",
                                                           "profile_id": "service_check"})
        self.assertEqual(status, 400)
        self.assertIn("port", body["error"])
        status, body, _ = request("POST", "/api/devices", {"hostname": "web", "ip_address": "192.0.2.231",
                                                           "profile_id": "service_check", "service_port": 8080})
        self.assertEqual(status, 201, body)
        svc_id = body["device_id"]
        # A second port on the same host is its own check; the same port twice is refused.
        self.assertEqual(request("POST", "/api/devices", {"hostname": "web2", "ip_address": "192.0.2.231",
                                                          "profile_id": "service_check", "service_port": 8443})[0], 201)
        self.assertEqual(request("POST", "/api/devices", {"hostname": "dup", "ip_address": "192.0.2.231",
                                                          "profile_id": "service_check", "service_port": 8080})[0], 409)
        dev = request("GET", f"/api/devices/{svc_id}")[1]["device"]
        self.assertEqual((dev["service_port"], dev["profile_id"]), (8080, "service_check"))
        # Other templates never carry a port, whatever the browser sends.
        status, body, _ = request("PUT", f"/api/devices/{snmp_id}", {"hostname": "svc-host", "ip_address": "192.0.2.231",
                                                                       "profile_id": "generic_device", "service_port": 22})
        self.assertEqual(status, 200, body)
        self.assertEqual(database.get_device(snmp_id)["service_port"], 0)
        # Hostnames work as addresses.
        status, body, _ = request("POST", "/api/devices", {"hostname": "loopback web", "ip_address": "localhost",
                                                           "profile_id": "service_check", "service_port": 9}, )
        self.assertEqual(status, 201, body)

    def test_probe_tests_the_port(self):
        with Listener() as l:
            status, body, _ = request("POST", "/api/devices/probe", {"ip_address": "127.0.0.1", "service_port": l.port})
        self.assertEqual(status, 200)
        self.assertTrue(body["open"])
        body = request("POST", "/api/devices/probe", {"ip_address": "127.0.0.1", "service_port": closed_port()})[1]
        self.assertFalse(body["open"])

    def test_scheduler_skips_snmp(self):
        prof = {p["profile_id"]: p for p in poller.load_hardware_profiles()}
        self.assertIs(prof["service_check"]["snmp"], False)
        self.assertEqual(prof["service_check"]["signature_oids"], [])   # never chosen by auto-detect


class MapTests(unittest.TestCase):
    def test_service_hangs_off_its_host(self):
        devices = [{"id": 1, "hostname": "nas", "ip_address": "10.0.0.5", "profile_id": "qnap_nas", "service_port": 0},
                   {"id": 2, "hostname": "nas web", "ip_address": "10.0.0.5", "profile_id": "service_check", "service_port": 8080},
                   {"id": 3, "hostname": "elsewhere", "ip_address": "web.example", "profile_id": "service_check", "service_port": 443}]
        t = topology.infer(devices, {}, {}, {})
        kinds = {n["key"]: n["kind"] for n in t["nodes"]}
        self.assertEqual(kinds, {"d:1": "nas", "d:2": "service", "d:3": "service"})
        self.assertEqual([(l["a"], l["b"], l["kind"]) for l in t["links"]], [("d:1", "d:2", "service")])


class MigrationTests(unittest.TestCase):
    def test_old_unique_address_schema_is_rebuilt(self):
        tmp = tempfile.mkdtemp(prefix="hm-mig-")
        path = os.path.join(tmp, "old.db")
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE,
              profile_id TEXT NOT NULL, snmp_version TEXT NOT NULL DEFAULT 'v2c', snmp_community TEXT DEFAULT 'public',
              snmp_port INTEGER NOT NULL DEFAULT 161, poll_interval INTEGER, ping_interval INTEGER,
              status TEXT NOT NULL DEFAULT 'unknown', last_ping_ms REAL, last_seen INTEGER, created_at INTEGER NOT NULL,
              tags TEXT DEFAULT '[]', inventory TEXT NOT NULL DEFAULT '{}', snmp_status TEXT NOT NULL DEFAULT 'unknown');
            CREATE TABLE metrics (id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE, v REAL);
            INSERT INTO devices (hostname, ip_address, profile_id, created_at) VALUES ('a', '10.0.0.1', 'generic_device', 1);
            INSERT INTO metrics (device_id, v) VALUES (1, 5.0);
        """)
        conn.commit()
        conn.close()
        with mock.patch.object(database, "DB_FILE", path):
            database._migrate_device_uniqueness()
            database._migrate_device_uniqueness()           # idempotent
        conn = sqlite3.connect(path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0], 1)   # not cascaded away
        self.assertEqual(conn.execute("SELECT hostname, service_port FROM devices").fetchall(), [("a", 0)])
        conn.execute("INSERT INTO devices (hostname, ip_address, profile_id, created_at, service_port) VALUES ('w', '10.0.0.1', 'service_check', 1, 80)")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO devices (hostname, ip_address, profile_id, created_at) VALUES ('b', '10.0.0.1', 'generic_device', 1)")
        conn.close()


if __name__ == "__main__":
    unittest.main()
