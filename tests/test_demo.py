"""Demo mode: the seed (documentation addresses only, history, refusals) and simulated polling.

The seed runs against its own throwaway database file so the devices it adds do not show up
in the other suites' shared test database. Polling tests patch every way out to the network
(sockets, ping subprocesses and urllib) so a single real call fails the test.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from unittest import mock

from tests import _env  # noqa: F401  (must precede project imports)

import database
import demo
import poller
from vault import VAULT

DEMO_ON = {"MONITOR_DEMO": "1"}


def _no_network(*_a, **_kw):
    raise AssertionError("demo mode made a network call")


class _Sandbox:
    """Points the database module at a fresh file for the duration of a test class."""

    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="hm-demo-", dir=_env.TMP)
        self.patch = mock.patch.object(database, "DB_FILE", os.path.join(self.dir, "monitor.db"))

    def __enter__(self):
        self.patch.start()
        demo._forget()               # demo mode is read from this database, not the last one
        return self

    def __exit__(self, *exc) -> None:
        self.patch.stop()
        demo._forget()
        # The vault remembers where its metadata lives: send it back to the shared test database.
        VAULT.load(os.path.dirname(os.path.abspath(database.DB_FILE)))
        shutil.rmtree(self.dir, ignore_errors=True)


def _cut_network():
    """Patches that make any socket, subprocess or urllib use fail loudly."""
    return [mock.patch.object(socket, "socket", side_effect=_no_network),
            mock.patch.object(socket, "create_connection", side_effect=_no_network),
            mock.patch.object(socket, "getaddrinfo", side_effect=_no_network),
            mock.patch.object(subprocess, "run", side_effect=_no_network),
            mock.patch.object(subprocess, "Popen", side_effect=_no_network),
            mock.patch.object(urllib.request, "urlopen", side_effect=_no_network),
            mock.patch.object(urllib.request.OpenerDirector, "open", side_effect=_no_network)]


class DemoSeedAndPollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sandbox = _Sandbox().__enter__()
        cls.result = demo.seed(days=1, log=lambda *_a: None)
        cls.devices = database.list_devices()
        cls.profiles = {p["profile_id"]: p for p in poller.load_hardware_profiles()}

    @classmethod
    def tearDownClass(cls):
        cls.sandbox.__exit__(None, None, None)

    def device(self, hostname):
        return next(d for d in database.list_devices() if d["hostname"] == hostname)

    # --- Seed ---

    def test_seed_uses_documentation_addresses_only(self):
        self.assertTrue(12 <= len(self.devices) <= 16, len(self.devices))
        for d in self.devices:
            self.assertTrue(demo.is_demo_address(d["ip_address"]), d)
            self.assertIn(d["profile_id"], self.profiles)
        names = {d["hostname"] for d in self.devices}
        self.assertTrue({"core-switch", "edge-router", "nas-01", "hypervisor-01", "pihole", "ups", "web-check"} <= names)

    def test_seed_writes_history_events_groups_tags_and_map(self):
        with database.get_connection() as conn:
            per_device = {r[0]: r[1] for r in conn.execute("SELECT device_id, COUNT(*) FROM metrics GROUP BY device_id;")}
            hourly = conn.execute("SELECT COUNT(*) FROM metrics_hourly;").fetchone()[0]
            beats = conn.execute("SELECT COUNT(*) FROM avail_hourly;").fetchone()[0]
        for d in self.devices:
            # One day at five minute steps: about 288 rounds, each with at least a latency sample.
            self.assertGreater(per_device.get(d["id"], 0), 200, d["hostname"])
        self.assertGreater(hourly, 0)
        self.assertGreater(beats, 0)
        now = int(time.time())
        cpu = database.get_metric_history(self.device("hypervisor-01")["id"], "cpu_usage_pct", now - 2 * 86400, now)
        self.assertGreater(len(cpu), 200)
        self.assertGreater(max(p["value"] for p in cpu) - min(p["value"] for p in cpu), 5)
        events = database.list_events(limit=500)
        self.assertTrue(any(e["event_type"] == "config" for e in events))
        self.assertTrue(any(d.get("device_group") for d in self.devices))
        self.assertTrue(any(d["tags"] not in (None, "", "[]") for d in self.devices))
        self.assertGreaterEqual(len(database.get_map_positions()), len(self.devices))
        tables = database.list_table_names(self.device("backup-nas")["id"])
        self.assertIn("interfaces", tables)
        self.assertIn("storage", tables)

    def test_seed_creates_no_account(self):
        self.assertIsNone(database.get_account())
        self.assertEqual(database.list_users(), [])

    def test_seed_refuses_twice(self):
        with self.assertRaises(demo.SeedRefused):
            demo.seed(days=1, log=lambda *_a: None)

    # --- Polling in demo mode ---

    def test_demo_polling_is_plausible_and_offline(self):
        patches = _cut_network()
        with mock.patch.dict(os.environ, DEMO_ON), mock.patch.object(demo, "outage", return_value=None):
            mocks = [p.start() for p in patches]
            try:
                for d in database.list_devices():
                    status, ms = poller.ping_device(d)
                    self.assertEqual(status, "online", d["hostname"])
                    self.assertTrue(0 < ms < 500, (d["hostname"], ms))
                    profile = self.profiles[d["profile_id"]]
                    if d.get("service_port") or not profile.get("metrics"):
                        continue
                    m = poller.poll_snmp_metrics(d, profile)
                    self.assertGreater(m["uptime_seconds"], 0)
                    if "cpu_usage_pct" in m:
                        self.assertTrue(0 <= m["cpu_usage_pct"] <= 100, (d["hostname"], m))
                    if "mem_used_pct" in m:
                        self.assertTrue(1 <= m["mem_used_pct"] <= 99, (d["hostname"], m))
                    written = poller.collect_tables(d, profile)
                    self.assertIn("interfaces", written)
                    live = poller.live_sample(d, profile)
                    self.assertTrue(live["alive"])
                    self.assertTrue(live["counters"])
                nas = self.device("nas-01")
                m = {r["metric_key"]: r["value"] for r in database.get_latest_metrics(nas["id"])}
                self.assertTrue(20 < m["system_temp_c"] < 80, m)
                self.assertIn("vol.1.used_pct", m)
                web = self.device("web-check")
                up, ms, extra = poller.service_check(web, 2.0)
                self.assertTrue(up)
                self.assertEqual(extra["http_status"], 200.0)
                self.assertTrue(0 < extra["tls_days_left"] <= 90)
                self.assertEqual(poller.ping_host("192.0.2.1")[0], True)
                self.assertEqual(poller.tcp_check("198.51.100.40", 80)[0], True)
                self.assertTrue(poller.http_check("https://www.example.com/")["up"])
                self.assertIsNone(poller.snmp_get("203.0.113.10", "1.3.6.1.2.1.1.3.0"))
            finally:
                for p in patches:
                    p.stop()
        for p, m in zip(patches, mocks):
            self.assertFalse(m.called, p.attribute)

    def test_values_are_deterministic_and_smooth(self):
        d = self.device("hypervisor-01")
        t0 = 1_790_000_000
        self.assertEqual(demo.values(d, t0), demo.values(d, t0))
        mem = [demo.values(d, t0 + i * 300)["mem_used_pct"] for i in range(288)]
        self.assertLess(max(abs(a - b) for a, b in zip(mem, mem[1:])), 10)
        self.assertGreater(max(mem) - min(mem), 2)
        # Another device at the same instants gets its own curve.
        other = [demo.values(self.device("pihole"), t0 + i * 300)["mem_used_pct"] for i in range(288)]
        self.assertNotEqual(mem, other)

    def test_outages_and_disk_creep(self):
        t0 = 1_790_000_000
        found = None
        for d in self.devices:
            spans = demo.outages_between(d, t0, t0 + 14 * 86400)
            if spans:
                found = (d, spans[0])
                break
        self.assertIsNotNone(found, "no device has an outage in two weeks")
        d, (a, b) = found
        self.assertTrue(180 <= b - a <= 1500)
        self.assertEqual(demo.ping(d, a + 1), (False, None))
        self.assertEqual(demo.snmp_metrics(d, [{"key": "uptime_seconds"}], a + 1), {})
        self.assertTrue(demo.ping(d, b + 1)[0])
        self.assertLess(demo.values(d, b + 60)["uptime_seconds"], 600)
        backup = self.device("backup-nas")
        levels = [demo.disk_used_pct(backup, t0 + h * 3600, 1) for h in range(0, 10 * 24, 3)]
        self.assertGreaterEqual(max(levels), 90)
        self.assertLess(min(levels), 80)


class DemoModeFlagTests(unittest.TestCase):
    """The seed switches demo mode on in the database (no environment variable needed); removing it
    takes away exactly what the seed made and switches it off."""

    def test_seed_turns_it_on_and_remove_takes_only_the_demo(self):
        import setup
        import taxonomy
        with _Sandbox(), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MONITOR_DEMO", None)
            self.assertFalse(demo.enabled())
            demo.seed(days=1, log=lambda *_a: None)
            self.assertTrue(demo.enabled())
            self.assertTrue(setup.is_completed())                  # straight to the dashboard
            seeded = demo.status()
            self.assertTrue(seeded["on"])
            self.assertGreaterEqual(seeded["devices"], 12)
            # Things that are not the demo's: a real device using a demo tag, and a demo device moved to a real address.
            real = database.add_device("home-router", "192.168.1.1", "generic_device", snmp_community="public")
            taxonomy.set_device_tags(real, ["critical"])
            moved = next(d for d in database.list_devices() if d["hostname"] == "pihole")
            with database.get_connection() as conn:
                conn.execute("UPDATE devices SET ip_address = '192.168.1.53' WHERE id = ?;", (moved["id"],))
                conn.commit()
            done = demo.remove(log=lambda *_a: None)
            self.assertEqual(done["devices"], seeded["devices"] - 1)
            left = {d["hostname"] for d in database.list_devices()}
            self.assertEqual(left, {"home-router", "pihole"})
            self.assertIn("critical", [x["name"] for x in taxonomy.tags()])   # still used by a real device
            with database.get_connection() as conn:
                orphans = conn.execute("SELECT COUNT(*) FROM metrics WHERE device_id NOT IN (SELECT id FROM devices);").fetchone()[0]
            self.assertEqual(orphans, 0)
            self.assertFalse(demo.enabled())
            self.assertFalse(demo.status()["on"])
            self.assertEqual(demo.remove(log=lambda *_a: None)["devices"], 0)   # a second time removes nothing


class DemoRefusesRealDataTests(unittest.TestCase):
    def test_refuses_database_with_real_device(self):
        import server
        with _Sandbox():
            server.initialise()
            database.add_device("home-router", "192.168.1.1", "generic_device", snmp_community="public")
            with self.assertRaises(demo.SeedRefused) as cm:
                demo.seed(days=1, log=lambda *_a: None)
            self.assertIn("192.168.1.1", str(cm.exception))
            self.assertEqual([d["hostname"] for d in database.list_devices()], ["home-router"])


class DemoOffTests(unittest.TestCase):
    """With demo mode off a documentation address goes to the network like any other."""

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop("MONITOR_DEMO", None)

    def tearDown(self):
        self.env.stop()

    def test_off_means_real_calls(self):
        self.assertFalse(demo.handles("192.0.2.1"))
        self.assertFalse(demo.handles_url("https://www.example.com/"))
        done = subprocess.CompletedProcess(["ping"], 1, "", "")
        with mock.patch.object(poller.subprocess, "run", return_value=done) as run:
            self.assertEqual(poller.ping_host("192.0.2.1", 0.5), (False, None))
        run.assert_called_once()
        with mock.patch.object(poller.socket, "create_connection", side_effect=OSError("refused")) as conn:
            self.assertEqual(poller.tcp_check("192.0.2.1", 22, 0.5), (False, None))
        conn.assert_called_once()
        udp = mock.MagicMock()
        udp.connect.side_effect = OSError("no route")
        with mock.patch.object(poller.socket, "socket", return_value=udp) as sock:
            self.assertIsNone(poller.snmp_get("192.0.2.1", "1.3.6.1.2.1.1.3.0"))
        sock.assert_called_once()
        udp.connect.assert_called_once_with(("192.0.2.1", 161))

    def test_demo_on_leaves_real_addresses_alone(self):
        done = subprocess.CompletedProcess(["ping"], 1, "", "")
        with mock.patch.dict(os.environ, DEMO_ON), mock.patch.object(poller.subprocess, "run", return_value=done) as run:
            self.assertFalse(demo.handles("192.168.1.1"))
            self.assertEqual(poller.ping_host("192.168.1.1", 0.5), (False, None))
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
