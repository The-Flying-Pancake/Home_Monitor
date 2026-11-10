"""Metric storage classes, hourly rollups, retention, comparison windows and the problem engine."""

import itertools
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import server


class StorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("storage-dev", "192.0.2.20")

    def count(self, key):
        with database.get_connection() as c:
            return c.execute("SELECT COUNT(*) FROM metrics WHERE device_id = ? AND metric_key = ?", (self.dev, key)).fetchone()[0]

    def test_history_modes(self):
        t0 = int(time.time()) - 7200
        modes = {"raw_k": "raw", "chg_k": "change", "hr_k": "hourly", "none_k": "none"}
        for i in range(5):
            database.record_metrics(self.dev, {"raw_k": float(i), "chg_k": 1.0 if i < 3 else 2.0, "hr_k": float(i), "none_k": 9.0},
                                    timestamp=t0 + i * 300, history=modes)
        self.assertEqual(self.count("raw_k"), 5)
        self.assertEqual(self.count("chg_k"), 2)   # stored at first sample and on the change to 2.0
        self.assertEqual(self.count("hr_k"), 1)    # five samples within the same hour
        self.assertEqual(self.count("none_k"), 0)
        latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(self.dev)}
        self.assertEqual(latest["none_k"], 9.0)    # latest value still shown
        self.assertEqual(latest["chg_k"], 2.0)

    def test_change_mode_hourly_heartbeat(self):
        t0 = int(time.time()) - 10000
        for i in range(3):
            database.record_metrics(self.dev, {"hb_k": 5.0}, timestamp=t0 + i * 3700, history={"hb_k": "change"})
        self.assertEqual(self.count("hb_k"), 3)

    def test_rollup_and_exclusion(self):
        hour = (int(time.time()) // 3600 - 3) * 3600
        for i in range(6):
            database.record_metrics(self.dev, {"roll_k": float(i), "skip_k": 1.0}, timestamp=hour + i * 600)
        with database.get_connection() as c:
            c.execute("DELETE FROM metrics_hourly")
            c.commit()
        database.rollup_hourly(exclude={(self.dev, "skip_k")})
        with database.get_connection() as c:
            row = c.execute("SELECT avg, min, max, samples FROM metrics_hourly WHERE device_id=? AND metric_key='roll_k' AND hour=?",
                            (self.dev, hour)).fetchone()
            skipped = c.execute("SELECT COUNT(*) FROM metrics_hourly WHERE metric_key='skip_k'").fetchone()[0]
        self.assertEqual(tuple(row), (2.5, 0.0, 5.0, 6))
        self.assertEqual(skipped, 0)

    def test_compare_window_shifted(self):
        now = int(time.time())
        database.record_metrics(self.dev, {"cmp_k": 10.0}, timestamp=now - 3600 * 30)  # yesterday, within 24-48 h ago
        database.record_metrics(self.dev, {"cmp_k": 20.0}, timestamp=now - 3600 * 6)
        _, body, _ = request("GET", f"/api/devices/{self.dev}/history?keys=cmp_k&hours=24&compare=1")
        self.assertEqual([p["value"] for p in body["series"]["cmp_k"]], [20.0])
        prev = body["previous"]["cmp_k"]
        self.assertEqual(len(prev), 1)
        self.assertAlmostEqual(prev[0]["timestamp"], now - 3600 * 6, delta=600)  # shifted onto today's axis

    def test_retention_purge(self):
        old = int(time.time()) - 40 * 86400
        database.record_metrics(self.dev, {"old_k": 1.0}, timestamp=old)
        database.purge_expired(raw_retention_days=7, audit_retention_days=90, trend_retention_days=30)
        self.assertEqual(self.count("old_k"), 0)


class SoftwareEventTests(unittest.TestCase):
    def test_install_remove_update_and_batch(self):
        dev = add_device("sw-dev", "192.0.2.22")
        old = {"a": {"version": "1"}, "b": {"version": "1"}, "c": {"version": "1"}}
        new = {"a": {"version": "2"}, "c": {"version": "1"}, "d": {"version": "5"}}
        server.poller.log_software_changes(dev, old, new)
        msgs = sorted(e["message"] for e in database.list_events(dev) if e["event_type"] == "software")
        self.assertEqual(msgs, ["Installed d 5", "Removed b 1", "Updated a 1 to 2"])
        big = {f"pkg{i}": {"version": "2"} for i in range(30)}
        server.poller.log_software_changes(dev, {k: {"version": "1"} for k in big}, big)
        latest = database.list_events(dev, limit=1)[0]["message"]
        self.assertTrue(latest.startswith("30 software changes"))


class WanPeakTests(unittest.TestCase):
    """The WAN sampler keeps the highest short-interval rate, which a 5-minute average hides."""

    def test_peak_survives_averaging(self):
        dev = add_device("wan-dev", "192.0.2.21")
        database.update_device_status(dev, "online", 1.0)
        sampler = server.WanPeakSampler()
        target = [{"device_id": dev, "if_index": 8, "speed_mbps": 1000}]
        # Octets: idle, then 900 Mbit/s for 10 s, then idle again.
        octets = iter([0, 0, 1_000, 100, 1_125_001_000, 10_100, 1_125_002_000, 10_200])
        # sample() reads the clock twice per call, so samples land 10 s apart.
        clock = itertools.count(1000.0, 5.0)

        def fake_get(ip, oids, *a, **k):
            return {oids[0]: next(octets), oids[1]: next(octets)}

        with mock.patch.object(server, "wan_interfaces", return_value=target),                 mock.patch.object(server.poller, "snmp_get_many", side_effect=fake_get),                 mock.patch.object(server.time, "time", side_effect=lambda: next(clock)):
            for _ in range(4):
                sampler.sample(1.0)
        peak_in, peak_out = sampler.peaks[(dev, 8)]
        self.assertAlmostEqual(peak_in, 900e6, delta=1e6)
        self.assertLess(peak_out, 1e5)
        sampler.flush()
        latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(dev)}
        self.assertAlmostEqual(latest["if.8.in_peak_bps"], 900e6, delta=1e6)
        self.assertEqual(sampler.peaks, {})


class ProblemEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("problem-dev", "192.0.2.30")

    def dev_problems(self, **kw):
        d = database.get_device(self.dev)
        d.update(kw.pop("device", {}))
        return {p["key"]: p for p in server.device_problems(d, kw.get("m", {}), kw.get("tables", {}))}

    def test_triggers(self):
        self.assertIn("unreachable", self.dev_problems(device={"status": "offline"}))
        probs = self.dev_problems(device={"status": "online", "snmp_status": "ok"}, m={"uptime_seconds": 99999, "cpu_usage_pct": 95, "mem_used_pct": 92},
                                  tables={"disks": {"1": {"name": "HDD1", "smart": "Abnormal", "temp_c": 60}},
                                          "volumes": {"1": {"descr": "Data", "status": "Degraded", "used_pct": 95}},
                                          "radios": {"1": {"band": "ng", "util_pct": 80}},
                                          "sensors": {"3": {"name": "Tctl", "slug": "tctl", "temp_c": 91.5}, "1": {"name": "Composite", "slug": "composite", "temp_c": 50.0}},
                                          "interfaces": {"3": {"kind": "port", "label": "0/3", "in_errors_delta": 4}}})
        for key in ("cpu", "mem", "disk_smart:1", "disk_temp:1", "volume_state:1", "volume_full:1", "radio:ng", "port_errors:3", "sensor_temp:tctl"):
            self.assertIn(key, probs)
        self.assertEqual(probs["disk_smart:1"]["severity"], "critical")
        self.assertNotIn("sensor_temp:composite", probs)
        self.assertIn("snmp_view", self.dev_problems(device={"status": "online", "snmp_status": "ok"}, m={"uptime_seconds": 5000}))

    def test_watched_process_and_service(self):
        watches = [{"kind": "process", "name": "pihole-FTL"}, {"kind": "service", "name": "Veeam"}, {"kind": "process", "name": "sshd"}]
        d = dict(database.get_device(self.dev), status="online")
        tables = {"processes": {"sshd": {"name": "sshd", "count": 2}}, "services": {"Veeam": {"name": "Veeam", "state": "paused"}}}
        keys = {p["key"] for p in server.device_problems(d, {}, tables, None, watches)}
        self.assertIn("watch:process:pihole-FTL", keys)
        self.assertIn("watch:service:Veeam", keys)
        self.assertNotIn("watch:process:sshd", keys)
        # No table collected (SNMP down): nothing reported for the watches.
        keys = {p["key"] for p in server.device_problems(d, {}, {}, None, watches)}
        self.assertFalse(any(k.startswith("watch:") for k in keys))

    def test_watch_api(self):
        status, body, _ = request("POST", f"/api/devices/{self.dev}/watches", {"kind": "process", "name": "nginx", "watched": True})
        self.assertEqual(status, 200)
        self.assertEqual([w["name"] for w in body["watches"]], ["nginx"])
        for bad in ({"kind": "file", "name": "x", "watched": True}, {"kind": "process", "name": "", "watched": True},
                    {"kind": "process", "name": "x", "watched": "yes"}):
            self.assertEqual(request("POST", f"/api/devices/{self.dev}/watches", bad)[0], 400)
        status, body, _ = request("POST", f"/api/devices/{self.dev}/watches", {"kind": "process", "name": "nginx", "watched": False})
        self.assertEqual(body["watches"], [])
        self.assertEqual(request("GET", f"/api/devices/{self.dev}/processes")[0], 200)

    def test_open_hysteresis_resolve_and_ack(self):
        p = {"device_id": self.dev, "hostname": "problem-dev", "key": "cpu", "severity": "warning", "message": "CPU usage 95%"}
        now = int(time.time())
        delay = lambda key: 0 if key == "unreachable" else 300
        self.assertEqual(len(database.sync_problems([p], delay, now)["opened"]), 1)
        status, _, _ = request("POST", "/api/problems/ack", {"device_id": self.dev, "problem_key": "cpu", "acknowledged": True, "note": "known"})
        self.assertEqual(status, 200)
        self.assertEqual(database.sync_problems([p], delay, now + 30)["opened"], [])   # still open, ack kept
        acked = [x for x in database.list_active_problems() if x["device_id"] == self.dev][0]
        self.assertIsNotNone(acked["acknowledged_at"])
        self.assertEqual(database.sync_problems([], delay, now + 100)["resolved"], [])  # inside the resolve delay
        self.assertEqual(len(database.sync_problems([], delay, now + 400)["resolved"]), 1)
        reopened = database.sync_problems([p], delay, now + 500)["opened"]
        self.assertEqual(len(reopened), 1)
        fresh = [x for x in database.list_active_problems() if x["device_id"] == self.dev][0]
        self.assertIsNone(fresh["acknowledged_at"])                                       # recurrence is unacknowledged
        database.sync_problems([], lambda k: 0, now + 600)


class AuditRetentionTests(unittest.TestCase):
    def test_audit_floor_and_separate_events(self):
        now = int(time.time())
        with database.get_connection() as conn:
            conn.execute("INSERT INTO audit_log (timestamp, category, message, details) VALUES (?, 'floor', 'sixty days old', '');",
                         (now - 60 * 86400,))
            conn.execute("INSERT INTO events (timestamp, severity, event_type, message) VALUES (?, 'info', 'floortest', 'ten days old');",
                         (now - 10 * 86400,))
            conn.execute("INSERT INTO events (timestamp, severity, event_type, message) VALUES (?, 'info', 'floortest', 'two days old');",
                         (now - 2 * 86400,))
            conn.commit()
        database.purge_expired(7, 1, 365, event_retention_days=5)
        with database.get_connection() as conn:
            audit = conn.execute("SELECT COUNT(*) FROM audit_log WHERE category = 'floor';").fetchone()[0]
            events = [r[0] for r in conn.execute("SELECT message FROM events WHERE event_type = 'floortest';")]
            conn.execute("DELETE FROM audit_log WHERE category = 'floor';")
            conn.execute("DELETE FROM events WHERE event_type = 'floortest';")
            conn.commit()
        self.assertEqual(audit, 1)                    # a 1-day setting cannot go below 90 days
        self.assertEqual(events, ["two days old"])    # events follow their own setting


if __name__ == "__main__":
    unittest.main()
