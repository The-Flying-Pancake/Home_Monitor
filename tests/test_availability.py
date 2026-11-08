"""Availability: beats, hourly counters, uptime windows, response times, incidents, API, scope."""

import time
import unittest

from tests import _env  # noqa: F401
from tests.helpers import request, start_api_server

import availability
import database


def add_device(name, ip):
    # Straight into the database: these tests are about availability, not the add-device route.
    return database.add_device(name, ip, "generic_device", snmp_community="public")


class AvailabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("avail-a", "192.0.2.240")
        cls.other = add_device("avail-b", "192.0.2.241")

    def setUp(self):
        with database.get_connection() as conn:
            for t in ("avail_beats", "avail_hourly", "avail_incidents"):
                conn.execute(f"DELETE FROM {t} WHERE device_id IN (?, ?);", (self.dev, self.other))
            conn.commit()

    def test_uptime_response_and_incidents(self):
        now = int(time.time())
        # 2 hours ago: 10 checks, 2 down in a row; last hour: 10 good checks.
        base = now - 2 * 3600
        for i in range(10):
            availability.record(self.dev, i not in (4, 5), 10.0 + i, ts=base + i * 60)
        for i in range(10):
            availability.record(self.dev, True, 20.0, ts=now - 600 + i * 30)
        s = availability.summary([self.dev], now=now)[self.dev]
        self.assertEqual(s["uptime"]["24h"], 90.0)
        self.assertEqual(s["uptime"]["90d"], 90.0)
        self.assertEqual(len(s["beats"]), 20)
        self.assertFalse(s["beats"][4]["up"])
        self.assertIsNone(s["down_since"])
        self.assertAlmostEqual(s["avg_ms"], (sum(10.0 + i for i in range(10) if i not in (4, 5)) + 200) / 18, places=2)
        self.assertEqual(s["p95_ms"], 20.0)
        d = availability.detail(self.dev, now=now)
        self.assertEqual([(i["started"], i["ended"]) for i in d["incidents"]], [(base + 240, base + 360)])
        self.assertEqual(sum(h[1] for h in d["hourly"]), 20)

    def test_ranges(self):
        # Fixed clock: 2026-11-04 10:30 UTC. Viewer two hours east (SAST), so local 12:30.
        now = 1793788200
        tz = 120
        availability.record(self.dev, True, 5.0, ts=now - 600)               # this hour
        availability.record(self.dev, False, None, ts=now - 3 * 86400)      # 3 days ago
        availability.record(self.dev, True, 7.0, ts=now - 40 * 86400)       # only inside 90 days
        for key, (hours, count) in availability.RANGE_BARS.items():
            r = availability.ranged([self.dev], key, tz, now=now)[self.dev]
            self.assertEqual((len(r["bars"]), r["bar_hours"]), (count, hours), key)
            self.assertLessEqual(r["bars"][-1][0], now)                     # the last bar is the current one
            self.assertGreater(r["bars"][-1][0] + hours * 3600, now)
        day = availability.ranged([self.dev], "30d", tz, now=now)[self.dev]
        # Day bars start at the viewer's midnight: 00:00 local is 22:00 UTC the day before.
        self.assertEqual((day["bars"][-1][0] + tz * 60) % 86400, 0)
        self.assertEqual(availability.ranged([self.dev], "24h", tz, now=now)[self.dev]["uptime"], 100.0)
        self.assertEqual(availability.ranged([self.dev], "7d", tz, now=now)[self.dev]["uptime"], 50.0)
        self.assertEqual(availability.ranged([self.dev], "30d", tz, now=now)[self.dev]["uptime"], 50.0)
        ninety = availability.ranged([self.dev], "90d", tz, now=now)[self.dev]
        self.assertAlmostEqual(ninety["uptime"], 66.667, places=2)
        self.assertEqual(ninety["avg_ms"], 6.0)
        self.assertEqual(sum(1 for b in ninety["bars"] if b[1]), 3)          # three days with checks, the rest no data
        with self.assertRaises(ValueError):
            availability.ranged([self.dev], "1y")

    def test_range_api(self):
        availability.record(self.dev, True, 5.0)
        status, body, _ = request("GET", "/api/availability?range=7d&tz=120")
        self.assertEqual((status, body["range"]), (200, "7d"))
        row = next(d for d in body["devices"] if d["id"] == self.dev)
        self.assertEqual(len(row["ranged"]["bars"]), 28)
        status, body, _ = request("GET", f"/api/availability/{self.dev}?range=90d&tz=0")
        self.assertEqual((status, len(body["ranged"]["bars"])), (200, 90))
        self.assertEqual(request("GET", "/api/availability?range=1y")[0], 400)
        self.assertEqual(request("GET", "/api/availability?tz=9999")[0], 400)

    def test_open_incident_and_no_data(self):
        now = int(time.time())
        availability.record(self.dev, True, 5.0, ts=now - 120)
        availability.record(self.dev, False, None, ts=now - 60)
        s = availability.summary([self.dev, self.other], now=now)
        self.assertEqual(s[self.dev]["down_since"], now - 60)
        self.assertEqual(s[self.dev]["uptime"]["24h"], 50.0)
        # No checks at all is "no data", never 0 % or 100 %.
        self.assertEqual(s[self.other]["uptime"], {"24h": None, "7d": None, "30d": None, "90d": None})

    def test_purge_and_cascade(self):
        now = int(time.time())
        availability.record(self.dev, True, 1.0, ts=now - 3 * 86400)
        availability.record(self.dev, True, 1.0, ts=now - 200 * 86400)
        availability.purge(now)
        with database.get_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM avail_beats WHERE device_id = ?;", (self.dev,)).fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM avail_hourly WHERE device_id = ?;", (self.dev,)).fetchone()[0], 1)
        gone = add_device("avail-gone", "192.0.2.242")
        availability.record(gone, False, None)
        self.assertTrue(database.delete_device(gone))
        with database.get_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM avail_incidents WHERE device_id = ?;", (gone,)).fetchone()[0], 0)

    def test_response_time_prefers_the_service_check(self):
        database.record_metrics(self.dev, {"tcp_connect_ms": 42.0, "icmp_ping_ms": 1.0})
        self.assertEqual(availability.response_ms(self.dev, 1.0), 42.0)

    def test_api(self):
        availability.record(self.dev, True, 3.0)
        status, body, _ = request("GET", "/api/availability")
        self.assertEqual(status, 200)
        row = next(d for d in body["devices"] if d["id"] == self.dev)
        self.assertEqual(row["uptime"]["24h"], 100.0)
        self.assertNotIn("snmp_community", row)
        status, body, _ = request("GET", f"/api/availability/{self.dev}")
        self.assertEqual(status, 200)
        self.assertIn("hourly", body)
        self.assertEqual(request("GET", "/api/availability/999999")[0], 404)


if __name__ == "__main__":
    unittest.main()
