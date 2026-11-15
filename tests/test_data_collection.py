"""Data the reports asked for: several pings per check (packet loss and jitter), LLDP neighbours on
the map and in the interface tables, and capacity readings from custom OIDs."""

import subprocess
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import request, start_api_server

import availability
import customoids
import database
import forecast
import poller
import server
import topology

LINUX_OK = """PING 192.0.2.10 (192.0.2.10) 56(84) bytes of data.
64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 192.0.2.10: icmp_seq=2 ttl=64 time=1.80 ms
64 bytes from 192.0.2.10: icmp_seq=3 ttl=64 time=1.50 ms

--- 192.0.2.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 402ms
rtt min/avg/max/mdev = 1.200/1.500/1.800/0.245 ms
"""
LINUX_PARTIAL = """PING 192.0.2.10 (192.0.2.10) 56(84) bytes of data.
64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=2.0 ms
64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=2.4 ms (DUP!)
64 bytes from 192.0.2.10: icmp_seq=3 ttl=64 time=6.0 ms

--- 192.0.2.10 ping statistics ---
3 packets transmitted, 2 received, +1 duplicates, 33.3333% packet loss, time 405ms
"""
LINUX_LOST = """PING 192.0.2.10 (192.0.2.10) 56(84) bytes of data.

--- 192.0.2.10 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 1010ms
"""
WINDOWS_MIXED = """
Pinging 192.0.2.10 with 32 bytes of data:
Reply from 192.0.2.10: bytes=32 time=3ms TTL=64
Request timed out.
Reply from 192.0.2.10: bytes=32 time<1ms TTL=64
Reply from 192.0.2.1: Destination host unreachable.

Ping statistics for 192.0.2.10:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
"""


class PingParsingTests(unittest.TestCase):
    def test_linux_outputs(self):
        self.assertEqual(poller.parse_ping_replies(LINUX_OK, windows=False), [(1, 1.2), (2, 1.8), (3, 1.5)])
        self.assertEqual(poller.parse_ping_replies(LINUX_PARTIAL, windows=False), [(1, 2.0), (3, 6.0)])   # the duplicate counts once
        self.assertEqual(poller.parse_ping_replies(LINUX_LOST, windows=False), [])

    def test_windows_output(self):
        # Only lines with a TTL are answers; "time<1ms" reads as 1 ms like a single ping always did.
        self.assertEqual(poller.parse_ping_replies(WINDOWS_MIXED, windows=True), [(1, 3.0), (2, 1.0)])

    def test_loss_and_jitter(self):
        full = poller.echo_stats(3, [1.2, 1.8, 1.5])
        self.assertEqual((full["sent"], full["received"], full["loss_pct"]), (3, 3, 0.0))
        self.assertEqual((full["min"], full["avg"], full["max"]), (1.2, 1.5, 1.8))
        self.assertAlmostEqual(full["jitter"], (0.6 + 0.3) / 2, places=3)          # mean absolute difference of consecutive answers
        part = poller.echo_stats(3, [2.0, 6.0])
        self.assertEqual((part["received"], part["loss_pct"], part["jitter"]), (2, 33.33, 4.0))
        one = poller.echo_stats(3, [5.0])
        self.assertIsNone(one["jitter"])                                              # jitter needs two answers
        lost = poller.echo_stats(3, [])
        self.assertEqual((lost["received"], lost["loss_pct"], lost["avg"], lost["jitter"]), (0, 100.0, None, None))

    def test_linux_command_is_gentle_and_parses_partial_loss(self):
        calls = []

        def run(cmd, **kw):
            calls.append((cmd, kw))
            return subprocess.CompletedProcess(cmd, 1, LINUX_PARTIAL, "")      # iputils exits 1 on partial loss
        with mock.patch.object(poller.platform, "system", return_value="Linux"), \
                mock.patch.object(poller.subprocess, "run", side_effect=run), \
                mock.patch.object(poller, "_simulated", return_value=False):
            got = poller.ping_echoes("192.0.2.10", 1.5)
        cmd, kw = calls[0]
        self.assertEqual(cmd, ["ping", "-c", "3", "-i", "0.2", "-w", "1", "192.0.2.10"])
        self.assertFalse(kw["shell"])
        self.assertLessEqual(kw["timeout"], 1.5 + 1.0)                               # never longer than one ping took
        self.assertEqual((got["sent"], got["received"], got["avg"]), (3, 2, 4.0))

    def test_linux_all_lost(self):
        with mock.patch.object(poller.platform, "system", return_value="Linux"), \
                mock.patch.object(poller.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, LINUX_LOST, "")), \
                mock.patch.object(poller, "_simulated", return_value=False):
            got = poller.ping_echoes("192.0.2.10", 2.0)
        self.assertEqual((got["received"], got["loss_pct"]), (0, 100.0))
        self.assertEqual(poller.ping_echoes("-c")["received"], 0)                  # option injection refused

    def test_windows_staggers_single_pings(self):
        starts = []

        def one(ip, timeout):
            starts.append(timeout)
            return (True, 2.0) if len(starts) != 2 else (False, None)
        with mock.patch.object(poller.platform, "system", return_value="Windows"), \
                mock.patch.object(poller, "ping_host", side_effect=one), \
                mock.patch.object(poller, "_simulated", return_value=False):
            got = poller.ping_echoes("192.0.2.10", 2.0)
        self.assertEqual((got["sent"], got["received"]), (3, 2))
        self.assertTrue(all(t <= 2.0 for t in starts))                               # each waits only for what is left


class EchoStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = database.add_device("echo-a", "203.0.113.247", "generic_device", snmp_community="public")

    def test_check_device_records_loss_and_jitter_metrics(self):
        echo = poller.echo_stats(3, [2.0, 4.0])
        with mock.patch.object(poller, "ping_echoes", return_value=echo), mock.patch.object(poller, "_simulated", return_value=False):
            status, ms, got = poller.check_device(database.get_device(self.dev), 1.5)
        self.assertEqual((status, ms, got["received"]), ("online", 3.0, 2))
        latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(self.dev)}
        self.assertEqual((latest["icmp_ping_ms"], latest["icmp_loss_pct"], latest["icmp_jitter_ms"]), (3.0, 33.33, 2.0))
        # A single echo (Poll now) keeps the old shape.
        with mock.patch.object(poller, "ping_host", return_value=(True, 1.0)), mock.patch.object(poller, "_simulated", return_value=False):
            self.assertEqual(poller.ping_device(database.get_device(self.dev)), ("online", 1.0))

    def test_beats_and_hours_keep_echoes(self):
        now = int(time.time())
        hour = now - now % 3600 - 3600
        availability.record(self.dev, True, 3.0, ts=hour + 10, echo=poller.echo_stats(3, [2.0, 4.0, 3.0]))
        availability.record(self.dev, True, 5.0, ts=hour + 70, echo=poller.echo_stats(3, [5.0]))
        availability.record(self.dev, False, None, ts=hour + 130, echo=poller.echo_stats(3, []))
        availability.record(self.dev, True, 1.0, ts=hour + 190)                 # a check without echo counts
        with database.get_connection() as conn:
            h = dict(conn.execute("SELECT * FROM avail_hourly WHERE device_id = ? AND hour = ?;", (self.dev, hour)).fetchone())
            beat = dict(conn.execute("SELECT * FROM avail_beats WHERE device_id = ? AND ts = ?;", (self.dev, hour + 10)).fetchone())
        self.assertEqual((h["checks"], h["echo_sent"], h["echo_recv"], h["jitter_n"]), (4, 9, 4, 1))
        self.assertEqual((h["rtt_min"], h["rtt_max"]), (2.0, 5.0))
        self.assertEqual((beat["echo_sent"], beat["echo_recv"], beat["rtt_min"], beat["rtt_max"], beat["jitter"]), (3, 3, 2.0, 4.0, 1.5))
        tot = availability.echo_totals([self.dev], hour, now)[self.dev]
        self.assertEqual((tot["sent"], tot["received"], tot["loss_pct"], tot["jitter_ms"]), (9, 4, 55.556, 1.5))
        availability.init()                                                          # the columns are added only once

    def test_old_tables_gain_the_columns(self):
        import sqlite3
        import tempfile
        import os
        path = os.path.join(tempfile.mkdtemp(prefix="hm-echo-"), "old.db")
        conn = sqlite3.connect(path)
        conn.executescript("CREATE TABLE avail_beats (device_id INTEGER NOT NULL, ts INTEGER NOT NULL, up INTEGER NOT NULL, ms REAL);"
                           "CREATE TABLE avail_hourly (device_id INTEGER NOT NULL, hour INTEGER NOT NULL, checks INTEGER NOT NULL, "
                           "ups INTEGER NOT NULL, ms_sum REAL NOT NULL DEFAULT 0, ms_count INTEGER NOT NULL DEFAULT 0, ms_max REAL, "
                           "PRIMARY KEY (device_id, hour)); INSERT INTO avail_hourly VALUES (1, 0, 5, 5, 0, 0, NULL);")
        conn.close()

        opened = []

        def connect():
            c = sqlite3.connect(path)
            c.row_factory = sqlite3.Row
            opened.append(c)
            return c
        with mock.patch.object(availability.database, "get_connection", side_effect=connect):
            availability.init()
        for c in opened:
            c.close()
        conn = sqlite3.connect(path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(avail_hourly);")}
        row = conn.execute("SELECT checks, echo_sent FROM avail_hourly;").fetchone()
        conn.close()
        self.assertTrue({"echo_sent", "echo_recv", "jitter_sum", "jitter_n", "rtt_min", "rtt_max"} <= cols)
        self.assertEqual(row, (5, 0))                                                # old rows kept, no echoes


def custom(*blocks):
    return {"template": "custom", "title": "Mine", "period": "7d", "blocks": list(blocks)}


class LossReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.new = database.add_device("loss-new", "203.0.113.248", "generic_device", snmp_community="public")
        cls.old = database.add_device("loss-old", "203.0.113.249", "generic_device", snmp_community="public")
        now = int(time.time())
        for i in range(40):
            t = now - 3 * 86400 + i * 600
            availability.record(cls.new, True, 3.0, ts=t, echo=poller.echo_stats(3, [2.0, 4.0] if i % 4 == 0 else [2.0, 4.0, 3.0]))
            availability.record(cls.old, i % 10 != 0, 5.0 if i % 10 else None, ts=t)          # one ping per check
            database.record_metrics(cls.new, {"icmp_ping_ms": 3.0 + i % 3}, timestamp=t)
            database.record_metrics(cls.old, {"icmp_ping_ms": 5.0 + i % 4}, timestamp=t)

    def run_spec(self, spec):
        status, body, _ = request("POST", "/api/reports/run", {"spec": spec})
        self.assertEqual(status, 200, body)
        return body

    def scope(self, *ids):
        return {"kind": "devices", "devices": list(ids)}

    def test_true_loss_and_jitter_where_measured(self):
        r = self.run_spec(custom({"type": "kpi_row", "tiles": [{"metric": "failed"}, {"metric": "rtt_sd"}], "scope": self.scope(self.new)},
                                 {"type": "chart", "source": "failed", "view": "per", "chart": "lollipop", "split": "device", "scope": self.scope(self.new)},
                                 {"type": "chart", "source": "ping", "view": "stddev", "chart": "bar", "split": "device", "scope": self.scope(self.new)},
                                 {"type": "table", "entity": "device", "columns": ["name", "failed", "rtt_sd"], "scope": self.scope(self.new)}))
        tiles, lolli, jit, table = r["blocks"]
        loss, jitter = tiles["tiles"]
        expected = round(100.0 * 10 / 120, 1)                                       # 10 of 120 echoes lost
        self.assertEqual(loss["label"], "Packet loss")
        self.assertIn(f"{expected}", loss["value"])
        self.assertEqual(jitter["label"], "Jitter")
        self.assertIn("Packet loss per device", lolli["chart"]["title"])
        self.assertNotIn("Not packet loss", lolli["chart"]["note"])
        self.assertEqual(jit["chart"]["title"], "Jitter")
        # Three answers (2, 4, 3) give 1.5 and two answers (2, 4) give 2: 30 and 10 checks average to 1.625.
        self.assertAlmostEqual(jit["chart"]["bars"][0][1], 1.62, places=2)
        self.assertEqual([c["label"] for c in table["columns"]], ["Device", "Packet loss", "Jitter"])

    def test_stand_ins_stay_labelled_before_collection(self):
        r = self.run_spec(custom({"type": "kpi_row", "tiles": [{"metric": "failed"}, {"metric": "rtt_sd"}], "scope": self.scope(self.old)},
                                 {"type": "chart", "source": "failed", "view": "per", "chart": "lollipop", "split": "device", "scope": self.scope(self.old)},
                                 {"type": "table", "entity": "device", "columns": ["name", "failed", "rtt_sd"], "scope": self.scope(self.old)}))
        tiles, lolli, table = r["blocks"]
        self.assertEqual([t["label"] for t in tiles["tiles"]], ["Failed checks", "RTT standard deviation"])
        self.assertIn("Failed checks per device", lolli["chart"]["title"])
        self.assertEqual([c["label"] for c in table["columns"]], ["Device", "Failed checks", "RTT std dev"])

    def test_mixed_and_the_latency_template(self):
        r = self.run_spec(custom({"type": "table", "entity": "device", "columns": ["name", "failed"], "scope": self.scope(self.new, self.old)},
                                 {"type": "chart", "source": "failed", "view": "time", "chart": "columns", "scope": self.scope(self.new)}))
        self.assertEqual(r["blocks"][0]["columns"][1]["label"], "Packet loss or failed checks")
        self.assertEqual(r["blocks"][1]["chart"]["series"][0]["name"], "Packet loss")
        status, body, _ = request("POST", "/api/reports/run", {"spec": {"template": "latency_review", "period": "7d"}})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["title"], "Latency, packet loss and jitter")


class LldpTests(unittest.TestCase):
    # Switch A (ifIndex 2 = "Port 2") sees B on its port 2; B (ifIndex 8 = "Port 8") sees A on port 8.
    REMOTE_A = {
        "4.0.2.1": 4, "5.0.2.1": "aa:00:00:00:00:0b", "6.0.2.1": 5, "7.0.2.1": "Port 8", "8.0.2.1": "", "9.0.2.1": "lldp-b.lan",
        "4.0.3.1": 4, "5.0.3.1": "de:ad:be:ef:00:01", "6.0.3.1": 3, "7.0.3.1": "de:ad:be:ef:00:01", "9.0.3.1": "phone",
    }
    LOCAL_A = {"2.2": 5, "3.2": "Port 2", "4.2": "Port 2", "2.3": 5, "3.3": "Port 3", "4.3": "Port 3"}
    MGMT_A = {"0.2.1.1.4.192.0.2.62": 2}

    def test_parse(self):
        rows = poller.parse_lldp(self.REMOTE_A, self.LOCAL_A, self.MGMT_A, {"2": {"if_index": 2, "label": "Port 2", "name": "Port 2"}})
        self.assertEqual(set(rows), {"2.1", "3.1"})
        b = rows["2.1"]
        self.assertEqual((b["if_index"], b["local_port"], b["sys_name"], b["chassis_mac"], b["mgmt_ip"], b["remote_port"]),
                         (2, "Port 2", "lldp-b.lan", "aa:00:00:00:00:0b", "192.0.2.62", "Port 8"))
        self.assertEqual(rows["3.1"]["local_port"], "Port 3")                         # no such interface: the LLDP name
        self.assertEqual(poller.parse_lldp({}, {}, {}, {}), {})

    def test_collector_walks_and_stores(self):
        start_api_server()
        dev = database.add_device("lldp-walk", "192.0.2.69", "generic_device", snmp_community="public")
        walks = {poller.LLDP_REM_ENTRY: self.REMOTE_A, poller.LLDP_LOC_PORT_ENTRY: self.LOCAL_A, poller.LLDP_REM_MAN_ADDR_IF: self.MGMT_A}
        tc = poller.TableCollector(database.get_device(dev), {"tables": []}, 1.0, 0)
        with mock.patch.object(tc, "walk", side_effect=lambda oid: walks.get(oid, {})):
            self.assertTrue(tc.collect_lldp())
        self.assertEqual(database.get_device_table(dev, "lldp")["2.1"]["sys_name"], "lldp-b.lan")
        with mock.patch.object(tc, "walk", return_value={}):
            self.assertFalse(tc.collect_lldp())                                         # gone quiet: the old neighbours go
        self.assertEqual(database.get_device_table(dev, "lldp"), {})

    def test_links_and_merge(self):
        devs = [{"id": 1, "hostname": "a", "ip_address": "192.0.2.61", "inventory": {"sys_name": "lldp-a"}},
                {"id": 2, "hostname": "b", "ip_address": "192.0.2.62", "inventory": {}},
                {"id": 3, "hostname": "nas", "ip_address": "192.0.2.63", "inventory": {}}]
        lldp = {1: {"2.1": {"local_port": "Port 2", "sys_name": "", "chassis_mac": "", "mgmt_ip": "192.0.2.62", "port_id": "8", "remote_port": "8"}},
                2: {"8.1": {"local_port": "Port 8", "sys_name": "LLDP-A", "chassis_mac": "", "mgmt_ip": "", "port_id": "x"}}}
        links = topology.lldp_links(devs, lldp, {}, {2: {8: "Port 8"}})
        self.assertEqual(links, [{"a": "d:1", "b": "d:2", "a_port": "Port 2", "b_port": "Port 8", "source": "lldp"}])
        # Forwarding tables guessed the NAS straight off A's port 2 and A to B with no ports.
        guessed = {("d:1", "d:3"): {"a": "d:1", "b": "d:3", "a_port": "Port 2", "b_port": None, "source": "auto", "hidden": False},
                   ("d:1", "d:2"): {"a": "d:1", "b": "d:2", "a_port": None, "b_port": None, "source": "auto", "hidden": True}}
        topology.merge_lldp(guessed, links)
        self.assertEqual(guessed[("d:1", "d:2")]["source"], "lldp")
        self.assertTrue(guessed[("d:1", "d:2")]["hidden"])                              # hiding a link still holds
        self.assertNotIn(("d:1", "d:3"), guessed)
        self.assertEqual(guessed[("d:2", "d:3")]["source"], "auto")                     # the NAS sits behind B

    def test_map_and_interface_table(self):
        start_api_server()
        a = database.add_device("lldp-a", "192.0.2.64", "generic_device", snmp_community="public")
        b = database.add_device("lldp-b", "192.0.2.65", "generic_device", snmp_community="public")
        now = int(time.time())
        database.replace_device_table(a, "interfaces", {"2": {"if_index": 2, "label": "Port 2", "kind": "port", "oper": 1}}, now)
        database.replace_device_table(b, "interfaces", {"8": {"if_index": 8, "label": "Port 8", "kind": "port", "oper": 1}}, now)
        database.replace_device_table(a, "lldp", {"2.1": {"local_port_num": 2, "if_index": 2, "local_port": "Port 2", "sys_name": "lldp-b",
                                                          "chassis_mac": "", "mgmt_ip": "", "port_id": "Port 8", "port_desc": "",
                                                          "remote_port": "Port 8"}}, now)
        view = request("GET", "/api/map")[1]
        link = next(l for l in view["links"] if {l["a"], l["b"]} == {f"d:{a}", f"d:{b}"})
        ports = {link["a"]: link["a_port"], link["b"]: link["b_port"]}
        self.assertEqual((link["source"], ports[f"d:{a}"], ports[f"d:{b}"]), ("lldp", "Port 2", "Port 8"))
        rows = request("GET", f"/api/devices/{a}/ports")[1]["ports"]
        self.assertEqual(rows[0]["neighbour"], "to lldp-b Port 8")
        self.assertEqual(server.lldp_neighbours(b), {})


class CapacityOidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = database.add_device("cap-router", "203.0.113.250", "generic_device", snmp_community="public")

    def base(self, **kw):
        return dict({"scope": "device", "target": str(self.dev), "oid": "1.3.6.1.4.1.99.7.1.0", "label": "Leases", "kind": "gauge"}, **kw)

    def test_validation(self):
        parse = lambda **kw: customoids.parse(self.base(**kw), [], [self.dev])
        ok = parse(cap_resource="DHCP scope", cap_limit="254")
        self.assertEqual((ok["cap_resource"], ok["cap_limit"], ok["cap_warn"], ok["cap_crit"]), ("DHCP scope", 254.0, 75.0, 90.0))
        self.assertEqual(parse(cap_resource="Sessions", cap_limit_oid=".1.3.6.1.4.1.99.7.2.0")["cap_limit_oid"], "1.3.6.1.4.1.99.7.2.0")
        self.assertIsNone(parse()["cap_resource"])
        for kw, msg in ((dict(cap_resource="DHCP"), "number or as the OID"),
                        (dict(cap_resource="DHCP", cap_limit=5, cap_limit_oid="1.3.6.1.4.1.9"), "not both"),
                        (dict(cap_resource="DHCP", cap_limit=0), "more than 0"),
                        (dict(cap_resource="DHCP", cap_limit="lots"), "number"),
                        (dict(cap_resource="DHCP", cap_limit_oid="leases"), "OID"),
                        (dict(cap_resource="DHCP", cap_limit_oid="1.3.6.1.4.1.99.7.1.0"), "differ"),
                        (dict(cap_resource="DHCP", cap_limit=10, cap_warn=95, cap_crit=90), "below"),
                        (dict(cap_resource="DHCP", cap_limit=10, cap_crit=150), "between"),
                        (dict(cap_limit=10), "Name the resource"),
                        (dict(cap_resource="DHCP", cap_limit=10, kind="counter"), "gauge")):
            with self.assertRaises(ValueError) as ctx:
                parse(**kw)
            self.assertIn(msg, str(ctx.exception), kw)
        status, body, _ = request("POST", "/api/custom-oids", self.base(cap_resource="DHCP", cap_limit=-1))
        self.assertEqual(status, 400, body)

    def test_used_percent_forecast_and_reports(self):
        status, body, _ = request("POST", "/api/custom-oids", self.base(cap_resource="DHCP scope", cap_limit=200))
        self.assertEqual(status, 201, body)
        fixed = body["id"]
        status, body, _ = request("POST", "/api/custom-oids", self.base(oid="1.3.6.1.4.1.99.8.1.0", label="Sessions", scale=1,
                                                                       cap_resource="Firewall sessions", cap_limit_oid="1.3.6.1.4.1.99.8.2.0",
                                                                       cap_warn=60, cap_crit=80))
        self.assertEqual(status, 201, body)
        by_oid = body["id"]
        answers = {"1.3.6.1.4.1.99.7.1.0": 150, "1.3.6.1.4.1.99.8.1.0": 700, "1.3.6.1.4.1.99.8.2.0": 1000}
        with mock.patch.object(customoids.poller, "snmp_get_many", return_value=answers) as get:
            got = customoids.poll(database.get_device(self.dev))
        self.assertIn("1.3.6.1.4.1.99.8.2.0", get.call_args[0][1])                    # the limit OID is read in the same request
        self.assertEqual((got[f"custom.{fixed}.used_pct"], got[f"custom.{by_oid}.used_pct"]), (75.0, 70.0))
        self.assertEqual(customoids.metric_info(database.get_device(self.dev))[f"custom.{fixed}.used_pct"]["label"], "DHCP scope used (%)")
        # Hourly history rising a point a day: the forecast sees it like a filling disk.
        now = time.time()
        with database.get_connection() as conn:
            for h in range(72):
                t = int(now - (72 - h) * 3600)
                t -= t % 3600
                conn.execute("INSERT OR REPLACE INTO metrics_hourly (device_id, metric_key, hour, avg, min, max, samples) VALUES (?, ?, ?, ?, ?, ?, 1);",
                             (self.dev, f"custom.{fixed}.used_pct", t, 70 + h / 24, 70 + h / 24, 70 + h / 24))
            conn.commit()
        rows = forecast.compute(now).get(self.dev, [])
        row = next(r for r in rows if r["key"] == f"custom.{fixed}.used_pct")
        self.assertEqual(row["label"], "DHCP scope (Leases)")
        self.assertAlmostEqual(row["per_day"], 1.0, places=1)
        # Capacity bars and the resources table of the reports.
        scope = {"kind": "devices", "devices": [self.dev]}
        status, body, _ = request("POST", "/api/reports/run", {"spec": custom(
            {"type": "chart", "source": "capacity", "view": "now", "chart": "capacity", "scope": scope},
            {"type": "table", "entity": "resource", "scope": scope})})
        self.assertEqual(status, 200, body)
        bars = {b[0]: b for b in body["blocks"][0]["chart"]["bars"]}
        self.assertEqual(bars["cap-router Firewall sessions"][1:], [70.0, "warn"])     # its own levels: amber from 60
        self.assertIn("cap-router DHCP scope", bars)
        res = body["blocks"][1]
        names = [r[res["columns"].index(next(c for c in res["columns"] if c["key"] == "resource"))] for r in res["rows"]]
        self.assertIn("Firewall sessions", names)
        self.assertEqual(request("DELETE", f"/api/custom-oids/{fixed}")[0], 200)
        latest = {m["metric_key"] for m in database.get_latest_metrics(self.dev)}
        self.assertNotIn(f"custom.{fixed}.used_pct", latest)


if __name__ == "__main__":
    unittest.main()
