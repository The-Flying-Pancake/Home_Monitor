"""Toward 1.0: maintenance windows, root-cause alerts, forecasts, certificate expiry, the
inventory and new devices, Pi-hole, UniFi and the digest. Pi-hole, UniFi, DNS and TLS run
against small local stand-ins, so nothing here reaches the real network."""

import datetime
import http.server
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import availability
import database
import digest
import forecast
import inventory
import maintenance
import pihole
import poller
import server
import tls
import unifi


def serve(handler_cls):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")


class Pihole6(Quiet):
    logins = 0

    def do_POST(self):
        if self.path == "/api/auth":
            ok = self.body().get("password") == "app-pass"
            Pihole6.logins += ok
            return self.reply(200 if ok else 401, {"session": {"valid": ok, "sid": "S1", "validity": 1800}})
        if self.path == "/api/dns/blocking" and self.headers.get("X-FTL-SID") == "S1":
            Pihole6.blocking_calls.append(self.body())
            return self.reply(200, {"blocking": "disabled", "timer": 300})
        self.body()
        self.reply(404, {})

    blocking_calls = []

    def do_GET(self):
        if self.headers.get("X-FTL-SID") != "S1":
            return self.reply(401, {"error": "unauthorized"})
        if self.path == "/api/stats/summary":
            return self.reply(200, {"queries": {"total": 1000, "blocked": 150, "percent_blocked": 15.0},
                                    "clients": {"active": 9}, "gravity": {"domains_being_blocked": 120000,
                                                                          "last_update": time.time() - 20 * 86400}})
        if self.path == "/api/dns/blocking":
            return self.reply(200, {"blocking": "disabled"})
        if self.path == "/api/stats/upstreams":
            return self.reply(200, {"upstreams": [{"ip": "1.1.1.1", "name": "one.one.one.one", "port": 53, "count": 700,
                                                   "statistics": {"response": 0.012}}]})
        if self.path.startswith("/api/stats/top_domains"):
            return self.reply(200, {"domains": [{"domain": "ads.example", "count": 40}]})
        self.reply(404, {})


class Pihole5(Quiet):
    def do_POST(self):
        self.body()
        self.reply(404, {})

    def do_GET(self):
        if "auth=tok5" not in self.path:
            return self.reply(200, [])
        if "summaryRaw" in self.path:
            return self.reply(200, {"dns_queries_today": 500, "ads_blocked_today": 50, "ads_percentage_today": 10.0,
                                    "unique_clients": 4, "domains_being_blocked": 9000, "status": "enabled",
                                    "gravity_last_updated": {"absolute": time.time() - 86400}})
        if "getForwardDestinations" in self.path:
            return self.reply(200, {"forward_destinations": {"dns.google|8.8.8.8": 60.0}})
        if "topItems" in self.path:
            return self.reply(200, {"top_ads": {"tracker.example": 12}})
        self.reply(404, {})


class Unifi(Quiet):
    def do_POST(self):
        if self.path == "/api/auth/login":
            b = self.body()
            if b.get("username") == "monitor" and b.get("password") == "pw":
                return self.reply(200, {}, {"Set-Cookie": "TOKEN=abc; Path=/; HttpOnly", "X-CSRF-Token": "csrf1"})
            return self.reply(401, {})
        if self.path == "/proxy/network/api/s/default/cmd/stamgr" and "TOKEN=abc" in (self.headers.get("Cookie") or "") \
                and self.headers.get("X-CSRF-Token") == "csrf1":
            b = self.body()
            Unifi.kicked.append(b.get("mac"))
            return self.reply(200, {"meta": {"rc": "ok"}, "data": []})
        self.body()
        self.reply(404, {})

    kicked = []

    def do_GET(self):
        if "TOKEN=abc" not in (self.headers.get("Cookie") or ""):
            return self.reply(401, {})
        if self.path == "/proxy/network/api/self/sites":
            return self.reply(200, {"data": [{"name": "default", "desc": "Home"}]})
        if self.path.startswith("/proxy/network/api/s/") and not self.path.startswith("/proxy/network/api/s/default/"):
            return self.reply(401, {})                 # what UniFi OS answers for a site it does not have
        if self.path == "/proxy/network/api/s/default/stat/device":
            return self.reply(200, {"data": [{"mac": "AA:BB:CC:00:00:01", "ip": "198.51.100.210", "name": "ap-living-room", "type": "uap"},
                                             {"mac": "aa:bb:cc:00:00:09", "ip": "198.51.100.211", "name": "Switch", "type": "usw"}]})
        if self.path == "/proxy/network/api/s/default/stat/sta":
            return self.reply(200, {"data": [
                {"mac": "02:11:22:33:44:55", "ip": "198.51.100.50", "hostname": "phone", "oui": "", "ap_mac": "aa:bb:cc:00:00:01",
                 "radio": "na", "channel": 36, "signal": -82, "tx_rate": 144000, "rx_rate": 86000, "tx_retries": 900,
                 "satisfaction": 40, "uptime": 3600, "essid": "Home"},
                {"mac": "10:22:33:44:55:66", "ip": "198.51.100.51", "name": "TV", "oui": "Samsung", "ap_mac": "aa:bb:cc:00:00:01",
                 "radio": "ng", "channel": 6, "signal": -55, "satisfaction": 98},
                {"mac": "10:22:33:44:55:77", "ip": "198.51.100.52", "hostname": "nas", "oui": "QNAP", "is_wired": True,
                 "sw_mac": "aa:bb:cc:00:00:09", "sw_port": 4},
            ]})
        self.reply(404, {})


REAL_SENDTO = socket.socket.sendto


class UnifiStrict(Unifi):
    """UniFi OS that sends no CSRF header at login, only the token inside the JWT cookie, and refuses
    any request without it."""
    TOKEN = "e30." + __import__("base64").urlsafe_b64encode(b'{"csrfToken":"from-jwt"}').decode().rstrip("=") + ".sig"

    def do_POST(self):
        if self.path == "/api/auth/login":
            self.body()
            return self.reply(200, {}, {"Set-Cookie": f"TOKEN={self.TOKEN}; Path=/; HttpOnly"})
        self.body()
        self.reply(404, {})

    def do_GET(self):
        if f"TOKEN={self.TOKEN}" not in (self.headers.get("Cookie") or "") or self.headers.get("X-CSRF-Token") != "from-jwt":
            return self.reply(401, {})
        self.headers.replace_header("Cookie", "TOKEN=abc") if self.headers.get("Cookie") else None
        return Unifi.do_GET(self)


def fake_dns(answer_rcode=0):
    """A UDP server on 127.0.0.1 that answers every query with the given rcode."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def run():
        while True:
            try:
                data, addr = sock.recvfrom(512)
            except OSError:
                return
            reply = bytearray(data)
            reply[2] |= 0x80
            reply[3] = (reply[3] & 0xF0) | answer_rcode
            REAL_SENDTO(sock, bytes(reply), addr)     # not the redirected one the test installs
    threading.Thread(target=run, daemon=True).start()
    return sock, sock.getsockname()[1]


class MaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("maint-dev", "198.51.100.201", profile="ping_only")

    def setUp(self):
        database.set_internal_setting(maintenance.KEY, "[]")

    def test_windows_and_scopes(self):
        now = time.time()
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.add("device", "", now, now + 60, "", "t", now)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.add("all", "", now, now - 1, "", "t", now)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.add("all", "", now, now + 15 * 86400, "", "t", now)
        w = maintenance.add("tag", "Rack", now - 10, now + 600, "patching", "t", now)
        dev = {"id": 5, "tags": ["rack", "x"], "group": "nas"}
        self.assertEqual(maintenance.active_for(dev, now)["id"], w["id"])                 # tag match ignores case
        self.assertIsNone(maintenance.active_for({"id": 6, "tags": []}, now))
        later = maintenance.add("group", "nas", now + 3600, now + 7200, "", "t", now)
        self.assertEqual([x["state"] for x in maintenance.windows(now)], ["scheduled", "active"])
        self.assertIsNone(maintenance.active_for({"id": 7, "group": "nas"}, now))
        self.assertEqual(maintenance.active_for({"id": 7, "group": "nas"}, now + 4000)["id"], later["id"])
        maintenance.end(later["id"], now)                                                   # a scheduled one is removed
        maintenance.end(w["id"], now)
        self.assertEqual([x["state"] for x in maintenance.windows(now + 1)], ["ended"])

    def test_api_and_device_page(self):
        status, body, _ = request("POST", "/api/maintenance", {"scope": "device", "target": str(self.dev), "minutes": 30, "note": "swap"})
        self.assertEqual(status, 201, body)
        self.assertEqual(request("GET", f"/api/devices/{self.dev}")[1]["maintenance"]["note"], "swap")
        self.assertEqual(request("POST", "/api/maintenance", {"scope": "nope", "minutes": 30})[0], 400)
        wid = body["window"]["id"]
        self.assertEqual(request("POST", f"/api/maintenance/{wid}/end")[0], 200)
        self.assertIsNone(request("GET", f"/api/devices/{self.dev}")[1]["maintenance"])
        self.assertEqual(request("POST", "/api/maintenance/9999/end")[0], 404)

    def test_quiet_while_in_maintenance(self):
        with database.get_connection() as c:
            c.execute("DELETE FROM problems_active WHERE device_id = ?", (self.dev,))
            c.execute("UPDATE devices SET status = 'offline' WHERE id = ?", (self.dev,))
            c.commit()
        now = time.time()
        windows = json.dumps([{"id": 1, "scope": "device", "target": str(self.dev), "start": now - 60, "end": now + 600, "note": "", "by": "t"}])
        base = {"telegram_enabled": "on", "notify_min_severity": "warning", "notify_repeat_hours": "0", "notify_new_devices": "on",
                maintenance.KEY: windows}
        sent = []
        with database.get_connection() as c:
            before = {(r[0], r[1]) for r in c.execute("SELECT device_id, problem_key FROM problems_active")}
            last_event = c.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        try:
            with mock.patch.object(server.NOTIFIER, "event", side_effect=lambda kind, values, **kw: sent.append(values.get("device"))), \
                    mock.patch.object(database, "get_all_settings", return_value=base):
                server.PollScheduler.__new__(server.PollScheduler)._problem_job(0)
            self.assertNotIn("maint-dev", sent)
            self.assertIn((self.dev, "unreachable"), server.HELD_BACK)
            ev = [e["message"] for e in database.list_events(self.dev, limit=5)]
            self.assertTrue(any("during maintenance" in m for m in ev), ev)
        finally:
            with database.get_connection() as c:
                c.execute("UPDATE devices SET status = 'unknown' WHERE id = ?", (self.dev,))
                # The job evaluated every device: leave the problem table as it was for the other tests.
                for dev_id, key in c.execute("SELECT device_id, problem_key FROM problems_active").fetchall():
                    if (dev_id, key) not in before:
                        c.execute("DELETE FROM problems_active WHERE device_id = ? AND problem_key = ?", (dev_id, key))
                # And its events (other tests count what is in the bell).
                c.execute("DELETE FROM events WHERE id > ?", (last_event,))
                c.commit()
            server.HELD_BACK.clear()

    def test_planned_downtime(self):
        dev = add_device("maint-avail", "198.51.100.202", profile="ping_only")
        now = int(time.time())
        availability.record(dev, True, 1.0, ts=now - 120)
        availability.record(dev, False, None, ts=now - 60, planned=True)
        s = availability.summary([dev], now=now)[dev]
        self.assertEqual(s["uptime"]["24h"], 100.0)                 # the planned check does not count
        self.assertTrue(s["beats"][-1]["planned"])
        self.assertIsNone(s["down_since"])                           # and opened no incident


class RootCauseTests(unittest.TestCase):
    def test_behind_the_device_that_failed(self):
        devices = [{"id": i, "hostname": n} for i, n in [(1, "gw"), (2, "switch"), (3, "nas"), (4, "pc")]]
        parent = {"d:1": None, "d:2": "d:1", "o:9": "d:2", "d:3": "o:9", "d:4": "d:2"}
        problems = [{"device_id": d, "key": "unreachable", "message": "Device unreachable"} for d in (2, 3, 4)]
        out = server.root_cause(problems, devices, parent)
        by = {p["device_id"]: p["message"] for p in out}
        self.assertEqual(server.BEHIND, {3: 2, 4: 2})                # an object (modem, socket) in between is passed over
        self.assertIn("Also unreachable behind it: nas, pc", by[2])
        self.assertIn("behind switch", by[3])
        # Only one down: nothing to group.
        server.root_cause([{"device_id": 3, "key": "unreachable", "message": "x"}], devices, parent)
        self.assertEqual(server.BEHIND, {})


class ForecastTests(unittest.TestCase):
    def test_fit(self):
        hour = 3600
        rising = [[i * hour, 50 + i * 0.25 / 24 * 24] for i in range(72)]           # 0.25 points an hour = 6 a day
        f = forecast.fit(rising)
        self.assertAlmostEqual(f["per_day"], 6.0, places=2)
        self.assertAlmostEqual(f["days"], (100 - rising[-1][1]) / 6.0, delta=0.2)
        self.assertIsNone(forecast.fit(rising[:10]))                                  # too little history
        self.assertIsNone(forecast.fit([[i * 60, 50] for i in range(100)]))           # spread over too short a time
        self.assertIsNone(forecast.fit([[i * hour, 60.0] for i in range(72)])["days"])  # flat: never full

    def test_compute_and_problem(self):
        start_api_server()
        dev = add_device("fc-nas", "198.51.100.203", profile="generic_device")
        now = int(time.time())
        base = now - now % 3600 - 96 * 3600
        with database.get_connection() as c:
            c.executemany("INSERT OR REPLACE INTO metrics_hourly (device_id, metric_key, hour, avg, min, max, samples) VALUES (?, ?, ?, ?, ?, ?, 1);",
                          [(dev, "vol.1.used_pct", base + i * 3600, 80 + i * 0.1, 80, 90) for i in range(96)])
            c.commit()
        database.replace_device_table(dev, "volumes", {"1": {"descr": "DataVol1", "used_pct": 89.5}}, now)
        rows = forecast.compute(now)[dev]
        self.assertEqual(rows[0]["label"], "Volume DataVol1")
        self.assertLess(rows[0]["days"], 14)
        rule = server.alert_policy().for_device(database.get_device(dev))
        probs = server.forecast_problems(database.get_device(dev), rule, rows)
        self.assertEqual(probs[0]["key"], "forecast_full:vol.1.used_pct")
        self.assertIn("full in about", probs[0]["message"])
        # Growing fast but only 57% full: no warning (it starts at 80%).
        low = [dict(rows[0], now=57.0)]
        self.assertEqual(server.forecast_problems(database.get_device(dev), rule, low), [])


class CertificateTests(unittest.TestCase):
    def test_days_left_from_the_handshake(self):
        cert, key = tls.make_self_signed(["127.0.0.1"])
        ctx = tls.build_context(cert, key)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def accept():
            conn, _ = srv.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass
        threading.Thread(target=accept, daemon=True).start()
        days = poller.cert_days_left(f"https://127.0.0.1:{srv.getsockname()[1]}/", 3)
        srv.close()
        self.assertAlmostEqual(days, tls.SELF_SIGNED_DAYS, delta=1)
        self.assertIsNone(poller.cert_days_left("http://127.0.0.1/"))

    def test_problem(self):
        dev = {"id": 1, "hostname": "nas web", "status": "online", "service_port": 443, "service_kind": "http",
               "service_url": "https://nas.lan/", "profile_id": "service_check"}
        out = server.device_problems(dev, {"service_up": 1, "tls_days_left": 9.0}, {})
        self.assertEqual([p["rule"] for p in out], ["cert_expiry"])
        self.assertIn("runs out in 9 days", out[0]["message"])
        self.assertEqual(server.device_problems(dev, {"service_up": 1, "tls_days_left": 90.0}, {}), [])


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        with database.get_connection() as c:
            c.execute("DELETE FROM inventory;")
            c.commit()
        database.delete_settings([inventory.STARTED_KEY])

    def test_gather(self):
        devices = [{"id": 1, "hostname": "core", "ip_address": "198.51.100.1"}, {"id": 2, "hostname": "edge", "ip_address": "198.51.100.2"}]
        fdb = [{"device_id": 1, "row_key": "aa:aa:aa:aa:aa:01", "if_index": 24}, {"device_id": 1, "row_key": "aa:aa:aa:aa:aa:02", "if_index": 24},
               {"device_id": 2, "row_key": "aa:aa:aa:aa:aa:01", "if_index": 3},
               {"device_id": 1, "row_key": "01:00:5e:00:00:01", "if_index": 5}]                 # multicast: ignored
        arp = [{"row_key": "198.51.100.40", "mac": "AA-AA-AA-AA-AA-01"}, {"row_key": "198.51.100.2", "mac": "aa:aa:aa:aa:aa:02"}]
        seen = inventory.gather(devices, fdb, arp, [], {2: {3: "Port 3"}, 1: {24: "Port 24"}})
        self.assertEqual(set(seen), {"aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"})
        self.assertEqual(seen["aa:aa:aa:aa:aa:01"]["where_seen"], "edge port Port 3")            # the edge port, not the uplink
        self.assertEqual(seen["aa:aa:aa:aa:aa:01"]["ip"], "198.51.100.40")
        self.assertEqual(seen["aa:aa:aa:aa:aa:02"]["device_id"], 2)
        wifi = [{"mac": "02:11:22:33:44:55", "ip": "198.51.100.50", "name": "phone", "vendor": "", "ap": "ap-living-room", "signal": -61}]
        seen = inventory.gather(devices, [], [], [], {}, wifi)
        self.assertEqual(seen["02:11:22:33:44:55"]["where_seen"], "ap-living-room (Wi-Fi, -61 dBm)")
        self.assertTrue(inventory.is_private("02:11:22:33:44:55"))
        self.assertIn("private address", inventory.describe(seen["02:11:22:33:44:55"]))

    def test_a_monitored_device_is_one_row(self):
        # An access point with an address per radio and network: one row, under the address its IP uses.
        ap = add_device("inv-ap", "198.51.100.8", profile="generic_device")
        devices = [{"id": ap, "hostname": "inv-ap", "ip_address": "198.51.100.8"}]
        ifs = [{"device_id": ap, "mac": m} for m in ("aa:aa:aa:00:00:08", "7a:aa:aa:00:00:01", "7a:aa:aa:00:00:02", "7a:aa:aa:00:00:03")]
        fdb = [{"device_id": 1, "row_key": m, "if_index": 4} for m in ("aa:aa:aa:00:00:08", "7a:aa:aa:00:00:01", "7a:aa:aa:00:00:02")]
        arp = [{"row_key": "198.51.100.8", "mac": "aa:aa:aa:00:00:08"}]
        seen = inventory.gather(devices, fdb, arp, ifs, {})
        self.assertEqual(list(seen), ["aa:aa:aa:00:00:08"])
        self.assertEqual(seen["aa:aa:aa:00:00:08"]["device_id"], ap)
        extra = inventory.extra_macs(devices, arp, ifs)
        self.assertEqual(extra, {"7a:aa:aa:00:00:01", "7a:aa:aa:00:00:02", "7a:aa:aa:00:00:03"})
        # Without an ARP entry the lowest of its own addresses stands for it.
        self.assertEqual(inventory.extra_macs(devices, [], ifs), set(m["mac"] for m in ifs) - {"7a:aa:aa:00:00:01"})
        # Old rows of the folded addresses go, unless someone wrote on them.
        now = time.time()
        with database.get_connection() as c:
            for m, name in (("7a:aa:aa:00:00:01", ""), ("7a:aa:aa:00:00:02", "kept: I named it")):
                c.execute("INSERT INTO inventory (mac, name, first_seen, last_seen, known) VALUES (?, ?, ?, ?, 1);", (m, name, now, now))
            c.commit()
        inventory.update(seen, lambda s: None, now, drop=extra)
        left = {r["mac"] for r in request("GET", "/api/inventory")[1]["rows"]}
        self.assertNotIn("7a:aa:aa:00:00:01", left)
        self.assertIn("7a:aa:aa:00:00:02", left)

    def test_learning_then_new(self):
        told = []
        one = {"aa:aa:aa:aa:aa:10": {"mac": "aa:aa:aa:aa:aa:10", "ip": "198.51.100.60", "device_id": None, "where_seen": "", "via": "",
                                     "seen_name": "", "vendor": ""}}
        now = time.time()
        self.assertEqual(inventory.update(one, told.append, now), [])                      # learning: quietly known
        later = now + inventory.LEARN_SECONDS + 60
        two = dict(one, **{"aa:aa:aa:aa:aa:11": dict(one["aa:aa:aa:aa:aa:10"], mac="aa:aa:aa:aa:aa:11", ip="198.51.100.61")})
        new = inventory.update(two, told.append, later)
        self.assertEqual([n["mac"] for n in new], ["aa:aa:aa:aa:aa:11"])
        self.assertEqual(len(told), 1)
        rows = {r["mac"]: r for r in request("GET", "/api/inventory")[1]["rows"]}
        self.assertFalse(rows["aa:aa:aa:aa:aa:11"]["known"])
        self.assertTrue(rows["aa:aa:aa:aa:aa:10"]["known"])
        # Edit, refuse a bad date, mark known, forget.
        self.assertEqual(request("PUT", "/api/inventory/aa:aa:aa:aa:aa:11", {"name": "Printer", "purchased": "2024-13"})[0], 400)
        self.assertEqual(request("PUT", "/api/inventory/aa:aa:aa:aa:aa:11", {"name": "Printer", "location": "Study", "purchased": "2024-03-01"})[0], 200)
        self.assertEqual(request("POST", "/api/inventory/known")[1]["changed"], 1)
        self.assertEqual(request("DELETE", "/api/inventory/aa:aa:aa:aa:aa:11")[0], 200)
        self.assertEqual(request("DELETE", "/api/inventory/aa:aa:aa:aa:aa:11")[0], 404)
        # Many at once: a few messages, then one summary.
        many = {f"aa:aa:aa:aa:ab:{i:02x}": dict(one["aa:aa:aa:aa:aa:10"], mac=f"aa:aa:aa:aa:ab:{i:02x}") for i in range(12)}
        told.clear()
        inventory.update(many, told.append, later + 300)
        self.assertEqual(len(told), inventory.MAX_MESSAGES_PER_RUN + 1)
        self.assertEqual(told[-1]["summary"], 12 - inventory.MAX_MESSAGES_PER_RUN)

    def test_quiet_networks_ssid_and_added_by_hand(self):
        database.delete_settings([inventory.QUIET_SSIDS_KEY])
        now = time.time()
        inventory.update({}, lambda s: None, now - inventory.LEARN_SECONDS - 60)           # learning is over
        base = {"ip": "", "device_id": None, "seen_name": "", "vendor": ""}
        wifi = [{"mac": "aa:aa:aa:aa:ad:01", "ip": "198.51.100.71", "name": "tenant-phone", "ap": "ap-kitchen", "signal": -60, "ssid": "Tenant"},
                {"mac": "aa:aa:aa:aa:ad:02", "ip": "198.51.100.72", "name": "my-laptop", "ap": "ap-living-room", "signal": -55, "ssid": "Home"}]
        seen = inventory.gather([], [], [], [], {}, wifi)
        self.assertEqual(seen["aa:aa:aa:aa:ad:01"]["ssid"], "Tenant")
        # A quiet network (case does not matter): its new device is recorded but not announced.
        self.assertEqual(request("PUT", "/api/inventory/quiet-ssids", {"ssids": ["tenant", " ", "TENANT"]})[1]["ssids"], ["tenant"])
        told = []
        new = inventory.update(seen, told.append, now)
        self.assertEqual([n["mac"] for n in new], ["aa:aa:aa:aa:ad:02"])
        body = request("GET", "/api/inventory")[1]
        rows = {r["mac"]: r for r in body["rows"]}
        self.assertEqual(rows["aa:aa:aa:aa:ad:01"]["ssid"], "Tenant")
        self.assertTrue(rows["aa:aa:aa:aa:ad:01"]["hushed"] and rows["aa:aa:aa:aa:ad:01"]["quiet_net"])
        self.assertFalse(rows["aa:aa:aa:aa:ad:01"]["known"])                                # quiet is not known
        self.assertFalse(rows["aa:aa:aa:aa:ad:02"]["hushed"])
        self.assertEqual({s["ssid"]: s["quiet"] for s in body["ssids"]}, {"Tenant": True, "Home": False})
        # Not counted as new in /changes; Mark all new as known leaves it alone.
        import telebot
        self.assertNotIn("tenant-phone", json.dumps(telebot.changes_values(now + 1)))
        self.assertIn("my-laptop", json.dumps(telebot.changes_values(now + 1)))
        self.assertEqual(request("POST", "/api/inventory/known")[1]["changed"], 1)
        self.assertFalse({r["mac"]: r for r in request("GET", "/api/inventory")[1]["rows"]}["aa:aa:aa:aa:ad:01"]["known"])
        # Moving to a cable clears the SSID; unseen keeps it.
        moved = {"aa:aa:aa:aa:ad:02": dict(seen["aa:aa:aa:aa:ad:02"], via="cable", ssid="", where_seen="core port 3")}
        inventory.update(moved, told.append, now + 60)
        unseen = {"aa:aa:aa:aa:ad:01": dict(seen["aa:aa:aa:aa:ad:01"], via="", ssid="", where_seen="")}
        inventory.update(unseen, told.append, now + 60)
        rows = {r["mac"]: r for r in request("GET", "/api/inventory")[1]["rows"]}
        self.assertEqual(rows["aa:aa:aa:aa:ad:02"]["ssid"], "")
        self.assertEqual(rows["aa:aa:aa:aa:ad:01"]["ssid"], "Tenant")
        # One device quiet by itself, on a loud network.
        self.assertEqual(request("PUT", "/api/inventory/aa:aa:aa:aa:ad:02", {"quiet": True})[0], 200)
        self.assertTrue({r["mac"]: r for r in request("GET", "/api/inventory")[1]["rows"]}["aa:aa:aa:aa:ad:02"]["hushed"])
        self.assertEqual(request("PUT", "/api/inventory/quiet-ssids", {"ssids": ["x" * 33]})[0], 400)
        # Added by hand while offline: known at once, never announced when it shows up.
        code, body, *_ = request("POST", "/api/inventory", {"mac": "AA-AA-AA-AA-AD-09", "name": "Garage sensor", "location": "Garage"})
        self.assertEqual(code, 200, body)
        self.assertEqual(request("POST", "/api/inventory", {"mac": "aa:aa:aa:aa:ad:09"})[0], 400)      # already there
        self.assertEqual(request("POST", "/api/inventory", {"mac": "nonsense"})[0], 400)
        self.assertEqual(request("POST", "/api/inventory", {"mac": "aa:aa:aa:aa:ad:0a", "purchased": "bad"})[0], 400)
        self.assertNotIn("aa:aa:aa:aa:ad:0a", {r["mac"] for r in request("GET", "/api/inventory")[1]["rows"]})
        row = {r["mac"]: r for r in request("GET", "/api/inventory")[1]["rows"]}["aa:aa:aa:aa:ad:09"]
        self.assertTrue(row["known"])
        self.assertEqual((row["name"], row["location"]), ("Garage sensor", "Garage"))
        later = dict(base, mac="aa:aa:aa:aa:ad:09", via="cable", where_seen="core port 9", ssid="")
        self.assertEqual(inventory.update({"aa:aa:aa:aa:ad:09": later}, told.append, now + 120), [])
        database.delete_settings([inventory.QUIET_SSIDS_KEY])

    def test_weak_wifi_per_device(self):
        database.delete_settings([inventory.WIFI_ALERT_KEY])
        now = time.time()
        sensor, phone = "aa:aa:aa:aa:ac:01", "aa:aa:aa:aa:ac:02"
        with database.get_connection() as c:
            for m in (sensor, phone):
                c.execute("INSERT INTO inventory (mac, via, first_seen, last_seen, known) VALUES (?, 'wifi', ?, ?, 1);", (m, now, now))
            c.commit()
        tables = {"wifi_clients": {sensor: {"mac": sensor, "name": "Garden sensor", "signal": -82},
                                   phone: {"mac": phone, "name": "Phone", "signal": -78}}}

        def problems():
            out = []
            server.lan_service_problems({"id": 1, "hostname": "ap-living-room"}, {}, tables,
                                        lambda key, rule, text: out.append(text), lambda rule: -75 if rule == "wifi_weak" else None)
            return out

        self.assertEqual(problems(), ["2 devices on weak Wi-Fi: Garden sensor (-82 dBm), Phone (-78 dBm)"])
        # Never report the sensor: only the phone is left. Typed with dashes and capitals, stored by MAC.
        self.assertEqual(request("PUT", "/api/inventory/AA-AA-AA-AA-AC-01", {"wifi_alert": "off"})[0], 200)
        self.assertEqual(problems(), ["1 device on weak Wi-Fi: Phone (-78 dBm)"])
        rows = {r["mac"]: r for r in request("GET", "/api/inventory")[1]["rows"]}
        self.assertEqual(rows[sensor]["wifi_alert"], "off")
        self.assertEqual(rows[phone]["wifi_alert"], "")
        self.assertIn("Weak Wi-Fi for aa:aa:aa:aa:ac:01: never reported", json.dumps(database.list_audit_logs(limit=1000)))
        # The phone gets its own line at -85: it is not reported at -78, and is again at -88.
        self.assertEqual(request("PUT", f"/api/inventory/{phone}", {"wifi_alert": "-85"})[0], 200)
        self.assertEqual(problems(), [])
        tables["wifi_clients"][phone]["signal"] = -88
        self.assertEqual(problems(), ["1 device on weak Wi-Fi: Phone (-88 dBm)"])
        # Out of range, nonsense and unknown addresses are refused; nothing changes.
        for bad in ("-20", "-120", "loud"):
            self.assertEqual(request("PUT", f"/api/inventory/{phone}", {"wifi_alert": bad})[0], 400, bad)
        self.assertEqual(request("PUT", "/api/inventory/aa:aa:aa:aa:ac:99", {"wifi_alert": "off"})[0], 400)
        self.assertEqual(inventory.wifi_alerts(), {sensor: "off", phone: -85})
        # Back to usual; forgetting the sensor drops its rule too.
        self.assertEqual(request("PUT", f"/api/inventory/{phone}", {"wifi_alert": ""})[0], 200)
        self.assertEqual(request("DELETE", f"/api/inventory/{sensor}")[0], 200)
        self.assertEqual(inventory.wifi_alerts(), {})


class PiholeTests(unittest.TestCase):
    def setUp(self):
        pihole.SESSION.clear()

    def test_v6(self):
        httpd, base = serve(Pihole6)
        try:
            data = pihole.collect({"url": base, "secret": "app-pass", "fingerprint": ""})
            m = data["metrics"]
            self.assertEqual((data["version"], m["pihole.queries"], m["pihole.blocked_pct"], m["pihole.blocking"]), (6, 1000.0, 15.0, 0.0))
            self.assertAlmostEqual(m["pihole.gravity_days"], 20, delta=0.2)
            self.assertEqual(data["upstreams"][0]["response_ms"], 12.0)
            pihole.collect({"url": base, "secret": "app-pass", "fingerprint": ""})
            self.assertEqual(Pihole6.logins, 1)                                                # the session is reused
            pihole.SESSION.clear()
            with self.assertRaises(pihole.PiholeError) as cm:
                pihole.collect({"url": base, "secret": "wrong", "fingerprint": ""})
            self.assertIn("refused the password", str(cm.exception))
        finally:
            httpd.shutdown()

    def test_v5(self):
        httpd, base = serve(Pihole5)
        try:
            data = pihole.collect({"url": base, "secret": "tok5", "fingerprint": ""})
            self.assertEqual((data["version"], data["metrics"]["pihole.queries"], data["metrics"]["pihole.blocking"]), (5, 500.0, 1.0))
            self.assertEqual(data["blocked"], [{"domain": "tracker.example", "count": 12}])
            pihole.SESSION.clear()
            pihole.SESSION.version = 5
            with self.assertRaises(pihole.PiholeError):
                pihole.collect({"url": base, "secret": "bad", "fingerprint": ""})
        finally:
            httpd.shutdown()

    def test_dns_check(self):
        # Queries go to port 53; the stand-in listens elsewhere, so sending is redirected to it.
        sock, port = fake_dns(0)
        real_sendto = socket.socket.sendto
        with mock.patch("socket.socket.sendto", lambda self, data, addr: real_sendto(self, data, ("127.0.0.1", port))):
            r = pihole.dns_check("127.0.0.1", "example.com", 1.0)
        self.assertTrue(r["ok"], r)
        self.assertIsNotNone(r["ms"])
        sock.close()
        sock, port = fake_dns(2)
        with mock.patch("socket.socket.sendto", lambda self, data, addr: real_sendto(self, data, ("127.0.0.1", port))):
            self.assertEqual(pihole.dns_check("127.0.0.1", "example.com", 1.0)["error"], "server failure")
        sock.close()
        self.assertFalse(pihole.dns_check("127.0.0.1", "bad name!", 0.3)["ok"])

    def test_problems(self):
        dev = {"id": 1, "hostname": "pihole", "status": "online", "profile_id": "ping_only"}
        out = server.device_problems(dev, {"dns.ok": 0, "pihole.blocking": 0, "pihole.gravity_days": 30}, {})
        self.assertEqual(sorted(p["rule"] for p in out), ["dns_down", "pihole_blocking", "pihole_lists"])
        out = server.device_problems(dev, {"dns.ok": 1, "dns.ms": 900}, {})
        self.assertEqual([p["rule"] for p in out], ["dns_slow"])


class UnifiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_clients_and_access_point(self):
        unifi.SESSION.clear()
        httpd, base = serve(Unifi)
        try:
            cfg = {"url": base, "username": "monitor", "secret": "pw", "fingerprint": "", "site": "default"}
            rows, infra = unifi.clients(cfg)
            self.assertEqual(len(rows), 3)
            phone = next(r for r in rows if r["name"] == "phone")
            self.assertEqual((phone["ap"], phone["band"], phone["signal"], phone["tx_mbps"]), ("ap-living-room", "5 GHz", -82.0, 144.0))
            nas = next(r for r in rows if r["name"] == "nas")
            self.assertEqual(nas["wired_on"], "Switch port 4")
            self.assertEqual(unifi.SESSION.csrf, "csrf1")
            with mock.patch.object(unifi, "is_enabled", return_value=True), mock.patch.object(unifi, "is_configured", return_value=True), \
                    mock.patch.object(unifi, "load_config", return_value=cfg):
                ap = (next((d["id"] for d in database.list_devices() if d["ip_address"] == "198.51.100.210"), None) or add_device("ap-living-room-t", "198.51.100.210", profile="generic_device"))
                got = unifi.run(database.list_devices(), -75)
            self.assertEqual(len(got), 3)
            table = database.get_device_table(ap, "wifi_clients")
            self.assertEqual(set(table), {"02:11:22:33:44:55", "10:22:33:44:55:66"})
            latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(ap)}
            self.assertEqual(latest["wifi.weak"], 1.0)
            self.assertEqual(latest["wifi.experience"], 69.0)
            out = server.device_problems(dict(database.get_device(ap), status="online"), {}, {"wifi_clients": table})
            weak = [p for p in out if p["rule"] == "wifi_weak"]
            self.assertIn("phone (-82 dBm)", weak[0]["message"])
            cfg["secret"] = "nope"
            unifi.SESSION.clear()
            with self.assertRaises(unifi.UnifiError) as cm:
                unifi.clients(cfg)
            self.assertIn("local account", str(cm.exception))
        finally:
            httpd.shutdown()

    def test_site_by_name_or_id(self):
        httpd, base = serve(Unifi)
        try:
            for site in ("Home", "default", "home"):
                unifi.SESSION.clear()
                rows, _ = unifi.clients({"url": base, "username": "monitor", "secret": "pw", "fingerprint": "", "site": site})
                self.assertEqual(len(rows), 3, site)
                self.assertEqual(unifi.SESSION.site, "default")
            unifi.SESSION.clear()
            with self.assertRaises(unifi.UnifiError) as cm:
                unifi.clients({"url": base, "username": "monitor", "secret": "pw", "fingerprint": "", "site": "Office"})
            self.assertIn("Its sites: Home (id default)", str(cm.exception))
        finally:
            httpd.shutdown()
            unifi.SESSION.clear()

    def test_csrf_from_the_token_cookie(self):
        unifi.SESSION.clear()
        httpd, base = serve(UnifiStrict)
        try:
            rows, _ = unifi.clients({"url": base, "username": "monitor", "secret": "pw", "fingerprint": "", "site": "default"})
            self.assertEqual(len(rows), 3)
            self.assertEqual(unifi.SESSION.csrf, "from-jwt")
        finally:
            httpd.shutdown()
            unifi.SESSION.clear()

    def test_settings_api(self):
        self.assertEqual(request("PUT", "/api/unifi/config", {"url": "http://192.0.2.1", "username": "m", "secret": "p"})[0], 400)
        self.assertEqual(request("PUT", "/api/unifi/config", {"url": "https://192.0.2.1", "username": "", "secret": "p"})[0], 400)
        status, body, _ = request("PUT", "/api/unifi/config", {"url": "https://192.0.2.1", "username": "monitor", "secret": "pw", "site": "default"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["config"]["configured"])
        self.assertNotIn("pw", json.dumps(body))
        with database.get_connection() as c:
            self.assertTrue(c.execute("SELECT value FROM settings WHERE key = 'unifi_secret'").fetchone()["value"].startswith("enc1:"))
        self.assertEqual(request("PUT", "/api/unifi/config", {"disconnect": True})[1]["config"]["configured"], False)
        self.assertEqual(request("PUT", "/api/pihole/config", {"url": "ftp://x", "secret": "s"})[0], 400)
        status, body, _ = request("PUT", "/api/pihole/config", {"url": "http://192.0.2.5", "secret": "s", "test_name": "example.org"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["config"]["test_name"], "example.org")
        request("PUT", "/api/pihole/config", {"disconnect": True})


class StoredSecretTests(unittest.TestCase):
    """The Test buttons and saves reuse the stored password only for the stored address."""

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_pihole_secret_stays_with_its_address(self):
        import rbac
        self.assertEqual(rbac.route_tier("POST", "/api/pihole/test"), 2)
        self.assertEqual(rbac.route_tier("POST", "/api/unifi/test"), 2)
        self.assertEqual(request("PUT", "/api/pihole/config", {"url": "http://192.0.2.5", "secret": "stored-pihole-pw"})[0], 200)
        seen = []
        with mock.patch.object(pihole, "test", side_effect=lambda cfg: seen.append(cfg) or {"version": 6}):
            for url, fp in (("http://198.51.100.66", ""), ("http://192.0.2.5:8080", ""), ("http://192.0.2.5", "ab" * 32)):
                status, body, _ = request("POST", "/api/pihole/test", {"url": url, "secret": "", "fingerprint": fp})
                self.assertEqual(status, 400, url)
                self.assertIn("Enter the password again", body["error"])
            self.assertEqual(seen, [])                                       # nothing was sent anywhere
            # A typed password works for a new address; the stored one for the stored address.
            self.assertEqual(request("POST", "/api/pihole/test", {"url": "http://198.51.100.66", "secret": "typed"})[0], 200)
            self.assertEqual(request("POST", "/api/pihole/test", {"url": "http://192.0.2.5/", "secret": ""})[0], 200)
        self.assertEqual([c["secret"] for c in seen], ["typed", "stored-pihole-pw"])
        # Saving a new address without the password is refused too.
        self.assertEqual(request("PUT", "/api/pihole/config", {"url": "http://198.51.100.66", "secret": ""})[0], 400)
        self.assertEqual(pihole.load_config()["url"], "http://192.0.2.5")
        request("PUT", "/api/pihole/config", {"disconnect": True})

    def test_unifi_secret_stays_with_its_address_and_account(self):
        self.assertEqual(request("PUT", "/api/unifi/config", {"url": "https://192.0.2.1", "username": "monitor",
                                                               "secret": "stored-unifi-pw"})[0], 200)
        seen = []
        with mock.patch.object(unifi, "test", side_effect=lambda cfg: seen.append(cfg) or {}):
            for body in ({"url": "https://198.51.100.67", "username": "monitor"}, {"url": "https://192.0.2.1", "username": "other"}):
                self.assertEqual(request("POST", "/api/unifi/test", dict(body, secret=""))[0], 400, body)
            self.assertEqual(request("POST", "/api/unifi/test", {"url": "https://192.0.2.1", "username": "monitor", "secret": ""})[0], 200)
        self.assertEqual([c["secret"] for c in seen], ["stored-unifi-pw"])
        request("PUT", "/api/unifi/config", {"disconnect": True})

    def test_unifi_channel_is_a_number(self):
        self.assertEqual(unifi._channel(36), 36)
        self.assertEqual(unifi._channel("149"), 149)
        for bad in ('<img src=x onerror=alert(1)>', None, True, -1, "6e"):
            self.assertIsNone(unifi._channel(bad), bad)


class DigestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_due(self):
        monday_9 = datetime.datetime(2026, 11, 2, 9, 0)
        self.assertIsNone(digest.due({"notify_digest": "off"}, monday_9))
        self.assertEqual(digest.due({"notify_digest": "daily", "notify_digest_time": "08:00"}, monday_9), "daily")
        self.assertIsNone(digest.due({"notify_digest": "daily", "notify_digest_time": "10:00"}, monday_9))
        self.assertEqual(digest.due({"notify_digest": "weekly", "notify_digest_day": "monday"}, monday_9), "weekly")
        self.assertIsNone(digest.due({"notify_digest": "weekly", "notify_digest_day": "friday"}, monday_9))
        self.assertIsNone(digest.due({"notify_digest": "daily", digest.LAST_KEY: "2026-11-02"}, monday_9))   # once a day

    def test_compose(self):
        text = digest.compose("weekly")
        self.assertTrue(text.startswith("Weekly summary"))
        self.assertIn("Problems:", text)
        sent = []
        database.delete_settings([digest.LAST_KEY])
        self.assertTrue(digest.run({"notify_digest": "daily", "notify_digest_time": "00:00"}, sent.append))
        self.assertTrue(sent[0].startswith("Daily summary"))
        self.assertFalse(digest.run(dict(database.get_all_settings(), notify_digest="daily", notify_digest_time="00:00"), sent.append))


class UnifiMapAndActionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        unifi.SESSION.clear()

    def test_map_links_from_the_layout(self):
        topo = {"at": 1, "devices": [
            {"mac": "aa:00:00:00:00:01", "ip": "198.51.100.241", "name": "gw", "type": "udm", "uplink_mac": "", "ports": {}},
            {"mac": "aa:00:00:00:00:02", "ip": "198.51.100.242", "name": "sw", "type": "usw", "uplink_mac": "aa:00:00:00:00:01",
             "uplink_port": 4, "ports": {"4": "Uplink"}},
            {"mac": "aa:00:00:00:00:03", "ip": "198.51.100.243", "name": "ap", "type": "uap", "uplink_mac": "aa:00:00:00:00:02",
             "uplink_port": 7, "ports": {}, "uplink_type": "wire"}],
            "clients": [{"mac": "bb:00:00:00:00:01", "ip": "198.51.100.244", "wired": True, "sw_mac": "aa:00:00:00:00:02", "sw_port": 3},
                        {"mac": "bb:00:00:00:00:02", "ip": "198.51.100.245", "wired": False, "ap_mac": "aa:00:00:00:00:03"},
                        {"mac": "bb:00:00:00:00:03", "ip": "198.51.100.99", "wired": False, "ap_mac": "aa:00:00:00:00:03"}]}
        devices = [{"id": i, "ip_address": f"198.51.100.{240 + i}", "hostname": f"d{i}"} for i in (1, 2, 3, 4, 5)]
        labels = {1: {10: "0/4"}, 2: {3: "Port 3"}}
        with mock.patch.object(unifi, "topology", return_value=topo):
            links, counts = server.unifi_map_links(devices, {}, labels)
        self.assertIn(("d:2", "d:1", "0/4", "cable"), links)           # the switch's own label for that port
        self.assertIn(("d:3", "d:2", "Port 7", "cable"), links)        # no label known: UniFi's number
        self.assertIn(("d:4", "d:2", "Port 3", "cable"), links)        # a wired monitored device, its switch port
        self.assertIn(("d:5", "d:3", None, "wifi"), links)             # a monitored device on Wi-Fi hangs off its AP
        self.assertEqual(counts, {"d:3": 1})                           # the unmonitored Wi-Fi device counts on the AP

    def test_reconnect_and_guard_rails(self):
        httpd, base = serve(Unifi)
        Unifi.kicked.clear()
        cfg = {"url": base, "username": "monitor", "secret": "pw", "fingerprint": "", "site": "default"}
        try:
            with mock.patch.object(unifi, "is_enabled", return_value=True), mock.patch.object(unifi, "is_configured", return_value=True), \
                    mock.patch.object(unifi, "load_config", return_value=cfg):
                ap = (next((d["id"] for d in database.list_devices() if d["ip_address"] == "198.51.100.210"), None) or add_device("AP-kick", "198.51.100.210", profile="generic_device"))
                unifi.run(database.list_devices(), -75)
                database.set_internal_setting(unifi.RECONNECTED_KEY, "{}")
                unifi.set_never_list("")
                done, skipped = unifi.reconnect_weak(ap, -75)
                self.assertEqual(Unifi.kicked, ["02:11:22:33:44:55"])          # only the weak one (-82 dBm)
                self.assertIn("phone", done[0])
                done, skipped = unifi.reconnect_weak(ap, -75)                    # an hour has not passed
                self.assertEqual(done, [])
                self.assertIn("at most once an hour", skipped[0])
                database.set_internal_setting(unifi.RECONNECTED_KEY, "{}")
                unifi.set_never_list("Phone, 99:99:99:99:99:99")
                done, skipped = unifi.reconnect_weak(ap, -75)
                self.assertIn("never-reconnect list", skipped[0])
                # The Wi-Fi page and its button.
                unifi.set_never_list("")
                view = request("GET", "/api/wifi")[1]
                self.assertIn("AP-kick", [a["name"] for a in view["aps"]])
                tv = next(c for c in view["clients"] if c["name"] == "TV")
                self.assertIsNone(tv["blocked"])
                self.assertEqual(request("POST", "/api/wifi/reconnect", {"mac": tv["mac"]})[0], 200)
                self.assertEqual(Unifi.kicked[-1], tv["mac"])
                self.assertEqual(request("POST", "/api/wifi/reconnect", {"mac": "00:00:00:00:00:99"})[0], 404)
        finally:
            httpd.shutdown()
            database.set_internal_setting(unifi.RECONNECTED_KEY, "{}")

    def test_workflow_step(self):
        import workflows
        step = workflows._parse_step({"type": "wifi_reconnect", "device_id": 7}, {7}, set())
        self.assertEqual(step, {"type": "wifi_reconnect", "label": "", "device_id": 7})
        with self.assertRaises(workflows.WorkflowError):
            workflows._parse_step({"type": "wifi_reconnect", "device_id": 8}, {7}, set())
        self.assertEqual(workflows.describe(step, {7: "ap-living-room"}), "Reconnect weak Wi-Fi devices on ap-living-room")

    def test_pihole_pause(self):
        pihole.SESSION.clear()
        httpd, base = serve(Pihole6)
        Pihole6.blocking_calls.clear()
        cfg = {"url": base, "secret": "app-pass", "fingerprint": "", "device_id": "", "test_name": "example.com"}
        try:
            with mock.patch.object(pihole, "is_enabled", return_value=True), mock.patch.object(pihole, "is_configured", return_value=True), \
                    mock.patch.object(pihole, "load_config", return_value=cfg):
                pihole.set_blocking(False, 300)
                self.assertEqual(Pihole6.blocking_calls[-1], {"blocking": False, "timer": 300})
                with self.assertRaises(pihole.PiholeError):
                    pihole.set_blocking(False, None)
                data = pihole.collect(cfg)
        finally:
            httpd.shutdown()
            database.set_internal_setting(pihole.PAUSED_KEY, "")
        # Pi-hole 6 reports blocking off with a timer: paused, not a problem.
        dev = {"id": 1, "hostname": "pihole", "status": "online", "profile_id": "ping_only"}
        out = server.device_problems(dev, {"pihole.blocking": 0, "pihole.paused": 1}, {})
        self.assertNotIn("pihole_blocking", [p["rule"] for p in out])
        self.assertIn("pihole_blocking", [p["rule"] for p in server.device_problems(dev, {"pihole.blocking": 0, "pihole.paused": 0}, {})])


if __name__ == "__main__":
    unittest.main()
