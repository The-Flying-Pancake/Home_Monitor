"""Devices: groups by template category and the administrator's choice, detail overrides, authoritative uplink,
attention markers, multi-subnet and port scans, bulk add of port checks, HTTP(S) checks."""

import http.server
import os
import threading
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import discovery
import poller
import server


class WebServer:
    """A local page: /ok answers 200 with a marker, /fail answers 500, /moved redirects elsewhere."""

    def __enter__(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/moved"):
                    self.send_response(302)
                    self.send_header("Location", "http://internal.example:8384/secret")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                code = 200 if self.path.startswith("/ok") else 500
                body = b"<html>all systems nominal</html>"
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class DiscoveryParsingTests(unittest.TestCase):
    def test_subnets_and_ports(self):
        nets = discovery.parse_subnets(["192.168.10.0/25", "192.168.10.128/25", " ", "10.1.0.0/30"])
        self.assertEqual([str(n) for n in nets], ["10.1.0.0/30", "192.168.10.0/24"])   # merged and sorted
        with self.assertRaises(discovery.DiscoveryError):
            discovery.parse_subnets(["8.8.8.0/24"])                                     # public range refused
        with self.assertRaises(discovery.DiscoveryError):
            discovery.parse_subnets(["10.0.0.0/22", "10.2.0.0/24"])                     # over 1024 in total
        self.assertEqual(discovery.parse_ports("22, 80,8000-8002"), [22, 80, 8000, 8001, 8002])
        # No port limit any more: the full range, the common list, and long ranges.
        self.assertEqual(len(discovery.parse_ports("all")), 65535)
        self.assertEqual(discovery.parse_ports("common"), discovery.COMMON_PORTS)
        self.assertEqual(len(discovery.parse_ports("1-100")), 100)
        self.assertIn(9999, discovery.parse_ports("common,9999"))
        for bad in ("0", "70000", "abc"):
            with self.assertRaises(discovery.DiscoveryError):
                discovery.parse_ports(bad)
        self.assertEqual(discovery.parse_hosts(["192.168.1.20", "192.168.1.3", "192.168.1.20"]), ["192.168.1.3", "192.168.1.20"])
        for bad in (["8.8.8.8"], ["127.0.0.1"], ["nope"], []):
            with self.assertRaises(discovery.DiscoveryError):
                discovery.parse_hosts(bad)


class PortSweepTests(unittest.TestCase):
    def listeners(self, *ports):
        import socket
        out = []
        for port in ports:
            sock = socket.socket()
            sock.bind(("127.0.0.1", port))
            sock.listen(50)
            out.append(sock)
        self.addCleanup(lambda: [x.close() for x in out])

    def test_sweep_finds_open_ports(self):
        self.listeners(52101, 52133)
        found = []
        discovery.tcp_sweep((("127.0.0.1", p) for p in range(52100, 52201)),
                            lambda ip, port, open_, ms: open_ and found.append(port), threading.Event())
        self.assertEqual(sorted(found), [52101, 52133])

    def test_scan_job_on_chosen_hosts_and_large_ranges(self):
        self.listeners(52301, 53999)
        # A small list: every chosen host is scanned straight away.
        job = discovery.ScanJob([], "", set(), ports=[52300, 52301, 52302], hosts=["127.0.0.1"],
                                known_ports={("127.0.0.1", 52301)})
        job.run()
        v = job.view()
        self.assertEqual((v["phase"], v["results"][0]["open_ports"], v["results"][0]["monitored_ports"]), ("ports", [52301], [52301]))
        # More than LIVE_FIRST_PORTS ports: hosts that are up are found first, then only they are scanned.
        job = discovery.ScanJob([], "", set(), ports=list(range(52300, 54001)), hosts=["127.0.0.1"])
        job.run()
        v = job.view()
        self.assertEqual(v["live_hosts"], 1)
        # Other programs on this machine may hold ports in the range too: the two listeners must be found.
        self.assertLessEqual({52301, 53999}, set(v["results"][0]["open_ports"]))
        self.assertEqual(v["done"], v["total"])

    def test_stop_keeps_what_was_found(self):
        self.listeners(52401)
        job = discovery.ScanJob([], "", set(), ports=[52401] + list(range(1, 30000)), hosts=["127.0.0.1"])
        t = threading.Thread(target=job.run)
        t.start()
        deadline = time.time() + 20
        while time.time() < deadline and not job.results:
            time.sleep(0.1)
        job.stop()
        t.join(30)
        v = job.view()
        self.assertTrue(v["finished"] and v["stopped"])
        self.assertLess(v["done"], v["total"])
        self.assertIn(52401, v["results"][0]["open_ports"])            # found before the stop (listed first)

    def test_host_without_snmp_is_suggested_as_ping_only(self):
        from unittest import mock
        with mock.patch.object(poller, "ping_host", return_value=(True, 1.5)),                 mock.patch.object(poller, "snmp_get_many", return_value={}):
            r = discovery.probe("192.0.2.77", "public", [], 0.2)
        self.assertEqual((r["profile_id"], r["snmp"], r["ping"]), ("ping_only", False, True))


class HttpCheckTests(unittest.TestCase):
    def test_status_keyword_and_failures(self):
        with WebServer() as w:
            base = f"http://127.0.0.1:{w.port}"
            self.assertTrue(poller.http_check(base + "/ok")["up"])
            r = poller.http_check(base + "/ok", {"keyword": "nominal"})
            self.assertTrue(r["up"])
            self.assertEqual(r["status"], 200)
            self.assertFalse(poller.http_check(base + "/ok", {"keyword": "missing words"})["up"])
            r = poller.http_check(base + "/fail")
            self.assertEqual((r["up"], r["status"]), (False, 500))
            self.assertTrue(poller.http_check(base + "/fail", {"status": "200,500"})["up"])
        self.assertFalse(poller.http_check("ftp://x")["up"])
        # Without the test switch, the monitor's own loopback and link-local addresses are refused.
        os.environ.pop("MONITOR_ALLOW_LOOPBACK_CHECKS")
        try:
            for url in ("http://127.0.0.1:8384/", "http://localhost/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/"):
                r = poller.http_check(url)
                self.assertFalse(r["up"])
                self.assertIn("own or link-local", r["error"], url)
        finally:
            os.environ["MONITOR_ALLOW_LOOPBACK_CHECKS"] = "1"
        self.assertFalse(poller.http_check("file:///etc/passwd")["up"])
        self.assertFalse(poller._status_ok(404, "200-399"))

    def test_redirects_are_reported_not_followed(self):
        with WebServer() as w, mock.patch("socket.create_connection", wraps=__import__("socket").create_connection) as conn:
            base = f"http://127.0.0.1:{w.port}"
            r = poller.http_check(base + "/moved")
            self.assertEqual((r["up"], r["status"], r["redirect"]), (True, 302, "internal.example"))
            r = poller.http_check(base + "/moved", {"status": "200"})
            self.assertEqual((r["up"], r["status"]), (False, 302))
            self.assertIn("redirects to internal.example, not followed", r["error"])
            hosts = {c.args[0][0] for c in conn.call_args_list}
        self.assertEqual(hosts, {"127.0.0.1"})                          # never connected to the redirect target
        self.assertTrue(poller._status_ok(301, "200-399"))


class DeviceApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_group_follows_category_and_owner_choice(self):
        sw = add_device("grp-switch", "198.51.100.40", profile="managed_switch")
        listed = {d["id"]: d for d in request("GET", "/api/devices")[1]["devices"]}
        self.assertEqual(listed[sw]["group"], "switch")          # a non-UniFi switch is a switch, not "other"
        body = {"hostname": "grp-switch", "ip_address": "198.51.100.40", "profile_id": "managed_switch",
                "device_group": "server", "overrides": {"sys_location": "Garage rack", "bogus": "x"}}
        self.assertEqual(request("PUT", f"/api/devices/{sw}", body)[0], 200)
        d = request("GET", f"/api/devices/{sw}")[1]["device"]
        self.assertEqual(d["group"], "server")
        self.assertEqual(d["inventory"]["sys_location"], "Garage rack")
        self.assertEqual(d["overrides"], {"sys_location": "Garage rack"})
        self.assertEqual(request("PUT", f"/api/devices/{sw}", dict(body, device_group="nonsense"))[0], 400)
        self.assertEqual(request("PUT", f"/api/devices/{sw}", dict(body, upstream_device_id=sw))[0], 400)

    def test_upstream_is_authoritative_on_the_map(self):
        a = add_device("up-a", "198.51.100.41")
        b = add_device("up-b", "198.51.100.42")
        body = {"hostname": "up-b", "ip_address": "198.51.100.42", "profile_id": "generic_device",
                "upstream_device_id": a, "upstream_port": "Port 7"}
        self.assertEqual(request("PUT", f"/api/devices/{b}", body)[0], 200)
        links = request("GET", "/api/map")[1]["links"]
        drawn = [l for l in links if l["source"] == "owner"]
        self.assertEqual(len(drawn), 1)
        self.assertEqual({drawn[0]["a"], drawn[0]["b"]}, {f"d:{a}", f"d:{b}"})
        self.assertIn("Port 7", (drawn[0]["a_port"], drawn[0]["b_port"]))
        # Deleting the uplink device clears the reference instead of leaving it dangling.
        self.assertEqual(request("DELETE", f"/api/devices/{a}")[0], 200)
        self.assertIsNone(database.get_device(b)["upstream_device_id"])

    def test_attention_marker(self):
        dev = add_device("attn-a", "198.51.100.43")
        database.add_event(dev, "info", "reboot", "Device restarted (uptime reset)")
        listed = {d["id"]: d for d in request("GET", "/api/devices")[1]["devices"]}
        self.assertEqual(listed[dev]["attention"]["kind"], "event")
        # An old info event is not shown.
        dev2 = add_device("attn-b", "198.51.100.44")
        database.add_event(dev2, "info", "reboot", "Old restart", timestamp=int(time.time()) - 7200)
        listed = {d["id"]: d for d in request("GET", "/api/devices")[1]["devices"]}
        self.assertIsNone(listed[dev2]["attention"])

    def test_scan_routes_and_bulk_add_of_port_checks(self):
        status, body, _ = request("POST", "/api/devices/scan", {"subnets": ["127.0.0.0/30"], "ports": "1"})
        self.assertEqual(status, 400)                            # loopback is not a LAN range
        status, body, _ = request("POST", "/api/devices/scan", {"subnets": "nope"})
        self.assertEqual(status, 400)
        body = {"devices": [{"ip_address": "198.51.100.45", "hostname": "svc web", "profile_id": "service_check", "service_port": 80},
                            {"ip_address": "198.51.100.45", "hostname": "svc ssh", "profile_id": "service_check", "service_port": 22},
                            {"ip_address": "198.51.100.45", "hostname": "dup", "profile_id": "service_check", "service_port": 80}]}
        status, r, _ = request("POST", "/api/devices/bulk-add", body)
        self.assertEqual(status, 200, r)
        self.assertEqual(sorted(a["service_port"] for a in r["added"]), [22, 80])
        status, r, _ = request("POST", "/api/devices/bulk-add", body)
        self.assertEqual(len(r["added"]), 0)
        self.assertEqual(len(r["skipped"]), 2)

    def test_web_check_add_probe_and_problem(self):
        with WebServer() as w:
            url = f"http://127.0.0.1:{w.port}/ok"
            status, r, _ = request("POST", "/api/devices/probe", {"service_kind": "http", "service_url": url,
                                                                  "service_expect": {"keyword": "nominal"}})
            self.assertEqual(status, 200, r)
            self.assertTrue(r["open"])
            status, r, _ = request("POST", "/api/devices", {"hostname": "", "ip_address": "", "profile_id": "service_check",
                                                            "service_kind": "http", "service_url": url,
                                                            "service_expect": {"status": "200", "keyword": "nominal"}})
            self.assertEqual(status, 201, r)
            d = database.get_device(r["device_id"])
            self.assertEqual((d["ip_address"], d["service_port"], d["service_kind"]), ("127.0.0.1", w.port, "http"))
            poller.ping_device(d)
            latest = {x["metric_key"]: x["value"] for x in database.get_latest_metrics(d["id"])}
            self.assertEqual((latest["service_up"], latest["http_status"]), (1.0, 200.0))
        dd = dict(d, status="degraded")
        msgs = [p["message"] for p in server.device_problems(dd, {"service_up": 0.0, "http_status": 500.0}, {})]
        self.assertEqual(len(msgs), 1)
        self.assertIn("answered HTTP 500", msgs[0])
        bad = {"hostname": "x", "profile_id": "service_check", "service_kind": "http", "service_url": "notaurl"}
        self.assertEqual(request("POST", "/api/devices", bad)[0], 400)
        bad = dict(bad, service_url="http://127.0.0.1/", service_expect={"status": "2xx"})
        self.assertEqual(request("POST", "/api/devices", bad)[0], 400)


if __name__ == "__main__":
    unittest.main()


class PingOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_ping_only_device_never_uses_snmp(self):
        from unittest import mock
        dev = add_device("ping-phone", "198.51.100.150", profile="ping_only")
        row = next(d for d in request("GET", "/api/devices")[1]["devices"] if d["id"] == dev)
        self.assertFalse(row["snmp"])
        self.assertEqual(row["group"], "other")
        self.assertFalse(request("GET", f"/api/devices/{dev}")[1]["device"]["snmp"])
        self.assertFalse(server.profile_uses_snmp("ping_only"))
        self.assertTrue(server.profile_uses_snmp("generic_device"))
        # The refresh after Fix SNMP and the live sample ping it and nothing else.
        device = database.get_device(dev)
        with mock.patch.object(server.scheduler, "_snmp_job") as snmp_job, \
                mock.patch.object(server.scheduler, "_ping_job"), mock.patch.object(server.scheduler, "_problem_job"), \
                mock.patch.object(server.scheduler, "_submit", side_effect=lambda kind, key, fn, *a: fn(*a)):
            server.scheduler.refresh_device(dev)
        snmp_job.assert_not_called()
        with mock.patch.object(poller, "ping_host", return_value=(True, 2.5)), \
                mock.patch.object(poller, "live_sample") as live:
            server.scheduler._live_job(device, 1.0, 5)
        live.assert_not_called()
        request("DELETE", f"/api/devices/{dev}")

    def test_ping_test(self):
        from unittest import mock
        with mock.patch.object(poller, "ping_host", side_effect=[(True, 1.0), (False, None), (True, 3.0)]):
            status, body, _ = request("POST", "/api/devices/probe", {"ip_address": "198.51.100.151", "mode": "ping"})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["ping"], body["replies"], body["sent"], body["ping_ms"]), (True, 2, 3, 2.0))

    def test_setup_plan_wording(self):
        import setup
        site = {"ssh": {"enabled": False}, "syncthing": {"enabled": False}, "nfs": {"enabled": False}, "telegram": {"enabled": False}}
        lines = setup.plan_lines({}, site, [
            {"hostname": "tv", "ip_address": "198.51.100.152", "profile_id": "ping_only"},
            {"hostname": "nas web", "ip_address": "198.51.100.153", "profile_id": "service_check", "service_port": 5001}], {})
        self.assertIn("Add device tv (198.51.100.152), ping only", lines)
        self.assertIn("Add port check nas web (198.51.100.153:5001)", lines)

    def test_port_scan_of_chosen_hosts_can_be_stopped(self):
        from unittest import mock
        # Chosen hosts must be private addresses, like subnets.
        self.assertEqual(request("POST", "/api/devices/scan", {"hosts": ["8.8.8.8"], "ports": "common"})[0], 400)
        with mock.patch.object(discovery, "tcp_sweep", side_effect=lambda pairs, done, cancelled, **k: cancelled.wait(10)), \
                mock.patch.object(poller, "ping_host", return_value=(False, None)):
            status, body, _ = request("POST", "/api/setup/scan", {"hosts": ["192.168.77.5", "192.168.77.6"], "ports": "all"})
            self.assertEqual((status, body["ports"]), (200, 65535), body)
            self.assertEqual(request("DELETE", f"/api/setup/scan/{body['id']}")[0], 200)
            deadline = time.time() + 15
            while time.time() < deadline and not request("GET", f"/api/setup/scan/{body['id']}")[1]["finished"]:
                time.sleep(0.2)
        v = request("GET", f"/api/setup/scan/{body['id']}")[1]
        self.assertTrue(v["finished"] and v["stopped"], v)
        self.assertEqual(request("DELETE", "/api/devices/scan/" + "0" * 32)[0], 404)
