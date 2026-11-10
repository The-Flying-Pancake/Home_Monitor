"""HTTP security controls and input validation of the REST API."""

import socket
import threading
import time
import types
import unittest
from unittest import mock

from tests import _env
from tests.helpers import add_device, request, start_api_server

import database
import server


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_security_headers(self):
        _, _, headers = request("GET", "/")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        for directive in ("script-src 'self'", "style-src 'self'", "img-src 'self' data:", "connect-src 'self'"):
            self.assertIn(directive, headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Strict-Transport-Security", headers)                 # plain HTTP: no HSTS

    def test_hsts_over_tls(self):
        import ssl
        sent = []
        h = server.ApiRequestHandler.__new__(server.ApiRequestHandler)
        h.send_header = lambda k, v: sent.append((k, v))
        h.connection = mock.MagicMock(spec=ssl.SSLSocket)
        h._security_headers()
        self.assertIn(("Strict-Transport-Security", "max-age=31536000"), sent)
        sent.clear()
        h.connection = mock.MagicMock()
        h._security_headers()
        self.assertNotIn("Strict-Transport-Security", dict(sent))

    def test_huge_numbers_are_not_server_errors(self):
        for path in ("/api/devices/99999999999999999999999", "/api/devices/99999999999999999999999/events"):
            status, body, _ = request("GET", path)
            self.assertIn(status, (400, 404), (path, body))
        self.assertIn(request("DELETE", "/api/workflows/99999999999999999999999")[0], (400, 404))

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(request("GET", "/api/devices", headers={"Host": "evil.example:8080"})[0], 421)

    def test_cross_origin_mutation_rejected(self):
        self.assertEqual(request("POST", "/api/settings", {}, headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(request("DELETE", "/api/devices/1", headers={"Origin": "http://evil.example"})[0], 403)

    def test_form_post_rejected(self):
        self.assertEqual(request("POST", "/api/settings", raw=b"{}", headers={"Content-Type": "text/plain"})[0], 415)

    def test_body_limits_and_shape(self):
        self.assertEqual(request("POST", "/api/devices", raw=b"[1,2]")[0], 400)
        self.assertEqual(request("POST", "/api/devices", raw=b"{bad")[0], 400)
        # Oversized bodies are refused without being read (that is the protection), so the
        # client may see 413 or a connection reset depending on timing and OS.
        try:
            self.assertEqual(request("POST", "/api/settings", raw=b"x" * 200000)[0], 413)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def test_no_inline_handlers_or_styles_in_frontend(self):
        import os, re
        for name in ("index.html", "app.js"):
            with open(os.path.join(_env.ROOT, "web", name), encoding="utf-8") as f:
                text = f.read()
            self.assertIsNone(re.search(r"\son(click|load|change|submit|input)=", text), name)
            self.assertIsNone(re.search(r'\sstyle="', text), name)


class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("api-dev", "192.0.2.40")

    def post_device(self, **fields):
        body = {"hostname": "x", "ip_address": "192.0.2.41", "profile_id": "generic_device"}
        body.update(fields)
        return request("POST", "/api/devices", body)

    def test_device_validation(self):
        # Any name that does not resolve is refused.
        self.assertEqual(self.post_device(ip_address="ap-living-room-not-an-address")[0], 400)
        self.assertEqual(self.post_device(ip_address="192.168.1.999")[0], 400)
        self.assertEqual(self.post_device(ip_address="-n")[0], 400)
        self.assertEqual(self.post_device(snmp_port=99999)[0], 400)
        self.assertEqual(self.post_device(poll_interval="<img src=x>")[0], 400)
        self.assertEqual(self.post_device(profile_id="nope")[0], 400)
        self.assertEqual(self.post_device(ip_address=123)[0], 400)
        status, body, _ = self.post_device(ip_address="192.0.2.40")
        self.assertEqual(status, 409, body)

    def test_hostname_regex_is_linear(self):
        import time
        t = time.time()
        self.assertEqual(self.post_device(ip_address="a" * 60 + "!")[0], 400)
        self.assertLess(time.time() - t, 2.0)

    def test_missing_device(self):
        self.assertEqual(request("PUT", "/api/devices/999999", {"ip_address": "192.0.2.99"})[0], 404)
        self.assertEqual(request("DELETE", "/api/devices/999999")[0], 404)

    def test_settings_validation(self):
        self.assertEqual(request("POST", "/api/settings", {"evil": "1"})[0], 400)
        self.assertEqual(request("POST", "/api/settings", {"default_retries": "50"})[0], 400)
        self.assertEqual(request("POST", "/api/settings", {"raw_retention_days": "60", "metric_retention_days": "30"})[0], 400)
        status, body, _ = request("POST", "/api/settings", {"problem_resolve_minutes": "7"})
        self.assertEqual((status, body["changed"]), (200, ["problem_resolve_minutes"]))
        self.assertEqual(request("POST", "/api/settings", {"threshold_cpu_pct": "85"})[0], 400)    # now an alert rule

    def test_dashboard_layout_validation(self):
        good = {"columns": 6, "layout": [{"id": "a", "type": "summary", "span": 6, "rows": 2, "config": {}},
                                          {"id": "b", "type": "graph", "span": 9, "rows": 3, "config": {}}]}
        too_tall = {"columns": 6, "layout": [{"id": "c", "type": "graph", "span": 2, "rows": 30, "config": {}}]}
        self.assertEqual(request("PUT", "/api/dashboard", too_tall)[0], 400)
        self.assertEqual(request("PUT", "/api/dashboard", good)[0], 200)
        _, body, _ = request("GET", "/api/dashboard")
        self.assertEqual(body["columns"], 6)
        self.assertEqual(body["layout"][1]["span"], 6)  # clamped to the grid width
        self.assertEqual(request("PUT", "/api/dashboard", {"columns": 5, "layout": []})[0], 400)
        self.assertEqual(request("PUT", "/api/dashboard", {"columns": 4, "layout": [{"id": "x", "type": "evil"}]})[0], 400)
        self.assertEqual(request("PUT", "/api/dashboard", {"columns": 4, "layout": [{"id": "bad id!", "type": "summary"}]})[0], 400)

    def test_credential_validation(self):
        self.assertEqual(request("POST", "/api/credentials", {"name": "k", "cred_type": "ssh_key", "secret": "not a key"})[0], 400)
        self.assertEqual(request("POST", "/api/credentials", {"name": "k", "cred_type": "telnet", "secret": "x"})[0], 400)
        self.assertEqual(request("POST", "/api/credentials", {"name": "", "cred_type": "password", "secret": "x"})[0], 400)
        self.assertEqual(request("POST", "/api/credentials", {"name": "nosecret", "cred_type": "password"})[0], 400)
        self.assertEqual(request("POST", "/api/credentials", {"name": "dup", "cred_type": "password", "secret": "x"})[0], 201)
        self.assertEqual(request("POST", "/api/credentials", {"name": "dup", "cred_type": "password", "secret": "x"})[0], 409)

    def test_ssh_tasks_become_workflows(self):
        import server
        _, body, _ = request("POST", "/api/credentials", {"name": "task-cred", "cred_type": "password", "username": "u", "secret": "x"})
        cred = body["id"]
        with database.get_connection() as conn:
            conn.execute("INSERT INTO automations (name, command, credential_id, device_ids, trigger_type, trigger_cron, "
                         "expected_exit_code, timeout_s, ssh_port, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                         ("old-task", "uptime", cred, f"[{self.dev}]", "schedule", "0 3 * * 0", 0, 90, 2222, 1, 0))
            conn.commit()
        self.assertEqual(server.migrate_tasks_to_workflows(), 1)
        self.assertEqual(database.list_tasks(), [])
        wf = next(w for w in request("GET", "/api/workflows")[1]["workflows"] if w["name"] == "old-task")
        self.assertEqual((wf["trigger_type"], wf["trigger_cron"], wf["schedule_text"]), ("schedule", "0 3 * * 0", "Every Sunday at 03:00"))
        step = wf["steps"][0]
        self.assertEqual((step["command"], step["device_ids"], step["timeout_s"], step["ssh_port"]), ("uptime", [self.dev], 90, 2222))
        self.assertEqual(request("GET", "/api/tasks")[0], 404)       # the routes are gone
        self.assertEqual(request("POST", "/api/tasks", {})[0], 404)

    def test_poll_all_queues_every_device(self):
        status, body, _ = request("POST", "/api/devices/poll-all", {})
        self.assertEqual((status, body["queued"]), (200, len(database.list_devices())))


class LanListenTests(unittest.TestCase):
    """Host header rules when the container listens on the LAN (MONITOR_LISTEN=0.0.0.0)."""

    def test_host_allowed(self):
        port = server.LISTEN_PORT
        with mock.patch.object(server, "LISTEN_HOST", "0.0.0.0"), mock.patch.object(server, "ALLOWED_NAMES", {"monitor"}),                 mock.patch.object(server.socket, "gethostname", return_value="Monitor"):
            for ok in (f"127.0.0.1:{port}", f"192.168.1.201:{port}", f"[fd00::5]:{port}", f"monitor:{port}", f"monitor.lan:{port}"):
                self.assertTrue(server.host_allowed(ok), ok)
            for bad in (f"evil.example:{port}", f"192.168.1.201:{port + 1}", "192.168.1.201", f"monitor.evil.example:{port}", ""):
                self.assertFalse(server.host_allowed(bad), bad)
        # On a workstation only the local names pass.
        self.assertFalse(server.host_allowed(f"192.168.1.201:{port}"))


class ServerLimitTests(unittest.TestCase):
    """Read limits and the connection cap, on real sockets against a server of their own with small limits."""

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        self.httpd = server.ThreadingServer(("127.0.0.1", 0), server.ApiRequestHandler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.socks = []

    def tearDown(self):
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.httpd.shutdown()
        self.httpd.server_close()

    def connect(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.socks.append(s)
        return s

    def wait_open(self, n, seconds=3.0):
        end = time.monotonic() + seconds
        while time.monotonic() < end and self.httpd.open_connections() != n:
            time.sleep(0.02)
        self.assertEqual(self.httpd.open_connections(), n)

    @staticmethod
    def closed_within(s, seconds):
        """Reads until the server closes; returns (seconds taken, bytes received), or None if still open."""
        s.settimeout(seconds)
        started = time.monotonic()
        got = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    return time.monotonic() - started, got
                got += chunk
        except (ConnectionResetError, ConnectionAbortedError):
            return time.monotonic() - started, got
        except TimeoutError:
            return None

    def get_status(self, path="/api/auth/status"):
        s = self.connect()
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{_env.PORT}\r\n\r\n".encode())
        result = self.closed_within(s, 5)
        self.assertIsNotNone(result)
        return int(result[1].split(b" ", 2)[1]) if result[1] else None

    def test_slow_request_line_disconnected(self):
        with mock.patch.object(server, "READ_IDLE_SECONDS", 0.4):
            s = self.connect()
            s.sendall(b"GET /api/auth/sta")
            result = self.closed_within(s, 3)
        self.assertIsNotNone(result, "a half request line kept the connection open")
        self.assertLess(result[0], 2)

    def test_drip_fed_headers_disconnected(self):
        with mock.patch.object(server, "READ_IDLE_SECONDS", 2), mock.patch.object(server, "READ_TOTAL_SECONDS", 0.5):
            s = self.connect()
            started = time.monotonic()
            closed = False
            for b in f"GET / HTTP/1.0\r\nHost: 127.0.0.1:{_env.PORT}\r\nX-Slow: {'a' * 40}".encode():
                try:
                    s.sendall(bytes([b]))
                except OSError:
                    closed = True
                    break
                if self.closed_within(s, 0.1) is not None:
                    closed = True
                    break
            took = time.monotonic() - started
        self.assertTrue(closed, "a drip-fed request was never cut off")
        self.assertLess(took, 2)

    def test_slow_body_gets_408(self):
        with mock.patch.object(server, "READ_IDLE_SECONDS", 0.3), mock.patch.object(server, "READ_TOTAL_SECONDS", 1):
            s = self.connect()
            s.sendall((f"POST /api/auth/login HTTP/1.0\r\nHost: 127.0.0.1:{_env.PORT}\r\n"
                       "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"user").encode())
            result = self.closed_within(s, 5)
        self.assertIsNotNone(result)
        self.assertIn(b" 408 ", result[1].split(b"\r\n", 1)[0])
        self.assertIn(server.SLOW_REQUEST_TEXT.encode(), result[1])

    def test_http10_has_no_keep_alive(self):
        self.assertEqual(server.ApiRequestHandler.protocol_version, "HTTP/1.0")
        s = self.connect()
        s.sendall(f"GET /api/auth/status HTTP/1.1\r\nHost: 127.0.0.1:{_env.PORT}\r\nConnection: keep-alive\r\n\r\n".encode())
        result = self.closed_within(s, 3)
        self.assertIsNotNone(result, "the connection stayed open after the reply")
        self.assertIn(b" 200 ", result[1].split(b"\r\n", 1)[0])

    def test_thread_cap_holds(self):
        self.httpd.local_client = staticmethod(lambda addr: False)
        with mock.patch.object(server, "MAX_CONNECTIONS", 3), mock.patch.object(server, "READ_IDLE_SECONDS", 5):
            before = threading.active_count()
            for _ in range(3):
                self.connect()
            self.wait_open(3)
            started = time.monotonic()
            fourth = self.connect()
            result = self.closed_within(fourth, 3)
            self.assertIsNotNone(result)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertIn(b" 503 ", result[1].split(b"\r\n", 1)[0])
            self.assertIn(b"Retry-After: 5", result[1])
            self.assertIn(server.BUSY_TEXT.encode(), result[1])
            self.assertLessEqual(threading.active_count() - before, 3)
            self.assertEqual(self.httpd.open_connections(), 3)

    def test_slot_is_given_back(self):
        self.httpd.local_client = staticmethod(lambda addr: False)
        with mock.patch.object(server, "MAX_CONNECTIONS", 3), mock.patch.object(server, "READ_IDLE_SECONDS", 5):
            held = [self.connect() for _ in range(3)]
            self.wait_open(3)
            for s in held:
                s.close()
            self.wait_open(0)
            self.assertEqual(self.get_status(), 200)

    def test_per_address_cap(self):
        self.httpd.local_client = staticmethod(lambda addr: False)
        with mock.patch.object(server, "MAX_CONNECTIONS", 10), mock.patch.object(server, "MAX_PER_ADDRESS", 2), \
                mock.patch.object(server, "READ_IDLE_SECONDS", 5):
            self.connect()
            self.connect()
            self.wait_open(2)
            result = self.closed_within(self.connect(), 3)
        self.assertIsNotNone(result)
        self.assertIn(b" 503 ", result[1])

    def test_local_clients_get_extra_slots(self):
        remote = {"on": True}
        self.httpd.local_client = staticmethod(lambda addr: not remote["on"])
        with mock.patch.object(server, "MAX_CONNECTIONS", 2), mock.patch.object(server, "READ_IDLE_SECONDS", 5):
            self.connect()
            self.connect()
            self.wait_open(2)
            refused = self.closed_within(self.connect(), 3)
            self.assertIn(b" 503 ", refused[1])
            remote["on"] = False   # this machine: a health check still answers
            self.assertEqual(self.get_status(), 200)

    def test_thread_start_failure_is_safe(self):
        class NoStart(threading.Thread):
            def start(self):
                raise RuntimeError("can't start new thread")
        fake = types.SimpleNamespace(**{k: getattr(threading, k) for k in dir(threading) if not k.startswith("__")})
        fake.Thread = NoStart
        with mock.patch.object(server, "threading", fake):
            result = self.closed_within(self.connect(), 3)
            self.assertIsNotNone(result)
            self.assertIn(b" 503 ", result[1])
            self.assertEqual(self.httpd.open_connections(), 0)
        self.assertEqual(self.get_status(), 200)
        self.wait_open(0)


class RetentionSettingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_audit_retention_below_floor_refused(self):
        status, body, _ = request("POST", "/api/settings", {"audit_retention_days": "30"})
        self.assertEqual(status, 400, body)
        self.assertEqual(server.get_setting({"audit_retention_days": "5"}, "audit_retention_days"), 90)
        self.assertEqual(request("POST", "/api/settings", {"event_retention_days": "30"})[0], 200)
        request("POST", "/api/settings", {"event_retention_days": "90"})

    def test_retention_change_is_audited(self):
        from tests.helpers import TEST_USER
        self.assertEqual(request("POST", "/api/settings", {"audit_retention_days": "100"})[0], 200)
        self.assertEqual(request("POST", "/api/settings", {"audit_retention_days": "90"})[0], 200)
        rows = database.list_audit_filtered(q="Audit log retention changed")[0]
        self.assertEqual([(r["message"], r["actor"]) for r in rows[:2]],
                         [("Audit log retention changed from 100 to 90 days", TEST_USER),
                          ("Audit log retention changed from 90 to 100 days", TEST_USER)])


if __name__ == "__main__":
    unittest.main()
