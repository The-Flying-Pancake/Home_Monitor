"""Web UI login: password hashing, session gate, cookie flags, confirmation, rate limiting, password change."""

import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import TEST_PASSWORD, TEST_USER, login, raw_bytes, request, session_cookie, start_api_server

import auth
import database
import server


class PasswordHashTests(unittest.TestCase):
    def test_hash_format_and_verify(self):
        saved = auth.SCRYPT_N
        auth.SCRYPT_N = 2 ** 17     # production cost
        try:
            h = auth.hash_password("a long passphrase")
        finally:
            auth.SCRYPT_N = saved
        scheme, n, r, p, salt, digest = h.split("$")
        self.assertEqual((scheme, n, r, p), ("scrypt", str(2 ** 17), "8", "1"))
        self.assertTrue(auth.verify_password("a long passphrase", h))
        self.assertFalse(auth.verify_password("a long passphrasE", h))
        self.assertNotEqual(auth.hash_password("same"), auth.hash_password("same"))  # per-hash salt
        self.assertFalse(auth.verify_password("x", "garbage"))

    def test_password_rules(self):
        self.assertIsNotNone(auth.password_problem("short"))
        self.assertIsNotNone(auth.password_problem("aaaaaaaaaaaaaaaa"))
        self.assertIsNone(auth.password_problem("correct horse battery"))


class SessionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_api_requires_session(self):
        for method, path in (("GET", "/api/devices"), ("GET", "/api/settings"), ("GET", "/api/credentials"),
                             ("POST", "/api/devices/poll-all"), ("GET", "/api/system")):
            status, body, _ = request(method, path, session=False)
            self.assertEqual(status, 401, path)
            self.assertEqual(body["auth"], "login")
        # A forged or stale cookie is the same as none.
        status, _, _ = request("GET", "/api/devices", headers={"Cookie": f"{auth.SESSION_COOKIE}=forged"}, session=False)
        self.assertEqual(status, 401)
        # Static files carry no data and stay reachable, so the login page can load.
        self.assertEqual(request("GET", "/", session=False)[0], 200)

    def test_status_and_setup_only_once(self):
        status, body, _ = request("GET", "/api/auth/status", session=False)
        self.assertEqual((status, body["configured"], body["authenticated"]), (200, True, False))
        self.assertTrue(request("GET", "/api/auth/status")[1]["authenticated"])
        status, _, _ = request("POST", "/api/auth/setup", {"username": "intruder", "password": "another long password"}, session=False)
        self.assertEqual(status, 409)

    def test_setup_token_required_when_configured(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"MONITOR_SETUP_TOKEN": "one-time-token"}):
            body = {"username": "x", "password": "another long password"}
            self.assertEqual(request("POST", "/api/auth/setup", body, session=False)[0], 403)
            self.assertEqual(request("POST", "/api/auth/setup", dict(body, setup_token="wrong"), session=False)[0], 403)
            # Right token reaches the one-account rule.
            self.assertEqual(request("POST", "/api/auth/setup", dict(body, setup_token="one-time-token"), session=False)[0], 409)
            # A non-ASCII token is a wrong token (403), not a server error.
            self.assertEqual(request("POST", "/api/auth/setup", dict(body, setup_token="tökén-é"), session=False)[0], 403)

    def test_cookie_flags_and_logout(self):
        status, _, headers = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
        self.assertEqual(status, 200)
        raw = next(v for k, v in headers.items() if k.lower() == "set-cookie")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, raw)
        token = session_cookie(headers)
        cookie = {"Cookie": f"{auth.SESSION_COOKIE}={token}"}
        self.assertEqual(request("GET", "/api/devices", headers=cookie, session=False)[0], 200)
        request("POST", "/api/auth/logout", headers=cookie, session=False)
        self.assertEqual(request("GET", "/api/devices", headers=cookie, session=False)[0], 401)
        # The server keeps only a hash of the token.
        self.assertFalse(any(token in k for k in auth.SESSIONS.sessions))

    def test_wrong_credentials(self):
        auth.LIMITER.failures.clear()
        for creds in ({"username": TEST_USER, "password": "wrong password!"}, {"username": "nobody", "password": TEST_PASSWORD},
                      {"username": "bad name!", "password": TEST_PASSWORD}):
            status, body, _ = request("POST", "/api/auth/login", creds, session=False)
            self.assertEqual(status, 401)
            self.assertEqual(body["error"], "Wrong username or password")
        auth.LIMITER.failures.clear()

    def test_rate_limit(self):
        auth.LIMITER.failures.clear()
        for _ in range(auth.FAIL_FREE_ATTEMPTS):
            request("POST", "/api/auth/login", {"username": TEST_USER, "password": "wrong password!"}, session=False)
        status, body, _ = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
        self.assertEqual(status, 429)
        self.assertIn("Too many failed attempts", body["error"])
        auth.LIMITER.failures.clear()
        self.assertEqual(request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)[0], 200)

    def test_failed_login_audited_without_password(self):
        auth.LIMITER.failures.clear()
        request("POST", "/api/auth/login", {"username": TEST_USER, "password": "audit-probe-secret"}, session=False)
        auth.LIMITER.failures.clear()
        logs = database.list_audit_logs(limit=500)   # other tests may write many rows in the same second
        self.assertTrue(any(l["category"] == "auth" and l["message"] == "Failed login" for l in logs))
        self.assertNotIn("audit-probe-secret", repr(logs))


class ConfirmationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def expire_confirmation(self):
        with auth.SESSIONS.lock:
            for s in auth.SESSIONS.sessions.values():
                s["tier2_until"] = s["tier3_until"] = 0

    def test_sensitive_routes_need_recent_password(self):
        self.expire_confirmation()
        cred = {"name": "confirm-test", "cred_type": "password", "username": "root", "secret": "pw-confirm-test"}
        status, body, _ = request("POST", "/api/credentials", cred)
        # Credentials are tier 3; without 2FA the password alone confirms, and the reply suggests 2FA.
        self.assertEqual((status, body["auth"], body["tier"], body["mfa"], body["suggest_2fa"]), (403, "confirm", 3, False, True))
        self.assertEqual(request("POST", "/api/auth/confirm", {"password": "wrong password!", "tier": 3})[0], 401)
        auth.LIMITER.failures.clear()
        # A tier 2 confirmation does not open a tier 3 route.
        self.assertEqual(request("POST", "/api/auth/confirm", {"password": TEST_PASSWORD, "tier": 2})[0], 200)
        self.assertEqual(request("POST", "/api/credentials", cred)[0], 403)
        self.assertEqual(request("POST", "/api/auth/confirm", {"password": TEST_PASSWORD, "tier": 3})[0], 200)
        self.assertEqual(request("POST", "/api/credentials", cred)[0], 201)
        self.assertEqual(server.rbac.route_tier("DELETE", "/api/devices/4"), 2)
        self.assertEqual(server.rbac.route_tier("GET", "/api/devices/4"), 1)
        # Ordinary routes never ask.
        self.expire_confirmation()
        self.assertEqual(request("GET", "/api/credentials")[0], 200)
        for method, path in (("POST", "/api/workflows/1/run"), ("POST", "/api/credentials"), ("PUT", "/api/credentials/3"),
                             ("POST", "/api/devices/4/hostkey")):
            self.assertTrue(server.needs_confirmation(method, path), path)
        self.assertFalse(server.needs_confirmation("GET", "/api/credentials"))
        login()


class LimiterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def tearDown(self):
        auth.LIMITER.failures.clear()

    def test_per_username_lockout_across_addresses(self):
        auth.LIMITER.failures.clear()
        for i in range(auth.FAIL_FREE_ATTEMPTS + 1):
            auth.LIMITER.failed(f"192.0.2.{i + 1}", TEST_USER)
        self.assertGreater(auth.LIMITER.locked_for("198.51.100.9", TEST_USER), 0)
        self.assertEqual(auth.LIMITER.locked_for("198.51.100.9"), 0)                 # the address alone is not
        self.assertEqual(auth.LIMITER.locked_for("198.51.100.9", "someone-else"), 0)
        status, body, _ = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
        self.assertEqual(status, 429, body)

    def test_entries_are_pruned_and_capped(self):
        import time
        from unittest import mock
        auth.LIMITER.failures.clear()
        auth.LIMITER.failures["203.0.113.1"] = [time.time() - auth.FAIL_WINDOW_SECONDS - 5]
        auth.LIMITER.failed("203.0.113.2")
        self.assertNotIn("203.0.113.1", auth.LIMITER.failures)
        for _ in range(100):
            auth.LIMITER.failed("203.0.113.3")
        self.assertLessEqual(len(auth.LIMITER.failures["203.0.113.3"]), auth.FAIL_FREE_ATTEMPTS + 20)
        with mock.patch.object(auth, "MAX_TRACKED", 5):
            for i in range(20):
                auth.LIMITER.failed(f"203.0.113.{i + 10}", f"user{i}")
            self.assertLessEqual(len(auth.LIMITER.failures), 5)

    def test_password_change_respects_the_lockout(self):
        auth.LIMITER.failures.clear()
        for _ in range(auth.FAIL_FREE_ATTEMPTS + 1):
            auth.LIMITER.failed("192.0.2.77", TEST_USER)
        status, body, _ = request("POST", "/api/auth/password", {"current": TEST_PASSWORD, "new": "a different passphrase"})
        self.assertEqual(status, 429, body)
        auth.LIMITER.failures.clear()
        # A wrong current password counts against the username as well.
        for _ in range(auth.FAIL_FREE_ATTEMPTS + 1):
            request("POST", "/api/auth/password", {"current": "nope nope nope", "new": "x" * 20})
        self.assertGreater(auth.LIMITER.locked_for("198.51.100.1", TEST_USER), 0)

    def test_busy_hashing_answers_503(self):
        import threading
        from unittest import mock
        auth.LIMITER.failures.clear()
        full = threading.BoundedSemaphore(1)
        full.acquire()
        with mock.patch.object(auth, "HASH_SLOTS", full), mock.patch.object(auth, "HASH_WAIT_SECONDS", 0.05):
            status, body, _ = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
            self.assertEqual((status, body["error"]), (503, "Busy, try again in a moment"))
            self.assertEqual(request("POST", "/api/auth/confirm", {"password": TEST_PASSWORD})[0], 503)
            self.assertEqual(request("POST", "/api/auth/password", {"current": TEST_PASSWORD, "new": "x" * 20})[0], 503)
        self.assertEqual(auth.LIMITER.locked_for("127.0.0.1", TEST_USER), 0)         # not counted as a failure
        self.assertEqual(auth.LIMITER.failures, {})
        # At most two checks at once; slots are given back.
        self.assertTrue(auth.verify_password("x", auth.hash_password("x")))
        self.assertTrue(auth.HASH_SLOTS.acquire(timeout=0.1) and auth.HASH_SLOTS.acquire(timeout=0.1))
        self.assertFalse(auth.HASH_SLOTS.acquire(timeout=0.05))
        auth.HASH_SLOTS.release()
        auth.HASH_SLOTS.release()

    def test_reserve_is_atomic(self):
        import threading
        auth.LIMITER.failures.clear()
        got, start = [], threading.Barrier(50)

        def one():
            start.wait()
            got.append(auth.LIMITER.reserve("192.0.2.60", "reserve-user"))
        threads = [threading.Thread(target=one) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for w in got if w == 0), auth.FAIL_FREE_ATTEMPTS)
        self.assertEqual(len(auth.LIMITER.failures["user:reserve-user"]), auth.FAIL_FREE_ATTEMPTS)

    def test_refund_removes_one(self):
        auth.LIMITER.failures.clear()
        auth.LIMITER.failed("192.0.2.61", "refund-user")
        auth.LIMITER.reserve("192.0.2.61", "refund-user")
        auth.LIMITER.refund("192.0.2.61", "refund-user")
        self.assertEqual(len(auth.LIMITER.failures["192.0.2.61"]), 1)
        self.assertEqual(len(auth.LIMITER.failures["user:refund-user"]), 1)
        auth.LIMITER.refund("192.0.2.61", "refund-user")
        self.assertEqual(auth.LIMITER.failures, {})                                    # an empty key is deleted

    def test_password_only_login_clears_as_before(self):
        auth.LIMITER.failures.clear()
        for _ in range(3):
            request("POST", "/api/auth/login", {"username": TEST_USER, "password": "wrong password!"}, session=False)
        self.assertEqual(len(auth.LIMITER.failures["user:" + TEST_USER]), 3)
        status, body, headers = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
        self.assertEqual((status, body.get("success")), (200, True))
        self.assertIsNotNone(session_cookie(headers))
        self.assertEqual(auth.LIMITER.failures, {})


class PasswordChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_change_logs_out_other_sessions(self):
        _, _, headers = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
        other = {"Cookie": f"{auth.SESSION_COOKIE}={session_cookie(headers)}"}
        self.assertEqual(request("POST", "/api/auth/password", {"current": "nope nope nope", "new": "x" * 20})[0], 401)
        auth.LIMITER.failures.clear()
        self.assertEqual(request("POST", "/api/auth/password", {"current": TEST_PASSWORD, "new": "short"})[0], 400)
        self.assertEqual(request("POST", "/api/auth/password", {"current": TEST_PASSWORD, "new": "a different passphrase"})[0], 200)
        self.assertEqual(request("GET", "/api/devices")[0], 200)                       # this session survives
        self.assertEqual(request("GET", "/api/devices", headers=other, session=False)[0], 401)  # others end
        request("POST", "/api/auth/password", {"current": "a different passphrase", "new": TEST_PASSWORD})
        self.assertNotIn(b"a different passphrase", raw_bytes())
        login()


class LockoutAlertTests(unittest.TestCase):
    """A lockout is audited and alerted once per target, with an hourly ceiling (REV-09)."""

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        self.calls = []
        p = mock.patch.object(server.NOTIFIER, "security", side_effect=lambda key, **kw: self.calls.append(kw.get("target")))
        p.start()
        self.addCleanup(p.stop)
        server._LOCKOUT["sent"].clear()
        server._LOCKOUT["hour"].clear()
        self.limiter = auth.LoginLimiter()
        self.limiter.on_lockout = server._lockout_alert

    def lock(self, client, user=None):
        for _ in range(auth.FAIL_FREE_ATTEMPTS):
            self.limiter.failed(client, user)

    def test_lockout_alert_once_per_target(self):
        self.lock("192.0.2.30", TEST_USER)
        self.limiter.failed("192.0.2.30", TEST_USER)
        self.limiter.succeeded("192.0.2.30", TEST_USER)
        self.lock("192.0.2.30", TEST_USER)
        self.assertEqual(self.calls, [TEST_USER])

    def test_lockout_alert_hourly_ceiling(self):
        for i in range(server.LOCKOUT_ALERTS_PER_HOUR + 5):
            self.lock(f"198.51.100.{i + 1}")
        self.assertEqual(len(self.calls), server.LOCKOUT_ALERTS_PER_HOUR)

    def test_unknown_name_alerts_the_address_only(self):
        self.lock("192.0.2.31", "no-such-user-xyz")
        self.assertEqual(self.calls, ["192.0.2.31"])
        self.assertNotIn("no-such-user-xyz", str(database.list_audit_filtered(q="Login lockout started")[0][:2]))

    def test_reserve_reports_lockout(self):
        for _ in range(auth.FAIL_FREE_ATTEMPTS):
            self.limiter.reserve("192.0.2.32", None)
        self.assertEqual(self.calls, ["192.0.2.32"])

    def test_lockout_is_audited(self):
        self.lock("192.0.2.33", None)
        rows = database.list_audit_filtered(q="192.0.2.33")[0]
        self.assertEqual([(r["message"], r["details"]) for r in rows], [("Login lockout started", "192.0.2.33")])


if __name__ == "__main__":
    unittest.main()
