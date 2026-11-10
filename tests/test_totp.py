"""2FA: TOTP and recovery codes, the QR encoder, login with a code, step-up tiers, password recovery."""

import threading
import time
import types
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import request, session_cookie, start_api_server

import auth
import database
import server
import totp

PASSWORD = "two factor test passphrase"


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        # RFC 6238 appendix B, SHA-1, secret "12345678901234567890", 8 digits.
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        for t, code in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")):
            self.assertEqual(totp.hotp(secret, t // 30, 8), code)

    def test_verify_drift_and_replay(self):
        s = totp.new_secret()
        now = 1_700_000_000
        code = totp.code_at(s, now)
        step = totp.verify(s, code, when=now)
        self.assertEqual(step, now // 30)
        self.assertIsNotNone(totp.verify(s, totp.code_at(s, now - 30), when=now))     # one step behind
        self.assertIsNone(totp.verify(s, totp.code_at(s, now - 90), when=now))        # too old
        self.assertIsNone(totp.verify(s, code, when=now, last_step=step))             # no replay
        self.assertIsNone(totp.verify(s, "12a", when=now))

    def test_recovery_codes(self):
        codes = totp.new_recovery_codes()
        self.assertEqual(len(codes), 8)
        hashes = [totp.hash_recovery(c) for c in codes]
        self.assertEqual(totp.match_recovery(codes[3].lower().replace("-", " "), hashes), 3)
        self.assertIsNone(totp.match_recovery("AAAA-AAAA", hashes))
        self.assertNotIn(codes[0], "".join(hashes))

    def test_uri(self):
        uri = totp.otpauth_uri("ABCDEF", "ann")
        self.assertTrue(uri.startswith("otpauth://totp/Homelab%20Monitor:ann?secret=ABCDEF&issuer=Homelab%20Monitor"))


class QrTests(unittest.TestCase):
    def test_reed_solomon_vector(self):
        # ISO 18004 / thonky.com worked example, version 1-M.
        data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
        self.assertEqual(totp.rs_encode(data, 10), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23])

    def test_format_and_version_bits(self):
        # Level M mask 0 and version 7 from the specification tables.
        self.assertEqual(totp.format_bits(0), 0b101010000010010)
        self.assertEqual(totp.version_bits(7), 0b000111110010010100)

    def test_round_trip_every_version(self):
        for n in (1, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213):
            text = ("otpauth://totp/x?secret=" + "A" * 300)[:n]
            m = totp.qr_matrix(text)
            version = (len(m) - 17) // 4
            mask, decoded = totp.decode_matrix(m)
            self.assertEqual(decoded, text, version)
            # Finder patterns in the three corners.
            for r, c in ((0, 0), (0, len(m) - 7), (len(m) - 7, 0)):
                self.assertEqual([m[r][c + i] for i in range(7)], [1] * 7)
        with self.assertRaises(ValueError):
            totp.qr_matrix("x" * 214)

    def test_svg(self):
        svg = totp.qr_svg("hello")
        self.assertTrue(svg.startswith("<svg") and "<path" in svg and "script" not in svg)


def login_as(username, password=PASSWORD):
    return request("POST", "/api/auth/login", {"username": username, "password": password}, session=False)


def as_user(cookie, method, path, body=None):
    return request(method, path, body, headers={"Cookie": f"{auth.SESSION_COOKIE}={cookie}"}, session=False)


class TwoFactorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    @classmethod
    def tearDownClass(cls):
        # Other suites rely on the test user being the only administrator (last-admin protection).
        for name in ("mfa1", "mfa2", "mfa3", "mfa4", "mfa5", "mfa6", "mfa7", "mfa8", "mfa9", "mfa10", "mfa11",
                     "mfa12", "mfa13", "mfa14", "mfa15"):
            database.delete_user(name)
        auth.LIMITER.failures.clear()

    def make_user(self, name):
        status, body, _ = request("POST", "/api/users", {"username": name, "password": PASSWORD, "role": "admin"})
        self.assertEqual(status, 201, body)
        status, body, headers = login_as(name)
        self.assertEqual(status, 200)
        return session_cookie(headers)

    def enable(self, cookie):
        status, body, _ = as_user(cookie, "POST", "/api/auth/2fa/start", {})
        self.assertEqual(status, 200, body)
        self.assertIn("<svg", body["svg"])
        secret = body["secret"].replace(" ", "")
        status, res, _ = as_user(cookie, "POST", "/api/auth/2fa/enable", {"code": "000000"})
        self.assertEqual(status, 400)
        auth.LIMITER.failures.clear()
        status, res, _ = as_user(cookie, "POST", "/api/auth/2fa/enable", {"code": totp.code_at(secret)})
        self.assertEqual(status, 200, res)
        self.assertEqual(len(res["recovery_codes"]), 8)
        return secret, res["recovery_codes"]

    def test_login_needs_the_code(self):
        cookie = self.make_user("mfa1")
        secret, codes = self.enable(cookie)
        self.assertNotIn(secret, repr(database.list_users()))          # stored encrypted only
        status, body, headers = login_as("mfa1")
        self.assertEqual((status, body.get("mfa_required")), (200, True))
        self.assertIsNone(session_cookie(headers))                      # no session before the code
        ch = body["challenge"]
        self.assertEqual(request("POST", "/api/auth/login/mfa", {"challenge": ch, "code": "123456"}, session=False)[0], 401)
        auth.LIMITER.failures.clear()
        # A recovery code works once.
        status, _, headers = request("POST", "/api/auth/login/mfa", {"challenge": ch, "code": codes[0]}, session=False)
        self.assertEqual(status, 200)
        self.assertIsNotNone(session_cookie(headers))
        ch = login_as("mfa1")[1]["challenge"]
        self.assertEqual(request("POST", "/api/auth/login/mfa", {"challenge": ch, "code": codes[0]}, session=False)[0], 401)
        auth.LIMITER.failures.clear()
        # The current code is accepted once (replay refused).
        with mock.patch.object(totp.time, "time", return_value=__import__("time").time() + 30):
            status, _, _ = request("POST", "/api/auth/login/mfa", {"challenge": ch, "code": totp.code_at(secret)}, session=False)
        self.assertEqual(status, 200)

    def test_tier3_asks_for_the_code(self):
        cookie = self.make_user("mfa2")
        secret, _ = self.enable(cookie)
        with auth.SESSIONS.lock:
            for s in auth.SESSIONS.sessions.values():
                if s["username"] == "mfa2":
                    s["tier2_until"] = s["tier3_until"] = 0
        status, body, _ = as_user(cookie, "POST", "/api/credentials", {"name": "t3", "cred_type": "password", "username": "r", "secret": "x"})
        self.assertEqual((status, body["tier"], body["mfa"]), (403, 3, True))
        self.assertEqual(as_user(cookie, "POST", "/api/auth/confirm", {"password": PASSWORD, "tier": 3})[0], 401)
        auth.LIMITER.failures.clear()
        with mock.patch.object(totp.time, "time", return_value=__import__("time").time() + 60):
            self.assertEqual(as_user(cookie, "POST", "/api/auth/confirm",
                                     {"password": PASSWORD, "tier": 3, "code": totp.code_at(secret)})[0], 200)
        self.assertEqual(as_user(cookie, "POST", "/api/credentials", {"name": "t3", "cred_type": "password", "username": "r", "secret": "x"})[0], 201)
        # Disabling needs tier 3 too (satisfied now), then login no longer asks for a code.
        self.assertEqual(as_user(cookie, "POST", "/api/auth/2fa/disable", {})[0], 200)
        self.assertTrue(login_as("mfa2")[1].get("success"))

    def test_admin_reset(self):
        cookie = self.make_user("mfa3")
        self.enable(cookie)
        self.assertEqual(request("POST", "/api/users/mfa3/2fa-reset", {})[0], 200)
        self.assertFalse(database.get_totp("mfa3")["enabled"])
        self.assertTrue(login_as("mfa3")[1].get("success"))

    def test_enable_and_disable_log_out_other_sessions(self):
        cookie = self.make_user("mfa5")
        other = session_cookie(login_as("mfa5")[2])
        self.assertEqual(as_user(other, "GET", "/api/devices")[0], 200)
        secret, _ = self.enable(cookie)
        self.assertEqual(as_user(other, "GET", "/api/devices")[0], 401)       # the other session ended
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)      # this one is kept
        status, body, _ = login_as("mfa5")
        with mock.patch.object(totp.time, "time", return_value=__import__("time").time() + 30):
            status, _, headers = request("POST", "/api/auth/login/mfa", {"challenge": body["challenge"], "code": totp.code_at(secret)},
                                         session=False)
        self.assertEqual(status, 200)
        other = session_cookie(headers)
        self.assertEqual(as_user(cookie, "POST", "/api/auth/2fa/disable", {})[0], 200)
        self.assertEqual(as_user(other, "GET", "/api/devices")[0], 401)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)

    def test_code_and_recovery_code_used_once_even_in_parallel(self):
        cookie = self.make_user("mfa6")
        secret, codes = self.enable(cookie)
        t = database.get_totp("mfa6")
        step = t["last_step"] + 1
        # Two requests that both passed totp.verify: only the first conditional update wins.
        self.assertTrue(database.consume_totp_step("mfa6", step))
        self.assertFalse(database.consume_totp_step("mfa6", step))
        self.assertFalse(database.consume_totp_step("mfa6", step - 1))
        h = t["recovery"][0]
        self.assertEqual(database.consume_recovery_code("mfa6", h), len(codes) - 1)
        self.assertIsNone(database.consume_recovery_code("mfa6", h))
        # The same check through second_factor_ok when the stored state was read before the other request wrote.
        stale = database.get_totp("mfa6")
        database.consume_recovery_code("mfa6", stale["recovery"][0])
        with mock.patch.object(database, "get_totp", return_value=stale):
            self.assertFalse(server.second_factor_ok("mfa6", codes[1]))

    def test_enable_respects_the_lockout(self):
        auth.LIMITER.failures.clear()
        for _ in range(auth.FAIL_FREE_ATTEMPTS + 1):
            auth.LIMITER.failed("192.0.2.1", "tester")
        status, body, _ = request("POST", "/api/auth/2fa/enable", {"code": "000000"})
        self.assertEqual(status, 429, body)
        auth.LIMITER.failures.clear()

    def test_password_recovery(self):
        cookie = self.make_user("mfa4")
        secret, _ = self.enable(cookie)
        database.update_setting("telegram_enabled", "on")
        database.update_setting("telegram_token", "123:abc")
        database.update_setting("telegram_chat_id", "42")
        sent = []
        try:
            self.assertTrue(request("GET", "/api/auth/status", session=False)[1]["recovery"])
            with mock.patch.object(server.notify, "send", side_effect=lambda t, c, text: sent.append(text)):
                self.assertEqual(request("POST", "/api/auth/recover/start", {"username": "mfa4", "code": "000000"}, session=False)[0], 401)
                self.assertEqual(request("POST", "/api/auth/recover/start", {"username": "nobody", "code": "000000"}, session=False)[0], 401)
                auth.LIMITER.failures.clear()
                with mock.patch.object(totp.time, "time", return_value=__import__("time").time() + 90):
                    status, body, _ = request("POST", "/api/auth/recover/start",
                                              {"username": "mfa4", "code": totp.code_at(secret)}, session=False)
            self.assertEqual(status, 200, body)
            code = sent[0].split(": ")[1][:8]
            ticket = body["ticket"]
            self.assertEqual(request("POST", "/api/auth/recover/finish", {"username": "mfa4", "ticket": ticket,
                                                                          "telegram_code": "00000000", "new": "a new long password"}, session=False)[0], 401)
            auth.LIMITER.failures.clear()
            self.assertEqual(request("POST", "/api/auth/recover/finish", {"username": "mfa4", "ticket": ticket,
                                                                          "telegram_code": code, "new": "a new long password"}, session=False)[0], 200)
            self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 401)       # old sessions ended
            self.assertEqual(login_as("mfa4", "a new long password")[1].get("mfa_required"), True)
            # The ticket is single use.
            self.assertEqual(request("POST", "/api/auth/recover/finish", {"username": "mfa4", "ticket": ticket,
                                                                          "telegram_code": code, "new": "another long one"}, session=False)[0], 401)
            auth.LIMITER.failures.clear()
        finally:
            database.update_setting("telegram_enabled", "off")

    # --- Lockout with a second factor (MUST-3) ---

    def mfa_user(self, name):
        cookie = self.make_user(name)
        secret, codes = self.enable(cookie)
        auth.LIMITER.failures.clear()
        return secret, codes

    @staticmethod
    def code(challenge, code):
        return request("POST", "/api/auth/login/mfa", {"challenge": challenge, "code": code}, session=False)

    @staticmethod
    def right_code(secret, ahead):
        """A current code from a later time step, so earlier steps used by the test are not a replay."""
        with mock.patch.object(totp.time, "time", return_value=time.time() + ahead):
            return totp.code_at(secret)

    def test_lockout_doubles_across_challenges(self):
        self.mfa_user("mfa7")
        clock = [time.time()]
        fake = types.SimpleNamespace(time=lambda: clock[0])
        with mock.patch.object(auth, "time", fake), mock.patch.object(server, "second_factor_ok", return_value=False):
            ch = login_as("mfa7")[1]["challenge"]
            for _ in range(auth.FAIL_FREE_ATTEMPTS):
                clock[0] += 1
                self.assertEqual(self.code(ch, "123456")[0], 401)
            clock[0] += 1
            status, body, _ = self.code(ch, "123456")
            self.assertEqual(status, 429, body)                         # locked out before 30 s
            clock[0] += auth.LOCK_BASE_SECONDS + 1
            status, body, _ = login_as("mfa7")                          # the password still works
            self.assertEqual(status, 200, body)
            self.assertEqual(self.code(body["challenge"], "123456")[0], 401)
            wait = auth.LIMITER.locked_for("198.51.100.7", "mfa7")
            self.assertGreater(wait, auth.LOCK_BASE_SECONDS)            # the second cycle waits longer
            status, body, _ = login_as("mfa7")
            self.assertEqual(status, 429, body)
            self.assertGreater(int(body["error"].split(" in ")[1].split()[0]), auth.LOCK_BASE_SECONDS)
        auth.LIMITER.failures.clear()

    def test_right_password_does_not_clear_code_failures(self):
        self.mfa_user("mfa8")
        ch = login_as("mfa8")[1]["challenge"]
        for _ in range(3):
            self.assertEqual(self.code(ch, "123456")[0], 401)
        self.assertEqual(login_as("mfa8")[0], 200)
        self.assertEqual(len(auth.LIMITER.failures["user:mfa8"]), 3)
        auth.LIMITER.failures.clear()

    def test_parallel_codes_are_limited(self):
        self.mfa_user("mfa9")
        ch = login_as("mfa9")[1]["challenge"]
        calls, statuses, start = [], [], threading.Barrier(12)

        def slow_refusal(username, code):
            calls.append(code)
            time.sleep(0.05)
            return False

        def one():
            start.wait()
            statuses.append(self.code(ch, "123456")[0])
        with mock.patch.object(server, "second_factor_ok", side_effect=slow_refusal):
            threads = [threading.Thread(target=one) for _ in range(12)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertLessEqual(len(calls), auth.FAIL_FREE_ATTEMPTS)
        self.assertEqual(len(statuses), 12)
        self.assertTrue(all(s in (401, 429) for s in statuses), statuses)
        auth.LIMITER.failures.clear()

    def test_full_login_clears_counters(self):
        secret, _ = self.mfa_user("mfa10")
        ch = login_as("mfa10")[1]["challenge"]
        self.assertEqual(self.code(ch, "123456")[0], 401)
        ch = login_as("mfa10")[1]["challenge"]
        status, body, headers = self.code(ch, self.right_code(secret, 30))
        self.assertEqual(status, 200, body)
        self.assertIsNotNone(session_cookie(headers))
        self.assertNotIn("user:mfa10", auth.LIMITER.failures)
        self.assertNotIn("127.0.0.1", auth.LIMITER.failures)

    def test_new_challenge_voids_the_old_one(self):
        secret, _ = self.mfa_user("mfa11")
        first = login_as("mfa11")[1]["challenge"]
        second = login_as("mfa11")[1]["challenge"]
        right = self.right_code(secret, 30)
        status, body, _ = self.code(first, right)
        self.assertEqual(status, 401, body)
        self.assertIn("expired", body["error"])
        self.assertEqual(self.code(second, right)[0], 200)
        auth.LIMITER.failures.clear()

    def telegram_on(self):
        database.update_setting("telegram_enabled", "on")
        database.update_setting("telegram_token", "123:abc")
        database.update_setting("telegram_chat_id", "42")
        self.addCleanup(database.update_setting, "telegram_enabled", "off")

    def recover_start(self, name, code, sent=None):
        with mock.patch.object(server.notify, "send", side_effect=lambda t, c, text: (sent if sent is not None else []).append(text)):
            return request("POST", "/api/auth/recover/start", {"username": name, "code": code}, session=False)

    def test_recover_start_counts_towards_lockout(self):
        self.mfa_user("mfa12")
        self.telegram_on()
        with mock.patch.object(server, "second_factor_ok", return_value=False):
            for _ in range(auth.FAIL_FREE_ATTEMPTS):
                self.assertEqual(self.recover_start("mfa12", "123456")[0], 401)
            self.assertEqual(self.recover_start("mfa12", "123456")[0], 429)
        status, body, _ = login_as("mfa12")
        self.assertEqual(status, 429, body)
        auth.LIMITER.failures.clear()

    def test_recover_start_success_is_not_charged(self):
        secret, _ = self.mfa_user("mfa13")
        self.telegram_on()
        auth.LIMITER.failed("198.51.100.13", "mfa13")
        auth.LIMITER.failed("198.51.100.13", "mfa13")
        status, body, _ = self.recover_start("mfa13", self.right_code(secret, 30))
        self.assertEqual(status, 200, body)
        self.assertEqual(len(auth.LIMITER.failures["user:mfa13"]), 2)
        auth.LIMITER.failures.clear()

    def finish_after(self, name, change):
        """Starts a recovery, applies change to the account, then tries to finish it."""
        secret, _ = self.mfa_user(name)
        self.telegram_on()
        sent = []
        status, body, _ = self.recover_start(name, self.right_code(secret, 30), sent)
        self.assertEqual(status, 200, body)
        before = database.get_user(name)["password_hash"]
        change()
        status, body, _ = request("POST", "/api/auth/recover/finish", {
            "username": name, "ticket": body["ticket"], "telegram_code": sent[0].split(": ")[1][:8],
            "new": "a brand new passphrase"}, session=False)
        self.assertEqual(status, 401, body)
        self.assertEqual(body["error"], "That code is wrong or has expired")
        self.assertEqual(database.get_user(name)["password_hash"], before)
        auth.LIMITER.failures.clear()

    def test_recover_finish_refuses_blocked_account(self):
        self.finish_after("mfa14", lambda: database.update_user("mfa14", {"disabled": 1}))
        logs, _ = database.list_audit_filtered(q="Password recovery refused at the last step", category="auth")
        self.assertTrue(any("User mfa14: blocked or two-factor authentication off" in l["details"] for l in logs), logs)

    def test_recover_finish_refuses_2fa_off(self):
        self.finish_after("mfa15", lambda: database.set_totp("mfa15", None, False))


def name_of(cookie):
    return auth.SESSIONS.get(cookie)["username"]


class RequireTwoFactorTests(unittest.TestCase):
    """Settings, Login security (REV-10): enrolment forced after the password, tier 3 needs 2FA,
    and the last administrator is never locked out."""

    USERS = ("rq-admin", "rq-admin2", "rq-viewer", "rq-custom", "rq-mfa")

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        for name in self.USERS:
            database.delete_user(name)
        auth.LIMITER.failures.clear()

    def tearDown(self):
        database.set_internal_setting("require_2fa", "off")
        for name in self.USERS:
            database.delete_user(name)
        auth.LIMITER.failures.clear()

    @staticmethod
    def rule(value):
        database.set_internal_setting("require_2fa", value)

    @staticmethod
    def expire(username):
        """The confirmation has lapsed: a tier 3 route asks again."""
        with auth.SESSIONS.lock:
            for sess in auth.SESSIONS.sessions.values():
                if sess["username"] == username:
                    sess["tier2_until"] = sess["tier3_until"] = 0

    def make(self, name, role="admin", perms=None, with_2fa=False):
        import json as _json
        database.create_user(name, auth.hash_password(PASSWORD), role, _json.dumps(perms) if perms else None, None, None)
        secret = None
        if with_2fa:
            secret = totp.new_secret()
            database.set_totp(name, secret, True, [])
        return secret

    def session(self, name, secret=None):
        status, body, headers = login_as(name)
        self.assertEqual(status, 200, body)
        if body.get("mfa_required"):
            _, body, headers = request("POST", "/api/auth/login/mfa", {"challenge": body["challenge"],
                                                                       "code": totp.code_at(secret, time.time())}, session=False)
        return session_cookie(headers), body

    def enrol(self, cookie):
        start = as_user(cookie, "POST", "/api/auth/2fa/start", {})
        self.assertEqual(start[0], 200, start[1])
        secret = start[1]["secret"].replace(" ", "")
        done = as_user(cookie, "POST", "/api/auth/2fa/enable", {"code": totp.code_at(secret, time.time())})
        self.assertEqual(done[0], 200, done[1])
        return secret

    def test_enrolment_is_forced_after_the_password(self):
        self.make("rq-admin")
        self.rule("admins")
        cookie, body = self.session("rq-admin")
        self.assertIs(body["enrol_2fa"], True)
        status, body, _ = as_user(cookie, "GET", "/api/devices")
        self.assertEqual((status, body.get("auth"), body["error"]), (403, "enrol", server.ENROL_TEXT))
        self.assertIs(as_user(cookie, "GET", "/api/auth/status")[1]["enrol_2fa"], True)
        self.enrol(cookie)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)

    def test_open_session_is_caught(self):
        self.make("rq-admin")
        cookie, _ = self.session("rq-admin")
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)
        self.rule("admins")
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[1].get("auth"), "enrol")

    def test_only_enrolment_routes_are_open(self):
        self.make("rq-admin")
        self.rule("all")
        cookie, _ = self.session("rq-admin")
        for method, path in (("GET", "/api/devices"), ("GET", "/api/settings"), ("POST", "/api/settings"),
                             ("GET", "/api/audit"), ("POST", "/api/credentials"), ("DELETE", "/api/devices/1"),
                             ("PUT", "/api/devices/1"), ("POST", "/api/auth/password"), ("POST", "/api/auth/2fa/disable"),
                             ("GET", "/api/users"), ("POST", "/api/users")):
            with self.subTest(path=path, method=method):
                status, body, _ = as_user(cookie, method, path, {} if method in ("POST", "PUT") else None)
                self.assertEqual((status, body.get("auth")), (403, "enrol"))
        self.assertEqual(as_user(cookie, "GET", "/api/auth/2fa")[0], 200)
        self.assertEqual(as_user(cookie, "POST", "/api/auth/logout", {})[0], 200)

    def test_admins_rule_leaves_a_viewer_free(self):
        self.make("rq-viewer", "viewer")
        self.rule("admins")
        cookie, body = self.session("rq-viewer")
        self.assertIs(body["enrol_2fa"], False)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)

    def test_all_rule_covers_a_viewer(self):
        self.make("rq-viewer", "viewer")
        self.rule("all")
        cookie, _ = self.session("rq-viewer")
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[1].get("auth"), "enrol")

    def test_user_with_2fa_is_not_stopped(self):
        secret = self.make("rq-mfa", with_2fa=True)
        self.rule("all")
        cookie, body = self.session("rq-mfa", secret)
        self.assertEqual(body.get("success"), True, body)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)

    def test_tier3_needs_2fa_when_on(self):
        self.make("rq-custom", "custom", ["credentials.manage"])
        cookie, _ = self.session("rq-custom")
        self.expire(name_of(cookie))
        body = {"name": "rq-cred", "cred_type": "password", "username": "root", "secret": "x"}
        status, res, _ = as_user(cookie, "POST", "/api/credentials", body)
        self.assertEqual((status, res.get("auth")), (403, "confirm"))       # rule off: the prompt as before
        self.rule("admins")
        status, res, _ = as_user(cookie, "POST", "/api/credentials", body)
        self.assertEqual((status, res.get("auth"), res["error"]), (403, None, server.TIER3_NEEDS_2FA_TEXT))

    def test_fresh_password_grant_does_not_pass_tier3(self):
        self.make("rq-custom", "custom", ["credentials.manage"])
        self.rule("admins")
        cookie, _ = self.session("rq-custom")
        self.assertGreater(auth.SESSIONS.get(cookie)["tier3_until"], time.time())
        status, res, _ = as_user(cookie, "POST", "/api/credentials", {"name": "rq-cred", "cred_type": "password",
                                                                      "username": "root", "secret": "x"})
        self.assertEqual((status, res["error"]), (403, server.TIER3_NEEDS_2FA_TEXT))
        self.assertIsNone(next((c for c in database.list_credentials() if c["name"] == "rq-cred"), None))

    def test_2fa_start_is_open_for_enrolment(self):
        self.make("rq-custom", "custom", ["credentials.manage"])
        self.rule("all")
        cookie, _ = self.session("rq-custom")
        self.assertEqual(as_user(cookie, "POST", "/api/auth/2fa/start", {})[0], 200)
        self.assertEqual(as_user(cookie, "POST", "/api/credentials", {"name": "x", "cred_type": "password", "secret": "x"})[1]
                         .get("auth"), "enrol")

    def test_user_with_2fa_keeps_tier3(self):
        secret = self.make("rq-mfa", "custom", ["credentials.manage"], with_2fa=True)
        self.rule("admins")
        cookie, _ = self.session("rq-mfa", secret)
        self.expire(name_of(cookie))
        status, res, _ = as_user(cookie, "POST", "/api/credentials", {"name": "rq-cred", "cred_type": "password",
                                                                      "username": "root", "secret": "x"})
        self.assertEqual((status, res.get("auth"), res.get("mfa")), (403, "confirm", True))

    def test_cannot_turn_on_without_own_2fa(self):
        status, body, _ = request("POST", "/api/settings", {"require_2fa": "admins"})
        self.assertEqual(status, 409, body)
        self.assertIn("your own account first", body["error"])
        self.assertEqual(server.two_factor_rule(), "off")

    def test_cannot_turn_on_without_an_admin_with_2fa(self):
        secret = self.make("rq-custom", "custom", ["settings.system"], with_2fa=True)
        cookie, _ = self.session("rq-custom", secret)
        status, body, _ = as_user(cookie, "POST", "/api/settings", {"require_2fa": "admins"})
        self.assertEqual(status, 409, body)
        self.assertIn("At least one administrator", body["error"])
        self.assertEqual(server.two_factor_rule(), "off")
        # With an administrator who has it, the same person may turn it on.
        self.make("rq-admin2", with_2fa=True)
        self.assertEqual(as_user(cookie, "POST", "/api/settings", {"require_2fa": "admins"})[0], 200)
        self.assertEqual(server.two_factor_rule(), "admins")

    def test_turning_on_asks_tier3(self):
        secret = self.make("rq-admin", with_2fa=True)
        cookie, _ = self.session("rq-admin", secret)
        self.expire(name_of(cookie))
        status, body, _ = as_user(cookie, "POST", "/api/settings", {"require_2fa": "admins"})
        self.assertEqual((status, body.get("auth"), body.get("tier")), (403, "confirm", 3))
        self.assertEqual(server.two_factor_rule(), "off")

    def test_disable_refused_while_required(self):
        secret = self.make("rq-admin", with_2fa=True)
        cookie, _ = self.session("rq-admin", secret)
        self.rule("admins")
        status, body, _ = as_user(cookie, "POST", "/api/auth/2fa/disable", {})
        self.assertEqual(status, 409, body)
        self.assertTrue(database.get_totp("rq-admin")["enabled"])
        self.rule("off")
        self.assertEqual(as_user(cookie, "POST", "/api/auth/2fa/disable", {})[0], 200)

    def test_last_admin_can_enrol_and_log_out(self):
        from tests.helpers import TEST_USER
        self.rule("all")
        try:
            cookie, body = self.session_of_test_user()
            self.assertIs(body["enrol_2fa"], True)
            self.assertEqual(as_user(cookie, "GET", "/api/devices")[1].get("auth"), "enrol")
            self.assertEqual(as_user(cookie, "POST", "/api/auth/2fa/start", {})[0], 200)
            self.assertEqual(as_user(cookie, "POST", "/api/auth/logout", {})[0], 200)
        finally:
            self.rule("off")
            database.set_totp(TEST_USER, None, False)
            from tests.helpers import login
            login()

    def session_of_test_user(self):
        from tests.helpers import TEST_PASSWORD, TEST_USER
        status, body, headers = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
        self.assertEqual(status, 200, body)
        return session_cookie(headers), body

    def test_reset_by_admin_then_enrol(self):
        self.make("rq-admin2", with_2fa=True)
        # The test administrator has no 2FA, so the reset (tier 3) is done before the rule is on.
        self.assertEqual(request("POST", "/api/users/rq-admin2/2fa-reset", {})[0], 200)
        self.rule("admins")
        cookie, body = self.session("rq-admin2")
        self.assertIs(body["enrol_2fa"], True)
        self.enrol(cookie)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)

    def test_locked_vault_does_not_trap(self):
        self.make("rq-admin")
        self.rule("all")
        cookie, _ = self.session("rq-admin")
        with mock.patch.object(type(server.VAULT), "enabled", new_callable=mock.PropertyMock, return_value=False):
            status, body, _ = as_user(cookie, "GET", "/api/devices")
        self.assertNotEqual(body.get("auth") if isinstance(body, dict) else None, "enrol")


if __name__ == "__main__":
    unittest.main()
