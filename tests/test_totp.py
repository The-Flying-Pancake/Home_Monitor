"""2FA: TOTP and recovery codes, the QR encoder, login with a code, step-up tiers, password recovery."""

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
        for name in ("mfa1", "mfa2", "mfa3", "mfa4", "mfa5", "mfa6"):
            database.delete_user(name)

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


if __name__ == "__main__":
    unittest.main()
