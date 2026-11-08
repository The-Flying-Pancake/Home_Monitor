"""HTTPS (tls.py): certificates made and checked, the three modes through the API, one port for
HTTPS and plain HTTP (redirect from other machines, served as before for this one), Secure
cookies and the Origin check over HTTPS, the question after an upgrade, expiry handling."""

import datetime
import http.client
import json
import ssl
import unittest

from tests import _env
from tests import helpers
from tests.helpers import request, start_api_server

import database
import server
import tls


def https_get(path, headers=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("127.0.0.1", _env.PORT, context=ctx, timeout=10)
    try:
        conn.request("GET", path, headers=headers or {})
        peer = conn.sock.getpeercert(binary_form=True)
        r = conn.getresponse()
        return r.status, r.read().decode(), dict(r.getheaders()), peer
    finally:
        conn.close()


def https_post(path, body, headers):
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection("127.0.0.1", _env.PORT, context=ctx, timeout=10)
    try:
        conn.request("POST", path, body=json.dumps(body), headers=dict({"Content-Type": "application/json"}, **headers))
        r = conn.getresponse()
        return r.status, r.read().decode(), dict(r.getheaders())
    finally:
        conn.close()


def plain_get(path, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", _env.PORT, timeout=10)
    try:
        conn.putrequest("GET", path, skip_host=True)
        conn.putheader("Host", host or f"127.0.0.1:{_env.PORT}")
        conn.endheaders()
        r = conn.getresponse()
        return r.status, r.read().decode(), dict(r.getheaders())
    finally:
        conn.close()


class CertificateTests(unittest.TestCase):
    def test_self_signed(self):
        cert, key = tls.make_self_signed(["monitor", "monitor.lan", "192.168.1.174", "127.0.0.1"])
        info = tls.describe(cert)
        self.assertTrue(info["self_signed"])
        self.assertEqual(set(info["names"]), {"monitor", "monitor.lan", "192.168.1.174", "127.0.0.1"})
        self.assertAlmostEqual((info["not_after"] - info["not_before"]) / 86400, tls.SELF_SIGNED_DAYS, delta=1)
        self.assertRegex(info["fingerprint"], r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
        self.assertIn("PRIVATE KEY", key)
        self.assertEqual(tls.check_pair(cert, key)["fingerprint"], info["fingerprint"])

    def test_bad_pairs(self):
        cert, key = tls.make_self_signed(["a.example"])
        _, other = tls.make_self_signed(["b.example"])
        for c, k, says in [(cert, other, "does not belong"), ("", key, "both"), ("hello", key, "No certificate"),
                           (cert, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n", "passphrase"),
                           (cert, "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n", "could not be read")]:
            with self.assertRaises(tls.TlsError) as cm:
                tls.check_pair(c, k)
            self.assertIn(says, str(cm.exception))
        old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=tls.SELF_SIGNED_DAYS + 1)
        c, k = tls.make_self_signed(["old.example"], now=old)
        with self.assertRaises(tls.TlsError) as cm:
            tls.check_pair(c, k)
        self.assertIn("expired", str(cm.exception))

    def test_extra_names(self):
        self.assertEqual(tls.clean_names("Monitor.Home.Example.com, 192.168.1.9  monitor.home.example.com."),
                         ["monitor.home.example.com", "192.168.1.9"])
        for bad in ("bad_name", "-x.example", "a..b", "x" * 64 + ".example"):
            with self.assertRaises(tls.TlsError):
                tls.clean_names(bad)
        with self.assertRaises(tls.TlsError):
            tls.clean_names(" ".join(f"h{i}.example" for i in range(tls.MAX_NAMES + 1)))

    def test_machine_names(self):
        names = tls.machine_names(["extra.example"])
        self.assertIn("localhost", names)
        self.assertIn("127.0.0.1", names)
        self.assertIn("extra.example", names)
        self.assertEqual(len(names), len(set(names)))


class HttpsServingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def tearDown(self):
        tls.set_off()
        helpers._httpd.__dict__.pop("local_client", None)

    def test_modes_through_the_api(self):
        status, body, _ = request("GET", "/api/tls")
        self.assertEqual((status, body["mode"], body["active"]), (200, "off", False))
        self.assertEqual(request("GET", "/api/tls/certificate")[0], 404)
        self.assertEqual(request("PUT", "/api/tls", {"mode": "nope"})[0], 400)
        self.assertEqual(request("PUT", "/api/tls", {"mode": "self-signed", "extra_names": "bad_name"})[0], 400)

        # Self-signed: the key is stored encrypted and never returned.
        status, body, _ = request("PUT", "/api/tls", {"mode": "self-signed", "extra_names": "monitor.home.example.com"})
        self.assertEqual(status, 200, body)
        state = body["tls"]
        self.assertEqual((state["mode"], state["active"]), ("self-signed", True))
        self.assertIn("monitor.home.example.com", state["certificate"]["names"])
        self.assertNotIn("PRIVATE", json.dumps(body))
        with database.get_connection() as conn:
            raw = conn.execute("SELECT value FROM settings WHERE key = 'tls_key';").fetchone()["value"]
        self.assertTrue(raw.startswith("enc1:"), raw[:12])
        self.assertNotIn("PRIVATE", request("GET", "/api/settings")[1].__repr__())
        status, pem, headers = request("GET", "/api/tls/certificate")
        self.assertEqual(status, 200)
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertNotIn("PRIVATE", pem)
        first_fp = state["certificate"]["fingerprint"]

        # Re-saving the same names keeps the certificate (it may already be trusted); new names make a new one.
        same = request("PUT", "/api/tls", {"mode": "self-signed", "extra_names": "monitor.home.example.com"})[1]["tls"]
        self.assertEqual(same["certificate"]["fingerprint"], first_fp)
        new = request("PUT", "/api/tls", {"mode": "self-signed", "extra_names": ""})[1]["tls"]
        self.assertNotEqual(new["certificate"]["fingerprint"], first_fp)

        # Own: a pair checked first; a wrong key is refused and changes nothing.
        cert, key = tls.make_self_signed(["own.example"])
        _, wrong = tls.make_self_signed(["other.example"])
        status, body, _ = request("PUT", "/api/tls", {"mode": "own", "certificate": cert, "key": wrong})
        self.assertEqual(status, 400)
        self.assertIn("does not belong", body["error"])
        self.assertEqual(request("GET", "/api/tls")[1]["mode"], "self-signed")
        status, body, _ = request("PUT", "/api/tls", {"mode": "own", "certificate": cert, "key": key})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["tls"]["mode"], body["tls"]["certificate"]["names"]), ("own", ["own.example"]))
        der = https_get("/api/auth/status")[3]
        self.assertEqual(tls.describe(cert)["fingerprint"].replace(":", ""), __import__("hashlib").sha256(der).hexdigest().upper())

        # Off: plain HTTP only again.
        self.assertEqual(request("PUT", "/api/tls", {"mode": "off"})[1]["tls"]["active"], False)
        with self.assertRaises((ssl.SSLError, OSError)):
            https_get("/api/auth/status")
        audit = [a["message"] for a in database.list_audit(limit=20)] if hasattr(database, "list_audit") else []
        if audit:
            self.assertTrue(any("self-signed" in m for m in audit))

    def test_one_port_for_both(self):
        self.assertEqual(request("PUT", "/api/tls", {"mode": "self-signed", "extra_names": ""})[0], 200)
        status, text, _, _ = https_get("/api/auth/status")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(text)["https"])
        # Plain HTTP from this machine (health checks, the installer) is answered as before.
        status, text, _ = plain_get("/api/auth/status")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(text)["https"])
        # From another machine it is sent to https, to this server's own name only.
        helpers._httpd.local_client = staticmethod(lambda addr: False)
        status, _, headers = plain_get("/devices?x=1")
        self.assertEqual(status, 308)
        self.assertEqual(headers["Location"], f"https://127.0.0.1:{_env.PORT}/devices?x=1")
        self.assertEqual(plain_get("/", host="evil.example:8080")[0], 421)

    def test_cookie_and_origin_over_https(self):
        self.assertEqual(request("PUT", "/api/tls", {"mode": "self-signed", "extra_names": ""})[0], 200)
        status, _, headers = https_post("/api/auth/login", {"username": helpers.TEST_USER, "password": helpers.TEST_PASSWORD}, {})
        self.assertEqual(status, 200)
        cookie = next(v for k, v in headers.items() if k.lower() == "set-cookie")
        self.assertIn("Secure", cookie)
        self.assertNotIn("Secure", next(v for k, v in request("POST", "/api/auth/login", {
            "username": helpers.TEST_USER, "password": helpers.TEST_PASSWORD}, session=False)[2].items() if k.lower() == "set-cookie"))
        here = f"127.0.0.1:{_env.PORT}"
        self.assertEqual(https_post("/api/auth/login", {"username": helpers.TEST_USER, "password": helpers.TEST_PASSWORD},
                                    {"Origin": f"http://{here}"})[0], 403)
        self.assertEqual(https_post("/api/auth/login", {"username": helpers.TEST_USER, "password": helpers.TEST_PASSWORD},
                                    {"Origin": f"https://{here}"})[0], 200)
        helpers.login()

    def test_upgrade_question(self):
        # An install from before HTTPS (accounts, no mode stored) keeps HTTP and asks once.
        database.delete_settings([tls.MODE_KEY, tls.PROMPT_KEY])
        tls.first_run(database.get_all_settings(), has_accounts=True)
        self.assertEqual(tls.mode(), "off")
        self.assertTrue(request("GET", "/api/features")[1]["tls_prompt"])
        self.assertEqual(request("POST", "/api/tls/dismiss")[0], 200)
        self.assertFalse(request("GET", "/api/features")[1]["tls_prompt"])
        # Already decided: nothing changes on the next start.
        tls.first_run(database.get_all_settings(), has_accounts=True)
        self.assertFalse(tls.public_state()["prompt"])

    def test_fresh_install_default(self):
        import os
        database.delete_settings([tls.MODE_KEY, tls.PROMPT_KEY])
        os.environ["MONITOR_TLS_DEFAULT"] = "self-signed"
        try:
            tls.first_run({}, has_accounts=False)
        finally:
            del os.environ["MONITOR_TLS_DEFAULT"]
        self.assertEqual(tls.mode(), "self-signed")
        self.assertFalse(tls.public_state()["prompt"])
        tls.load()
        self.assertIsNotNone(tls.SERVER.context)
        database.delete_settings([tls.MODE_KEY])
        tls.first_run({}, has_accounts=False)
        self.assertEqual(tls.mode(), "off")

    def test_expiry(self):
        sent = []
        notify = lambda days, date: sent.append((days, date))
        now = datetime.datetime.now(datetime.timezone.utc)
        # An own certificate 10 days from expiry: warned once, not again the same day.
        cert, key = tls.make_self_signed(["soon.example"], now=now - datetime.timedelta(days=tls.SELF_SIGNED_DAYS - 10))
        tls.set_own(cert, key)
        self.assertEqual(tls.daily_check(notify), "warned")
        self.assertEqual(sent[0][0], 9)
        self.assertIsNone(tls.daily_check(notify))
        self.assertEqual(len(sent), 1)
        self.assertEqual(tls.daily_check(notify, now=now.timestamp() + 2 * 86400), "warned")
        # Far from expiry: nothing.
        cert, key = tls.make_self_signed(["later.example"])
        tls.set_own(cert, key)
        self.assertIsNone(tls.daily_check(notify))
        # Self-signed near expiry: made again, no message.
        tls.set_self_signed([])
        old, old_key = tls.make_self_signed(tls.machine_names(), now=now - datetime.timedelta(days=tls.SELF_SIGNED_DAYS - 5))
        tls._store("self-signed", old, old_key)
        self.assertEqual(tls.daily_check(notify), "renewed")
        self.assertGreater(tls.public_state()["certificate"]["not_after"] - now.timestamp(), 800 * 86400)
        self.assertEqual(len(sent), 2)


if __name__ == "__main__":
    unittest.main()
