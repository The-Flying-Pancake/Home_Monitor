"""Report a problem (report.py): what it holds, what it masks, and the administrator-only route."""

import json
import os
import shutil
import tempfile
import time
import unittest

from tests import _env  # noqa: F401
from tests.helpers import TEST_USER, add_device, request, start_api_server

import database
import report
import server


class RedactTests(unittest.TestCase):
    def test_masks_addresses_secrets_and_names(self):
        text = ("at 18:48:02 reach 192.168.1.5/24 and fe80::1 and 2001:db8:0:0:1:2:3:4, mac aa:bb:cc:dd:ee:ff, "
                "BACKUP_PASSPHRASE=hunter2hunter2 telegram_token: 123:abc, me@example.com, https://nas.local/share, "
                "device office-nas is down")
        out = report.redact(text, ["office-nas"])
        for gone in ("192.168.1.5", "fe80::1", "2001:db8", "aa:bb:cc", "hunter2", "123:abc", "me@example.com", "nas.local", "office-nas"):
            self.assertNotIn(gone, out)
        self.assertIn("18:48:02", out)                                   # clock times stay
        self.assertIn("device <name> is down", out)
        # A name is masked only as a whole word: parts of other words stay readable.
        self.assertEqual(report.redact("qnap_nas and nas-01 and nas", ["nas"]), "qnap_nas and nas-01 and <name>")


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("report-private-box", "192.168.1.77", "generic_device")
        database.add_event(cls.dev, "critical", "problem", "Problem: report-private-box at 192.168.1.77 unreachable", int(time.time()))

    def test_report_holds_facts_and_no_private_details(self):
        tmp = tempfile.mkdtemp(prefix="hm-report-", dir=_env.TMP)
        try:
            with open(os.path.join(tmp, "update-history.json"), "w", encoding="utf-8") as f:
                json.dump([{"id": 1, "time": 1, "kind": "upgrade", "from": "0.6.0", "to": "0.9.0", "ok": True}], f)
            text = report.build(database.DB_FILE, install_dir=tmp, extra={"log": ["WARNING poller: report-private-box timed out"]})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertIn(f"Version: {server.APP_VERSION}", text)
        self.assertIn("generic_device", text)                             # devices by template
        self.assertIn("upgrade 0.6.0 to 0.9.0: passed", text)
        self.assertIn("Problem: <name> at <address> unreachable", text)
        self.assertIn("WARNING poller: <name> timed out", text)
        self.assertNotIn("report-private-box", text)
        self.assertNotIn("192.168.1.77", text)
        self.assertNotIn(TEST_USER, text)                                   # account names are masked

    def test_route_is_for_administrators(self):
        code, body, _ = request("GET", "/api/support/report")
        self.assertEqual(code, 200)
        self.assertIn("Home Monitor problem report", body["report"])
        self.assertTrue(body["issue_url"].endswith("/issues/new?template=problem.yml"))
        self.assertNotIn("report-private-box", body["report"])
        request("POST", "/api/users", {"username": "report-op", "password": "another long passphrase", "role": "operator"})
        from tests.test_users import as_user, login_as
        _, _, c = login_as("report-op")
        self.assertEqual(as_user(c, "GET", "/api/support/report")[0], 403)
        request("DELETE", "/api/users/report-op")


if __name__ == "__main__":
    unittest.main()
