"""Settings, Backups (Syncthing location, back up now, root requests) and the audit log filters."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests import _env  # noqa: F401
from tests.helpers import request, session_cookie, start_api_server

import auth
import database
import server
import setup

ROOT = _env.ROOT


class BackupRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.data = os.path.dirname(os.path.abspath(database.DB_FILE))

    def request_file(self, kind):
        return os.path.join(self.data, "requests", kind)

    def test_syncthing_location_saved_and_requested(self):
        bad = request("PUT", "/api/backups/site", {"enabled": True, "keys_source": "not an export", "data_folder": "/mnt/Syncthing/Monitor"})
        self.assertEqual(bad[0], 400)
        bad = request("PUT", "/api/backups/site", {"enabled": True, "keys_source": "nas:/keys/Monitor", "data_folder": "/etc/evil"})
        self.assertEqual(bad[0], 400)
        status, body, _ = request("PUT", "/api/backups/site", {"enabled": True, "keys_source": "192.0.2.10:/Share/SyncThingKeys/Monitor",
                                                               "data_folder": "/mnt/Syncthing/Monitor"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["syncthing"])
        self.assertEqual(body["folder"], "/mnt/Syncthing/Monitor")
        self.assertTrue(os.path.exists(self.request_file("site")))
        self.assertTrue(body["pending"]["site"])
        self.assertEqual(setup.get_site()["syncthing"]["keys_source"], "192.0.2.10:/Share/SyncThingKeys/Monitor")
        # Off again: backups go back to the local folder.
        status, body, _ = request("PUT", "/api/backups/site", {"enabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(body["syncthing"])
        self.assertTrue(body["folder"].endswith("backups"))

    def test_backup_now_and_results(self):
        status, body, _ = request("POST", "/api/backups/run", {})
        self.assertEqual(status, 200)
        self.assertTrue(os.path.exists(self.request_file("backup")))
        self.assertTrue(body["pending"]["backup"])
        # Root's answer arrives as a result file newer than the request.
        with open(os.path.join(self.data, "backup.result.json"), "w", encoding="utf-8") as f:
            json.dump({"time": int(open(self.request_file("backup")).read()) + 1, "ok": True, "output": "Backup written"}, f)
        body = request("GET", "/api/system")[1]["backup"]
        self.assertFalse(body["pending"]["backup"])
        self.assertTrue(body["results"]["backup"]["ok"])


class SitectlResultTests(unittest.TestCase):
    def test_backup_writes_result(self):
        tmp = tempfile.mkdtemp(prefix="hm-bkres-")
        try:
            data = os.path.join(tmp, "data")
            os.makedirs(data)
            conn = sqlite3.connect(os.path.join(data, "monitor.db"))
            conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, description TEXT, updated_at INTEGER NOT NULL)")
            conn.commit()
            conn.close()
            r = subprocess.run([sys.executable, os.path.join(ROOT, "deploy", "sitectl.py"), "backup", "--data", data,
                                "--dest", os.path.join(tmp, "out")], capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(data, "backup.result.json"), encoding="utf-8") as f:
                res = json.load(f)
            self.assertTrue(res["ok"])
            self.assertTrue(res["file"].startswith("monitor-backup-"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class AuditFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        for i in range(30):
            database.add_audit("auditflt", f"Filter test entry {i}", f"secret-detail-{i}")
        database.add_audit("ssh", "Approved SSH host key for filter-host", "SHA256:sensitivefingerprint")

    def test_category_search_and_pages(self):
        status, body, _ = request("GET", "/api/audit?category=auditflt&per_page=10&page=2")
        self.assertEqual(status, 200)
        self.assertEqual((body["total"], body["pages"], len(body["logs"])), (30, 3, 10))
        self.assertIn("auditflt", body["categories"])
        body = request("GET", "/api/audit?q=entry%2017")[1]
        self.assertEqual([l["message"] for l in body["logs"]], ["Filter test entry 17"])
        body = request("GET", "/api/audit?q=secret-detail-5")[1]
        self.assertEqual(body["total"], 1)                    # an admin's search covers details too
        self.assertEqual(request("GET", "/api/audit?q=%25%25")[1]["total"], 0)

    def test_hidden_details_are_not_searchable(self):
        status, body, _ = request("POST", "/api/users", {"username": "auditor1", "password": "auditor pass phrase",
                                                         "role": "custom", "permissions": ["audit.view"]})
        self.assertIn(status, (201, 409), body)
        status, _, headers = request("POST", "/api/auth/login", {"username": "auditor1", "password": "auditor pass phrase"}, session=False)
        cookie = session_cookie(headers)

        def as_auditor(path):
            return request("GET", path, headers={"Cookie": f"{auth.SESSION_COOKIE}={cookie}"}, session=False)[1]
        body = as_auditor("/api/audit?q=sensitivefingerprint")
        self.assertEqual(body["total"], 0)                    # details are hidden, so they are not searched
        body = as_auditor("/api/audit?q=filter-host")
        self.assertEqual(body["total"], 1)
        self.assertNotIn("sensitivefingerprint", json.dumps(body))
        request("DELETE", "/api/users/auditor1")


if __name__ == "__main__":
    unittest.main()
