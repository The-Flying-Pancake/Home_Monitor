"""Settings, Backups (Syncthing location, back up now, root requests) and the audit log filters."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

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


    def test_set_backup_passphrase_from_settings(self):
        """The passphrase leaves the app sealed with the vault key, after a fresh password, once at a time."""
        from tests.helpers import TEST_PASSWORD
        req = self.request_file("backup-passphrase")
        if os.path.exists(req):
            os.remove(req)
        phrase = "correct horse battery staple"
        for bad in ("short", "x" * 1025, "twelve chars\nnewline", 12345):
            self.assertEqual(request("POST", "/api/backups/passphrase", {"passphrase": bad})[0], 400, bad)
        self.assertFalse(os.path.exists(req))
        # It needs a fresh password confirmation (tier 3).
        for s in auth.SESSIONS.sessions.values():
            s["tier2_until"] = s["tier3_until"] = 0
        status, body, _ = request("POST", "/api/backups/passphrase", {"passphrase": phrase})
        self.assertEqual(status, 403)
        self.assertEqual(body.get("auth"), "confirm")
        self.assertFalse(os.path.exists(req))
        self.assertEqual(request("POST", "/api/auth/confirm", {"password": TEST_PASSWORD, "tier": 3})[0], 200)
        with mock.patch.object(server, "security_alert") as alert:
            status, body, _ = request("POST", "/api/backups/passphrase", {"passphrase": phrase})
        self.assertEqual(status, 200, body)
        alert.assert_called_once()
        self.assertEqual(alert.call_args[0][0], "backup_passphrase")
        self.assertTrue(body["pending"]["passphrase"])
        with open(req, encoding="ascii") as f:
            token = f.read().strip()
        self.assertNotIn(phrase, token)
        self.assertEqual(server.VAULT.decrypt(token, "backup-passphrase-request"), phrase)
        self.assertNotIn(phrase, json.dumps(body))
        # A second one while the first waits is refused.
        self.assertEqual(request("POST", "/api/backups/passphrase", {"passphrase": phrase + "!"})[0], 409)
        rows = database.get_audit_log(limit=20) if hasattr(database, "get_audit_log") else []
        self.assertFalse(any(phrase in json.dumps(r) for r in rows))
        os.remove(req)


class PassphraseStatusTests(unittest.TestCase):
    """Settings, Backups: without a backup passphrase the status says so (the page shows the command)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-bkst-")
        self.conf = os.path.join(self.tmp, "install.conf")
        with open(self.conf, "w", encoding="utf-8") as f:
            f.write('CTID="201"' + chr(10))
        self.saved = os.environ.get("MONITOR_INSTALL_CONF")
        os.environ["MONITOR_INSTALL_CONF"] = self.conf

    def tearDown(self):
        if self.saved is None:
            os.environ.pop("MONITOR_INSTALL_CONF", None)
        else:
            os.environ["MONITOR_INSTALL_CONF"] = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_status_warns_without_a_passphrase(self):
        b = server.backup_status()
        self.assertTrue(b["installed"])
        self.assertFalse(b["passphrase_set"])
        self.assertIn(b["key_state"], ("withheld", "clear-local"))
        self.assertNotIn("includes_key", b)

    def test_status_quiet_with_a_passphrase(self):
        with open(os.path.join(self.tmp, "backup-passphrase"), "w") as f:
            f.write("a long backup passphrase" + chr(10))
        b = server.backup_status()
        self.assertTrue(b["passphrase_set"])
        self.assertEqual(b["key_state"], "sealed")
        self.assertNotIn("a long backup passphrase", json.dumps(b))


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


class AuditAttributionTests(unittest.TestCase):
    """Every audit row a request writes names who did it and from which address (REV-09)."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        from tests.helpers import TEST_USER
        cls.user = TEST_USER

    def mark(self):
        with database.get_connection() as conn:
            return conn.execute("SELECT COALESCE(MAX(id), 0) AS n FROM audit_log;").fetchone()["n"]

    def rows_since(self, mark):
        with database.get_connection() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_log WHERE id > ? ORDER BY id;", (mark,))]

    def assert_attributed(self, mark, actor=None):
        rows = self.rows_since(mark)
        self.assertTrue(rows, "no audit row written")
        for r in rows:
            self.assertEqual((r["actor"], r["source"]), (actor or self.user, "127.0.0.1"), r)
        return rows

    def test_credentials(self):
        m = self.mark()
        status, body, _ = request("POST", "/api/credentials", {"name": "attr-cred", "cred_type": "password",
                                                                "username": "root", "secret": "pw-attr"})
        self.assertEqual(status, 201, body)
        cid = body["id"]
        self.assertEqual(request("PUT", f"/api/credentials/{cid}", {"name": "attr-cred2", "username": "root"})[0], 200)
        self.assertEqual(request("DELETE", f"/api/credentials/{cid}")[0], 200)
        self.assertEqual(len(self.assert_attributed(m)), 3)

    def test_host_keys(self):
        from tests.helpers import add_device
        dev = add_device("attr-hk", "203.0.113.241", profile="linux_host")
        try:
            m = self.mark()
            presented = {"key_type": "ssh-ed25519", "key_b64": "EEEE", "fingerprint": "SHA256:attr"}
            with mock.patch.object(server.ssh_runner, "fetch_host_key", return_value=presented):
                self.assertEqual(request("POST", f"/api/devices/{dev}/hostkey", {"fingerprint": "SHA256:attr"})[0], 200)
            self.assertEqual(request("DELETE", f"/api/devices/{dev}/hostkey")[0], 200)
            database.approve_host_key(dev, "ssh-ed25519", "EEEE", "SHA256:attr")
            self.assertEqual(request("PUT", f"/api/devices/{dev}", {"hostname": "attr-hk", "ip_address": "203.0.113.242",
                                                                    "profile_id": "linux_host"})[0], 200)
            msgs = [r["message"] for r in self.assert_attributed(m)]
            self.assertIn("Approved SSH host key for attr-hk", msgs)
            self.assertIn("Forgot SSH host key", msgs)
            self.assertIn("Forgot the SSH host key of attr-hk", msgs)
        finally:
            database.delete_device(dev)

    def test_settings_and_devices(self):
        from tests.helpers import add_device
        m = self.mark()
        self.assertEqual(request("POST", "/api/settings", {"live_interval": "6"})[0], 200)
        dev = add_device("attr-dev", "203.0.113.243")
        self.assertEqual(request("PUT", f"/api/devices/{dev}", {"hostname": "attr-dev2", "ip_address": "203.0.113.243",
                                                                "profile_id": "generic_device"})[0], 200)
        self.assertEqual(request("DELETE", f"/api/devices/{dev}")[0], 200)
        request("POST", "/api/settings", {"live_interval": "5"})
        msgs = [r["message"] for r in self.assert_attributed(m)]
        for text in ("Added device attr-dev (203.0.113.243)", "Updated configuration for attr-dev2 (203.0.113.243)",
                     "Removed device attr-dev2 (203.0.113.243)"):
            self.assertIn(text, msgs)

    def test_users(self):
        m = self.mark()
        self.assertEqual(request("POST", "/api/users", {"username": "attr-u", "password": "attr user pass phrase"})[0], 201)
        self.assertEqual(request("PUT", "/api/users/attr-u", {"role": "operator"})[0], 200)
        self.assertEqual(request("POST", "/api/users/attr-u/password", {"password": "attr user pass phrase 2"})[0], 200)
        self.assertEqual(request("DELETE", "/api/users/attr-u")[0], 200)
        self.assertEqual(len(self.assert_attributed(m)), 4)

    def test_workflows_tls_updates_and_backups(self):
        m = self.mark()
        status, body, _ = request("POST", "/api/workflows", {"name": "attr-wf", "graph": {
            "nodes": [{"id": "t", "type": "trigger", "x": 0, "y": 0, "schedule": {"kind": "manual"}}], "edges": []}})
        if status == 201:
            request("DELETE", f"/api/workflows/{body['id']}")
        self.assertEqual(request("PUT", "/api/tls", {"mode": "off"})[0], 200)
        request("POST", "/api/backups/run", {})
        self.assert_attributed(m)

    def test_login_rows_name_the_account(self):
        from tests.helpers import TEST_PASSWORD
        m = self.mark()
        request("POST", "/api/auth/login", {"username": self.user, "password": TEST_PASSWORD}, session=False)
        request("POST", "/api/auth/login", {"username": self.user, "password": "wrong password here"}, session=False)
        request("POST", "/api/auth/login", {"username": "nobody-here", "password": "wrong password here"}, session=False)
        rows = self.rows_since(m)
        auth.LIMITER.succeeded("127.0.0.1", self.user)
        auth.LIMITER.succeeded("127.0.0.1", "nobody-here")
        self.assertEqual([(r["message"], r["actor"], r["source"]) for r in rows],
                         [(f"Logged in as {self.user}", self.user, "127.0.0.1"),
                          ("Failed login", self.user, "127.0.0.1"),
                          ("Failed login", "anonymous", "127.0.0.1")])

    def test_background_rows_are_system(self):
        import threading
        database.add_audit("bgtest", "Outside any request")
        seen = {}
        with database.audit_context("someone", "192.0.2.9"):
            t = threading.Thread(target=lambda: seen.setdefault("id", database.audit_identity()))
            t.start()
            t.join()
            inside = database.audit_identity()
        self.assertEqual(seen["id"], ("system", ""))          # a thread a request starts does not inherit it
        self.assertEqual(inside, ("someone", "192.0.2.9"))
        self.assertEqual(database.audit_identity(), ("system", ""))
        with database.get_connection() as conn:
            row = conn.execute("SELECT actor, source FROM audit_log WHERE category = 'bgtest' ORDER BY id DESC LIMIT 1;").fetchone()
        self.assertEqual(tuple(row), ("system", ""))

    def test_visibility(self):
        database.add_audit("auth", "Visibility check row", "detail", actor="vis-actor")
        status, _, _ = request("POST", "/api/users", {"username": "attr-viewer", "password": "attr viewer pass phrase",
                                                      "role": "custom", "permissions": ["audit.view"]})
        self.assertIn(status, (201, 409))
        try:
            _, _, headers = request("POST", "/api/auth/login", {"username": "attr-viewer", "password": "attr viewer pass phrase"},
                                    session=False)
            cookie = {"Cookie": f"{auth.SESSION_COOKIE}={session_cookie(headers)}"}
            logs = request("GET", "/api/audit?per_page=200", headers=cookie, session=False)[1]["logs"]
            self.assertTrue(all(l["source"] == "" for l in logs))
            row = next(l for l in logs if l["message"] == "Visibility check row")
            self.assertEqual(row["actor"], "")
            self.assertEqual(request("GET", "/api/audit?q=vis-actor", headers=cookie, session=False)[1]["total"], 0)
            mine = next(l for l in request("GET", "/api/audit?per_page=200")[1]["logs"] if l["message"] == "Visibility check row")
            self.assertEqual(mine["actor"], "vis-actor")
            self.assertEqual(request("GET", "/api/audit?q=vis-actor")[1]["total"], 1)
        finally:
            database.delete_user("attr-viewer")


class RootResultWatchTests(unittest.TestCase):
    """Restores and updates root did are reported once each (watch_root_results)."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.data = os.path.dirname(os.path.abspath(database.DB_FILE))

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-watch-")
        self.history = os.path.join(self.tmp, "update-history.json")
        p = mock.patch.object(server, "UPDATE_HISTORY", self.history)
        p.start()
        self.addCleanup(p.stop)
        self.alerts = []
        p2 = mock.patch.object(server.NOTIFIER, "security", side_effect=lambda key, **kw: self.alerts.append((key, kw)))
        p2.start()
        self.addCleanup(p2.stop)
        for key in (server.ALERT_SEEN_RESTORE, server.ALERT_SEEN_UPDATE):
            database.set_internal_setting(key, "")
        self.addCleanup(lambda: os.path.exists(self.result()) and os.remove(self.result()))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def result(self):
        return os.path.join(self.data, "restore.result.json")

    def write_history(self, rows):
        with open(self.history, "w", encoding="utf-8") as f:
            json.dump(rows, f)

    def test_update_result_alerted_once(self):
        now = time.time()
        self.write_history([{"id": 1, "time": int(now) - 600, "kind": "update", "from": "0.11.2", "to": "0.12.0", "ok": True}])
        self.assertEqual(server.watch_root_results(), 0)          # first run: the marker is set silently
        self.write_history([{"id": 2, "time": int(now), "kind": "update", "from": "0.12.0", "to": "0.12.1", "ok": False,
                             "error": "Download failed"},
                            {"id": 1, "time": int(now) - 600, "kind": "update", "from": "0.11.2", "to": "0.12.0", "ok": True}])
        self.assertEqual(server.watch_root_results(), 1)
        self.assertEqual(server.watch_root_results(), 0)
        self.assertEqual(self.alerts, [("update_failed", {"who": "root", "source": "", "kind": "Update", "to": "0.12.1",
                                                          "error": "Download failed"})])
        rows = [(a["message"], a["actor"]) for a in database.list_audit_filtered(q="0.12.1")[0]]
        self.assertIn(("Update from 0.12.0 to 0.12.1 failed", "root"), rows)

    def test_first_run_sets_the_marker_silently(self):
        self.write_history([{"id": 7, "time": int(time.time()), "kind": "update", "from": "a", "to": "b", "ok": True}])
        server.watch_root_results()
        self.assertEqual(database.get_all_settings()[server.ALERT_SEEN_UPDATE], "7")
        self.assertEqual(self.alerts, [])

    def test_old_results_are_not_replayed(self):
        now = int(time.time())
        database.set_internal_setting(server.ALERT_SEEN_UPDATE, "1")
        rows = [{"id": i, "time": now - (90000 if i < 4 else 0), "kind": "update", "from": "x", "to": str(i), "ok": True}
                for i in range(2, 12)]
        self.write_history(rows)
        self.assertEqual(server.watch_root_results(), 5)          # recent ones only, at most five
        self.assertEqual([kw["to"] for _, kw in self.alerts], ["7", "8", "9", "10", "11"])

    def test_restore_alerted_once_after_restore(self):
        with open(self.result(), "w", encoding="utf-8") as f:
            json.dump({"time": int(time.time()), "ok": True, "output": "Restored", "file": "monitor-backup-x.tar.gz"}, f)
        database.set_internal_setting(server.ALERT_SEEN_RESTORE, str(int(time.time()) - 5000))   # an older marker
        self.write_history([])
        self.assertEqual(server.watch_root_results(), 1)
        self.assertEqual(server.watch_root_results(), 0)
        self.assertEqual(self.alerts, [("restored", {"who": "root", "source": "", "file": "monitor-backup-x.tar.gz"})])

    def test_watcher_not_in_initialise(self):
        import inspect
        self.assertNotIn("watch_root_results", inspect.getsource(server.initialise))
        self.assertIn("watch_root_results", inspect.getsource(server.start_server))


if __name__ == "__main__":
    unittest.main()
