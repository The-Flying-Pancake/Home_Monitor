"""Setup wizard: subnet rules, discovery, site settings validation, preview without writes, one real run, bulk add and delete."""

import time
import unittest
from unittest import mock

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from tests import _env  # noqa: F401
from tests.helpers import TEST_PASSWORD, add_device, request, start_api_server

import auth
import database
import discovery
import server
import setup


class SubnetTests(unittest.TestCase):
    def test_private_and_size_limits(self):
        self.assertEqual(str(discovery.parse_subnet("192.168.1.77/24")), "192.168.1.0/24")
        self.assertEqual(str(discovery.parse_subnet("10.1.0.0/22")), "10.1.0.0/22")
        for bad in ("8.8.8.0/24", "192.168.0.0/16", "127.0.0.0/24", "169.254.0.0/24", "fd00::/120", "nonsense"):
            with self.assertRaises(discovery.DiscoveryError, msg=bad):
                discovery.parse_subnet(bad)
        self.assertEqual(discovery.default_subnet("192.168.1.174"), "192.168.1.0/24")


class DiscoveryTests(unittest.TestCase):
    def test_scan_finds_ping_and_snmp_hosts(self):
        answers = {"192.0.2.1": (True, {discovery.SYS_OIDS[0]: "Linux pve 7.0-pve", discovery.SYS_OIDS[1]: "1.3.6.1.4.1.8072.3.2.10",
                                        discovery.SYS_OIDS[2]: "pve"}),
                   "192.0.2.2": (True, {}), "192.0.2.3": (False, {discovery.SYS_OIDS[2]: "quiet"})}

        def ping(ip, timeout):
            return answers.get(ip, (False, {}))[0], 1.0

        def snmp(ip, oids, community, port, timeout, retries):
            self.assertEqual(community, "scan-comm")
            return answers.get(ip, (False, {}))[1]

        with mock.patch.object(discovery.poller, "ping_host", side_effect=ping), \
                mock.patch.object(discovery.poller, "snmp_get_many", side_effect=snmp), \
                mock.patch.object(discovery, "_reverse_dns", return_value=""):
            job = discovery.ScanJob(discovery.parse_subnet("192.0.2.0/29"), "scan-comm", {"192.0.2.2"})
            job.run()
        v = job.view()
        self.assertTrue(v["finished"])
        self.assertEqual(v["done"], 6)
        by_ip = {r["ip"]: r for r in v["results"]}
        self.assertEqual(sorted(by_ip), ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        self.assertEqual(by_ip["192.0.2.1"]["profile_id"], "linux_host")
        self.assertTrue(by_ip["192.0.2.2"]["monitored"])
        self.assertTrue(by_ip["192.0.2.3"]["snmp"] and not by_ip["192.0.2.3"]["ping"])   # blocks ping, answers SNMP
        self.assertEqual(job.community, "")                                                # not kept after the run


class SiteSettingsTests(unittest.TestCase):
    def test_validation(self):
        site, secrets = setup.parse_site({
            "ssh": {"enabled": True, "credential": {"name": "root", "username": "root", "cred_type": "password", "secret": "pw"}},
            "syncthing": {"enabled": True, "keys_source": "192.168.1.99:/Share/Keys/Monitor", "data_folder": "/mnt/Syncthing/Monitor/"},
            "nfs": {"enabled": True, "mounts": [{"source": "nas:/Share/Media", "target": "/mnt/media", "options": "defaults,ro"}]},
            "telegram": {"enabled": False},
        }, set())
        self.assertEqual(site["syncthing"]["data_folder"], "/mnt/Syncthing/Monitor")
        self.assertEqual(site["nfs"]["mounts"][0]["options"], "defaults,ro,nosuid,nodev,noexec")
        self.assertNotIn("secret", repr(site))                      # secrets are kept apart
        self.assertEqual(secrets["credential"]["secret"], "pw")
        bad = [{"syncthing": {"enabled": True, "keys_source": "no-colon", "data_folder": "/mnt/x"}},
               {"nfs": {"enabled": True, "mounts": [{"source": "a:/b", "target": "/mnt/../etc"}]}},
               {"nfs": {"enabled": True, "mounts": [{"source": "a:/b", "target": "/mnt/x", "options": "x;rm -rf /"}]}},
               {"nfs": {"enabled": True, "mounts": [{"source": "a:/b", "target": "/etc"}]}},
               {"nfs": {"enabled": True, "mounts": []}},
               {"telegram": {"enabled": True, "token": "nope", "chat_id": "1"}},
               {"ssh": {"enabled": True, "credential": {"name": "", "username": "root", "secret": "x"}}}]
        for raw in bad:
            with self.assertRaises(setup.SetupError, msg=raw):
                setup.parse_site(raw, set())


class SetupApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def payload(self, ip="192.0.2.101"):
        return {"settings": {"default_poll_interval": "120", "default_snmp_community": "wizard-comm"},
                "site": {"ssh": {"enabled": False}, "syncthing": {"enabled": False}, "nfs": {"enabled": False},
                         "telegram": {"enabled": True, "token": "123456789:" + "A" * 35, "chat_id": "42"}},
                "devices": [{"ip_address": ip, "hostname": "wiz-a", "profile_id": "generic_device"}]}

    def test_preview_writes_nothing_and_apply_runs_once(self):
        database.set_internal_setting(setup.COMPLETED_KEY, "0")
        before = (len(database.list_devices()), database.get_all_settings().get("default_poll_interval"))
        status, res, _ = request("POST", "/api/setup/preview", self.payload())
        self.assertEqual(status, 200, res)
        self.assertTrue(res["preview"])
        self.assertIn("Add device wiz-a (192.0.2.101) with template generic_device", res["plan"])
        self.assertNotIn("wizard-comm", repr(res))                          # secrets never echoed
        self.assertNotIn("AAAAAAAAAA", repr(res))
        self.assertEqual((len(database.list_devices()), database.get_all_settings().get("default_poll_interval")), before)
        self.assertEqual(request("POST", "/api/setup/preview", dict(self.payload(), settings={"default_poll_interval": "1"}))[0], 400)
        self.assertEqual(request("POST", "/api/setup/preview", dict(self.payload(), settings={"telegram_token": "x"}))[0], 400)

        # Applying needs the admin password in the request every time, whatever the session timers say.
        self.assertEqual(request("POST", "/api/setup/apply", self.payload())[0], 401)
        self.assertEqual(request("POST", "/api/setup/apply", dict(self.payload(), admin_password="wrong password here"))[0], 401)
        auth.LIMITER.failures.clear()
        status, res, _ = request("POST", "/api/setup/apply", dict(self.payload(), admin_password=TEST_PASSWORD))
        self.assertEqual(status, 200, res)
        s = database.get_all_settings()
        self.assertEqual((s["default_poll_interval"], s["telegram_enabled"], s["telegram_chat_id"]), ("120", "on", "42"))
        self.assertTrue(setup.is_completed())
        self.assertEqual(setup.get_site()["telegram"], {"enabled": True})
        dev = next(d for d in database.list_devices() if d["ip_address"] == "192.0.2.101")
        self.assertEqual(dev["snmp_community"], "wizard-comm")
        # Once only, even with the right password; the refusal is audited.
        self.assertEqual(request("POST", "/api/setup/apply", dict(self.payload("192.0.2.102"), admin_password=TEST_PASSWORD))[0], 409)
        self.assertTrue(any(l["message"] == "Refused a second run of the setup wizard" for l in database.list_audit_logs(limit=20)))
        self.assertFalse(server.needs_confirmation("POST", "/api/setup/preview"))
        self.assertTrue(request("GET", "/api/setup/status")[1]["completed"])

    def test_bulk_add_and_delete(self):
        existing = add_device("bulk-existing", "192.0.2.111")
        body = {"devices": [{"ip_address": "192.0.2.111", "hostname": "dup"}, {"ip_address": "192.0.2.112", "hostname": "new"},
                            {"ip_address": "192.0.2.112", "hostname": "twice"}]}
        status, res, _ = request("POST", "/api/devices/bulk-add", dict(body, dry_run=True))
        self.assertEqual(([a["ip_address"] for a in res["added"]], [x["ip_address"] for x in res["skipped"]]), (["192.0.2.112"], ["192.0.2.111"]))
        self.assertFalse(any(d["ip_address"] == "192.0.2.112" for d in database.list_devices()))
        res = request("POST", "/api/devices/bulk-add", body)[1]
        new = next(d["id"] for d in database.list_devices() if d["ip_address"] == "192.0.2.112")
        self.assertEqual(request("POST", "/api/devices/bulk-add", {"devices": [{"ip_address": "not an ip"}]})[0], 400)
        status, res, _ = request("POST", "/api/devices/bulk-delete", {"device_ids": [existing, new, 999999]})
        self.assertEqual((sorted(res["deleted"]), res["missing"]), (sorted([existing, new]), [999999]))
        self.assertEqual(request("POST", "/api/devices/bulk-delete", {"device_ids": []})[0], 400)
        self.assertEqual(request("POST", "/api/devices/bulk-delete", {"device_ids": ["1"]})[0], 400)

    def test_existing_install_counts_as_set_up(self):
        add_device("already-here", "192.0.2.121")
        database.set_internal_setting(setup.COMPLETED_KEY, "0")
        server.initialise()
        self.assertTrue(setup.is_completed())

    def test_scan_rejects_public_ranges(self):
        status, res, _ = request("POST", "/api/setup/scan", {"subnet": "8.8.8.0/24", "community": "x"})
        self.assertEqual(status, 400)
        self.assertIn("private", res["error"])


class ContainerAccountCommandTests(unittest.TestCase):
    """sitectl.py commands behind /root/reset-admin.sh and /root/setup-code.sh."""

    SITECTL = os.path.join(_env.ROOT, "deploy", "sitectl.py")

    def setUp(self):
        start_api_server()
        self.tmp = tempfile.mkdtemp(prefix="hm-acct-")
        # A copy of the test database (it has the test account and its 2FA columns).
        with database.get_connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(FULL);")
        src = sqlite3.connect(database.DB_FILE)
        dst = sqlite3.connect(os.path.join(self.tmp, "monitor.db"))
        src.backup(dst)
        src.close()
        dst.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cmd(self, *args, stdin=""):
        env = dict(os.environ)
        return subprocess.run([sys.executable, self.SITECTL, *args], input=stdin.encode(), capture_output=True, env=env)

    def test_setup_code_refused_once_an_account_exists(self):
        env_file = os.path.join(self.tmp, "setup.env")
        r = self.run_cmd("new-setup-code", "--data", self.tmp, "--env", env_file)
        self.assertEqual(r.returncode, 3)
        self.assertIn("already exists", r.stderr.decode())
        self.assertFalse(os.path.exists(env_file))
        empty = tempfile.mkdtemp(prefix="hm-acct-empty-")
        try:
            r = self.run_cmd("new-setup-code", "--data", empty, "--env", os.path.join(empty, "setup.env"))
            self.assertEqual(r.returncode, 0, r.stderr)
            code = r.stdout.decode().strip()
            self.assertEqual(open(os.path.join(empty, "setup.env")).read(), f"MONITOR_SETUP_TOKEN={code}\n")
        finally:
            shutil.rmtree(empty, ignore_errors=True)

    def test_reset_password_and_2fa(self):
        from tests.helpers import TEST_USER
        listed = self.run_cmd("accounts", "--data", self.tmp).stdout.decode()
        self.assertIn(TEST_USER, listed)
        self.assertEqual(self.run_cmd("reset-password", "--data", self.tmp, "--user", TEST_USER, stdin="short\n").returncode, 1)
        self.assertEqual(self.run_cmd("reset-password", "--data", self.tmp, "--user", "nobody", stdin="a long new password\n").returncode, 1)
        conn = sqlite3.connect(os.path.join(self.tmp, "monitor.db"))
        conn.execute("UPDATE accounts SET totp_enabled = 1, totp_secret = 'enc1:x' WHERE username = ?", (TEST_USER,))
        conn.commit()
        conn.close()
        r = self.run_cmd("reset-password", "--data", self.tmp, "--user", TEST_USER, "--reset-2fa", stdin="a long new password\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(os.path.join(self.tmp, "monitor.db"))
        h, enabled = conn.execute("SELECT password_hash, totp_enabled FROM accounts WHERE username = ?", (TEST_USER,)).fetchone()
        msg = conn.execute("SELECT message FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0]
        conn.close()
        self.assertTrue(auth.verify_password("a long new password", h))
        self.assertEqual(enabled, 0)
        self.assertIn("container shell", msg)


if __name__ == "__main__":
    unittest.main()
