"""Across builds: schema versions, the compat check (trial migration on a copy), and restore refusing
what this build cannot run. The fingerprint test fails when the schema changes without a version bump."""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tests import _env  # noqa: F401

import compat
import database

ROOT = _env.ROOT
SITECTL = os.path.join(ROOT, "deploy", "sitectl.py")

# sha256 of the normalised schema a fresh start creates, per SCHEMA_VERSION. When this test fails
# after a schema change: raise database.SCHEMA_VERSION and add the new fingerprint here.
SCHEMA_FINGERPRINTS = {
    1: "8696eba0d5738b2e210dd861ac1667a989069a43b2ee8808f962ef5e60546d76",
    2: "a4add215c7fd740fe420969f3818537c0db10203668cf7628620e78e29e6c072",   # alert rules by tag
    3: "8966cf02256e9629ec9b59212e210eaf4290fad6f8428fce6418ce6b61771c8a",   # inventory
    4: "9fee856c57a973d15d0914a4aa24d3943977bd93c44973ed9e59a447d8ae9b6c",   # inventory ssid and quiet
    5: "50a2b3702d203e96ff54c108d566235c93b18a1066b7b57b11c784a5f1e261e4",   # action_runs (host actions)
    6: "6ae966f4af4e9e6325436068e706aa24ad84fc8874a81ec9f25ea67e8fa81275",   # workflows.saved_by (rights checked at run)
    7: "53d0aa0ca4ec6cdbfb290b9e723eb942f7c785cfddc56e748e39cd3032bafec7",   # audit_log.actor and audit_log.source
    8: "8593391624b36e3ddacd15c5ffc24c96d81a94b33025d4e48e06884b6322bbec",   # devices.snmp_v3
    9: "5419690a7425de69ade286f280ed7104503444eff1ccd836c1e55cb3a23796d0",   # reports and report_runs
}


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def schema_sql(db):
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
                            "ORDER BY type, name;").fetchall()
    finally:
        conn.close()
    return "\n".join(f"{t} {n} {re.sub(r'\s+', ' ', s).strip()}" for t, n, s in rows)


# A database as the first builds wrote it: devices with a unique address and no port column,
# a settings key the app has since dropped, nothing else.
OLD_SCHEMA = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, description TEXT, updated_at INTEGER NOT NULL);
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE, profile_id TEXT NOT NULL,
    snmp_version TEXT NOT NULL DEFAULT 'v2c', snmp_community TEXT DEFAULT 'public', snmp_port INTEGER NOT NULL DEFAULT 161,
    poll_interval INTEGER, ping_interval INTEGER, status TEXT NOT NULL DEFAULT 'unknown', last_ping_ms REAL,
    last_seen INTEGER, created_at INTEGER NOT NULL, tags TEXT DEFAULT '[]');
INSERT INTO settings VALUES ('threshold_cpu_pct', '85', 'old setting', 0);
INSERT INTO settings VALUES ('a_key_no_build_knows', 'kept', '', 0);
INSERT INTO devices (hostname, ip_address, profile_id, created_at) VALUES ('old-switch', '192.0.2.201', 'unifi_switch', 0);
INSERT INTO devices (hostname, ip_address, profile_id, created_at) VALUES ('old-gone', '192.0.2.202', 'a_template_that_is_gone', 0);
"""


class CompatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-compat-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_old(self):
        db = os.path.join(self.tmp, "old.db")
        conn = sqlite3.connect(db)
        conn.executescript(OLD_SCHEMA)
        conn.close()
        return db

    def run_initialise(self, db, key):
        return subprocess.run([sys.executable, "-c", "import server; server.initialise()"], cwd=ROOT, capture_output=True, text=True,
                              env=dict(os.environ, MONITOR_DB_PATH=db, MONITOR_KEY_FILE=key), timeout=300)

    def test_fresh_start_records_version_and_fingerprint(self):
        db = os.path.join(self.tmp, "fresh.db")
        r = self.run_initialise(db, os.path.join(self.tmp, "fresh.key"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(database.schema_version(db), database.SCHEMA_VERSION)
        digest = hashlib.sha256(schema_sql(db).encode()).hexdigest()
        known = SCHEMA_FINGERPRINTS.get(database.SCHEMA_VERSION)
        self.assertIsNotNone(known, f"No fingerprint recorded for schema {database.SCHEMA_VERSION}: add {digest!r}")
        self.assertEqual(digest, known, "The schema changed: raise database.SCHEMA_VERSION and record the new "
                                        f"fingerprint {digest!r} in SCHEMA_FINGERPRINTS")

    def test_old_database_migrates_on_a_copy_then_for_real(self):
        db = self.make_old()
        before = read_bytes(db)
        report = compat.check(db, None, run_trial=True)
        self.assertEqual((report["verdict"], report["exit"]), ("older", 0), report)
        self.assertTrue(report["trial"]["ok"], report["trial"])
        self.assertTrue(any("a_template_that_is_gone" in n for n in report["notes"]), report["notes"])
        self.assertEqual(read_bytes(db), before)                     # the trial never touched the original
        r = self.run_initialise(db, os.path.join(self.tmp, "old.key"))
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices;").fetchone()[0], 2)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices);")}
        settings = dict(conn.execute("SELECT key, value FROM settings;").fetchall())
        conn.close()
        self.assertIn("service_port", cols)
        self.assertNotIn("threshold_cpu_pct", settings)                     # moved into the alert rules
        self.assertEqual(settings.get("a_key_no_build_knows"), "kept")      # unknown data is kept, not deleted
        self.assertEqual(database.schema_version(db), database.SCHEMA_VERSION)
        self.assertEqual(compat.check(db)["verdict"], "same")

    def test_alert_rules_survive_the_tag_scope_migration(self):
        db = os.path.join(self.tmp, "v1.db")
        conn = sqlite3.connect(db)
        conn.executescript(OLD_SCHEMA + """
            CREATE TABLE alert_overrides (scope TEXT NOT NULL CHECK (scope IN ('global', 'template', 'device')),
                target TEXT NOT NULL, rule_id TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL,
                updated_at INTEGER NOT NULL, PRIMARY KEY (scope, target, rule_id, field));
            INSERT INTO alert_overrides VALUES ('global', '', 'mem', 'threshold', '75', 0);
            INSERT INTO alert_overrides VALUES ('device', '1', 'cpu', 'enabled', '0', 0);
            PRAGMA user_version = 1;""")
        conn.close()
        self.assertTrue(compat.check(db, None, run_trial=True)["trial"]["ok"])
        r = self.run_initialise(db, os.path.join(self.tmp, "v1.key"))
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(db)
        rows = conn.execute("SELECT scope, target, rule_id, field, value FROM alert_overrides ORDER BY scope;").fetchall()
        conn.execute("INSERT INTO alert_overrides VALUES ('tag', 'lab', 'cpu', 'enabled', '0', 0);")   # now allowed
        conn.close()
        self.assertIn(("global", "", "mem", "threshold", "75"), rows)
        self.assertIn(("device", "1", "cpu", "enabled", "0"), rows)
        self.assertEqual(database.schema_version(db), database.SCHEMA_VERSION)

    def test_credentials_use_on_a_0_11_2_database(self):
        """A database as 0.11.2 left it: custom users without the new permission and no marker."""
        db = os.path.join(self.tmp, "v0112.db")
        key = os.path.join(self.tmp, "v0112.key")
        self.assertEqual(self.run_initialise(db, key).returncode, 0)
        conn = sqlite3.connect(db)
        users = [("cu-admin", "admin", None), ("cu-run", "custom", '["automation.run"]'),
                 ("cu-dev", "custom", '["devices.manage"]'), ("cu-poll", "custom", '["devices.poll"]'),
                 ("cu-op", "operator", None)]
        for name, role, perms in users:
            conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at, role, permissions) "
                         "VALUES (?, 'x', 0, 0, ?, ?);", (name, role, perms))
        conn.execute("DELETE FROM settings WHERE key = 'migrated_credentials_use';")
        conn.execute("PRAGMA user_version = 6;")
        conn.commit()
        conn.close()
        report = compat.check(db, key, run_trial=True)
        self.assertTrue(report["trial"]["ok"], report["trial"])
        r = self.run_initialise(db, key)
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(db)
        perms = dict(conn.execute("SELECT username, permissions FROM accounts;").fetchall())
        notices = conn.execute("SELECT actor FROM events WHERE message LIKE 'Home Monitor now has a Use stored%';").fetchall()
        audit = [m for (m,) in conn.execute("SELECT message FROM audit_log;")]
        marker = conn.execute("SELECT value FROM settings WHERE key = 'migrated_credentials_use';").fetchone()
        conn.close()
        self.assertIn("credentials.use", json.loads(perms["cu-run"]))
        self.assertIn("credentials.use", json.loads(perms["cu-dev"]))
        self.assertEqual(json.loads(perms["cu-poll"]), ["devices.poll"])
        self.assertIsNone(perms["cu-op"])                                   # built-in roles: worked out when read
        self.assertEqual(notices, [("cu-admin",)])
        self.assertIn("Gave cu-run the Use stored credentials permission", audit)
        self.assertEqual(marker, ("1",))
        self.assertEqual(compat.check(db)["verdict"], "same")

    def test_workflow_check_on_a_0_11_2_database(self):
        """A 0.11.2 database whose limited user saved a workflow that keeps every device quiet: the
        first start of this build tells the administrator once and changes nothing."""
        db = os.path.join(self.tmp, "wf0112.db")
        key = os.path.join(self.tmp, "wf0112.key")
        self.assertEqual(self.run_initialise(db, key).returncode, 0)
        conn = sqlite3.connect(db)
        conn.execute("INSERT INTO devices (hostname, ip_address, profile_id, created_at) VALUES ('wf-dev', '192.0.2.231', 'generic_device', 0);")
        dev = conn.execute("SELECT id FROM devices WHERE hostname = 'wf-dev';").fetchone()[0]
        conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at, role) VALUES ('wf-admin', 'x', 0, 0, 'admin');")
        conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at, role, permissions, device_scope) "
                     "VALUES ('wf-limited', 'x', 0, 0, 'custom', '[\"automation.edit\"]', ?);",
                     (json.dumps({"all": False, "profiles": [], "devices": [dev]}),))
        steps = json.dumps([{"type": "mute", "scope": "all", "until_end": True, "minutes": 60, "grace_min": 5, "label": ""}])
        conn.execute("INSERT INTO workflows (name, steps, trigger_type, created_at, updated_at, saved_by) "
                     "VALUES ('Quiet all', ?, 'manual', 0, 0, 'wf-limited');", (steps,))
        conn.execute("DELETE FROM settings WHERE key = 'checked_workflow_scope';")
        conn.execute("PRAGMA user_version = 6;")
        conn.commit()
        conn.close()
        report = compat.check(db, key, run_trial=True)
        self.assertTrue(report["trial"]["ok"], report["trial"])
        for _ in range(2):                                                  # the second start adds nothing
            r = self.run_initialise(db, key)
            self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(db)
        notices = conn.execute("SELECT actor, message FROM events WHERE message LIKE '%reach further than the person%';").fetchall()
        marker = conn.execute("SELECT value FROM settings WHERE key = 'checked_workflow_scope';").fetchone()
        kept = conn.execute("SELECT COUNT(*) FROM workflows WHERE name = 'Quiet all';").fetchone()[0]
        conn.close()
        self.assertEqual([n[0] for n in notices], ["wf-admin"])
        self.assertTrue(notices[0][1].startswith("1 saved workflow(s)"))
        self.assertEqual((marker, kept), (("1",), 1))

    def test_newer_database_is_refused_and_left_alone(self):
        db = self.make_old()
        conn = sqlite3.connect(db)
        conn.execute(f"PRAGMA user_version = {database.SCHEMA_VERSION + 5};")
        conn.close()
        before = read_bytes(db)
        report = compat.check(db, None, run_trial=True)
        self.assertEqual((report["verdict"], report["exit"]), ("newer", 3))
        self.assertNotIn("trial", report)
        r = self.run_initialise(db, os.path.join(self.tmp, "new.key"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("newer build", r.stderr)
        self.assertEqual(read_bytes(db), before)

    def test_damaged_and_foreign_files(self):
        junk = os.path.join(self.tmp, "junk.db")
        with open(junk, "wb") as f:
            f.write(os.urandom(4096))
        self.assertEqual(compat.check(junk)["verdict"], "damaged")
        other = os.path.join(self.tmp, "other.db")
        sqlite3.connect(other).execute("CREATE TABLE x (a);").connection.close()
        self.assertEqual(compat.check(other)["verdict"], "damaged")
        self.assertEqual(compat.check(os.path.join(self.tmp, "missing.db"))["exit"], 4)

    def test_cli_json(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "compat.py"), "check", "--db", self.make_old(), "--json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["verdict"], "older")

    def make_0112(self, name):
        """A database as 0.11.2 left it: no actor or source on audit rows, one retention setting."""
        db = os.path.join(self.tmp, f"{name}.db")
        key = os.path.join(self.tmp, f"{name}.key")
        self.assertEqual(self.run_initialise(db, key).returncode, 0)
        conn = sqlite3.connect(db)
        conn.execute("ALTER TABLE audit_log DROP COLUMN actor;")
        conn.execute("ALTER TABLE audit_log DROP COLUMN source;")
        conn.execute("INSERT INTO audit_log (timestamp, category, message, details) VALUES (1, 'auth', 'An old row', 'By someone');")
        conn.execute("DELETE FROM settings WHERE key IN ('event_retention_days', 'notice_security_0_12');")
        conn.execute("PRAGMA user_version = 6;")
        conn.commit()
        conn.close()
        return db, key

    def test_audit_columns_on_a_0_11_2_database(self):
        db, key = self.make_0112("audit0112")
        report = compat.check(db, key, run_trial=True)
        self.assertTrue(report["trial"]["ok"], report["trial"])
        r = self.run_initialise(db, key)
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(db)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log);")}
        old = conn.execute("SELECT actor, source, details FROM audit_log WHERE message = 'An old row';").fetchone()
        conn.close()
        self.assertTrue({"actor", "source"} <= cols)
        self.assertEqual(old, ("", "", "By someone"))
        self.assertEqual(database.schema_version(db), database.SCHEMA_VERSION)
        conn = sqlite3.connect(db)
        device_cols = {row[1] for row in conn.execute("PRAGMA table_info(devices);")}
        conn.close()
        self.assertIn("snmp_v3", device_cols)          # schema 8: SNMPv3 settings per device

    def test_retention_split_on_a_0_11_2_database(self):
        for before, events, audit, rows in (("30", "30", "90", 1), ("200", "200", "200", 0)):
            with self.subTest(before=before):
                db, key = self.make_0112(f"ret{before}")
                conn = sqlite3.connect(db)
                conn.execute("UPDATE settings SET value = ? WHERE key = 'audit_retention_days';", (before,))
                conn.commit()
                conn.close()
                for _ in range(2):                                          # a second start changes nothing
                    r = self.run_initialise(db, key)
                    self.assertEqual(r.returncode, 0, r.stderr)
                conn = sqlite3.connect(db)
                s = dict(conn.execute("SELECT key, value FROM settings;").fetchall())
                raised = conn.execute("SELECT COUNT(*) FROM audit_log WHERE message LIKE 'Audit log retention raised%';").fetchone()[0]
                conn.close()
                self.assertEqual((s["event_retention_days"], s["audit_retention_days"], raised), (events, audit, rows))

    def test_require_2fa_on_a_0_11_2_database(self):
        db, key = self.make_0112("rq0112")
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM settings WHERE key = 'require_2fa';")
        conn.commit()
        conn.close()
        self.assertEqual(self.run_initialise(db, key).returncode, 0)
        conn = sqlite3.connect(db)
        self.assertEqual(conn.execute("SELECT value FROM settings WHERE key = 'require_2fa';").fetchone(), ("off",))
        conn.execute("UPDATE settings SET value = 'all' WHERE key = 'require_2fa';")
        conn.commit()
        conn.close()
        self.assertEqual(self.run_initialise(db, key).returncode, 0)
        conn = sqlite3.connect(db)
        self.assertEqual(conn.execute("SELECT value FROM settings WHERE key = 'require_2fa';").fetchone(), ("all",))
        conn.close()



class TrialAccountTests(unittest.TestCase):
    """REV-03: the trial runs as the monitor's own account on a copy made by root."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-trialacct-")
        self.db = os.path.join(self.tmp, "monitor.db")
        conn = sqlite3.connect(self.db)
        conn.executescript(OLD_SCHEMA)
        conn.close()
        self.saved = (compat.subprocess.run, compat._give)
        import safefile
        self.safefile = safefile
        self.saved_ids = safefile.service_ids
        self.seen = {}

    def tearDown(self):
        compat.subprocess.run, compat._give = self.saved
        self.safefile.service_ids = self.saved_ids
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake(self, ids=(1234, 5678)):
        self.safefile.service_ids = lambda *a: ids
        compat._give = lambda path, got: self.seen.setdefault("give", (path, got))

        def run(cmd, **kw):
            work = os.path.dirname(kw["cwd"])
            self.seen.update(cmd=cmd, kw=kw, files=sorted(os.listdir(work)), code=sorted(os.listdir(kw["cwd"])),
                             profiles=sorted(os.listdir(os.path.join(kw["cwd"], "profiles"))),
                             key=read_bytes(os.path.join(work, "vault.key")) if os.path.exists(os.path.join(work, "vault.key")) else None)
            after = {"devices": 2}
            return subprocess.CompletedProcess(cmd, 0, "noise\nHM_TRIAL " + json.dumps(
                {"ok": True, "version": database.SCHEMA_VERSION, "after": after}) + "\n", "")
        compat.subprocess.run = run

    def test_trial_runs_as_the_service_account(self):
        self.fake()
        r = compat.trial(self.db, None)
        self.assertTrue(r["ok"], r)
        kw = self.seen["kw"]
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (1234, 5678, []))
        self.assertTrue(kw["cwd"].startswith(os.path.dirname(self.seen["give"][0])))
        self.assertEqual(self.seen["give"][1], (1234, 5678))
        self.assertEqual(self.seen["cmd"][-1], "trial-child")

    def test_trial_copies_the_code_it_needs(self):
        self.fake()
        compat.trial(self.db, None)
        self.assertTrue(all(n.endswith(".py") or n == "profiles" for n in self.seen["code"]), self.seen["code"])
        self.assertIn("server.py", self.seen["code"])
        self.assertTrue(all(n.endswith(".json") for n in self.seen["profiles"]))
        self.assertEqual(self.seen["files"], ["code", "monitor.db"])

    def test_trial_fails_when_the_account_is_missing(self):
        self.fake()

        def missing(*a):
            raise KeyError("homelab-monitor")
        self.safefile.service_ids = missing
        r = compat.trial(self.db, None)
        self.assertFalse(r["ok"])
        self.assertIn("that account is missing", r["message"])
        self.assertNotIn("cmd", self.seen)

    def test_trial_environment_is_minimal(self):
        self.fake()
        os.environ["MONITOR_MASTER_KEY"], os.environ["HM_SECRET_X"] = "x", "y"
        try:
            compat.trial(self.db, None)
        finally:
            os.environ.pop("MONITOR_MASTER_KEY")
            os.environ.pop("HM_SECRET_X")
        env = self.seen["kw"]["env"]
        self.assertNotIn("MONITOR_MASTER_KEY", env)
        self.assertFalse([k for k in env if k.startswith("HM_")])
        self.assertTrue(set(env) <= {"PATH", "LANG", "HOME", "PYTHONDONTWRITEBYTECODE", "MONITOR_DB_PATH", "MONITOR_KEY_FILE", "SYSTEMROOT", "APPDATA"})

    def test_trial_does_not_follow_a_link_at_the_key_or_vault_json(self):
        if os.name != "posix":
            self.skipTest("following links is a POSIX matter (checked on Linux)")
        self.fake()
        secret = os.path.join(self.tmp, "root-secret")
        with open(secret, "w") as f:
            f.write("root only")
        key = os.path.join(self.tmp, "vault.key")
        os.symlink(secret, key)
        r = compat.trial(self.db, key)
        self.assertFalse(r["ok"])
        self.assertNotIn("key", self.seen)                 # never got as far as the child
        os.remove(key)
        os.symlink(secret, os.path.join(self.tmp, "vault.json"))
        self.assertFalse(compat.trial(self.db, None)["ok"])

    def test_trial_child_really_runs(self):
        """Without root (the test suite) nothing is dropped: the real child migrates the copy."""
        r = compat.trial(self.db, None)
        self.assertTrue(r["ok"], r)


class RestoreAcrossBuildsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-compat-restore-")
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(self.data)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        conn.executescript(OLD_SCHEMA)
        conn.close()
        self.key = os.path.join(self.tmp, "keys", "vault.key")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sitectl(self, *args):
        return subprocess.run([sys.executable, SITECTL, *args], capture_output=True, text=True, timeout=300)

    def archive_with_schema(self, version):
        work = os.path.join(self.tmp, f"bk{version}")
        os.makedirs(work)
        db = os.path.join(work, "monitor.db")
        conn = sqlite3.connect(db)
        conn.executescript(OLD_SCHEMA.replace("old-switch", f"from-backup-{version}"))
        conn.execute(f"PRAGMA user_version = {version};")
        conn.close()
        path = os.path.join(self.tmp, f"monitor-backup-{version}.tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            tar.add(db, arcname="monitor.db")
        return path

    def test_backup_manifest_records_the_schema(self):
        r = self.sitectl("backup", "--data", self.data, "--dest", os.path.join(self.tmp, "out"))
        self.assertEqual(r.returncode, 0, r.stderr)
        path = r.stdout.strip().splitlines()[-1]
        with tarfile.open(path) as tar:
            manifest = json.load(tar.extractfile("manifest.json"))
        self.assertEqual(manifest["schema"], 0)
        self.assertTrue(manifest["app_version"])

    def test_restore_refuses_a_newer_backup_and_keeps_the_data(self):
        before = read_bytes(os.path.join(self.data, "monitor.db"))
        # Hand-built archives carry no tag: confirmed on purpose, as restore.sh asks.
        r = self.sitectl("restore", self.archive_with_schema(database.SCHEMA_VERSION + 1), "--data", self.data, "--key", self.key,
                         "--accept-unverified")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("newer build", r.stdout)
        self.assertIn("current data was not touched", r.stderr)
        self.assertEqual(read_bytes(os.path.join(self.data, "monitor.db")), before)

    def test_restore_accepts_an_older_backup(self):
        r = self.sitectl("restore", self.archive_with_schema(0), "--data", self.data, "--key", self.key, "--accept-unverified")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("migrates it", r.stdout)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT hostname FROM devices ORDER BY id LIMIT 1;").fetchone()[0], "from-backup-0")
        conn.close()


if __name__ == "__main__":
    unittest.main()
