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
        r = self.sitectl("restore", self.archive_with_schema(database.SCHEMA_VERSION + 1), "--data", self.data, "--key", self.key)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("newer build", r.stdout)
        self.assertIn("current data was not touched", r.stderr)
        self.assertEqual(read_bytes(os.path.join(self.data, "monitor.db")), before)

    def test_restore_accepts_an_older_backup(self):
        r = self.sitectl("restore", self.archive_with_schema(0), "--data", self.data, "--key", self.key)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("migrates it", r.stdout)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT hostname FROM devices ORDER BY id LIMIT 1;").fetchone()[0], "from-backup-0")
        conn.close()


if __name__ == "__main__":
    unittest.main()
