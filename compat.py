"""Can this build run on that data? Checks a database (the live one before an upgrade, or the one
inside a backup before a restore) without changing it.

  python3 compat.py check --db FILE [--key FILE] [--trial] [--json]

Steps:
  1. The file opens and passes SQLite's integrity check.
  2. Its schema version (PRAGMA user_version, see database.SCHEMA_VERSION):
       same      nothing to migrate
       older     this build migrates it on start (every migration is additive and idempotent)
       newer     written by a newer build: refused, this code would misread tables it does not know
       too old   older than database.MIN_SCHEMA_VERSION: upgrade through an intermediate build first
  3. --trial: copies the file (SQLite backup API, so a running service is no problem) with its
     vault.json and key into a private temporary folder, runs this build's full startup migration
     on the copy in a separate process (server.initialise), and compares before and after: the
     copy must pass the integrity check again, carry the new version, and keep every device,
     account, credential and workflow. The original is never opened for writing.
  4. Notes for what an older file carries that this build no longer has (templates that are gone,
     tables nothing reads). They are kept, never deleted: a later build may use them again.

Exit codes: 0 can run (same or older), 3 newer, 4 damaged or not a monitor database, 5 the trial
migration failed, 6 too old. --json prints the report as JSON for home_monitor.sh and restore.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

EXIT = {"same": 0, "older": 0, "newer": 3, "damaged": 4, "trial_failed": 5, "too_old": 6}
# Kept across a migration: losing any of these rows would be data loss, not a schema change.
KEPT_TABLES = ("devices", "accounts", "credentials", "workflows", "alert_overrides", "custom_oids", "map_objects")


def _ro(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def _counts(conn: sqlite3.Connection, tables: List[str]) -> Dict[str, int]:
    return {t: conn.execute(f'SELECT COUNT(*) FROM "{t}";').fetchone()[0] for t in KEPT_TABLES if t in tables}


def _tables(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';")]


def inspect(db: str) -> Dict[str, Any]:
    """Version, integrity and notes for one database file, read only."""
    import database
    report: Dict[str, Any] = {"db": db, "build_schema": database.SCHEMA_VERSION, "notes": []}
    if not os.path.exists(db):
        return dict(report, verdict="damaged", message=f"No database at {db}")
    try:
        conn = _ro(db)
        try:
            ok = conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
            version = int(conn.execute("PRAGMA user_version;").fetchone()[0])
            tables = _tables(conn)
            counts = _counts(conn, tables) if ok else {}
            profiles = [r[0] for r in conn.execute("SELECT DISTINCT profile_id FROM devices;")] if ok and "devices" in tables else []
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return dict(report, verdict="damaged", message=f"Not a readable SQLite database: {exc}")
    report.update(schema=version, tables=len(tables), counts=counts)
    if not ok:
        return dict(report, verdict="damaged", message="The database fails SQLite's integrity check")
    if "settings" not in tables or "devices" not in tables:
        return dict(report, verdict="damaged", message="This is not a Homelab Monitor database (no settings or devices table)")
    if version > database.SCHEMA_VERSION:
        return dict(report, verdict="newer", message=(
            f"Written by a newer build (schema {version}; this build knows up to {database.SCHEMA_VERSION}). "
            "Use the newer home_monitor.sh, or a backup made before that upgrade."))
    if version < database.MIN_SCHEMA_VERSION:
        return dict(report, verdict="too_old", message=(
            f"Schema {version} is older than this build can migrate (from {database.MIN_SCHEMA_VERSION}). "
            "Restore it with an intermediate build first, then upgrade."))
    shipped = {f[:-5] for f in os.listdir(os.path.join(HERE, "profiles")) if f.endswith(".json")} \
        if os.path.isdir(os.path.join(HERE, "profiles")) else set()
    gone = sorted(p for p in profiles if shipped and p not in shipped)
    if gone:
        report["notes"].append("Devices use templates this build does not ship (" + ", ".join(gone) +
                               "): they keep their data and are polled for reachability; pick a template in Edit.")
    if version == database.SCHEMA_VERSION:
        return dict(report, verdict="same", message="Same schema as this build: nothing to migrate")
    return dict(report, verdict="older", message=(
        f"Schema {version}{' (from before versions were kept)' if version == 0 else ''}: "
        f"this build migrates it to {database.SCHEMA_VERSION} on start"))


def trial(db: str, key: Optional[str]) -> Dict[str, Any]:
    """Runs this build's startup migration on a private copy and checks nothing was lost."""
    work = tempfile.mkdtemp(prefix="hm-trial-")
    try:
        os.chmod(work, 0o700)
        copy = os.path.join(work, "monitor.db")
        src, dst = _ro(db), sqlite3.connect(copy)
        src.backup(dst)
        src.close()
        dst.close()
        meta = os.path.join(os.path.dirname(os.path.abspath(db)), "vault.json")
        if os.path.exists(meta):
            shutil.copy2(meta, os.path.join(work, "vault.json"))
        # The copy gets its own key file: the trial never reads or creates a key anywhere else.
        env = {k: v for k, v in os.environ.items() if k != "MONITOR_MASTER_KEY"}
        env.update(MONITOR_DB_PATH=copy, MONITOR_KEY_FILE=os.path.join(work, "vault.key"))
        if key and os.path.exists(key):
            shutil.copy2(key, os.path.join(work, "vault.key"))
        conn = _ro(copy)
        before = _counts(conn, _tables(conn))
        conn.close()
        r = subprocess.run([sys.executable, "-c", "import server; server.initialise()"], cwd=HERE, env=env,
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            last = [l for l in (r.stderr or r.stdout).strip().splitlines() if l.strip()][-3:]
            return {"ok": False, "message": "The migration stopped: " + " | ".join(last)}
        conn = _ro(copy)
        try:
            ok = conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
            version = int(conn.execute("PRAGMA user_version;").fetchone()[0])
            after = _counts(conn, _tables(conn))
        finally:
            conn.close()
        import database
        lost = {t: (n, after.get(t, 0)) for t, n in before.items() if after.get(t, 0) < n}
        if not ok:
            return {"ok": False, "message": "The migrated copy fails the integrity check"}
        if version != database.SCHEMA_VERSION:
            return {"ok": False, "message": f"The migrated copy has schema {version}, expected {database.SCHEMA_VERSION}"}
        if lost:
            return {"ok": False, "message": "Rows would be lost: " + ", ".join(f"{t} {a} -> {b}" for t, (a, b) in lost.items())}
        return {"ok": True, "message": f"Trial migration on a copy passed ({', '.join(f'{n} {t}' for t, n in after.items())})"}
    except (sqlite3.Error, OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": f"The trial could not run: {exc}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check(db: str, key: Optional[str] = None, run_trial: bool = False) -> Dict[str, Any]:
    report = inspect(db)
    if run_trial and report["verdict"] in ("same", "older"):
        t = trial(db, key)
        report["trial"] = t
        if not t["ok"]:
            report.update(verdict="trial_failed", message=t["message"])
    report["exit"] = EXIT[report["verdict"]]
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check")
    p.add_argument("--db", required=True)
    p.add_argument("--key")
    p.add_argument("--trial", action="store_true")
    p.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = check(args.db, args.key, args.trial)
    if args.json:
        print(json.dumps(report))
    else:
        print(report["message"])
        if report.get("trial"):
            print(report["trial"]["message"])
        for n in report["notes"]:
            print("Note: " + n)
    sys.exit(report["exit"])


if __name__ == "__main__":
    main()
