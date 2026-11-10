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
     vault.json and key (never through a link) and this build's code into a new temporary folder,
     hands the copy to the monitor's own account and runs this build's full startup migration on
     it in a separate process as that account (server.initialise; uid and gid dropped, no other
     groups, a minimal environment), so root never runs the app's code on data the app could
     write. The copy must pass the integrity check again, carry the new version, and keep every
     device, account, credential and workflow. The original is never opened for writing.
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
    if os.path.islink(db):
        return dict(report, verdict="damaged", message=f"{db} is a link, so it was not opened")
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


MISSING_ACCOUNT = "The data check could not run as the monitor's own account: that account is missing."


def _copy_code(dest: str) -> None:
    """The code the trial needs: top-level *.py and profiles/ (never data, keys or other folders)."""
    os.makedirs(dest)
    for name in os.listdir(HERE):
        src = os.path.join(HERE, name)
        if name.endswith(".py") and os.path.isfile(src) and not os.path.islink(src):
            shutil.copyfile(src, os.path.join(dest, name))
    prof = os.path.join(HERE, "profiles")
    if os.path.isdir(prof) and not os.path.islink(prof):
        os.makedirs(os.path.join(dest, "profiles"))
        for name in os.listdir(prof):
            src = os.path.join(prof, name)
            if name.endswith(".json") and os.path.isfile(src) and not os.path.islink(src):
                shutil.copyfile(src, os.path.join(dest, "profiles", name))


def _give(path: str, ids) -> None:
    """Hands a copy to the monitor's account without following links, files first."""
    if not ids:
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for n in files + dirs:
            os.chown(os.path.join(root, n), ids[0], ids[1], follow_symlinks=False)
    os.chown(path, ids[0], ids[1], follow_symlinks=False)


def _trial_child() -> None:
    """Runs inside the copy, as the monitor's account: this build's startup on the copied database,
    then the checks, printed as one JSON line for root to read (root opens nothing the child wrote)."""
    import server
    server.initialise()
    db = os.environ["MONITOR_DB_PATH"]
    conn = _ro(db)
    try:
        ok = conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        version = int(conn.execute("PRAGMA user_version;").fetchone()[0])
        after = _counts(conn, _tables(conn))
    finally:
        conn.close()
    print("HM_TRIAL " + json.dumps({"ok": ok, "version": version, "after": after}))


def trial(db: str, key: Optional[str]) -> Dict[str, Any]:
    """Runs this build's startup migration on a private copy, as the monitor's own account, and checks
    nothing was lost. The copy (database, vault.json, key and this build's code) is made by root in a
    new folder, then handed to that account; the child process runs with its uid and gid, no other
    groups and a minimal environment."""
    import safefile
    try:
        ids = safefile.service_ids()
    except KeyError:
        return {"ok": False, "message": MISSING_ACCOUNT}
    work = tempfile.mkdtemp(prefix="hm-trial-")
    try:
        os.chmod(work, 0o700)
        if os.path.islink(db):
            return {"ok": False, "message": "The database is a link, so the trial did not run"}
        copy = os.path.join(work, "monitor.db")
        src, dst = _ro(db), sqlite3.connect(copy)
        src.backup(dst)
        src.close()
        dst.close()
        # vault.json and the key are read without following a link (a link could point anywhere).
        meta = os.path.join(os.path.dirname(os.path.abspath(db)), "vault.json")
        if os.path.lexists(meta):
            with open(os.path.join(work, "vault.json"), "wb") as f:
                f.write(safefile.read_regular(meta, 1024 * 1024))
        if key and os.path.lexists(key):
            with open(os.path.join(work, "vault.key"), "wb") as f:
                f.write(safefile.read_regular(key, 4096))
        _copy_code(os.path.join(work, "code"))
        conn = _ro(copy)
        before = _counts(conn, _tables(conn))
        conn.close()
        _give(work, ids)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": os.environ.get("LANG", "C.UTF-8"), "HOME": work,
               "PYTHONDONTWRITEBYTECODE": "1", "MONITOR_DB_PATH": copy, "MONITOR_KEY_FILE": os.path.join(work, "vault.key")}
        if os.name == "nt":                     # Windows (the test suite): Python needs these to start and find packages
            env.update({k: os.environ[k] for k in ("SYSTEMROOT", "APPDATA") if k in os.environ})
        kw = {"user": ids[0], "group": ids[1], "extra_groups": []} if ids else {}
        # Isolated from the environment and user packages (on Windows, the test suite, the user's own
        # packages hold cryptography, so only the environment is ignored there).
        flags = ["-I", "-B"] if os.name == "posix" else ["-E", "-B"]
        r = subprocess.run([sys.executable, *flags, os.path.join(work, "code", "compat.py"), "trial-child"],
                           cwd=os.path.join(work, "code"), env=env, capture_output=True, text=True, timeout=600, **kw)
        if r.returncode != 0:
            last = [l for l in (r.stderr or r.stdout).strip().splitlines() if l.strip()][-3:]
            return {"ok": False, "message": "The migration stopped: " + " | ".join(last)}
        lines = [l for l in (r.stdout or "").splitlines() if l.startswith("HM_TRIAL ")]
        try:
            res = json.loads(lines[-1][len("HM_TRIAL "):])
            ok, version = bool(res["ok"]), int(res["version"])
            after = {str(k): int(v) for k, v in dict(res["after"]).items()}
        except (IndexError, ValueError, KeyError, TypeError):
            return {"ok": False, "message": "The trial gave no readable answer"}
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
    sub.add_parser("trial-child")          # inside the trial's copy, as the monitor's account (see trial)
    args = ap.parse_args()
    if args.cmd == "trial-child":
        _trial_child()
        return
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
