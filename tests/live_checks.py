"""Live checks against the running server, the real database and real devices.

Run:  py -3.15 tests/live_checks.py   (server must be running; MONITOR_URL overrides http://127.0.0.1:8080)
Login: HM_TEST_USER and HM_TEST_PASSWORD (the web UI account). Without them only
the login gate is checked and the run is reported as skipped.
Optional: HM_TEST_SSH_HOST=<ip> also checks SSH host key retrieval.

Read-only except for one normal poll per device. Uses the real vault key to
decrypt community strings in-process, only to confirm they are absent from
the raw database file. Nothing secret is printed or written to the results.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import database  # noqa: E402  (real MONITOR_DB_PATH / default, not the test sandbox)
import poller  # noqa: E402
import ssh_runner  # noqa: E402
from vault import VAULT  # noqa: E402

BASE = os.environ.get("MONITOR_URL", "http://127.0.0.1:8080")
EXPECTED_TABLES = {"unifi_switch": {"interfaces", "fdb"}, "unifi_ap": {"interfaces", "radios", "ssids"},
                   "unifi_gateway": {"interfaces", "arp"}, "qnap_nas": {"interfaces", "disks", "volumes"},
                   "linux_host": {"interfaces", "storage", "processes", "software"},
                   "windows_host": {"interfaces", "storage", "processes", "services", "software"}}
RESULTS = []
COOKIE = {"value": ""}


def api(path, body=None):
    headers = {"Content-Type": "application/json"}
    if COOKIE["value"]:
        headers["Cookie"] = COOKIE["value"]
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        cookie = r.headers.get("Set-Cookie")
        if cookie:
            COOKIE["value"] = cookie.split(";", 1)[0]
        return json.load(r)


def login() -> bool:
    """Checks the gate, then logs in with HM_TEST_USER / HM_TEST_PASSWORD. False when they are not set."""
    try:
        api("/api/devices")
        record("API refuses requests without a login", False, "returned data without a session")
    except urllib.error.HTTPError as exc:
        record("API refuses requests without a login", exc.code == 401, f"HTTP {exc.code}")
    user, password = os.environ.get("HM_TEST_USER"), os.environ.get("HM_TEST_PASSWORD")
    if not user or not password:
        print("  SKIP  remaining live checks: set HM_TEST_USER and HM_TEST_PASSWORD to the web UI login")
        return False
    api("/api/auth/login", {"username": user, "password": password})
    return True


def record(name, ok, detail=""):
    RESULTS.append({"test": name, "ok": bool(ok), "detail": detail})
    print(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}")


def main() -> int:
    print(f"Live checks against {BASE}")
    if not login():
        write_results(skipped=True)
        return 0 if all(r["ok"] for r in RESULTS) else 1
    system = api("/api/system")
    record("Server responds", True, f"version {system['version']}, {system['devices']} devices")
    v = system["vault"]
    record("Vault enabled with key outside the data folder", v["enabled"] and not v["key_beside_database"],
           f"{v['encrypted_items']} encrypted items")

    settings = api("/api/settings")
    poll = int(settings["default_poll_interval"])
    devices = api("/api/devices")["devices"]
    now = time.time()
    profiles = poller.load_hardware_profiles()

    VAULT.load(os.path.dirname(os.path.abspath(database.DB_FILE)))
    communities = {d["id"]: database.get_device(d["id"])["snmp_community"] for d in devices}
    with database.get_connection() as conn:
        conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
    raw = b""
    for suffix in ("", "-wal"):
        if os.path.exists(database.DB_FILE + suffix):
            with open(database.DB_FILE + suffix, "rb") as f:
                raw += f.read()
    leaked = sum(1 for c in set(communities.values()) if c and c.encode() in raw)
    record("No community string in plaintext in the real database files", leaked == 0,
           f"{len(set(communities.values()))} distinct communities checked")

    for d in devices:
        name = f"{d['hostname']} ({d['profile_id']})"
        detail = api(f"/api/devices/{d['id']}")
        tables = set(detail["sections"])
        fresh = d["last_seen"] and now - d["last_seen"] < max(3 * int(settings["default_ping_interval"]), 180)
        latest = max((m["timestamp"] for m in detail["latest_metrics"]), default=0)
        polled = now - latest < 3 * poll
        restricted = any(p["problem_key"] == "snmp_view" for p in detail["problems"])
        # A restricted snmpd view is a host setting the app already reports; its tables cannot exist yet.
        missing = set() if restricted else EXPECTED_TABLES.get(d["profile_id"], set()) - tables
        probe = poller.probe_device(d["ip_address"], communities[d["id"]], d["snmp_port"])
        template_ok = probe.get("profile_id") == d["profile_id"]
        ok = d["status"] == "online" and fresh and polled and not missing and template_ok
        record(f"Device {name}", ok,
               f"{d['status']}, SNMP {detail['device'].get('snmp_status')}, metrics {len(detail['latest_metrics'])}, "
               f"tables {sorted(tables)}" + (f", MISSING {sorted(missing)}" if missing else "")
               + ("" if template_ok else f", auto-detect says {probe.get('profile_id')}")
               + ("" if polled else ", metrics stale") + (", restricted snmpd view (Fix SNMP)" if restricted else ""))

    storage = system["storage"]
    record("Database growth within the planned budget", storage["metric_rows_per_day"] < 150000,
           f"{storage['metric_rows_per_day']:,} rows/day, {storage['total_bytes'] / 1e6:.1f} MB")

    problems = api("/api/problems")["problems"]
    record("Problem engine reachable", True, f"{len(problems)} open problem(s)")

    host = os.environ.get("HM_TEST_SSH_HOST")
    if host:
        k = ssh_runner.fetch_host_key(host)
        record(f"SSH host key retrieval from {host}", "fingerprint" in k, k.get("fingerprint") or k.get("error", ""))

    write_results()
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


def write_results(skipped: bool = False) -> None:
    out = os.path.join(ROOT, "tests", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "live.json"), "w", encoding="utf-8") as f:
        json.dump({"run_at": time.strftime("%Y-%m-%d %H:%M:%S"), "skipped": skipped, "results": RESULTS}, f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
