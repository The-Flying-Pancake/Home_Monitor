"""Runs the test suites and writes results to tests/results/.

  py -3.15 tests/run_all.py              unit + API tests (isolated, no network)
  py -3.15 tests/run_all.py --browser    also browser tests (headless Edge/Chrome, isolated server)
  py -3.15 tests/run_all.py --live       also live checks (running server, real devices)
  py -3.15 tests/run_all.py --all        everything
  py -3.15 tests/run_all.py --shard 2/3  only every third test file, starting with the second (shards
                                         run side by side, each in its own sandbox; all of them
                                         together are the whole unit suite)

Set HM_TEST_SSH_HOST=<ip of an sshd host> to include the SSH host key and task run checks.
See TESTING.md for what each suite covers and the latest recorded results.
"""

import json
import os
import subprocess
import sys
import time
import unittest

# Captured before the unit tests import tests/_env.py, which points MONITOR_* at a sandbox.
# The live checks must see the real environment; the browser checks build their own sandbox.
ORIGINAL_ENV = dict(os.environ)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS_DIR = os.path.join(HERE, "results")


class _Recorder(unittest.TextTestResult):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"test": test.id(), "ok": True})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append({"test": test.id(), "ok": False, "detail": self._exc_info_to_string(err, test)[-600:]})

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append({"test": test.id(), "ok": False, "detail": self._exc_info_to_string(err, test)[-600:]})


def shard_files(n: int, m: int) -> list:
    """Shard n of m: every m-th test file (sorted), starting with the n-th. Shards 1..m cover each file once."""
    files = sorted(f[:-3] for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py"))
    return [f for i, f in enumerate(files) if i % m == n - 1]


def run_unit(shard: tuple = None) -> bool:
    sys.path.insert(0, ROOT)
    if shard:
        names = [f"tests.{f}" for f in shard_files(*shard)]
        print(f"Shard {shard[0]} of {shard[1]}: {', '.join(n[6:] for n in names)}")
        suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    else:
        suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=ROOT)
    runner = unittest.TextTestRunner(resultclass=_Recorder, verbosity=1)
    result = runner.run(suite)
    out = f"unit-shard{shard[0]}of{shard[1]}.json" if shard else "unit.json"
    with open(os.path.join(RESULTS_DIR, out), "w", encoding="utf-8") as f:
        json.dump({"run_at": time.strftime("%Y-%m-%d %H:%M:%S"), "passed": result.testsRun - len(result.failures) - len(result.errors),
                   "failed": len(result.failures) + len(result.errors), "results": result.records}, f, indent=2)
    return result.wasSuccessful()


def run_script(name: str) -> bool:
    return subprocess.run([sys.executable, os.path.join(HERE, name)], cwd=ROOT, env=ORIGINAL_ENV).returncode == 0


def main() -> int:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    args = set(sys.argv[1:])
    shard = None
    if "--shard" in sys.argv:
        n, m = (int(x) for x in sys.argv[sys.argv.index("--shard") + 1].split("/"))
        if not 1 <= n <= m:
            raise SystemExit("--shard N/M with 1 <= N <= M")
        shard = (n, m)
    ok = {"unit": run_unit(shard)}
    if args & {"--browser", "--all"}:
        ok["browser"] = run_script("browser_checks.py")
        ok["first run"] = run_script("first_run_check.py")
    if args & {"--live", "--all"}:
        ok["live"] = run_script("live_checks.py")
    print("\nSummary: " + ", ".join(f"{k} {'PASS' if v else 'FAIL'}" for k, v in ok.items()))
    return 0 if all(ok.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
