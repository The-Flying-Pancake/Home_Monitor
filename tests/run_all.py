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
        self.seconds = {}           # "test_file.Class" -> seconds, for balancing the shards
        self.methods = {}           # "test_file.Class.test_name" -> seconds (a slow class is split by these)
        self._started = 0.0

    def startTest(self, test):
        self._started = time.monotonic()
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)
        parts = test.id().split(".")
        if parts[0] == "tests":
            parts = parts[1:]
        took = time.monotonic() - self._started
        unit = ".".join(parts[:2])          # test file and class: the shards are balanced per class
        self.seconds[unit] = self.seconds.get(unit, 0.0) + took
        self.methods[".".join(parts[:3])] = took

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"test": test.id(), "ok": True})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append({"test": test.id(), "ok": False, "detail": self._exc_info_to_string(err, test)[-600:]})

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append({"test": test.id(), "ok": False, "detail": self._exc_info_to_string(err, test)[-600:]})


WEIGHTS_FILE = os.path.join(HERE, "shard_weights.json")


def load_weights(kind: str) -> dict:
    """Seconds per test file (or browser check) from the last measured run (tests/shard_weights.json)."""
    try:
        with open(WEIGHTS_FILE, encoding="utf-8") as f:
            data = json.load(f).get(kind) or {}
        return {str(k): float(v) for k, v in data.items()}
    except (OSError, ValueError, AttributeError):
        return {}


def balance(names: list, m: int, weights: dict) -> list:
    """Splits names into m groups of about the same running time: the longest first, each into the
    group with the least time so far (an unmeasured name counts as the median). Deterministic, so
    every shard computes the same split; each name is in exactly one group."""
    known = sorted(weights[n] for n in names if n in weights)
    guess = known[len(known) // 2] if known else 1.0
    groups = [[] for _ in range(m)]
    totals = [0.0] * m
    for name in sorted(names, key=lambda n: (-weights.get(n, guess), n)):
        i = min(range(m), key=lambda k: (totals[k], k))
        groups[i].append(name)
        totals[i] += weights.get(name, guess)
    return groups


SPLIT_CLASS_SECONDS = 60     # a class that took longer is shared out per test method


def test_methods() -> list:
    """Every test as "test_file.ClassName.test_name"."""
    sys.path.insert(0, ROOT)
    files = sorted(f[:-3] for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py"))
    found = []

    def walk(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                walk(item)
            else:
                found.append(f"{type(item).__module__.split('.')[-1]}.{type(item).__name__}.{item._testMethodName}")
    walk(unittest.defaultTestLoader.loadTestsFromNames([f"tests.{f}" for f in files]))
    return sorted(set(found))


def shard_units() -> tuple:
    """What the shards share out, with their weights: every test class, except that a class which took
    longer than SPLIT_CLASS_SECONDS last time (the installer tests run the whole installer in bash, slow
    on Windows) is shared out per test method. Its setUpClass then runs once in each shard that has some."""
    classes = load_weights("unit")
    methods = load_weights("unit_methods")
    units, weights = [], {}
    by_class = {}
    for m in test_methods():
        by_class.setdefault(m.rsplit(".", 1)[0], []).append(m)
    for cls, ms in sorted(by_class.items()):
        if classes.get(cls, 0) > SPLIT_CLASS_SECONDS:
            units += ms
            weights.update({m: methods[m] for m in ms if m in methods})
        else:
            units.append(cls)
            if cls in classes:
                weights[cls] = classes[cls]
    return units, weights


def shard_files(n: int, m: int) -> list:
    """Shard n of m: test classes (or a slow class's methods) balanced by their last measured time.
    Shards 1..m together run every test once."""
    units, weights = shard_units()
    return sorted(balance(units, m, weights)[n - 1])


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
                   "failed": len(result.failures) + len(result.errors), "results": result.records,
                   "seconds": {k: round(v, 1) for k, v in sorted(result.seconds.items())},
                   "methods": {k: round(v, 2) for k, v in sorted(result.methods.items())}}, f, indent=2)
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
