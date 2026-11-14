"""The full test run in one command: the unit tests and the browser checks, split into shards that
run side by side, each in its own sandbox (its own database, key and port).

  py -3.15 tests/run_parallel.py                    6 unit shards and 3 browser shards (the default)
  py -3.15 tests/run_parallel.py --unit 4 --browser 2
  py -3.15 tests/run_parallel.py --no-browser       unit tests only
  py -3.15 tests/run_parallel.py --save-weights     afterwards, store each file's and check's time in
                                                    tests/shard_weights.json, so the shards stay even

Each shard's output goes to tests/results/logs/. At the end one line per shard and the FAIL and ERROR
lines of any that did not pass. The exit code is 0 only when every shard passed.

The defaults use 9 processes at once (each browser shard is a server and a headless browser too).
On a 24-thread development PC the tests mostly wait, so this leaves plenty of room. Keep the
total at about half the threads at most.
"""

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(HERE, "results")
LOGS = os.path.join(RESULTS, "logs")
MAX_PROCESSES = 12


def _arg(name: str, default: int) -> int:
    if name in sys.argv:
        return int(sys.argv[sys.argv.index(name) + 1])
    return default


def _tail_problems(path: str) -> list:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return ["(no log)"]
    return [l for l in lines if l.startswith(("FAIL:", "ERROR:", "  FAIL  "))][:20]


def save_weights(unit: int, browser: int) -> None:
    """Seconds per test file and per browser check, from the shard results of this run."""
    weights = {"unit": {}, "unit_methods": {}, "browser": {}}
    try:
        with open(os.path.join(HERE, "shard_weights.json"), encoding="utf-8") as f:
            old = json.load(f)
        for k in weights:
            weights[k].update(old.get(k) or {})
    except (OSError, ValueError):
        pass
    # A class split over several shards: its time is the sum of its parts.
    classes, methods = {}, {}
    for n in range(1, unit + 1):
        try:
            with open(os.path.join(RESULTS, f"unit-shard{n}of{unit}.json"), encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        for k, v in (data.get("seconds") or {}).items():
            classes[k] = classes.get(k, 0.0) + v
        methods.update(data.get("methods") or {})
    weights["unit"].update(classes)
    # Method times are kept only for slow classes (the ones that are split).
    slow = {c for c, v in weights["unit"].items() if v > 60}
    weights["unit_methods"] = {k: round(v, 2) for k, v in sorted({**weights["unit_methods"], **methods}.items())
                               if k.rsplit(".", 1)[0] in slow}
    for n in range(1, browser + 1):
        try:
            with open(os.path.join(RESULTS, f"browser-shard{n}of{browser}.json"), encoding="utf-8") as f:
                for r in json.load(f).get("results") or []:
                    if r.get("fn") and r["fn"] not in ("t_login", "t_no_js_errors"):
                        weights["browser"][r["fn"]] = r.get("seconds", 0)
        except (OSError, ValueError):
            pass
    present = {f[:-3] for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py")}
    # Per class ("test_file.ClassName"), for files that still exist.
    weights["unit"] = {k: round(v, 1) for k, v in sorted(weights["unit"].items()) if "." in k and k.split(".")[0] in present}
    weights["browser"] = {k: round(v, 1) for k, v in sorted(weights["browser"].items())}
    with open(os.path.join(HERE, "shard_weights.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(weights, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"Saved the times of {len(weights['unit'])} test files and {len(weights['browser'])} browser checks")


def main() -> int:
    unit = _arg("--unit", 6)
    browser = 0 if "--no-browser" in sys.argv else _arg("--browser", 3)
    if unit < 1 or browser < 0 or unit + browser > MAX_PROCESSES:
        raise SystemExit(f"Between 1 and {MAX_PROCESSES} shards in all")
    os.makedirs(LOGS, exist_ok=True)
    jobs = [(f"unit {n}/{unit}", [sys.executable, os.path.join(HERE, "run_all.py"), "--shard", f"{n}/{unit}"],
             os.path.join(LOGS, f"unit-{n}of{unit}.txt")) for n in range(1, unit + 1)]
    jobs += [(f"browser {n}/{browser}", [sys.executable, os.path.join(HERE, "browser_checks.py"), "--shard", f"{n}/{browser}"],
              os.path.join(LOGS, f"browser-{n}of{browser}.txt")) for n in range(1, browser + 1)]
    started = time.monotonic()
    running = []
    for name, cmd, log in jobs:
        out = open(log, "w", encoding="utf-8")
        running.append((name, subprocess.Popen(cmd, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT), out, log, time.monotonic()))
    print(f"Started {len(jobs)} shards; logs in {LOGS}")
    results, waiting = [], list(running)
    while waiting:
        for job in list(waiting):
            name, proc, out, log, t0 = job
            code = proc.poll()
            if code is None:
                continue
            out.close()
            results.append((name, code, time.monotonic() - t0, log))
            waiting.remove(job)
        if waiting:
            time.sleep(1)
    order = [j[0] for j in jobs]
    results.sort(key=lambda r: order.index(r[0]))
    total = time.monotonic() - started
    failed = [r for r in results if r[1] != 0]
    for name, code, secs, log in results:
        print(f"  {'PASS' if code == 0 else 'FAIL'}  {name:<12} {secs:6.0f} s")
    for name, code, secs, log in failed:
        print(f"\n{name} did not pass ({log}):")
        for line in _tail_problems(log):
            print(f"    {line}")
    print(f"\n{len(results) - len(failed)} of {len(results)} shards passed in {total:.0f} s")
    if "--save-weights" in sys.argv:
        save_weights(unit, browser)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
