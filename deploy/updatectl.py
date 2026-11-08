"""Update and roll back from the public repository, run by root on the box. Standard library only.

  updatectl.py requests --data DIR      what the web app asked for (DATA/requests/update-*), one by one
  updatectl.py check    --data DIR      the newest release: version, date and notes (changes nothing)
  updatectl.py install  --data DIR      download, check the signature, refuse older versions, upgrade
  updatectl.py rollback --data DIR --mode code|all
  updatectl.py prune    --data DIR      pre-update backups older than two days are removed
  updatectl.py record   --data DIR --kind upgrade --ok 1|0 [--from V --to V --why W --log FILE --source host]
                                        add an upgrade run from the Proxmox host to the update history

How an update is trusted: a release carries home_monitor.sh and home_monitor.sh.sig. The signature is checked
with ssh-keygen against release-signers, the public key built into the app that is installed now
(never one that came with the download). Only a newer version than the one running is installed.
The upgrade itself is home_monitor.sh's own (--update-here): check the data with the new build, back up,
replace, wait for an answer, put everything back if it does not answer.

Every update keeps its own backup in DATA/backups/pre-update, and the app that ran before stays in
APP_DIR.old. For two days the update can be undone:
  code  the previous version on today's data (only when the data still suits the older version:
        an update that changed the database's layout cannot go back this way)
  all   the previous version and the data from just before the update (later changes are lost)
Before a rollback the current state is backed up into DATA/backups/pre-rollback.

Requests come from the app (an unprivileged user) as files whose content is only a time; nothing in
them is run or trusted beyond choosing one of the fixed actions above.

What the app can read back: DATA/update-progress.json while an update runs (which step it is on),
and the update history in INSTALL_DIR (root's folder, readable by the app's group): every update,
upgrade and rollback with its result, and its log as a numbered file. The app only ever opens a log
by the number it finds in the history, never by a name or path from the browser.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = "The-Flying-Pancake/Home_Monitor"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
INSTALLER_NAMES = ("home_monitor.sh", "infra.sh")
API_LIST = f"https://api.github.com/repos/{REPO}/releases?per_page=30"
APP_DIR = "/opt/homelab-monitor"
INSTALL_DIR = "/etc/homelab-monitor-install"
STATE_FILE = os.path.join(INSTALL_DIR, "last-update.json")
HISTORY_NAME, LOGS_NAME = "update-history.json", "update-logs"     # in INSTALL_DIR
HISTORY_KEEP = 25
LOG_LIMIT = 400 * 1024              # the end of a log is kept when it is longer
# The steps of an update as the app shows them: two here, the rest are home_monitor.sh's own (run_step ids).
STEPS = ("download", "verify", "ready", "copy", "check", "repair", "backup", "replace", "health")
_STEP_LINE = re.compile(r"^\s*\.\.\. ([a-z]+)( \(skipped\))?\s*$")
SIGNERS = os.path.join(HERE, "release-signers")
IDENTITY = "release@home-monitor"
NAMESPACE = "home-monitor-release"
KEEP_SECONDS = 2 * 24 * 3600
MAX_DOWNLOAD = 20 * 1024 * 1024
ACTIONS = ("update-check", "update-install", "rollback-code", "rollback-all")
_VERSION = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")


class UpdateError(Exception):
    pass


def version_tuple(v: str) -> tuple:
    v = (v or "").strip().lstrip("v")
    if not _VERSION.fullmatch(v):
        raise UpdateError(f"Not a version number: {v[:40]!r}")
    return tuple(int(x) for x in v.split("."))


def installed_version(app_dir: str = "") -> str:
    app_dir = app_dir or APP_DIR
    try:
        with open(os.path.join(app_dir, "server.py"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("APP_VERSION = "):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def write_result(data: str, kind: str, payload: dict) -> None:
    write_json(data, f"{kind}.result.json", payload)


def write_json(data: str, name: str, payload: dict) -> None:
    """DATA/<name> through a new randomly named file, renamed into place (links are never followed)."""
    path = os.path.join(data, name)
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".new", dir=data)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dict(payload, time=int(time.time())), f)
        owner = os.stat(data)
        try:
            os.chown(tmp, owner.st_uid, owner.st_gid, follow_symlinks=False)
        except (AttributeError, PermissionError, NotImplementedError):
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _get(url: str, limit: int, accept: str = "application/octet-stream") -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "home-monitor-updater", "Accept": accept})
    with urllib.request.urlopen(req, timeout=60) as r:      # GitHub's download links redirect to its file host
        data = r.read(limit + 1)
    if len(data) > limit:
        raise UpdateError("The download is larger than an installer can be")
    return data


def _refresh_firewall() -> None:
    """GitHub's addresses change: the outbound firewall's list is refreshed before going out."""
    script = "/etc/homelab-monitor-egress/refresh.sh"
    if os.path.exists(script):
        subprocess.run([script], capture_output=True, timeout=120)


def latest_release(fetch=None) -> dict:
    """The newest release: version, name, date, notes and the two download links."""
    if fetch is None:
        fetch = _get
        if fetch.__module__ == __name__:     # the real download (not a test's stand-in)
            _refresh_firewall()
    try:
        meta = json.loads(fetch(API, 512 * 1024, "application/vnd.github+json"))
    except UpdateError:
        raise
    except Exception as exc:
        raise UpdateError(f"Could not reach the release page on GitHub ({type(exc).__name__}). "
                          "Is the box allowed out to GitHub (the outbound firewall) and is DNS working?")
    assets = {a.get("name"): a.get("browser_download_url") for a in meta.get("assets") or []}
    # home_monitor.sh since 0.10.0; infra.sh (its old name) in releases before that.
    name = next((n for n in INSTALLER_NAMES if assets.get(n) and assets.get(n + ".sig")), None)
    if not name:
        raise UpdateError("The newest release has no signed installer (home_monitor.sh and home_monitor.sh.sig)")
    version = str(meta.get("tag_name") or "").lstrip("v")
    version_tuple(version)
    for url in (assets[name], assets[name + ".sig"]):
        if not str(url).startswith(f"https://github.com/{REPO}/releases/download/"):
            raise UpdateError("The release links do not point at this project's releases")
    return {"version": version, "name": str(meta.get("name") or "")[:200], "published": str(meta.get("published_at") or ""),
            "notes": str(meta.get("body") or "")[:6000], "url": str(meta.get("html_url") or ""),
            "installer": assets[name], "signature": assets[name + ".sig"]}


def notes_between(current: str, latest: str, fetch=None) -> list:
    """Release notes of every version newer than current up to latest, newest first (at most 30).
    When the list cannot be read, an empty list (the latest release's own notes still show)."""
    fetch = fetch or _get
    try:
        rows = json.loads(fetch(API_LIST, 2 * 1024 * 1024, "application/vnd.github+json"))
    except Exception:
        return []
    out = []
    low, high = version_tuple(current or "0.0.0"), version_tuple(latest)
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        v = str(r.get("tag_name") or "").lstrip("v")
        try:
            vt = version_tuple(v)
        except UpdateError:
            continue
        if low < vt <= high:
            out.append({"version": v, "name": str(r.get("name") or "")[:200], "published": str(r.get("published_at") or "")[:40],
                        "notes": str(r.get("body") or "")[:6000]})
    out.sort(key=lambda x: version_tuple(x["version"]), reverse=True)
    return out[:30]


def verify_signature(installer: str, signature: str, signers: str = "") -> None:
    """ssh-keygen -Y verify against the key in the installed app; raises UpdateError when it does not match."""
    signers = signers or SIGNERS
    if not os.path.exists(signers):
        raise UpdateError("This install has no release key (release-signers): update once with home_monitor.sh --upgrade")
    with open(installer, "rb") as data:
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", signers, "-I", IDENTITY, "-n", NAMESPACE, "-s", signature],
                           stdin=data, capture_output=True, text=True)
    if r.returncode != 0:
        why = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        raise UpdateError("The download's signature does not match the release key; nothing was installed (" + why[0][:200] + ")")


def installer_version(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^VERSION="([0-9.]+)"', line)
            if m:
                return m.group(1)
            if line.startswith("__PAYLOAD_BEGIN__"):
                break
    raise UpdateError("The installer does not say which version it is")


def _read_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_state(state: dict) -> None:
    os.makedirs(INSTALL_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".last-update.", dir=INSTALL_DIR)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.chmod(tmp, 0o640)
    try:
        import grp
        os.chown(tmp, 0, grp.getgrnam("homelab-monitor").gr_gid)
    except (ImportError, KeyError, PermissionError, AttributeError):
        pass
    os.replace(tmp, STATE_FILE)


def prune(data: str, now: float = None) -> list:
    """Pre-update and pre-rollback backups older than two days are removed; returns what went."""
    now = time.time() if now is None else now
    gone = []
    for sub in ("pre-update", "pre-rollback"):
        folder = os.path.join(data, "backups", sub)
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            path = os.path.join(folder, name)
            if name.startswith("monitor-backup-") and not os.path.islink(path) and now - os.path.getmtime(path) > KEEP_SECONDS:
                os.remove(path)
                gone.append(path)
    return gone


def rollback_options(data: str, now: float = None) -> dict:
    """Which ways back are open now, and why not when they are not."""
    now = time.time() if now is None else now
    state = _read_state()
    out = {"from": state.get("to_version"), "to": state.get("from_version"), "code": False, "all": False, "why": ""}
    backup = state.get("backup") or ""
    if not state:
        out["why"] = "No update has been installed from here yet"
    elif now - float(state.get("time") or 0) > KEEP_SECONDS or not os.path.isfile(backup):
        out["why"] = "The copy kept for two days after the update has expired"
    elif installed_version(APP_DIR + ".old") != state.get("from_version") or installed_version(APP_DIR) != state.get("to_version"):
        out["why"] = "The previous version is no longer beside this one"
    else:
        out["all"] = True
        out["code"] = bool(state.get("schema_same"))
        if not out["code"]:
            out["why_code"] = "The update changed how the data is stored, so the older version cannot use today's data"
        out["expires"] = int(float(state["time"]) + KEEP_SECONDS)
    return out


def _schema(db: str) -> int:
    import sqlite3
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return int(conn.execute("PRAGMA user_version;").fetchone()[0])
    finally:
        conn.close()


def check(args) -> dict:
    current = installed_version()
    rel = latest_release()
    newer = version_tuple(rel["version"]) > version_tuple(current or "0.0.0")
    out = {"ok": True, "current": current, "latest": rel["version"], "name": rel["name"], "published": rel["published"],
           "notes": rel["notes"], "url": rel["url"], "newer": newer,
           "changes": notes_between(current, rel["version"]) if newer else []}
    write_result(args.data, "update-check", out)
    return out


def _stream(cmd, on_line=None, **kw) -> subprocess.CompletedProcess:
    """Runs cmd and hands each line of its output to on_line as it comes (the progress screen)."""
    kw.pop("capture_output", None)
    kw.pop("text", None)
    lines = []
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", **kw) as proc:
        for line in proc.stdout:
            lines.append(line)
            if on_line:
                on_line(line)
    return subprocess.CompletedProcess(cmd, proc.returncode, "".join(lines), "")


class Progress:
    """DATA/update-progress.json: which step an update is on, for the app's progress screen. The app
    is down for part of it (while it restarts); the file is there for when it is back."""

    def __init__(self, data: str, frm: str, to: str):
        self.data, self.state = data, {"from": frm, "to": to, "started": int(time.time()), "state": "running",
                                       "steps": {s: "pending" for s in STEPS}, "current": ""}

    def step(self, sid: str, status: str = "run") -> None:
        if sid not in STEPS:
            return
        steps = self.state["steps"]
        for s, st in steps.items():          # whatever ran before this step is done
            if st == "run" and s != sid:
                steps[s] = "ok"
        steps[sid] = status
        self.state["current"] = sid
        self.save()

    def line(self, text: str) -> None:
        m = _STEP_LINE.match(text)
        if m:
            self.step(m.group(1), "skip" if m.group(2) else "run")

    def finish(self, ok: bool, error: str = "") -> None:
        steps = self.state["steps"]
        for s, st in steps.items():
            if st == "run":
                steps[s] = "ok" if ok else "fail"
        self.state.update(state="ok" if ok else "failed", error=error[:2000], finished=int(time.time()))
        self.save()

    def save(self) -> None:
        try:
            write_json(self.data, "update-progress.json", self.state)
        except OSError:
            pass


def install(args, runner=None) -> dict:
    """Downloads the newest release, checks it, then lets its home_monitor.sh upgrade this box in place."""
    current = installed_version()
    db = os.path.join(args.data, "monitor.db")
    if not os.path.exists(os.path.join(INSTALL_DIR, "settings.env")):
        raise UpdateError("This install does not record its settings yet: run bash home_monitor.sh --upgrade once from the "
                          "Proxmox host (or --local --upgrade on this machine), then Update works from here")
    rel = latest_release()
    if version_tuple(rel["version"]) <= version_tuple(current or "0.0.0"):
        raise UpdateError(f"Already up to date ({current}); the newest release is {rel['version']}")
    progress = Progress(args.data, current, rel["version"])
    work = tempfile.mkdtemp(prefix="hm-update-", dir="/root" if os.path.isdir("/root") else None)
    log = os.path.join(work, "install.log")
    output = ""
    try:
        progress.step("download")
        installer, sig = os.path.join(work, "home_monitor.sh"), os.path.join(work, "home_monitor.sh.sig")
        for url, path in ((rel["installer"], installer), (rel["signature"], sig)):
            with open(path, "wb") as f:
                f.write(_get(url, MAX_DOWNLOAD))
        progress.step("verify")
        verify_signature(installer, sig)
        got = installer_version(installer)
        if got != rel["version"]:
            raise UpdateError(f"The installer is version {got}, the release says {rel['version']}; nothing was installed")
        schema_before = _schema(db) if os.path.exists(db) else 0
        started = time.time()
        r = (runner or _stream)(["bash", installer, "--update-here"], capture_output=True, text=True, on_line=progress.line,
                                env=dict(os.environ, NO_COLOR="1", HM_UPDATE_BACKUP="pre-update", HM_FROM_UPDATER="1",
                                         HM_LOG_FILE=log))
        output = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0:
            raise UpdateError("The update did not complete and the previous version was put back. "
                              + _last_lines(output))
        backup = _newest(os.path.join(args.data, "backups", "pre-update"), since=started - 5)
        _write_state({"from_version": current, "to_version": got, "time": int(time.time()), "backup": backup,
                      "schema_same": os.path.exists(db) and _schema(db) == schema_before})
        out = {"ok": True, "action": "install", "from": current, "to": got, "output": _last_lines(output, 30)}
        progress.finish(True)
        record({"kind": "update", "source": "app", "from": current, "to": got, "ok": True}, _log_text(log, output))
        write_result(args.data, "update", out)
        return out
    except Exception as exc:
        why = str(exc) if isinstance(exc, UpdateError) else f"{type(exc).__name__}: {exc}"
        progress.finish(False, why)
        record({"kind": "update", "source": "app", "from": current, "to": rel["version"], "ok": False, "error": why},
               _log_text(log, output))
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _log_text(path: str, fallback: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        text = ""
    return (text + ("\n\n===== What the installer printed =====\n" + fallback if fallback else "")).strip()


# --- Update history: INSTALL_DIR/update-history.json and INSTALL_DIR/update-logs/<id>.log ---

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\r")
_SECRET = re.compile(r"(?i)\b([\w-]*(?:passphrase|password|token|secret|community)[\w-]*)(\s*[=:]\s*)(\S+)")
WHY = {"blocked": "The check found something that stops an in-place upgrade; nothing was changed",
       "replace": "The new files could not be installed; the previous version was put back",
       "health": "The new version did not start; the previous version was put back"}


def clean_log(text: str) -> str:
    """Colour codes out, anything that looks like a secret masked, the end kept when it is long."""
    text = _SECRET.sub(lambda m: m.group(1) + m.group(2) + "••••", _ANSI.sub("", text or ""))
    if len(text) > LOG_LIMIT:
        text = "[The start of this log was cut; this is its end]\n" + text[-LOG_LIMIT:]
    return text


def read_history() -> list:
    try:
        with open(os.path.join(INSTALL_DIR, HISTORY_NAME), encoding="utf-8") as f:
            rows = json.load(f)
    except (OSError, ValueError):
        return []
    return [r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), int)] if isinstance(rows, list) else []


def _app_group(path: str) -> None:
    """Owned by root, readable by the app's group (the app shows it, root alone writes it)."""
    try:
        import grp
        os.chown(path, 0, grp.getgrnam("homelab-monitor").gr_gid, follow_symlinks=False)
    except (ImportError, KeyError, PermissionError, AttributeError, NotImplementedError):
        pass


def _root_file(path: str, text: str) -> None:
    """Root's own file, readable by the app's group, put in place through a new file (links never followed)."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".hm-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o640)
        _app_group(tmp)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def record(entry: dict, log_text: str = "") -> dict:
    """Adds an update, upgrade or rollback to the history (newest first, the last HISTORY_KEEP kept)."""
    rows = read_history()
    eid = max([int(time.time() * 1000)] + [r["id"] + 1 for r in rows])
    row = {"id": eid, "time": int(time.time()), "kind": str(entry.get("kind") or "update")[:20],
           "source": str(entry.get("source") or "app")[:10], "from": str(entry.get("from") or "")[:20],
           "to": str(entry.get("to") or "")[:20], "ok": bool(entry.get("ok")), "error": str(entry.get("error") or "")[:2000],
           "log": bool(log_text)}
    if log_text:
        logs = os.path.join(INSTALL_DIR, LOGS_NAME)
        os.makedirs(logs, mode=0o750, exist_ok=True)
        _app_group(logs)
        _root_file(os.path.join(INSTALL_DIR, LOGS_NAME, f"{eid}.log"), clean_log(log_text))
    rows = [row] + rows
    for old in rows[HISTORY_KEEP:]:
        try:
            os.remove(os.path.join(INSTALL_DIR, LOGS_NAME, f"{int(old['id'])}.log"))
        except OSError:
            pass
    _root_file(os.path.join(INSTALL_DIR, HISTORY_NAME), json.dumps(rows[:HISTORY_KEEP], indent=1))
    return row


def record_cmd(args) -> dict:
    """An upgrade run with home_monitor.sh from the Proxmox host (or --local): into the history with its log."""
    for v in (args.version_from, args.to):
        if v:
            version_tuple(v)
    text = ""
    if args.log:
        with open(args.log, encoding="utf-8", errors="replace") as f:
            text = f.read(LOG_LIMIT * 4)
    ok = args.ok == "1"
    return record({"kind": args.kind, "source": args.source, "from": args.version_from, "to": args.to, "ok": ok,
                   "error": "" if ok else WHY.get(args.why, "The upgrade did not complete")}, text)


def rollback(args, runner=subprocess.run) -> dict:
    try:
        return _rollback(args, runner)
    except UpdateError as exc:
        state = _read_state()
        record({"kind": f"rollback-{args.mode}", "source": "app", "from": state.get("to_version"), "to": state.get("from_version"),
                "ok": False, "error": str(exc)})
        raise


def _rollback(args, runner) -> dict:
    opts = rollback_options(args.data)
    if not opts.get(args.mode):
        raise UpdateError(opts.get("why_code") if args.mode == "code" and opts.get("all") else opts["why"] or "Not possible now")
    state = _read_state()
    data, key = args.data, "/etc/homelab-monitor/vault.key"
    old, cur = APP_DIR + ".old", APP_DIR
    sitectl = os.path.join(old, "sitectl.py")
    # The state now, kept for two days like the update's own backup.
    r = runner(["python3", os.path.join(cur, "sitectl.py"), "backup", "--data", data, "--key", key,
                "--dest", os.path.join(data, "backups", "pre-rollback"), "--keep", "5"], capture_output=True, text=True)
    if r.returncode != 0:
        raise UpdateError("Could not back up the current state first; nothing was changed. " + _last_lines(r.stdout + r.stderr))
    runner(["systemctl", "stop", "homelab-monitor"], capture_output=True, text=True)
    shutil.rmtree(cur + ".rolledback", ignore_errors=True)
    os.rename(cur, cur + ".rolledback")
    os.rename(old, cur)
    steps = []
    if args.mode == "all":
        r = runner(["python3", os.path.join(cur, "sitectl.py"), "restore", state["backup"], "--data", data, "--key", key,
                    "--passphrase-file", os.path.join(INSTALL_DIR, "backup-passphrase")], capture_output=True, text=True)
        steps.append(r.stdout + r.stderr)
        if r.returncode != 0:
            _swap_back(cur, runner)
            raise UpdateError("The backup from before the update could not be restored; the current version is "
                              "running again. " + _last_lines(r.stdout + r.stderr))
    runner(["chown", "-R", "homelab-monitor:homelab-monitor", data, "/etc/homelab-monitor"], capture_output=True, text=True)
    runner(["systemctl", "start", "homelab-monitor"], capture_output=True, text=True)
    if not _answers(runner):
        _swap_back(cur, runner)
        raise UpdateError("The previous version did not start; the current version is running again")
    shutil.rmtree(cur + ".rolledback", ignore_errors=True)
    _write_state(dict(state, rolled_back=int(time.time()), rollback_mode=args.mode))
    out = {"ok": True, "action": f"rollback-{args.mode}", "from": state.get("to_version"), "to": state.get("from_version"),
           "output": _last_lines("\n".join(steps), 20)}
    record({"kind": f"rollback-{args.mode}", "source": "app", "from": out["from"], "to": out["to"], "ok": True}, "\n".join(steps))
    write_result(data, "update", out)
    return out


def _swap_back(cur: str, runner) -> None:
    runner(["systemctl", "stop", "homelab-monitor"], capture_output=True, text=True)
    if os.path.isdir(cur + ".rolledback"):
        os.rename(cur, cur + ".old")
        os.rename(cur + ".rolledback", cur)
    runner(["systemctl", "start", "homelab-monitor"], capture_output=True, text=True)


def _answers(runner, tries: int = 45) -> bool:
    port = os.environ.get("HM_PORT", "")
    if not port:
        try:
            with open("/etc/systemd/system/homelab-monitor.service", encoding="utf-8") as f:
                port = (re.search(r"MONITOR_PORT=(\d+)", f.read()) or [None, "8080"])[1]
        except OSError:
            port = "8080"
    for _ in range(tries):
        r = runner(["curl", "-fsS", f"http://127.0.0.1:{port}/api/auth/status"], capture_output=True, text=True)
        if r.returncode == 0:
            return True
        time.sleep(2)
    return False


def _newest(folder: str, since: float) -> str:
    try:
        names = [n for n in os.listdir(folder) if n.startswith("monitor-backup-")]
    except OSError:
        return ""
    paths = sorted((os.path.join(folder, n) for n in names), key=os.path.getmtime)
    return paths[-1] if paths and os.path.getmtime(paths[-1]) >= since else ""


def _last_lines(text: str, n: int = 8) -> str:
    return "\n".join(l for l in (text or "").strip().splitlines()[-n:])


def _request_time(data: str, kind: str) -> int:
    try:
        with open(os.path.join(data, "requests", kind), encoding="ascii") as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _result_time(data: str, kind: str) -> int:
    try:
        with open(os.path.join(data, f"{kind}.result.json"), encoding="utf-8") as f:
            return int(json.load(f).get("time") or 0)
    except (OSError, ValueError):
        return 0


def requests(args) -> None:
    """Every action the app asked for since its last result, in a fixed order. One update at a time."""
    prune(args.data)
    for action in ACTIONS:
        result_kind = "update-check" if action == "update-check" else "update"
        if _request_time(args.data, action) <= _result_time(args.data, result_kind):
            continue
        try:
            if action == "update-check":
                check(args)
            elif action == "update-install":
                install(args)
            else:
                rollback(argparse.Namespace(data=args.data, mode=action.split("-")[1]))
        except UpdateError as exc:
            write_result(args.data, result_kind, {"ok": False, "action": action, "error": str(exc)})
        except Exception as exc:  # recorded for the Settings page; the unit's journal has the trace
            write_result(args.data, result_kind, {"ok": False, "action": action, "error": f"{type(exc).__name__}: {exc}"})
            raise


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("requests", "check", "install", "prune", "rollback", "record"):
        p = sub.add_parser(name)
        p.add_argument("--data", required=True)
        if name == "rollback":
            p.add_argument("--mode", choices=("code", "all"), required=True)
        if name == "record":
            p.add_argument("--kind", choices=("upgrade",), required=True)
            p.add_argument("--source", choices=("host",), default="host")
            p.add_argument("--from", dest="version_from", default="")
            p.add_argument("--to", default="")
            p.add_argument("--ok", choices=("1", "0"), required=True)
            p.add_argument("--why", choices=("none", *WHY), default="none")
            p.add_argument("--log", default="")
    args = ap.parse_args()
    try:
        if args.cmd == "requests":
            requests(args)
        elif args.cmd == "check":
            print(json.dumps(check(args), indent=2))
        elif args.cmd == "install":
            print(json.dumps(install(args), indent=2))
        elif args.cmd == "rollback":
            print(json.dumps(rollback(args), indent=2))
        elif args.cmd == "record":
            print(json.dumps(record_cmd(args), indent=2))
        else:
            for p in prune(args.data):
                print(f"Removed {p}")
    except UpdateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
