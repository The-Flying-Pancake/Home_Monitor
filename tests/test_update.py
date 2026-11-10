"""Update from the project's releases (deploy/updatectl.py): what is trusted, what is refused, the ways back."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from tests import _env  # noqa: F401

ROOT = _env.ROOT
sys.path.insert(0, os.path.join(ROOT, "deploy"))
import updatectl  # noqa: E402

REPO_DL = f"https://github.com/{updatectl.REPO}/releases/download/v9.9.9/"


def release_json(version="9.9.9", installer=REPO_DL + "home_monitor.sh", sig=REPO_DL + "home_monitor.sh.sig"):
    return json.dumps({"tag_name": f"v{version}", "name": f"Home Monitor {version}", "published_at": "2026-11-09T10:00:00Z",
                       "body": "New things", "html_url": "https://github.com/x/y/releases/tag/v" + version,
                       "assets": [{"name": "home_monitor.sh", "browser_download_url": installer},
                                  {"name": "home_monitor.sh.sig", "browser_download_url": sig}]}).encode()


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-update-")
        self.data = os.path.join(self.tmp, "data")
        self.app = os.path.join(self.tmp, "opt", "homelab-monitor")
        self.inst = os.path.join(self.tmp, "etc-install")
        for d in (self.data, self.app, self.inst, os.path.join(self.data, "requests")):
            os.makedirs(d)
        self.write(os.path.join(self.app, "server.py"), 'APP_VERSION = "0.8.0"\n')
        self.saved = {k: getattr(updatectl, k) for k in ("APP_DIR", "INSTALL_DIR", "STATE_FILE", "SIGNERS", "_get", "SAFE_DIR")}
        updatectl.APP_DIR, updatectl.INSTALL_DIR = self.app, self.inst
        self.safe = updatectl.SAFE_DIR = os.path.join(self.tmp, "safe")
        updatectl.STATE_FILE = os.path.join(self.inst, "last-update.json")
        # A release key made for the test: signs like deploy/release.py, checked like the box does.
        self.key = os.path.join(self.tmp, "k")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key], check=True, stdin=subprocess.DEVNULL, timeout=30)
        pub = open(self.key + ".pub").read().split()
        updatectl.SIGNERS = os.path.join(self.tmp, "release-signers")
        self.write(updatectl.SIGNERS, f'{updatectl.IDENTITY} namespaces="{updatectl.NAMESPACE}" {pub[0]} {pub[1]}\n')

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(updatectl, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def write(path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def sign(self, path, key=None):
        if os.path.exists(path + ".sig"):
            os.remove(path + ".sig")                       # ssh-keygen would stop to ask before overwriting
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key or self.key, "-n", updatectl.NAMESPACE, path], check=True,
                       capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
        return path + ".sig"

    def fake_release(self, version="9.9.9", installer_version=None, tamper=False):
        """GitHub as the box would see it: the release page, the installer and its signature."""
        inst = os.path.join(self.tmp, "dl", "home_monitor.sh")
        self.write(inst, f'#!/usr/bin/env bash\nVERSION="{installer_version or version}"\necho upgrading\n__PAYLOAD_BEGIN__\nxx\n__PAYLOAD_END__\n')
        sig = self.sign(inst)
        body = open(inst, "rb").read()
        if tamper:
            body = body.replace(b"echo upgrading", b"echo pwned!!!!")
        files = {REPO_DL + "home_monitor.sh": body, REPO_DL + "home_monitor.sh.sig": open(sig, "rb").read()}

        def fetch(url, limit, accept="application/octet-stream"):
            if url == updatectl.API:
                return release_json(version)
            return files[url]
        updatectl._get = fetch

    def test_versions_and_release_page(self):
        self.assertGreater(updatectl.version_tuple("0.10.0"), updatectl.version_tuple("0.9.9"))
        with self.assertRaises(updatectl.UpdateError):
            updatectl.version_tuple("1.0; rm -rf /")
        rel = updatectl.latest_release(lambda *a, **k: release_json())
        self.assertEqual((rel["version"], rel["notes"]), ("9.9.9", "New things"))
        # Links that leave this project's releases are refused before anything is downloaded.
        with self.assertRaises(updatectl.UpdateError):
            updatectl.latest_release(lambda *a, **k: release_json(installer="https://evil.example/home_monitor.sh"))
        with self.assertRaises(updatectl.UpdateError):
            updatectl.latest_release(lambda *a, **k: json.dumps({"tag_name": "v9.9.9", "assets": []}).encode())
        # A release from before the rename (infra.sh only) is still understood; the new name wins when both are there.
        old = json.loads(release_json(installer=REPO_DL + "infra.sh", sig=REPO_DL + "infra.sh.sig"))
        for a in old["assets"]:
            a["name"] = a["name"].replace("home_monitor.sh", "infra.sh")
        self.assertTrue(updatectl.latest_release(lambda *a, **k: json.dumps(old).encode())["installer"].endswith("/infra.sh"))
        both = json.loads(release_json())
        both["assets"] += old["assets"]
        self.assertTrue(updatectl.latest_release(lambda *a, **k: json.dumps(both).encode())["installer"].endswith("/home_monitor.sh"))

    def test_signature_is_checked_against_the_installed_key(self):
        f = os.path.join(self.tmp, "home_monitor.sh")
        self.write(f, "hello\n")
        sig = self.sign(f)
        updatectl.verify_signature(f, sig)
        self.write(f, "hello, changed\n")
        with self.assertRaises(updatectl.UpdateError):
            updatectl.verify_signature(f, sig)
        # A key that is not the project's: refused too.
        other = os.path.join(self.tmp, "other")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other], check=True, stdin=subprocess.DEVNULL, timeout=30)
        self.write(f, "hello\n")
        sig = self.sign(f, key=other)
        with self.assertRaises(updatectl.UpdateError):
            updatectl.verify_signature(f, sig)

    def safe_copy(self, name="monitor-backup-20261109-100000.tar.gz", body="a backup"):
        folder = os.path.join(self.safe, "pre-update")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name)
        self.write(path, body)
        return path

    def record(self, **kw):
        path = kw.pop("backup", None) or self.safe_copy()
        rec = dict({"from": "0.7.0", "to": "0.8.0", "started": int(time.time()), "state": "done", "backup": path,
                    "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest()}, **kw)
        self.write(os.path.join(self.inst, updatectl.RECORD_NAME), json.dumps(rec))
        return rec

    def run_install(self, runner=None):
        calls = []

        def fake_runner(cmd, **kw):
            calls.append(cmd)
            # home_monitor.sh --update-here makes the pre-update backup in root's folder and notes it in
            # root's record (note-backup); the fake does the same.
            self.seen_record = json.load(open(os.path.join(self.inst, updatectl.RECORD_NAME)))
            updatectl.note_backup(argparse.Namespace(data=self.data, file=self.safe_copy(), to="9.9.9"))
            return subprocess.CompletedProcess(cmd, 0, "Upgraded to 9.9.9 and answering\n", "")
        return updatectl.install(argparse.Namespace(data=self.data), runner=runner or fake_runner), calls

    def test_install_needs_recorded_settings(self):
        self.fake_release()
        with self.assertRaises(updatectl.UpdateError) as e:
            self.run_install()
        self.assertIn("home_monitor.sh --upgrade once", str(e.exception))

    def test_install_checks_then_upgrades_in_place(self):
        self.write(os.path.join(self.inst, "settings.env"), 'PORT="8080"\n')
        self.fake_release()
        out, calls = self.run_install()
        self.assertTrue(out["ok"])
        self.assertEqual(calls[0][0:1] + calls[0][2:], ["bash", "--update-here"])
        state = json.load(open(updatectl.STATE_FILE))
        self.assertEqual((state["from_version"], state["to_version"]), ("0.8.0", "9.9.9"))
        self.assertTrue(state["backup"].endswith(".tar.gz"))
        rec = json.load(open(os.path.join(self.inst, updatectl.RECORD_NAME)))
        self.assertEqual((rec["from"], rec["to"], rec["state"]), ("0.8.0", "9.9.9", "done"))
        self.assertRegex(rec["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(json.load(open(os.path.join(self.data, "update.result.json")))["ok"])

    def test_install_writes_the_record_before_the_installer(self):
        self.write(os.path.join(self.inst, "settings.env"), 'PORT="8080"\n')
        self.fake_release()
        self.run_install()
        self.assertEqual((self.seen_record["state"], self.seen_record["to"], self.seen_record["backup"]), ("running", "9.9.9", ""))

    def test_note_backup_records_hash_for_first_update(self):
        """The update to this version runs under the older updater, which writes no record: the
        installer's note-backup makes it."""
        self.write(os.path.join(self.app, "server.py"), 'APP_VERSION = "0.11.2"\n')
        path = self.safe_copy()
        rec = updatectl.note_backup(argparse.Namespace(data=self.data, file=path, to="0.12.0"))
        self.assertEqual((rec["from"], rec["to"], rec["state"], rec["backup"]), ("0.11.2", "0.12.0", "running", path))
        self.assertEqual(rec["sha256"], hashlib.sha256(b"a backup").hexdigest())
        # Only a copy in root's own folder is recorded.
        elsewhere = os.path.join(self.data, "backups", "pre-update", "monitor-backup-x.tar.gz")
        self.write(elsewhere, "planted")
        with self.assertRaises(updatectl.UpdateError):
            updatectl.note_backup(argparse.Namespace(data=self.data, file=elsewhere, to="0.12.0"))

    def test_install_refuses_older_tampered_or_mislabelled(self):
        self.write(os.path.join(self.inst, "settings.env"), 'PORT="8080"\n')
        for kw, msg in (({"version": "0.7.0"}, "Already up to date"), ({"version": "0.8.0"}, "Already up to date"),
                        ({"tamper": True}, "signature does not match"), ({"installer_version": "9.9.8"}, "installer is version")):
            self.fake_release(**kw)
            with self.assertRaises(updatectl.UpdateError, msg=kw) as e:
                self.run_install(runner=lambda *a, **k: self.fail("nothing may run"))
            self.assertIn(msg, str(e.exception))
        self.assertFalse(os.path.exists(updatectl.STATE_FILE))

    def test_prune_keeps_two_days(self):
        folder = os.path.join(self.data, "backups", "pre-update")
        os.makedirs(folder)
        old, new = (os.path.join(folder, f"monitor-backup-{n}.tar.gz") for n in ("old", "new"))
        for p in (old, new):
            open(p, "w").close()
        os.utime(old, (time.time() - 3 * 86400,) * 2)
        self.assertEqual(updatectl.prune(self.data), [old])
        self.assertTrue(os.path.exists(new))

    def test_prune_covers_roots_folder_and_old_places(self):
        """Root's folder (two days), the old places in DATA/backups (two days, or 14 for upgrade and
        restore copies from before 0.12.0) and the pre-restore folders (newest kept)."""
        now = time.time()
        made = {}
        for folder, age in ((os.path.join(self.safe, "pre-update"), 3), (os.path.join(self.safe, "pre-rollback"), 1),
                            (os.path.join(self.data, "backups", "pre-upgrade"), 10),
                            (os.path.join(self.data, "backups", "pre-restore"), 20)):
            os.makedirs(folder)
            p = os.path.join(folder, "monitor-backup-x.tar.gz")
            open(p, "w").close()
            os.utime(p, (now - age * 86400,) * 2)
            made[os.path.basename(folder)] = p
        for i, age in enumerate((1, 40)):
            d = os.path.join(self.safe, f"pre-restore-{i}")
            os.makedirs(d)
            os.utime(d, (now - age * 86400,) * 2)
        gone = updatectl.prune(self.data, now)
        self.assertIn(made["pre-update"], gone)
        self.assertIn(made["pre-restore"], gone)
        self.assertTrue(os.path.exists(made["pre-rollback"]))
        self.assertTrue(os.path.exists(made["pre-upgrade"]))
        self.assertEqual(sorted(os.listdir(self.safe)), ["pre-restore-0", "pre-rollback", "pre-update"])

    def test_rollback_options(self):
        self.assertFalse(updatectl.rollback_options(self.data)["all"])
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
        backup = self.record()["backup"]
        state = {"from_version": "0.7.0", "to_version": "0.8.0", "time": int(time.time()), "backup": backup, "schema_same": True}
        self.write(updatectl.STATE_FILE, json.dumps(state))
        o = updatectl.rollback_options(self.data)
        self.assertTrue(o["all"] and o["code"])
        # The update changed the database layout: only the way back with the old data is open.
        self.write(updatectl.STATE_FILE, json.dumps(dict(state, schema_same=False)))
        o = updatectl.rollback_options(self.data)
        self.assertTrue(o["all"])
        self.assertFalse(o["code"])
        self.assertIn("changed how the data is stored", o["why_code"])
        # Two days later both close.
        self.write(updatectl.STATE_FILE, json.dumps(dict(state, time=int(time.time()) - 3 * 86400)))
        o = updatectl.rollback_options(self.data)
        self.assertFalse(o["all"] or o["code"])
        self.assertIn("expired", o["why"])

    def test_rollback_options_need_a_matching_record(self):
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
        state = {"from_version": "0.7.0", "to_version": "0.8.0", "time": int(time.time()), "schema_same": True,
                 "backup": os.path.join(self.data, "backups", "pre-update", "planted.tar.gz")}
        self.write(state["backup"], "planted by the app")
        self.write(updatectl.STATE_FILE, json.dumps(state))
        self.assertFalse(updatectl.rollback_options(self.data)["all"])          # no record: the app's file is not used
        self.record(**{"from": "0.6.0"})
        self.assertFalse(updatectl.rollback_options(self.data)["all"])          # another update's record
        self.record()
        self.assertTrue(updatectl.rollback_options(self.data)["all"])

    def test_rollback_refuses_a_changed_backup(self):
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
        rec = self.record()
        self.write(updatectl.STATE_FILE, json.dumps({"from_version": "0.7.0", "to_version": "0.8.0", "time": int(time.time()),
                                                     "backup": "", "schema_same": False}))
        self.write(rec["backup"], "changed after the update")
        calls = []
        with self.assertRaises(updatectl.UpdateError) as e:
            updatectl.rollback(argparse.Namespace(data=self.data, mode="all"),
                               runner=lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""))
        self.assertIn("has changed since the update", str(e.exception))
        self.assertEqual(calls, [])                                       # nothing stopped, nothing backed up
        self.assertEqual(updatectl.installed_version(self.app), "0.8.0")

    def test_rollback_all_checks_the_copy_with_the_older_sitectl(self):
        """Undo restores with the previous build's sitectl.py: given the checksum only when it knows it."""
        rec = self.record()
        for knows, text in ((True, "p.add_argument('--expect-sha256')\n"), (False, "# 0.11.2\n")):
            shutil.rmtree(self.app + ".old", ignore_errors=True)
            self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
            self.write(os.path.join(self.app + ".old", "sitectl.py"), text)
            self.write(os.path.join(self.app, "server.py"), 'APP_VERSION = "0.8.0"\n')
            self.write(updatectl.STATE_FILE, json.dumps({"from_version": "0.7.0", "to_version": "0.8.0",
                                                         "time": int(time.time()), "backup": "", "schema_same": False}))
            calls = []

            def runner(cmd, **kw):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            updatectl.rollback(argparse.Namespace(data=self.data, mode="all"), runner=runner)
            restore = next(c for c in calls if "restore" in c)
            self.assertIn(rec["backup"], restore)
            self.assertEqual("--expect-sha256" in restore, knows)
            if knows:
                self.assertEqual(restore[restore.index("--expect-sha256") + 1], rec["sha256"])
            self.assertIn(["chown", "-hR", "homelab-monitor:homelab-monitor", self.data, "/etc/homelab-monitor"], calls)

    def test_rollback_code_swaps_back_and_keeps_data(self):
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
        backup = self.record()["backup"]
        self.write(updatectl.STATE_FILE, json.dumps({"from_version": "0.7.0", "to_version": "0.8.0", "time": int(time.time()),
                                                     "backup": backup, "schema_same": True}))
        calls = []

        def runner(cmd, **kw):
            calls.append(" ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        out = updatectl.rollback(argparse.Namespace(data=self.data, mode="code"), runner=runner)
        self.assertTrue(out["ok"])
        self.assertEqual(updatectl.installed_version(self.app), "0.7.0")
        self.assertIn("pre-rollback", calls[0])                       # the state now is backed up first
        self.assertIn(os.path.join(self.safe, "pre-rollback") + " --keep 5 --safety", calls[0])   # into root's own folder
        self.assertFalse(any("restore" in c for c in calls))           # today's data stays
        self.assertFalse(updatectl.rollback_options(self.data)["all"])  # done once

    def test_notes_cover_every_version_in_between(self):
        rows = [{"tag_name": f"v{v}", "name": v, "body": f"notes {v}", "published_at": "2026"} for v in
                ("1.2.0", "1.1.0", "1.0.1", "1.0.0", "0.9.0")] + [{"tag_name": "v1.3.0", "draft": True}, {"tag_name": "nonsense"}]
        got = updatectl.notes_between("1.0.0", "1.2.0", lambda *a, **k: json.dumps(rows).encode())
        self.assertEqual([r["version"] for r in got], ["1.2.0", "1.1.0", "1.0.1"])
        self.assertEqual(updatectl.notes_between("1.0.0", "1.2.0", lambda *a, **k: (_ for _ in ()).throw(OSError())), [])

    def test_progress_follows_the_installer(self):
        p = updatectl.Progress(self.data, "0.8.0", "9.9.9")
        p.step("download")
        p.step("verify")
        for line in ("  ... ready\n", "noise\n", "  ... check\n", "  ... repair (skipped)\n", "  ... backup\n", "  ... evil/../x\n"):
            p.line(line)
        s = json.load(open(os.path.join(self.data, "update-progress.json")))
        self.assertEqual((s["current"], s["state"]), ("backup", "running"))
        self.assertEqual([s["steps"][k] for k in ("download", "verify", "ready", "check", "repair", "backup", "health")],
                         ["ok", "ok", "ok", "ok", "skip", "run", "pending"])
        p.finish(False, "It did not start")
        s = json.load(open(os.path.join(self.data, "update-progress.json")))
        self.assertEqual((s["steps"]["backup"], s["state"], s["error"]), ("fail", "failed", "It did not start"))

    def test_history_records_updates_with_their_log(self):
        self.write(os.path.join(self.inst, "settings.env"), 'PORT="8080"\n')
        self.fake_release()

        def runner(cmd, on_line=None, env=None, **kw):
            self.write(env["HM_LOG_FILE"], "\x1b[32mok\x1b[0m\nBACKUP_PASSPHRASE=hunter2hunter2\ntelegram_token: 123:abc\n")
            for l in ("  ... ready\n", "  ... health\n"):
                on_line(l)
            folder = os.path.join(self.data, "backups", "pre-update")
            os.makedirs(folder, exist_ok=True)
            open(os.path.join(folder, "monitor-backup-20261109-100000.tar.gz"), "w").close()
            return subprocess.CompletedProcess(cmd, 0, "Upgraded\n", "")
        self.run_install(runner=runner)
        rows = updatectl.read_history()
        self.assertEqual([(r["kind"], r["from"], r["to"], r["ok"], r["log"]) for r in rows], [("update", "0.8.0", "9.9.9", True, True)])
        log = open(os.path.join(self.inst, "update-logs", f"{rows[0]['id']}.log"), encoding="utf-8").read()
        self.assertIn("ok\n", log)
        self.assertNotIn("\x1b", log)
        self.assertNotIn("hunter2", log)
        self.assertNotIn("123:abc", log)
        self.assertEqual(json.load(open(os.path.join(self.data, "update-progress.json")))["state"], "ok")

    def test_history_records_a_failed_update_and_keeps_the_last_ones(self):
        self.write(os.path.join(self.inst, "settings.env"), 'PORT="8080"\n')
        self.fake_release()
        with self.assertRaises(updatectl.UpdateError):
            def runner(cmd, on_line=None, **kw):
                on_line("  ... health\n")
                return subprocess.CompletedProcess(cmd, 1, "  ... health\nfailed\n", "")
            self.run_install(runner=runner)
        row = updatectl.read_history()[0]
        self.assertFalse(row["ok"])
        self.assertIn("previous version was put back", row["error"])
        self.assertEqual(json.load(open(os.path.join(self.data, "update-progress.json")))["steps"]["health"], "fail")
        for i in range(updatectl.HISTORY_KEEP + 3):
            updatectl.record({"kind": "upgrade", "ok": True}, f"log {i}")
        rows = updatectl.read_history()
        self.assertEqual(len(rows), updatectl.HISTORY_KEEP)
        self.assertEqual(len(rows), len({r["id"] for r in rows}))
        self.assertEqual(sorted(os.listdir(os.path.join(self.inst, "update-logs"))), sorted(f"{r['id']}.log" for r in rows))

    def test_record_from_the_host(self):
        log = os.path.join(self.tmp, "host.log")
        self.write(log, "===== health =====\ncurl: (7) Failed to connect\n")
        ns = argparse.Namespace(kind="upgrade", source="host", version_from="0.6.0", to="0.9.0", ok="0", why="health", log=log)
        row = updatectl.record_cmd(ns)
        self.assertEqual((row["from"], row["to"], row["ok"], row["source"]), ("0.6.0", "0.9.0", False, "host"))
        self.assertIn("did not start", row["error"])
        with self.assertRaises(updatectl.UpdateError):
            updatectl.record_cmd(argparse.Namespace(**dict(vars(ns), version_from="1; rm -rf /")))

    # --- Cut short by a restart (updatectl.py recover, at boot) ---

    def ask(self, action, when):
        with open(os.path.join(self.data, "requests", action), "w") as f:
            f.write(str(int(when)))

    def progress(self, **kw):
        self.write(os.path.join(self.data, "update-progress.json"), json.dumps(dict(
            {"from": "0.8.0", "to": "9.9.9", "started": int(time.time()) - 60, "state": "running", "current": "replace",
             "steps": {"download": "ok", "replace": "run", "health": "pending"}, "boot": "old-boot"}, **kw)))

    def recover(self):
        work = os.path.join(self.tmp, "root")
        os.makedirs(work, exist_ok=True)
        return updatectl.recover(argparse.Namespace(data=self.data), work_root=work), work

    def test_recover_does_nothing_without_a_cut(self):
        out, _ = self.recover()
        self.assertEqual(out["action"], "nothing")
        self.assertFalse(os.path.exists(os.path.join(self.data, "update.result.json")))
        self.assertEqual(updatectl.read_history(), [])

    def test_recover_puts_a_half_swapped_app_back(self):
        # Cut between "app to app.old" and "app.new to app": no app folder at all.
        shutil.rmtree(self.app)
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.8.0"\n')
        self.write(os.path.join(self.app + ".new", "server.py"), 'APP_VERSION = "9.9.9"\n')
        self.ask("update-install", time.time() - 120)
        self.progress()
        out, work = self.recover()
        self.assertFalse(out["ok"])
        self.assertEqual(updatectl.installed_version(self.app), "0.8.0")
        self.assertFalse(os.path.exists(self.app + ".new"))
        self.assertIn("cut short", out["error"])
        result = json.load(open(os.path.join(self.data, "update.result.json")))
        self.assertTrue(result["interrupted"] and not result["ok"])
        prog = json.load(open(os.path.join(self.data, "update-progress.json")))
        self.assertEqual((prog["state"], prog["steps"]["replace"]), ("failed", "fail"))
        self.assertFalse(updatectl.read_history()[0]["ok"])
        self.assertEqual(self.recover()[0]["action"], "nothing")       # a second boot finds nothing to do

    def test_recover_uses_the_root_record(self):
        """Replaces the way-back test that read the progress file: versions and the copy come from root's record."""
        self.write(os.path.join(self.app, "server.py"), 'APP_VERSION = "9.9.9"\n')
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.8.0"\n')
        self.record(**{"from": "0.8.0", "to": "9.9.9", "state": "running", "started": int(time.time()) - 60})
        self.ask("update-install", time.time() - 120)
        self.progress(current="health", steps={"health": "run"})
        work = os.path.join(self.tmp, "root", "hm-update-abc")
        self.write(os.path.join(work, "install.log"), "===== health =====\nwaiting\n")
        out, root = self.recover()
        self.assertIn("Undo below puts 0.8.0 back", out["error"])
        o = updatectl.rollback_options(self.data)
        self.assertTrue(o["all"])
        self.assertFalse(o["code"])                                     # the data may not suit 0.8.0: only the full way back
        self.assertFalse(os.path.exists(work))                          # the cut-short download is cleared
        log = open(os.path.join(self.inst, "update-logs", f"{updatectl.read_history()[0]['id']}.log"), encoding="utf-8").read()
        self.assertIn("waiting", log)
        self.assertEqual(json.load(open(os.path.join(self.inst, updatectl.RECORD_NAME)))["state"], "done")

    def cut_update(self):
        self.write(os.path.join(self.app, "server.py"), 'APP_VERSION = "9.9.9"\n')
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.8.0"\n')
        self.ask("update-install", time.time() - 120)
        self.progress(current="health", steps={"health": "run"})

    def test_recover_ignores_a_forged_progress_file(self):
        """No record: the versions and start time in the app's progress file are never used."""
        self.cut_update()
        self.progress(**{"from": "0.1.0", "to": "6.6.6", "started": int(time.time())})
        self.safe_copy()
        out, _ = self.recover()
        self.assertFalse(os.path.exists(updatectl.STATE_FILE))
        self.assertNotIn("6.6.6", out["error"])
        self.assertFalse(updatectl.rollback_options(self.data)["all"])

    def test_recover_ignores_a_planted_backup(self):
        """Cut before the copy was made: a newer file in the old folder (or root's) is not taken up."""
        self.cut_update()
        rec = {"from": "0.8.0", "to": "9.9.9", "started": int(time.time()) - 60, "state": "running", "backup": "", "sha256": ""}
        self.write(os.path.join(self.inst, updatectl.RECORD_NAME), json.dumps(rec))
        self.write(os.path.join(self.data, "backups", "pre-update", "monitor-backup-20991231-000000.tar.gz"), "planted")
        self.safe_copy("monitor-backup-20991231-000000.tar.gz")
        out, _ = self.recover()
        self.assertFalse(os.path.exists(updatectl.STATE_FILE))
        self.assertNotIn("Undo", out["error"])

    def test_recover_cannot_reopen_a_used_record(self):
        self.cut_update()
        self.record(**{"from": "0.8.0", "to": "9.9.9", "state": "done"})
        self.recover()
        self.assertFalse(os.path.exists(updatectl.STATE_FILE))

    def test_recover_ignores_an_expired_record(self):
        self.cut_update()
        self.record(**{"from": "0.8.0", "to": "9.9.9", "state": "running", "started": int(time.time()) - 3 * 86400})
        self.recover()
        self.assertFalse(os.path.exists(updatectl.STATE_FILE))

    def test_request_reader_does_not_follow_a_link(self):
        target = os.path.join(self.tmp, "elsewhere")
        self.write(target, str(int(time.time()) + 999))
        link = os.path.join(self.data, "requests", "update-install")
        if os.name != "posix":
            self.skipTest("following links is a POSIX matter (checked on Linux)")
        os.symlink(target, link)
        self.assertEqual(updatectl._request_time(self.data, "update-install"), 0)
        os.remove(link)
        os.mkfifo(link)                                      # a file that never ends is not waited on
        self.assertEqual(updatectl._request_time(self.data, "update-install"), 0)

    def test_recover_finishes_a_cut_short_undo(self):
        shutil.rmtree(self.app)
        self.write(os.path.join(self.app + ".rolledback", "server.py"), 'APP_VERSION = "9.9.9"\n')
        self.ask("rollback-all", time.time() - 120)
        out, _ = self.recover()
        self.assertEqual(out["action"], "rollback-all")
        self.assertEqual(updatectl.installed_version(self.app), "9.9.9")
        self.assertIn("undo was cut short", out["error"])

    def test_requests_run_only_what_was_asked(self):
        self.fake_release()
        with open(os.path.join(self.data, "requests", "update-check"), "w") as f:
            f.write(str(int(time.time()) + 5))
        updatectl.requests(argparse.Namespace(data=self.data))
        r = json.load(open(os.path.join(self.data, "update-check.result.json")))
        self.assertTrue(r["newer"])
        self.assertEqual(r["latest"], "9.9.9")
        self.assertFalse(os.path.exists(os.path.join(self.data, "update.result.json")))  # nothing installed


if __name__ == "__main__":
    unittest.main()
