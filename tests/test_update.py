"""Update from the project's releases (deploy/updatectl.py): what is trusted, what is refused, the ways back."""

import argparse
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


def release_json(version="9.9.9", installer=REPO_DL + "infra.sh", sig=REPO_DL + "infra.sh.sig"):
    return json.dumps({"tag_name": f"v{version}", "name": f"Home Monitor {version}", "published_at": "2026-11-09T10:00:00Z",
                       "body": "New things", "html_url": "https://github.com/x/y/releases/tag/v" + version,
                       "assets": [{"name": "infra.sh", "browser_download_url": installer},
                                  {"name": "infra.sh.sig", "browser_download_url": sig}]}).encode()


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-update-")
        self.data = os.path.join(self.tmp, "data")
        self.app = os.path.join(self.tmp, "opt", "homelab-monitor")
        self.inst = os.path.join(self.tmp, "etc-install")
        for d in (self.data, self.app, self.inst, os.path.join(self.data, "requests")):
            os.makedirs(d)
        self.write(os.path.join(self.app, "server.py"), 'APP_VERSION = "0.8.0"\n')
        self.saved = {k: getattr(updatectl, k) for k in ("APP_DIR", "INSTALL_DIR", "STATE_FILE", "SIGNERS", "_get")}
        updatectl.APP_DIR, updatectl.INSTALL_DIR = self.app, self.inst
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
        inst = os.path.join(self.tmp, "dl", "infra.sh")
        self.write(inst, f'#!/usr/bin/env bash\nVERSION="{installer_version or version}"\necho upgrading\n__PAYLOAD_BEGIN__\nxx\n__PAYLOAD_END__\n')
        sig = self.sign(inst)
        body = open(inst, "rb").read()
        if tamper:
            body = body.replace(b"echo upgrading", b"echo pwned!!!!")
        files = {REPO_DL + "infra.sh": body, REPO_DL + "infra.sh.sig": open(sig, "rb").read()}

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
            updatectl.latest_release(lambda *a, **k: release_json(installer="https://evil.example/infra.sh"))
        with self.assertRaises(updatectl.UpdateError):
            updatectl.latest_release(lambda *a, **k: json.dumps({"tag_name": "v9.9.9", "assets": []}).encode())

    def test_signature_is_checked_against_the_installed_key(self):
        f = os.path.join(self.tmp, "infra.sh")
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

    def run_install(self, runner=None):
        calls = []

        def fake_runner(cmd, **kw):
            calls.append(cmd)
            # infra.sh --update-here makes the pre-update backup; the fake does the same.
            folder = os.path.join(self.data, "backups", "pre-update")
            os.makedirs(folder, exist_ok=True)
            open(os.path.join(folder, "monitor-backup-20261109-100000.tar.gz"), "w").close()
            return subprocess.CompletedProcess(cmd, 0, "Upgraded to 9.9.9 and answering\n", "")
        return updatectl.install(argparse.Namespace(data=self.data), runner=runner or fake_runner), calls

    def test_install_needs_recorded_settings(self):
        self.fake_release()
        with self.assertRaises(updatectl.UpdateError) as e:
            self.run_install()
        self.assertIn("infra.sh --upgrade once", str(e.exception))

    def test_install_checks_then_upgrades_in_place(self):
        self.write(os.path.join(self.inst, "settings.env"), 'PORT="8080"\n')
        self.fake_release()
        out, calls = self.run_install()
        self.assertTrue(out["ok"])
        self.assertEqual(calls[0][0:1] + calls[0][2:], ["bash", "--update-here"])
        state = json.load(open(updatectl.STATE_FILE))
        self.assertEqual((state["from_version"], state["to_version"]), ("0.8.0", "9.9.9"))
        self.assertTrue(state["backup"].endswith(".tar.gz"))
        self.assertTrue(json.load(open(os.path.join(self.data, "update.result.json")))["ok"])

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

    def test_rollback_options(self):
        self.assertFalse(updatectl.rollback_options(self.data)["all"])
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
        backup = os.path.join(self.data, "b.tar.gz")
        open(backup, "w").close()
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

    def test_rollback_code_swaps_back_and_keeps_data(self):
        self.write(os.path.join(self.app + ".old", "server.py"), 'APP_VERSION = "0.7.0"\n')
        backup = os.path.join(self.data, "b.tar.gz")
        open(backup, "w").close()
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
        self.assertFalse(any("restore" in c for c in calls))           # today's data stays
        self.assertFalse(updatectl.rollback_options(self.data)["all"])  # done once

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
