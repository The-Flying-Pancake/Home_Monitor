"""Fix SNMP: the clean snmpd.conf, secret masking, the paste-ready script, and the preview / apply / rollback flow."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import server
import snmpfix

DEBIAN_DEFAULT = """# snmpd.conf
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
includeDir /etc/snmp/snmpd.conf.d
"""

# A hand-made config shared by several hosts.
HAND_MADE_CONF = """sysServices    72
master  agentx
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  labcomm default -V systemonly
rocommunity6 labcomm default -V systemonly
rouser authPrivUser authpriv -V systemonly
includeDir /etc/snmp/snmpd.conf.d
"""

LISTENS_ON_ALL = """agentAddress udp:161
master  agentx
view   systemonly  included   .1.3.6.1.2.1.1
rocommunity  s3cret-comm default -V systemonly
"""


class BuildConfTests(unittest.TestCase):
    def test_clean_file_replaces_artefacts(self):
        plan = snmpfix.build_conf(HAND_MADE_CONF, "labcomm", "192.0.2.174", now=0)
        lines = plan["content"].splitlines()
        self.assertIn("agentAddress udp:161", lines)
        self.assertFalse(any("udp6" in l for l in lines))     # snmpd exits when IPv6 is disabled
        self.assertIn("view   hmmonitor  included   .1", lines)
        self.assertIn("rocommunity  labcomm 192.0.2.174/32 -V hmmonitor", lines)
        self.assertIn("rocommunity  labcomm 127.0.0.1 -V hmmonitor", lines)
        self.assertTrue(any(l.startswith("master") and l.endswith("agentx") for l in lines))
        # Old access lines, users, views and includes are gone: only the monitor and localhost remain.
        body = [l for l in lines if not l.startswith("#")]
        for gone in ("systemonly", "default", "rouser", "rocommunity6", "includeDir"):
            self.assertFalse(any(gone in l for l in body), gone)
        self.assertEqual(sum(l.startswith("rocommunity") for l in body), 2)
        self.assertIn("2 view lines", plan["changes"][2])
        self.assertIn("SNMPv3 user line", plan["changes"][2])

    def test_location_and_contact_kept(self):
        lines = snmpfix.build_conf(DEBIAN_DEFAULT, "c", "10.0.0.9")["content"].splitlines()
        self.assertTrue(any(l.startswith("sysLocation") and l.endswith("Sitting on the Dock of the Bay") for l in lines))
        self.assertTrue(any(l.startswith("sysContact") and l.endswith("Me <me@example.org>") for l in lines))
        self.assertFalse(any("127.0.0.1,[::1]" in l for l in lines))     # localhost-only listening removed
        blank = snmpfix.build_conf("", "c", "10.0.0.9")["content"]
        self.assertIn("sysLocation  Unknown", blank)

    def test_idempotent(self):
        once = snmpfix.build_conf(HAND_MADE_CONF, "c", "10.0.0.9", now=0)["content"]
        self.assertEqual(snmpfix.build_conf(once, "c", "10.0.0.9", now=0)["content"], once)

    def test_community_checks(self):
        self.assertIsNone(snmpfix.community_problem("labcomm-2024"))
        for bad in ("", "has space", "a#b", 'q"t'):
            self.assertIsNotNone(snmpfix.community_problem(bad), bad)

    def test_mask_hides_communities(self):
        text = snmpfix.mask(snmpfix.build_conf(LISTENS_ON_ALL, "s3cret-comm", "10.0.0.9")["content"], ["s3cret-comm"])
        self.assertNotIn("s3cret-comm", text)
        self.assertIn("rocommunity  •••• 10.0.0.9/32 -V hmmonitor", text)
        self.assertEqual(snmpfix.mask("com2sec readonly default other-secret", []), "com2sec readonly default ••••")

    def test_copy_script_is_paste_ready(self):
        content = snmpfix.build_conf(HAND_MADE_CONF, "labcomm", "192.0.2.174", now=0)["content"]
        script = snmpfix.copy_script(content, "192.0.2.174")
        self.assertIn("rocommunity  labcomm 192.0.2.174/32 -V hmmonitor", script)   # the real community
        self.assertNotIn("<community>", script)
        self.assertFalse(any(l.startswith(("+", "-")) for l in script.splitlines()))
        self.assertIn("apt-get install -y snmpd", script)
        bash = shutil.which("bash")
        if not bash:
            return
        # Run it against a sandbox: the heredoc must write the file byte for byte.
        tmp = tempfile.mkdtemp(prefix="hm-snmpcopy-")
        try:
            etc = os.path.join(tmp, "etc", "snmp").replace("\\", "/")
            os.makedirs(etc)
            fakebin = os.path.join(tmp, "bin")
            os.makedirs(fakebin)
            for name in ("snmpd", "systemctl", "sudo", "ufw", "apt-get"):
                with open(os.path.join(fakebin, name), "w", newline="\n") as f:
                    f.write('#!/usr/bin/env bash\n[ "$(basename "$0")" = sudo ] && exec "$@"\nexit 0\n')
                os.chmod(os.path.join(fakebin, name), 0o755)
            local = script.replace("/etc/snmp", etc)
            sep = ";" if os.name == "nt" else ":"
            env = dict(os.environ, PATH=fakebin + sep + os.environ["PATH"])
            r = subprocess.run([bash, "-c", local], capture_output=True, env=env, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(etc, "snmpd.conf"), encoding="utf-8") as f:
                self.assertEqual(f.read(), content)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_read_flags(self):
        state = snmpfix.parse_read("HM_ROOT=0\nHM_SUDO=0\nHM_INSTALLED=1\nHM_APT=1\nHM_ACTIVE=active\nHM_UFW=1\nHM_DROPINS=old.conf x.conf \nHM_CONF_BEGIN\nabc")
        self.assertEqual((state["root"], state["sudo"], state["ufw"], state["dropins"], state["conf"]),
                         (False, False, True, ["old.conf", "x.conf"], "abc"))


class FixApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("fix-host", "192.0.2.91", community="s3cret-comm", profile="linux_host")
        cls.other = add_device("fix-switch", "192.0.2.92", profile="unifi_switch")
        cls.nokey = add_device("fix-nokey", "192.0.2.93", community="s3cret-comm", profile="linux_host")
        database.approve_host_key(cls.dev, "ssh-ed25519", "AAAA", "SHA256:x")
        cls.cred = request("POST", "/api/credentials", {"name": "fix-root", "cred_type": "password", "username": "root", "secret": "pw-fix"})[1]["id"]

    def call(self, body, files, verify=True, device=None):
        """Runs the endpoint against a fake host whose snmpd.conf lives in files["conf"]."""
        calls = []

        def fake_ssh(ip, port, cred, command, keys, timeout, input_data=None):
            calls.append((command, input_data))
            if command == snmpfix.READ_SCRIPT:
                head = (f"HM_ROOT={files.get('root', 1)}\nHM_SUDO={files.get('sudo', 1)}\nHM_INSTALLED={files.get('installed', 1)}\n"
                        f"HM_APT={files.get('apt', 1)}\nHM_ACTIVE={files.get('active', 'active')}\nHM_UFW={files.get('ufw', 0)}\n"
                        f"HM_DROPINS={files.get('dropins', '')}\n")
                return {"status": "completed", "exit_code": 0, "stdout": head + "HM_CONF_BEGIN\n" + files["conf"], "stderr": "", "duration": 0.1}
            if command == snmpfix.apply_script("192.0.2.174") and files.get("start_fails"):
                # The file is replaced, then snmpd refuses to start: the backup line came first.
                files["backup"], files["conf"] = files["conf"], input_data.decode()
                out = ("BACKUP=/etc/snmp/snmpd.conf.hm-backup-1\nHM_STARTED=0\n"
                       "LOG: Error opening specified endpoint \"udp6:[::]:161\"\nLOG: Server Exiting with code 1\n")
                return {"status": "completed", "exit_code": 3, "stdout": out, "stderr": "", "duration": 0.1}
            if command == snmpfix.apply_script("192.0.2.174"):
                had = bool(files["conf"])
                files["backup"], files["conf"] = files["conf"], input_data.decode()
                files.update(installed=1, active="active")
                out = "BACKUP=/etc/snmp/snmpd.conf.hm-backup-1\n" if had else "INSTALLED=1\nBACKUP=none\n"
                return {"status": "completed", "exit_code": 0, "stdout": out, "stderr": "", "duration": 0.1}
            if "hm-backup-1" in command:
                files["conf"] = files["backup"]
                return {"status": "completed", "exit_code": 0, "stdout": "", "stderr": "", "duration": 0.1}
            raise AssertionError(command)

        with mock.patch.object(server.ssh_runner, "run_command", side_effect=fake_ssh), \
                mock.patch.object(server.snmpfix, "source_address", return_value="192.0.2.174"), \
                mock.patch.object(server.snmpfix, "verify", return_value=verify), \
                mock.patch.object(server.scheduler, "refresh_device") as refresh:
            status, res, _ = request("POST", f"/api/devices/{device or self.dev}/fix-snmp", body)
        self.refreshed = refresh.called
        return status, res, calls

    def test_preview_apply_and_secret_handling(self):
        files = {"conf": HAND_MADE_CONF}
        status, res, _ = self.call({"mode": "preview", "credential_id": self.cred}, files)
        self.assertEqual(status, 200, res)
        self.assertNotIn("s3cret-comm", json.dumps(res))
        self.assertIn("rocommunity  •••• 192.0.2.174/32 -V hmmonitor", res["content"])
        self.assertTrue(any(c.startswith("Removes from the old file") for c in res["changes"]))
        # A stale preview is refused.
        status, _, _ = self.call({"mode": "apply", "credential_id": self.cred, "expected_sha": "0" * 64}, files)
        self.assertEqual(status, 409)
        status, res2, calls = self.call({"mode": "apply", "credential_id": self.cred, "expected_sha": res["sha"]}, files)
        self.assertEqual((status, res2["success"]), (200, True), res2)
        self.assertIn("rocommunity  s3cret-comm 192.0.2.174/32 -V hmmonitor", files["conf"])
        self.assertNotIn("systemonly", files["conf"])
        self.assertTrue(self.refreshed)                 # polled and re-evaluated straight after
        # The community travels on stdin only, never in a command line.
        self.assertFalse(any("s3cret-comm" in c for c, _ in calls))
        self.assertTrue(any(i and b"s3cret-comm" in i for _, i in calls))
        # Running again on the clean file: nothing to change.
        res3 = self.call({"mode": "preview", "credential_id": self.cred}, files)[1]
        self.assertTrue(res3["unchanged"], res3)

    def test_copy_as_commands(self):
        status, res, _ = self.call({"mode": "script", "credential_id": self.cred}, {"conf": DEBIAN_DEFAULT})
        self.assertEqual(status, 200, res)
        self.assertIn("rocommunity  s3cret-comm 192.0.2.174/32 -V hmmonitor", res["script"])
        self.assertIn("Sitting on the Dock of the Bay", res["script"])     # kept from the host's file
        self.assertTrue(server.needs_confirmation("POST", f"/api/devices/{self.dev}/fix-snmp"))
        # No credential and no host key: still available, built from a blank file.
        status, res, _ = self.call({"mode": "script"}, {"conf": ""}, device=self.nokey)
        self.assertEqual(status, 200, res)
        self.assertIn("rocommunity  s3cret-comm 192.0.2.174/32", res["script"])

    def test_sudo_and_ufw(self):
        status, res, _ = self.call({"mode": "preview", "credential_id": self.cred}, {"conf": LISTENS_ON_ALL, "root": 0, "sudo": 0})
        self.assertEqual(status, 409)
        self.assertIn("sudo asks for a password", res["error"])
        res = self.call({"mode": "preview", "credential_id": self.cred},
                        {"conf": LISTENS_ON_ALL, "root": 0, "sudo": 1, "ufw": 1, "dropins": "old.conf"})[1]
        self.assertTrue(any("ufw is active" in c for c in res["changes"]))
        self.assertTrue(any("old.conf" in c for c in res["changes"]))
        self.assertIn("ufw allow from '192.0.2.174' to any port 161 proto udp", snmpfix.apply_script("192.0.2.174").replace("ufw allow from 192.0.2.174", "ufw allow from '192.0.2.174'"))

    def test_rollback_when_snmpd_does_not_start(self):
        files = {"conf": LISTENS_ON_ALL, "start_fails": True}
        sha = self.call({"mode": "preview", "credential_id": self.cred}, files)[1]["sha"]
        status, res, _ = self.call({"mode": "apply", "credential_id": self.cred, "expected_sha": sha}, files)
        self.assertEqual(status, 502)
        self.assertEqual(files["conf"], LISTENS_ON_ALL)              # restored, not left broken
        self.assertIn("previous file was restored", res["error"])
        self.assertIn("Error opening specified endpoint", res["error"])  # snmpd's own reason reaches the user

    def test_login_refused_in_plain_words(self):
        self.assertIn("PermitRootLogin", snmpfix.login_problem("root@192.0.2.91: Permission denied (publickey,password)."))
        self.assertIsNone(snmpfix.login_problem("something else"))

    def test_rollback_when_verify_fails(self):
        files = {"conf": LISTENS_ON_ALL}
        sha = self.call({"mode": "preview", "credential_id": self.cred}, files)[1]["sha"]
        status, res, _ = self.call({"mode": "apply", "credential_id": self.cred, "expected_sha": sha}, files, verify=False)
        self.assertEqual(status, 200)
        self.assertTrue(res["rolled_back"])
        self.assertEqual(files["conf"], LISTENS_ON_ALL)

    def test_install_when_missing(self):
        files = {"conf": "", "installed": 0, "active": "inactive"}
        status, res, _ = self.call({"mode": "preview", "credential_id": self.cred}, files)
        self.assertEqual(status, 200, res)
        self.assertTrue(res["changes"][0].startswith("snmpd is not installed"))
        self.assertIn("agentAddress udp:161\n", res["content"])
        status, res2, _ = self.call({"mode": "apply", "credential_id": self.cred, "expected_sha": res["sha"]}, files)
        self.assertEqual((status, res2["success"], res2["backup"]), (200, True, "none"), res2)
        self.assertIn("rocommunity  s3cret-comm 192.0.2.174/32 -V hmmonitor", files["conf"])
        # No apt-get and no snmpd: refused with a clear message.
        status, res3, _ = self.call({"mode": "preview", "credential_id": self.cred}, {"conf": "", "installed": 0, "apt": 0})
        self.assertEqual(status, 409)
        self.assertIn("no apt-get", res3["error"])

    def test_stopped_service_reported(self):
        status, res, _ = self.call({"mode": "preview", "credential_id": self.cred}, {"conf": LISTENS_ON_ALL, "active": "failed"})
        self.assertTrue(res["changes"][0].startswith("snmpd is failed"))
        self.assertFalse(res["unchanged"])

    def test_guards(self):
        database.set_snmp_status(self.other, "ok")
        self.assertEqual(request("POST", f"/api/devices/{self.other}/fix-snmp", {"credential_id": self.cred})[0], 400)
        self.assertEqual(request("POST", f"/api/devices/{self.dev}/fix-snmp", {"mode": "preview"})[0], 400)
        self.assertEqual(request("POST", f"/api/devices/{self.dev}/fix-snmp", {"mode": "bogus"})[0], 400)
        self.assertTrue(server.needs_confirmation("POST", f"/api/devices/{self.dev}/fix-snmp"))

    def test_outcomes_reach_the_notification_centre(self):
        def bell():
            return [e["message"] for e in request("GET", "/api/notifications")[1]["items"] if e["device_id"] == self.dev]
        # Refused before starting (no credential): an action event for this device.
        self.assertEqual(request("POST", f"/api/devices/{self.dev}/fix-snmp", {"mode": "preview"})[0], 400)
        self.assertTrue(any("choose a stored credential" in m for m in bell()), bell())
        files = {"conf": LISTENS_ON_ALL}
        sha = self.call({"mode": "preview", "credential_id": self.cred}, files)[1]["sha"]
        self.call({"mode": "apply", "credential_id": self.cred, "expected_sha": sha}, files)
        msgs = bell()
        self.assertTrue(any(m.startswith("Fix SNMP started on") for m in msgs), msgs)
        self.assertTrue(any(m.startswith("Fix SNMP done on") for m in msgs), msgs)


class SchedulerTests(unittest.TestCase):
    def test_poll_now_survives_a_running_poll(self):
        """A "poll now" while the previous poll still runs must not be lost until the next interval."""
        s = server.PollScheduler.__new__(server.PollScheduler)
        import threading
        s.lock = threading.RLock()
        s.in_flight = {("snmp", 7)}
        ran = []
        s.pool = mock.Mock(submit=lambda fn: ran.append(fn))
        self.assertFalse(s._submit("snmp", 7, lambda: None))
        self.assertTrue(s._submit("snmp", 8, lambda: None))
        self.assertEqual(len(ran), 1)


if __name__ == "__main__":
    unittest.main()
