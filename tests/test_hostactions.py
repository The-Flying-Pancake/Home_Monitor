"""Host actions: the fixed catalogue of Linux maintenance jobs run once over SSH (hostactions.py and its routes).
SSH is replaced by a stand-in, so nothing here reaches a host."""

import os
import shutil
import subprocess
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import hostactions
import maintenance
import server
import workflows


def git_bash():
    """A real bash for syntax checks: on Windows the one on PATH may be the WSL launcher."""
    for path in (shutil.which("bash"), r"C:\Program Files\Git\usr\bin\bash.exe", r"C:\Program Files\Git\bin\bash.exe"):
        if path and os.path.exists(path) and "system32" not in path.lower():
            return path
    return None


class CatalogueTests(unittest.TestCase):
    def test_every_action_is_well_formed(self):
        ids = [a["id"] for a in hostactions.ACTIONS]
        self.assertEqual(len(ids), len(set(ids)))
        for a in hostactions.ACTIONS:
            self.assertIn(a["kind"], hostactions.KINDS, a["id"])
            self.assertTrue(a["note"] and a["note"][0].isupper(), a["id"])
            if a["kind"] != "check":
                self.assertIn("preview", a, f"{a['id']} changes something: it needs a preview")
            choice = (a.get("choice") or {}).get("default") or ("x" if a.get("choice") else None)
            # A workflow command step holds at most 4000 characters.
            self.assertLessEqual(len(hostactions.workflow_script(a["id"])), 4000, a["id"])
            self.assertTrue(hostactions.script(a["id"], "run", choice).startswith(hostactions.PRELUDE))
        # Nothing in the catalogue deletes by path, formats, partitions or touches users or the firewall.
        everything = "\n".join(a["run"] + a.get("preview", "") for a in hostactions.ACTIONS)
        for word in ("rm -", "mkfs", "fdisk", "parted", "wipefs", "fsck", "userdel", "iptables", "ufw ", "qm destroy",
                     "pct destroy", "qm stop", "pct stop", "rollback", "docker system prune", "volume prune", "-a -f"):
            self.assertNotIn(word, everything, word)

    def test_scripts_parse_as_posix_shell(self):
        bash = git_bash()
        if not bash:
            self.skipTest("no bash to check the scripts with")
        for a in hostactions.ACTIONS:
            choice = (a.get("choice") or {}).get("default") or ("x" if a.get("choice") else None)
            modes = ["run"] + (["preview"] if "preview" in a else []) + (["list"] if (a.get("choice") or {}).get("list") else [])
            texts = [hostactions.script(a["id"], m, choice) for m in modes] + [hostactions.workflow_script(a["id"])]
            for text in texts:
                r = subprocess.run([bash, "-n", "-o", "posix"], input=text.encode(), capture_output=True)
                self.assertEqual(r.returncode, 0, f"{a['id']}: {r.stderr.decode()}")

    def test_choices_cannot_reach_the_shell(self):
        svc = hostactions.BY_ID["restart_service"]
        for bad in ("nginx; reboot", "$(reboot)", "`id`", "a b", "-rf", "../x", "a|b", "", "x" * 200, "a'b", "a\nb"):
            with self.assertRaises(hostactions.ActionError, msg=bad):
                hostactions.check_choice(svc, bad)
        self.assertEqual(hostactions.check_choice(svc, "nginx"), "nginx")
        self.assertEqual(hostactions.check_choice(svc, "openvpn@home"), "openvpn@home")
        # The network, systemd, the session and this monitor are never restarted from here.
        for blocked in ("networking", "systemd-networkd", "dbus", "NetworkManager", "homelab-monitor", "user@0"):
            with self.assertRaises(hostactions.ActionError, msg=blocked):
                hostactions.check_choice(svc, blocked)
        # ...but their status can be read.
        self.assertEqual(hostactions.check_choice(hostactions.BY_ID["service_status"], "networking"), "networking")
        # Fixed options only.
        vac = hostactions.BY_ID["journal_vacuum"]
        self.assertEqual(hostactions.check_choice(vac, None), "200M")
        with self.assertRaises(hostactions.ActionError):
            hostactions.check_choice(vac, "1K")
        # The choice travels as one quoted assignment.
        self.assertIn("C=openvpn@home\n", hostactions.script("restart_service", "run", "openvpn@home"))
        self.assertIn("C=a+b\n", hostactions.script("restart_service", "run", "a+b"))
        self.assertIn("C=name   # service: change this", hostactions.workflow_script("restart_service"))
        self.assertTrue(hostactions.workflow_script("restart_service", "nginx").startswith("C=nginx   # service\n"))

    def test_list_parsing_drops_odd_names(self):
        self.assertEqual(hostactions.parse_list("nginx\nsnmpd\n\nbad name\n$(x)\nnginx\npihole-FTL\n"),
                         ["nginx", "snmpd", "pihole-FTL"])

    def test_suggestions_follow_the_problem(self):
        ids = [s["id"] for s in hostactions.suggest("forecast_full:3")]
        self.assertEqual(ids[0], "disk_usage")                       # a check first: it changes nothing
        self.assertIn("journal_vacuum", ids)
        self.assertNotIn("reboot", ids)
        watched = hostactions.suggest("watch:service:nginx")
        self.assertEqual(watched[:2], [{"id": "service_status", "choice": "nginx"}, {"id": "restart_service", "choice": "nginx"}])
        self.assertEqual(hostactions.suggest("snmp")[0], {"id": "service_status", "choice": "snmpd"})
        self.assertEqual(hostactions.suggest("unreachable"), [])     # nothing to SSH into
        self.assertEqual(hostactions.suggest(""), [])

    def test_previews_expire_and_are_per_choice(self):
        p = hostactions.Previews()
        p.mark("ann", 1, "journal_vacuum", "200M", now=1000)
        self.assertTrue(p.fresh("ann", 1, "journal_vacuum", "200M", now=1000 + 60))
        self.assertFalse(p.fresh("ann", 1, "journal_vacuum", "500M", now=1000 + 60))
        self.assertFalse(p.fresh("bob", 1, "journal_vacuum", "200M", now=1000 + 60))
        self.assertFalse(p.fresh("ann", 1, "journal_vacuum", "200M", now=1000 + hostactions.PREVIEW_TTL + 1))


def ok(stdout="", code=0):
    return {"status": "completed", "exit_code": code, "stdout": stdout, "stderr": "", "duration": 0.1}


class HostActionApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("ha-host", "192.0.2.161", profile="linux_host")
        cls.nokey = add_device("ha-nokey", "192.0.2.162", profile="linux_host")
        database.approve_host_key(cls.dev, "ssh-ed25519", "AAAA", "SHA256:x")
        cls.cred = request("POST", "/api/credentials", {"name": "ha-root", "cred_type": "password", "username": "root",
                                                         "secret": "pw-ha"})[1]["id"]

    @classmethod
    def tearDownClass(cls):
        # Its "action" events would crowd other tests' notification bell.
        with database.get_connection() as c:
            c.execute("DELETE FROM events WHERE device_id IN (?, ?)", (cls.dev, cls.nokey))
            c.commit()

    def post(self, action, body, ssh=None, device=None):
        calls = []

        def fake(ip, port, cred, command, keys, timeout, input_data=None):
            calls.append(command)
            return (ssh or (lambda c: ok("fine")))(command)

        with mock.patch.object(server.ssh_runner, "run_command", side_effect=fake):
            status, res, _ = request("POST", f"/api/devices/{device or self.dev}/host-actions/{action}",
                                     dict({"credential_id": self.cred}, **body))
            if status == 200 and res.get("run_id"):
                res["run"] = self.wait(res["run_id"])
        return status, res, calls

    def wait(self, run_id):
        for _ in range(100):
            run = database.get_action_run(run_id)
            if run["status"] != "running":
                return run
            time.sleep(0.05)
        self.fail("run did not finish")

    def test_catalogue_view_and_suggestions(self):
        status, res, _ = request("GET", f"/api/host-actions?device_id={self.dev}&problem=forecast_full:1")
        self.assertEqual(status, 200, res)
        self.assertEqual(res["device"]["hostname"], "ha-host")
        self.assertTrue(res["device"]["host_key"])
        self.assertEqual(res["suggested"][0]["id"], "disk_usage")
        self.assertEqual(len(res["actions"]), len(hostactions.ACTIONS))
        self.assertNotIn("preview", res["actions"][0])               # only the run script goes to the browser

    def test_check_runs_at_once_and_is_recorded(self):
        status, res, calls = self.post("disk_usage", {"mode": "run", "problem_key": "forecast_full:1"},
                                       ssh=lambda c: ok("== Filesystems ==\n/dev/sda1 50%"))
        self.assertEqual(status, 200, res)
        run = res["run"]
        self.assertEqual((run["status"], run["action_id"], run["problem_key"]), ("ok", "disk_usage", "forecast_full:1"))
        self.assertIn("/dev/sda1 50%", run["output"])
        self.assertEqual(calls, [hostactions.script("disk_usage", "run")])
        runs = request("GET", f"/api/host-actions/runs?device_id={self.dev}")[1]["runs"]
        self.assertEqual(runs[0]["id"], run["id"])
        self.assertNotIn("output", runs[0])                          # the list is light; one run carries its output
        self.assertIn("Ran host action Disk space", " ".join(a["message"] for a in database.list_audit_logs(limit=1000)))

    def test_change_needs_its_own_preview_first(self):
        status, res, calls = self.post("journal_vacuum", {"mode": "run", "choice": "200M"})
        self.assertEqual(status, 409, res)
        self.assertEqual(calls, [])
        status, res, _ = self.post("journal_vacuum", {"mode": "preview", "choice": "200M"},
                                   ssh=lambda c: ok("Archived and active journals take up 1.2G"))
        self.assertEqual(status, 200, res)
        self.assertIn("1.2G", res["output"])
        # A preview of another size does not count.
        self.assertEqual(self.post("journal_vacuum", {"mode": "run", "choice": "500M"})[0], 409)
        status, res, calls = self.post("journal_vacuum", {"mode": "run", "choice": "200M"}, ssh=lambda c: ok("Vacuuming done"))
        self.assertEqual((status, res["run"]["status"]), (200, "ok"), res)
        self.assertIn("C=200M\n", calls[0])
        events = database.list_events(self.dev, 50)
        self.assertTrue(any("Shrink the system journal" in e["message"] and "done" in e["message"] for e in events))

    def test_restart_needs_the_name_and_refuses_blocked_services(self):
        self.assertEqual(self.post("restart_service", {"mode": "preview", "choice": "networking"})[0], 400)
        listing = lambda c: ok("nginx\nnetworking\nsystemd-journald\nsnmpd\n")
        status, res, _ = self.post("restart_service", {"mode": "choices"}, ssh=listing)
        self.assertEqual(res["options"], ["nginx", "snmpd"])
        self.assertEqual(self.post("restart_service", {"mode": "preview", "choice": "nginx"}, ssh=lambda c: ok("active"))[0], 200)
        status, res, calls = self.post("restart_service", {"mode": "run", "choice": "nginx", "confirm": "wrong"})
        self.assertEqual((status, calls), (400, []))
        status, res, calls = self.post("restart_service", {"mode": "run", "choice": "nginx", "confirm": "HA-HOST "},
                                       ssh=lambda c: ok("nginx is running."))
        self.assertEqual((status, res["run"]["status"]), (200, "ok"), res)

    def test_failures_read_plainly(self):
        no_sudo = lambda c: ok("HM_NO_SUDO\n", hostactions.NO_SUDO)
        run = self.post("health", {"mode": "run"}, ssh=no_sudo)[1]["run"]
        self.assertEqual(run["status"], "failed")
        self.assertIn("sudo asks for a password", run["output"])
        refused = lambda c: {"status": "error", "exit_code": 255, "stdout": "", "stderr": "Permission denied (publickey)", "duration": 0}
        run = self.post("health", {"mode": "run"}, ssh=refused)[1]["run"]
        self.assertIn("refused the login", run["output"])
        missing = lambda c: ok("No service called nope on this host\n", hostactions.NOT_FOUND)
        run = self.post("service_status", {"mode": "run", "choice": "nope"}, ssh=missing)[1]["run"]
        self.assertEqual(run["status"], "failed")

    def test_guards(self):
        self.assertEqual(self.post("bogus", {"mode": "run"})[0], 404)
        self.assertEqual(self.post("health", {"mode": "nope"})[0], 400)
        self.assertEqual(request("POST", f"/api/devices/{self.dev}/host-actions/health", {"mode": "run"})[0], 400)   # no credential
        self.assertEqual(self.post("health", {"mode": "run"}, device=self.nokey)[0], 409)                         # no host key
        self.assertEqual(self.post("restart_service", {"mode": "run", "choice": "nginx; reboot"})[0], 400)
        self.assertEqual(self.post("health", {"mode": "preview"})[0], 400)      # a check has nothing to preview
        self.assertTrue(server.needs_confirmation("POST", f"/api/devices/{self.dev}/host-actions/health"))
        # A snapshot needs a Proxmox guest behind the device.
        self.post("autoremove", {"mode": "preview"})
        self.assertEqual(self.post("autoremove", {"mode": "run", "snapshot": True})[0], 409)
        # Restarting the machine the monitor runs on is refused.
        self.post("reboot", {"mode": "preview"})
        with mock.patch.object(server, "is_this_machine", return_value=True):
            self.assertEqual(self.post("reboot", {"mode": "run", "confirm": "ha-host"})[0], 409)

    def test_one_run_at_a_time_per_device(self):
        hostactions.RUNS.active[self.dev] = 999999
        try:
            self.assertEqual(self.post("health", {"mode": "run"})[0], 409)
        finally:
            hostactions.RUNS.release(self.dev)

    def test_reboot_mutes_waits_and_reports(self):
        self.post("reboot", {"mode": "preview"})
        pings = iter([(False, None), (True, 1.0), (True, 1.0)])
        with mock.patch.object(server.poller, "ping_host", side_effect=lambda ip, t: next(pings)), \
                mock.patch.object(server.workflows, "POLL_SECONDS", 0), \
                mock.patch.object(server, "is_this_machine", return_value=False):
            status, res, calls = self.post("reboot", {"mode": "run", "confirm": "ha-host"}, ssh=lambda c: ok("Restarting in 5 s"))
        self.assertEqual(status, 200, res)
        self.assertEqual(res["run"]["status"], "ok", res["run"]["output"])
        self.assertIn("answers ping again", res["run"]["output"])
        # Its notifications were muted for the restart; the window closes five minutes after it is back.
        mine = [w for w in maintenance._load() if w["by"] == f"action:{res['run']['id']}"]
        self.assertEqual(len(mine), 1)
        self.assertLessEqual(mine[0]["end"], time.time() + 301)

    def test_make_a_workflow(self):
        status, res, _ = self.post("restart_service", {"mode": "workflow", "choice": "nginx"})
        self.assertEqual(status, 200, res)
        wf = database.get_workflow(res["workflow_id"])
        self.assertEqual(wf["name"], "Restart a service on ha-host")
        step = wf["steps"][0]
        self.assertEqual((step["type"], step["device_ids"], step["credential_id"]), ("command", [self.dev], self.cred))
        self.assertTrue(step["command"].startswith("C=nginx   # service\n"))
        status, res, _ = self.post("reboot", {"mode": "workflow"})
        steps = database.get_workflow(res["workflow_id"])["steps"]
        self.assertEqual([s["type"] for s in steps], ["command", "wait_ping", "wait_ping"])
        self.assertTrue(workflows.expects_drop(steps[0]))



class SshSetupTests(unittest.TestCase):
    """Copy console commands: one line that lets the monitor in over SSH, from its address only."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("ssh-setup-host", "203.0.113.181", profile="linux_host")

    def test_script(self):
        import snmpfix
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl it's mine"
        s = snmpfix.ssh_setup_script("192.0.2.10", "root", key)
        self.assertNotIn(chr(10), s)                                # one line to paste
        self.assertIn("Match Address 192.0.2.10", s)                # password and root logins from the monitor only
        self.assertIn("sshd -t", s)                                  # checked; the backup returns when it fails
        self.assertIn("authorized_keys", s)
        self.assertNotIn("it's mine", s)                            # the key's comment is replaced, never pasted as given
        bash = git_bash()
        if bash:
            self.assertEqual(subprocess.run([bash, "-n", "-c", s], capture_output=True).returncode, 0)
        # With a key, root may log in by key only; without one (a password setup) by password.
        self.assertIn("PermitRootLogin prohibit-password", s)
        self.assertNotIn("PermitRootLogin yes", s)
        # A key turns password logins from the monitor off and is bound to its address (REV-04).
        self.assertIn("PasswordAuthentication no", s)
        self.assertNotIn("PasswordAuthentication yes", s)
        self.assertIn('from="192.0.2.10"', s)
        self.assertIn("PermitRootLogin yes", snmpfix.ssh_setup_script("192.0.2.10", "root", None))
        odd = snmpfix.ssh_setup_script("192.0.2.10", "x; rm -rf /", None)
        self.assertIn("passwd root", odd)                          # an odd user name falls back to root
        self.assertNotIn("rm -rf", odd)
        with self.assertRaises(ValueError):
            snmpfix.ssh_setup_script("not-an-address")

    def test_endpoint(self):
        status, body, _ = request("POST", f"/api/devices/{self.dev}/ssh-setup", {})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["script"].startswith("sh -c "))
        self.assertIn(body["monitor_ip"], body["script"])
        self.assertEqual(request("POST", "/api/devices/999999/ssh-setup", {})[0], 404)

    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

    def test_password_script_is_unchanged(self):
        import snmpfix
        s = snmpfix.ssh_setup_script("192.0.2.10", "root", None)
        self.assertIn("PermitRootLogin yes", s)
        self.assertIn("PasswordAuthentication yes", s)
        self.assertNotIn("authorized_keys", s)

    def test_key_script_rerun_replaces_only_its_own_line(self):
        import snmpfix
        s = snmpfix.ssh_setup_script("192.0.2.10", "root", self.KEY + " a comment")
        blob = self.KEY.split()[1]
        inner = s.replace("'\"'\"'", "'")                                  # without the outer sh -c quoting
        self.assertIn(f"grep -v ' {blob} homelab-monitor$'", inner)      # removes only the monitor's own line
        self.assertEqual(s.count("authorized_keys"), 1)                   # one file, named once
        self.assertEqual(s.count(f'from="192.0.2.10" {self.KEY} homelab-monitor'), 1)   # and adds one line
        bash = git_bash()
        if bash:
            self.assertEqual(subprocess.run([bash, "-n", "-c", s], capture_output=True).returncode, 0)

    def test_key_script_rerun_runs(self):
        """The removal and the new line run against a sample file: a second run leaves one monitor line."""
        bash = git_bash()
        if not bash:
            self.skipTest("no bash")
        import snmpfix
        import tempfile
        blob = self.KEY.split()[1]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "authorized_keys").replace("\\", "/")
            with open(path, "w", newline="\n") as f:
                f.write(f"ssh-ed25519 AAAAOWNKEY me@laptop\n{self.KEY} homelab-monitor\n{self.KEY} mine\n")
            # The authorized_keys part of the script, pointed at the sample file.
            s = snmpfix.ssh_setup_script("192.0.2.10", "root", self.KEY)
            part = s[s.index("T=$(mktemp)"):s.index("chown")].replace('"$A"', f'"{path}"')
            part = part.replace("'\"'\"'", "'")                           # undo the outer sh -c quoting
            for _ in range(2):
                subprocess.run([bash, "-c", part], check=True, capture_output=True)
            with open(path) as f:
                lines = f.read().splitlines()
        self.assertEqual(lines, ["ssh-ed25519 AAAAOWNKEY me@laptop", f"{self.KEY} mine",
                                 f'from="192.0.2.10" {self.KEY} homelab-monitor'])
        self.assertEqual(sum(1 for line in lines if line.endswith(f"{blob} homelab-monitor")), 1)

    def test_unusable_key_raises(self):
        import snmpfix
        for bad in ("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAI", "not a key"):
            with self.assertRaises(ValueError):
                snmpfix.ssh_setup_script("192.0.2.10", "root", bad)

    def setup_route(self, cred_id):
        with mock.patch.object(server.snmpfix, "source_address", return_value="192.0.2.10"):
            return request("POST", f"/api/devices/{self.dev}/ssh-setup", {"credential_id": cred_id})

    def test_route_key_credential(self):
        cid = database.add_credential("ssh-setup-key", "ssh_key", "admin", "PRIVATE-KEY-TEXT-route", public_key=self.KEY + " me")
        with mock.patch.object(server.database, "get_credential_secret", side_effect=AssertionError("no secret needed")):
            status, body, _ = self.setup_route(cid)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["kind"], "key")
        for want in (self.KEY, "PasswordAuthentication no", "PermitRootLogin prohibit-password", 'from="192.0.2.10"'):
            self.assertIn(want, body["script"])
        self.assertNotIn("PasswordAuthentication yes", body["script"])

    def test_route_password_credential(self):
        cid = database.add_credential("ssh-setup-pw", "password", "root", "pw-ssh-setup")
        status, body, _ = self.setup_route(cid)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["kind"], "password")
        self.assertIn("PermitRootLogin yes", body["script"])
        self.assertIn("PasswordAuthentication yes", body["script"])
        self.assertNotIn("pw-ssh-setup", repr(body))

    def test_route_old_key_without_public_key(self):
        cid = database.add_credential("ssh-setup-old", "ssh_key", "root", "OLD-PRIVATE-KEY-TEXT")
        with mock.patch.object(server.ssh_runner, "public_key_of", return_value=self.KEY):
            status, body, _ = self.setup_route(cid)
        self.assertEqual((status, body["kind"]), (200, "key"))
        self.assertIn(self.KEY, body["script"])
        with mock.patch.object(server.ssh_runner, "public_key_of", return_value=None):
            status, body, _ = self.setup_route(cid)
        self.assertEqual(status, 409, body)
        self.assertIn("no public key saved", body["error"])
        self.assertNotIn("OLD-PRIVATE-KEY-TEXT", repr(body))

class PasswordCredentialTests(unittest.TestCase):
    """A stored password follows the device's address, so only Manage credentials may use one on an
    action; and a new address forgets the approved host keys."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("pwc-host", "203.0.113.243", profile="linux_host")
        database.approve_host_key(cls.dev, "ssh-ed25519", "AAAA", "SHA256:x")
        cls.pw = request("POST", "/api/credentials", {"name": "pwc-root", "cred_type": "password", "username": "root",
                                                       "secret": "pw-pwc"})[1]["id"]
        from tests.helpers import session_cookie
        status, res, _ = request("POST", "/api/users", {"username": "pwc-user", "password": "password cred passphrase",
                                                         "role": "custom", "permissions": ["devices.manage", "automation.run"]})
        assert status == 201, res
        _, _, headers = request("POST", "/api/auth/login", {"username": "pwc-user", "password": "password cred passphrase"},
                                session=False)
        cls.cookie = {"Cookie": f"{server.auth.SESSION_COOKIE}={session_cookie(headers)}"}

    @classmethod
    def tearDownClass(cls):
        database.delete_user("pwc-user")

    def test_password_credential_needs_manage_credentials(self):
        for path, body in ((f"/api/devices/{self.dev}/ssh-setup", {"credential_id": self.pw}),
                           (f"/api/devices/{self.dev}/fix-snmp", {"mode": "preview", "credential_id": self.pw}),
                           (f"/api/devices/{self.dev}/host-actions/health", {"mode": "run", "credential_id": self.pw})):
            with mock.patch.object(server.ssh_runner, "run_command") as ssh:
                status, res, _ = request("POST", path, body, headers=self.cookie, session=False)
            self.assertEqual(status, 403, (path, res))
            self.assertIn("Manage credentials", res["error"])
            ssh.assert_not_called()
        # Without a credential the copy-paste commands still work.
        with mock.patch.object(server.snmpfix, "source_address", return_value="192.0.2.174"):
            status, res, _ = request("POST", f"/api/devices/{self.dev}/ssh-setup", {}, headers=self.cookie, session=False)
        self.assertEqual(status, 200, res)

    def test_new_address_forgets_host_keys(self):
        self.assertTrue(database.get_host_keys(self.dev))
        body = {"hostname": "pwc-host", "ip_address": "203.0.113.243", "profile_id": "linux_host"}
        self.assertEqual(request("PUT", f"/api/devices/{self.dev}", body)[0], 200)
        self.assertTrue(database.get_host_keys(self.dev))                   # same address: kept
        self.assertEqual(request("PUT", f"/api/devices/{self.dev}", dict(body, ip_address="203.0.113.244"))[0], 200)
        self.assertFalse(database.get_host_keys(self.dev))
        audit = [a["message"] for a in database.list_audit_logs(limit=20)]
        self.assertTrue(any("Forgot the SSH host key of pwc-host" in m for m in audit))
        request("PUT", f"/api/devices/{self.dev}", body)
        database.approve_host_key(self.dev, "ssh-ed25519", "AAAA", "SHA256:x")


def login_cookie(name, permissions=None, role="custom"):
    """A user created by the test administrator, logged in: the session cookie header."""
    from tests.helpers import session_cookie
    body = {"username": name, "password": "credential use passphrase", "role": role}
    if permissions is not None:
        body["permissions"] = permissions
    status, res, _ = request("POST", "/api/users", body)
    assert status == 201, res
    _, _, headers = request("POST", "/api/auth/login", {"username": name, "password": "credential use passphrase"}, session=False)
    return {"Cookie": f"{server.auth.SESSION_COOKIE}={session_cookie(headers)}"}


def expire_step_up(username):
    """The user's confirmation has lapsed: a tier 2 or 3 route would ask for the password first."""
    with server.auth.SESSIONS.lock:
        for sess in server.auth.SESSIONS.sessions.values():
            if sess["username"] == username:
                sess["tier2_until"] = sess["tier3_until"] = 0


class CredentialUseTests(unittest.TestCase):
    """Use stored credentials on host actions, Fix SNMP and ssh-setup; approving a host key needs
    Manage credentials, forgetting one stays on Manage devices."""

    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("cu-ha-host", "203.0.113.236", profile="linux_host")
        database.approve_host_key(cls.dev, "ssh-ed25519", "AAAA", "SHA256:cuha")
        cls.key = database.add_credential("cu-ha-key", "ssh_key", "root", "CU-HA-PRIVATE-KEY", public_key=cls.KEY + " me")
        cls.pw = database.add_credential("cu-ha-pw", "password", "root", "pw-cu-ha")
        cls.devman = login_cookie("cu-ha-devman", ["devices.manage"])
        cls.actor = login_cookie("cu-ha-actor", ["devices.manage", "automation.run"])
        cls.operator = login_cookie("cu-ha-op", role="operator")

    @classmethod
    def tearDownClass(cls):
        for name in ("cu-ha-devman", "cu-ha-actor", "cu-ha-op"):
            database.delete_user(name)
        with database.get_connection() as c:
            c.execute("DELETE FROM events WHERE device_id = ?", (cls.dev,))
            c.commit()

    def as_(self, who, method, path, body=None):
        return request(method, path, body, headers=who, session=False)

    def test_devices_manage_only_cannot_approve_host_key(self):
        cookie = login_cookie("cu-ha-approver", ["devices.manage"])
        self.addCleanup(database.delete_user, "cu-ha-approver")
        expire_step_up("cu-ha-approver")
        presented = {"key_type": "ssh-ed25519", "key_b64": "CCCC", "fingerprint": "SHA256:other"}
        with mock.patch.object(server.ssh_runner, "fetch_host_key", return_value=presented) as fetch:
            status, res, _ = self.as_(cookie, "POST", f"/api/devices/{self.dev}/hostkey", {"fingerprint": "SHA256:other"})
        self.assertEqual(status, 403, res)
        self.assertNotEqual(res.get("auth"), "confirm")            # refused before any password prompt
        fetch.assert_not_called()
        self.assertEqual([k["fingerprint"] for k in database.get_host_keys(self.dev)], ["SHA256:cuha"])

    def test_forget_host_key_stays_on_devices_manage(self):
        dev = add_device("cu-ha-forget", "203.0.113.237", profile="linux_host")
        try:
            database.approve_host_key(dev, "ssh-ed25519", "AAAA", "SHA256:f")
            cookie = login_cookie("cu-ha-forgetter", ["devices.manage"])
            status, res, _ = self.as_(cookie, "DELETE", f"/api/devices/{dev}/hostkey")
            self.assertEqual(status, 200, res)
            self.assertFalse(database.get_host_keys(dev))
        finally:
            database.delete_user("cu-ha-forgetter")
            database.delete_device(dev)

    def test_host_key_audit_names_the_actor(self):
        from tests.helpers import TEST_PASSWORD, TEST_USER
        dev = add_device("cu-ha-audit", "203.0.113.238", profile="linux_host")
        try:
            request("POST", "/api/auth/confirm", {"password": TEST_PASSWORD, "tier": 3})
            presented = {"key_type": "ssh-ed25519", "key_b64": "DDDD", "fingerprint": "SHA256:aud"}
            with mock.patch.object(server.ssh_runner, "fetch_host_key", return_value=presented):
                status, res, _ = request("POST", f"/api/devices/{dev}/hostkey", {"fingerprint": "SHA256:aud"})
            self.assertEqual(status, 200, res)
            self.assertEqual(request("DELETE", f"/api/devices/{dev}/hostkey")[0], 200)
            rows = [(a["message"], a["details"]) for a in database.list_audit_logs(limit=50)]
            self.assertIn(("Approved SSH host key for cu-ha-audit", f"SHA256:aud; by {TEST_USER}"), rows)
            self.assertIn(("Forgot SSH host key", f"Device ID: {dev}, 1 key(s); by {TEST_USER}"), rows)
        finally:
            database.delete_device(dev)

    def test_key_credential_needs_use_on_actions(self):
        for path, body in ((f"/api/devices/{self.dev}/fix-snmp", {"mode": "preview", "credential_id": self.key}),
                           (f"/api/devices/{self.dev}/fix-snmp", {"mode": "script", "credential_id": self.key}),
                           (f"/api/devices/{self.dev}/host-actions/disk_usage", {"mode": "run", "credential_id": self.key})):
            with mock.patch.object(server.ssh_runner, "run_command") as ssh:
                status, res, _ = self.as_(self.actor, "POST", path, body)
            self.assertEqual(status, 403, (path, res))
            self.assertIn("Use stored credentials", res["error"])
            ssh.assert_not_called()

    def test_fix_snmp_copy_without_credential_needs_no_use(self):
        with mock.patch.object(server.snmpfix, "source_address", return_value="192.0.2.174"), \
                mock.patch.object(server.ssh_runner, "run_command") as ssh:
            status, res, _ = self.as_(self.devman, "POST", f"/api/devices/{self.dev}/fix-snmp", {"mode": "script"})
        self.assertEqual(status, 200, res)
        self.assertIn("rocommunity", res["script"])
        ssh.assert_not_called()

    def test_ssh_setup_does_not_need_use(self):
        with mock.patch.object(server.snmpfix, "source_address", return_value="192.0.2.174"):
            status, res, _ = self.as_(self.devman, "POST", f"/api/devices/{self.dev}/ssh-setup", {"credential_id": self.key})
            self.assertEqual(status, 200, res)
            self.assertEqual(res["kind"], "key")
            status, res, _ = self.as_(self.devman, "POST", f"/api/devices/{self.dev}/ssh-setup", {"credential_id": self.pw})
        self.assertEqual(status, 403, res)
        self.assertIn("Manage credentials", res["error"])

    def test_operator_keeps_host_actions(self):
        with mock.patch.object(server.ssh_runner, "run_command", return_value=ok("fine")) as ssh:
            status, res, _ = self.as_(self.operator, "POST", f"/api/devices/{self.dev}/host-actions/disk_usage",
                                      {"mode": "run", "credential_id": self.pw})
            self.assertEqual(status, 403, res)
            self.assertIn("Manage credentials", res["error"])
            ssh.assert_not_called()
            status, res, _ = self.as_(self.operator, "POST", f"/api/devices/{self.dev}/host-actions/disk_usage",
                                      {"mode": "run", "credential_id": self.key})
            self.assertEqual(status, 200, res)
            for _ in range(100):
                if database.get_action_run(res["run_id"])["status"] != "running":
                    break
                time.sleep(0.05)
        self.assertEqual(database.get_action_run(res["run_id"])["status"], "ok")
        ssh.assert_called_once()


if __name__ == "__main__":
    unittest.main()
