"""Schedule picker translation, one-off runs, the graph workflow API, run preflight and SSH key credentials."""

import time
import unittest
from datetime import datetime
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import database
import schedule
import server
import ssh_runner
import workflows

NOW = time.mktime(datetime(2026, 11, 1, 12, 0).timetuple())


class ScheduleTests(unittest.TestCase):
    def test_kinds_to_cron_and_text(self):
        cases = [
            ({"kind": "daily", "time": "04:30"}, "30 4 * * *", "Every day at 04:30"),
            ({"kind": "weekly", "weekdays": [0], "time": "04:00"}, "0 4 * * 0", "Every Sunday at 04:00"),
            ({"kind": "weekly", "weekdays": [5, 1, 3], "time": "22:15"}, "15 22 * * 1,3,5",
             "Every Monday, Wednesday and Friday at 22:15"),
            ({"kind": "weekly", "weekdays": [1, 2, 3, 4, 5], "time": "06:00"}, "0 6 * * 1,2,3,4,5", "Every weekday at 06:00"),
            ({"kind": "monthly", "day": 1, "time": "03:00"}, "0 3 1 * *", "Monthly on the 1st at 03:00"),
            ({"kind": "interval", "every": 15, "unit": "minutes"}, "*/15 * * * *", "Every 15 minutes"),
            ({"kind": "interval", "every": 1, "unit": "hours"}, "0 */1 * * *", "Every hour"),
        ]
        for raw, cron, text in cases:
            s = schedule.parse(raw, NOW)
            self.assertEqual(schedule.to_trigger(s), ("schedule", cron, None), raw)
            self.assertEqual(schedule.describe(s), text)
            self.assertEqual(schedule.to_trigger(schedule.from_cron(cron))[1], cron)     # cron maps back to the picker
            ssh_runner.parse_cron(cron)

    def test_once(self):
        s = schedule.parse({"kind": "once", "date": "2026-11-02", "time": "03:00"}, NOW)
        kind, cron, run_at = schedule.to_trigger(s)
        self.assertEqual((kind, cron), ("once", None))
        self.assertEqual(datetime.fromtimestamp(run_at), datetime(2026, 11, 2, 3, 0))
        self.assertEqual(schedule.describe(s), "Once on 2026-11-02 at 03:00")
        with self.assertRaisesRegex(schedule.ScheduleError, "already passed"):
            schedule.parse({"kind": "once", "date": "2026-10-01", "time": "03:00"}, NOW)
        with self.assertRaisesRegex(schedule.ScheduleError, "does not exist"):
            schedule.parse({"kind": "once", "date": "2026-02-30", "time": "03:00"}, NOW)
        done = schedule.parse({"kind": "once", "date": "2026-10-01", "time": "03:00", "done": True}, NOW)
        self.assertEqual(schedule.to_trigger(done), ("manual", None, None))

    def test_rejects(self):
        for raw in ({"kind": "hourly"}, {"kind": "daily", "time": "4:00"}, {"kind": "weekly", "weekdays": [], "time": "04:00"},
                    {"kind": "weekly", "weekdays": [7], "time": "04:00"}, {"kind": "monthly", "day": 32, "time": "04:00"},
                    {"kind": "interval", "every": 7, "unit": "minutes"}, {"kind": "interval", "every": 5, "unit": "days"},
                    {"kind": "cron", "cron": "99 * * * *"}, "daily"):
            with self.assertRaises(schedule.ScheduleError, msg=raw):
                schedule.parse(raw, NOW)

    def test_unmapped_cron_stays_custom(self):
        s = schedule.from_cron("5 4 1-7 * 1")
        self.assertEqual(s["kind"], "cron")
        self.assertEqual(schedule.describe(s), "Custom (cron 5 4 1-7 * 1)")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("auto-a", "192.0.2.210")
        status, body, _ = request("POST", "/api/credentials", {"name": "auto-cred", "cred_type": "password", "username": "root",
                                                                "secret": "pw-auto"})
        cls.cred = body["id"]

    def graph(self, sched=None, host_key=True):
        return {"nodes": [{"id": "t", "type": "trigger", "x": 0, "y": 0, "schedule": sched or {"kind": "manual"}},
                          {"id": "a", "type": "command", "x": 250, "y": 0, "command": "uptime", "device_ids": [self.dev],
                           "credential_id": self.cred}],
                "edges": [{"from": "t", "to": "a", "kind": "ok"}]}

    def test_graph_save_and_view(self):
        status, body, _ = request("POST", "/api/workflows", {"name": "graph-wf", "graph": self.graph(
            {"kind": "weekly", "weekdays": [0], "time": "04:00"})})
        self.assertEqual(status, 201, body)
        wf = next(w for w in request("GET", "/api/workflows")[1]["workflows"] if w["id"] == body["id"])
        self.assertEqual((wf["trigger_type"], wf["trigger_cron"], wf["schedule_text"]), ("schedule", "0 4 * * 0", "Every Sunday at 04:00"))
        self.assertEqual([n["id"] for n in wf["graph"]["nodes"]], ["t", "a"])
        self.assertEqual(wf["steps"][0]["command"], "uptime")
        bad = self.graph()
        bad["edges"].append({"from": "a", "to": "a", "kind": "fail"})
        self.assertEqual(request("POST", "/api/workflows", {"name": "bad", "graph": bad})[0], 400)
        request("DELETE", f"/api/workflows/{body['id']}")

    def test_run_blocked_by_host_key_is_an_event(self):
        dev = add_device("auto-nokey", "192.0.2.211")
        g = self.graph()
        g["nodes"][1]["device_ids"] = [dev]
        _, body, _ = request("POST", "/api/workflows", {"name": "needs-key", "graph": g})
        status, res, _ = request("POST", f"/api/workflows/{body['id']}/run")
        self.assertEqual(status, 409, res)
        self.assertIn("host key is not approved", res["error"])
        events = [e for e in database.list_events(dev, limit=20) if e["event_type"] == "action"]
        self.assertTrue(any("needs-key" in e["message"] for e in events), events)
        self.assertEqual(database.list_workflow_runs(body["id"]), [])        # nothing started
        request("DELETE", f"/api/workflows/{body['id']}")

    def test_once_runs_then_becomes_manual(self):
        fields = server.workflow_fields("once-wf", "", workflows.parse_graph(self.graph(
            {"kind": "once", "date": "2030-01-01", "time": "03:00"}), {self.dev}, {self.cred}), True)
        wid = database.save_workflow(None, fields)
        database.approve_host_key(self.dev, "ssh-ed25519", "AAAA", "SHA256:x")
        sched = server.PollScheduler.__new__(server.PollScheduler)
        with mock.patch.object(workflows.MANAGER, "start") as start:
            sched._due_workflows(fields["run_at"] - 60)
            start.assert_not_called()                                         # not due yet
            sched._due_workflows(fields["run_at"] + 120)
            start.assert_called_once()
            sched._due_workflows(fields["run_at"] + 180)
            start.assert_called_once()                                        # one-off: never twice
        wf = server.workflow_view(database.get_workflow(wid))
        self.assertEqual((wf["trigger_type"], wf["schedule"].get("done")), ("manual", True))
        self.assertEqual(wf["schedule_text"], "Once on 2030-01-01 at 03:00 (done)")
        database.delete_workflow(wid)

    def test_missed_once_is_logged_not_run(self):
        fields = server.workflow_fields("missed-wf", "", workflows.parse_graph(self.graph(
            {"kind": "once", "date": "2030-01-01", "time": "03:00"}), {self.dev}, {self.cred}), True)
        wid = database.save_workflow(None, fields)
        sched = server.PollScheduler.__new__(server.PollScheduler)
        with mock.patch.object(workflows.MANAGER, "start") as start:
            sched._due_workflows(fields["run_at"] + 2 * schedule.ONCE_GRACE_SECONDS)
            start.assert_not_called()
        self.assertTrue(any("missed-wf" in e["message"] and "missed" in e["message"]
                            for e in database.list_events(None, limit=20)))
        self.assertEqual(database.get_workflow(wid)["trigger_type"], "manual")
        database.delete_workflow(wid)

    @unittest.skipUnless(ssh_runner.keygen_available(), "ssh-keygen not installed")
    def test_generated_key_credential(self):
        status, body, _ = request("POST", "/api/credentials", {"name": "gen-key", "cred_type": "ssh_key", "username": "root",
                                                                "generate": True})
        self.assertEqual(status, 201, body)
        self.assertTrue(body["public_key"].startswith("ssh-ed25519 "))
        listed = next(c for c in request("GET", "/api/credentials")[1]["credentials"] if c["id"] == body["id"])
        self.assertEqual(listed["public_key"], body["public_key"])
        self.assertTrue(listed["public_fingerprint"].startswith("SHA256:"))
        secret = database.get_credential_secret(body["id"])
        self.assertIn("OPENSSH PRIVATE KEY", secret["secret"])
        self.assertNotIn("PRIVATE KEY", str(request("GET", "/api/credentials")[1]))

    def test_pasted_key_passphrase_is_encrypted_and_hidden(self):
        if not ssh_runner.keygen_available():
            self.skipTest("ssh-keygen not installed")
        private, public = ssh_runner.generate_keypair("t")
        status, body, _ = request("POST", "/api/credentials", {"name": "pasted-key", "cred_type": "ssh_key", "username": "u",
                                                                "secret": private, "passphrase": "Phrase-Not-Shown-4z"})
        self.assertEqual(status, 201, body)
        self.assertEqual(body["public_key"], " ".join(public.split()[:2]))
        listed = request("GET", "/api/credentials")[1]
        self.assertNotIn("Phrase-Not-Shown-4z", str(listed))
        self.assertTrue(next(c for c in listed["credentials"] if c["id"] == body["id"])["has_passphrase"])
        self.assertEqual(database.get_credential_secret(body["id"])["passphrase"], "Phrase-Not-Shown-4z")
        with database.get_connection() as conn:
            raw = conn.execute("SELECT passphrase_encrypted FROM credentials WHERE id = ?;", (body["id"],)).fetchone()[0]
        self.assertTrue(raw.startswith("enc1:"))


class CredentialTestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("cred-test", "192.0.2.215")
        cls.cred = request("POST", "/api/credentials", {"name": "ct-cred", "cred_type": "password", "username": "root",
                                                         "secret": "pw-test-secret"})[1]["id"]

    def test_host_key_first_then_login(self):
        status, body, _ = request("POST", f"/api/credentials/{self.cred}/test", {"device_id": self.dev})
        self.assertEqual((status, body["ok"], body["need_hostkey"]), (200, False, True))
        database.approve_host_key(self.dev, "ssh-ed25519", "AAAA", "SHA256:x")
        calls = []
        ok = {"status": "completed", "exit_code": 0, "stdout": "", "stderr": "", "duration": 0.2}
        with mock.patch.object(server.ssh_runner, "run_command", side_effect=lambda *a, **k: calls.append(a) or ok):
            status, body, _ = request("POST", f"/api/credentials/{self.cred}/test", {"device_id": self.dev, "ssh_port": 2222})
        self.assertEqual((status, body["ok"]), (200, True))
        self.assertEqual((calls[0][0], calls[0][1], calls[0][3]), ("192.0.2.215", 2222, "true"))   # only `true` runs
        bad = {"status": "error", "exit_code": 255, "stdout": "", "stderr": "Permission denied (password).", "duration": 0.2}
        with mock.patch.object(server.ssh_runner, "run_command", return_value=bad):
            body = request("POST", f"/api/credentials/{self.cred}/test", {"device_id": self.dev})[1]
        self.assertFalse(body["ok"])
        self.assertIn("Permission denied", body["message"])
        self.assertNotIn("pw-test-secret", repr(body))
        self.assertEqual(request("POST", "/api/credentials/99999/test", {"device_id": self.dev})[0], 404)

    def user(self, name, permissions):
        from tests.helpers import session_cookie
        status, res, _ = request("POST", "/api/users", {"username": name, "password": "credential test passphrase",
                                                        "role": "custom", "permissions": permissions})
        self.assertEqual(status, 201, res)
        _, _, headers = request("POST", "/api/auth/login", {"username": name, "password": "credential test passphrase"},
                                session=False)
        self.addCleanup(database.delete_user, name)
        return {"Cookie": f"{server.auth.SESSION_COOKIE}={session_cookie(headers)}"}

    def test_credential_test_password_needs_manage(self):
        who = self.user("ct-edit-use", ["automation.edit", "credentials.use"])
        with mock.patch.object(server.ssh_runner, "run_command") as ssh, \
                mock.patch.object(server.database, "get_credential_secret", wraps=database.get_credential_secret) as secret:
            status, res, _ = request("POST", f"/api/credentials/{self.cred}/test", {"device_id": self.dev},
                                     headers=who, session=False)
        self.assertEqual(status, 403, res)
        self.assertIn("Manage credentials", res["error"])
        ssh.assert_not_called()
        secret.assert_not_called()                                    # refused before the secret is decrypted

    def test_credential_test_needs_use(self):
        who = self.user("ct-manage-only", ["credentials.manage"])
        with server.auth.SESSIONS.lock:
            for sess in server.auth.SESSIONS.sessions.values():
                if sess["username"] == "ct-manage-only":
                    sess["tier2_until"] = sess["tier3_until"] = 0
        with mock.patch.object(server.ssh_runner, "run_command") as ssh:
            status, res, _ = request("POST", f"/api/credentials/{self.cred}/test", {"device_id": self.dev},
                                     headers=who, session=False)
        self.assertEqual(status, 403, res)
        self.assertNotEqual(res.get("auth"), "confirm")              # refused before any password prompt
        ssh.assert_not_called()


class EventTriggerTests(unittest.TestCase):
    """ "When something happens": validation, plain words, and when a run starts."""

    def test_parse_and_describe(self):
        s = schedule.parse({"kind": "event", "when": {"type": "metric", "device_id": 3, "metric": "cpu_usage_pct",
                                                      "op": "above", "value": 90, "for_minutes": 10}})
        self.assertEqual((s["cooldown_minutes"], schedule.to_trigger(s)), (30, ("event", None, None)))
        self.assertEqual(workflows.event_text(s, {3: "nas-02"}), "When nas-02 cpu_usage_pct is above 90 for 10 min")
        p = schedule.parse({"kind": "event", "when": {"type": "problem", "device_id": 3, "min_severity": "critical"}})
        self.assertEqual(workflows.event_text(p, {}), "When device #3 has a problem (critical or worse)")
        for bad in ({"type": "metric", "device_id": 3, "metric": "x y", "op": "above", "value": 1},
                    {"type": "metric", "device_id": 3, "metric": "cpu", "op": "near", "value": 1},
                    {"type": "offline", "device_id": 3, "for_minutes": 5000}, {"type": "boom", "device_id": 3},
                    {"type": "offline"}):
            with self.assertRaises(schedule.ScheduleError, msg=bad):
                schedule.parse({"kind": "event", "when": bad})
        with self.assertRaisesRegex(workflows.WorkflowError, "does not exist"):
            workflows.parse_graph({"nodes": [{"id": "t", "type": "trigger", "x": 0, "y": 0, "schedule": {"kind": "event", "when": {"type": "offline", "device_id": 99}}},
                                             {"id": "a", "type": "wait", "seconds": 1, "x": 0, "y": 0}],
                                   "edges": [{"from": "t", "to": "a", "kind": "ok"}]}, {1}, set())

    def watch(self, when, device, metrics=None, problems=None, steps=()):
        """Runs the watcher over a sequence of (time, device state) steps; returns the times it fired."""
        wf = {"id": 1, "is_active": True, "trigger_type": "event", "name": "w",
              "schedule": {"kind": "event", "when": dict(when, device_id=1), "cooldown_minutes": 30}}
        w = workflows.TriggerWatcher()
        fired = []
        for t, state in steps:
            dev = dict(device, id=1, hostname="gw", profile_id="unifi_gateway", **state.get("device", {}))
            with mock.patch.object(workflows.database, "list_devices", return_value=[dev]), \
                    mock.patch.object(workflows.database, "list_active_problems", return_value=state.get("problems", problems or [])), \
                    mock.patch.object(workflows.database, "get_latest_metrics",
                                      return_value=[{"metric_key": k, "value": v} for k, v in state.get("metrics", metrics or {}).items()]):
                w.evaluate(t, lambda wf_, why: fired.append((t, why)), [wf])
        return fired

    def test_metric_must_hold_then_fires_once(self):
        hot, cool = {"metrics": {"cpu_usage_pct": 97.0}}, {"metrics": {"cpu_usage_pct": 20.0}}
        fired = self.watch({"type": "metric", "metric": "cpu_usage_pct", "op": "above", "value": 90, "for_minutes": 10},
                           {"status": "online"}, steps=[(0, hot), (300, hot), (600, hot), (900, hot), (1000, cool),
                                                       (1100, hot), (1800, hot), (4000, hot)])
        # 600: held 10 min. 1800: held again but inside the cooldown. 4000: cooled down.
        self.assertEqual([t for t, _ in fired], [600, 4000])
        self.assertIn("cpu_usage_pct 97 above 90", fired[0][1])

    def test_cooldown_and_refire_after_clearing(self):
        hot, cool = {"metrics": {"cpu_usage_pct": 97.0}}, {"metrics": {"cpu_usage_pct": 20.0}}
        when = {"type": "metric", "metric": "cpu_usage_pct", "op": "above", "value": 90}
        fired = self.watch(when, {"status": "online"}, steps=[(0, hot), (60, cool), (120, hot), (3000, cool), (3100, hot)])
        self.assertEqual([t for t, _ in fired], [0, 3100])       # 120 is inside the 30 min cooldown

    def test_online_needs_a_seen_change(self):
        up, down = {"device": {"status": "online"}}, {"device": {"status": "offline"}}
        fired = self.watch({"type": "online"}, {"status": "online"}, steps=[(0, up), (60, up), (120, down), (180, up)])
        self.assertEqual([t for t, _ in fired], [180])

    def test_snmp_down_watch_and_problem(self):
        fired = self.watch({"type": "snmp_down", "for_minutes": 0}, {"status": "online"},
                           steps=[(0, {"device": {"snmp_status": "ok"}}), (60, {"device": {"snmp_status": "no_response"}})])
        self.assertEqual([t for t, _ in fired], [60])
        prob = [{"device_id": 1, "problem_key": "watch:service:sshd", "severity": "warning", "message": "sshd stopped"}]
        self.assertEqual(len(self.watch({"type": "watch", "name": "SSHD"}, {"status": "online"}, steps=[(0, {"problems": prob})])), 1)
        self.assertEqual(self.watch({"type": "watch", "name": "nginx"}, {"status": "online"}, steps=[(0, {"problems": prob})]), [])
        self.assertEqual(self.watch({"type": "problem", "min_severity": "critical"}, {"status": "online"}, steps=[(0, {"problems": prob})]), [])
        self.assertEqual(len(self.watch({"type": "problem", "min_severity": "warning"}, {"status": "online"}, steps=[(0, {"problems": prob})])), 1)


if __name__ == "__main__":
    unittest.main()
