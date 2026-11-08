"""Workflow validation, step execution order, failure policies, cancel, and the workflow API."""

import itertools
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import auth
import database
import workflows


class StepValidationTests(unittest.TestCase):
    DEVICES = {1, 2}
    CREDS = {7}

    def parse(self, steps):
        return workflows.parse_steps(steps, self.DEVICES, self.CREDS)

    def test_normalises_and_keeps_host_order(self):
        steps = self.parse([{"type": "command", "command": " reboot ", "device_ids": [2, 1, 2], "credential_id": 7, "any_exit": True},
                            {"type": "wait", "seconds": 5},
                            {"type": "wait_ping", "device_id": 2, "state": "down", "timeout_s": 120, "on_failure": "retry", "retries": 3}])
        self.assertEqual(steps[0]["device_ids"], [2, 1])          # restart order as entered, duplicates dropped
        self.assertEqual(steps[0]["command"], "reboot")
        self.assertTrue(steps[0]["any_exit"])
        self.assertEqual((steps[2]["state"], steps[2]["retries"]), ("down", 3))

    def test_rejects_bad_steps(self):
        bad = [[], [{"type": "shell"}], [{"type": "wait", "seconds": 0}],
               [{"type": "command", "command": "x", "device_ids": [9], "credential_id": 7}],
               [{"type": "command", "command": "x", "device_ids": [1], "credential_id": 8}],
               [{"type": "command", "command": "", "device_ids": [1], "credential_id": 7}],
               [{"type": "wait_ping", "device_id": 1, "state": "sideways"}],
               [{"type": "wait", "seconds": 5, "on_failure": "explode"}],
               [{"type": "wait", "seconds": True}]]
        for steps in bad:
            with self.assertRaises(workflows.WorkflowError, msg=steps):
                self.parse(steps)
        with self.assertRaisesRegex(workflows.WorkflowError, "Step 2"):
            self.parse([{"type": "wait", "seconds": 1}, {"type": "wait", "seconds": -1}])


def node(nid, kind="wait", **kw):
    base = {"id": nid, "type": kind, "x": 0, "y": 0}
    if kind == "wait":
        base["seconds"] = 1
    if kind == "trigger":
        base["schedule"] = {"kind": "manual"}
    base.update(kw)
    return base


def edge(a, b, kind="ok"):
    return {"from": a, "to": b, "kind": kind}


class GraphValidationTests(unittest.TestCase):
    def parse(self, nodes, edges):
        return workflows.parse_graph({"nodes": nodes, "edges": edges}, {1, 2}, {7})

    def test_valid_graph_and_reading_order(self):
        g = self.parse([node("t", "trigger"), node("a"), node("b"), node("c", label="cleanup")],
                       [edge("t", "a"), edge("a", "b"), edge("a", "c", "fail")])
        self.assertEqual([n["id"] for n in workflows.step_order(g)], ["a", "b", "c"])
        self.assertEqual(workflows.graph_trigger(g)["schedule"], {"kind": "manual"})

    def test_rejects_bad_graphs(self):
        t = node("t", "trigger")
        cases = {
            "trigger": ([node("a")], []),
            "one trigger": ([t, node("t2", "trigger")], []),
            "itself": ([t, node("a")], [edge("t", "a"), edge("a", "a")]),
            "loop": ([t, node("a"), node("b")], [edge("t", "a"), edge("a", "b"), edge("b", "a", "fail")]),
            "two success": ([t, node("a"), node("b"), node("c")], [edge("t", "a"), edge("a", "b"), edge("a", "c")]),
            "Not connected": ([t, node("a"), node("b")], [edge("t", "a")]),
            "failure output": ([t, node("a")], [edge("t", "a", "fail")]),
            "does not exist": ([t, node("a")], [edge("t", "zz")]),
            "at least one step": ([t], []),
            "repeated id": ([t, node("a"), node("a")], []),
            "Schedule": ([dict(t, schedule={"kind": "daily", "time": "25:00"}), node("a")], [edge("t", "a")]),
        }
        for message, (nodes, edges) in cases.items():
            with self.assertRaisesRegex(workflows.WorkflowError, message, msg=message):
                self.parse(nodes, edges)

    def test_old_steps_convert_to_a_chain(self):
        steps = workflows.parse_steps([{"type": "wait", "seconds": 1, "on_failure": "continue"},
                                       {"type": "wait", "seconds": 2, "on_failure": "retry", "retries": 3}], set(), set())
        g = workflows.steps_to_graph(steps)
        self.assertEqual([(e["from"], e["to"], e["kind"]) for e in g["edges"]],
                         [("trigger", "n1", "ok"), ("n1", "n2", "ok"), ("n1", "n2", "fail")])
        self.assertEqual(g["nodes"][2]["retries"], 3)
        self.assertEqual(workflows.parse_graph(g, set(), set())["edges"], g["edges"])     # round trip


class RunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.a = add_device("wf-a", "192.0.2.81")
        cls.b = add_device("wf-b", "192.0.2.82")
        status, body, _ = request("POST", "/api/credentials", {"name": "wf-cred", "cred_type": "password", "username": "root", "secret": "pw-wf"})
        cls.cred = body["id"]
        for d in (cls.a, cls.b):
            database.approve_host_key(d, "ssh-ed25519", "AAAA", "SHA256:x")

    def run_wf(self, steps, ssh=None, ping=None, graph=None):
        fields = {"name": f"t{time.time()}", "description": "", "steps": steps,
                  "trigger_type": "manual", "trigger_cron": None, "is_active": True}
        if graph:
            fields.update(graph=graph, steps=workflows.step_order(graph))
        wid = database.save_workflow(None, fields)
        wf = database.get_workflow(wid)
        run_id = database.start_workflow_run(wid, "test")
        calls = []

        def fake_ssh(ip, port, cred, command, keys, timeout):
            calls.append(("ssh", ip, command))
            return (ssh or {}).get(ip, {"status": "completed", "exit_code": 0, "stdout": "ok", "stderr": "", "duration": 0.1})

        pings = iter(ping or [])

        def fake_ping(ip, timeout):
            calls.append(("ping", ip))
            return next(pings), 1.0

        with mock.patch.object(workflows.ssh_runner, "run_command", side_effect=fake_ssh), \
                mock.patch.object(workflows.poller, "ping_host", side_effect=fake_ping), \
                mock.patch.object(workflows, "POLL_SECONDS", 0):
            status = workflows.WorkflowRun(wf, run_id, "test").run()
        return status, calls, database.get_workflow_run(run_id)

    def test_restart_sequence(self):
        steps = workflows.parse_steps([
            {"type": "command", "command": "reboot", "device_ids": [self.b], "credential_id": self.cred, "any_exit": True},
            {"type": "wait_ping", "device_id": self.b, "state": "down", "timeout_s": 30},
            {"type": "wait_ping", "device_id": self.b, "state": "up", "timeout_s": 30},
            {"type": "command", "command": "reboot", "device_ids": [self.a], "credential_id": self.cred, "any_exit": True},
        ], {self.a, self.b}, {self.cred})
        status, calls, run = self.run_wf(steps, ping=[True, False, False, True, True])
        self.assertEqual(status, "success")
        # Down: still up once, then down. Up: down, then two replies in a row.
        self.assertEqual(calls, [("ssh", "192.0.2.82", "reboot"), ("ping", "192.0.2.82"), ("ping", "192.0.2.82"),
                                 ("ping", "192.0.2.82"), ("ping", "192.0.2.82"), ("ping", "192.0.2.82"),
                                 ("ssh", "192.0.2.81", "reboot")])
        self.assertEqual(run["status"], "success")
        self.assertEqual([e["status"] for e in run["log"]], ["ok", "ok", "ok", "ok"])
        self.assertIsNotNone(run["finished_at"])
        self.assertNotIn("pw-wf", repr(run))

    def test_failure_policies(self):
        fail = {"192.0.2.81": {"status": "completed", "exit_code": 1, "stdout": "", "stderr": "nope", "duration": 0.1}}
        base = {"type": "command", "command": "x", "device_ids": [self.a], "credential_id": self.cred}
        nxt = {"type": "command", "command": "after", "device_ids": [self.b], "credential_id": self.cred}
        ids, creds = {self.a, self.b}, {self.cred}
        status, calls, _ = self.run_wf(workflows.parse_steps([base, nxt], ids, creds), ssh=fail)
        self.assertEqual(status, "failed")
        self.assertNotIn(("ssh", "192.0.2.82", "after"), calls)          # stop: later steps skipped
        status, calls, _ = self.run_wf(workflows.parse_steps([dict(base, on_failure="continue"), nxt], ids, creds), ssh=fail)
        self.assertEqual(status, "partial")
        self.assertIn(("ssh", "192.0.2.82", "after"), calls)
        status, calls, run = self.run_wf(workflows.parse_steps([dict(base, on_failure="retry", retries=2)], ids, creds), ssh=fail)
        self.assertEqual(calls.count(("ssh", "192.0.2.81", "x")), 3)       # first try plus 2 retries
        self.assertEqual(status, "failed")
        self.assertIn("Exit 1 (expected 0)", run["log"][0]["detail"])

    def test_graph_failure_branch(self):
        fail = {"192.0.2.81": {"status": "completed", "exit_code": 1, "stdout": "", "stderr": "nope", "duration": 0.1}}
        cmd = {"type": "command", "credential_id": self.cred}
        g = workflows.parse_graph({"nodes": [
            node("t", "trigger"),
            node("a", **cmd, command="update", device_ids=[self.a]),
            node("ok", **cmd, command="reboot", device_ids=[self.a]),
            node("bad", **cmd, command="report", device_ids=[self.b]),
        ], "edges": [edge("t", "a"), edge("a", "ok"), edge("a", "bad", "fail")]}, {self.a, self.b}, {self.cred})
        status, calls, run = self.run_wf(None, ssh=fail, graph=g)
        self.assertEqual(status, "partial")                                  # failure handled by its branch
        self.assertEqual(calls, [("ssh", "192.0.2.81", "update"), ("ssh", "192.0.2.82", "report")])
        self.assertEqual([(e["node"], e["status"], e["host_id"]) for e in run["log"]],
                         [("a", "failed", self.a), ("bad", "ok", self.b)])
        status, calls, _ = self.run_wf(None, graph=g)
        self.assertEqual((status, [c[2] for c in calls]), ("success", ["update", "reboot"]))

    def test_failed_step_is_a_problem_on_its_host(self):
        import server
        fail = {"192.0.2.81": {"status": "completed", "exit_code": 2, "stdout": "", "stderr": "", "duration": 0.1}}
        steps = workflows.parse_steps([{"type": "command", "command": "x", "device_ids": [self.a], "credential_id": self.cred,
                                        "label": "Update packages"}], {self.a}, {self.cred})
        self.run_wf(steps, ssh=fail)
        found = [p for p in server.evaluate_problems() if p["key"].startswith("workflow:")]
        self.assertTrue(any(p["device_id"] == self.a and "Update packages" in p["message"] for p in found), found)
        self.assertFalse(any(p["device_id"] == self.b for p in found))

    def test_wait_ping_timeout(self):
        steps = workflows.parse_steps([{"type": "wait_ping", "device_id": self.a, "state": "up", "timeout_s": 10}], {self.a}, set())
        clock = itertools.count(1000.0, 2.0)   # every clock read advances 2 s
        with mock.patch.object(workflows.time, "time", side_effect=lambda: next(clock)):
            status, calls, run = self.run_wf(steps, ping=[False] * 50)
        self.assertEqual(status, "failed")
        self.assertIn("Gave up after 10 s", run["log"][0]["detail"])

    DROP = {"status": "error", "exit_code": 255, "stdout": "", "stderr": "Connection to 192.0.2.81 closed by remote host.", "duration": 0.5}
    REFUSED = {"status": "error", "exit_code": 255, "stdout": "", "stderr": "ssh: connect to host 192.0.2.81 port 22: Connection refused", "duration": 0.1}

    def test_restart_that_drops_the_session_carries_on(self):
        """A UniFi gateway case: reboot cuts SSH; the waits must still run and the job succeed."""
        ids, creds = {self.a}, {self.cred}
        steps = workflows.parse_steps([
            {"type": "command", "command": "reboot", "device_ids": [self.a], "credential_id": self.cred},
            {"type": "wait_ping", "device_id": self.a, "state": "down", "timeout_s": 30},
            {"type": "wait_ping", "device_id": self.a, "state": "up", "timeout_s": 30},
        ], ids, creds)
        # Already down when the wait starts (a fast restart) counts as down.
        status, calls, run = self.run_wf(steps, ssh={"192.0.2.81": self.DROP}, ping=[False, False, True, True])
        self.assertEqual(status, "success", run["log"])
        self.assertIn("dropped, as a restart does", run["log"][0]["detail"])
        self.assertEqual([e["status"] for e in run["log"]], ["ok", "ok", "ok"])
        # Marked explicitly: a drop is fine even without a wait step after it.
        steps = workflows.parse_steps([{"type": "command", "command": "/usr/sbin/do-it", "device_ids": [self.a],
                                        "credential_id": self.cred, "expect_disconnect": True}], ids, creds)
        self.assertEqual(self.run_wf(steps, ssh={"192.0.2.81": self.DROP})[0], "success")
        # Refused means the command never ran: still a failure, with a hint.
        status, _, run = self.run_wf(steps, ssh={"192.0.2.81": self.REFUSED})
        self.assertEqual(status, "failed")
        self.assertIn("refused SSH", run["log"][0]["detail"])
        # Not a restart and not marked: a dropped session is a failure as before.
        steps = workflows.parse_steps([{"type": "command", "command": "apt-get update", "device_ids": [self.a],
                                        "credential_id": self.cred}], ids, creds)
        self.assertEqual(self.run_wf(steps, ssh={"192.0.2.81": self.DROP})[0], "failed")

    def test_wait_up_needs_two_replies_and_says_why_it_gave_up(self):
        steps = workflows.parse_steps([{"type": "wait_ping", "device_id": self.a, "state": "up", "timeout_s": 10}], {self.a}, set())
        clock = itertools.count(1000.0, 2.0)
        with mock.patch.object(workflows.time, "time", side_effect=lambda: next(clock)):
            status, _, run = self.run_wf(steps, ping=[True, False] * 25)       # flapping: never two in a row
        self.assertEqual(status, "failed")
        self.assertIn("was not answering", run["log"][0]["detail"])
        self.assertIn("Raise the step's timeout", run["log"][0]["detail"])

    def test_telegram_step(self):
        steps = workflows.parse_steps([{"type": "command", "command": "uptime", "device_ids": [self.a], "credential_id": self.cred},
                                       {"type": "telegram", "text": "{workflow} done:\n{steps}"}], {self.a}, {self.cred})
        sent = []
        with mock.patch.object(workflows, "send_telegram", side_effect=lambda text: sent.append(text) or 1):
            status, _, run = self.run_wf(steps)
        self.assertEqual(status, "success")
        self.assertIn("done:", sent[0])
        self.assertIn("✅ Run 'uptime' on wf-a", sent[0])
        with mock.patch.object(workflows, "send_telegram", return_value=None):
            status, _, run = self.run_wf(steps)
        self.assertEqual(status, "failed")
        self.assertIn("Telegram is off", run["log"][-1]["detail"])
        with self.assertRaises(workflows.WorkflowError):
            workflows.parse_steps([{"type": "telegram", "text": " "}], set(), set())

    def test_quiet_message_and_suppress_notifications(self):
        import maintenance
        # Send quietly: the message goes without a sound.
        steps = workflows.parse_steps([{"type": "telegram", "text": "hi", "silent": True}], set(), set())
        sent = []
        with mock.patch.object(workflows, "send_telegram", side_effect=lambda text, silent=False: sent.append((text, silent)) or 1):
            self.assertEqual(self.run_wf(steps)[0], "success")
        self.assertEqual(sent, [("hi", True)])
        # Suppress notifications for the workflow's hosts until the run ends, plus 5 minutes.
        steps = workflows.parse_steps([
            {"type": "mute", "scope": "hosts", "grace_min": 5},
            {"type": "command", "command": "uptime", "device_ids": [self.a], "credential_id": self.cred},
        ], {self.a}, {self.cred})
        seen = {}
        real = workflows.WorkflowRun._execute

        def spy(run, step, host):
            if step["type"] == "command":                  # while the command runs, the host is in a window
                seen["during"] = maintenance.active_for(run.devices[self.a])
            return real(run, step, host)
        with mock.patch.object(workflows.WorkflowRun, "_execute", spy):
            status, _, run = self.run_wf(steps)
        self.assertEqual(status, "success", run["log"])
        self.assertIsNotNone(seen["during"])
        self.assertIn("Notifications suppressed for this workflow's hosts until the run ends", run["log"][0]["detail"])
        w = next(x for x in maintenance.windows() if x["id"] == seen["during"]["id"])
        self.assertLess(w["end"] - time.time(), 5 * 60 + 5)              # ends 5 minutes after the run
        self.assertGreater(w["end"] - time.time(), 4 * 60)
        maintenance.end(w["id"])
        # A fixed time, a tag; Notifications back on ends it early.
        steps = workflows.parse_steps([{"type": "mute", "scope": "tag", "target": "rack", "until_end": False, "minutes": 30},
                                       {"type": "unmute"}], set(), set())
        status, _, run = self.run_wf(steps)
        self.assertEqual(status, "success")
        self.assertIn("Nothing was suppressed by this run", run["log"][1]["detail"])   # fixed-time windows stay
        tagged = [x for x in maintenance.windows() if x["scope"] == "tag" and x["target"] == "rack" and x["state"] == "active"]
        self.assertTrue(tagged)
        for x in tagged:
            maintenance.end(x["id"])
        for bad in ({"scope": "nope"}, {"scope": "devices"}, {"scope": "group"}, {"scope": "hosts", "minutes": 0}):
            with self.assertRaises(workflows.WorkflowError, msg=bad):
                workflows.parse_steps([dict({"type": "mute"}, **bad)], set(), set())
        self.assertEqual(workflows.describe({"type": "mute", "scope": "devices", "device_ids": [self.a]}, {self.a: "wf-a"}),
                         "Suppress notifications for wf-a")

    def test_start_hook(self):
        seen = []
        steps = workflows.parse_steps([{"type": "wait", "seconds": 1}], set(), set())
        with mock.patch.object(workflows, "on_started", side_effect=lambda wf, trig: seen.append(trig)):
            self.run_wf(steps)
        self.assertEqual(seen, ["test"])

    def test_cancel(self):
        steps = workflows.parse_steps([{"type": "wait", "seconds": 30}, {"type": "wait", "seconds": 1}], set(), set())
        wid = database.save_workflow(None, {"name": "cancel-me", "description": "", "steps": steps, "trigger_type": "manual",
                                            "trigger_cron": None, "is_active": True})
        run_id = workflows.MANAGER.start(database.get_workflow(wid), "test")
        with self.assertRaises(workflows.WorkflowError):
            workflows.MANAGER.start(database.get_workflow(wid), "test")   # one run per workflow
        time.sleep(0.3)
        self.assertTrue(workflows.MANAGER.cancel(run_id))
        for _ in range(50):
            if wid not in workflows.MANAGER.running():
                break
            time.sleep(0.1)
        self.assertEqual(database.get_workflow_run(run_id)["status"], "cancelled")


class WorkflowApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("wf-api", "192.0.2.83")

    def test_crud_and_confirmation(self):
        body = {"name": "Nightly wait", "steps": [{"type": "wait", "seconds": 1}]}
        status, res, _ = request("POST", "/api/workflows", body)
        self.assertEqual(status, 201, res)
        wid = res["id"]
        self.assertEqual(request("POST", "/api/workflows", {"name": "x", "steps": [{"type": "wait", "seconds": 0}]})[0], 400)
        self.assertEqual(request("POST", "/api/workflows", dict(body, trigger_type="schedule", trigger_cron="bad"))[0], 400)
        self.assertEqual(request("PUT", f"/api/workflows/{wid}", dict(body, name="Renamed"))[0], 200)
        listed = {w["id"]: w for w in request("GET", "/api/workflows")[1]["workflows"]}
        self.assertEqual(listed[wid]["name"], "Renamed")
        # Running needs a recent password confirmation.
        with auth.SESSIONS.lock:
            for s in auth.SESSIONS.sessions.values():
                s["tier2_until"] = s["tier3_until"] = 0
        status, res, _ = request("POST", f"/api/workflows/{wid}/run")
        self.assertEqual((status, res.get("auth")), (403, "confirm"))
        from tests.helpers import TEST_PASSWORD
        # Tier 3 also covers tier 2, so later suites that add credentials are not left needing a confirmation.
        request("POST", "/api/auth/confirm", {"password": TEST_PASSWORD, "tier": 3})
        status, res, _ = request("POST", f"/api/workflows/{wid}/run")
        self.assertEqual(status, 200, res)
        for _ in range(50):
            run = request("GET", f"/api/workflow-runs/{res['run_id']}")[1]
            if run["status"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(run["status"], "success")
        self.assertEqual(len(request("GET", f"/api/workflows/runs?workflow_id={wid}")[1]["runs"]), 1)
        self.assertEqual(request("DELETE", f"/api/workflows/{wid}")[0], 200)
        self.assertEqual(request("GET", f"/api/workflow-runs/{res['run_id']}")[0], 404)


def user_session(name, role="custom", permissions=None, scope=None):
    """A user created by the test administrator, logged in: the session cookie header."""
    from tests.helpers import session_cookie
    body = {"username": name, "password": "workflow scope passphrase", "role": role}
    if permissions is not None:
        body["permissions"] = permissions
    if scope is not None:
        body["device_scope"] = scope
    status, res, _ = request("POST", "/api/users", body)
    assert status == 201, res
    _, _, headers = request("POST", "/api/auth/login", {"username": name, "password": "workflow scope passphrase"}, session=False)
    return {"Cookie": f"{auth.SESSION_COOKIE}={session_cookie(headers)}"}


class WorkflowScopeTests(unittest.TestCase):
    """Run logs and definitions follow Run or Edit workflows and the device access; saving checks
    the saver's rights, and a scheduled run checks them again."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.inside = add_device("wfs-in", "203.0.113.241")
        cls.outside = add_device("wfs-out", "203.0.113.242")
        cls.pw = request("POST", "/api/credentials", {"name": "wfs-pw", "cred_type": "password", "username": "root",
                                                       "secret": "pw-wfs"})[1]["id"]
        status, res, _ = request("POST", "/api/workflows", {"name": "Outside", "steps": [
            {"type": "command", "command": "uptime", "device_ids": [cls.outside], "credential_id": cls.pw}]})
        assert status == 201, res
        cls.wf_out = res["id"]
        cls.run_out = database.start_workflow_run(cls.wf_out, "test")
        database.update_workflow_run(cls.run_out, "success", '[{"detail": "secret output"}]', time.time())
        cls.viewer = user_session("wfs-viewer", role="viewer")
        cls.scoped = user_session("wfs-op", permissions=["automation.run", "automation.edit"],
                                  scope={"all": False, "devices": [cls.inside]})

    @classmethod
    def tearDownClass(cls):
        for name in ("wfs-viewer", "wfs-op"):
            database.delete_user(name)

    def as_(self, who, method, path, body=None):
        return request(method, path, body, headers=who, session=False)

    def test_viewer_reads_no_workflows_or_logs(self):
        for path in ("/api/workflows", "/api/workflows/runs", f"/api/workflow-runs/{self.run_out}"):
            self.assertEqual(self.as_(self.viewer, "GET", path)[0], 403, path)

    def test_runs_outside_the_device_access_are_hidden(self):
        runs = self.as_(self.scoped, "GET", "/api/workflows/runs")[1]["runs"]
        self.assertNotIn(self.run_out, [r["id"] for r in runs])
        self.assertEqual(self.as_(self.scoped, "GET", f"/api/workflow-runs/{self.run_out}")[0], 404)
        self.assertEqual(self.as_(self.scoped, "POST", f"/api/workflow-runs/{self.run_out}/cancel", {})[0], 404)
        listed = [w["id"] for w in self.as_(self.scoped, "GET", "/api/workflows")[1]["workflows"]]
        self.assertNotIn(self.wf_out, listed)
        self.assertEqual(self.as_(self.scoped, "PUT", f"/api/workflows/{self.wf_out}", {"name": "x", "steps": [
            {"type": "wait", "seconds": 1}]})[0], 404)
        self.assertEqual(self.as_(self.scoped, "DELETE", f"/api/workflows/{self.wf_out}")[0], 404)
        # The administrator sees it.
        self.assertEqual(request("GET", f"/api/workflow-runs/{self.run_out}")[0], 200)

    def test_save_checks_device_access_and_password_credentials(self):
        import rbac
        self.assertEqual(rbac.route_tier("POST", "/api/workflows"), 2)
        self.assertEqual(rbac.route_tier("PUT", "/api/workflows/3"), 2)
        status, res, _ = self.as_(self.scoped, "POST", "/api/workflows", {"name": "Reach out", "steps": [
            {"type": "wait_ping", "device_id": self.outside, "state": "up"}]})
        self.assertEqual(status, 403, res)
        self.assertIn("outside the device access", res["error"])
        status, res, _ = self.as_(self.scoped, "POST", "/api/workflows", {"name": "With password", "steps": [
            {"type": "command", "command": "id", "device_ids": [self.inside], "credential_id": self.pw}]})
        self.assertEqual(status, 403, res)
        self.assertIn("Manage credentials", res["error"])
        status, res, _ = self.as_(self.scoped, "POST", "/api/workflows", {"name": "Mine", "steps": [
            {"type": "wait_ping", "device_id": self.inside, "state": "up"}]})
        self.assertEqual(status, 201, res)
        self.assertEqual(database.get_workflow(res["id"])["saved_by"], "wfs-op")
        database.delete_workflow(res["id"])

    def test_scheduled_run_checks_the_author_again(self):
        import server
        sched = server.PollScheduler.__new__(server.PollScheduler)
        user_session("wfs-author", permissions=["automation.edit"], scope={"all": False, "devices": [self.inside]})
        fields = server.parse_workflow_payload({"name": "Author check", "steps": [
            {"type": "wait_ping", "device_id": self.inside, "state": "up"}]})
        wid = database.save_workflow(None, dict(fields, saved_by="wfs-author"))
        try:
            wf = database.get_workflow(wid)
            self.assertIsNone(server.workflow_author_problem(wf))
            self.assertIsNone(server.workflow_author_problem(dict(wf, saved_by=None)))   # older rows: no author, allowed
            cases = [({"disabled": 1}, "is blocked"),
                     ({"disabled": 0, "device_scope": '{"all": false, "devices": [%d]}' % self.outside}, "outside the device access"),
                     ({"device_scope": None, "role": "viewer"}, "may no longer run or edit")]
            for change, why in cases:
                database.update_user("wfs-author", change)
                self.assertIn(why, server.workflow_author_problem(wf))
                with mock.patch.object(workflows.MANAGER, "start") as start:
                    sched._start_scheduled(wf, "schedule: test")
                    start.assert_not_called()
                run = database.get_workflow_run(database.list_workflow_runs(wid)[0]["id"])
                self.assertEqual(run["status"], "failed")
                self.assertIn(why, run["log"][0]["detail"])
            database.delete_user("wfs-author")
            self.assertIn("no longer exists", server.workflow_author_problem(wf))
        finally:
            database.delete_workflow(wid)
            database.delete_user("wfs-author")


if __name__ == "__main__":
    unittest.main()
