"""Incident and change records (incidents.py, maintenance.py history): the API, permissions and
device access, the Telegram messages, keeping changes a year and the reports that use them."""

import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, session_cookie, start_api_server

import auth
import database
import incidents
import maintenance
import notify
import rbac
import reports
import server

PASSWORD = "incident tests passphrase"


def login(name, role="custom", permissions=None, scope=None):
    body = {"username": name, "password": PASSWORD, "role": role, "permissions": permissions or []}
    if scope is not None:
        body["device_scope"] = scope
    status, res, _ = request("POST", "/api/users", body)
    assert status == 201, res
    _, _, headers = request("POST", "/api/auth/login", {"username": name, "password": PASSWORD}, session=False)
    return {"Cookie": f"{auth.SESSION_COOKIE}={session_cookie(headers)}"}


def setUpModule():
    start_api_server()


def open_problem(device_id, key="cpu", severity="critical", message="CPU usage 97% (threshold 90%)"):
    database.sync_problems([{"device_id": device_id, "key": key, "severity": severity, "message": message}], lambda k: 10 ** 9)


class IncidentModelTests(unittest.TestCase):
    def test_fields_are_checked(self):
        with self.assertRaises(incidents.IncidentError):
            incidents.clean_fields({"title": " "}, partial=False)
        with self.assertRaises(incidents.IncidentError):
            incidents.clean_fields({"title": "x", "priority": "P4"}, partial=False)
        with self.assertRaises(incidents.IncidentError):
            incidents.clean_fields({"title": "x", "status": "Closed"}, partial=False)
        with self.assertRaises(incidents.IncidentError):
            incidents.clean_action({"description": "x", "due": "2026-02-30"}, partial=False)
        with self.assertRaises(incidents.IncidentError):
            incidents.clean_action({"description": "x", "status": "Later"}, partial=False)
        f = incidents.clean_fields({"title": " Router down ", "priority": "P1"}, partial=False, now=1_800_000_000)
        self.assertEqual((f["title"], f["status"], f["started_at"]), ("Router down", "Open", 1_800_000_000))
        self.assertEqual(incidents.ref(7), "INC-0007")
        self.assertEqual([incidents.priority_for(s) for s in ("critical", "high", "warning", "info")], ["P1", "P1", "P2", "P3"])

    def test_resolve_sets_and_clears_the_time(self):
        inc = incidents.create(incidents.clean_fields({"title": "Model check"}, partial=False, now=1_800_000_000), [], "t",
                               now=1_800_000_000)
        after, changed = incidents.update(inc["id"], {"status": "Resolved"}, None, "t", now=1_800_000_600)
        self.assertEqual(after["resolved_at"], 1_800_000_600)
        self.assertIn("status", changed)
        self.assertEqual(incidents.view(after, now=1_800_000_700)["seconds"], 600)
        after, _ = incidents.update(inc["id"], {"status": "Monitoring"}, None, "t", now=1_800_000_900)
        self.assertIsNone(after["resolved_at"])
        texts = [n["text"] for n in after["notes"]]
        self.assertIn("Status Open to Resolved by t", texts)
        self.assertIn("Status Resolved to Monitoring by t", texts)
        database.delete_incident(inc["id"])

    def test_visibility_follows_device_access(self):
        inc = {"devices": [{"id": 1}, {"id": 2}]}
        self.assertTrue(incidents.visible_to(inc, True, lambda i: False))
        self.assertTrue(incidents.visible_to(inc, False, lambda i: i in (1, 2)))
        self.assertFalse(incidents.visible_to(inc, False, lambda i: i == 1))
        self.assertFalse(incidents.visible_to({"devices": []}, False, lambda i: True))

    def test_telegram_messages_are_off_by_default(self):
        self.assertIs(notify.EVENTS["incident_opened"][1], False)
        self.assertIs(notify.EVENTS["incident_resolved"][1], False)
        self.assertEqual(server.SETTINGS["notify_on_incident_opened"]["default"], "off")
        n = notify.Notifier(lambda: {"telegram_enabled": "on"})
        with mock.patch.object(notify, "queue_message") as q:
            self.assertIsNone(n.event("incident_opened", {"incident": "INC-0001", "title": "x", "priority": "P1"}))
            q.assert_not_called()
            n2 = notify.Notifier(lambda: {"telegram_enabled": "on", "notify_on_incident_opened": "on"})
            n2.event("incident_opened", {"incident": "INC-0001", "title": "Router down", "priority": "P1", "owner": "alex"})
            self.assertEqual(q.call_args[0][0], "INC-0001 opened, P1: Router down, owner alex")


class ChangeRetentionTests(unittest.TestCase):
    def setUp(self):
        self.saved = database.get_all_settings().get(maintenance.KEY) or "[]"

    def tearDown(self):
        database.set_internal_setting(maintenance.KEY, self.saved)

    def test_changes_are_kept_a_year(self):
        now = time.time()
        database.set_internal_setting(maintenance.KEY, "[]")
        old = maintenance.add("all", "", now - 20 * 86400, now - 20 * 86400 + 600, "patching", "t", now=now - 20 * 86400 - 60,
                              change_note="Firmware 2.1 on the switches")
        gone = maintenance.add("all", "", now - 400 * 86400, now - 400 * 86400 + 600, "", "t", now=now - 400 * 86400 - 60)
        maintenance.add("device", "1", now, now + 600, "", "t", now=now)            # saving moves the old ones out
        self.assertNotIn(old["id"], [w["id"] for w in maintenance.windows(now)])     # the short list keeps a week
        hist = {w["id"]: w for w in maintenance.history(now=now)}
        self.assertIn(old["id"], hist)                                                 # the history keeps a year
        self.assertTrue(hist[old["id"]]["change"])
        self.assertEqual(hist[old["id"]]["change_note"], "Firmware 2.1 on the switches")
        self.assertNotIn(gone["id"], hist)                                             # past a year it is dropped
        self.assertEqual([w["id"] for w in maintenance.history(now=now, changes_only=True)], [old["id"]])
        # Marking works on the history too, and ids are never reused.
        self.assertFalse(maintenance.set_change(old["id"], "", now=now)["change"])
        self.assertTrue(maintenance.set_change(old["id"], "Firmware", now=now)["change"])
        database.set_internal_setting(maintenance.KEY, "[]")
        self.assertGreater(maintenance.add("all", "", now, now + 60, "", "t", now=now)["id"], old["id"])


class IncidentApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.d1 = add_device("inc-in1", "203.0.113.231")
        cls.d2 = add_device("inc-in2", "203.0.113.232")
        cls.out = add_device("inc-out", "203.0.113.233")
        cls.op = login("inc-op", role="operator")
        cls.viewer = login("inc-viewer", role="viewer")
        cls.scoped = login("inc-scoped", permissions=["incidents.manage", "problems.ack"], scope={"all": False, "devices": [cls.d1, cls.d2]})

    @classmethod
    def tearDownClass(cls):
        for name in ("inc-op", "inc-viewer", "inc-scoped"):
            database.delete_user(name)
        for i in database.list_incidents():
            if any(d["id"] in (cls.d1, cls.d2, cls.out) for d in i["devices"]) or i["title"].startswith("API "):
                database.delete_incident(i["id"])
        for dev in (cls.d1, cls.d2, cls.out):
            database.delete_device(dev)

    def as_(self, who, method, path, body=None):
        return request(method, path, body, headers=who, session=False)

    def test_permission_and_roles(self):
        self.assertIn("incidents.manage", rbac.ROLES["operator"][2])
        self.assertEqual(rbac.route_permission("POST", "/api/incidents"), "incidents.manage")
        self.assertEqual(rbac.route_permission("DELETE", "/api/incidents/3"), "admin")
        status, res, _ = self.as_(self.viewer, "POST", "/api/incidents", {"title": "API viewer"})
        self.assertEqual(status, 403, res)
        status, res, _ = self.as_(self.viewer, "GET", "/api/incidents?show=all")
        self.assertEqual(status, 200, res)
        self.assertFalse(res["can_manage"])
        self.assertEqual(res["owners"], [])

    def test_create_update_notes_and_actions(self):
        status, res, _ = self.as_(self.op, "POST", "/api/incidents",
                                  {"title": "API switch loop", "priority": "P2", "devices": [self.d1], "owner": "inc-op"})
        self.assertEqual(status, 201, res)
        inc = res["incident"]
        self.assertTrue(inc["ref"].startswith("INC-"))
        path = f"/api/incidents/{inc['id']}"
        status, res, _ = self.as_(self.op, "PUT", path, {"root_cause": "A loop through a new switch", "status": "Investigating",
                                                         "devices": [self.d1, self.d2]})
        self.assertEqual(status, 200, res)
        self.assertEqual(sorted(res["changed"]), ["devices", "root_cause", "status"])
        self.assertEqual(len(res["incident"]["devices"]), 2)
        self.assertEqual(self.as_(self.op, "POST", path + "/notes", {"text": "Pulled the cable"})[0], 200)
        self.assertEqual(self.as_(self.op, "POST", path + "/notes", {"text": "  "})[0], 400)
        status, res, _ = self.as_(self.op, "POST", path + "/actions", {"description": "Turn on loop protection", "owner": "inc-op",
                                                                       "due": "2026-12-01"})
        self.assertEqual(status, 200, res)
        action = res["incident"]["actions"][0]
        self.assertEqual((action["status"], res["incident"]["open_actions"]), ("Plan", 1))
        status, res, _ = self.as_(self.op, "PUT", f"{path}/actions/{action['id']}", {"status": "Done"})
        self.assertEqual((status, res["incident"]["open_actions"]), (200, 0), res)
        self.assertEqual(self.as_(self.op, "PUT", f"{path}/actions/999999", {"status": "Done"})[0], 404)
        status, res, _ = self.as_(self.op, "PUT", path, {"status": "Resolved"})
        self.assertTrue(res["incident"]["resolved_at"])
        self.assertIn("Pulled the cable", [n["text"] for n in res["incident"]["notes"]])
        audit = [a["message"] for a in database.list_audit_logs(30)]
        self.assertTrue(any(m.startswith(f"Opened {inc['ref']}") for m in audit), audit)
        # Only an administrator deletes one.
        self.assertEqual(self.as_(self.op, "DELETE", path)[0], 403)
        self.assertEqual(request("DELETE", path)[0], 200)
        self.assertEqual(request("GET", path)[0], 404)

    def test_from_a_problem(self):
        open_problem(self.d2, "cpu")
        before = int(time.time())
        status, res, _ = self.as_(self.op, "POST", "/api/incidents", {"from_problem": {"device_id": self.d2, "problem_key": "cpu"}})
        self.assertEqual(status, 201, res)
        inc = res["incident"]
        self.assertEqual(inc["priority"], "P1")
        self.assertEqual([d["id"] for d in inc["devices"]], [self.d2])
        self.assertEqual(inc["problems"][0]["problem_key"], "cpu")
        self.assertTrue(inc["problems"][0]["open"])
        self.assertLessEqual(inc["started_at"], before + 1)
        self.assertIn("inc-in2", inc["title"])
        # The same problem again opens the incident already there.
        status, res, _ = self.as_(self.op, "POST", "/api/incidents", {"from_problem": {"device_id": self.d2, "problem_key": "cpu"}})
        self.assertEqual((status, res.get("existing"), res["incident"]["id"]), (200, True, inc["id"]))
        status, _, _ = self.as_(self.op, "POST", "/api/incidents", {"from_problem": {"device_id": self.d2, "problem_key": "nope"}})
        self.assertEqual(status, 404)
        # Linking another problem adds its device.
        open_problem(self.d1, "memory", "warning", "Memory 93%")
        status, res, _ = self.as_(self.op, "POST", f"/api/incidents/{inc['id']}/problems", {"device_id": self.d1, "problem_key": "memory"})
        self.assertEqual(status, 200, res)
        self.assertEqual(sorted(d["id"] for d in res["incident"]["devices"]), sorted([self.d1, self.d2]))
        database.sync_problems([], lambda k: 0)

    def test_device_scope(self):
        status, res, _ = self.as_(self.op, "POST", "/api/incidents", {"title": "API outside", "devices": [self.d1, self.out]})
        mixed = res["incident"]["id"]
        status, res, _ = self.as_(self.op, "POST", "/api/incidents", {"title": "API inside", "devices": [self.d1]})
        inside = res["incident"]["id"]
        status, res, _ = self.as_(self.op, "POST", "/api/incidents", {"title": "API no devices"})
        bare = res["incident"]["id"]
        listed = {i["id"] for i in self.as_(self.scoped, "GET", "/api/incidents?show=all")[1]["incidents"]}
        self.assertIn(inside, listed)
        self.assertNotIn(mixed, listed)
        self.assertNotIn(bare, listed)
        self.assertEqual(self.as_(self.scoped, "GET", f"/api/incidents/{mixed}")[0], 404)
        self.assertEqual(self.as_(self.scoped, "PUT", f"/api/incidents/{mixed}", {"status": "Resolved"})[0], 404)
        self.assertEqual(self.as_(self.scoped, "POST", f"/api/incidents/{mixed}/notes", {"text": "x"})[0], 404)
        # A scoped user names devices inside their access, at least one.
        self.assertEqual(self.as_(self.scoped, "POST", "/api/incidents", {"title": "API scoped bare"})[0], 400)
        self.assertEqual(self.as_(self.scoped, "POST", "/api/incidents", {"title": "API scoped out", "devices": [self.out]})[0], 400)
        self.assertEqual(self.as_(self.scoped, "PUT", f"/api/incidents/{inside}", {"devices": [self.d1, self.out]})[0], 400)
        self.assertEqual(self.as_(self.scoped, "POST", "/api/incidents", {"title": "API scoped in", "devices": [self.d2]})[0], 201)
        # The reports follow the same rule.
        user = rbac.User(database.get_user("inc-scoped"))
        user.bind_devices(database.device_profiles())
        choices = {c["id"] for c in reports.incident_choices(server.report_devices(user, {})[0], False)}
        self.assertIn(inside, choices)
        self.assertNotIn(mixed, choices)

    def test_change_log_route(self):
        saved = database.get_all_settings().get(maintenance.KEY) or "[]"
        try:
            now = time.time()
            status, res, _ = self.as_(self.op, "POST", "/api/maintenance", {"scope": "device", "target": str(self.d1), "minutes": 30,
                                                                             "change_note": "New disk in the NAS"})
            self.assertEqual(status, 201, res)
            self.assertTrue(res["window"]["change"])
            wid = res["window"]["id"]
            other = maintenance.add("device", str(self.out), now, now + 600, "", "admin", now=now)
            listed = self.as_(self.scoped, "GET", "/api/maintenance/history?changes=1")[1]["windows"]
            self.assertEqual([w["id"] for w in listed if w["id"] in (wid, other["id"])], [wid])
            self.assertEqual(listed[0]["covers"], "Device inc-in1")
            self.assertEqual(self.as_(self.scoped, "POST", f"/api/maintenance/{other['id']}/change", {"change_note": "x"})[0], 404)
            status, res, _ = self.as_(self.op, "POST", f"/api/maintenance/{other['id']}/change", {"change_note": "Swapped a cable"})
            self.assertEqual((status, res["window"]["change_note"]), (200, "Swapped a cable"))
            self.assertEqual(self.as_(self.viewer, "POST", f"/api/maintenance/{wid}/change", {"change_note": ""})[0], 403)
        finally:
            database.set_internal_setting(maintenance.KEY, saved)

    def test_messages_when_opened_and_resolved(self):
        with mock.patch.object(server.NOTIFIER, "event") as ev:
            status, res, _ = self.as_(self.op, "POST", "/api/incidents", {"title": "API message", "priority": "P1"})
            self.assertEqual(ev.call_args[0][0], "incident_opened")
            self.assertEqual(ev.call_args[0][1]["incident"], res["incident"]["ref"])
            self.as_(self.op, "PUT", f"/api/incidents/{res['incident']['id']}", {"status": "Resolved"})
            self.assertEqual(ev.call_args[0][0], "incident_resolved")


class IncidentReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("inc-rep", "203.0.113.235")
        now = int(time.time())
        f = incidents.clean_fields({"title": "Report NAS offline", "priority": "P1", "owner": "alex", "impact": "Backups paused",
                                    "summary": "The NAS lost power.", "root_cause": "A tripped breaker",
                                    "started_at": now - 3 * 3600}, partial=False, now=now)
        cls.inc = incidents.create(f, [(cls.dev, "inc-rep")], "t", now=now - 3 * 3600)
        incidents.add_action(cls.inc["id"], {"description": "Label the breaker", "owner": "alex", "due": "2026-12-01"})
        incidents.add_note(cls.inc["id"], "Power is back", "t", now=now - 2 * 3600)
        cls.saved = database.get_all_settings().get(maintenance.KEY) or "[]"
        maintenance.add("device", str(cls.dev), now - 3600, now + 600, "", "t", now=now - 3700, change_note="New power strip")

    @classmethod
    def tearDownClass(cls):
        database.delete_incident(cls.inc["id"])
        database.set_internal_setting(maintenance.KEY, cls.saved)
        database.delete_device(cls.dev)

    def run_report(self, spec):
        return server.run_report(reports.parse_spec(spec, True), None)

    def table(self, report, title):
        flat = [x for b in report["blocks"] for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b])]
        return next(b for b in flat if b.get("title") == title)

    def test_monthly_top_issues_are_incidents(self):
        rep = self.run_report({"template": "monthly", "period": "30d"})
        self.assertEqual([c["label"] for c in rep["columns"]], ["Issue", "Pri", "Impact", "Duration", "Owner", "Status"])
        row = next(r for r in rep["rows"] if "Report NAS offline" in r[0])
        self.assertEqual(row[1:3], ["P1", "Backups paused"])
        self.assertIn("incident", rep["summary"])

    def test_handover_lists_open_incidents_and_changes(self):
        rep = self.run_report({"template": "handover", "period": "24h"})
        tb = self.table(rep, "Open incidents")
        heads = [c["label"] for c in tb["columns"]]
        self.assertEqual(heads[:2], ["ID", "Pri"])
        self.assertIn("Report NAS offline", [r[2] for r in tb["rows"]])
        tiles = {t["label"]: t for t in rep["kpis"]}
        self.assertIn("Open incidents", tiles)
        self.assertIn("Changes today", tiles)
        self.assertGreaterEqual(int(tiles["Changes today"]["value"]), 1)

    def test_the_timeline_keeps_the_incident_among_many_events(self):
        """A busy network: 80 other events in the incident's hours. The timeline still shows the incident's own
        note and change (it used to show every nth event, which could leave them out)."""
        other = add_device("inc-busy", "203.0.113.236")
        try:
            now = int(time.time())
            for i in range(80):
                database.add_event(other, "warning", "snmp", f"Busy event {i}", timestamp=now - 3 * 3600 + 60 * i)
            rep = self.run_report({"template": "outage", "period": "7d", "focus": {"incident": self.inc["id"]}})
            timeline = next(b["chart"] for b in rep["blocks"] if b["type"] == "chart" and b["chart"]["kind"] == "timeline")
            labels = [e[1] for e in timeline["events"]]
            self.assertLessEqual(len(labels), 16)
            self.assertTrue(any("Power is back" in l for l in labels), labels)
            self.assertTrue(any("New power strip" in l for l in labels), labels)
            self.assertTrue(any("Busy event" in l for l in labels), labels)
        finally:
            database.delete_device(other)

    def test_outage_review_from_an_incident(self):
        rep = self.run_report({"template": "outage", "period": "7d", "focus": {"incident": self.inc["id"]}})
        self.assertTrue(rep["title"].endswith(incidents.ref(self.inc["id"])))
        texts = {b["title"]: b["text"] for b in [x for b in rep["blocks"] for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b])]
                 if b["type"] == "text"}
        self.assertEqual(texts["Root cause"], "A tripped breaker")
        self.assertEqual(texts["Impact"], "Backups paused")
        self.assertTrue(texts["Summary"].startswith("The NAS lost power."))
        actions = self.table(rep, "Actions")
        self.assertEqual(actions["rows"][0][1], "Label the breaker")
        timeline = next(b["chart"] for b in rep["blocks"] if b["type"] == "chart" and b["chart"]["kind"] == "timeline")
        labels = [e[1] for e in timeline["events"]]
        self.assertTrue(any("Power is back" in l for l in labels), labels)
        self.assertTrue(any("New power strip" in l for l in labels), labels)
        # Without an incident the stand-ins stay: written texts and an Actions text box.
        rep = self.run_report({"template": "outage", "period": "7d", "focus": {"incident": 999999}})
        flat = [x for b in rep["blocks"] for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b])]
        self.assertTrue(any(b["type"] == "text" and b["title"] == "Actions" for b in flat))

    def test_builder_tables_and_strict_blocks(self):
        blocks = reports.parse_blocks([{"type": "table", "entity": "incident", "show": "open", "fallback": "problem"},
                                       {"type": "table", "entity": "change", "fallback": "problem", "show": "open"}], True)
        self.assertEqual((blocks[0]["show"], blocks[0]["fallback"]), ("open", "problem"))
        self.assertEqual(blocks[1]["fallback"], "")
        self.assertNotIn("show", blocks[1])
        self.assertEqual(reports.parse_blocks([{"type": "table", "entity": "incident", "show": "everything"}], True)[0]["show"], "period")
        with self.assertRaises(reports.ReportError):
            reports.parse_blocks([{"type": "table", "entity": "incidentz"}], True)
        ids = {t["id"] for t in reports.catalog(True)["tables"]}
        self.assertTrue({"incident", "change"} <= ids)
        rep = self.run_report({"template": "custom", "period": "24h", "blocks": [{"type": "table", "entity": "change", "title": "Changes"}]})
        self.assertIn("New power strip", [r[2] for r in self.table(rep, "Changes")["rows"]])


if __name__ == "__main__":
    unittest.main()
