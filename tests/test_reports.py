"""Reports (reports.py and the /api/reports routes): templates, filters, CSV and PDF, saved and scheduled reports."""

import json
import time
import unittest
import urllib.request
from datetime import datetime
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, session_cookie, start_api_server, _cookie  # noqa: F401

import auth
import database
import rbac
import reports
import server

V3 = {"user": "reporter", "level": "authPriv", "auth_protocol": "SHA", "auth_password": "auth-secret-123",
      "priv_protocol": "AES", "priv_password": "priv-secret-456"}


def download(path, body):
    """POST and the raw bytes of the answer (a file), with its headers."""
    req = urllib.request.Request(f"http://127.0.0.1:{_env.PORT}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Cookie": f"{auth.SESSION_COOKIE}={_cookie['value']}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(), dict(r.headers)


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.v2 = add_device("rep-v2", "192.0.2.150", community="public")
        status, body, _ = request("POST", "/api/devices", {"hostname": "rep-v3", "ip_address": "192.0.2.151",
                                                           "profile_id": "generic_device", "snmp_version": "v3", "snmp_v3": V3,
                                                           "tags": ["report-tag"]})
        assert status == 201, body
        cls.v3 = body["device_id"]

    def run_spec(self, **spec):
        status, body, _ = request("POST", "/api/reports/run", {"spec": spec})
        self.assertEqual(status, 200, body)
        return body

    def test_templates_listed_with_their_columns(self):
        status, body, _ = request("GET", "/api/reports")
        self.assertEqual(status, 200)
        ids = [t["id"] for t in body["templates"]]
        self.assertEqual(ids, reports.TEMPLATE_ORDER)
        self.assertTrue(body["can_save"])
        self.assertIn({"id": self.v3, "name": "rep-v3", "ip": "192.0.2.151"}, body["devices"])

    def test_devices_report_shows_snmp_version_never_a_password(self):
        r = self.run_spec(template="devices")
        cols = [c["key"] for c in r["columns"]]
        rows = {row[cols.index("name")]: dict(zip(cols, row)) for row in r["rows"]}
        self.assertEqual(rows["rep-v2"]["snmp"], "v2c")
        self.assertEqual(rows["rep-v3"]["snmp"], "v3")
        self.assertEqual(rows["rep-v3"]["snmp_security"], "User reporter, signed and encrypted, SHA and AES")
        self.assertNotIn("secret", json.dumps(r))
        self.assertIn("Devices by SNMP version", [c["title"] for c in r["charts"]])

    def test_filters_tag_device_and_chosen_columns(self):
        r = self.run_spec(template="devices", filter={"tag": "report-tag"}, columns=["ip", "name", "nonsense"])
        self.assertEqual([c["key"] for c in r["columns"]], ["ip", "name"])
        self.assertEqual(r["rows"], [["192.0.2.151", "rep-v3"]])
        self.assertIn("Tag report-tag", r["subtitle"])
        one = self.run_spec(template="devices", filter={"device": self.v2}, columns=["name"])
        self.assertEqual(one["rows"], [["rep-v2"]])
        limited = self.run_spec(template="devices", columns=["name"], sort={"column": "name", "desc": True}, limit=1)
        self.assertEqual(len(limited["rows"]), 1)
        self.assertGreaterEqual(limited["total"], 2)

    def test_every_template_runs(self):
        for tid in reports.TEMPLATE_ORDER:
            for period in ("24h", "90d"):
                r = self.run_spec(template=tid, period=period)
                self.assertEqual(len(r["columns"]), len(reports.TEMPLATES[tid]["default"]), tid)
                self.assertTrue(all(len(row) == len(r["columns"]) for row in r["rows"]), tid)
        self.assertEqual(request("POST", "/api/reports/run", {"spec": {"template": "nope"}})[0], 400)

    def test_csv_and_pdf_downloads(self):
        with database.get_connection() as conn:
            conn.execute("UPDATE devices SET hostname = ? WHERE id = ?;", ("=cmd|calc", self.v2))
            conn.commit()

        def rename_back():
            with database.get_connection() as conn:
                conn.execute("UPDATE devices SET hostname = ? WHERE id = ?;", ("rep-v2", self.v2))
                conn.commit()
        self.addCleanup(rename_back)
        data, headers = download("/api/reports/download", {"spec": {"template": "devices", "columns": ["name", "snmp"]}, "format": "csv"})
        self.assertTrue(data.startswith("﻿".encode()))
        text = data.decode("utf-8-sig")
        self.assertTrue(text.startswith("Name,SNMP\r\n"))
        self.assertIn("'=cmd|calc,v2c", text)                     # a formula never runs in a spreadsheet
        self.assertIn('attachment; filename="devices-and-snmp-settings-', headers["Content-Disposition"])
        pdf, headers = download("/api/reports/download", {"spec": {"template": "devices"}, "format": "pdf"})
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertEqual(headers["Content-Type"], "application/pdf")

    def test_saved_report_runs_on_schedule_and_keeps_files(self):
        body = {"name": "Weekly SNMP list", "spec": {"template": "devices", "columns": ["name", "snmp"]},
                "schedule": {"kind": "daily", "time": "07:30"}, "formats": "both"}
        status, res, _ = request("POST", "/api/reports", body)
        self.assertEqual(status, 201, res)
        rid = res["id"]
        self.addCleanup(database.delete_report, rid)
        at = datetime(2026, 11, 16, 7, 30).timestamp()
        self.assertIn(rid, [r["id"] for r in server.due_reports(at)])
        self.assertNotIn(rid, [r["id"] for r in server.due_reports(at + 60)])
        server.make_report_run(database.get_report(rid), "schedule", int(at))
        self.assertNotIn(rid, [r["id"] for r in server.due_reports(at)])          # not twice in one minute
        saved = next(r for r in request("GET", "/api/reports")[1]["saved"] if r["id"] == rid)
        self.assertIn("07:30", saved["schedule_text"])
        run = saved["runs"][0]
        self.assertTrue(run["has_csv"] and run["has_pdf"])
        status, text, headers = request("GET", f"/api/reports/runs/{run['id']}.csv")
        self.assertEqual(status, 200)
        self.assertIn("rep-v3,v3", text)
        # Only the newest runs are kept.
        for _ in range(database.REPORT_RUNS_KEPT + 2):
            server.make_report_run(database.get_report(rid), "by hand")
        self.assertEqual(len(database.list_report_runs(rid)), database.REPORT_RUNS_KEPT)
        self.assertEqual(request("PUT", f"/api/reports/{rid}", dict(body, name=""))[0], 400)
        self.assertEqual(request("DELETE", f"/api/reports/{rid}")[0], 200)
        self.assertIsNone(database.get_report(rid))

    def test_telegram_gets_the_files(self):
        sent = []
        rid = database.save_report(None, "To the phone", json.dumps({"template": "devices"}), "", "both", True, database.list_users()[0]["username"])
        self.addCleanup(database.delete_report, rid)
        with mock.patch.object(server, "telegram_ready", return_value=True), \
                mock.patch.object(server.notify, "send_document", lambda *a: sent.append((a[2], a[4]))):
            result = server.make_report_run(database.get_report(rid), "by hand")
        self.assertEqual(result["error"], "")
        self.assertEqual([m for _, m in sent], ["application/pdf", "text/csv"])
        self.assertTrue(sent[0][0].startswith("to-the-phone-"))

    def test_broken_or_orphaned_report_is_recorded_not_raised(self):
        rid = database.save_report(None, "Orphan", json.dumps({"template": "devices"}), "", "csv", False, "nobody-here")
        self.addCleanup(database.delete_report, rid)
        result = server.make_report_run(database.get_report(rid), "schedule")
        self.assertIn("no longer exists", result["error"])
        self.assertIn("no longer exists", database.list_report_runs(rid)[0]["error"])


class ScopeTests(unittest.TestCase):
    """A user limited to some devices: network-wide templates, other people's reports and Telegram are closed."""

    def test_network_wide_templates_need_every_device(self):
        ids = [t["id"] for t in reports.template_list(False)]
        self.assertNotIn("proxmox", ids)
        self.assertNotIn("new_devices", ids)
        with self.assertRaises(reports.ReportError):
            reports.parse_spec({"template": "proxmox"}, False)

    def test_saved_reports_are_private_to_a_scoped_owner(self):
        scoped = rbac.User({"username": "limited", "role": "viewer", "device_scope": json.dumps({"all": False, "profiles": [], "devices": []})})
        everyone = rbac.User({"username": "boss", "role": "admin"})
        mine, theirs = {"owner": "limited"}, {"owner": "boss"}
        self.assertTrue(server.may_see_report(scoped, mine))
        self.assertFalse(server.may_see_report(scoped, theirs))
        self.assertTrue(server.may_see_report(everyone, mine))

    def test_csv_cells_and_formatting(self):
        self.assertEqual(reports._csv_value("text", "@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(reports._csv_value("pct", 99.5), "99.5")
        self.assertEqual(reports.format_cell("bytes", 1536), "1.5 KB")
        self.assertEqual(reports.format_cell("duration", 3700), "1 h 1 min")
        self.assertEqual(reports.format_cell("pct", 99.99), "99.99%")
        self.assertEqual(reports.format_cell("text", None), "")


if __name__ == "__main__":
    unittest.main()
