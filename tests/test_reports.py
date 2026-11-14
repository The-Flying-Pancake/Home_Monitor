"""Reports (reports.py and the /api/reports routes): templates, filters, CSV and PDF, saved and scheduled reports."""

import json
import re
import time
import zlib
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
        self.assertEqual(r["main"]["title"], "Devices by SNMP version")
        self.assertIn("Devices per template", [c["title"] for c in r["charts"]])

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
                # The report layout: header, key figures, a summary in words and a footer.
                self.assertTrue(r["purpose"] and r["facts"] and r["footer"], tid)
                self.assertTrue(3 <= len(r["kpis"]) <= 6, tid)
                self.assertTrue(all(k["tone"] in ("good", "warn", "bad", "info", "none") for k in r["kpis"]), tid)
                self.assertTrue(r["summary"][:1].isupper(), (tid, r["summary"]))
                self.assertNotIn(", and ", r["summary"], tid)
                self.assertIn("Times are local", r["footer"])
                for c in ([r["main"]] if r["main"] else []) + r["charts"]:
                    self.assertIn(c["kind"], ("line", "mirror", "bar", "columns", "donut", "strips", "heatmap", "grid"), tid)
                    self.assertTrue(c["title"], tid)
        self.assertEqual(request("POST", "/api/reports/run", {"spec": {"template": "nope"}})[0], 400)

    def test_every_template_makes_a_pdf_and_csv(self):
        for tid in reports.TEMPLATE_ORDER:
            spec = reports.parse_spec({"template": tid, "period": "7d"}, True)
            report = server.run_report(spec, None)
            pdf = reports.to_pdf(report)
            self.assertTrue(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"), tid)
            text = b"".join(zlib.decompress(m) for m in re.findall(rb"stream\n(.*?)\nendstream", pdf, re.S))
            self.assertIn(b"Page 1 of", text, tid)
            self.assertIn(b"Times are local", text, tid)
            title = reports.TEMPLATES[tid]["title"].replace("(", "\\(").replace(")", "\\)")
            self.assertIn(b"(" + title.encode("cp1252") + b") Tj", text, tid)
            self.assertTrue(reports.to_csv(report).startswith("\ufeff".encode()), tid)

    def test_layout_with_history_compares_periods_and_shows_pills(self):
        """Seeded checks, pings, processor readings and a problem: comparisons, pills, charts and the PDF."""
        now = int(time.time())
        day = 86400
        with database.get_connection() as conn:
            for back in range(1, 14 * 24):
                hour = now - now % 3600 - back * 3600
                ups = 59 if back == 30 else 60 if back < 7 * 24 else 57
                conn.execute("INSERT OR REPLACE INTO avail_hourly (device_id, hour, checks, ups, ms_sum, ms_count, ms_max) "
                             "VALUES (?, ?, 60, ?, ?, 60, 9);", (self.v2, hour, ups, 60 * 4.0))
            conn.execute("INSERT INTO avail_incidents (device_id, started, ended) VALUES (?, ?, ?);",
                         (self.v2, now - 30 * 3600, now - 30 * 3600 + 600))
            conn.commit()
        for i in range(0, 7 * 24 * 12):
            t = now - 7 * day + i * 300
            database.record_metrics(self.v2, {"icmp_ping_ms": 2.0 + (i % 5), "cpu_usage_pct": 85.0 if i % 50 == 0 else 20.0,
                                              "mem_used_pct": 40.0}, timestamp=t)
        database.add_event(self.v2, "critical", "problem", "Problem: Device unreachable (no ICMP reply)", timestamp=now - 600)
        self.addCleanup(self.forget_history)
        r = self.run_spec(template="availability", period="7d", filter={"device": self.v2})
        kpis = {k["label"]: k for k in r["kpis"]}
        self.assertTrue(kpis["Overall uptime"]["note"].startswith("Up "), kpis["Overall uptime"])   # 95% the week before
        self.assertIn("on the previous 7 days", kpis["Overall uptime"]["note"])
        self.assertEqual(kpis["Overall uptime"]["trend"], "good")
        self.assertEqual(r["main"]["kind"], "strips")
        cols = [c["key"] for c in r["columns"]]
        self.assertIn(r["rows"][0][cols.index("target")], ("Met", "At risk", "Breached"))
        self.assertIn(r["tones"][r["rows"][0][cols.index("target")]], ("good", "warn", "bad"))
        self.assertIn("rep-v2", r["summary"])
        self.assertIn("Address", [f[0] for f in r["facts"]])                 # one device: its details in the header
        lat = self.run_spec(template="latency", period="7d", filter={"device": self.v2})
        cols = [c["key"] for c in lat["columns"]]
        self.assertEqual(lat["rows"][0][cols.index("state")], "Good")
        self.assertGreater(len(lat["rows"][0][cols.index("trend")]), 1)
        self.assertEqual(lat["main"]["kind"], "line")
        dev = self.run_spec(template="device", period="7d", filter={"device": self.v2})
        self.assertEqual(dev["main"]["title"], "Processor and memory")
        self.assertEqual([b["tone"] for b in dev["main"]["bands"]], ["warn", "bad"])
        monthly = self.run_spec(template="monthly", period="7d")
        self.assertEqual(monthly["main"]["kind"], "columns")
        self.assertEqual(monthly["main"]["target"]["value"], reports.UPTIME_TARGET)
        self.assertTrue(any(row[0].startswith("Device unreachable") for row in monthly["rows"]))
        for spec in ({"template": "availability"}, {"template": "device", "filter": {"device": self.v2}}, {"template": "latency"}):
            pdf, _ = download("/api/reports/download", {"spec": dict(spec, period="7d"), "format": "pdf"})
            self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        csv_text = download("/api/reports/download", {"spec": {"template": "latency", "period": "7d"}, "format": "csv"})[0].decode("utf-8-sig")
        self.assertNotIn("Trend", csv_text.splitlines()[0])                    # a trend line is not a CSV column

    def forget_history(self):
        with database.get_connection() as conn:
            for table in ("avail_hourly", "avail_incidents", "metrics", "metrics_hourly", "events"):
                conn.execute(f"DELETE FROM {table} WHERE device_id = ?;", (self.v2,))
            conn.commit()

    def test_status_now_lists_every_device(self):
        r = self.run_spec(template="status")
        self.assertEqual(r["main"]["kind"], "grid")
        self.assertEqual(len(r["main"]["tiles"]), len(request("GET", "/api/reports")[1]["devices"]))
        self.assertEqual([k["label"] for k in r["kpis"][:4]], ["Up", "With problems", "Down", "Not monitored"])

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

    def test_change_on_the_previous_period(self):
        self.assertEqual(reports._change(99.96, 99.93, "7d", "points", "up"), ("Up 0.03 points on the previous 7 days", "good"))
        self.assertEqual(reports._change(12, 20, "30d", "ms", "down"), ("Down 8.0 ms on the previous 30 days", "good"))
        self.assertEqual(reports._change(5, 2, "24h", "count", "down"), ("Up 3 on the previous 24 hours", "bad"))
        self.assertEqual(reports._change(4, 4, "7d", "count", "down")[0], "Same as the previous 7 days")
        self.assertEqual(reports._change(None, 4, "7d", "count", "down"), ("", None))

    def test_words(self):
        self.assertEqual(reports._and(["a", "b", "c"]), "a, b and c")
        self.assertEqual(reports._count(3, "problem"), "Three problems")
        self.assertEqual(reports._count(1, "device"), "One device")
        self.assertEqual(reports._count(40, "event"), "In all 40 events")
        self.assertEqual(reports._target_word(99.95, 0, 7 * 86400), "Met")
        self.assertEqual(reports._target_word(99.92, 400, 7 * 86400), "At risk")
        self.assertEqual(reports._target_word(99.5, 3000, 7 * 86400), "Breached")
        self.assertEqual(reports._quantile([1, 2, 3, 4, 100], 0.95), 100)
        self.assertEqual(reports._median([1, 3, 2, 4]), 2.5)

    def test_new_templates_listed(self):
        ids = [t["id"] for t in reports.template_list(False)]
        for tid in ("monthly", "status", "availability", "latency", "bandwidth", "alerts", "device"):
            self.assertIn(tid, ids)
        self.assertTrue(next(t for t in reports.template_list(True) if t["id"] == "device")["one_device"])
        self.assertEqual(reports.parse_spec({"template": "monthly"}, True)["period"], "30d")

    def test_csv_cells_and_formatting(self):
        self.assertEqual(reports._csv_value("text", "@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(reports._csv_value("pct", 99.5), "99.5")
        self.assertEqual(reports.format_cell("bytes", 1536), "1.5 KB")
        self.assertEqual(reports.format_cell("duration", 3700), "1 h 1 min")
        self.assertEqual(reports.format_cell("pct", 99.99), "99.99%")
        self.assertEqual(reports.format_cell("text", None), "")


if __name__ == "__main__":
    unittest.main()
