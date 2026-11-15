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

# Every chart kind the page (reports.js) and the PDF (pdfdoc.py) draw.
PAGE_KINDS = ("line", "mirror", "bar", "columns", "donut", "strips", "heatmap", "grid", "gauge", "headline", "sparktable", "bullet",
              "lollipop", "diverging", "dumbbell", "butterfly", "stack100", "treemap", "waterfall", "pareto", "histogram", "box", "cdf",
              "band", "baseline", "step", "multiples", "forecast", "calendar", "gantt", "clock", "timeline", "scatter", "radar", "topology")

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
        # The class can be set up twice in one run (its tests are spread over shards): reuse the devices.
        have = {d["ip_address"]: d["id"] for d in database.list_devices()}
        cls.v2 = have.get("192.0.2.150") or add_device("rep-v2", "192.0.2.150", community="public")
        if "192.0.2.151" in have:
            cls.v3 = have["192.0.2.151"]
            return
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
                # Key figures, except where the spec's layout has none (the device deep dive).
                self.assertTrue(3 <= len(r["kpis"]) <= 6 or not any(b["type"] == "kpi_row" for b in reports.TEMPLATES[tid]["blocks"]), tid)
                self.assertTrue(all(k["tone"] in ("good", "warn", "bad", "info", "none") for k in r["kpis"]), tid)
                self.assertTrue(r["summary"][:1].isupper(), (tid, r["summary"]))
                self.assertNotIn(", and ", r["summary"], tid)
                self.assertIn("Times are local", r["footer"])
                for c in ([r["main"]] if r["main"] else []) + r["charts"]:
                    self.assertIn(c["kind"], PAGE_KINDS, tid)
                    self.assertTrue(c["title"], tid)
                # The one block model: every report is a list of blocks drawn by the same code.
                self.assertTrue(r["blocks"], tid)
                for b in r["blocks"]:
                    self.assertIn(b["type"], ("kpi_row", "chart", "table", "text", "key_value", "two_column"), tid)
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


def custom(*blocks, **extra):
    return dict({"template": "custom", "title": "Mine", "period": "7d", "blocks": list(blocks)}, **extra)


def chart(source, view, kind, **kw):
    return dict({"type": "chart", "source": source, "view": view, "chart": kind}, **kw)


class BlockModelTests(unittest.TestCase):
    """Checking a custom report's blocks: only known names survive, sizes are bounded, network-wide
    blocks need every device. Nothing from the browser reaches a query unchecked."""

    def parse(self, spec, all_devices=True):
        return reports.parse_spec(spec, all_devices)

    def test_a_good_definition_is_read_into_a_fresh_structure(self):
        spec = self.parse(custom(
            {"type": "kpi_row", "tiles": [{"metric": "availability", "compare": "target", "target": 99.5, "sql": "DROP TABLE"}]},
            chart("ping", "per", "lollipop", split="group", top=500, agg="nonsense", threshold={"mode": "override", "target": 30, "warn": "x"}),
            {"type": "two_column", "left": {"type": "text", "title": "Root cause", "text": "Line one\r\nLine two\n\n\n\nEnd"},
             "right": chart("status", "now", "donut")},
            {"type": "table", "entity": "device", "columns": ["name", "nope", "availability", "name"], "limit": 9999},
            {"type": "key_value", "fields": ["model", "secret"], "scope": {"kind": "devices", "devices": [3, "4", True, -1, 3]}},
            subtitle="x" * 500, evil={"path": "../../etc"}))
        self.assertNotIn("evil", spec)
        self.assertEqual(len(spec["subtitle"]), 200)
        tiles = spec["blocks"][0]["tiles"]
        self.assertEqual(tiles, [{"metric": "availability", "label": "", "compare": "target", "better": "up", "target": 99.5}])
        b = spec["blocks"][1]
        self.assertEqual((b["agg"], b["split"], b["top"]), ("median", "group", 10))     # unknown or too big: the default
        self.assertEqual(b["threshold"], {"mode": "override", "target": 30.0})
        self.assertEqual(spec["blocks"][2]["left"]["text"], "Line one\nLine two\n\nEnd")
        self.assertEqual(spec["blocks"][3]["columns"], ["name", "availability"])
        self.assertEqual(spec["blocks"][3]["limit"], 0)
        self.assertEqual(spec["blocks"][4]["fields"], ["model"])
        self.assertEqual(spec["blocks"][4]["scope"], {"kind": "devices", "devices": [3]})

    def test_bad_definitions_are_refused_in_words(self):
        bad = [
            custom({"type": "script"}),
            custom(chart("passwords", "per", "bar")),
            custom(chart("ping", "upside_down", "bar")),
            custom(chart("availability", "time", "radar")),                      # a chart that does not suit the data
            custom({"type": "kpi_row", "tiles": [{"metric": "availability"}] * 7}),
            custom({"type": "kpi_row", "tiles": [{"metric": "root_password"}]}),
            custom({"type": "table", "entity": "users"}),
            custom({"type": "part", "template": "devices", "part": "chart.9"}),
            custom({"type": "two_column", "left": {"type": "two_column", "left": {"type": "text", "title": "a"}}}),
            custom({"type": "two_column", "left": {"type": "table", "entity": "device"}}),
            custom({"type": "text"}),
            custom(),
            custom(*([{"type": "text", "title": "t"}] * (reports.MAX_BLOCKS + 1))),
            custom(blocks="not a list"),
        ]
        for spec in bad:
            with self.assertRaises(reports.ReportError, msg=str(spec)[:120]) as cm:
                self.parse(spec)
            self.assertTrue(str(cm.exception)[:1].isupper(), str(cm.exception))

    def test_network_wide_blocks_need_every_device(self):
        with self.assertRaises(reports.ReportError):
            self.parse(custom(chart("topology", "map", "topology")), all_devices=False)
        with self.assertRaises(reports.ReportError):
            self.parse(custom({"type": "part", "template": "proxmox", "part": "kpis"}), all_devices=False)
        self.assertEqual(self.parse(custom(chart("topology", "map", "topology")))["blocks"][0]["source"], "topology")
        names = {s["id"] for s in reports.catalog(False)["sources"]}
        self.assertNotIn("topology", names)
        self.assertIn("topology", {s["id"] for s in reports.catalog(True)["sources"]})

    def test_the_catalog_only_offers_what_exists(self):
        cat = reports.catalog(True)
        for s in cat["sources"]:
            for v in s["views"]:
                for c in v["charts"]:
                    self.assertIn(c, reports.CHARTS, (s["id"], v["id"]))
                    self.assertEqual(cat["charts"][c]["shape"], reports.CHART_SHAPES[c])
        for q in cat["questions"]:
            self.assertTrue(q["text"].endswith("?"))
            for ch in q["charts"]:
                self.assertIn(ch["chart"], reports.SOURCES[ch["source"]]["views"][ch["view"]]["charts"], q["id"])
            for tid in q["templates"]:
                self.assertIn(tid, reports.TEMPLATES)
        grouped = [tid for g in reports.TEMPLATE_GROUPS for tid in g["templates"]]
        self.assertEqual(sorted(grouped), sorted(reports.TEMPLATES))                 # every template sits in one group
        for t in reports.template_list(True):
            self.assertTrue(t["audience"] and t["group"] and t["blocks"], t["id"])
            # Start from this template: the template's own blocks are a valid custom definition.
            self.parse(custom(*t["blocks"]))
        # The spec's chart numbers (section 8) used by the builder.
        used = {c for s in reports.SOURCES.values() for v in s["views"].values() for c in v["charts"]}
        self.assertGreaterEqual(len(used), 38)


class CustomReportTests(unittest.TestCase):
    """The builder: a custom report runs, saves, runs on schedule and keeps its files, as its owner."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.a = add_device("blk-a", "192.0.2.160")
        cls.b = add_device("blk-b", "192.0.2.161")
        now = int(time.time())
        with database.get_connection() as conn:
            for back in range(1, 8 * 24):
                hour = now - now % 3600 - back * 3600
                for dev, ups in ((cls.a, 60), (cls.b, 58 if back % 20 == 0 else 60)):
                    conn.execute("INSERT OR REPLACE INTO avail_hourly (device_id, hour, checks, ups, ms_sum, ms_count, ms_max) "
                                 "VALUES (?, ?, 60, ?, ?, 60, 9);", (dev, hour, ups, 60 * 3.0))
            conn.execute("INSERT INTO avail_incidents (device_id, started, ended) VALUES (?, ?, ?);", (cls.b, now - 50 * 3600, now - 50 * 3600 + 900))
            conn.commit()
        for i in range(0, 3 * 24 * 12):
            t = now - 3 * 86400 + i * 300
            database.record_metrics(cls.a, {"icmp_ping_ms": 1.5 + (i % 7), "cpu_usage_pct": 30.0 + i % 40, "mem_used_pct": 50.0}, timestamp=t)
            database.record_metrics(cls.b, {"icmp_ping_ms": 9.0 + (i % 11), "cpu_usage_pct": 70.0 + i % 25, "mem_used_pct": 85.0}, timestamp=t)
        database.add_event(cls.b, "warning", "problem", "Problem: CPU at 91% (above 90%)", timestamp=now - 7200)
        database.add_event(cls.b, "info", "problem", "Resolved: CPU at 91% (above 90%) (lasted 3m)", timestamp=now - 7000)

    def run_spec(self, spec, code=200):
        status, body, _ = request("POST", "/api/reports/run", {"spec": spec})
        self.assertEqual(status, code, body)
        return body

    def test_every_source_view_and_chart_runs_on_the_page_and_in_the_pdf(self):
        blocks = []
        for sid, s in reports.SOURCES.items():
            for vid, v in s["views"].items():
                for kind in v["charts"]:
                    blocks.append(chart(sid, vid, kind, scope={"kind": "devices", "devices": [self.a, self.b]}))
        kinds = set()
        for i in range(0, len(blocks), 25):
            r = self.run_spec(custom(*blocks[i:i + 25]))
            self.assertEqual(len(r["blocks"]), len(blocks[i:i + 25]))
            for b in r["blocks"]:
                self.assertEqual(b["type"], "chart")
                self.assertIn(b["chart"]["kind"], PAGE_KINDS)
                kinds.add(b["chart"]["kind"])
            spec = reports.parse_spec(custom(*blocks[i:i + 25]), True)
            pdf = reports.to_pdf(server.run_report(spec, None))
            self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertEqual(kinds, set(PAGE_KINDS))                                   # every primitive is reachable

    def test_charts_draw_their_data(self):
        r = self.run_spec(custom(chart("ping", "distribution", "box", split="device", scope={"kind": "devices", "devices": [self.a, self.b]}),
                                 chart("ping", "band", "band", scope={"kind": "devices", "devices": [self.a, self.b]}),
                                 chart("cpu", "time", "threshold", agg="max", scope={"kind": "devices", "devices": [self.b]}),
                                 chart("cpu_mem", "scatter", "scatter", scope={"kind": "devices", "devices": [self.a, self.b]}),
                                 chart("availability", "budget", "waterfall", scope={"kind": "devices", "devices": [self.a, self.b]}),
                                 chart("problems", "per", "pareto", split="rule", period="24h", scope={"kind": "devices", "devices": [self.b]})))
        box, band, cpu, scatter, water, pareto = [b["chart"] for b in r["blocks"]]
        self.assertEqual([x["label"] for x in box["rows"]], ["blk-b", "blk-a"])            # slowest median first
        self.assertTrue(all(x["q1"] <= x["med"] <= x["q3"] for x in box["rows"]))
        self.assertTrue(any(p[3] is not None for p in band["points"]))                      # percentiles from raw samples
        self.assertEqual([b["tone"] for b in cpu["bands"]], ["warn", "bad"])
        self.assertTrue(cpu["dots"])                                                         # readings in the red are marked
        self.assertEqual(next(p for p in scatter["points"] if p[0] == "blk-b")[3], "bad")     # processor and memory both over 80%
        self.assertEqual(next(p for p in scatter["points"] if p[0] == "blk-a")[3], "info")
        steps = water["steps"]
        self.assertEqual((steps[0][2], steps[-1][2]), ("start", "end"))
        self.assertAlmostEqual(steps[-1][1], round(steps[0][1] - sum(s[1] for s in steps[1:-1]), 1), places=0)
        self.assertEqual(pareto["bars"][0][1], 1)
        self.assertEqual(pareto["cumulative"][-1], 100.0)
        self.assertIn("Covers the last 24 hours", pareto["note"])

    def test_scope_is_respected(self):
        # A block narrowed to one device only reads that device.
        r = self.run_spec(custom({"type": "table", "entity": "device", "columns": ["name", "availability"],
                                  "scope": {"kind": "devices", "devices": [self.a]}}))
        self.assertEqual([row[0] for row in r["blocks"][0]["rows"]], ["blk-a"])
        # A user limited to no devices sees nothing, whatever ids the definition names.
        scoped = rbac.User({"username": "nobody-sees", "role": "viewer", "device_scope": json.dumps({"all": False, "profiles": [], "devices": []})})
        scoped.bind_devices(database.device_profiles())
        spec = reports.parse_spec(custom({"type": "table", "entity": "device", "scope": {"kind": "devices", "devices": [self.a, self.b]}},
                                         chart("ping", "per", "bar", scope={"kind": "devices", "devices": [self.a]})), False)
        out = server.run_report(spec, scoped)
        self.assertEqual(out["blocks"][0]["rows"], [])
        self.assertEqual(out["blocks"][1]["chart"]["bars"], [])
        # Network-wide blocks of a template are left out for someone who does not see every device.
        devices, ctx = server.report_args(scoped, reports.parse_spec({"template": "handover"}, False))
        handover = reports.run(reports.parse_spec({"template": "handover"}, False), devices, ctx)
        kinds = [x["chart"]["kind"] for b in handover["blocks"] for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b]) if x["type"] == "chart"]
        self.assertNotIn("topology", kinds)

    def test_saving_and_running_a_custom_report(self):
        spec = custom({"type": "kpi_row", "tiles": [{"metric": "availability", "compare": "target"}, {"metric": "ping", "agg": "p95"}]},
                      {"type": "text", "title": "Handover notes", "text": "Check blk-b.\nIgnore the printer."},
                      {"type": "two_column", "left": chart("ping", "per", "diverging", split="device"), "right": {"type": "key_value"}},
                      {"type": "table", "entity": "device", "columns": ["name", "ping_median", "status", "trend"], "status": "ping", "spark": "ping"},
                      subtitle="What I look at every morning", audience="Me")
        status, res, _ = request("POST", "/api/reports", {"name": "Morning look", "spec": spec, "schedule": {"kind": "daily", "time": "06:15"}, "formats": "both"})
        self.assertEqual(status, 201, res)
        rid = res["id"]
        self.addCleanup(database.delete_report, rid)
        saved = next(r for r in request("GET", "/api/reports")[1]["saved"] if r["id"] == rid)
        self.assertEqual(saved["spec"]["template"], "custom")
        self.assertEqual(saved["spec"]["blocks"][1]["text"], "Check blk-b.\nIgnore the printer.")      # the words stay with it
        result = server.make_report_run(database.get_report(rid), "by hand")
        self.assertEqual(result["error"], "")
        run = database.list_report_runs(rid)[0]
        self.assertTrue(run["has_pdf"] and run["has_csv"])
        status, text, _ = request("GET", f"/api/reports/runs/{run['id']}.csv")
        self.assertEqual(status, 200)
        self.assertTrue(text.lstrip("﻿").startswith("Device,Median ping,Against the ping target"))   # the first table
        pdf, _ = download("/api/reports/download", {"spec": spec, "format": "pdf"})
        body = b"".join(zlib.decompress(m) for m in re.findall(rb"stream\n(.*?)\nendstream", pdf, re.S))
        for want in (b"(Mine) Tj", b"(Handover notes) Tj", b"(Ignore the printer.) Tj", b"(What I look at every morning) Tj"):
            self.assertIn(want, body)
        # The preview: header from the builder, the blocks in order.
        r = self.run_spec(spec)
        self.assertEqual(r["purpose"], "What I look at every morning")
        self.assertIn(["Audience", "Me"], r["facts"])
        self.assertEqual([b["type"] for b in r["blocks"]], ["kpi_row", "text", "two_column", "table"])
        self.assertEqual(r["blocks"][2]["right"]["type"], "key_value")
        # Changing it keeps it custom; a bad block is refused with a message.
        self.assertEqual(request("PUT", f"/api/reports/{rid}", {"name": "Morning look", "spec": dict(spec, blocks=spec["blocks"][:1])})[0], 200)
        status, body, _ = request("PUT", f"/api/reports/{rid}", {"name": "Morning look", "spec": dict(spec, blocks=[{"type": "nope"}])})
        self.assertEqual(status, 400)
        self.assertIn("block", body["error"])

    def test_start_from_a_template_copies_its_blocks(self):
        t = next(x for x in request("GET", "/api/reports")[1]["templates"] if x["id"] == "availability")
        r = self.run_spec(custom(*t["blocks"], based_on="availability", period="7d"))
        same = self.run_spec({"template": "availability", "period": "7d"})
        self.assertEqual([b["type"] for b in r["blocks"]], [b["type"] for b in same["blocks"]])
        self.assertEqual(r["columns"], same["columns"])

    def test_every_new_template_page_and_pdf(self):
        for tid in reports.NEW_TEMPLATES:
            for period in ("24h", "90d"):
                r = self.run_spec({"template": tid, "period": period})
                self.assertTrue(r["blocks"], tid)
                self.assertTrue(r["audience"], tid)
                for b in r["blocks"]:
                    for x in ([b["left"], b["right"]] if b["type"] == "two_column" else [b]):
                        if x["type"] == "text":
                            self.assertNotIn(", and ", x["text"], tid)
                            self.assertTrue(not x["text"] or x["text"][:1].isupper(), (tid, x["text"]))
                spec = reports.parse_spec({"template": tid, "period": period}, True)
                report = server.run_report(spec, None)
                pdf = reports.to_pdf(report)
                text = b"".join(zlib.decompress(m) for m in re.findall(rb"stream\n(.*?)\nendstream", pdf, re.S))
                self.assertIn(b"(" + reports.TEMPLATES[tid]["title"].encode("cp1252") + b") Tj", text, tid)
                self.assertNotIn(b"No data for this period", text)
                self.assertTrue(reports.to_csv(report).startswith("﻿".encode()), tid)

    def test_the_outage_review_picks_an_outage_of_your_own(self):
        r = self.run_spec({"template": "outage", "period": "7d"})
        self.assertIn("Outage", [f[0] for f in r["facts"]])
        self.assertTrue(r["summary"].startswith("The device blk-b went down") or r["summary"].startswith("The device"), r["summary"])
        listed = request("GET", "/api/reports")[1]["outages"]
        self.assertTrue(any(o["device"] == "blk-b" for o in listed))
        mine = next(o for o in listed if o["device"] == "blk-b")
        r = self.run_spec({"template": "outage", "period": "7d", "focus": {"outage": mine["id"]}})
        self.assertIn("blk-b", dict(r["facts"])["Outage"])
        # An outage id outside the devices the report covers is not used.
        r = self.run_spec({"template": "outage", "period": "7d", "filter": {"device": self.a}, "focus": {"outage": mine["id"]}})
        self.assertNotIn("Outage", [f[0] for f in r["facts"]])

    def test_calculations(self):
        self.assertEqual(reports._lasted_seconds("Resolved: CPU high (lasted 1h 5m)"), 3900)
        self.assertEqual(reports._lasted_seconds("Resolved: CPU high (lasted 2d 3h)"), 2 * 86400 + 3 * 3600)
        self.assertIsNone(reports._lasted_seconds("Resolved: CPU high"))
        fit = reports._fit_line([(d * 86400, 10 + 0.5 * d) for d in range(30)])
        self.assertAlmostEqual(fit["slope"], 0.5)
        self.assertAlmostEqual(fit["se"], 0.0)
        row = reports._forecast_row({"name": "nas", "id": 1}, "Disk 1", "Disk", [(d * 86400, 10 + 0.5 * d) for d in range(30)], 24.5, 90.0, 29 * 86400)
        self.assertAlmostEqual(row["days"], 131, places=0)                                  # (90 - 10) / 0.5 - 29
        self.assertEqual((reports._priority(row), row["growth"]), ("P3", 15.0))
        short = reports._forecast_row({"name": "nas", "id": 1}, "Disk 1", "Disk", [(0, 50.0)], 50.0, 90.0, 0)
        self.assertEqual(reports._days_text(short), f"Needs {reports.FORECAST_MIN_DAYS} days of history")
        self.assertEqual(reports._target_status(99.95, 0, 7 * 86400, 99.9), "Met")
        self.assertEqual(reports._target_status(99.5, 3000, 7 * 86400, 99.9), "Breached")
        hint, state = reports._hint({"count": 6, "quick": 5, "durations": [60, 90, 120], "open": False, "ids": {1, 2}})
        self.assertEqual(state, "Plan")
        self.assertIn("wait longer", hint)
        self.assertEqual(reports._hint({"count": 2, "quick": 0, "durations": [], "open": True, "ids": {1}})[1], "Open")
        tm = reports._treemap("T", "", [("a", 6, None), ("b", 3, None), ("c", 1, None)], "")
        self.assertAlmostEqual(sum(i["w"] * i["h"] for i in tm["items"]), 1.0, places=3)


if __name__ == "__main__":
    unittest.main()
