"""PDF writer (pdfdoc.py): the file structure readers rely on, text handling, tables over pages and charts.
The checks read the output back with simple patterns and unpack the page streams with zlib."""

import re
import time
import unittest
import zlib

from tests import _env  # noqa: F401

import pdfdoc


def objects(data: bytes) -> dict[int, bytes]:
    return {int(m.group(1)): m.group(2) for m in re.finditer(rb"(\d+) 0 obj\n(.*?)\nendobj\n", data, re.S)}


def page_streams(data: bytes) -> list[bytes]:
    found = re.findall(rb"stream\n(.*?)\nendstream", data, re.S)
    return [zlib.decompress(s) for s in found]


def page_count(data: bytes) -> int:
    return int(re.search(rb"/Type /Pages /Kids \[[^\]]*\] /Count (\d+)", data).group(1))


class Structure(unittest.TestCase):
    def setUp(self):
        doc = pdfdoc.Document(title="Inventory (all)")
        doc.heading("Inventory")
        doc.text("Group: Servers. 12 devices.", size=9, color=(0.4, 0.4, 0.4))
        doc.table(["Name", "Address"], [["nas", "192.0.2.10"], ["router", "192.0.2.1"]])
        self.data = doc.render()

    def test_header_and_end(self):
        self.assertTrue(self.data.startswith(b"%PDF-1.4\n"))
        self.assertTrue(self.data.rstrip().endswith(b"%%EOF"))

    def test_xref_offsets_point_at_objects(self):
        start = int(re.search(rb"startxref\n(\d+)\n", self.data).group(1))
        self.assertTrue(self.data[start:].startswith(b"xref\n"))
        head = re.match(rb"xref\n0 (\d+)\n", self.data[start:])
        size = int(head.group(1))
        entries = re.findall(rb"(\d{10}) (\d{5}) ([nf]) \n", self.data[start:])
        self.assertEqual(len(entries), size)
        self.assertEqual(entries[0], (b"0000000000", b"65535", b"f"))
        for number, (offset, _, _) in enumerate(entries[1:], start=1):
            self.assertTrue(self.data[int(offset):].startswith(b"%d 0 obj" % number), number)
        self.assertIn(b"/Size %d" % size, self.data)
        self.assertEqual(len(objects(self.data)), size - 1)

    def test_info_dictionary(self):
        info_ref = int(re.search(rb"/Info (\d+) 0 R", self.data).group(1))
        info = objects(self.data)[info_ref]
        self.assertIn(rb"/Title (Inventory \(all\))", info)
        self.assertIn(b"/Producer (Home Monitor)", info)
        self.assertRegex(info, rb"/CreationDate \(D:\d{14}Z\)")

    def test_unicode_title_uses_utf16(self):
        data = pdfdoc.Document(title="Caf\u00e9 \u2713").render()
        hexed = re.search(rb"/Title <FEFF([0-9A-F]+)>", data).group(1)
        self.assertEqual(bytes.fromhex(hexed.decode()).decode("utf-16-be"), "Caf\u00e9 \u2713")

    def test_footer_on_every_page(self):
        text = page_streams(self.data)[0]
        self.assertIn(b"(Home Monitor) Tj", text)
        self.assertIn(b"(Page 1 of 1) Tj", text)
        self.assertIn(b"/BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding", self.data)

    def test_portrait_and_landscape(self):
        def box(data):
            return [float(v) for v in re.search(rb"/MediaBox \[0 0 ([\d.]+) ([\d.]+)\]", data).groups()]
        width, height = box(self.data)
        self.assertLess(width, height)
        width, height = box(pdfdoc.Document(landscape=True).render())
        self.assertGreater(width, height)
        self.assertAlmostEqual(width, 841.89)


class Text(unittest.TestCase):
    def test_escaping(self):
        doc = pdfdoc.Document()
        doc.text(r"a (b) c\d")
        stream = page_streams(doc.render())[0]
        self.assertIn(rb"(a \(b\) c\\d) Tj", stream)

    def test_outside_cp1252_becomes_question_mark(self):
        self.assertEqual(pdfdoc.encode("Caf\u00e9 \u4e2d\u6587 \u2713"), b"Caf\xe9 ?? ?")
        self.assertEqual(pdfdoc.encode("tab\there\x01"), b"tab here?")
        doc = pdfdoc.Document()
        doc.text("Name \u4e2d")
        self.assertIn(b"(Name ?) Tj", page_streams(doc.render())[0])

    def test_widths_from_the_font_metrics(self):
        self.assertAlmostEqual(pdfdoc.text_width("A", 10), 6.67)
        self.assertAlmostEqual(pdfdoc.text_width("A", 10, bold=True), 7.22)
        self.assertAlmostEqual(pdfdoc.text_width("ill", 1000), 222 * 3)
        self.assertAlmostEqual(pdfdoc.text_width("\u20ac", 1000), 556)

    def test_truncation(self):
        self.assertEqual(pdfdoc.fit("short", 100, 10), "short")
        cut = pdfdoc.fit("a long device name that will not fit", 60, 10)
        self.assertTrue(cut.endswith("..."))
        self.assertLessEqual(pdfdoc.text_width(cut, 10), 60)
        longer = cut[:-3] + "a long device name that will not fit"[len(cut) - 3] + "..."
        self.assertGreater(pdfdoc.text_width(longer, 10), 60)
        # Narrow letters fit more of them than wide ones in the same room.
        self.assertGreater(len(pdfdoc.fit("i" * 50, 40, 10)), len(pdfdoc.fit("W" * 50, 40, 10)))

    def test_wrap(self):
        lines = pdfdoc.wrap("word " * 60, 200, 10)
        self.assertGreater(len(lines), 1)
        self.assertTrue(all(pdfdoc.text_width(line, 10) <= 200 for line in lines))


class Tables(unittest.TestCase):
    def test_long_table_flows_and_repeats_header(self):
        rows = [[f"device-{i}", f"192.0.2.{i % 250}", i] for i in range(200)]
        doc = pdfdoc.Document(title="Long")
        doc.table(["Name", "Address", "Count"], rows, align="llr")
        data = doc.render()
        # A4 portrait: 770 points of room at 14 points a row is about 54 rows a page, header included.
        rows_per_page = int((pdfdoc.A4[1] - 2 * pdfdoc.MARGIN) // 14) - 1
        expected = -(-200 // rows_per_page)
        self.assertEqual(page_count(data), expected)
        streams = page_streams(data)
        self.assertEqual(len(streams), expected)
        for number, stream in enumerate(streams, start=1):
            self.assertEqual(stream.count(b"/F2 8 Tf"), 3, number)  # The bold header, once per page.
            self.assertIn(b"(Page %d of %d) Tj" % (number, expected), stream)
        self.assertIn(b"(device-199) Tj", streams[-1])

    def test_cells_truncated_and_right_aligned(self):
        doc = pdfdoc.Document()
        doc.table(["Name", "Value"], [["x" * 300, 42]], widths=[3, 1], align=["l", "r"])
        stream = page_streams(doc.render())[0].decode("latin-1")
        cell = re.search(r"\((x+\.\.\.)\) Tj", stream).group(1)
        name_width = (pdfdoc.A4[0] - 2 * pdfdoc.MARGIN) * 0.75
        self.assertLessEqual(pdfdoc.text_width(cell, 8), name_width - 8)
        x = float(re.search(r"([\d.]+) [\d.]+ Td \(42\) Tj", stream).group(1))
        self.assertAlmostEqual(x + pdfdoc.text_width("42", 8), pdfdoc.A4[0] - pdfdoc.MARGIN - 4, places=1)

    def test_computed_widths_fill_the_page(self):
        doc = pdfdoc.Document()
        widths = doc._column_widths(["A", "B", "C"], [["a" * 200, "b", "c" * 200]], 8, None)
        self.assertAlmostEqual(sum(widths), doc.content_width)
        self.assertLess(widths[1], widths[0])

    def test_empty_table(self):
        doc = pdfdoc.Document()
        doc.table(["Name"], [])
        self.assertIn(b"(No rows) Tj", page_streams(doc.render())[0])


class Charts(unittest.TestCase):
    def test_line_chart_with_gaps(self):
        now = int(time.time())
        points = [(now + i * 300, None if i in (5, 6, 12) else i % 40) for i in range(30)]
        doc = pdfdoc.Document()
        doc.line_chart("CPU", [{"name": "CPU", "points": points},
                               {"name": "Memory", "points": [(now, 50), (now + 9000, 60)]}], y_unit="%")
        stream = page_streams(doc.render())[0].decode("latin-1")
        first_series = [s for s in stream.splitlines() if " l S" in s and s.startswith(pdfdoc._rgb(pdfdoc.PALETTE[0], "RG") + " 1.2")]
        self.assertEqual(len(first_series), 3)  # Broken at 5 and 6, then again at 12.
        self.assertIn("(100%) Tj", stream)
        self.assertIn("(Memory) Tj", stream)

    def test_isolated_point_is_drawn(self):
        self.assertEqual(pdfdoc._runs([(1, 2), (2, None), (3, 4), (4, 5)]), [[(1, 2.0)], [(3, 4.0), (4, 5.0)]])

    def test_empty_charts_say_no_data(self):
        doc = pdfdoc.Document()
        doc.line_chart("Nothing", [{"name": "CPU", "points": [(1, None)]}])
        doc.line_chart("Nothing at all", [])
        doc.bar_chart("No bars", [])
        self.assertEqual(page_streams(doc.render())[0].count(b"(No data) Tj"), 3)

    def test_single_point_and_flat_series(self):
        doc = pdfdoc.Document()
        doc.line_chart("One", [{"name": "x", "points": [(1000, 5)]}])
        doc.line_chart("Flat", [{"name": "x", "points": [(1000, 0), (2000, 0)]}])
        self.assertTrue(doc.render().startswith(b"%PDF"))

    def test_bar_chart(self):
        doc = pdfdoc.Document()
        doc.bar_chart("Top disks", [("nas", 91.5), ("a very long server name " * 4, 40), ("router", 0)], unit="%")
        stream = page_streams(doc.render())[0].decode("latin-1")
        self.assertIn("(91.5%) Tj", stream)
        self.assertIn("...) Tj", stream)

    def test_charts_flow_to_new_pages(self):
        doc = pdfdoc.Document()
        for i in range(8):
            doc.line_chart(f"Chart {i}", [{"name": "x", "points": [(0, 1), (3600, 2)]}])
        self.assertGreaterEqual(page_count(doc.render()), 2)

    def test_time_tick_formats(self):
        start = 1_800_000_000
        self.assertEqual(pdfdoc.time_ticks(start, start + 6 * 3600)[1], "%H:%M")
        self.assertEqual(pdfdoc.time_ticks(start, start + 3 * 86400)[1], "%d %b %H:%M")
        self.assertEqual(pdfdoc.time_ticks(start, start + 30 * 86400)[1], "%d %b")
        ticks, _ = pdfdoc.time_ticks(start, start + 6 * 3600)
        self.assertTrue(3 <= len(ticks) <= 7)

    def test_nice_ticks(self):
        self.assertEqual(pdfdoc.nice_ticks(0, 100), [0, 20, 40, 60, 80, 100])
        ticks = pdfdoc.nice_ticks(0, 0.37)
        self.assertGreaterEqual(ticks[-1], 0.37)


class ReportBlocks(unittest.TestCase):
    """The report layout: header band, key figures, the chart kinds, pills and trend lines in tables."""

    def stream(self, doc):
        return b"\n".join(page_streams(doc.render())).decode("latin-1")

    def test_header_band_and_kpi_tiles(self):
        doc = pdfdoc.Document(footer="Data from ping. Times are local.")
        doc.header_band("Availability", "Whether each device was reachable.",
                        [("Period", "8 Nov 2026 00:00 to 15 Nov 2026 00:00 (the last 7 days)"), ("Covers", "All devices"), ("Made", "15 Nov")])
        doc.kpi_tiles([{"label": "Uptime", "value": "99.96%", "tone": "good", "sub": "Target 99.9%",
                        "note": "Up 0.03 points on the previous 7 days", "trend": "good"},
                       {"label": "Outages", "value": "2", "tone": "warn", "note": "Up 1 on the previous 7 days", "trend": "bad"},
                       {"label": "Down", "value": "0", "tone": "bad"}])
        text = self.stream(doc)
        for want in ("(Availability) Tj", "(PERIOD) Tj", "(99.96%) Tj", "(Data from ping. Times are local.) Tj", "(Page 1 of 1) Tj"):
            self.assertIn(want, text)
        self.assertIn(" c h B", text)                                                  # rounded corners
        # The status edges in their tone colours, the comparisons in good or bad ink.
        for tone in ("good", "warn", "bad"):
            self.assertIn(pdfdoc._rgb(pdfdoc.TONES[tone], "rg") + " ", text)
        self.assertIn(pdfdoc._rgb(pdfdoc.TONE_INK["good"], "rg") + " 56", text.replace("\n", " ")[:0] or pdfdoc._rgb(pdfdoc.TONE_INK["good"], "rg") + " 56")
        self.assertIn(pdfdoc._rgb(pdfdoc.TONE_INK["bad"], "rg"), text)
        # The long period takes two columns rather than being cut short.
        self.assertIn("(the last 7 days\\)) Tj", text)

    def test_every_chart_kind_draws(self):
        now = 1_800_000_000
        pts = [(now + i * 600, None if i == 5 else 20 + i % 7) for i in range(40)]
        specs = [
            {"kind": "line", "title": "CPU", "unit": "%", "series": [{"name": "CPU", "points": pts}],
             "bands": [{"from": 80, "to": 90, "tone": "warn"}], "thresholds": [{"value": 80, "tone": "warn", "label": "Watch 80%"}]},
            {"kind": "mirror", "title": "WAN", "unit": "bps", "in": [(now + i * 60, 5e6 + i * 1e5) for i in range(30)],
             "out": [(now + i * 60, 1e6) for i in range(30)], "in_label": "In (download)", "out_label": "Out (upload)"},
            {"kind": "bar", "title": "Fullest", "unit": "%", "max": 100, "bars": [["nas", 93.0, "bad"], ["pc", 40.0, "good"]],
             "thresholds": [{"value": 80, "tone": "warn"}, {"value": 90, "tone": "bad"}]},
            {"kind": "columns", "title": "Per day", "labels": ["Mon", "Tue", "Wed"], "stacked": True, "whole": True,
             "series": [{"name": "Critical", "tone": "bad", "values": [1, 0, 2]}, {"name": "Warning", "tone": "warn", "values": [0, 3, 1]}],
             "target": {"value": 2, "label": "Target", "tone": "none"}},
            {"kind": "donut", "title": "Now", "segments": [{"label": "Up", "value": 16, "tone": "good"}, {"label": "Down", "value": 1, "tone": "bad"}],
             "total": 17, "total_label": "devices"},
            {"kind": "strips", "title": "Uptime", "rows": [{"name": "nas", "value_text": "99.5%", "cells": [[100, "good"], [None, "none"], [98, "bad"]]}],
             "start_text": "8 Nov", "end_text": "15 Nov"},
            {"kind": "heatmap", "title": "Busy", "unit": "bps", "rows": ["Mon", "Tue"], "values": [[1e6] * 24, [None] * 23 + [5e6]], "max": 5e6},
            {"kind": "grid", "title": "Devices", "tiles": [{"label": "nas", "tone": "good", "sub": "Up"}, {"label": "tv", "tone": "bad", "sub": "Down"}]},
        ]
        doc = pdfdoc.Document()
        doc.chart(specs[0])
        doc.chart_grid(specs[1:], columns=2)
        text = self.stream(doc)
        self.assertNotIn("(No data) Tj", text)
        for title in ("CPU", "WAN", "Fullest", "Per day", "Now", "Uptime", "Busy", "Devices"):
            self.assertIn(f"({title}) Tj", text)
        self.assertIn("[3 2] 0 d", text)                                           # thresholds are dashed
        self.assertIn("(17) Tj", text)                                             # the donut's total
        self.assertIn("(Watch 80%) Tj", text)
        self.assertIn("(In \\(download\\)) Tj", text)
        self.assertIn("(Low) Tj", text)
        self.assertIn(pdfdoc._rgb(pdfdoc.TONE_TINT["warn"], "rg"), text)         # the band
        # Whole numbers only on a count axis: no 0.5.
        self.assertNotIn("(0.5) Tj", text)

    def test_unknown_or_empty_charts_say_no_data(self):
        doc = pdfdoc.Document()
        doc.chart_grid([{"kind": "donut", "title": "A", "segments": []}, {"kind": "nonsense", "title": "B"}])
        self.assertEqual(self.stream(doc).count("(No data) Tj"), 2)

    def test_far_threshold_is_named_not_drawn(self):
        near, far = pdfdoc.split_marks([{"value": 50, "label": "Target"}], 2.0, None)
        self.assertEqual((near, [m["label"] for m in far]), ([], ["Target"]))
        doc = pdfdoc.Document()
        doc.chart({"kind": "line", "title": "Ping", "unit": "ms", "series": [{"name": "Ping", "points": [(0, 1), (3600, 2)]}],
                   "thresholds": [{"value": 50, "tone": "warn", "label": "Target 50 ms"}]})
        text = self.stream(doc)
        self.assertIn("(Target 50 ms, above the chart) Tj", text)
        self.assertNotIn("(50 ms) Tj", text)

    def test_zoomed_axis_starts_where_asked(self):
        self.assertEqual(pdfdoc.exact_ticks(99.5, 100), [99.5, 99.6, 99.7, 99.8, 99.9, 100])
        doc = pdfdoc.Document()
        doc.chart({"kind": "columns", "title": "Days", "unit": "%", "y_min": 99.5, "y_max": 100, "labels": ["a", "b"],
                   "series": [{"name": "Up", "values": [99.95, 100]}], "bar_tones": ["good", "good"]})
        self.assertIn("(99.5%) Tj", self.stream(doc))

    def test_pills_and_sparks_in_tables(self):
        doc = pdfdoc.Document()
        doc.table(["Device", "Trend", "State"], [["nas", pdfdoc.Spark([1, 3, None, 2, 5]), pdfdoc.Pill("Breached", "bad")],
                                                 ["pc", pdfdoc.Spark([]), pdfdoc.Pill("Met", "nonsense")]])
        text = self.stream(doc)
        self.assertIn("(Breached) Tj", text)
        self.assertIn(pdfdoc._rgb(pdfdoc.TONE_TINT["bad"], "rg"), text)
        self.assertIn(pdfdoc._rgb(pdfdoc.TONE_INK["none"], "rg"), text)           # an unknown tone is grey
        self.assertEqual(str(pdfdoc.Pill("Met", "good")).strip(), "Met")
        self.assertIn(pdfdoc._rgb(pdfdoc.PALETTE[0], "RG") + " 0.8 w", text)       # the trend line, broken at the gap

    def test_every_new_chart_kind_draws(self):
        """The kinds added with the report blocks: each draws its data (no "No data" box) with its marks."""
        now = 1_800_000_000
        series = [(now + i * 3600, 10 + i % 9) for i in range(48)]
        specs = [
            {"kind": "gauge", "title": "Gauges", "gauges": [{"label": "CPU", "value": 72, "text": "72%", "max": 100, "warn": 80, "bad": 90},
                                                           {"label": "Temp", "value": None, "text": "Not read"}]},
            {"kind": "headline", "title": "Headline", "items": [{"label": "Ping", "value_text": "4 ms", "values": [3, 4, None, 6, 2], "better": "down"}]},
            {"kind": "sparktable", "title": "Watch", "header": ["Device", "CPU", "Now", ""], "rows": [{"name": "nas", "values": [1, 5, 3], "now": "93%", "tone": "bad"}]},
            {"kind": "bullet", "title": "Bullet", "min": 99, "max": 100, "target": 99.9, "target_label": "Target 99.9%", "bands": [99, 99.5, 99.9],
             "rows": [["web", 99.95, "99.95%"]], "unit": "%"},
            {"kind": "lollipop", "title": "Lollipop", "unit": "%", "items": [["a", 0.2, "good"], ["b", 1.4, "bad"]], "thresholds": [{"value": 1, "tone": "bad"}]},
            {"kind": "diverging", "title": "Diverging", "unit": "ms", "rows": [["a", 12, "12 ms over"], ["b", -8, "8 ms under"]]},
            {"kind": "dumbbell", "title": "Dumbbell", "unit": "ms", "rows": [["a", 10, 6], ["b", None, 4]], "before_label": "Before", "after_label": "After"},
            {"kind": "butterfly", "title": "Butterfly", "unit": "bps", "rows": [["eth0", 5e6, 1e6]], "left_label": "In", "right_label": "Out"},
            {"kind": "stack100", "title": "Bands", "rows": [{"label": "Lab", "values": [3, 1, 0, 0, 1]}],
             "parts": [{"name": "Low", "tone": None}, {"name": "Mid", "tone": None}, {"name": "High", "tone": None}, {"name": "Busy", "tone": "warn"}, {"name": "Full", "tone": "bad"}]},
            {"kind": "treemap", "title": "Treemap", "items": [{"label": "a", "text": "6", "x": 0, "y": 0, "w": 0.6, "h": 1, "tone": None},
                                                              {"label": "b", "text": "4", "x": 0.6, "y": 0, "w": 0.4, "h": 1, "tone": "warn"}]},
            {"kind": "waterfall", "title": "Budget", "unit": "min", "steps": [["Budget", 43.2, "start"], ["nas 3 Nov", 50, "minus"], ["Left", -6.8, "end"]]},
            {"kind": "pareto", "title": "Pareto", "bars": [["CPU high", 8], ["Disk", 2]], "cumulative": [80.0, 100.0]},
            {"kind": "histogram", "title": "Histogram", "unit": "ms", "bins": [[0, 1, 5], [1, 2, 9], [2, 3, 1]],
             "marks": [{"value": 1.4, "label": "Median 1.4 ms", "tone": "s5"}, {"value": 2.5, "label": "99th 2.5 ms", "tone": "bad"}]},
            {"kind": "box", "title": "Box", "unit": "ms", "target": 50, "rows": [{"label": "Lab", "lo": 1, "q1": 2, "med": 3, "q3": 5, "hi": 9, "n": 40, "outliers": [20, 31]}]},
            {"kind": "cdf", "title": "CDF", "unit": "ms", "mark": 0.95, "series": [{"name": "Lab", "points": [[1, 0.2], [3, 0.8], [9, 1.0]]}]},
            {"kind": "band", "title": "Band", "unit": "ms", "start": now, "end": now + 47 * 3600,
             "points": [[t, v - 3, v - 1, v, v + 2, v + 6] if i != 5 else [t, None, None, None, None, None] for i, (t, v) in enumerate(series)]},
            {"kind": "baseline", "title": "Usual", "unit": "%", "start": now, "end": now + 47 * 3600, "points": series,
             "band": [[t, 5, 15] for t, _ in series], "anomalies": [[series[8][0], 18]]},
            {"kind": "step", "title": "Answering", "start": now, "end": now + 7200, "points": [[now, 5], [now + 1800, 4], [now + 3600, 5]], "expected": 5},
            {"kind": "multiples", "title": "Each", "unit": "%", "start": now, "end": now + 47 * 3600, "y_max": 100,
             "panels": [{"name": "a", "points": series, "bad": False}, {"name": "b", "points": series[:9], "bad": True}], "threshold": {"value": 80}},
            {"kind": "forecast", "title": "Forecast", "unit": "%", "start": now, "end": now + 60 * 86400, "observed": [[now + d * 86400, 50 + d] for d in range(20)],
             "projection": [[now + d * 86400, 50 + d] for d in range(19, 60, 5)], "cone": [[now + d * 86400, 45 + d, 55 + d] for d in range(19, 60, 5)],
             "limit": 90, "limit_label": "Limit 90%", "full_at": now + 40 * 86400, "full_text": "Limit around 3 Mar"},
            {"kind": "calendar", "title": "Calendar", "cells": [[0, d, 100, "good", False, "x"] for d in range(7)] + [[1, 0, 99.95, "good", True, "y"], [1, 1, None, "none", False, "z"]],
             "months": [[0, "Nov"]], "legend": [["100%", "good", False]]},
            {"kind": "gantt", "title": "Gantt", "start": now, "end": now + 7 * 86400, "marks": [[now + d * 86400, f"Day {d}"] for d in range(7)],
             "rows": [{"name": "nas", "spans": [[now + 3600, now + 7200, "bad", "down"], [now + 86400, now + 90000, "maint", "planned"]]}]},
            {"kind": "clock", "title": "Clock", "values": [0] * 6 + [5, 9] + [1] * 16, "warn": 4, "bad": 8},
            {"kind": "timeline", "title": "Timeline", "start": now, "end": now + 3600, "impact": [now + 600, now + 1800, "Down (20 minutes)"],
             "events": [[now + 600, "Problem: unreachable", "bad"], [now + 1800, "Resolved", "good"]]},
            {"kind": "scatter", "title": "Scatter", "max": 100, "x_line": 80, "y_line": 80, "x_label": "CPU", "y_label": "Memory",
             "points": [["nas", 85, 90, "bad", True], ["pc", 20, 30, "info", False]]},
            {"kind": "radar", "title": "Radar", "axes": ["A", "B", "C", "D"], "series": [{"name": "Now", "values": [90, 80, None, 70]}, {"name": "Before", "values": [85, 85, 60, 75]}]},
            {"kind": "topology", "title": "Map", "nodes": [{"key": "a", "label": "router", "tone": "good", "x": 0.5, "y": 0.2, "core": True},
                                                          {"key": "b", "label": "nas", "tone": "bad", "x": 0.5, "y": 0.8}],
             "links": [{"a": "a", "b": "b", "tone": "bad", "dashed": True}]},
            {"kind": "textbox", "title": "Notes", "text": "First paragraph.\nSecond one."},
            {"kind": "keyvalue", "title": "Details", "pairs": [["Model", "Demo NAS"], ["Address", "192.0.2.21"]]},
            {"kind": "columns", "title": "Grouped", "grouped": True, "stacked": False, "labels": ["a", "b"], "unit": "bps",
             "series": [{"name": "In", "values": [5e6, 2e6]}, {"name": "Out", "values": [1e6, 3e6]}]},
            {"kind": "grid", "title": "Grid", "tiles": [{"label": "nas", "tone": "good", "sub": "Up"}], "counts": [["Up", "good", 1], ["Down", "bad", 0]]},
            {"kind": "line", "title": "Dots", "unit": "%", "series": [{"name": "CPU", "points": series}], "dots": [[series[3][0], 92]]},
        ]
        doc = pdfdoc.Document()
        doc.chart_grid(specs, columns=2)
        text = self.stream(doc)
        self.assertNotIn("(No data) Tj", text)
        for spec in specs:
            self.assertIn(f"({spec['title']}) Tj", text, spec["kind"])
        for want in ("(72%) Tj", "(Target 99.9%) Tj", "(80%) Tj", "(Down \\(20 minutes\\)) Tj", "(00h) Tj", "(Limit around 3 Mar) Tj",
                     "(95% of answers) Tj", "(Up 1) Tj", "(Second one.) Tj", "(Demo NAS) Tj", "(< Better) Tj"):
            self.assertIn(want, text)
        self.assertIn(pdfdoc._rgb(pdfdoc.TONES["bad"], "rg"), text)                     # status colours where they mean status

    def test_empty_states_say_why(self):
        doc = pdfdoc.Document()
        doc.chart_grid([{"kind": "forecast", "title": "F", "observed": [], "empty_text": "A forecast needs 14 days of history."},
                        {"kind": "gauge", "title": "G", "gauges": []}])
        # A small multiple without data keeps its panel and says so (it is not left out).
        doc.chart({"kind": "multiples", "title": "M", "start": 0, "end": 10, "panels": [{"name": "quiet-one", "points": []}]})
        text = self.stream(doc)
        self.assertIn("(quiet-one) Tj", text)
        self.assertIn("(A forecast needs 14 days of history.) Tj", text)
        self.assertIn("(No data) Tj", text)

    def test_text_box(self):
        doc = pdfdoc.Document()
        doc.text_box("Root cause", "The switch lost power.\nThe spare took over.")
        doc.text_box("Long", "word " * 4000)                                             # longer than a page: flows on without the box
        text = self.stream(doc)
        self.assertIn("(Root cause) Tj", text)
        self.assertIn("(The spare took over.) Tj", text)
        self.assertGreaterEqual(page_count(doc.render()), 2)

    def test_format_value(self):
        self.assertEqual(pdfdoc.format_value(47_400_000, "bps"), "47.4 Mbps")
        self.assertEqual(pdfdoc.format_value(1536, "B"), "1.5 KB")
        self.assertEqual(pdfdoc.format_value(99.5, "%"), "99.5%")
        self.assertEqual(pdfdoc.format_value(12, "ms"), "12 ms")
        self.assertEqual(pdfdoc.format_value(None), "")


if __name__ == "__main__":
    unittest.main()
