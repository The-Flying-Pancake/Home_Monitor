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
        first_series = [s for s in stream.splitlines() if " l S" in s and s.startswith("0.12 0.47 0.71 RG 1.2")]
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


if __name__ == "__main__":
    unittest.main()
