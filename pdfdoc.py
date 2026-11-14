"""Small PDF writer for reports, built on the standard library only.

It writes PDF 1.4 files with the two built-in Helvetica fonts, so nothing has to be embedded and
every reader can open them. A document is built from the top down: headings, lines of text, line
and bar charts and tables. Long tables flow over pages and repeat their header row. Page footers
("Page N of M") are added when the file is rendered, once the page count is known.

    doc = Document(title="Inventory")
    doc.heading("Inventory")
    doc.text("Group: Servers. 12 devices.", size=9, color=(0.4, 0.4, 0.4))
    doc.table(columns=["Name", "Address"], rows=[["nas", "192.0.2.10"]])
    data = doc.render()
"""

from __future__ import annotations

import math
import time
import zlib
from typing import Iterable, Sequence

Color = tuple[float, float, float]

A4 = (595.28, 841.89)
MARGIN = 36.0
FOOTER_Y = 20.0
BLACK: Color = (0.0, 0.0, 0.0)
GREY: Color = (0.4, 0.4, 0.4)
# Six colours that stay apart from each other on screen and on paper.
PALETTE: list[Color] = [
    (0.12, 0.47, 0.71), (1.0, 0.50, 0.05), (0.17, 0.63, 0.17),
    (0.84, 0.15, 0.16), (0.58, 0.40, 0.74), (0.55, 0.34, 0.29),
]
ELLIPSIS = "..."


def _expand(spec: str) -> list[int]:
    """Turns "556*3 278" into [556, 556, 556, 278]."""
    out: list[int] = []
    for part in spec.split():
        value, _, count = part.partition("*")
        out.extend([int(value)] * int(count or 1))
    return out


# Character widths from the standard Adobe font metrics (AFM), in thousandths of the font size,
# for the codes 32 to 255 of WinAnsiEncoding (cp1252). A 0 marks a code with no character.
_HELVETICA = _expand(
    "278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 556*10 278 278 584 584 584 556 1015 "
    "667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 667 778 722 667 611 722 667 944 667 667 611 "
    "278 278 278 469 556 333 "
    "556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 556 556 333 500 278 556 500 722 500 500 500 "
    "334 260 334 584 0 "
    "556 0 222 556 333 1000 556 556 333 1000 667 333 1000 0 611 0 0 222 222 333 333 350 556 1000 333 1000 "
    "500 333 944 0 500 667 "
    "278 333 556 556 556 556 260 556 333 737 370 556 584 333 737 333 400 584 333 333 333 556 537 278 333 333 "
    "365 556 834 834 834 611 "
    "667*6 1000 722 667*4 278*4 722 722 778*5 584 778 722*4 667 667 611 "
    "556*6 889 500 556*4 278*4 556 556 556*5 584 611 556*4 500 556 500")
_HELVETICA_BOLD = _expand(
    "278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 556*10 333 333 584 584 584 611 975 "
    "722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 667 778 722 667 611 722 667 944 667 667 611 "
    "333 278 333 584 556 333 "
    "556 611 556 611 556 333 611 611 278 278 556 278 889 611 611 611 611 389 556 333 611 556 778 556 556 500 "
    "389 280 389 584 0 "
    "556 0 278 556 500 1000 556 556 333 1000 667 333 1000 0 611 0 0 278 278 500 500 350 556 1000 333 1000 "
    "556 333 944 0 500 667 "
    "278 333 556 556 556 556 280 556 333 737 370 556 584 333 737 333 400 584 333 333 333 611 556 278 333 333 "
    "365 556 834 834 834 611 "
    "722*6 1000 722 667*4 278*4 722 722 778*5 584 778 722*4 667 667 611 "
    "556*6 889 556 556*4 278*4 611 611 611*5 584 611 611*4 556 611 556")
assert len(_HELVETICA) == len(_HELVETICA_BOLD) == 224


def encode(text: object) -> bytes:
    """Text as cp1252 bytes. Anything the fonts cannot show (other scripts, control codes) becomes "?"."""
    raw = str(text).replace("\r\n", " ").replace("\n", " ").replace("\t", " ")
    data = raw.encode("cp1252", errors="replace")
    return bytes(b if b >= 32 and _HELVETICA[b - 32] else 63 for b in data)


def text_width(text: object, size: float, bold: bool = False) -> float:
    """How wide the text is in points when set at this font size."""
    table = _HELVETICA_BOLD if bold else _HELVETICA
    return sum(table[b - 32] for b in encode(text)) * size / 1000.0


def fit(text: object, width: float, size: float, bold: bool = False) -> str:
    """The text cut short with "..." so it fits in the width, or unchanged when it already fits."""
    text = encode(text).decode("cp1252")
    if text_width(text, size, bold) <= width:
        return text
    room = width - text_width(ELLIPSIS, size, bold)
    table = _HELVETICA_BOLD if bold else _HELVETICA
    used, keep = 0.0, 0
    for ch in text:
        used += table[ord(ch.encode("cp1252")) - 32] * size / 1000.0
        if used > room:
            break
        keep += 1
    return text[:keep].rstrip() + ELLIPSIS if room > 0 else ""


def wrap(text: object, width: float, size: float, bold: bool = False) -> list[str]:
    """Splits text into lines that fit the width, breaking between words."""
    lines: list[str] = []
    line = ""
    for word in encode(text).decode("cp1252").split(" "):
        trial = f"{line} {word}" if line else word
        if line and text_width(trial, size, bold) > width:
            lines.append(line)
            line = word
        else:
            line = trial
    lines.append(line)
    return [fit(item, width, size, bold) for item in lines]


def _pdf_string(text: object) -> bytes:
    """A PDF literal string: brackets and backslashes get a backslash in front."""
    data = encode(text)
    data = data.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    return b"(" + data + b")"


def _n(value: float) -> str:
    """A number for the page description, with at most two decimals."""
    out = f"{value:.2f}".rstrip("0").rstrip(".")
    return "0" if out in ("-0", "") else out


def format_number(value: float) -> str:
    """A short readable number: 1234, 12.5, 0.75."""
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    digits = 0 if abs(value) >= 100 else 1 if abs(value) >= 10 else 2
    return f"{value:.{digits}f}".rstrip("0").rstrip(".")


def nice_ticks(low: float, high: float, count: int = 5) -> list[float]:
    """Round tick values (steps of 1, 2 or 5 times a power of ten) that cover low to high."""
    if high <= low:
        high = low + 1
    rough = (high - low) / max(count, 1)
    power = 10 ** math.floor(math.log10(rough))
    step = next(m * power for m in (1, 2, 5, 10) if m * power >= rough)
    start = math.floor(low / step) * step
    ticks, value = [], start
    while value <= high + step * 0.001:
        ticks.append(round(value, 10))
        value += step
    if ticks[-1] < high:
        ticks.append(round(value, 10))
    return ticks


_TIME_STEPS = [60, 300, 600, 900, 1800, 3600, 7200, 3 * 3600, 6 * 3600, 12 * 3600,
               86400, 2 * 86400, 7 * 86400, 14 * 86400, 30 * 86400, 91 * 86400, 365 * 86400]


def time_ticks(start: float, end: float, count: int = 6) -> tuple[list[float], str]:
    """Tick times (unix seconds, on round local hours or days) and a strftime format that suits the span."""
    span = max(end - start, 1)
    step = next((s for s in _TIME_STEPS if span / s <= count), _TIME_STEPS[-1])
    offset = time.localtime(start).tm_gmtoff or 0
    first = math.ceil((start + offset) / step) * step - offset
    ticks = []
    value = first
    while value <= end:
        ticks.append(value)
        value += step
    if step < 86400:
        fmt = "%H:%M" if span <= 86400 else "%d %b %H:%M"
    else:
        fmt = "%d %b" if span < 300 * 86400 else "%b %Y"
    return ticks, fmt


class Document:
    """A report being built page by page. Call render() at the end to get the PDF bytes."""

    def __init__(self, title: str = "Report", landscape: bool = False, footer: str = "Home Monitor") -> None:
        self.title = title
        self.footer = footer
        self.width, self.height = (A4[1], A4[0]) if landscape else A4
        self.left, self.right = MARGIN, self.width - MARGIN
        self.bottom = MARGIN
        self._pages: list[list[str]] = []
        self._y = 0.0
        self.new_page()

    # Page and cursor --------------------------------------------------------------------------

    @property
    def content_width(self) -> float:
        """The width between the side margins."""
        return self.right - self.left

    @property
    def page_count(self) -> int:
        """Pages so far."""
        return len(self._pages)

    def new_page(self) -> None:
        """Starts a fresh page and puts the cursor at its top."""
        self._pages.append([])
        self._y = self.height - MARGIN

    def _ensure(self, needed: float) -> None:
        """Moves to a new page when less than this much room is left (unless the page is still empty)."""
        if self._y - needed < self.bottom and self._pages[-1]:
            self.new_page()

    def space(self, points: float = 8) -> None:
        """Leaves a gap below what came before."""
        self._y -= points

    def _op(self, *ops: str) -> None:
        self._pages[-1].extend(ops)

    # Drawing helpers --------------------------------------------------------------------------

    def _draw_text(self, x: float, y: float, text: object, size: float, bold: bool = False,
                   color: Color = BLACK, align: str = "l", page: list[str] | None = None) -> None:
        """Puts one line of text with its baseline at y. Align "l", "r" (x is the right end) or "c"."""
        if align == "r":
            x -= text_width(text, size, bold)
        elif align == "c":
            x -= text_width(text, size, bold) / 2
        op = (f"BT /{'F2' if bold else 'F1'} {_n(size)} Tf {_rgb(color, 'rg')} {_n(x)} {_n(y)} Td "
              f"{_pdf_string(text).decode('latin-1')} Tj ET")
        (self._pages[-1] if page is None else page).append(op)

    def _rect(self, x: float, y: float, w: float, h: float, fill: Color) -> None:
        self._op(f"{_rgb(fill, 'rg')} {_n(x)} {_n(y)} {_n(w)} {_n(h)} re f")

    def _line(self, x1: float, y1: float, x2: float, y2: float, color: Color, width: float = 0.5) -> None:
        self._op(f"{_rgb(color, 'RG')} {_n(width)} w {_n(x1)} {_n(y1)} m {_n(x2)} {_n(y2)} l S")

    # Text -------------------------------------------------------------------------------------

    def heading(self, text: str, size: float = 18) -> None:
        """A large bold title line."""
        self.text(text, size=size, bold=True)
        self.space(2)

    def text(self, text: str, size: float = 10, color: Color = BLACK, bold: bool = False) -> None:
        """A paragraph, wrapped to the page width."""
        for line in wrap(text, self.content_width, size, bold):
            self._ensure(size * 1.3)
            self._draw_text(self.left, self._y - size, line, size, bold, color)
            self._y -= size * 1.3

    # Charts -----------------------------------------------------------------------------------

    def _chart_frame(self, title: str, height: float) -> tuple[float, float]:
        """Makes room for a chart and draws its title. Returns the top and bottom of the chart box."""
        self._ensure(height + 10)
        self._y -= 4
        top = self._y
        self._draw_text(self.left, top - 10, fit(title, self.content_width, 10, True), 10, True)
        self._y -= height + 10
        return top - 16, top - height

    def _no_data(self, x1: float, y1: float, x2: float, y2: float) -> None:
        self._op(f"{_rgb((0.8, 0.8, 0.8), 'RG')} 0.5 w {_n(x1)} {_n(y1)} {_n(x2 - x1)} {_n(y2 - y1)} re S")
        self._draw_text((x1 + x2) / 2, (y1 + y2) / 2 - 3, "No data", 9, color=GREY, align="c")

    def line_chart(self, title: str, series: Sequence[dict], y_unit: str = "", height: float = 190,
                   y_min: float | None = None, y_max: float | None = None) -> None:
        """A line chart over time. Each series is {"name": str, "points": [(unix seconds, value), ...]};
        a value of None leaves a gap in the line."""
        top, bottom = self._chart_frame(title, height)
        clean = [(s.get("name", ""), sorted((p for p in s.get("points", []) if p[0] is not None),
                                            key=lambda p: p[0])) for s in series]
        values = [v for _, pts in clean for _, v in pts if v is not None]
        times = [t for _, pts in clean for t, v in pts if v is not None]
        if not values:
            self._no_data(self.left, bottom, self.right, top)
            return
        low = min(0.0, min(values)) if y_min is None else y_min
        high = max(values) if y_max is None else y_max
        if y_max is None and y_unit == "%" and high <= 100:
            high = 100.0
        ticks = nice_ticks(low, high)
        low, high = ticks[0], ticks[-1]
        labels = [format_number(v) + y_unit for v in ticks]
        legend_h = 12 if len(clean) > 1 else 0
        px1 = self.left + max(text_width(s, 7) for s in labels) + 6
        px2, py1, py2 = self.right - 4, bottom + 14 + legend_h, top
        t0, t1 = min(times), max(times)
        if t1 <= t0:
            t0, t1 = t0 - 1800, t1 + 1800

        def sx(t: float) -> float:
            return px1 + (t - t0) / (t1 - t0) * (px2 - px1)

        def sy(v: float) -> float:
            return py1 + (v - low) / (high - low) * (py2 - py1)

        for value, label in zip(ticks, labels):
            y = sy(value)
            self._line(px1, y, px2, y, (0.88, 0.88, 0.88), 0.4)
            self._draw_text(px1 - 4, y - 2.5, label, 7, color=GREY, align="r")
        self._line(px1, py1, px1, py2, (0.5, 0.5, 0.5))
        self._line(px1, py1, px2, py1, (0.5, 0.5, 0.5))
        tick_times, fmt = time_ticks(t0, t1)
        last_end = -1e9
        for t in tick_times:
            label = time.strftime(fmt, time.localtime(t))
            x, half = sx(t), text_width(label, 7) / 2
            if x - half < last_end + 4 or x + half > self.right:
                continue
            self._line(x, py1, x, py1 - 3, (0.5, 0.5, 0.5))
            self._draw_text(x, py1 - 10, label, 7, color=GREY, align="c")
            last_end = x + half
        self._op("q", f"{_n(px1)} {_n(py1 - 1)} {_n(px2 - px1)} {_n(py2 - py1 + 2)} re W n")
        for index, (_, pts) in enumerate(clean):
            color = PALETTE[index % len(PALETTE)]
            for run in _runs(pts):
                if len(run) == 1:
                    x, y = sx(run[0][0]), sy(run[0][1])
                    self._rect(x - 1.2, y - 1.2, 2.4, 2.4, color)
                    continue
                path = " ".join(f"{_n(sx(t))} {_n(sy(v))} {'m' if i == 0 else 'l'}" for i, (t, v) in enumerate(run))
                self._op(f"{_rgb(color, 'RG')} 1.2 w 1 j {path} S")
        self._op("Q")
        if legend_h:
            x = px1
            for index, (name, _) in enumerate(clean):
                name = fit(name, 140, 7)
                if x + 12 + text_width(name, 7) > self.right:
                    break
                self._rect(x, bottom + 1, 7, 7, PALETTE[index % len(PALETTE)])
                self._draw_text(x + 10, bottom + 2, name, 7)
                x += 10 + text_width(name, 7) + 14

    def bar_chart(self, title: str, bars: Sequence[tuple[str, float]], unit: str = "",
                  color: Color | None = None) -> None:
        """Horizontal bars with a label on the left and the value at the end, good for a "top 10"."""
        row = 14.0
        height = 20 + max(len(bars), 2) * row
        top, bottom = self._chart_frame(title, height)
        items = [(str(label), float(value)) for label, value in bars if value is not None]
        if not items:
            self._no_data(self.left, bottom, self.right, top)
            return
        labels = [label for label, _ in items]
        values = [format_number(value) + unit for _, value in items]
        label_w = min(max(text_width(s, 8) for s in labels) + 8, self.content_width * 0.35)
        value_w = max(text_width(s, 8) for s in values) + 6
        x0 = self.left + label_w
        span = self.right - value_w - x0
        biggest = max(max(v for _, v in items), 0.0) or 1.0
        if unit == "%" and biggest <= 100:
            biggest = 100.0
        y = top
        for (label, value), shown in zip(items, values):
            y -= row
            self._draw_text(x0 - 6, y + 3, fit(label, label_w - 8, 8), 8, align="r")
            length = max(value, 0.0) / biggest * span
            self._rect(x0, y + 1, max(length, 0.5), row - 5, color or PALETTE[0])
            self._draw_text(x0 + length + 4, y + 3, shown, 8, color=GREY)
        self._line(x0, y, x0, top, (0.5, 0.5, 0.5))

    # Tables -----------------------------------------------------------------------------------

    def _column_widths(self, columns: Sequence[str], rows: Sequence[Sequence[object]], size: float,
                       widths: Sequence[float] | None) -> list[float]:
        """Column widths in points. Given widths are relative and scaled to the page width;
        otherwise each column asks for its widest cell (capped) and the page is shared out."""
        room = self.content_width
        if widths:
            total = sum(widths) or 1
            return [w / total * room for w in widths]
        want = []
        for i, name in enumerate(columns):
            widest = text_width(name, size, True)
            for row in rows[:500]:
                if i < len(row) and row[i] is not None:
                    widest = max(widest, text_width(row[i], size))
            want.append(min(widest + 10, 240.0))
        if sum(want) <= room:
            extra = (room - sum(want)) / len(want)
            return [w + extra for w in want]
        # Too wide: narrow columns keep what they asked for, the wide ones share what is left.
        fixed: dict[int, float] = {}
        while True:
            free = [i for i in range(len(want)) if i not in fixed]
            share = (room - sum(fixed.values())) / len(free)
            narrow = [i for i in free if want[i] <= share]
            if not narrow:
                break
            fixed.update((i, want[i]) for i in narrow)
        left = room - sum(fixed.values())
        asked = sum(want[i] for i in free)
        return [fixed[i] if i in fixed else want[i] / asked * left for i in range(len(want))]

    def table(self, columns: Sequence[str], rows: Iterable[Sequence[object]], widths: Sequence[float] | None = None,
              align: Sequence[str] | str | None = None, size: float = 8, zebra: bool = True) -> None:
        """A table that flows over pages, repeating the header row. align holds "l", "r" or "c" per column."""
        rows = [list(r) for r in rows]
        if not columns:
            return
        cols = self._column_widths(columns, rows, size, widths)
        aligns = [(align[i] if align and i < len(align) else "l") for i in range(len(columns))]
        row_h = size + 6

        def cell(x: float, w: float, y: float, value: object, how: str, bold: bool) -> None:
            text = fit("" if value is None else value, w - 8, size, bold)
            tx = x + w - 4 if how == "r" else x + w / 2 if how == "c" else x + 4
            self._draw_text(tx, y + 4, text, size, bold, align=how)

        def header() -> None:
            self._y -= row_h
            self._rect(self.left, self._y, self.content_width, row_h, (0.92, 0.92, 0.92))
            x = self.left
            for name, w, how in zip(columns, cols, aligns):
                cell(x, w, self._y, name, how, True)
                x += w
            self._line(self.left, self._y, self.right, self._y, (0.6, 0.6, 0.6), 0.6)

        self._ensure(row_h * 2)
        header()
        if not rows:
            self._y -= row_h
            self._draw_text(self.left + 4, self._y + 4, "No rows", size, color=GREY)
        for index, values in enumerate(rows):
            if self._y - row_h < self.bottom:
                self.new_page()
                header()
            self._y -= row_h
            if zebra and index % 2:
                self._rect(self.left, self._y, self.content_width, row_h, (0.97, 0.97, 0.97))
            x = self.left
            for i, (w, how) in enumerate(zip(cols, aligns)):
                cell(x, w, self._y, values[i] if i < len(values) else "", how, False)
                x += w
            self._line(self.left, self._y, self.right, self._y, (0.85, 0.85, 0.85), 0.3)
        self.space(10)

    # Output -----------------------------------------------------------------------------------

    def render(self) -> bytes:
        """The finished PDF file as bytes, with page footers and the document info added."""
        total = len(self._pages)
        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        catalog = add(b"<< /Type /Catalog /Pages 2 0 R >>")
        add(b"")  # The page tree, filled in once the page numbers are known.
        add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        stamp = time.strftime("D:%Y%m%d%H%M%SZ", time.gmtime())
        info = add(b"<< /Title " + _info_string(self.title) + b" /Producer (Home Monitor) /CreationDate ("
                   + stamp.encode() + b") >>")
        kids = []
        box = f"[0 0 {_n(self.width)} {_n(self.height)}]".encode()
        for number, ops in enumerate(self._pages, start=1):
            footer: list[str] = []
            self._draw_text(self.left, FOOTER_Y, self.footer, 8, color=GREY, page=footer)
            self._draw_text(self.right, FOOTER_Y, f"Page {number} of {total}", 8, color=GREY, align="r", page=footer)
            stream = zlib.compress("\n".join(ops + footer).encode("latin-1"))
            content = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream")
            kids.append(add(b"<< /Type /Page /Parent 2 0 R /MediaBox " + box
                            + b" /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>" % content))
        objects[1] = (b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % k for k in kids)
                      + b"] /Count %d >>" % total)
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
        start = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
        out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
        out += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\n" % (len(objects) + 1, catalog, info)
        out += b"startxref\n%d\n%%%%EOF\n" % start
        return bytes(out)


def _rgb(color: Color, operator: str) -> str:
    return " ".join(_n(max(0.0, min(1.0, c))) for c in color) + " " + operator


def _info_string(text: str) -> bytes:
    """A string for the document info: plain when it is simple text, otherwise UTF-16 so any script shows."""
    if all(32 <= ord(ch) < 127 for ch in text):
        return _pdf_string(text)
    return b"<FEFF" + text.encode("utf-16-be").hex().upper().encode() + b">"


def _runs(points: Sequence[tuple[float, float | None]]) -> list[list[tuple[float, float]]]:
    """Splits points into unbroken stretches: a None value ends one stretch."""
    runs: list[list[tuple[float, float]]] = [[]]
    for t, v in points:
        if v is None:
            if runs[-1]:
                runs.append([])
        else:
            runs[-1].append((t, float(v)))
    return [run for run in runs if run]
