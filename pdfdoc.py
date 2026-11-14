"""Small PDF writer for reports, built on the standard library only.

It writes PDF 1.4 files with the two built-in Helvetica fonts, so nothing has to be embedded and
every reader can open them. A document is built from the top down: a header band, a row of key
figures (KPI tiles), headings and paragraphs, charts (full width or two to a row) and tables with
status pills and small trend lines. Long tables flow over pages and repeat their header row. Page footers
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
# The app's own colours (its light theme, as paper is light). Series colours for ordinary data;
# green, amber and red only for status; grey for unknown or no data.
PALETTE: list[Color] = [
    (0.18, 0.51, 0.97), (0.10, 0.62, 0.62), (0.64, 0.44, 0.97),
    (0.35, 0.45, 0.60), (0.55, 0.34, 0.29), (0.45, 0.62, 0.95),
]
TONES: dict[str, Color] = {"good": (0.18, 0.63, 0.26), "warn": (0.82, 0.60, 0.13), "bad": (0.85, 0.21, 0.20),
                           "info": (0.18, 0.51, 0.97), "none": (0.55, 0.58, 0.62)}
TONE_TINT: dict[str, Color] = {"good": (0.86, 0.98, 0.88), "warn": (1.0, 0.97, 0.77), "bad": (1.0, 0.92, 0.91),
                               "info": (0.87, 0.96, 1.0), "none": (0.92, 0.93, 0.95)}
TONE_INK: dict[str, Color] = {"good": (0.10, 0.50, 0.22), "warn": (0.60, 0.40, 0.0), "bad": (0.81, 0.13, 0.18),
                              "info": (0.04, 0.41, 0.85), "none": (0.35, 0.39, 0.43)}
WHITE: Color = (1.0, 1.0, 1.0)
INK: Color = (0.12, 0.14, 0.16)
BAND: Color = (0.965, 0.973, 0.98)
RULE: Color = (0.82, 0.84, 0.87)
GRID: Color = (0.90, 0.91, 0.93)
AXIS: Color = (0.55, 0.57, 0.6)
TRACK: Color = (0.93, 0.94, 0.95)
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


def exact_ticks(low: float, high: float) -> list[float]:
    """Ticks from exactly low to exactly high (a zoomed axis starts where the report says it does),
    in four or five even steps."""
    span = high - low
    if span <= 0:
        return [low, low + 1]
    for n in (5, 4, 2):
        step = span / n
        if abs(step * 100 - round(step * 100)) < 1e-6:
            return [round(low + k * step, 6) for k in range(n + 1)]
    return [low, high]


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



def format_value(value: float | None, unit: str = "") -> str:
    """A value with its unit, short enough for an axis or a bar end: 42%, 12 ms, 1.2 Mbps, 3 min."""
    if value is None:
        return ""
    if unit in ("bps", "B"):
        v = float(value)
        units, base = (["bps", "Kbps", "Mbps", "Gbps", "Tbps"], 1000.0) if unit == "bps" else (["B", "KB", "MB", "GB", "TB", "PB"], 1024.0)
        i = 0
        while abs(v) >= base and i < len(units) - 1:
            v /= base
            i += 1
        return f"{format_number(round(v, 0 if abs(v) >= 100 or i == 0 else 1))} {units[i]}"
    if unit == "%":
        return format_number(value) + "%"
    if unit in ("ms", "min", "h", "d"):
        return f"{format_number(value)} {unit}"
    return format_number(value) + (f" {unit}" if unit else "")


def mix(color: Color, other: Color, amount: float) -> Color:
    """A colour moved towards another (amount 0 keeps it, 1 gives the other): a tint on paper."""
    return tuple(c + (o - c) * amount for c, o in zip(color, other))  # type: ignore[return-value]


def split_marks(marks: Sequence[dict], top: float, y_max: float | None) -> tuple[list[dict], list[dict]]:
    """Thresholds to draw and those so far above the data (over twice its highest value) that
    drawing them would flatten the chart; those are only named in the legend."""
    if y_max is not None:
        return list(marks), []
    near = [m for m in marks if m.get("value") is not None and m["value"] <= max(top, 0) * 2]
    return near, [m for m in marks if m not in near]


class Pill:
    """A table cell drawn as a small coloured label: Pill("Met", "good")."""

    def __init__(self, text: object, tone: str = "none") -> None:
        self.text, self.tone = str(text), tone if tone in TONES else "none"

    def __str__(self) -> str:
        return self.text + "  "


class Spark:
    """A table cell drawn as a small line of the values (None leaves a gap)."""

    def __init__(self, values: Sequence[float | None]) -> None:
        self.values = list(values)

    def __str__(self) -> str:
        return "M" * 9


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

    def _line(self, x1: float, y1: float, x2: float, y2: float, color: Color, width: float = 0.5,
              dash: str = "") -> None:
        if dash:
            self._op(f"[{dash}] 0 d {_rgb(color, 'RG')} {_n(width)} w {_n(x1)} {_n(y1)} m {_n(x2)} {_n(y2)} l S [] 0 d")
        else:
            self._op(f"{_rgb(color, 'RG')} {_n(width)} w {_n(x1)} {_n(y1)} m {_n(x2)} {_n(y2)} l S")

    def _round_rect(self, x: float, y: float, w: float, h: float, r: float, fill: Color | None = None,
                    stroke: Color | None = None, width: float = 0.5) -> None:
        """A rectangle with rounded corners (Bezier quarter circles), filled, outlined or both."""
        r = max(0.0, min(r, w / 2, h / 2))
        k = 0.5523 * r
        p = [f"{_n(x + r)} {_n(y)} m", f"{_n(x + w - r)} {_n(y)} l",
             f"{_n(x + w - r + k)} {_n(y)} {_n(x + w)} {_n(y + r - k)} {_n(x + w)} {_n(y + r)} c",
             f"{_n(x + w)} {_n(y + h - r)} l",
             f"{_n(x + w)} {_n(y + h - r + k)} {_n(x + w - r + k)} {_n(y + h)} {_n(x + w - r)} {_n(y + h)} c",
             f"{_n(x + r)} {_n(y + h)} l",
             f"{_n(x + r - k)} {_n(y + h)} {_n(x)} {_n(y + h - r + k)} {_n(x)} {_n(y + h - r)} c",
             f"{_n(x)} {_n(y + r)} l",
             f"{_n(x)} {_n(y + r - k)} {_n(x + r - k)} {_n(y)} {_n(x + r)} {_n(y)} c", "h"]
        paint = "B" if fill and stroke else "f" if fill else "S"
        colours = (_rgb(fill, "rg") + " " if fill else "") + (f"{_rgb(stroke, 'RG')} {_n(width)} w " if stroke else "")
        self._op(colours + " ".join(p) + " " + paint)

    def _polygon(self, points: Sequence[tuple[float, float]], fill: Color) -> None:
        if len(points) < 3:
            return
        path = " ".join(f"{_n(px)} {_n(py)} {'m' if i == 0 else 'l'}" for i, (px, py) in enumerate(points))
        self._op(f"{_rgb(fill, 'rg')} {path} h f")

    def _polyline(self, points: Sequence[tuple[float, float]], color: Color, width: float = 1.2) -> None:
        if len(points) == 1:
            self._rect(points[0][0] - 1.2, points[0][1] - 1.2, 2.4, 2.4, color)
        elif points:
            path = " ".join(f"{_n(px)} {_n(py)} {'m' if i == 0 else 'l'}" for i, (px, py) in enumerate(points))
            self._op(f"{_rgb(color, 'RG')} {_n(width)} w 1 j {path} S")

    def _clip(self, x: float, y: float, w: float, h: float) -> None:
        self._op("q", f"{_n(x)} {_n(y)} {_n(w)} {_n(h)} re W n")

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

    def section(self, title: str, note: str = "") -> None:
        """A small bold heading for a part of the report, with an optional grey line under it."""
        self._ensure(40)
        self._y -= 4
        self._draw_text(self.left, self._y - 11, fit(title, self.content_width, 11, True), 11, True, INK)
        self._y -= 15
        if note:
            for line in wrap(note, self.content_width, 8)[:2]:
                self._draw_text(self.left, self._y - 8, line, 8, color=GREY)
                self._y -= 10.5
        self._y -= 3

    # Report blocks ----------------------------------------------------------------------------

    def header_band(self, title: str, purpose: str = "", facts: Sequence[tuple[str, object]] = ()) -> None:
        """The report's opening band: the title, a line on what it is for and the facts (period,
        what it covers, when it was made, a device's details) as small labelled values."""
        pad = 12.0
        inner = self.content_width - 2 * pad
        purpose_lines = wrap(purpose, inner, 9.5)[:3] if purpose else []
        per_row = 4 if self.width < 700 else 6
        col_w = inner / per_row
        facts = [(str(k), "" if v is None else str(v)) for k, v in facts]
        # Each fact takes as many columns as its value needs (a long period takes two), row by row.
        placed: list[tuple[int, int, int, str, str]] = []
        row, col = 0, 0
        for label, value in facts:
            span = min(per_row, max(1, math.ceil((text_width(value, 8.5, True) + 10) / col_w)))
            if col + span > per_row:
                row, col = row + 1, 0
            placed.append((row, col, span, label, value))
            col += span
        rows = row + 1 if facts else 0
        height = pad + 20 + len(purpose_lines) * 12.5 + (6 + rows * 24 if rows else 0) + pad - 4
        self._ensure(height + 8)
        top = self._y
        self._round_rect(self.left, top - height, self.content_width, height, 6, fill=BAND, stroke=RULE)
        y = top - pad - 16
        self._draw_text(self.left + pad, y, fit(title, inner, 17, True), 17, True, INK)
        y -= 6
        for line in purpose_lines:
            y -= 12.5
            self._draw_text(self.left + pad, y + 3, line, 9.5, color=GREY)
        if rows:
            y -= 8
            self._line(self.left + pad, y, self.right - pad, y, RULE, 0.5)
            for row, col, span, label, value in placed:
                cx = self.left + pad + col * col_w
                cy = y - 10 - row * 24
                self._draw_text(cx, cy, fit(label.upper(), span * col_w - 8, 6.5), 6.5, color=GREY)
                self._draw_text(cx, cy - 11, fit(value, span * col_w - 8, 8.5, True), 8.5, True, INK)
        self._y = top - height - 10

    def kpi_tiles(self, tiles: Sequence[dict]) -> None:
        """A row of key figures. Each tile: {"label", "value", "tone" (good, warn, bad, info),
        "sub" (a small line under the value), "note" (the comparison), "trend" (good, bad or neutral)}."""
        tiles = list(tiles)[:6]
        if not tiles:
            return
        gap = 8.0
        w = (self.content_width - gap * (len(tiles) - 1)) / len(tiles)
        notes = [wrap(t.get("note") or "", w - 16, 7)[:2] if t.get("note") else [] for t in tiles]
        height = 50 + (9 if any(t.get("sub") for t in tiles) else 0) + 8.5 * max(len(n) for n in notes)
        self._ensure(height + 10)
        top = self._y
        for i, (tile, lines) in enumerate(zip(tiles, notes)):
            x = self.left + i * (w + gap)
            tone = tile.get("tone") if tile.get("tone") in TONES else "info"
            self._round_rect(x, top - height, w, height, 5, fill=WHITE, stroke=RULE)
            self._rect(x + 0.6, top - height + 3, 3, height - 6, TONES[tone])
            self._draw_text(x + 10, top - 13, fit(tile.get("label", ""), w - 16, 7.5), 7.5, color=GREY)
            self._draw_text(x + 10, top - 33, fit(tile.get("value", ""), w - 16, 16, True), 16, True, INK)
            y = top - 33
            if tile.get("sub"):
                y -= 10
                self._draw_text(x + 10, y, fit(tile["sub"], w - 16, 7), 7, color=GREY)
            colour = {"good": TONE_INK["good"], "bad": TONE_INK["bad"]}.get(tile.get("trend") or "", GREY)
            for line in lines:
                y -= 9
                self._draw_text(x + 10, y, line, 7, color=colour)
        self._y = top - height - 12

    # Charts -----------------------------------------------------------------------------------

    def chart(self, spec: dict) -> None:
        """One chart across the full width (see chart_grid for the kinds and their fields)."""
        self.chart_grid([spec], columns=1)

    def chart_grid(self, specs: Sequence[dict], columns: int = 2) -> None:
        """Charts side by side, row by row, each with its title and a one-line note on how to read it.

        Kinds: line (series over time, with thresholds and bands), mirror (in above the axis, out
        below), bar (horizontal bars, capacity bars with thresholds), columns (vertical bars per
        category, stacked, with a target line), donut (parts of a total), strips (one small bar per
        day per row, coloured by its tone), heatmap (hour by weekday) and grid (one tile per device)."""
        specs = [s for s in specs if s]
        gap = 14.0
        w = (self.content_width - gap * (columns - 1)) / columns
        for start in range(0, len(specs), columns):
            row = specs[start:start + columns]
            heads = [self._chart_head_lines(s, w) for s in row]
            bodies = [self._chart_height(s, w, columns == 1) for s in row]
            height = max(16 + 9 * len(n) + b for n, b in zip(heads, bodies)) + 4
            self._ensure(height + 6)
            top = self._y
            for i, (spec, notes) in enumerate(zip(row, heads)):
                x = self.left + i * (w + gap)
                self._draw_text(x, top - 10, fit(spec.get("title", ""), w, 10, True), 10, True, INK)
                y = top - 14
                for line in notes:
                    y -= 9
                    self._draw_text(x, y + 1.5, line, 7.5, color=GREY)
                body_h = bodies[i]
                self._draw_chart(spec, x, y - 4 - body_h, w, body_h)
            self._y = top - height - 10

    def _chart_head_lines(self, spec: dict, w: float) -> list[str]:
        return wrap(spec["note"], w, 7.5)[:2] if spec.get("note") else []

    def _chart_height(self, spec: dict, w: float, full: bool) -> float:
        kind = spec.get("kind")
        if kind == "bar":
            return 8 + max(len(spec.get("bars") or []), 2) * 13
        if kind == "donut":
            return 120
        if kind == "strips":
            return 16 + max(len(spec.get("rows") or []), 1) * 13
        if kind == "heatmap":
            return 7 * 13 + 26
        if kind == "grid":
            per_row = max(1, int((w + 6) // 96))
            return max(1, -(-len(spec.get("tiles") or []) // per_row)) * 32
        return 170 if full else 140

    def _draw_chart(self, spec: dict, x: float, y: float, w: float, h: float) -> None:
        draw = {"line": self._draw_line, "mirror": self._draw_mirror, "bar": self._draw_bars,
                "columns": self._draw_columns, "donut": self._draw_donut, "strips": self._draw_strips,
                "heatmap": self._draw_heatmap, "grid": self._draw_grid}.get(spec.get("kind"))
        if draw is None or not draw(spec, x, y, w, h):
            self._no_data(x, y, x + w, y + h)

    def _no_data(self, x1: float, y1: float, x2: float, y2: float) -> None:
        self._op(f"{_rgb((0.8, 0.8, 0.8), 'RG')} 0.5 w {_n(x1)} {_n(y1)} {_n(x2 - x1)} {_n(y2 - y1)} re S")
        self._draw_text((x1 + x2) / 2, (y1 + y2) / 2 - 3, "No data", 9, color=GREY, align="c")

    def _legend(self, items: Sequence[tuple[str, Color, bool]], x: float, y: float, right: float) -> None:
        """Small keys in a row: (name, colour, dashed line instead of a square)."""
        for name, color, dashed in items:
            name = fit(name, 150, 7)
            if x + 14 + text_width(name, 7) > right:
                break
            if dashed:
                self._line(x, y + 3, x + 9, y + 3, color, 1, "2 1.5")
            else:
                self._rect(x, y, 7, 7, color)
            self._draw_text(x + 11, y + 1, name, 7)
            x += 11 + text_width(name, 7) + 12

    def _y_axis(self, low: float, high: float, unit: str, x: float, y1: float, y2: float, right: float,
                count: int = 4, whole: bool = False, exact: bool = False) -> tuple[list[float], float]:
        """Grid lines and labels for a value axis. Returns the ticks and where the plot starts."""
        ticks = exact_ticks(low, high) if exact else nice_ticks(low, high, count)
        if whole:
            ticks = [t for t in ticks if float(t).is_integer()] or [0, 1]
            if len(ticks) < 2:
                ticks.append(ticks[0] + 1)
        labels = [format_value(v, unit) for v in ticks]
        px = x + max(text_width(s, 7) for s in labels) + 6
        lo, hi = ticks[0], ticks[-1]
        for value, label in zip(ticks, labels):
            yy = y1 + (value - lo) / ((hi - lo) or 1) * (y2 - y1)
            self._line(px, yy, right, yy, GRID, 0.4)
            self._draw_text(px - 4, yy - 2.5, label, 7, color=GREY, align="r")
        return ticks, px

    def _time_axis(self, t0: float, t1: float, px1: float, px2: float, y: float) -> None:
        tick_times, fmt = time_ticks(t0, t1)
        last_end = -1e9
        for t in tick_times:
            label = time.strftime(fmt, time.localtime(t)).lstrip("0")
            xx = px1 + (t - t0) / ((t1 - t0) or 1) * (px2 - px1)
            half = text_width(label, 7) / 2
            if xx - half < last_end + 4 or xx + half > px2 + 20:
                continue
            self._line(xx, y, xx, y - 3, AXIS)
            self._draw_text(xx, y - 10, label, 7, color=GREY, align="c")
            last_end = xx + half

    def _draw_line(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        unit = spec.get("unit") or ""
        clean = [(s.get("name", ""), s.get("tone"), sorted((p for p in s.get("points", []) if p[0] is not None),
                                                         key=lambda p: p[0])) for s in spec.get("series", [])]
        values = [v for _, _, pts in clean for _, v in pts if v is not None]
        times = [t for _, _, pts in clean for t, v in pts if v is not None]
        if not values:
            return False
        shown_marks, far = split_marks(spec.get("thresholds") or [], max(values),
                                       spec.get("y_max") if spec.get("y_max") is not None else 100 if unit == "%" else None)
        marks = [t["value"] for t in shown_marks]
        low = min(0.0, min(values)) if spec.get("y_min") is None else spec["y_min"]
        high = max(values + marks) if spec.get("y_max") is None else spec["y_max"]
        if spec.get("y_max") is None and unit == "%" and high <= 100:
            high = 100.0
        legend = [(name, self._series_colour(i, tone), False) for i, (name, tone, _) in enumerate(clean)] if len(clean) > 1 else []
        legend += [(t.get("label", ""), TONES.get(t.get("tone"), GREY), True) for t in shown_marks if t.get("label")]
        legend += [(t.get("label", "") + ", above the chart", TONES.get(t.get("tone"), GREY), True) for t in far if t.get("label")]
        legend_h = 12 if legend else 0
        py1, py2 = y + 14 + legend_h, y + h
        ticks, px1 = self._y_axis(low, high, unit, x, py1, py2, x + w)
        low, high = ticks[0], ticks[-1]
        px2 = x + w - 4
        t0, t1 = spec.get("start") or min(times), spec.get("end") or max(times)
        if t1 <= t0:
            t0, t1 = t0 - 1800, t1 + 1800

        def sx(t: float) -> float:
            return px1 + (t - t0) / (t1 - t0) * (px2 - px1)

        def sy(v: float) -> float:
            return py1 + (max(low, min(high, v)) - low) / ((high - low) or 1) * (py2 - py1)

        for band in spec.get("bands") or []:
            b1, b2 = sy(band["from"]), sy(band["to"])
            self._rect(px1, b1, px2 - px1, b2 - b1, TONE_TINT.get(band.get("tone"), TONE_TINT["none"]))
        self._line(px1, py1, px1, py2, AXIS)
        self._line(px1, py1, px2, py1, AXIS)
        self._time_axis(t0, t1, px1, px2, py1)
        for mark in shown_marks:
            yy = sy(mark["value"])
            self._line(px1, yy, px2, yy, TONES.get(mark.get("tone"), GREY), 0.9, "3 2")
        self._clip(px1, py1 - 1, px2 - px1, py2 - py1 + 2)
        for index, (_, tone, pts) in enumerate(clean):
            color = self._series_colour(index, tone)
            for run in _runs(pts):
                self._polyline([(sx(t), sy(v)) for t, v in run], color)
        self._op("Q")
        if legend:
            self._legend(legend, px1, y + 1, x + w)
        return True

    def _series_colour(self, index: int, tone: str | None) -> Color:
        return TONES[tone] if tone in TONES else PALETTE[index % len(PALETTE)]

    def _draw_mirror(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        unit = spec.get("unit") or ""
        ins = sorted((p for p in spec.get("in") or [] if p[0] is not None), key=lambda p: p[0])
        outs = sorted((p for p in spec.get("out") or [] if p[0] is not None), key=lambda p: p[0])
        values = [abs(v) for _, v in ins + outs if v is not None]
        if not values:
            return False
        top = max(values + [spec.get("line") or 0]) or 1.0
        ticks = nice_ticks(0, top, 2)
        top = ticks[-1]
        labels = [format_value(v, unit) for v in ticks]
        px1 = x + max(text_width(s, 7) for s in labels) + 6
        px2 = x + w - 4
        py1, py2 = y + 26, y + h
        mid = (py1 + py2) / 2
        times = [t for t, v in ins + outs if v is not None]
        t0, t1 = spec.get("start") or min(times), spec.get("end") or max(times)
        if t1 <= t0:
            t0, t1 = t0 - 1800, t1 + 1800

        def sx(t: float) -> float:
            return px1 + (t - t0) / (t1 - t0) * (px2 - px1)

        half = (py2 - py1) / 2
        for value, label in zip(ticks, labels):
            for sign in ((1,) if value == 0 else (1, -1)):
                yy = mid + sign * value / top * half
                self._line(px1, yy, px2, yy, GRID, 0.4)
                self._draw_text(px1 - 4, yy - 2.5, label, 7, color=GREY, align="r")
        colours = (PALETTE[0], PALETTE[1])
        self._clip(px1, py1 - 1, px2 - px1, py2 - py1 + 2)
        for pts, sign, colour in ((ins, 1, colours[0]), (outs, -1, colours[1])):
            for run in _runs(pts):
                line = [(sx(t), mid + sign * min(abs(v), top) / top * half) for t, v in run]
                self._polygon([(line[0][0], mid)] + line + [(line[-1][0], mid)], mix(colour, WHITE, 0.6))
                self._polyline(line, colour, 1)
        if spec.get("line"):
            for sign in (1, -1):
                yy = mid + sign * min(spec["line"], top) / top * half
                self._line(px1, yy, px2, yy, GREY, 0.8, "3 2")
        self._op("Q")
        self._line(px1, mid, px2, mid, AXIS, 0.6)
        self._line(px1, py1, px1, py2, AXIS)
        self._time_axis(t0, t1, px1, px2, py1)
        self._legend([(spec.get("in_label") or "In", colours[0], False), (spec.get("out_label") or "Out", colours[1], False)]
                     + ([(spec.get("line_label") or "", GREY, True)] if spec.get("line") and spec.get("line_label") else []),
                     px1, y + 1, x + w)
        return True

    def _draw_bars(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        unit = spec.get("unit") or ""
        items = [(str(b[0]), float(b[1]), b[2] if len(b) > 2 else None) for b in spec.get("bars") or [] if b[1] is not None]
        if not items:
            return False
        row = 13.0
        shown = [format_value(v, unit) for _, v, _ in items]
        label_w = min(max(text_width(label, 7.5) for label, _, _ in items) + 8, w * 0.38)
        value_w = max(text_width(s, 7.5) for s in shown) + 6
        x0 = x + label_w
        span = max(10.0, x + w - value_w - x0)
        biggest = spec.get("max") or max(max(v for _, v, _ in items), 0.0) or 1.0
        if unit == "%" and biggest <= 100 and not spec.get("max"):
            biggest = 100.0
        yy = y + h
        for (label, value, tone), text in zip(items, shown):
            yy -= row
            self._draw_text(x0 - 6, yy + 3, fit(label, label_w - 8, 7.5), 7.5, align="r")
            self._rect(x0, yy + 1.5, span, row - 5, TRACK)
            length = max(0.0, min(value, biggest)) / biggest * span
            self._rect(x0, yy + 1.5, max(length, 0.5), row - 5, TONES[tone] if tone in TONES else PALETTE[0])
            self._draw_text(x0 + span + 4, yy + 3, text, 7.5, color=GREY)
        for mark in spec.get("thresholds") or []:
            mx = x0 + min(mark["value"], biggest) / biggest * span
            self._line(mx, yy, mx, y + h, TONES.get(mark.get("tone"), GREY), 0.8, "2 1.5")
        self._line(x0, yy, x0, y + h, AXIS)
        return True

    def _draw_columns(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        unit = spec.get("unit") or ""
        labels = [str(s) for s in spec.get("labels") or []]
        series = [s for s in spec.get("series") or [] if s.get("values")]
        if not labels or not series:
            return False
        stacked = spec.get("stacked", True)
        totals = [sum(max(0.0, float(s["values"][i] or 0)) for s in series) if stacked else
                  max(float(s["values"][i] or 0) for s in series) for i in range(len(labels))]
        target = spec.get("target") or {}
        if target and not spec.get("y_max") and split_marks([target], max(totals), None)[1]:
            target = dict(target, value=None, label=(target.get("label") or "") + ", above the chart" if target.get("label") else "")
        low = spec.get("y_min") or 0.0
        high = spec.get("y_max") or max(totals + [target.get("value") or 0]) or 1.0
        legend = [(s.get("name", ""), self._series_colour(i, s.get("tone")), False) for i, s in enumerate(series)] if len(series) > 1 else []
        if target.get("label"):
            legend.append((target["label"], TONES.get(target.get("tone"), GREY), True))
        py1, py2 = y + 14 + (12 if legend else 0), y + h
        ticks, px1 = self._y_axis(low, high, unit, x, py1, py2, x + w, whole=bool(spec.get("whole")),
                                    exact=bool(spec.get("y_min")) and spec.get("y_max") is not None)
        low, high = ticks[0], ticks[-1]
        px2 = x + w - 2

        def sy(v: float) -> float:
            return py1 + (max(low, min(high, v)) - low) / ((high - low) or 1) * (py2 - py1)

        slot = (px2 - px1) / len(labels)
        bar_w = max(1.0, slot * 0.72)
        tones = spec.get("bar_tones") or []
        for i in range(len(labels)):
            bx = px1 + i * slot + (slot - bar_w) / 2
            base = low
            for si, s in enumerate(series):
                value = s["values"][i]
                if value is None:
                    continue
                tone = tones[i] if len(series) == 1 and i < len(tones) and tones[i] else s.get("tone")
                colour = self._series_colour(si, tone)
                top = base + max(0.0, float(value)) if stacked else float(value)
                if sy(top) - sy(base) > 0.05:
                    self._rect(bx, sy(base), bar_w, sy(top) - sy(base), colour)
                if stacked:
                    base = top
        self._line(px1, py1, px2, py1, AXIS)
        if target.get("value") is not None:
            ty = sy(target["value"])
            self._line(px1, ty, px2, ty, TONES.get(target.get("tone"), GREY), 0.9, "3 2")
        every = max(1, math.ceil(max(text_width(s, 6.5) for s in labels) / max(slot - 2, 1)))
        for i, label in enumerate(labels):
            if i % every == 0:
                self._draw_text(px1 + i * slot + slot / 2, py1 - 9, label, 6.5, color=GREY, align="c")
        if legend:
            self._legend(legend, px1, y + 1, x + w)
        return True

    def _draw_donut(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        parts = [(str(p["label"]), float(p["value"]), p.get("tone")) for p in spec.get("segments") or []
                 if p.get("value") and p["value"] > 0]
        total = sum(v for _, v, _ in parts)
        if not parts or total <= 0:
            return False
        r_out = min(h / 2 - 2, w * 0.22)
        r_in = r_out * 0.62
        cx, cy = x + r_out + 4, y + h / 2
        angle = math.pi / 2
        for index, (_, value, tone) in enumerate(parts):
            sweep = value / total * 2 * math.pi
            steps = max(2, int(sweep / 0.06))
            outer = [(cx + r_out * math.cos(angle - sweep * k / steps), cy + r_out * math.sin(angle - sweep * k / steps))
                     for k in range(steps + 1)]
            inner = [(cx + r_in * math.cos(angle - sweep * k / steps), cy + r_in * math.sin(angle - sweep * k / steps))
                     for k in range(steps, -1, -1)]
            self._polygon(outer + inner, self._series_colour(index, tone))
            if len(parts) > 1:
                self._line(cx + r_in * math.cos(angle), cy + r_in * math.sin(angle),
                           cx + r_out * math.cos(angle), cy + r_out * math.sin(angle), WHITE, 1.2)
            angle -= sweep
        self._draw_text(cx, cy - 2, format_number(spec.get("total", total)), 15, True, INK, align="c")
        if spec.get("total_label"):
            self._draw_text(cx, cy - 12, fit(spec["total_label"], r_in * 2 - 4, 6.5), 6.5, color=GREY, align="c")
        lx = cx + r_out + 14
        ly = cy + len(parts) * 7
        for index, (label, value, tone) in enumerate(parts):
            ly -= 14
            self._rect(lx, ly, 7, 7, self._series_colour(index, tone))
            text = f"{format_number(value)}  {label}"
            self._draw_text(lx + 11, ly + 0.5, fit(text, x + w - lx - 12, 8), 8)
        return True

    def _draw_strips(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = spec.get("rows") or []
        if not rows or not any(r.get("cells") for r in rows):
            return False
        label_w = min(max(text_width(r.get("name", ""), 7.5) for r in rows) + 8, w * 0.3)
        value_w = max(text_width(r.get("value_text", ""), 7.5) for r in rows) + 8
        x0, x1 = x + label_w, x + w - value_w
        yy = y + h
        for r in rows:
            yy -= 13
            cells = r.get("cells") or []
            self._draw_text(x0 - 6, yy + 3, fit(r.get("name", ""), label_w - 8, 7.5), 7.5, align="r")
            self._draw_text(x + w, yy + 3, r.get("value_text", ""), 7.5, color=GREY, align="r")
            if cells:
                slot = (x1 - x0) / len(cells)
                gap = min(1.0, slot * 0.25)
                for i, cell in enumerate(cells):
                    tone = cell[1] if len(cell) > 1 and cell[1] in TONES else "none"
                    self._rect(x0 + i * slot, yy + 1, max(0.4, slot - gap), 9, TONES[tone] if tone != "none" else TRACK)
        self._draw_text(x0, yy - 9, spec.get("start_text", ""), 6.5, color=GREY)
        self._draw_text(x1, yy - 9, spec.get("end_text", ""), 6.5, color=GREY, align="r")
        return True

    def _draw_heatmap(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        grid = spec.get("values") or []
        flat = [v for row in grid for v in row if v is not None]
        if not flat:
            return False
        top = spec.get("max") or max(flat) or 1.0
        names = spec.get("rows") or [""] * len(grid)
        label_w = max(text_width(n, 7) for n in names) + 6
        cols = max(len(row) for row in grid)
        cell_w = (w - label_w) / cols
        yy = y + h
        for name, row in zip(names, grid):
            yy -= 13
            self._draw_text(x + label_w - 5, yy + 3, name, 7, color=GREY, align="r")
            for i, value in enumerate(row):
                colour = TRACK if value is None else mix(WHITE, PALETTE[0], 0.08 + 0.92 * max(0.0, min(1.0, value / top)))
                self._rect(x + label_w + i * cell_w, yy + 0.5, max(0.5, cell_w - 1), 12, colour)
        for hour in range(0, cols, 3):
            self._draw_text(x + label_w + (hour + 0.5) * cell_w, yy - 9, f"{hour:02d}", 6.5, color=GREY, align="c")
        lx = x + label_w
        self._draw_text(lx, yy - 21, "Low", 6.5, color=GREY)
        for k in range(10):
            self._rect(lx + 18 + k * 7, yy - 22, 7, 6, mix(WHITE, PALETTE[0], 0.08 + 0.092 * k))
        self._draw_text(lx + 92, yy - 21, f"High ({format_value(top, spec.get('unit') or '')})", 6.5, color=GREY)
        return True

    def _draw_grid(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        tiles = spec.get("tiles") or []
        if not tiles:
            return False
        per_row = max(1, int((w + 6) // 96))
        tw = (w - 6 * (per_row - 1)) / per_row
        for i, tile in enumerate(tiles):
            tx = x + (i % per_row) * (tw + 6)
            ty = y + h - (i // per_row + 1) * 32 + 4
            tone = tile.get("tone") if tile.get("tone") in TONES else "none"
            self._round_rect(tx, ty, tw, 26, 3, fill=TONE_TINT[tone])
            self._rect(tx, ty + 2, 2.5, 22, TONES[tone])
            self._draw_text(tx + 7, ty + 15, fit(tile.get("label", ""), tw - 10, 7.5, True), 7.5, True, INK)
            self._draw_text(tx + 7, ty + 5, fit(tile.get("sub", ""), tw - 10, 6.5), 6.5, color=TONE_INK[tone])
        return True

    def line_chart(self, title: str, series: Sequence[dict], y_unit: str = "", height: float = 190,
                   y_min: float | None = None, y_max: float | None = None) -> None:
        """A line chart over time across the page. Each series is {"name": str, "points": [(unix
        seconds, value), ...]}; a value of None leaves a gap in the line."""
        self.chart({"kind": "line", "title": title, "series": series, "unit": y_unit, "y_min": y_min, "y_max": y_max})

    def bar_chart(self, title: str, bars: Sequence[tuple[str, float]], unit: str = "",
                  color: Color | None = None) -> None:
        """Horizontal bars with a label on the left and the value at the end, good for a "top 10"."""
        self.chart({"kind": "bar", "title": title, "bars": [tuple(b) for b in bars], "unit": unit})

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
        """A table that flows over pages, repeating the header row. align holds "l", "r" or "c" per column.
        A cell may be a Pill (a coloured status label) or a Spark (a small line of values)."""
        rows = [list(r) for r in rows]
        if not columns:
            return
        cols = self._column_widths(columns, rows, size, widths)
        aligns = [(align[i] if align and i < len(align) else "l") for i in range(len(columns))]
        row_h = size + 6

        def cell(x: float, w: float, y: float, value: object, how: str, bold: bool) -> None:
            if isinstance(value, Pill):
                text = fit(value.text, w - 16, size - 0.5)
                pw = text_width(text, size - 0.5) + 10
                px = x + w - 4 - pw if how == "r" else x + 4
                self._round_rect(px, y + 1.8, pw, size + 2.6, (size + 2.6) / 2, fill=TONE_TINT[value.tone])
                self._draw_text(px + 5, y + 4.2, text, size - 0.5, color=TONE_INK[value.tone])
                return
            if isinstance(value, Spark):
                vals = [v for v in value.values if v is not None]
                if len(vals) > 1:
                    lo, hi = min(vals), max(vals)
                    sx0, sw = x + 4, min(w - 8, 60)
                    step = sw / max(len(value.values) - 1, 1)
                    for run in _runs([(i, v) for i, v in enumerate(value.values)]):
                        self._polyline([(sx0 + i * step, y + 2.5 + (v - lo) / ((hi - lo) or 1) * (size + 1))
                                        for i, v in run], PALETTE[0], 0.8)
                return
            text = fit("" if value is None else value, w - 8, size, bold)
            tx = x + w - 4 if how == "r" else x + w / 2 if how == "c" else x + 4
            self._draw_text(tx, y + 4, text, size, bold, align=how)

        def header() -> None:
            self._y -= row_h
            self._rect(self.left, self._y, self.content_width, row_h, BAND)
            x = self.left
            for name, w, how in zip(columns, cols, aligns):
                cell(x, w, self._y, name, how, True)
                x += w
            self._line(self.left, self._y, self.right, self._y, RULE, 0.6)

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
                self._rect(self.left, self._y, self.content_width, row_h, (0.98, 0.98, 0.985))
            x = self.left
            for i, (w, how) in enumerate(zip(cols, aligns)):
                cell(x, w, self._y, values[i] if i < len(values) else "", how, False)
                x += w
            self._line(self.left, self._y, self.right, self._y, GRID, 0.3)
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
            room = self.content_width - text_width(f"Page {number} of {total}", 8) - 16
            self._draw_text(self.left, FOOTER_Y, fit(self.footer, room, 8), 8, color=GREY, page=footer)
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
