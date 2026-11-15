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
    (0.97, 0.55, 0.25), (0.54, 0.60, 0.68), (0.45, 0.62, 0.95),
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


NAVY: Color = (0.106, 0.165, 0.255)
ORANGE: Color = (0.969, 0.549, 0.251)
SOFT_GREY: Color = (0.54, 0.60, 0.68)


def _tone_colour(tone: str | None, index: int = 0) -> Color:
    """A status tone, a series ("s3" is the fourth series colour) or the series colour of the index."""
    if tone in TONES:
        return TONES[tone]
    if isinstance(tone, str) and tone.startswith("s") and tone[1:].isdigit():
        return PALETTE[int(tone[1:]) % len(PALETTE)] if tone != "s5" else NAVY
    return PALETTE[index % len(PALETTE)]


class _Charts:
    """The chart kinds the report blocks added (spec section 8): each draws into a box (x, y is the
    bottom left corner) and returns False when there is nothing to draw, so the box says "No data"."""

    # Small shapes -------------------------------------------------------------------------------

    def _circle(self, cx: float, cy: float, r: float, fill: Color | None = None, stroke: Color | None = None, width: float = 0.6) -> None:
        k = 0.5523 * r
        p = (f"{_n(cx + r)} {_n(cy)} m {_n(cx + r)} {_n(cy + k)} {_n(cx + k)} {_n(cy + r)} {_n(cx)} {_n(cy + r)} c "
             f"{_n(cx - k)} {_n(cy + r)} {_n(cx - r)} {_n(cy + k)} {_n(cx - r)} {_n(cy)} c "
             f"{_n(cx - r)} {_n(cy - k)} {_n(cx - k)} {_n(cy - r)} {_n(cx)} {_n(cy - r)} c "
             f"{_n(cx + k)} {_n(cy - r)} {_n(cx + r)} {_n(cy - k)} {_n(cx + r)} {_n(cy)} c h")
        paint = "B" if fill and stroke else "f" if fill else "S"
        colours = (_rgb(fill, "rg") + " " if fill else "") + (f"{_rgb(stroke, 'RG')} {_n(width)} w " if stroke else "")
        self._op(colours + p + " " + paint)

    def _dashed(self, points: Sequence[tuple[float, float]], color: Color, width: float = 1.0, dash: str = "3 2") -> None:
        if len(points) > 1:
            path = " ".join(f"{_n(px)} {_n(py)} {'m' if i == 0 else 'l'}" for i, (px, py) in enumerate(points))
            self._op(f"[{dash}] 0 d {_rgb(color, 'RG')} {_n(width)} w {path} S [] 0 d")

    def _hatch(self, x: float, y: float, w: float, h: float) -> None:
        """White with grey diagonal lines: planned maintenance."""
        self._rect(x, y, w, h, WHITE)
        self._clip(x, y, w, h)
        step = 3.0
        k = -h
        while k < w:
            self._line(x + k, y, x + k + h, y + h, SOFT_GREY, 0.5)
            k += step
        self._op("Q")
        self._op(f"{_rgb(SOFT_GREY, 'RG')} 0.5 w {_n(x)} {_n(y)} {_n(w)} {_n(h)} re S")

    def _xy_frame(self, x: float, y: float, w: float, h: float, low: float, high: float, unit: str, legend: bool = False,
                  whole: bool = False) -> tuple[float, float, float, float, list[float]]:
        """A value axis with grid lines; returns the plot box (px1, py1, px2, py2) and the ticks."""
        py1, py2 = y + 14 + (12 if legend else 0), y + h
        ticks, px1 = self._y_axis(low, high, unit, x, py1, py2, x + w, whole=whole)
        return px1, py1, x + w - 4, py2, ticks

    # Text cells ---------------------------------------------------------------------------------

    def _text_lines(self, text: str, width: float, size: float = 8.5) -> list[str]:
        out: list[str] = []
        for para in str(text or "").split("\n"):
            out += wrap(para, width, size) if para.strip() else [""]
        return out

    def _draw_textbox(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        lines = self._text_lines(spec.get("text") or "", w - 16)
        self._round_rect(x, y, w, h, 5, fill=BAND)
        yy = y + h - 12
        for line in lines:
            self._draw_text(x + 8, yy, line, 8.5, color=INK)
            yy -= 11
        return True

    def _draw_keyvalue(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        pairs = spec.get("pairs") or []
        if not pairs:
            return False
        label_w = min(max(text_width(str(k), 8) for k, _ in pairs) + 12, w * 0.4)
        yy = y + h - 10
        for k, v in pairs:
            self._draw_text(x, yy, fit(k, label_w - 6, 8), 8, color=GREY)
            self._draw_text(x + label_w, yy, fit(v, w - label_w, 8.5, True), 8.5, True, INK)
            self._line(x, yy - 3.5, x + w, yy - 3.5, GRID, 0.3)
            yy -= 12
        return True

    # At a glance --------------------------------------------------------------------------------

    def _arc(self, cx: float, cy: float, r1: float, r2: float, a1: float, a2: float, color: Color) -> None:
        steps = max(2, int(abs(a2 - a1) / 0.06))
        outer = [(cx + r2 * math.cos(a1 + (a2 - a1) * k / steps), cy + r2 * math.sin(a1 + (a2 - a1) * k / steps)) for k in range(steps + 1)]
        inner = [(cx + r1 * math.cos(a1 + (a2 - a1) * k / steps), cy + r1 * math.sin(a1 + (a2 - a1) * k / steps)) for k in range(steps, -1, -1)]
        self._polygon(outer + inner, color)

    def _draw_gauge(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        gauges = spec.get("gauges") or []
        if not gauges:
            return False
        cell = w / len(gauges)
        for i, g in enumerate(gauges):
            cx = x + cell * (i + 0.5)
            r = min(cell * 0.4, h * 0.55)
            cy = y + 26
            top = float(g.get("max") or 100) or 100.0
            value = g.get("value")
            ang = lambda v: math.pi * (1 - max(0.0, min(1.0, v / top)))
            if value is None:
                self._arc(cx, cy, r * 0.7, r, 0, math.pi, TRACK)
            else:
                warn, bad = float(g.get("warn") or top), float(g.get("bad") or top)
                self._arc(cx, cy, r * 0.7, r, ang(warn), math.pi, mix(TONES["good"], WHITE, 0.25))
                self._arc(cx, cy, r * 0.7, r, ang(bad), ang(warn), mix(TONES["warn"], WHITE, 0.25))
                self._arc(cx, cy, r * 0.7, r, 0, ang(bad), mix(TONES["bad"], WHITE, 0.25))
                a = ang(float(value))
                self._line(cx, cy, cx + r * 0.92 * math.cos(a), cy + r * 0.92 * math.sin(a), NAVY, 1.6)
                self._circle(cx, cy, 2.2, NAVY)
            self._draw_text(cx, cy - 12, g.get("text") or ("No data" if value is None else format_number(value)), 11, True, INK, align="c")
            self._draw_text(cx, cy - 22, fit(g.get("label") or "", cell - 6, 7.5), 7.5, color=GREY, align="c")
        return True

    def _draw_headline(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        items = spec.get("items") or []
        if not items:
            return False
        yy = y + h
        for it in items:
            yy -= 30
            self._draw_text(x, yy + 12, fit(it.get("value_text") or "-", w * 0.35, 14, True), 14, True, INK)
            self._draw_text(x, yy + 3, fit(it.get("label") or "", w * 0.35, 7), 7, color=GREY)
            vals = [v for v in it.get("values") or []]
            known = [(i, v) for i, v in enumerate(vals) if v is not None]
            sx, sw = x + w * 0.4, w * 0.58
            if len(known) < 2:
                self._line(sx, yy + 10, sx + sw, yy + 10, TRACK, 1)
                continue
            lo, hi = min(v for _, v in known), max(v for _, v in known)
            px = lambda i: sx + i / max(len(vals) - 1, 1) * sw
            py = lambda v: yy + 3 + (v - lo) / ((hi - lo) or 1) * 18
            for run in _runs([(i, v) for i, v in enumerate(vals)]):
                self._polyline([(px(i), py(v)) for i, v in run], PALETTE[0], 0.9)
            good_low = (it.get("better") or "down") == "down"
            i_min = min(known, key=lambda p: p[1])[0]
            i_max = max(known, key=lambda p: p[1])[0]
            self._circle(px(i_min), py(vals[i_min]), 1.6, TONES["good" if good_low else "bad"])
            self._circle(px(i_max), py(vals[i_max]), 1.6, TONES["bad" if good_low else "good"])
            self._circle(px(known[-1][0]), py(known[-1][1]), 1.6, NAVY)
        return True

    def _draw_bullet(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = spec.get("rows") or []
        if not rows:
            return False
        lo, hi = float(spec.get("min") or 0), float(spec.get("max") or 100)
        bands = spec.get("bands") or [lo, lo, hi]
        label_w = min(max(text_width(str(r[0]), 7.5) for r in rows) + 8, w * 0.32)
        value_w = max(text_width(str(r[2]), 7.5) for r in rows) + 8
        x0, x1 = x + label_w, x + w - value_w
        sx = lambda v: x0 + (max(lo, min(hi, float(v))) - lo) / ((hi - lo) or 1) * (x1 - x0)
        yy = y + h
        shades = [(0.80, 0.82, 0.85), (0.88, 0.89, 0.91), (0.95, 0.95, 0.96)]
        for label, value, text in rows:
            yy -= 16
            self._draw_text(x0 - 6, yy + 4, fit(label, label_w - 8, 7.5), 7.5, align="r")
            edges = [lo, bands[1] if len(bands) > 1 else lo, bands[2] if len(bands) > 2 else hi, hi]
            for k in range(3):
                self._rect(sx(edges[k]), yy, max(0.0, sx(edges[k + 1]) - sx(edges[k])), 12, shades[k])
            if value is not None:
                self._rect(x0, yy + 4, max(0.6, sx(value) - x0), 4, INK)
            if spec.get("target") is not None:
                tx = sx(spec["target"])
                self._line(tx, yy - 1, tx, yy + 13, TONES["bad"], 1.4)
            self._draw_text(x1 + 4, yy + 4, text, 7.5, color=GREY)
        self._draw_text(x0, yy - 9, format_value(lo, spec.get("unit") or ""), 6.5, color=GREY)
        self._draw_text(x1, yy - 9, format_value(hi, spec.get("unit") or ""), 6.5, color=GREY, align="r")
        if spec.get("target_label"):
            self._draw_text(sx(spec["target"]), yy - 9, spec["target_label"], 6.5, color=TONE_INK["bad"], align="c")
        return True

    # Comparison ---------------------------------------------------------------------------------

    def _draw_lollipop(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        items = [it for it in spec.get("items") or [] if it[1] is not None]
        if not items:
            return False
        unit = spec.get("unit") or ""
        marks = [m for m in spec.get("thresholds") or [] if m.get("value") is not None]
        high = spec.get("max") or max([float(v) for _, v, _ in items] + [m["value"] for m in marks] + [0.0]) or 1.0
        px1, py1, px2, py2, ticks = self._xy_frame(x, y, w, h, 0, high, unit)
        top = ticks[-1]
        sy = lambda v: py1 + max(0.0, min(top, v)) / (top or 1) * (py2 - py1)
        for m in marks:
            self._line(px1, sy(m["value"]), px2, sy(m["value"]), TONES.get(m.get("tone"), GREY), 0.8, "2 1.5")
        slot = (px2 - px1) / len(items)
        for i, (label, value, tone) in enumerate(items):
            cx = px1 + slot * (i + 0.5)
            colour = TONES[tone] if tone in TONES else PALETTE[0]
            self._line(cx, py1, cx, sy(float(value)), colour, 1.2)
            self._circle(cx, sy(float(value)), 2.6, colour)
            self._draw_text(cx, py1 - 9, fit(label, max(slot - 2, 14), 6.5), 6.5, color=GREY, align="c")
        self._line(px1, py1, px2, py1, AXIS)
        return True

    def _draw_diverging(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = [r for r in spec.get("rows") or [] if r[1] is not None]
        if not rows:
            return False
        label_w = min(max(text_width(str(r[0]), 7.5) for r in rows) + 8, w * 0.3)
        x0, x1 = x + label_w, x + w - 4
        mid = (x0 + x1) / 2
        span = max(abs(float(r[1])) for r in rows) or 1.0
        yy = y + h
        for label, delta, text in rows:
            yy -= 13
            self._draw_text(x0 - 6, yy + 3, fit(label, label_w - 8, 7.5), 7.5, align="r")
            length = abs(float(delta)) / span * ((x1 - x0) / 2 - 50)
            worse = float(delta) > 0
            colour = TONES["bad" if worse else "good"]
            if worse:
                self._rect(mid, yy + 1.5, max(length, 0.6), 8, colour)
                self._draw_text(mid + length + 3, yy + 3, fit(text, 60, 6.5), 6.5, color=GREY)
            else:
                self._rect(mid - length, yy + 1.5, max(length, 0.6), 8, colour)
                self._draw_text(mid - length - 3, yy + 3, fit(text, 60, 6.5), 6.5, color=GREY, align="r")
        self._line(mid, yy - 1, mid, y + h, INK, 0.8)
        self._draw_text(x0, yy - 10, "< " + (spec.get("left_text") or "Better"), 6.5, color=TONE_INK["good"])
        self._draw_text(x1, yy - 10, (spec.get("right_text") or "Worse") + " >", 6.5, color=TONE_INK["bad"], align="r")
        return True

    def _draw_dumbbell(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = [r for r in spec.get("rows") or [] if r[1] is not None or r[2] is not None]
        if not rows:
            return False
        unit = spec.get("unit") or ""
        vals = [float(v) for r in rows for v in r[1:3] if v is not None]
        lo, hi = min(vals), max(vals)
        pad = (hi - lo) * 0.1 or abs(hi) * 0.05 or 1
        ticks = nice_ticks(max(0.0, lo - pad) if lo >= 0 else lo - pad, hi + pad, 4)
        label_w = min(max(text_width(str(r[0]), 7.5) for r in rows) + 8, w * 0.32)
        x0, x1 = x + label_w, x + w - 6
        sx = lambda v: x0 + (v - ticks[0]) / ((ticks[-1] - ticks[0]) or 1) * (x1 - x0)
        top = y + h - 12
        for t in ticks:
            self._line(sx(t), y + 12, sx(t), top, GRID, 0.4)
            self._draw_text(sx(t), y + 3, format_value(t, unit), 6.5, color=GREY, align="c")
        yy = top
        for label, before, after in rows:
            yy -= 14
            self._draw_text(x0 - 6, yy + 2, fit(label, label_w - 8, 7.5), 7.5, align="r")
            if before is not None and after is not None:
                self._line(sx(float(before)), yy + 4.5, sx(float(after)), yy + 4.5, mix(PALETTE[0], WHITE, 0.6), 3)
            if before is not None:
                self._circle(sx(float(before)), yy + 4.5, 2.8, SOFT_GREY)
            if after is not None:
                self._circle(sx(float(after)), yy + 4.5, 2.8, PALETTE[0])
        self._legend([(spec.get("before_label") or "Before", SOFT_GREY, False), (spec.get("after_label") or "After", PALETTE[0], False)],
                     x0, y + h - 9, x + w)
        return True

    def _draw_butterfly(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = spec.get("rows") or []
        if not rows:
            return False
        unit = spec.get("unit") or ""
        label_w = min(max(text_width(str(r[0]), 7.5) for r in rows) + 8, w * 0.28)
        x0, x1 = x + label_w, x + w - 2
        mid = (x0 + x1) / 2
        top = max([float(r[1] or 0) for r in rows] + [float(r[2] or 0) for r in rows]) or 1.0
        half = (x1 - mid) - 36
        yy = y + h - 12
        self._draw_text(mid - 4, yy + 2, "< " + (spec.get("left_label") or "In"), 7, True, PALETTE[0], align="r")
        self._draw_text(mid + 4, yy + 2, (spec.get("right_label") or "Out") + " >", 7, True, PALETTE[1])
        for label, left, right in rows:
            yy -= 13
            self._draw_text(x0 - 6, yy + 3, fit(label, label_w - 8, 7.5), 7.5, align="r")
            lw, rw = float(left or 0) / top * half, float(right or 0) / top * half
            self._rect(mid - lw, yy + 1.5, max(lw, 0.5), 8, PALETTE[0])
            self._rect(mid, yy + 1.5, max(rw, 0.5), 8, PALETTE[1])
            self._draw_text(mid - lw - 3, yy + 3, format_value(left, unit), 6.5, color=GREY, align="r")
            self._draw_text(mid + rw + 3, yy + 3, format_value(right, unit), 6.5, color=GREY)
        self._line(mid, yy, mid, y + h - 12, INK, 0.6)
        return True

    def _draw_stack100(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = [r for r in spec.get("rows") or [] if sum(r.get("values") or []) > 0]
        parts = spec.get("parts") or []
        if not rows or not parts:
            return False
        blues = [mix(PALETTE[0], WHITE, 0.75), mix(PALETTE[0], WHITE, 0.5), PALETTE[0]]
        colours = []
        for i, p in enumerate(parts):
            colours.append(TONES[p["tone"]] if p.get("tone") in TONES else blues[min(i, len(blues) - 1)])
        self._legend([(p["name"], colours[i], False) for i, p in enumerate(parts)], x, y + h - 9, x + w)
        label_w = min(max(text_width(str(r["label"]), 7.5) for r in rows) + 8, w * 0.3)
        x0, x1 = x + label_w, x + w - 2
        yy = y + h - 16
        for r in rows:
            yy -= 14
            self._draw_text(x0 - 6, yy + 3, fit(r["label"], label_w - 8, 7.5), 7.5, align="r")
            total = float(sum(r["values"]))
            px = x0
            for i, v in enumerate(r["values"]):
                seg = float(v) / total * (x1 - x0)
                if seg > 0:
                    self._rect(px, yy + 1, seg, 10, colours[i])
                    if seg > 18:
                        self._draw_text(px + seg / 2, yy + 3.5, f"{round(100 * v / total)}%", 6, color=WHITE if i >= 2 else INK, align="c")
                px += seg
        for k in (0, 50, 100):
            self._draw_text(x0 + k / 100 * (x1 - x0), yy - 9, f"{k}%", 6.5, color=GREY, align="c")
        return True

    def _draw_treemap(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        items = spec.get("items") or []
        if not items:
            return False
        for i, it in enumerate(items):
            tx, tw, th = x + it["x"] * w, it["w"] * w, it["h"] * h
            ty = y + h - (it["y"] + it["h"]) * h
            tone = it.get("tone")
            fill = TONE_TINT[tone] if tone in TONE_TINT else mix(PALETTE[i % 3], WHITE, 0.55 + 0.1 * (i // 3 % 3))
            self._rect(tx + 0.5, ty + 0.5, max(0.5, tw - 1), max(0.5, th - 1), fill)
            if tw > 30 and th > 16:
                self._draw_text(tx + 3, ty + th - 9, fit(it["label"], tw - 6, 7, True), 7, True, INK)
                if th > 24:
                    self._draw_text(tx + 3, ty + th - 18, fit(it.get("text") or "", tw - 6, 6.5), 6.5, color=GREY)
        return True

    # Composition --------------------------------------------------------------------------------

    def _draw_waterfall(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        steps = spec.get("steps") or []
        if not steps:
            return False
        unit = spec.get("unit") or ""
        run, spans = 0.0, []
        for label, value, kind in steps:
            v = float(value)
            if kind == "start":
                spans.append((label, 0.0, v, NAVY, v))
                run = v
            elif kind == "minus":
                spans.append((label, run - v, run, TONES["bad"], v))
                run -= v
            else:
                spans.append((label, min(0.0, v), max(0.0, v), TONES["good"] if v >= 0 else TONES["bad"], v))
        low = min(0.0, min(a for _, a, _, _, _ in spans))
        high = max(b for _, _, b, _, _ in spans) or 1.0
        px1, py1, px2, py2, ticks = self._xy_frame(x, y, w, h, low, high, unit)
        lo, hi = ticks[0], ticks[-1]
        sy = lambda v: py1 + (v - lo) / ((hi - lo) or 1) * (py2 - py1)
        slot = (px2 - px1) / len(spans)
        for i, (label, a, b, colour, v) in enumerate(spans):
            bx = px1 + i * slot + slot * 0.15
            self._rect(bx, sy(a), slot * 0.7, max(0.6, sy(b) - sy(a)), colour)
            self._draw_text(bx + slot * 0.35, sy(b) + 2, format_value(v, unit), 6.5, color=GREY, align="c")
            self._draw_text(bx + slot * 0.35, py1 - 9, fit(label, slot - 2, 6.5), 6.5, color=GREY, align="c")
        self._line(px1, sy(0), px2, sy(0), AXIS)
        return True

    def _draw_pareto(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        bars = spec.get("bars") or []
        if not bars:
            return False
        cum = spec.get("cumulative") or []
        px1, py1, px2, py2, ticks = self._xy_frame(x, y, w - 24, h, 0, max(float(b[1]) for b in bars) or 1, "", legend=True, whole=True)
        px2 = x + w - 26
        top = ticks[-1]
        sy = lambda v: py1 + v / (top or 1) * (py2 - py1)
        pc = lambda v: py1 + v / 100 * (py2 - py1)
        slot = (px2 - px1) / len(bars)
        for i, (label, n) in enumerate(bars):
            bx = px1 + i * slot + slot * 0.15
            self._rect(bx, py1, slot * 0.7, max(0.5, sy(float(n)) - py1), PALETTE[0])
            self._draw_text(bx + slot * 0.35, py1 - 9, fit(label, slot - 2, 6.5), 6.5, color=GREY, align="c")
        for k in (0, 50, 100):
            self._draw_text(px2 + 4, pc(k) - 2.5, f"{k}%", 6.5, color=GREY)
        self._line(px1, pc(80), px2, pc(80), SOFT_GREY, 0.6, "1 2")
        self._polyline([(px1 + slot * (i + 0.5), pc(v)) for i, v in enumerate(cum)], ORANGE, 1.2)
        for i, v in enumerate(cum):
            self._circle(px1 + slot * (i + 0.5), pc(v), 1.6, ORANGE)
        self._line(px1, py1, px2, py1, AXIS)
        self._legend([("Count", PALETTE[0], False), ("Running total (right axis)", ORANGE, False), ("80%", SOFT_GREY, True)], px1, y + 1, x + w)
        return True

    # Distribution -------------------------------------------------------------------------------

    def _draw_histogram(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        bins = spec.get("bins") or []
        if not bins:
            return False
        unit = spec.get("unit") or ""
        px1, py1, px2, py2, ticks = self._xy_frame(x, y, w, h - 22, 0, max(b[2] for b in bins) or 1, "", whole=True)
        top = ticks[-1]
        lo, hi = bins[0][0], bins[-1][1]
        sx = lambda v: px1 + (v - lo) / ((hi - lo) or 1) * (px2 - px1)
        for a, b, n in bins:
            if n:
                self._rect(sx(a) + 0.3, py1, max(0.4, sx(b) - sx(a) - 0.6), n / (top or 1) * (py2 - py1), mix(PALETTE[0], WHITE, 0.3))
        self._line(px1, py1, px2, py1, AXIS)
        for t in nice_ticks(lo, hi, 5):
            if lo <= t <= hi:
                self._draw_text(sx(t), py1 - 9, format_value(t, unit), 6.5, color=GREY, align="c")
        for k, m in enumerate(spec.get("marks") or []):
            if m.get("value") is None:
                continue
            mx = sx(max(lo, min(hi, m["value"])))
            colour = _tone_colour(m.get("tone"))
            self._line(mx, py1, mx, y + h - 4 - k * 7, colour, 0.9, "3 2")
            self._draw_text(mx + 2, y + h - 8 - k * 7, m.get("label") or "", 6.5, color=colour)
        return True

    def _draw_box(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = spec.get("rows") or []
        if not rows:
            return False
        unit = spec.get("unit") or ""
        high = max([r["hi"] for r in rows] + [max(r.get("outliers") or [0]) for r in rows] + [spec.get("target") or 0])
        ticks = nice_ticks(0, high or 1, 5)
        label_w = min(max(text_width(str(r["label"]), 7.5) for r in rows) + 8, w * 0.3)
        x0, x1 = x + label_w, x + w - 6
        sx = lambda v: x0 + v / (ticks[-1] or 1) * (x1 - x0)
        for t in ticks:
            self._line(sx(t), y + 12, sx(t), y + h, GRID, 0.4)
            self._draw_text(sx(t), y + 3, format_value(t, unit), 6.5, color=GREY, align="c")
        if spec.get("target") is not None:
            self._line(sx(spec["target"]), y + 12, sx(spec["target"]), y + h, TONES["warn"], 0.9, "3 2")
        yy = y + h
        for r in rows:
            yy -= 15
            self._draw_text(x0 - 6, yy + 3, fit(r["label"], label_w - 8, 7.5), 7.5, align="r")
            mid = yy + 5
            self._line(sx(r["lo"]), mid, sx(r["hi"]), mid, AXIS, 0.7)
            self._line(sx(r["lo"]), mid - 3, sx(r["lo"]), mid + 3, AXIS, 0.7)
            self._line(sx(r["hi"]), mid - 3, sx(r["hi"]), mid + 3, AXIS, 0.7)
            self._op(f"{_rgb(mix(PALETTE[0], WHITE, 0.65), 'rg')} {_rgb(PALETTE[0], 'RG')} 0.6 w {_n(sx(r['q1']))} {_n(mid - 4.5)} "
                     f"{_n(max(0.8, sx(r['q3']) - sx(r['q1'])))} 9 re B")
            self._line(sx(r["med"]), mid - 4.5, sx(r["med"]), mid + 4.5, NAVY, 1.4)
            for o in r.get("outliers") or []:
                self._circle(sx(o), mid, 1.1, SOFT_GREY)
        return True

    def _draw_cdf(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        series = [s for s in spec.get("series") or [] if s.get("points")]
        if not series:
            return False
        unit = spec.get("unit") or ""
        top = max(p[0] for s in series for p in s["points"]) or 1
        xt = nice_ticks(0, top, 5)
        py1, py2 = y + 26, y + h
        px1, px2 = x + 26, x + w - 4
        sx = lambda v: px1 + v / (xt[-1] or 1) * (px2 - px1)
        sy = lambda f: py1 + f * (py2 - py1)
        for k in (0, 0.25, 0.5, 0.75, 1.0):
            self._line(px1, sy(k), px2, sy(k), GRID, 0.4)
            self._draw_text(px1 - 4, sy(k) - 2.5, f"{int(k * 100)}%", 6.5, color=GREY, align="r")
        for t in xt:
            self._line(sx(t), py1, sx(t), py2, GRID, 0.4)
            self._draw_text(sx(t), py1 - 9, format_value(t, unit), 6.5, color=GREY, align="c")
        mark = spec.get("mark") or 0.95
        self._line(px1, sy(mark), px2, sy(mark), SOFT_GREY, 0.7, "1 2")
        self._draw_text(px2 - 2, sy(mark) - 8, f"{int(mark * 100)}% of answers", 6.5, color=GREY, align="r")
        for i, s in enumerate(series):
            self._polyline([(sx(a), sy(b)) for a, b in s["points"]], PALETTE[i % len(PALETTE)], 1.1)
        self._legend([(s["name"], PALETTE[i % len(PALETTE)], False) for i, s in enumerate(series)], px1, y + 1, x + w)
        return True

    # Over time ----------------------------------------------------------------------------------

    def _time_box(self, spec: dict, x: float, y: float, w: float, h: float, low: float, high: float, legend: bool):
        unit = spec.get("unit") or ""
        py1, py2 = y + 14 + (12 if legend else 0), y + h
        ticks, px1 = self._y_axis(low, high, unit, x, py1, py2, x + w)
        px2 = x + w - 4
        t0, t1 = spec.get("start"), spec.get("end")
        lo, hi = ticks[0], ticks[-1]
        sx = lambda t: px1 + (t - t0) / ((t1 - t0) or 1) * (px2 - px1)
        sy = lambda v: py1 + (max(lo, min(hi, v)) - lo) / ((hi - lo) or 1) * (py2 - py1)
        self._line(px1, py1, px2, py1, AXIS)
        self._time_axis(t0, t1, px1, px2, py1)
        return px1, py1, px2, py2, sx, sy

    def _band_runs(self, rows: Sequence[Sequence], lo_i: int, hi_i: int) -> list[list[tuple[float, float, float]]]:
        runs: list[list[tuple[float, float, float]]] = [[]]
        for r in rows:
            if r[lo_i] is None or r[hi_i] is None:
                if runs[-1]:
                    runs.append([])
            else:
                runs[-1].append((r[0], float(r[lo_i]), float(r[hi_i])))
        return [run for run in runs if run]

    def _draw_band(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        pts = spec.get("points") or []
        vals = [v for p in pts for v in p[1:] if v is not None]
        if not vals:
            return False
        marks = [m for m in spec.get("thresholds") or [] if m.get("value") is not None and m["value"] <= max(vals) * 2]
        spec = dict(spec, start=spec.get("start") or pts[0][0], end=spec.get("end") or pts[-1][0])
        px1, py1, px2, py2, sx, sy = self._time_box(spec, x, y, w, h, 0, max(vals + [m["value"] for m in marks]), True)
        self._clip(px1, py1, px2 - px1, py2 - py1)
        for lo_i, hi_i, amount in ((1, 5, 0.82), (2, 4, 0.55)):
            for run in self._band_runs(pts, lo_i, hi_i):
                poly = [(sx(t), sy(a)) for t, a, _ in run] + [(sx(t), sy(b)) for t, _, b in reversed(run)]
                self._polygon(poly, mix(PALETTE[0], WHITE, amount))
        for run in _runs([(p[0], p[3]) for p in pts]):
            self._polyline([(sx(t), sy(v)) for t, v in run], NAVY, 1.1)
        for m in marks:
            self._line(px1, sy(m["value"]), px2, sy(m["value"]), TONES.get(m.get("tone"), GREY), 0.8, "3 2")
        self._op("Q")
        self._legend([("5th to 95th", mix(PALETTE[0], WHITE, 0.82), False), ("25th to 75th", mix(PALETTE[0], WHITE, 0.55), False),
                      ("Median", NAVY, False)] + [(m.get("label") or "", TONES.get(m.get("tone"), GREY), True) for m in marks if m.get("label")],
                     px1, y + 1, x + w)
        return True

    def _draw_baseline(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        pts = spec.get("points") or []
        band = spec.get("band") or []
        vals = [v for _, v in pts if v is not None] + [v for b in band for v in b[1:] if v is not None]
        if not vals:
            return False
        px1, py1, px2, py2, sx, sy = self._time_box(spec, x, y, w, h, 0, max(vals), True)
        self._clip(px1, py1, px2 - px1, py2 - py1)
        for run in self._band_runs(band, 1, 2):
            self._polygon([(sx(t), sy(a)) for t, a, _ in run] + [(sx(t), sy(b)) for t, _, b in reversed(run)], (0.88, 0.89, 0.91))
        for run in _runs(pts):
            self._polyline([(sx(t), sy(v)) for t, v in run], PALETTE[0], 1.1)
        for t, v in spec.get("anomalies") or []:
            self._circle(sx(t), sy(v), 1.8, TONES["bad"])
        self._op("Q")
        self._legend([("Usual range", (0.88, 0.89, 0.91), False), ("Actual", PALETTE[0], False), ("Out of the usual", TONES["bad"], False)],
                     px1, y + 1, x + w)
        return True

    def _draw_step(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        pts = sorted(spec.get("points") or [], key=lambda p: p[0])
        if not pts:
            return False
        expected = spec.get("expected")
        high = max([p[1] for p in pts] + [expected or 0]) + 1
        unit = spec.get("unit") or ""
        py1, py2 = y + 14 + 12, y + h
        ticks, px1 = self._y_axis(0, high, unit, x, py1, py2, x + w, whole=True)
        px2 = x + w - 4
        t0, t1 = spec.get("start") or pts[0][0], spec.get("end") or pts[-1][0]
        sx = lambda t: px1 + (t - t0) / ((t1 - t0) or 1) * (px2 - px1)
        sy = lambda v: py1 + v / (ticks[-1] or 1) * (py2 - py1)
        line = []
        for i, (t, v) in enumerate(pts):
            if i:
                line.append((sx(t), sy(pts[i - 1][1])))
            line.append((sx(t), sy(v)))
        self._polygon([(line[0][0], py1)] + line + [(line[-1][0], py1)], mix(PALETTE[0], WHITE, 0.85))
        self._polyline(line, PALETTE[0], 1.2)
        if expected is not None:
            self._line(px1, sy(expected), px2, sy(expected), SOFT_GREY, 0.8, "1 2")
        self._line(px1, py1, px2, py1, AXIS)
        self._time_axis(t0, t1, px1, px2, py1)
        self._legend([("Answering", PALETTE[0], False)] + ([(spec.get("expected_label") or "Expected", SOFT_GREY, True)] if expected is not None else []),
                     px1, y + 1, x + w)
        return True

    def _draw_multiples(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        panels = spec.get("panels") or []
        if not panels:
            return False
        cols = 3
        gap = 8.0
        pw = (w - gap * (cols - 1)) / cols
        ph = 52.0
        top = float(spec.get("y_max") or 100) or 1.0
        t0, t1 = spec.get("start"), spec.get("end")
        th = (spec.get("threshold") or {}).get("value")
        for i, p in enumerate(panels):
            px = x + (i % cols) * (pw + gap)
            py = y + h - (i // cols + 1) * (ph + 6)
            self._draw_text(px, py + ph - 7, fit(p["name"], pw, 7, True), 7, True, INK)
            bx1, by1, bx2, by2 = px + (16 if i % cols == 0 else 0), py + 2, px + pw, py + ph - 11
            self._rect(bx1, by1, bx2 - bx1, by2 - by1, (0.975, 0.978, 0.983))
            if i % cols == 0:
                self._draw_text(bx1 - 2, by2 - 5, format_value(top, spec.get("unit") or ""), 5.5, color=GREY, align="r")
                self._draw_text(bx1 - 2, by1, "0", 5.5, color=GREY, align="r")
            pts = [(t, v) for t, v in p.get("points") or []]
            if not any(v is not None for _, v in pts):
                self._draw_text((bx1 + bx2) / 2, (by1 + by2) / 2 - 2, "No data", 6.5, color=GREY, align="c")
                continue
            sx = lambda t: bx1 + (t - t0) / ((t1 - t0) or 1) * (bx2 - bx1)
            sy = lambda v: by1 + max(0.0, min(top, v)) / top * (by2 - by1)
            if th is not None:
                self._line(bx1, sy(th), bx2, sy(th), SOFT_GREY, 0.5, "1 1.5")
            for run in _runs(pts):
                self._polyline([(sx(t), sy(v)) for t, v in run], TONES["bad"] if p.get("bad") else PALETTE[0], 0.8)
        return True

    def _draw_forecast(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        obs = spec.get("observed") or []
        if not obs:
            return False
        proj, cone = spec.get("projection") or [], spec.get("cone") or []
        limit = spec.get("limit")
        vals = [v for _, v in obs] + [v for _, v in proj] + [c[2] for c in cone]
        high = max(vals + [limit or 0, 100 if spec.get("unit") == "%" else 0])
        spec = dict(spec, start=spec.get("start") or obs[0][0], end=spec.get("end") or obs[-1][0])
        px1, py1, px2, py2, sx, sy = self._time_box(spec, x, y, w, h, 0, min(high, 100) if spec.get("unit") == "%" else high, True)
        self._clip(px1, py1, px2 - px1, py2 - py1)
        if cone:
            self._polygon([(sx(t), sy(a)) for t, a, _ in cone] + [(sx(t), sy(b)) for t, _, b in reversed(cone)], mix(PALETTE[0], WHITE, 0.85))
        self._polyline([(sx(t), sy(v)) for t, v in obs], PALETTE[0], 1.2)
        if proj:
            self._dashed([(sx(t), sy(v)) for t, v in proj], PALETTE[0], 1.1)
        if limit is not None:
            self._line(px1, sy(limit), px2, sy(limit), TONES["bad"], 0.9, "3 2")
        if spec.get("full_at"):
            fx = sx(spec["full_at"])
            self._line(fx, py1, fx, py2, INK, 0.6, "1 2")
            self._draw_text(fx - 2, py2 - 8, spec.get("full_text") or "", 6.5, color=INK, align="r")
        self._op("Q")
        self._legend([("Daily peak", PALETTE[0], False), ("Trend", PALETTE[0], True), ("About 90% confidence", mix(PALETTE[0], WHITE, 0.85), False)]
                     + ([(spec.get("limit_label") or "Limit", TONES["bad"], True)] if limit is not None else []), px1, y + 1, x + w)
        return True

    # Time patterns ------------------------------------------------------------------------------

    def _draw_calendar(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        cells = spec.get("cells") or []
        if not cells:
            return False
        weeks = max(c[0] for c in cells) + 1
        size = max(4.0, min(11.0, (w - 14) / weeks - 1))
        top = y + h - 12
        for wk, label in spec.get("months") or []:
            self._draw_text(x + 14 + wk * (size + 1), top + 3, label, 6.5, color=GREY)
        for k, name in enumerate("MTWTFSS"):
            if k % 2 == 0:
                self._draw_text(x, top - (k + 1) * (size + 1) + 1.5, name, 6, color=GREY)
        for wk, day, value, tone, soft, _ in cells:
            colour = TRACK if tone not in TONES or tone == "none" else TONES[tone]
            if soft:
                colour = mix(colour, WHITE, 0.55)
            self._rect(x + 14 + wk * (size + 1), top - (day + 1) * (size + 1), size, size, colour)
        lx = x + 14
        ly = top - 8 * (size + 1) - 4
        for label, tone, soft in spec.get("legend") or []:
            colour = TRACK if tone == "none" else mix(TONES[tone], WHITE, 0.55) if soft else TONES[tone]
            self._rect(lx, ly, 6, 6, colour)
            self._draw_text(lx + 8, ly + 0.5, label, 6.5, color=GREY)
            lx += 14 + text_width(label, 6.5)
        return True

    def _draw_gantt(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = spec.get("rows") or []
        t0, t1 = spec.get("start"), spec.get("end")
        if not rows or not t0 or not t1:
            return False
        label_w = min(max(text_width(r["name"], 7.5) for r in rows) + 8, w * 0.28)
        x0, x1 = x + label_w, x + w - 2
        sx = lambda t: x0 + (t - t0) / ((t1 - t0) or 1) * (x1 - x0)
        yy = y + h
        for r in rows:
            yy -= 13
            self._draw_text(x0 - 6, yy + 3, fit(r["name"], label_w - 8, 7.5), 7.5, align="r")
            self._rect(x0, yy + 1, x1 - x0, 9, TRACK)
            for a, b, tone, _ in r["spans"]:
                bx, bw = sx(a), max(1.5, sx(b) - sx(a))
                if tone == "maint":
                    self._hatch(bx, yy + 1, bw, 9)
                else:
                    self._rect(bx, yy + 1, bw, 9, TONES.get(tone, TONES["bad"]))
        marks = spec.get("marks") or []
        every = max(1, math.ceil(len(marks) / max(1, (x1 - x0) / 40)))
        for i, (t, label) in enumerate(marks):
            if t0 <= t <= t1:
                self._line(sx(t), yy, sx(t), y + h, GRID, 0.4)
                if i % every == 0:
                    self._draw_text(sx(t) + 1, yy - 8, label, 6, color=GREY)
        self._legend([("Down", TONES["bad"], False), ("Maintenance", SOFT_GREY, False)], x0, yy - 20, x + w)
        return True

    def _draw_clock(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        vals = spec.get("values") or []
        known = [v for v in vals if v is not None]
        if not known or not any(known):
            return False
        top = max(known) or 1.0
        cx, cy = x + w / 2, y + h / 2 + 2
        R = min(w, h) / 2 - 12
        r0 = R * 0.25
        warn, bad = spec.get("warn"), spec.get("bad")
        self._circle(cx, cy, R, None, GRID, 0.5)
        self._circle(cx, cy, r0, None, GRID, 0.5)
        for hour, v in enumerate(vals):
            if not v:
                continue
            a1 = math.pi / 2 - (hour / 24) * 2 * math.pi - 0.11
            a2 = a1 + 0.22
            length = r0 + (R - r0) * v / top
            tone = "bad" if bad is not None and v >= bad else "warn" if warn is not None and v >= warn else None
            self._arc(cx, cy, r0, length, a1, a2, TONES[tone] if tone else PALETTE[0])
        for hour, label in ((0, "00h"), (6, "06h"), (12, "12h"), (18, "18h")):
            a = math.pi / 2 - hour / 24 * 2 * math.pi
            self._draw_text(cx + (R + 8) * math.cos(a), cy + (R + 8) * math.sin(a) - 2.5, label, 6.5, color=GREY, align="c")
        return True

    def _draw_timeline(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        events = spec.get("events") or []
        t0, t1 = spec.get("start"), spec.get("end")
        if not t0 or not t1 or (not events and not spec.get("impact")):
            return False
        mid = y + h / 2
        sx = lambda t: x + 4 + (t - t0) / ((t1 - t0) or 1) * (w - 8)
        if spec.get("impact"):
            a, b, label = spec["impact"]
            self._rect(sx(a), y + 14, max(1.0, sx(b) - sx(a)), h - 18, TONE_TINT["bad"])
            self._draw_text(sx(a) + 2, y + h - 8, fit(label, max(40, sx(b) - sx(a)), 6.5), 6.5, color=TONE_INK["bad"])
        self._line(x + 4, mid, x + w - 4, mid, INK, 0.8)
        self._time_axis(t0, t1, x + 4, x + w - 4, y + 12)
        lane = 0
        for i, (t, label, tone) in enumerate(events):
            ex = sx(t)
            colour = TONES.get(tone, PALETTE[0])
            up = i % 2 == 0
            lane = (i // 2) % 3
            ly = mid + (1 if up else -1) * (12 + lane * 11)
            self._line(ex, mid, ex, ly, SOFT_GREY, 0.4)
            self._circle(ex, mid, 2.4, colour)
            text = fit(label, 110, 6)
            tw = text_width(text, 6) + 6
            bx = max(x, min(ex - tw / 2, x + w - tw))
            self._round_rect(bx, ly - 3.5, tw, 9, 3, fill=WHITE, stroke=colour, width=0.5)
            self._draw_text(bx + 3, ly - 1, text, 6, color=INK)
        return True

    # Relationship -------------------------------------------------------------------------------

    def _draw_scatter(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        pts = spec.get("points") or []
        if not pts:
            return False
        top = float(spec.get("max") or 100)
        size = min(w - 30, h - 24)
        px1, py1 = x + 26, y + 20
        px2, py2 = x + w - 4, py1 + size
        sx = lambda v: px1 + max(0.0, min(top, v)) / top * (px2 - px1)
        sy = lambda v: py1 + max(0.0, min(top, v)) / top * (py2 - py1)
        for k in nice_ticks(0, top, 4):
            self._line(sx(k), py1, sx(k), py2, GRID, 0.4)
            self._line(px1, sy(k), px2, sy(k), GRID, 0.4)
            self._draw_text(sx(k), py1 - 9, format_number(k), 6.5, color=GREY, align="c")
            self._draw_text(px1 - 4, sy(k) - 2.5, format_number(k), 6.5, color=GREY, align="r")
        if spec.get("x_line") is not None:
            self._line(sx(spec["x_line"]), py1, sx(spec["x_line"]), py2, SOFT_GREY, 0.7, "1 2")
        if spec.get("y_line") is not None:
            self._line(px1, sy(spec["y_line"]), px2, sy(spec["y_line"]), SOFT_GREY, 0.7, "1 2")
        for label, vx, vy, tone, named in pts:
            self._circle(sx(vx), sy(vy), 2.4, TONES.get(tone, PALETTE[0]))
            if named:
                self._draw_text(sx(vx) + 3.5, sy(vy) + 2, fit(label, 70, 6.5), 6.5, color=INK)
        self._draw_text((px1 + px2) / 2, y + 1, spec.get("x_label") or "", 6.5, color=GREY, align="c")
        self._draw_text(px1 + 4, py2 - 8, spec.get("y_label") or "", 6.5, color=GREY)
        return True

    def _draw_radar(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        axes = spec.get("axes") or []
        series = [s for s in spec.get("series") or [] if any(v is not None for v in s.get("values") or [])]
        if len(axes) < 3 or not series:
            return False
        cx, cy = x + w / 2, y + h / 2 + 4
        R = min(w / 2 - 40, h / 2 - 18)
        n = len(axes)
        ang = lambda i: math.pi / 2 - i * 2 * math.pi / n
        for ring in (25, 50, 75, 100):
            self._polyline([(cx + R * ring / 100 * math.cos(ang(i)), cy + R * ring / 100 * math.sin(ang(i))) for i in range(n + 1)], GRID, 0.5)
        for i, name in enumerate(axes):
            self._line(cx, cy, cx + R * math.cos(ang(i)), cy + R * math.sin(ang(i)), GRID, 0.5)
            lx, ly = cx + (R + 8) * math.cos(ang(i)), cy + (R + 8) * math.sin(ang(i))
            self._draw_text(lx, ly - 2.5, fit(name, 70, 6.5), 6.5, color=GREY, align="c" if abs(math.cos(ang(i))) < 0.3 else "l" if math.cos(ang(i)) > 0 else "r")
        colours = [PALETTE[0], SOFT_GREY]
        for k, s in enumerate(series):
            pts = [(cx + R * v / 100 * math.cos(ang(i)), cy + R * v / 100 * math.sin(ang(i))) for i, v in enumerate(s["values"]) if v is not None]
            if len(pts) > 2:
                self._polygon(pts, mix(colours[k % 2], WHITE, 0.82))
            self._polyline(pts + pts[:1], colours[k % 2], 1.1)
        self._legend([(s["name"], colours[k % 2], False) for k, s in enumerate(series)], x, y + 1, x + w)
        return True

    def _draw_topology(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        nodes = spec.get("nodes") or []
        if not nodes:
            return False
        pos = {n["key"]: (x + 20 + n["x"] * (w - 40), y + h - 6 - n["y"] * (h - 20)) for n in nodes}
        for l in spec.get("links") or []:
            if l["a"] in pos and l["b"] in pos:
                (ax, ay), (bx, by) = pos[l["a"]], pos[l["b"]]
                colour = TONES[l["tone"]] if l.get("tone") in ("warn", "bad") else SOFT_GREY
                self._line(ax, ay, bx, by, colour, 1.4 if l.get("tone") in ("warn", "bad") else 0.9, "2 2" if l.get("dashed") else "")
        for n in nodes:
            nx, ny = pos[n["key"]]
            self._circle(nx, ny, 6 if n.get("core") else 4.5, TONES.get(n.get("tone"), TONES["none"]), WHITE, 1)
            self._draw_text(nx, ny + 9 if n.get("alt") else ny - 13, fit(n["label"], 70, 6.5), 6.5, color=INK, align="c")
        return True

    def _draw_sparktable(self, spec: dict, x: float, y: float, w: float, h: float) -> bool:
        rows = spec.get("rows") or []
        if not rows:
            return False
        head = spec.get("header") or ["", "", "", ""]
        name_w, spark_w = w * 0.42, w * 0.34
        yy = y + h - 9
        for col, tx in ((0, x), (1, x + name_w), (2, x + name_w + spark_w + 4)):
            self._draw_text(tx, yy, fit(head[col] if col < len(head) else "", (spark_w if col == 1 else name_w) - 4, 6.5, True), 6.5, True, GREY)
        for r in rows:
            yy -= 14
            self._line(x, yy + 10.5, x + w, yy + 10.5, GRID, 0.3)
            tone = r.get("tone") if r.get("tone") in TONES else "none"
            self._draw_text(x, yy + 1, fit(r["name"], name_w - 6, 7.5), 7.5, color=INK)
            vals = r.get("values") or []
            known = [v for v in vals if v is not None]
            if len(known) > 1:
                lo, hi = min(known), max(known)
                sx0, sw = x + name_w, spark_w - 8
                for run in _runs([(i, v) for i, v in enumerate(vals)]):
                    self._polyline([(sx0 + i / max(len(vals) - 1, 1) * sw, yy - 1 + (v - lo) / ((hi - lo) or 1) * 9) for i, v in run],
                                   TONES[tone] if tone in ("warn", "bad") else PALETTE[0], 0.8)
            self._draw_text(x + name_w + spark_w + 4, yy + 1, fit(r.get("now") or "", w * 0.16, 7.5, True), 7.5, True,
                            TONE_INK[tone] if tone in ("warn", "bad") else INK)
            self._circle(x + w - 4, yy + 3.5, 2.6, TONES[tone])
        return True


class Document(_Charts):
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

    def text_box(self, title: str, text: str, size: float = 9) -> None:
        """A light rounded box with a bold title and the words inside (the spec's text box); a line
        break starts a new paragraph. Text longer than a page flows on without the box."""
        inner = self.content_width - 20
        lines: list[str] = []
        for para in str(text or "").split("\n"):
            lines += wrap(para, inner, size) if para.strip() else [""]
        height = 12 + (16 if title else 0) + len(lines) * size * 1.35 + 4
        if height > self.height - 2 * MARGIN - 40:
            self.section(title)
            for para in str(text or "").split("\n"):
                self.text(para, size=size)
            self.space(8)
            return
        self._ensure(height + 8)
        top = self._y
        self._round_rect(self.left, top - height, self.content_width, height, 6, fill=BAND, stroke=RULE)
        y = top - 8
        if title:
            self._draw_text(self.left + 10, y - 10, fit(title, inner, 10, True), 10, True, INK)
            y -= 16
        for line in lines:
            y -= size * 1.35
            self._draw_text(self.left + 10, y + 2, line, size, color=INK)
        self._y = top - height - 10

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
        subs = [wrap(t.get("sub") or "", w - 16, 7)[:2] if t.get("sub") else [] for t in tiles]
        height = 50 + 9 * max(len(x) for x in subs) + 8.5 * max(len(n) for n in notes)
        self._ensure(height + 10)
        top = self._y
        for i, (tile, lines) in enumerate(zip(tiles, notes)):
            x = self.left + i * (w + gap)
            tone = tile.get("tone") if tile.get("tone") in TONES else "info"
            self._round_rect(x, top - height, w, height, 5, fill=WHITE, stroke=RULE)
            self._rect(x + 0.6, top - height + 3, 3, height - 6, TONES[tone])
            self._draw_text(x + 10, top - 13, fit(tile.get("label", ""), w - 16, 7.5), 7.5, color=GREY)
            size = 16 if len(tiles) < 6 else 13
            self._draw_text(x + 10, top - 33, fit(tile.get("value", ""), w - 16, size, True), size, True, INK)
            y = top - 33
            for k, line in enumerate(subs[i]):
                y -= 10 if k == 0 else 8.5
                self._draw_text(x + 10, y, line, 7, color=GREY)
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
        return wrap(spec["note"], w, 7.5)[:3] if spec.get("note") else []

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
            return max(1, -(-len(spec.get("tiles") or []) // per_row)) * 32 + (14 if spec.get("counts") else 0)

        def rows(key: str, each: float, extra: float) -> float:
            return max(len(spec.get(key) or []), 1) * each + extra
        sized = {"textbox": lambda: len(self._text_lines(spec.get("text") or "", w - 16)) * 11 + 12,
                 "keyvalue": lambda: rows("pairs", 12, 6), "gauge": lambda: 92.0, "headline": lambda: rows("items", 30, 4),
                 "bullet": lambda: rows("rows", 16, 16), "diverging": lambda: rows("rows", 13, 16), "dumbbell": lambda: rows("rows", 14, 30),
                 "butterfly": lambda: rows("rows", 13, 16), "stack100": lambda: rows("rows", 14, 30), "box": lambda: rows("rows", 15, 16),
                 "gantt": lambda: rows("rows", 13, 34), "sparktable": lambda: rows("rows", 14, 16),
                 "calendar": lambda: 8 * 11 + 26.0, "multiples": lambda: max(1, -(-len(spec.get("panels") or []) // 3)) * 58 + 4.0,
                 "clock": lambda: 160.0, "radar": lambda: 175.0, "topology": lambda: 185.0, "timeline": lambda: 130.0,
                 "scatter": lambda: 190.0 if full else 165.0, "treemap": lambda: 150.0}
        if kind in sized:
            return float(sized[kind]())
        return 170 if full else 140

    def _draw_chart(self, spec: dict, x: float, y: float, w: float, h: float) -> None:
        draw = {"line": self._draw_line, "mirror": self._draw_mirror, "bar": self._draw_bars,
                "columns": self._draw_columns, "donut": self._draw_donut, "strips": self._draw_strips,
                "heatmap": self._draw_heatmap, "grid": self._draw_grid, "textbox": self._draw_textbox,
                "keyvalue": self._draw_keyvalue, "gauge": self._draw_gauge, "headline": self._draw_headline,
                "bullet": self._draw_bullet, "lollipop": self._draw_lollipop, "diverging": self._draw_diverging,
                "dumbbell": self._draw_dumbbell, "butterfly": self._draw_butterfly, "stack100": self._draw_stack100,
                "treemap": self._draw_treemap, "waterfall": self._draw_waterfall, "pareto": self._draw_pareto,
                "histogram": self._draw_histogram, "box": self._draw_box, "cdf": self._draw_cdf, "band": self._draw_band,
                "baseline": self._draw_baseline, "step": self._draw_step, "multiples": self._draw_multiples,
                "forecast": self._draw_forecast, "calendar": self._draw_calendar, "gantt": self._draw_gantt,
                "clock": self._draw_clock, "timeline": self._draw_timeline, "scatter": self._draw_scatter,
                "radar": self._draw_radar, "topology": self._draw_topology, "sparktable": self._draw_sparktable}.get(spec.get("kind"))
        if draw is None or not draw(spec, x, y, w, h):
            self._no_data(x, y, x + w, y + h, spec.get("empty_text") or "No data")

    def _no_data(self, x1: float, y1: float, x2: float, y2: float, text: str = "No data") -> None:
        self._op(f"{_rgb((0.8, 0.8, 0.8), 'RG')} 0.5 w {_n(x1)} {_n(y1)} {_n(x2 - x1)} {_n(y2 - y1)} re S")
        self._draw_text((x1 + x2) / 2, (y1 + y2) / 2 - 3, fit(text, x2 - x1 - 8, 9), 9, color=GREY, align="c")

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
        for t, v in spec.get("dots") or []:
            self._circle(sx(t), sy(v), 1.7, TONES["bad"])
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
        grouped = bool(spec.get("grouped")) and not stacked
        tones = spec.get("bar_tones") or []
        for i in range(len(labels)):
            bx = px1 + i * slot + (slot - bar_w) / 2
            base = low
            for si, s in enumerate(series):
                value = s["values"][i]
                if value is None:
                    continue
                if grouped:
                    each = bar_w / len(series)
                    self._rect(bx + si * each, sy(low), max(0.6, each - 0.6), max(0.0, sy(float(value)) - sy(low)),
                               self._series_colour(si, s.get("tone")))
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
        if spec.get("counts"):
            lx = x
            for label, tone, count in spec["counts"]:
                text = f"{label} {count}"
                self._rect(lx, y + 1, 7, 7, TONES.get(tone, TONES["none"]))
                self._draw_text(lx + 10, y + 1.5, text, 7, color=INK)
                lx += 18 + text_width(text, 7)
            y += 14
            h -= 14
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
