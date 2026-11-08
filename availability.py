"""Availability (uptime) per device, in the style of Uptime Kuma.

Source: every reachability check the scheduler runs (the ping-interval job, which for port
and HTTP checks also tests the service) is recorded here as one beat: up or down, plus the
response time. Metric history alone cannot give this: ping latency is stored only when the
host answers, so a missing sample cannot tell "down" from "monitor not running". Counting
real checks keeps the two apart: time with no checks is "no data" (grey), not downtime.

Tables:
  avail_beats      every check for the last BEATS_KEEP_HOURS (heartbeat bars, p95)
  avail_hourly     checks, up checks and response time sums per device per hour, kept
                   HOURLY_KEEP_DAYS (uptime % over 24 h to 90 d, the 30-day bar)
  avail_incidents  down periods: opened by the first failed check, closed by the first good one

Up means the device status after the check is "online": a ping device answered, a port
or HTTP check got its answer. A port check whose host answers ping but not the port
("degraded") counts as down: the service is what is being watched.
"""

import math
import time
from typing import Any, Dict, Iterable, List, Optional

import database

BEATS_KEEP_HOURS = 48
HOURLY_KEEP_DAYS = 100
WINDOWS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400}
# The bar for each range: hours per bar and how many bars (24 h: hours, 7 d: quarter days, 30 and 90 d: days).
RANGE_BARS = {"24h": (1, 24), "7d": (6, 28), "30d": (24, 30), "90d": (24, 90)}
# Response time comes from the check that decides up or down, in this order.
RESPONSE_KEYS = ("http_response_ms", "tcp_connect_ms", "icmp_ping_ms")


def init() -> None:
    with database.get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS avail_beats (
                device_id INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                up INTEGER NOT NULL,
                ms REAL,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_avail_beats ON avail_beats (device_id, ts);
            CREATE TABLE IF NOT EXISTS avail_hourly (
                device_id INTEGER NOT NULL,
                hour INTEGER NOT NULL,
                checks INTEGER NOT NULL,
                ups INTEGER NOT NULL,
                ms_sum REAL NOT NULL DEFAULT 0,
                ms_count INTEGER NOT NULL DEFAULT 0,
                ms_max REAL,
                PRIMARY KEY (device_id, hour),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS avail_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                started INTEGER NOT NULL,
                ended INTEGER,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_avail_incidents ON avail_incidents (device_id, started);
        """)
        conn.commit()


def response_ms(device_id: int, ping_ms: Optional[float]) -> Optional[float]:
    """The response time of the check that decided the result (HTTP, then TCP, then ping)."""
    with database.get_connection() as conn:
        rows = {r["metric_key"]: r for r in conn.execute(
            f"SELECT metric_key, value, timestamp FROM metric_latest WHERE device_id = ? AND metric_key IN "
            f"({','.join('?' * len(RESPONSE_KEYS))});", (device_id, *RESPONSE_KEYS))}
    now = time.time()
    for key in RESPONSE_KEYS:
        r = rows.get(key)
        # Only a value from this check (seconds old) counts; a stale one belongs to an older result.
        if r is not None and now - r["timestamp"] < 30:
            return float(r["value"])
    return ping_ms


def record(device_id: int, up: bool, ms: Optional[float], ts: Optional[int] = None, planned: bool = False) -> None:
    """Records one check: a beat, the hour's counters and the incident state.

    planned: the device is in a maintenance window (maintenance.py). A failed check then counts as
    planned downtime: the beat is kept (shown as planned, up = 2), the hour's counters and the
    incidents leave it out, so it does not lower uptime."""
    ts = int(ts if ts is not None else time.time())
    hour = ts - ts % 3600
    ms = float(ms) if ms is not None and math.isfinite(ms) else None
    if planned and not up:
        with database.get_connection() as conn:
            conn.execute("INSERT INTO avail_beats (device_id, ts, up, ms) VALUES (?, ?, 2, NULL);", (device_id, ts))
            conn.commit()
        return
    with database.get_connection() as conn:
        conn.execute("INSERT INTO avail_beats (device_id, ts, up, ms) VALUES (?, ?, ?, ?);",
                     (device_id, ts, 1 if up else 0, ms if up else None))
        conn.execute("""
            INSERT INTO avail_hourly (device_id, hour, checks, ups, ms_sum, ms_count, ms_max)
            VALUES (?, ?, 1, ?, ?, ?, ?)
            ON CONFLICT (device_id, hour) DO UPDATE SET
                checks = checks + 1, ups = ups + excluded.ups, ms_sum = ms_sum + excluded.ms_sum,
                ms_count = ms_count + excluded.ms_count,
                ms_max = CASE WHEN excluded.ms_max IS NULL THEN ms_max
                              WHEN ms_max IS NULL OR excluded.ms_max > ms_max THEN excluded.ms_max ELSE ms_max END;
        """, (device_id, hour, 1 if up else 0, ms if up and ms is not None else 0.0,
              1 if up and ms is not None else 0, ms if up else None))
        open_ = conn.execute("SELECT id FROM avail_incidents WHERE device_id = ? AND ended IS NULL "
                             "ORDER BY started DESC LIMIT 1;", (device_id,)).fetchone()
        if not up and not open_:
            conn.execute("INSERT INTO avail_incidents (device_id, started) VALUES (?, ?);", (device_id, ts))
        elif up and open_:
            conn.execute("UPDATE avail_incidents SET ended = ? WHERE id = ?;", (ts, open_["id"]))
        conn.commit()


def purge(now: Optional[int] = None) -> None:
    now = int(now if now is not None else time.time())
    with database.get_connection() as conn:
        conn.execute("DELETE FROM avail_beats WHERE ts < ?;", (now - BEATS_KEEP_HOURS * 3600,))
        conn.execute("DELETE FROM avail_hourly WHERE hour < ?;", (now - HOURLY_KEEP_DAYS * 86400,))
        conn.execute("DELETE FROM avail_incidents WHERE ended IS NOT NULL AND ended < ?;", (now - HOURLY_KEEP_DAYS * 86400,))
        conn.commit()


def _pct(ups: int, checks: int) -> Optional[float]:
    return round(100.0 * ups / checks, 3) if checks else None


def _p95(values: List[float]) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(math.ceil(0.95 * len(v))) - 1)], 2)


def summary(device_ids: Iterable[int], beats: int = 60, now: Optional[int] = None) -> Dict[int, Dict[str, Any]]:
    """Per device: uptime % per window, 24 h response average and p95, the last checks for the beat bar."""
    ids = sorted(set(int(i) for i in device_ids))
    now = int(now if now is not None else time.time())
    out: Dict[int, Dict[str, Any]] = {i: {"uptime": {k: None for k in WINDOWS}, "avg_ms": None, "p95_ms": None,
                                          "beats": [], "since": None, "down_since": None} for i in ids}
    if not ids:
        return out
    marks = ",".join("?" * len(ids))
    with database.get_connection() as conn:
        for name, span in WINDOWS.items():
            # Whole hours from the rollup; the current hour is partly in every window.
            for r in conn.execute(f"SELECT device_id, SUM(checks) AS c, SUM(ups) AS u FROM avail_hourly "
                                  f"WHERE device_id IN ({marks}) AND hour >= ? GROUP BY device_id;",
                                  (*ids, now - span - (now - span) % 3600)):
                out[r["device_id"]]["uptime"][name] = _pct(r["u"], r["c"])
        for r in conn.execute(f"SELECT device_id, MIN(hour) AS h FROM avail_hourly WHERE device_id IN ({marks}) "
                              f"GROUP BY device_id;", ids):
            out[r["device_id"]]["since"] = r["h"]
        per: Dict[int, List[float]] = {}
        for r in conn.execute(f"SELECT device_id, ms FROM avail_beats WHERE device_id IN ({marks}) AND ts >= ? "
                              f"AND up = 1 AND ms IS NOT NULL;", (*ids, now - 86400)):
            per.setdefault(r["device_id"], []).append(r["ms"])
        for i, vals in per.items():
            out[i]["avg_ms"] = round(sum(vals) / len(vals), 2)
            out[i]["p95_ms"] = _p95(vals)
        for i in ids:
            rows = conn.execute("SELECT ts, up, ms FROM avail_beats WHERE device_id = ? ORDER BY ts DESC LIMIT ?;",
                                (i, beats)).fetchall()
            out[i]["beats"] = [{"t": r["ts"], "up": r["up"] == 1, "planned": r["up"] == 2, "ms": r["ms"]} for r in reversed(rows)]
        for r in conn.execute(f"SELECT device_id, started FROM avail_incidents WHERE device_id IN ({marks}) "
                              f"AND ended IS NULL;", ids):
            out[r["device_id"]]["down_since"] = r["started"]
    return out


def ranged(device_ids: Iterable[int], key: str, tz_minutes: int = 0, now: Optional[int] = None) -> Dict[int, Dict[str, Any]]:
    """Per device, for one range (24h, 7d, 30d, 90d): uptime %, average response time and the bars.

    Bars come from the hourly counters: [start, checks, up checks, average ms]. They are aligned
    to the viewer's clock (tz_minutes east of UTC), so day bars start at local midnight and the
    last bar is the current, partial one. Bars with no checks are "no data", never up or down."""
    if key not in RANGE_BARS:
        raise ValueError("range is 24h, 7d, 30d or 90d")
    ids = sorted(set(int(i) for i in device_ids))
    now = int(now if now is not None else time.time())
    size_h, count = RANGE_BARS[key]
    size = size_h * 3600
    offset = int(tz_minutes) * 60
    last = (now + offset) // size * size - offset       # start of the current bar, in UTC seconds
    first = last - (count - 1) * size
    bars = {i: [[first + n * size, 0, 0, 0.0, 0] for n in range(count)] for i in ids}
    if ids:
        marks = ",".join("?" * len(ids))
        with database.get_connection() as conn:
            rows = conn.execute(f"SELECT device_id, hour, checks, ups, ms_sum, ms_count FROM avail_hourly "
                                f"WHERE device_id IN ({marks}) AND hour >= ?;", (*ids, first - 3600)).fetchall()
        for r in rows:
            n = (r["hour"] - first) // size
            if 0 <= n < count:
                b = bars[r["device_id"]][n]
                b[1] += r["checks"]
                b[2] += r["ups"]
                b[3] += r["ms_sum"]
                b[4] += r["ms_count"]
    out = {}
    for i in ids:
        checks = sum(b[1] for b in bars[i])
        ups = sum(b[2] for b in bars[i])
        ms_sum = sum(b[3] for b in bars[i])
        ms_n = sum(b[4] for b in bars[i])
        out[i] = {"uptime": _pct(ups, checks), "avg_ms": round(ms_sum / ms_n, 2) if ms_n else None,
                  "bars": [[b[0], b[1], b[2], round(b[3] / b[4], 2) if b[4] else None] for b in bars[i]],
                  "bar_hours": size_h}
    return out


def detail(device_id: int, now: Optional[int] = None) -> Dict[str, Any]:
    """One device: the summary, 31 days of hourly counters and recent incidents.

    Hours are sent raw ([hour start, checks, up checks, average ms]) so the browser groups them
    into its own local days; grouping here would cut days at UTC midnight."""
    now = int(now if now is not None else time.time())
    base = summary([device_id], beats=120, now=now)[device_id]
    with database.get_connection() as conn:
        hourly = conn.execute("SELECT hour, checks, ups, ms_sum, ms_count FROM avail_hourly "
                              "WHERE device_id = ? AND hour >= ? ORDER BY hour;",
                              (device_id, now - 31 * 86400)).fetchall()
        incidents = conn.execute("SELECT started, ended FROM avail_incidents WHERE device_id = ? "
                                 "ORDER BY started DESC LIMIT 50;", (device_id,)).fetchall()
    base["hourly"] = [[r["hour"], r["checks"], r["ups"], round(r["ms_sum"] / r["ms_count"], 2) if r["ms_count"] else None]
                      for r in hourly]
    base["incidents"] = [{"started": r["started"], "ended": r["ended"],
                          "seconds": (r["ended"] or now) - r["started"]} for r in incidents]
    base["now"] = now
    return base
