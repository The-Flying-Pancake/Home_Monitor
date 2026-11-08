"""Forecasts: how long until a volume or disk is full, from its own history.

Source: the hourly averages (metrics_hourly) of the "used percent" series:
  vol.<n>.used_pct   NAS volumes (QNAP, Synology)
  stor.<n>.used_pct  disks and mount points of hosts (HOST-RESOURCES-MIB, recorded by the poller)

A straight line (least squares) through the last LOOKBACK_DAYS of hours gives the growth per
day; the days left are (100 - now) / growth. Too little history (under MIN_HOURS, or spread over
less than MIN_SPAN_HOURS), or a series that is flat or shrinking, has no forecast: it is not
going to fill up on its own. Results are worked out at most once an hour (they are cheap, but
nothing changes faster than the hourly averages they read).
"""

import re
import time
from typing import Any, Dict, List, Optional

import database

LOOKBACK_DAYS = 14
MIN_HOURS = 24
MIN_SPAN_HOURS = 48
MIN_GROWTH_PER_DAY = 0.01      # percent points per day; below this the volume is effectively flat
MAX_DAYS = 3650
KEY_RE = re.compile(r"^(vol|stor|pvs)\.([^.]+)\.used_pct$")
CACHE_SECONDS = 3600
_cache: Dict[str, Any] = {"at": 0.0, "data": {}}


def fit(points: List[List[float]]) -> Optional[Dict[str, float]]:
    """points: [[timestamp, percent], ...] in time order. Returns growth per day, the fitted value
    now and the days until 100 %, or None when there is no meaningful forecast."""
    if len(points) < MIN_HOURS or points[-1][0] - points[0][0] < MIN_SPAN_HOURS * 3600:
        return None
    n = len(points)
    xs = [(p[0] - points[0][0]) / 86400.0 for p in points]
    ys = [p[1] for p in points]
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= 0:
        return None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    now_value = my + slope * (xs[-1] - mx)
    if slope < MIN_GROWTH_PER_DAY:
        return {"per_day": round(slope, 3), "now": round(now_value, 2), "days": None}
    days = max(0.0, (100.0 - max(ys[-1], now_value)) / slope)
    return {"per_day": round(slope, 3), "now": round(now_value, 2), "days": round(min(days, MAX_DAYS), 1)}


def compute(now: Optional[float] = None) -> Dict[int, List[Dict[str, Any]]]:
    """Per device: every filling series with a forecast, soonest full first."""
    now = now if now is not None else time.time()
    since = int(now - LOOKBACK_DAYS * 86400)
    series: Dict[tuple, List[List[float]]] = {}
    with database.get_connection() as conn:
        for r in conn.execute("SELECT device_id, metric_key, hour, avg FROM metrics_hourly WHERE hour >= ? AND "
                              "(metric_key LIKE 'vol.%.used_pct' OR metric_key LIKE 'stor.%.used_pct' OR metric_key LIKE 'pvs.%.used_pct') "
                              "ORDER BY device_id, metric_key, hour;", (since,)):
            series.setdefault((r["device_id"], r["metric_key"]), []).append([r["hour"], r["avg"]])
    out: Dict[int, List[Dict[str, Any]]] = {}
    labels: Dict[int, Dict[str, str]] = {}
    for (device_id, key), points in series.items():
        f = fit(points)
        if not f:
            continue
        if device_id not in labels:
            labels[device_id] = _labels(device_id)
        out.setdefault(device_id, []).append(dict(f, key=key, label=labels[device_id].get(key, key),
                                                  full_on=int(now + f["days"] * 86400) if f["days"] is not None else None))
    for rows in out.values():
        rows.sort(key=lambda r: r["days"] if r["days"] is not None else MAX_DAYS + 1)
    return out


def _labels(device_id: int) -> Dict[str, str]:
    """Names for the series: the volume or mount point as the device reports it."""
    out = {}
    for idx, v in database.get_device_table(device_id, "volumes").items():
        name = str(v.get("descr") or idx)
        # QNAP names its volumes "Volume Data, Pool 1" already.
        out[f"vol.{idx}.used_pct"] = name if name.lower().startswith("volume") else f"Volume {name}"
    for idx, s in database.get_device_table(device_id, "storage").items():
        out[f"stor.{idx}.used_pct"] = f"Storage {s.get('descr') or idx}"
    # Proxmox storage pools (proxmox.refresh), on the node's device.
    import proxmox
    for s in proxmox.layout().get("storage", []):
        out[f"pvs.{proxmox.storage_slug(s['storage'])}.used_pct"] = f"Proxmox storage {s['storage']}"
    return out


def cached(now: Optional[float] = None) -> Dict[int, List[Dict[str, Any]]]:
    now = now if now is not None else time.time()
    if now - _cache["at"] > CACHE_SECONDS:
        _cache["data"] = compute(now)
        _cache["at"] = now
    return _cache["data"]


def clear_cache() -> None:
    _cache["at"] = 0.0
