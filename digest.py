"""The digest: a short daily or weekly summary on Telegram. Off unless switched on (Settings,
Notifications, When: Summary message).

It says, for the period since the last one:
  availability overall and the devices that were down most
  problems opened, how many are still open, and the devices that had the most
  new devices on the network (inventory)
  volumes and disks forecast to be full within 60 days
  certificates of website checks running out within 30 days
Plain text, a few lines; nothing is sent when Telegram is off.
"""

import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional

import availability
import database
import forecast
import inventory

LAST_KEY = "digest_last"
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


def due(settings: Dict[str, str], now: Optional[datetime] = None) -> Optional[str]:
    """'daily' or 'weekly' when a digest should go out now (local time), else None."""
    now = now or datetime.now()
    mode = settings.get("notify_digest", "off")
    if mode not in ("daily", "weekly"):
        return None
    try:
        hh, mm = (int(x) for x in (settings.get("notify_digest_time") or "08:00").split(":"))
    except ValueError:
        hh, mm = 8, 0
    if (now.hour, now.minute) < (hh, mm):
        return None
    if mode == "weekly" and DAYS[now.weekday()] != (settings.get("notify_digest_day") or "monday"):
        return None
    stamp = now.strftime("%Y-%m-%d")
    if settings.get(LAST_KEY) == stamp:
        return None
    return mode


def compose(mode: str, now: Optional[float] = None) -> str:
    now = now if now is not None else time.time()
    span = 7 * 86400 if mode == "weekly" else 86400
    since = now - span
    first = datetime.fromtimestamp(since)
    title = (f"Weekly summary, {first:%d %b} to {datetime.fromtimestamp(now):%d %b}" if mode == "weekly"
             else f"Daily summary, {datetime.fromtimestamp(now):%A %d %b}")
    lines = [title, ""]
    devices = {d["id"]: d for d in database.list_devices()}
    # Availability.
    ranged = availability.ranged(list(devices), "7d" if mode == "weekly" else "24h")
    ups = [(devices[i]["hostname"], r["uptime"]) for i, r in ranged.items() if r["uptime"] is not None]
    if ups:
        overall = sum(u for _, u in ups) / len(ups)
        worst = sorted((x for x in ups if x[1] < 100), key=lambda x: x[1])[:3]
        lines.append(f"Availability: {len(ups)} devices, {overall:.1f}% on average."
                     + (f" Lowest: {', '.join(f'{n} {u:.1f}%' for n, u in worst)}." if worst else " Everything was up the whole time."))
    # Problems.
    with database.get_connection() as conn:
        opened = conn.execute("SELECT device_id, COUNT(*) AS n FROM events WHERE event_type = 'problem' AND message LIKE 'Problem:%' "
                              "AND timestamp >= ? GROUP BY device_id ORDER BY n DESC;", (int(since),)).fetchall()
        loud, loud_args = inventory.loud_sql()
        new = conn.execute(f"SELECT COUNT(*) FROM inventory WHERE first_seen >= ? AND known = 0 AND {loud};",
                           (int(since), *loud_args)).fetchone()[0]
        certs = conn.execute("SELECT device_id, value FROM metric_latest WHERE metric_key = 'tls_days_left' AND value <= 30 "
                             "ORDER BY value;").fetchall()
    total = sum(r["n"] for r in opened)
    still = sum(1 for p in database.list_active_problems() if p["severity"] != "info")
    if total:
        top = ", ".join(f"{devices[r['device_id']]['hostname']} ({r['n']})" for r in opened[:3] if r["device_id"] in devices)
        lines.append(f"Problems: {total} opened, {still} still open. Most: {top}.")
    else:
        lines.append(f"Problems: none opened{f', {still} still open from before' if still else ''}.")
    if new:
        lines.append(f"New on the network: {new} (see Inventory).")
    soon = [(devices[d]["hostname"], f) for d, rows in forecast.cached(now).items() if d in devices
            for f in rows if f["days"] is not None and f["days"] <= 60]
    if soon:
        lines.append("Filling up: " + "; ".join(f"{n} {f['label']} full in about {f['days']:.0f} days" for n, f in soon[:4]) + ".")
    if certs:
        lines.append("Certificates: " + "; ".join(
            f"{devices[r['device_id']]['hostname']} {max(0, int(r['value']))} days left" for r in certs[:4] if r["device_id"] in devices) + ".")
    return "\n".join(lines)


def run(settings: Dict[str, str], send: Callable[[str], Any], now: Optional[datetime] = None) -> bool:
    """Sends the digest when it is due. True when one went out."""
    mode = due(settings, now)
    if not mode:
        return False
    now = now or datetime.now()
    database.set_internal_setting(LAST_KEY, now.strftime("%Y-%m-%d"))
    send(compose(mode, now.timestamp()))
    return True
