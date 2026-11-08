"""Telegram commands: the bot answers a few read-only questions from the configured chat.

  /status            what is up and down, open problems, maintenance on now
  /problems          the open problems, most severe first, with how long each has been open
  /device <name>     one device: state, address, latest figures and its open problems
  /changes           the last 24 hours: new devices on the network, restarts, problems opened
  /help              this list

Nothing a command does changes anything: no acknowledging, muting or running workflows.

How it stays inside the air gap: the monitor asks Telegram for new messages (getUpdates, long
polling over the same HTTPS connection notifications use), so nothing on the internet connects in.
Only messages from the chat in Settings (telegram_chat_id) are answered; any other chat is ignored
and noted once an hour in the audit log. Every command answered is in the audit log too. Messages
older than STALE_SECONDS (sent while the monitor was off) are skipped rather than answered late.
Replies never hold secrets: they are built from device names, addresses, states and figures.

Switched by the setting telegram_commands (on by default, only while Telegram is on). The administrator
can rewrite each reply in Settings, Notifications, Commands (settings bot_tpl_*, see TEMPLATES),
switch commands off and add their own (botcmds.py). Telegram's command menu (setMyCommands)
follows the list.
"""

import json
import logging
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import database
import inventory
import tpl
import maintenance
import notify

log = logging.getLogger("telebot")

OFFSET_KEY = "telegram_offset"
POLL_SECONDS = 25            # Telegram holds the request open this long when nothing arrives
STALE_SECONDS = 300
FIND_SECONDS = 120           # Find my chat: how long after the button a message to the bot counts
BACKOFF_SECONDS = (15, 30, 60, 120, 300)
MAX_LINES = 60
SEVERITY_MARK = {"critical": "🔴", "high": "🟠", "warning": "🟡", "info": "🔵"}
STATE_WORD = {"online": "up", "offline": "down", "degraded": "degraded"}

# The built-in commands: what /help and Telegram's command menu say about them.
BUILTIN_INFO = {"status": "What is up and down", "problems": "The open problems", "device": "One device: /device NAME",
                "changes": "The last 24 hours"}


def menu() -> List[Dict[str, str]]:
    """Every command switched on, built-in ones first: [{command, description}]."""
    import botcmds
    data = botcmds.load()
    out = [{"command": k, "description": v} for k, v in BUILTIN_INFO.items() if k not in data["off"]]
    out += [{"command": c["name"], "description": c["description"][:100] or c["name"]} for c in data["custom"]
            if c["name"] not in data["off"]]
    return out + [{"command": "help", "description": "This list"}]


def help_text() -> str:
    return "Commands (read only):\n" + "\n".join(f"/{m['command']}: {m['description']}" for m in menu())




def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


def _clip(lines: List[str], more: int = 0) -> str:
    if len(lines) > MAX_LINES:
        more += len(lines) - MAX_LINES
        lines = lines[:MAX_LINES]
    if more:
        lines.append(f"... and {more} more (see the app)")
    return "\n".join(lines)[:notify.MAX_TEXT]


# --- The answers: values for each command, filled into the reply template ---
#
# Each reply is a template (Settings, Notifications, Commands) with {placeholders}. A placeholder
# that has nothing to say is empty, and a line left empty by its placeholders is dropped, so
# "{down_list}" adds no line while everything is up. Lists come as ready lines; a problem in a list
# is written with the "One problem in a list" template.

# key: (label, help, default text, ready-made alternatives)
TEMPLATES = {
    "status": ("/status reply", "What /status answers.",
               "{all_ok} {total} devices: {up} up, {down} down{degraded_part}\n{down_list}\n{problems_line}\n{maintenance}",
               ["🏠 {time}: {up}/{total} up\n{down_list}\n{problems_line}",
                "{all_ok} Up {up}, down {down}. Problems: {problems}\n{down_list}"]),
    "problems": ("/problems reply", "What /problems answers. {list} holds one line per problem.",
                 "{summary}\n{list}",
                 ["🚨 {count} open ({critical} critical)\n{list}", "{summary}\n{list}\n\nAs of {time}"]),
    "problem_item": ("One problem in a list", "How each problem is written in /problems and /device.",
                     "{mark} {device}: {problem} ({duration}{acknowledged})",
                     ["{mark} {severity} {device}: {problem}, {duration}", "• {device}: {problem} ({duration})"]),
    "device": ("/device reply", "What /device NAME answers.",
               "{device} ({ip}): {state}\n{figures}\n{problems_list}",
               ["🖥️ {device} is {state}\n{figures}\n{problems_list}",
                "{device} ({ip}) {state}\nPing {ping}\nCPU {cpu}, memory {memory}\nUp for {uptime}\n{problems_list}"]),
    "changes": ("/changes reply", "What /changes answers.",
                "The last 24 hours:\n{new_list}\n{restarts}\n{problems_line}\n{opened_list}\n{nothing}",
                ["📋 Since yesterday:\n{new_list}\n{restarts}\n{problems_line}\n{nothing}"]),
}

# Placeholders per template: name -> what it holds. Shown in the editor.
TEMPLATE_PLACEHOLDERS = {
    "status": {"time": "Time of the answer (HH:MM)", "total": "Number of devices", "up": "Devices up",
               "down": "Devices down", "degraded": "Devices degraded",
               "degraded_part": "', 2 degraded' when some are, else empty",
               "down_list": "'Down: nas-01, cam2' when something is down, else empty",
               "problems": "Open problems (number)", "critical": "Critical problems", "high": "High problems",
               "warning": "Warning problems",
               "problems_line": "'Open problems: 1 critical, 2 warning. /problems lists them.' or 'No open problems.'",
               "maintenance": "One line per maintenance window on now, else empty",
               "all_ok": "✅ when nothing is down and no problem is open, else empty"},
    "problems": {"time": "Time of the answer (HH:MM)", "count": "Open problems (number)", "critical": "Critical problems",
                 "high": "High problems", "warning": "Warning problems",
                 "summary": "'3 open problems:' or '✅ No open problems.'",
                 "list": "One line per problem (see One problem in a list)"},
    "problem_item": {"mark": "Colour dot for the severity", "severity": "critical, high or warning", "device": "Device name",
                     "ip": "Device address", "problem": "Problem text", "duration": "How long it has been open",
                     "acknowledged": "', acknowledged' when it is, else empty"},
    "device": {"device": "Device name", "ip": "Device address", "state": "up, down or degraded", "template": "Device template",
               "ping": "Last ping (12 ms), empty when down", "cpu": "CPU use (34%), empty when not known",
               "memory": "Memory use (61%), empty when not known", "uptime": "How long it has been up, empty when not known",
               "last_seen": "When it last answered, only while down",
               "figures": "Ping, CPU, memory and uptime on one line, whichever are known",
               "problems": "Its open problems (number)",
               "problems_list": "One line per problem, or 'No open problems.'"},
    "changes": {"time": "Time of the answer (HH:MM)", "new": "New devices on the network (number)",
                "new_list": "'New on the network (2): phone, 192.168.1.77' or empty",
                "restarts": "'Restarted: nas-01, pve' or empty", "opened": "Problems opened (number)",
                "resolved": "Problems resolved (number)",
                "problems_line": "'Problems: 3 opened, 2 resolved' or empty",
                "opened_list": "One line per problem opened, or empty",
                "nothing": "'Nothing changed.' when there is nothing else to say, else empty"},
}

_FIELD = re.compile(r"\{([\w.:-]+)\}")   # metric:<key> names hold dots and dashes


def template(settings: Dict[str, str], key: str) -> str:
    return (settings.get(f"bot_tpl_{key}") or "").strip() or TEMPLATES[key][2]


def fill(text: str, values: Dict[str, Any]) -> str:
    """Fills the placeholders (tpl.py: filters, arithmetic, {if}). A line whose placeholders were all
    empty and that holds nothing else is dropped; unknown names are left as written, so a typo shows."""
    return _clip(tpl.render(text, values, max_len=8000).split("\n"))


def _counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    by = {"critical": 0, "high": 0, "warning": 0}
    for p in rows:
        by[p["severity"]] = by.get(p["severity"], 0) + 1
    return by


def _item(settings: Dict[str, str], p: Dict[str, Any], now: float) -> str:
    return fill(template(settings, "problem_item"), {
        "mark": SEVERITY_MARK.get(p["severity"], ""), "severity": p["severity"], "device": p["hostname"],
        "ip": p.get("ip_address", ""), "problem": p["message"], "duration": _ago(now - p["since"]),
        "acknowledged": ", acknowledged" if p["acknowledged_at"] else ""})


def _open_problems() -> List[Dict[str, Any]]:
    return [p for p in database.list_active_problems() if p["severity"] != "info"]


def status_values(now: float) -> Dict[str, Any]:
    devices = database.list_devices()
    counts = {"online": 0, "offline": 0, "degraded": 0}
    for d in devices:
        counts[d["status"]] = counts.get(d["status"], 0) + 1
    down = [d["hostname"] for d in devices if d["status"] == "offline"]
    rows = _open_problems()
    by = _counts(rows)
    if rows:
        line = ("Open problems: " + ", ".join(f"{by[s]} {s}" for s in ("critical", "high", "warning") if by[s])
                + ". /problems lists them.")
    else:
        line = "No open problems."
    maint = []
    for w in [w for w in maintenance.windows(now) if w["state"] == "active"][:3]:
        what = "everything" if w["scope"] == "all" else f"{w['scope']} {w['target']}"
        maint.append(f"Maintenance on {what} until {datetime.fromtimestamp(w['end']):%H:%M}")
    return {"time": f"{datetime.fromtimestamp(now):%H:%M}", "total": len(devices), "up": counts["online"],
            "down": counts["offline"], "degraded": counts.get("degraded", 0),
            "degraded_part": f", {counts['degraded']} degraded" if counts.get("degraded") else "",
            "down_list": ("Down: " + ", ".join(down[:10]) + (f" and {len(down) - 10} more" if len(down) > 10 else "")) if down else "",
            "problems": len(rows), "critical": by["critical"], "high": by["high"], "warning": by["warning"],
            "problems_line": line, "maintenance": "\n".join(maint),
            "all_ok": "✅" if not down and not rows else ""}


def status(now: Optional[float] = None, settings: Optional[Dict[str, str]] = None) -> str:
    now = now if now is not None else time.time()
    settings = settings if settings is not None else database.get_all_settings()
    return fill(template(settings, "status"), status_values(now))


def problems_values(now: float, settings: Dict[str, str]) -> Dict[str, Any]:
    rows = _open_problems()
    by = _counts(rows)
    return {"time": f"{datetime.fromtimestamp(now):%H:%M}", "count": len(rows), **by,
            "summary": f"{len(rows)} open problem{'s' if len(rows) != 1 else ''}:" if rows else "✅ No open problems.",
            "list": "\n".join(_item(settings, p, now) for p in rows)}


def problems(now: Optional[float] = None, settings: Optional[Dict[str, str]] = None) -> str:
    now = now if now is not None else time.time()
    settings = settings if settings is not None else database.get_all_settings()
    return fill(template(settings, "problems"), problems_values(now, settings))


def _find(devices: List[Dict[str, Any]], name: str) -> List[Dict[str, Any]]:
    """Exact name or address first, then names starting with it, then names containing it."""
    q = name.strip().lower()
    for test in (lambda d: d["hostname"].lower() == q or d["ip_address"] == q,
                 lambda d: d["hostname"].lower().startswith(q),
                 lambda d: q in d["hostname"].lower()):
        hits = [d for d in devices if test(d)]
        if hits:
            return hits
    return []


def device_values(d: Dict[str, Any], now: float, settings: Dict[str, str]) -> Dict[str, Any]:
    latest = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(d["id"])}
    down = d["status"] == "offline"
    ping = f"{d['last_ping_ms']:.0f} ms" if d.get("last_ping_ms") is not None and not down else ""
    cpu = f"{latest['cpu_usage_pct']:.0f}%" if latest.get("cpu_usage_pct") is not None else ""
    mem = next((f"{latest[k]:.0f}%" for k in ("mem_used_pct", "mem_pct") if latest.get(k) is not None), "")
    uptime = _ago(latest["uptime_seconds"]) if latest.get("uptime_seconds") and not down else ""
    seen = f"{_ago(now - d['last_seen'])} ago" if down and d.get("last_seen") else ""
    figures = ", ".join(x for x in (f"last seen {seen}" if seen else "", f"ping {ping}" if ping else "",
                                    f"CPU {cpu}" if cpu else "", f"memory {mem}" if mem else "",
                                    f"up for {uptime}" if uptime else "") if x)
    mine = [dict(p, ip_address=d["ip_address"]) for p in _open_problems() if p["device_id"] == d["id"]]
    return {"device": d["hostname"], "ip": d["ip_address"], "template": d["profile_id"],
            "state": STATE_WORD.get(d["status"], d["status"] or "not checked yet"),
            "ping": ping, "cpu": cpu, "memory": mem, "uptime": uptime, "last_seen": seen, "figures": figures,
            "problems": len(mine),
            "problems_list": "\n".join(_item(settings, p, now) for p in mine) if mine else "No open problems."}


def device(name: str, now: Optional[float] = None, settings: Optional[Dict[str, str]] = None) -> str:
    now = now if now is not None else time.time()
    settings = settings if settings is not None else database.get_all_settings()
    if not name.strip():
        return "Which device? For example: /device nas-01"
    hits = _find(database.list_devices(), name)
    if not hits:
        return f"No device called {name.strip()[:40]}."
    if len(hits) > 1:
        return _clip([f"{len(hits)} devices match. Which one?"] + [f"/device {d['hostname']}" for d in hits])
    return fill(template(settings, "device"), device_values(hits[0], now, settings))


def changes_values(now: float) -> Dict[str, Any]:
    since = int(now - 86400)
    with database.get_connection() as conn:
        loud, loud_args = inventory.loud_sql()
        new = conn.execute(f"SELECT ip, seen_name, vendor FROM inventory WHERE first_seen >= ? AND known = 0 AND {loud} "
                           "ORDER BY first_seen DESC;", (since, *loud_args)).fetchall()
        events = conn.execute("SELECT e.event_type, e.message, d.hostname FROM events e LEFT JOIN devices d ON d.id = e.device_id "
                              "WHERE e.timestamp >= ? AND e.event_type IN ('reboot', 'problem') ORDER BY e.timestamp DESC;",
                              (since,)).fetchall()
    names = [r["seen_name"] or r["vendor"] or r["ip"] or "unknown" for r in new]
    restarts = sorted({r["hostname"] for r in events if r["event_type"] == "reboot" and r["hostname"]})
    opened = [r for r in events if r["event_type"] == "problem" and r["message"].startswith("Problem:")]
    resolved = sum(1 for r in events if r["event_type"] == "problem" and r["message"].startswith("Resolved:"))
    quiet = not (new or restarts or opened or resolved)
    return {"time": f"{datetime.fromtimestamp(now):%H:%M}", "new": len(new),
            "new_list": (f"New on the network ({len(new)}): " + ", ".join(names[:8]) + (" and more" if len(names) > 8 else "")) if new else "",
            "restarts": ("Restarted: " + ", ".join(restarts[:10])) if restarts else "",
            "opened": len(opened), "resolved": resolved,
            "problems_line": f"Problems: {len(opened)} opened, {resolved} resolved" if opened or resolved else "",
            "opened_list": "\n".join(f"  {r['hostname'] or 'monitor'}: {r['message'][len('Problem:'):].strip()}" for r in opened[:8]),
            "nothing": "Nothing changed." if quiet else ""}


def changes(now: Optional[float] = None, settings: Optional[Dict[str, str]] = None) -> str:
    now = now if now is not None else time.time()
    settings = settings if settings is not None else database.get_all_settings()
    return fill(template(settings, "changes"), changes_values(now))


def samples(now: Optional[float] = None) -> Dict[str, Dict[str, Any]]:
    """Today's real values for each template, for the editor's preview."""
    now = now if now is not None else time.time()
    settings = database.get_all_settings()
    devices = database.list_devices()
    rows = _open_problems()
    pick = next((d for d in devices if any(p["device_id"] == d["id"] for p in rows)), devices[0] if devices else None)
    item = {"mark": "🟡", "severity": "warning", "device": "nas-01", "ip": "192.168.1.99", "problem": "CPU usage 97% (threshold 90%)",
            "duration": "12m", "acknowledged": ""}
    if rows:
        p = rows[0]
        item = {"mark": SEVERITY_MARK.get(p["severity"], ""), "severity": p["severity"], "device": p["hostname"], "ip": "",
                "problem": p["message"], "duration": _ago(now - p["since"]), "acknowledged": ", acknowledged" if p["acknowledged_at"] else ""}
    return {"status": status_values(now), "problems": problems_values(now, settings), "problem_item": item,
            "device": device_values(pick, now, settings) if pick else {}, "changes": changes_values(now)}


COMMANDS: Dict[str, Callable[[str, Dict[str, str]], str]] = {
    "status": lambda arg, s: status(settings=s),
    "problems": lambda arg, s: problems(settings=s),
    "device": lambda arg, s: device(arg, settings=s),
    "changes": lambda arg, s: changes(settings=s),
    "help": lambda arg, s: help_text(),
    "start": lambda arg, s: help_text(),
}


def answer(text: str, settings: Optional[Dict[str, str]] = None) -> Optional[str]:
    """The reply to one message, or None for a message that is not a command."""
    text = (text or "").strip()
    if not text.startswith("/"):
        return None
    import botcmds
    word, _, arg = text[1:].partition(" ")
    cmd = word.split("@", 1)[0].lower()           # /status@MyBot in a group
    off = botcmds.load()["off"]
    fn = COMMANDS.get(cmd) if cmd not in off else None
    if fn is not None:
        return fn(arg, settings if settings is not None else database.get_all_settings())
    own = botcmds.find(cmd)
    if own is not None:
        return botcmds.render(own, arg)
    return f"I do not know /{cmd[:30]}.\n\n{help_text()}"


# --- Polling ---

def _get_updates(token: str, offset: int, timeout: int) -> List[Dict[str, Any]]:
    payload = {"offset": offset, "timeout": timeout, "allowed_updates": ["message"]}
    req = urllib.request.Request(f"{notify.API}/bot{token}/getUpdates", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout + 15, context=ssl.create_default_context()) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        exc.close()
        raise notify.TelegramError(f"Telegram refused getUpdates (HTTP {exc.code})")   # the URL holds the token
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise notify.TelegramError(f"Could not reach Telegram: {type(getattr(exc, 'reason', exc)).__name__}")
    if not data.get("ok"):
        raise notify.TelegramError(data.get("description", "Telegram returned an error"))
    return data.get("result") or []


def chat_name(c: Dict[str, Any]) -> str:
    return c.get("title") or " ".join(x for x in (c.get("first_name"), c.get("last_name")) if x) or c.get("username", "")


def find_chat_since(token: str, since: float) -> Optional[Dict[str, str]]:
    """Find my chat while the bot is not polling: the newest chat that messaged the bot after the
    search started, {id, name}. Older messages (anyone's) do not count."""
    updates = notify._post(token, "getUpdates", {"limit": 50, "timeout": 0})
    for u in reversed(updates or []):
        msg = u.get("message") or u.get("channel_post") or {}
        if msg.get("chat") and float(msg.get("date") or 0) >= int(since):
            return {"id": str(msg["chat"]["id"]), "name": chat_name(msg["chat"])}
    return None


def enabled(s: Dict[str, str]) -> bool:
    return (s.get("telegram_enabled") == "on" and s.get("telegram_commands", "on") == "on"
            and bool(s.get("telegram_token")) and bool(s.get("telegram_chat_id")))


class Bot:
    def __init__(self, settings: Callable[[], Dict[str, str]],
                 fetch: Callable[[str, int, int], List[Dict[str, Any]]] = None,
                 sender: Callable[..., None] = None) -> None:
        self.settings = settings
        self.fetch = fetch or _get_updates
        self.sender = sender or notify.send
        self.thread: Optional[threading.Thread] = None
        self.last_error = ""
        self._stranger_noted: Dict[str, float] = {}
        # Find my chat: while a search runs (find_since, FIND_SECONDS), the chat of the newest message
        # is kept here, since a second getUpdates would cut this poll off. Outside a search nothing is kept.
        self.last_chat: Optional[Dict[str, str]] = None
        self.find_since = 0.0
        # The command menu Telegram shows on "/", sent again whenever the commands change.
        self.menu_sent = ""
        self.menu_sender: Callable[[str, List[Dict[str, str]]], None] = lambda token, cmds: notify._post(
            token, "setMyCommands", {"commands": cmds})

    def sync_menu(self, token: str) -> None:
        cmds = menu()
        sig = json.dumps(cmds, sort_keys=True)
        if sig == self.menu_sent:
            return
        try:
            self.menu_sender(token, cmds)
            self.menu_sent = sig
        except notify.TelegramError as exc:
            log.info("Telegram command menu not updated: %s", exc)
            self.menu_sent = sig          # not retried every round; the next change tries again

    def start_find(self, now: Optional[float] = None) -> None:
        """Starts a Find my chat search: only messages from now on count."""
        self.find_since = now if now is not None else time.time()
        self.last_chat = None

    def finding(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) - self.find_since < FIND_SECONDS

    def end_find(self) -> None:
        self.find_since = 0.0
        self.last_chat = None

    def start(self) -> None:
        if self.thread is None:
            self.thread = threading.Thread(target=self._loop, name="telebot", daemon=True)
            self.thread.start()

    def _loop(self) -> None:
        failures = 0
        while True:
            try:
                if not enabled(self.settings()):
                    time.sleep(10)
                    continue
                self.poll_once(POLL_SECONDS)
                failures = 0
            except notify.TelegramError as exc:
                self.last_error = str(exc)
                time.sleep(BACKOFF_SECONDS[min(failures, len(BACKOFF_SECONDS) - 1)])
                failures += 1
            except Exception:
                log.exception("Telegram commands failed; retrying shortly")
                time.sleep(30)

    def poll_once(self, timeout: int = 0, now: Optional[float] = None) -> int:
        """One getUpdates round: answers what it should. Returns how many commands were answered."""
        s = self.settings()
        if not enabled(s):
            return 0
        token, chat = s["telegram_token"], str(s["telegram_chat_id"])
        self.sync_menu(token)
        try:
            offset = int(s.get(OFFSET_KEY) or 0)
        except ValueError:
            offset = 0
        updates = self.fetch(token, offset, timeout)
        now = now if now is not None else time.time()
        answered = 0
        for u in updates:
            # Confirmed first: a message that breaks the reply is not tried again and again.
            offset = max(offset, int(u.get("update_id", 0)) + 1)
            database.set_internal_setting(OFFSET_KEY, str(offset))
            msg = u.get("message") or {}
            text = msg.get("text") or ""
            from_chat = str((msg.get("chat") or {}).get("id", ""))
            # Telegram dates are whole seconds.
            if msg.get("chat") and self.finding(now) and float(msg.get("date") or 0) >= int(self.find_since):
                self.last_chat = {"id": from_chat, "name": chat_name(msg["chat"])}
            if not text.startswith("/"):
                continue
            if from_chat != chat:
                if now - self._stranger_noted.get(from_chat, 0) > 3600:
                    self._stranger_noted[from_chat] = now
                    database.add_audit("telegram", "Ignored a Telegram command from another chat", f"Chat {from_chat[:24]}")
                continue
            if now - float(msg.get("date") or 0) > STALE_SECONDS:
                continue
            reply = answer(text, s)
            if reply is None:
                continue
            database.add_audit("telegram", f"Answered Telegram command {text.split()[0][:40]}", text[:80])
            try:
                self.sender(token, chat, reply)
                answered += 1
            except notify.TelegramError as exc:
                self.last_error = str(exc)
                log.warning("Telegram reply not sent: %s", exc)
        return answered
