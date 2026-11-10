"""Telegram notifications: message templates, quiet hours and a background sender with an outbox.

This module is the application's only internet connection, an exception to
the air-gap rule: HTTPS to
api.telegram.org, and only while notifications are enabled in Settings. The
bot token is a secret setting (encrypted at rest, never sent to the browser,
never logged: request errors are reported without the URL).

Templates use {placeholder} names from PLACEHOLDERS. Substitution is a plain
lookup, not str.format, so a template cannot reach object attributes.
During quiet hours non-critical messages are held in the database and sent
as one summary when quiet hours end.

Delivery goes through an outbox table: every message is written there first
and the sender retries with backoff for up to OUTBOX_KEEP_SECONDS. When the
internet (or the router in front of it) is down, messages wait and go out
once Telegram answers again, marked with the time they were written. Each
delivered message, and each one given up on, is an event of type "telegram"
with its full text, so the event log shows what was sent and when.
"""

import json
import logging
import re
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import database
import tpl

log = logging.getLogger("notify")

API = "https://api.telegram.org"
MAX_TEXT = 3500

# event key: (label, default on, default template). "on" is None for problem messages:
# whether those are sent is decided by the alert rules (minimum severity and per-rule choice).
EVENTS = {
    "device_offline": ("Device offline", None, "{device} ({ip}) is offline. {problem}"),
    "device_online": ("Device back online", None, "{device} ({ip}) is back online after {duration}."),
    "problem": ("Problem opened", None, "{severity}: {device} ({ip}): {problem}"),
    "problem_resolved": ("Problem resolved", None, "Resolved on {device}: {problem} (lasted {duration})"),
    "watch": ("Watched service or process stopped", None, "{device}: watched {watch_kind} {watch_name} is not running."),
    "reminder": ("Reminder for an open problem", None, "Still open, {severity}: {device} ({ip}): {problem} (for {duration})"),
    "workflow": ("Workflow finished", True, "Workflow {workflow}: {status}{failed_step}"),
    "workflow_start": ("Workflow started", False, "Workflow {workflow} started ({trigger})"),
    "new_device": ("New device on the network", True, "New on the network: {what}"),
    "certificate": ("HTTPS certificate expiring", True, "The monitor's HTTPS certificate expires on {date} ({days} days). Upload a new one in Settings, HTTPS."),
    # Changes to users, credentials and host keys, lockouts, HTTPS, updates and restores (SECURITY_TEXTS).
    "security": ("Security alerts", True, "Security: {what}\n{if who}By {who}{end}{if source} from {source}{end}"),
    # Not an event of its own: several messages that came at once, sent as one (Notifier.drain, notify_group).
    "grouped": ("Several at once, grouped", None, "📣 {count} changes at {time}\n{if offline_count > 0}\n🔴 Offline ({offline_count}): {offline_list}\n{end}\n{if online_count > 0}\n🟢 Back online ({online_count}): {online_list}\n{end}\n{if proxmox_count > 0}\n🖥️ Proxmox ({proxmox_count}):\n{proxmox_list}\n{end}\n{other_list}"),
}
# Messages that may be grouped when several come at once; the rest always go on their own.
GROUP_KINDS = ("device_offline", "device_online", "problem", "problem_resolved", "watch", "reminder", "new_device")
# Messages that report something fixed: they make no sound during the silent window.
RECOVERY_KINDS = ("device_online", "problem_resolved")
# While messages keep coming, a group keeps waiting for more, up to this many times its window.
GROUP_STRETCH = 4

PLACEHOLDERS = {
    "device": "Device name", "ip": "Device IP address", "template": "Device template (for example unifi_switch)",
    "time": "Local time of the event", "severity": "info, warning, high or critical", "problem": "Problem text",
    "duration": "How long the device was down, or the problem lasted", "watch_name": "Watched service or process name",
    "watch_kind": "service or process", "workflow": "Workflow name", "status": "Workflow result (success, failed, ...)",
    "failed_step": "Failed step, when there is one", "trigger": "What started the workflow (manual, schedule, an event)",
    "date": "Expiry date of the certificate", "days": "Days left before it expires",
    "what": "The new device (its name or maker, address and where it is connected), or what happened (security alerts)",
    "who": "Who did it (security alerts)", "source": "The address it came from (security alerts)",
    "count": "How many messages were grouped", "offline_count": "Devices that went offline",
    "offline_list": "Their names, comma separated; devices unreachable behind one follow it in brackets", "online_count": "Devices back online", "online_list": "Their names",
    "other_list": "Every other message, one per line", "window": "Seconds the monitor waited to group them",
    "proxmox_count": "Proxmox messages (guests, nodes, storage)", "proxmox_list": "Those messages, one per line",
}
# Which placeholders mean something in each event (the template editor lists these).
EVENT_PLACEHOLDERS = {
    "device_offline": ["device", "ip", "template", "time", "problem"],
    "device_online": ["device", "ip", "template", "time", "duration"],
    "problem": ["severity", "device", "ip", "template", "time", "problem"],
    "problem_resolved": ["severity", "device", "ip", "template", "time", "problem", "duration"],
    "watch": ["device", "ip", "template", "time", "watch_kind", "watch_name", "severity"],
    "reminder": ["severity", "device", "ip", "template", "time", "problem", "duration"],
    "workflow": ["workflow", "status", "failed_step", "trigger", "time"],
    "workflow_start": ["workflow", "trigger", "time"],
    "security": ["what", "who", "source", "time"],
    "grouped": ["count", "time", "window", "offline_count", "offline_list", "online_count", "online_list",
                "proxmox_count", "proxmox_list", "other_list"],
}
# Sample values for the template editor's preview.
SAMPLE = {"device": "nas-01", "ip": "192.168.1.99", "template": "qnap_nas", "time": "2026-11-01 09:30",
          "severity": "warning", "problem": "CPU usage 97% (threshold 90%)", "duration": "12m", "watch_name": "sshd",
          "watch_kind": "service", "workflow": "Update Linux hosts", "status": "success", "failed_step": "",
          "trigger": "schedule", "count": 6, "offline_count": 4, "offline_list": "ap-living-room, ap-kitchen, ap-garden, ap-upstairs",
          "online_count": 0, "online_list": "", "other_list": "• warning: nas-01: CPU usage 97% (threshold 90%)\n• Resolved on pve: memory 91%",
          "proxmox_count": 1, "proxmox_list": "• warning: pve: Guest media-server (200) is stopped, although it starts at boot",
          "window": 30, "what": "New user added: alex (Viewer)", "who": "admin", "source": "192.168.1.20"}
# Ready-made texts offered in the template editor, per event. Short on purpose.
PRESETS = {
    "device_offline": ["🔴 {device} ({ip}) is offline. {problem}", "🔴 DOWN {device} ({ip}) at {time}",
                       "⚠️ {device} stopped answering. {problem}"],
    "device_online": ["🟢 {device} ({ip}) is back online after {duration}.", "🟢 UP {device} ({ip}), down for {duration}"],
    "problem": ["⚠️ {severity}: {device} ({ip}): {problem}", "🔥 {severity} on {device}: {problem} ({time})"],
    "problem_resolved": ["✅ Resolved on {device}: {problem} (lasted {duration})", "✅ {device}: {problem} is fine again"],
    "watch": ["🛠️ {device}: watched {watch_kind} {watch_name} is not running.", "❌ {watch_name} stopped on {device}"],
    "reminder": ["🔁 Still open, {severity}: {device} ({ip}): {problem} (for {duration})"],
    "workflow": ["✅ Workflow {workflow}: {status}{failed_step}", "🔁 {workflow} finished: {status}{failed_step}"],
    "workflow_start": ["▶️ Workflow {workflow} started ({trigger})", "⏱️ {time}: running {workflow}"],
    "security": ["🔒 Security: {what}\n{if who}By {who}{end}{if source} from {source}{end}", "🚨 {what} ({time})"],
    "grouped": ["📣 {count} changes at {time}\n{if offline_count > 0}\n🔴 Offline ({offline_count}): {offline_list}\n{end}\n{if online_count > 0}\n🟢 Back online ({online_count}): {online_list}\n{end}\n{if proxmox_count > 0}\n🖥️ Proxmox ({proxmox_count}):\n{proxmox_list}\n{end}\n{other_list}",
                "📣 {count} at once: {if offline_count > 0}{offline_count} down{end}{if online_count > 0} {online_count} up{end}\n{offline_list|before:\"Down: \"}\n{online_list|before:\"Up: \"}\n{other_list|first:5}"],
}
EMOJIS = ["✅", "❌", "⚠️", "ℹ️", "🔴", "🟢", "🟡", "🔵", "🔥", "🚨", "⏱️", "🔁", "▶️", "⏹️", "🖥️", "📶",
          "💾", "🌡️", "🔌", "🛠️", "🔒", "🔑", "📦", "🌐", "📡", "⚡", "🔋", "🧰", "📣", "👀"]

# What a security alert says (the {what} of the "security" message). Values are filled in as text:
# tpl.render reads only the template, so a username cannot add placeholders of its own.
SECURITY_TEXTS = {
    "admin_added": "{name} is now an administrator",
    "role_changed": "The role of {name} changed to {role}",
    "user_added": "New user added: {name} ({role})",
    "user_deleted": "User deleted: {name}",
    "twofa_off": "Two-factor authentication was turned off for {name}",
    "twofa_reset": "Two-factor authentication was reset for {name}",
    "recovery_code": "A recovery code was used for {name}. {left} left",
    "recovered": "The password of {name} was reset through password recovery",
    "cred_added": "Stored credential added: {name}",
    "cred_changed": "Stored credential changed: {name}",
    "cred_deleted": "Stored credential deleted: {name}",
    "key_approved": "SSH host key approved for {device}",
    "key_forgotten": "SSH host key forgotten for {device}",
    "lockout": "Too many failed logins for {target}. Further tries are paused",
    "https_failed": ("HTTPS could not start on the monitor: {reason}. It is serving plain HTTP and refuses logins from "
                     "other computers until this is fixed. Monitoring and alerts keep running. To get back in, run "
                     "/root/update.sh on its container and choose option 6."),
    "update_ok": "{kind} from {from} to {to} finished",
    "update_failed": "{kind} to {to} failed: {error}",
    "restored": "The monitor's data was restored from a backup: {file}",
    "retention": "The audit log is now kept for {days} days (it was {old})",
}
# What the event log says for a sent security alert: its text names people and addresses, and
# device-less events are seen by every user.
SECURITY_EVENT_TEXT = "a security alert (see the audit log)"

OUTBOX_KEEP_SECONDS = 24 * 3600
BACKOFF_SECONDS = (15, 30, 60, 120, 300, 600, 900)
# A message delivered this much later than it was written says so.
DELAY_NOTE_SECONDS = 120

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def render(template: str, values: Dict[str, Any]) -> str:
    """Fills a message template (tpl.py: placeholders, filters, arithmetic, {if}). Placeholder names
    the event does not supply come out empty; names nobody knows are left as written."""
    return tpl.render(template, values, known=set(PLACEHOLDERS) | set(values), max_len=MAX_TEXT)


TOO_LONG_NOTE = "Your custom text for this alert was too long to build, so this is the standard text."


def _render_custom(custom: Optional[str], builtin: str, values: Dict[str, Any]) -> str:
    """A saved custom text, or the built-in one with a short notice when the custom text is too long
    to build: a broken template must not blank every alert."""
    text = render(custom or builtin, values)
    if custom and text == tpl.FALLBACK[:MAX_TEXT]:
        text = (TOO_LONG_NOTE + "\n" + render(builtin, values))[:MAX_TEXT]
    return text


def in_quiet_hours(start: str, end: str, now: Optional[datetime] = None) -> bool:
    """True when the local time falls between start and end (HH:MM), across midnight if end is earlier."""
    now = now or datetime.now()
    try:
        s = tuple(int(x) for x in start.split(":"))
        e = tuple(int(x) for x in end.split(":"))
    except ValueError:
        return False
    t = (now.hour, now.minute)
    return s <= t < e if s <= e else (t >= s or t < e)


class TelegramError(Exception):
    pass


def _post(token: str, method: str, payload: Dict[str, Any], timeout: float = 15.0) -> Dict[str, Any]:
    req = urllib.request.Request(f"{API}/bot{token}/{method}", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # The URL holds the token: report the status and Telegram's description only.
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("description", "")
        except (ValueError, OSError):
            detail = ""
        exc.close()
        raise TelegramError(f"Telegram refused the request (HTTP {exc.code}) {detail}".strip())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TelegramError(f"Could not reach Telegram: {type(reason).__name__}")
    if not data.get("ok"):
        raise TelegramError(data.get("description", "Telegram returned an error"))
    return data.get("result", {})


def send(token: str, chat_id: str, text: str, silent: bool = False) -> None:
    """silent: delivered without a sound on the phone (Telegram's disable_notification)."""
    payload = {"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True}
    if silent:
        payload["disable_notification"] = True
    _post(token, "sendMessage", payload)


# Silent window: messages are delivered at once but make no sound, unless their severity is at
# or above notify_silent_sound_from, or their alert rule says "always" (rule field sound).
SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}


def is_silent(settings: Dict[str, str], severity: str, sound: str, now: Optional[datetime] = None) -> bool:
    """Whether a message goes out without a sound. sound is the alert rule's choice:
    'always' rings, 'silent' never rings, 'default' follows the silent window."""
    if sound == "always":
        return False
    if sound == "silent":
        return True
    if settings.get("notify_silent") != "on":
        return False
    if not in_quiet_hours(settings.get("notify_silent_start", "22:00"), settings.get("notify_silent_end", "07:00"), now):
        return False
    ring_from = settings.get("notify_silent_sound_from", "critical")
    if severity and ring_from != "none" and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(ring_from, 3):
        return False
    return True


def find_chat(token: str) -> Optional[Dict[str, Any]]:
    """The most recent chat that messaged the bot, from getUpdates: {id, name}."""
    updates = _post(token, "getUpdates", {"limit": 20, "timeout": 0})
    for u in reversed(updates or []):
        chat = (u.get("message") or u.get("channel_post") or {}).get("chat")
        if chat:
            name = chat.get("title") or " ".join(x for x in (chat.get("first_name"), chat.get("last_name")) if x) or chat.get("username", "")
            return {"id": str(chat["id"]), "name": name}
    return None


def bot_name(token: str) -> str:
    me = _post(token, "getMe", {})
    return me.get("username", "")


# --- Outbox (owned by this module; created on first use) ---

_OUTBOX_READY = False
_OUTBOX_LOCK = threading.Lock()


def _outbox() -> None:
    global _OUTBOX_READY
    if _OUTBOX_READY:
        return
    with _OUTBOX_LOCK, database.get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notify_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                text TEXT NOT NULL,
                device_id INTEGER,
                kind TEXT NOT NULL DEFAULT '',
                critical INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_try INTEGER NOT NULL,
                last_error TEXT
            );""")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(notify_outbox);")}
        if "severity" not in cols:
            conn.execute("ALTER TABLE notify_outbox ADD COLUMN severity TEXT NOT NULL DEFAULT '';")
        if "sound" not in cols:
            conn.execute("ALTER TABLE notify_outbox ADD COLUMN sound TEXT NOT NULL DEFAULT 'default';")
        if "topic" not in cols:
            conn.execute("ALTER TABLE notify_outbox ADD COLUMN topic TEXT NOT NULL DEFAULT '';")
        if "behind" not in cols:
            conn.execute("ALTER TABLE notify_outbox ADD COLUMN behind TEXT NOT NULL DEFAULT '';")
        conn.commit()
        _OUTBOX_READY = True


def queue_message(text: str, device_id: Optional[int] = None, kind: str = "", critical: bool = False,
                  now: Optional[float] = None, severity: str = "", sound: str = "default", topic: str = "",
                  behind: str = "") -> int:
    """Writes a message to the outbox. Returns its id. severity and sound decide a silent delivery;
    topic ("proxmox" or "") picks its section in a grouped message; behind names the devices unreachable
    behind this one (offline and back online messages), so a grouped message lists and counts them too."""
    _outbox()
    t = int(now if now is not None else time.time())
    sound = sound if sound in ("default", "always", "silent") else "default"
    with database.get_connection() as conn:
        cur = conn.execute("INSERT INTO notify_outbox (created_at, text, device_id, kind, critical, next_try, severity, sound, topic, behind) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                           (t, text[:MAX_TEXT], device_id, kind, 1 if critical else 0, t, severity or "", sound, topic[:20], behind[:1000]))
        conn.commit()
        return cur.lastrowid


def outbox_due(now: float) -> List[Dict[str, Any]]:
    _outbox()
    with database.get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, created_at, text, device_id, kind, critical, attempts, severity, sound, topic, behind FROM notify_outbox "
            "WHERE next_try <= ? ORDER BY id LIMIT 60;",
            (int(now),))]


def outbox_state(now: Optional[float] = None) -> Dict[str, Any]:
    _outbox()
    now = now if now is not None else time.time()
    with database.get_connection() as conn:
        row = conn.execute("SELECT COUNT(*), MIN(created_at) FROM notify_outbox;").fetchone()
        err = conn.execute("SELECT last_error FROM notify_outbox WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1;").fetchone()
    return {"queued": row[0], "oldest_seconds": int(now - row[1]) if row[1] else None, "last_error": err[0] if err else ""}


def _outbox_done(msg_id: int) -> None:
    with database.get_connection() as conn:
        conn.execute("DELETE FROM notify_outbox WHERE id = ?;", (msg_id,))
        conn.commit()


def _outbox_retry(msg: Dict[str, Any], error: str, now: float) -> None:
    attempts = msg["attempts"] + 1
    wait = BACKOFF_SECONDS[min(attempts - 1, len(BACKOFF_SECONDS) - 1)]
    with database.get_connection() as conn:
        conn.execute("UPDATE notify_outbox SET attempts = ?, next_try = ?, last_error = ? WHERE id = ?;",
                     (attempts, int(now + wait), error[:300], msg["id"]))
        conn.commit()


def _event(device_id: Optional[int], severity: str, text: str) -> None:
    """Event for a message; a device deleted while its message waited is recorded without it."""
    try:
        database.add_event(device_id, severity, "telegram", text)
    except sqlite3.IntegrityError:
        database.add_event(None, severity, "telegram", text)


def _logged(m: Dict[str, Any]) -> str:
    """A message as the event log shows it: a security alert only says it was one."""
    return SECURITY_EVENT_TEXT if m.get("kind") == "security" else m["text"]


def _line(m: Dict[str, Any]) -> str:
    return f"• {m['text'].splitlines()[0][:200]}"


class Notifier:
    """Accepts events from the poller threads; one background thread delivers the outbox."""

    def __init__(self, settings: Callable[[], Dict[str, str]],
                 sender: Callable[[str, str, str], None] = None, sleep: Callable[[float], None] = None) -> None:
        self.settings = settings
        self.sender = sender or send
        self.wake = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.last_error = ""
        self.sent = 0
        self._last_quiet = False

    def start(self) -> None:
        if self.thread is None:
            self.thread = threading.Thread(target=self._loop, name="notify", daemon=True)
            self.thread.start()

    def event(self, kind: str, values: Dict[str, Any], critical: bool = False, device_id: Optional[int] = None,
              sound: str = "default") -> Optional[int]:
        """Queues the message for an event when Telegram is on and the event is switched on. Returns the outbox id."""
        s = self.settings()
        if s.get("telegram_enabled") != "on" or kind not in EVENTS:
            return None
        if EVENTS[kind][1] is not None and s.get(f"notify_on_{kind}", "on" if EVENTS[kind][1] else "off") != "on":
            return None
        values = dict(values, time=datetime.now().strftime("%Y-%m-%d %H:%M"))
        text = _render_custom(s.get(f"notify_tpl_{kind}"), EVENTS[kind][2], values)
        # Good news never rings in the silent window: a recovery keeps its problem's severity in the
        # text but is queued without one, so "Still ring from" does not apply to it.
        severity = "" if kind in RECOVERY_KINDS else str(values.get("severity") or "")
        msg_id = queue_message(text, device_id if device_id is not None else values.get("device_id"), kind, critical,
                               severity=severity, sound=sound, topic=str(values.get("topic") or ""),
                               behind=str(values.get("behind") or ""))
        self.wake.set()
        return msg_id

    def security(self, key: str, who: str = "", source: str = "", **values: Any) -> Optional[int]:
        """A security alert: SECURITY_TEXTS[key] becomes {what} of the "security" message. Sent straight
        away, also in quiet hours."""
        what = render(SECURITY_TEXTS[key], {k: str(v) for k, v in values.items()})
        return self.event("security", {"what": what, "who": who, "source": source, "severity": "high"}, critical=True)

    def message(self, text: str, device_id: Optional[int] = None, kind: str = "workflow_step", silent: bool = False) -> Optional[int]:
        """A free-text message (the workflow Send Telegram step). None when Telegram is off.
        silent: delivered without a sound (the step's Send quietly)."""
        if self.settings().get("telegram_enabled") != "on":
            return None
        msg_id = queue_message(text[:MAX_TEXT], device_id, kind, critical=True, sound="silent" if silent else "default")
        self.wake.set()
        return msg_id

    def status(self) -> Dict[str, Any]:
        return dict(outbox_state(), sent=self.sent, last_error=self.last_error)

    def _loop(self) -> None:
        while True:
            self.wake.wait(timeout=10)
            self.wake.clear()
            try:
                self.drain()
            except Exception:
                log.exception("Telegram sender failed; retrying shortly")

    def drain(self, now: Optional[float] = None) -> None:
        """One pass over the outbox: quiet hours, delivery, retry or give up."""
        now = now if now is not None else time.time()
        s = self.settings()
        quiet = s.get("notify_quiet") == "on" and in_quiet_hours(s.get("notify_quiet_start", "22:00"), s.get("notify_quiet_end", "07:00"))
        if self._last_quiet and not quiet:
            held = database.take_held_notifications()
            if held:
                body = f"While quiet hours were on ({len(held)} message{'s' if len(held) != 1 else ''}):\n\n" + "\n".join(held)
                queue_message(body[:MAX_TEXT], None, "quiet_summary", critical=True, now=now)
        self._last_quiet = quiet
        token, chat = s.get("telegram_token", ""), s.get("telegram_chat_id", "")
        for msg in self.grouped(outbox_due(now), s, now):
            ids = msg.get("_ids") or [msg["id"]]
            if quiet and not msg["critical"]:
                for m in msg.get("_members") or [msg]:
                    database.hold_notification(m["text"])
                for i in ids:
                    _outbox_done(i)
                continue
            text = msg["text"]
            if now - msg["created_at"] > DELAY_NOTE_SECONDS:
                text = f"(Delayed: written {datetime.fromtimestamp(msg['created_at']).strftime('%Y-%m-%d %H:%M')})\n{text}"
            silent = is_silent(s, msg.get("severity") or "", msg.get("sound") or "default", datetime.fromtimestamp(now))
            try:
                if not token or not chat:
                    raise TelegramError("Bot token or chat not set")
                if silent:
                    self.sender(token, chat, text, silent=True)
                else:
                    self.sender(token, chat, text)
            except TelegramError as exc:
                self.last_error = str(exc)
                for m in msg.get("_members") or [msg]:
                    if now - m["created_at"] >= OUTBOX_KEEP_SECONDS:
                        _outbox_done(m["id"])
                        _event(m["device_id"], "warning", f"Telegram message not delivered after 24 hours ({exc}): {_logged(m)}")
                        log.warning("Telegram message given up after %d attempts: %s", m["attempts"] + 1, exc)
                    else:
                        _outbox_retry(m, str(exc), now)
                # Telegram (or the way to it) is down: the rest would fail the same way.
                break
            for i in ids:
                _outbox_done(i)
            self.sent += 1
            self.last_error = ""
            late = f" (delayed {int((now - msg['created_at']) // 60)} min)" if now - msg["created_at"] > DELAY_NOTE_SECONDS else ""
            grouped = f" ({len(ids)} grouped)" if len(ids) > 1 else ""
            _event(msg["device_id"], "info", f"Telegram sent{' silently' if silent else ''}{grouped}{late}: {_logged(msg)}")

    def grouped(self, due: List[Dict[str, Any]], s: Dict[str, str], now: float) -> List[Dict[str, Any]]:
        """Bursts become one message. With notify_group on, problem and device messages wait until
        none has come for notify_group_seconds (machines shut down one after another keep the group
        open), at most GROUP_STRETCH times that after the first. Then, when at least notify_group_min
        are waiting, they go as one message (the "grouped" template), else one by one as usual.
        Proxmox messages get their own section. Everything else passes straight through."""
        if s.get("notify_group", "on") != "on":
            return due
        try:
            window = max(5, min(600, int(s.get("notify_group_seconds") or 30)))
            least = max(2, min(50, int(s.get("notify_group_min") or 3)))
        except ValueError:
            window, least = 30, 3
        pool = [m for m in due if m.get("kind") in GROUP_KINDS]
        rest = [m for m in due if m.get("kind") not in GROUP_KINDS]
        if not pool:
            return due
        fresh = [m for m in pool if not m.get("attempts")]
        if fresh:
            first, last = min(m["created_at"] for m in fresh), max(m["created_at"] for m in fresh)
            if now - last < window and now - first < min(600, window * GROUP_STRETCH):
                return rest                 # still gathering: the pool waits for the next pass
        if len(pool) < least:
            return rest + pool
        names = {d["id"]: d["hostname"] for d in database.list_devices()}
        # A device with others unreachable behind it: "media-server (+ nas-01, web-app)", and all of them counted.
        def entry(m: Dict[str, Any]) -> str:
            name = names.get(m["device_id"], "?")
            return f"{name} (+ {m['behind']})" if m.get("behind") else name
        count = lambda kind: sum(1 + len([x for x in (m.get("behind") or "").split(", ") if x]) for m in pool if m["kind"] == kind)
        off = [entry(m) for m in pool if m["kind"] == "device_offline"]
        on = [entry(m) for m in pool if m["kind"] == "device_online"]
        template = s.get("notify_tpl_grouped") or EVENTS["grouped"][2]
        # A template written before the Proxmox section existed keeps those lines with the others.
        split = "proxmox_list" in template or "proxmox_count" in template
        listed = [m for m in pool if m["kind"] not in ("device_offline", "device_online")]
        pve = [_line(m) for m in listed if split and m.get("topic") == "proxmox"]
        other = [_line(m) for m in listed if not (split and m.get("topic") == "proxmox")]
        values = {"count": len(pool), "time": datetime.fromtimestamp(now).strftime("%H:%M"), "window": window,
                  "offline_count": count("device_offline"), "offline_list": ", ".join(off),
                  "online_count": count("device_online"), "online_list": ", ".join(on),
                  "proxmox_count": len(pve), "proxmox_list": "\n".join(pve), "other_list": "\n".join(other)}
        text = _render_custom(s.get("notify_tpl_grouped"), EVENTS["grouped"][2], values)
        sounds = {m.get("sound") or "default" for m in pool}
        rank = max((SEVERITY_RANK.get(m.get("severity") or "", 0) for m in pool), default=0)
        combined = {"id": pool[0]["id"], "created_at": min(m["created_at"] for m in pool), "text": text, "device_id": None,
                    "kind": "grouped", "critical": 1 if any(m["critical"] for m in pool) else 0,
                    "attempts": min(m.get("attempts") or 0 for m in pool),
                    "severity": next((k for k, v in SEVERITY_RANK.items() if v == rank), ""),
                    "sound": "always" if "always" in sounds else "silent" if sounds == {"silent"} else "default",
                    "_ids": [m["id"] for m in pool], "_members": pool}
        return rest + [combined]
