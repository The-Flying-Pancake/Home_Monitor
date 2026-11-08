"""Notifications: template rendering, quiet hours, event filtering, held messages, settings validation, token secrecy."""

import time
import unittest
from datetime import datetime
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, raw_bytes, request, start_api_server

import database
import notify
import server


class RenderTests(unittest.TestCase):
    def test_placeholders(self):
        self.assertEqual(notify.render("{device} ({ip}) is {status}", {"device": "nas", "ip": "10.0.0.2", "status": "down"}),
                         "nas (10.0.0.2) is down")
        self.assertEqual(notify.render("{device} {unknown} {failed_step}", {"device": "x"}), "x {unknown}")   # trailing spaces trimmed
        # No attribute access: a template cannot reach into objects.
        self.assertEqual(notify.render("{device.__class__}", {"device": "x"}), "{device.__class__}")

    def test_every_default_template_uses_known_placeholders(self):
        for kind, (_, _, tpl) in notify.EVENTS.items():
            for name in __import__("tpl").names(tpl):
                self.assertIn(name, notify.PLACEHOLDERS, kind)

    def test_quiet_hours(self):
        at = lambda h, m=0: datetime(2026, 11, 1, h, m)
        self.assertTrue(notify.in_quiet_hours("22:00", "07:00", at(23)))
        self.assertTrue(notify.in_quiet_hours("22:00", "07:00", at(6, 59)))
        self.assertFalse(notify.in_quiet_hours("22:00", "07:00", at(7)))
        self.assertFalse(notify.in_quiet_hours("22:00", "07:00", at(12)))
        self.assertTrue(notify.in_quiet_hours("13:00", "14:00", at(13, 30)))
        self.assertFalse(notify.in_quiet_hours("bad", "07:00", at(23)))


class GroupTests(unittest.TestCase):
    """Bursts of problem and device messages become one message."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.aps = [add_device(f"grp-ap{i}", f"192.0.2.{150 + i}") for i in range(4)]

    def setUp(self):
        notify._outbox()
        with database.get_connection() as conn:
            conn.execute("DELETE FROM notify_outbox;")
            conn.commit()
        self.sent = []
        self.n = notify.Notifier(lambda: {"telegram_enabled": "on", "telegram_token": "t", "telegram_chat_id": "1",
                                          "notify_group_seconds": "30", "notify_group_min": "3"},
                                 sender=lambda token, chat, text, silent=False: self.sent.append((text, silent)))

    def test_burst_is_one_message(self):
        t0 = time.time()
        for i, d in enumerate(self.aps):
            notify.queue_message(f"grp-ap{i} is offline", d, "device_offline", critical=True, now=t0 + i)
        notify.queue_message("warning: grp-ap0: CPU 99%", self.aps[0], "problem", now=t0 + 2)
        notify.queue_message("Workflow X: success", None, "workflow", now=t0 + 2)
        self.n.drain(now=t0 + 10)
        self.assertEqual([t for t, _ in self.sent], ["Workflow X: success"])    # the rest waits to be grouped
        self.n.drain(now=t0 + 31)
        self.assertEqual(len(self.sent), 1)                     # the last came at +3: 30 s quiet is +33
        self.n.drain(now=t0 + 34)
        self.assertEqual(len(self.sent), 2)
        text = self.sent[1][0]
        self.assertIn("5 changes", text)
        self.assertIn("Offline (4): grp-ap0, grp-ap1, grp-ap2, grp-ap3", text)
        self.assertIn("• warning: grp-ap0: CPU 99%", text)
        self.assertNotIn("Back online", text)                                   # an {if} that was false leaves no line
        self.assertEqual(notify.outbox_state()["queued"], 0)

    def test_few_go_one_by_one_and_off_means_at_once(self):
        t0 = time.time()
        notify.queue_message("grp-ap0 is offline", self.aps[0], "device_offline", now=t0)
        notify.queue_message("grp-ap1 is offline", self.aps[1], "device_offline", now=t0)
        self.n.drain(now=t0 + 31)
        self.assertEqual([t for t, _ in self.sent], ["grp-ap0 is offline", "grp-ap1 is offline"])
        self.sent.clear()
        base = self.n.settings()
        self.n.settings = lambda: dict(base, notify_group="off")
        notify.queue_message("grp-ap2 is offline", self.aps[2], "device_offline", now=t0 + 40)
        self.n.drain(now=t0 + 40)
        self.assertEqual(len(self.sent), 1)

    def test_group_stays_open_while_messages_keep_coming(self):
        t0 = time.time()
        for i, d in enumerate(self.aps[:3]):                    # shut down one after another, 20 s apart
            notify.queue_message(f"grp-ap{i} is offline", d, "device_offline", critical=True, now=t0 + 20 * i)
            self.n.drain(now=t0 + 20 * i + 1)
        self.assertEqual(self.sent, [])
        self.n.drain(now=t0 + 71)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("Offline (3): grp-ap0, grp-ap1, grp-ap2", self.sent[0][0])

    def test_group_wait_has_a_limit(self):
        t0 = time.time()
        for i in range(6):                                      # a message every 25 s for two minutes
            notify.queue_message(f"m{i}", self.aps[i % 4], "problem", now=t0 + 25 * i)
        self.n.drain(now=t0 + 126)                               # newest is 1 s old, but the first is 4 x 30 s old
        self.assertEqual(len(self.sent), 1)
        self.assertIn("6 changes", self.sent[0][0])

    def test_devices_behind_are_listed_and_counted(self):
        t0 = time.time()
        notify.queue_message("grp-ap0 is offline", self.aps[0], "device_offline", critical=True, now=t0, behind="nas-01, web-app")
        notify.queue_message("grp-ap1 is offline", self.aps[1], "device_offline", critical=True, now=t0, behind="downloads")
        notify.queue_message("grp-ap2 is offline", self.aps[2], "device_offline", critical=True, now=t0)
        self.n.drain(now=t0 + 31)
        self.assertIn("Offline (6): grp-ap0 (+ nas-01, web-app), grp-ap1 (+ downloads), grp-ap2", self.sent[0][0])

    def test_proxmox_section(self):
        t0 = time.time()
        notify.queue_message("grp-ap0 is offline", self.aps[0], "device_offline", critical=True, now=t0)
        notify.queue_message("warning: grp-ap1: Guest media-server (200) is stopped", self.aps[1], "problem", now=t0, topic="proxmox")
        notify.queue_message("warning: grp-ap2: CPU 99%", self.aps[2], "problem", now=t0)
        self.n.drain(now=t0 + 31)
        text = self.sent[0][0]
        self.assertIn("Proxmox (1):\n• warning: grp-ap1: Guest media-server (200) is stopped", text)
        self.assertEqual(text.count("Guest media-server"), 1)
        self.assertIn("• warning: grp-ap2: CPU 99%", text)
        # A custom grouped template without the section keeps every line in the list.
        with database.get_connection() as conn:
            conn.execute("DELETE FROM notify_outbox;")
            conn.commit()
        self.sent.clear()
        base = self.n.settings()
        self.n.settings = lambda: dict(base, notify_tpl_grouped="{count}:\n{other_list}")
        for i in range(3):
            notify.queue_message(f"pve {i}", self.aps[i], "problem", now=t0, topic="proxmox")
        self.n.drain(now=t0 + 31)
        self.assertEqual(self.sent[0][0], "3:\n• pve 0\n• pve 1\n• pve 2")

    def test_grouped_is_silent_only_when_all_are(self):
        t0 = time.time()
        for i, d in enumerate(self.aps[:3]):
            notify.queue_message(f"m{i}", d, "problem", now=t0, sound="silent")
        self.n.drain(now=t0 + 31)
        self.assertTrue(self.sent[0][1])


class NotifierTests(unittest.TestCase):
    """The outbox: messages are written first, delivered with retry, and every result is an event."""

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        notify._outbox()
        with database.get_connection() as conn:
            conn.execute("DELETE FROM notify_outbox;")
            conn.commit()
        database.take_held_notifications()
        self.sent = []

    def notifier(self, fail=None, **settings):
        # Grouping holds problem messages for a while; these tests are about one message at a time.
        base = {"telegram_enabled": "on", "telegram_token": "t", "telegram_chat_id": "1", "notify_group": "off"}

        def sender(token, chat, text):
            if fail and fail():
                raise notify.TelegramError("Could not reach Telegram: URLError")
            self.sent.append(text)
        return notify.Notifier(lambda: dict(base, **settings), sender=sender)

    def queued(self):
        return notify.outbox_state()["queued"]

    def telegram_events(self):
        return [e["message"] for e in database.list_events_filtered(event_type="telegram", limit=50)[0]]

    def test_event_filtering_and_templates(self):
        n = self.notifier(notify_tpl_device_offline="DOWN {device}")
        n.event("device_offline", {"device": "sw1"})
        self.assertEqual(self.queued(), 1)
        n.drain()
        self.assertEqual(self.sent, ["DOWN sw1"])
        self.assertEqual(self.queued(), 0)
        self.assertIn("Telegram sent: DOWN sw1", self.telegram_events())
        # Workflow messages keep their own switch; problem messages are filtered by the alert rules instead.
        quiet = self.notifier(notify_on_workflow="off")
        quiet.event("workflow", {"workflow": "w"})
        quiet.event("problem_resolved", {"device": "sw1"})
        self.assertEqual(self.queued(), 1)
        off = self.notifier(telegram_enabled="off")
        self.assertIsNone(off.event("device_offline", {"device": "sw1"}))
        # "Workflow started" is off until switched on.
        self.assertIsNone(self.notifier().event("workflow_start", {"workflow": "w", "trigger": "manual"}))
        self.assertIsNotNone(self.notifier(notify_on_workflow_start="on").event("workflow_start", {"workflow": "w", "trigger": "manual"}))

    def test_outage_waits_then_delivers_with_note(self):
        down = {"v": True}
        n = self.notifier(fail=lambda: down["v"])
        t0 = time.time()
        n.event("device_offline", {"device": "gw"})
        n.drain(now=t0)
        self.assertEqual((self.sent, self.queued()), ([], 1))
        self.assertIn("Could not reach Telegram", n.status()["last_error"])
        n.drain(now=t0 + 5)                 # backoff: not due yet
        self.assertEqual(len(self.sent), 0)
        down["v"] = False
        n.drain(now=t0 + 600)
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(self.sent[0].startswith("(Delayed: written"))
        self.assertTrue(any("delayed 10 min" in e for e in self.telegram_events()))

    def test_given_up_after_a_day_is_an_event(self):
        n = self.notifier(fail=lambda: True)
        t0 = time.time()
        notify.queue_message("old news", None, "device_offline", now=t0 - notify.OUTBOX_KEEP_SECONDS - 10)
        n.drain(now=t0)
        self.assertEqual(self.queued(), 0)
        self.assertTrue(any(e.startswith("Telegram message not delivered after 24 hours") for e in self.telegram_events()))

    def test_held_during_quiet_hours_and_summary(self):
        n = self.notifier(notify_quiet="on", notify_quiet_start="00:00", notify_quiet_end="23:59")
        n.event("problem", {"device": "a", "problem": "x"})
        n.event("device_offline", {"device": "b"}, critical=True)
        n.drain()
        self.assertEqual(len(self.sent), 1)                  # the critical one went at once
        n.settings = lambda: {"telegram_enabled": "on", "telegram_token": "t", "telegram_chat_id": "1", "notify_quiet": "off", "notify_group": "off"}
        n.drain()                                            # quiet hours over: one summary
        self.assertEqual(len(self.sent), 2)
        self.assertIn("1 message", self.sent[1])
        self.assertEqual(database.take_held_notifications(), [])

    def test_new_device_quiet_period(self):
        now = time.time()
        fresh, old = {"created_at": now - 60}, {"created_at": now - 3 * 3600}
        settings = {"notify_new_device_minutes": "30"}
        self.assertTrue(server.in_new_device_quiet(fresh, settings, now))
        self.assertFalse(server.in_new_device_quiet(old, settings, now))
        self.assertFalse(server.in_new_device_quiet(fresh, dict(settings, notify_new_devices="on"), now))
        self.assertFalse(server.in_new_device_quiet(None, settings, now))

    def test_problem_mapping(self):
        calls = []
        with mock.patch.object(server.NOTIFIER, "event", side_effect=lambda kind, values, critical=False, **kw: calls.append((kind, critical, values.get("watch_name")))):
            dev = {"hostname": "h", "ip_address": "10.0.0.9", "profile_id": "linux_host"}
            server.notify_problem(dev, "unreachable", "critical", "down", opened=True)
            server.notify_problem(dev, "unreachable", "critical", "down", opened=False, lasted="5m")
            server.notify_problem(dev, "watch:service:Veeam", "warning", "x", opened=True)
            server.notify_problem(dev, "cpu", "warning", "x", opened=True)
            server.notify_problem(dev, "cpu", "warning", "x", opened=False)
        self.assertEqual(calls, [("device_offline", True, None), ("device_online", False, None), ("watch", False, "Veeam"),
                                 ("problem", False, None), ("problem_resolved", False, None)])


class SettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_validation_and_token_secrecy(self):
        token = "987654321:" + "Z" * 35
        self.assertEqual(request("POST", "/api/settings", {"telegram_token": token, "notify_quiet_start": "23:30"})[0], 200)
        settings = request("GET", "/api/settings")[1]
        self.assertTrue(settings["telegram_token__set"])
        self.assertEqual(settings["telegram_token"], "")
        self.assertNotIn(token.encode(), raw_bytes())                  # encrypted at rest
        for bad in ({"notify_quiet_start": "25:00"}, {"telegram_chat_id": "abc"}, {"notify_tpl_problem": "x" * 501},
                    {"telegram_enabled": "maybe"}):
            self.assertEqual(request("POST", "/api/settings", bad)[0], 400, bad)
        # An emptied template falls back to the default text.
        request("POST", "/api/settings", {"notify_tpl_problem": ""})
        self.assertEqual(database.get_all_settings()["notify_tpl_problem"], notify.EVENTS["problem"][2])

    def test_find_chat_errors_hide_token(self):
        token = "123456789:" + "Q" * 35
        with mock.patch.object(notify, "_post", side_effect=notify.TelegramError("Telegram refused the request (HTTP 401) Unauthorized")):
            status, res, _ = request("POST", "/api/notify/find-chat", {"token": token})
        self.assertEqual(status, 502)
        self.assertNotIn(token, repr(res))
        self.assertEqual(request("POST", "/api/notify/find-chat", {"token": "nope"})[0], 400)
        info = request("GET", "/api/notify/info")[1]
        self.assertIn("device", info["placeholders"])


class SilentWindowTests(unittest.TestCase):
    """Silent window: delivered at once without a sound, severities and rules can still ring."""

    def setUp(self):
        start_api_server()
        with database.get_connection() as conn:
            notify._outbox()
            conn.execute("DELETE FROM notify_outbox;")
            conn.commit()

    def test_decision(self):
        night = datetime(2026, 11, 2, 23, 30)
        day = datetime(2026, 11, 2, 12, 0)
        s = {"notify_silent": "on", "notify_silent_start": "22:00", "notify_silent_end": "07:00",
             "notify_silent_sound_from": "critical"}
        self.assertTrue(notify.is_silent(s, "warning", "default", night))
        self.assertFalse(notify.is_silent(s, "warning", "default", day))          # outside the window
        self.assertFalse(notify.is_silent(s, "critical", "default", night))       # still rings from critical
        self.assertFalse(notify.is_silent(s, "warning", "always", night))         # rule: always ring
        self.assertTrue(notify.is_silent(s, "critical", "silent", day))           # rule: always silent
        self.assertTrue(notify.is_silent(dict(s, notify_silent_sound_from="none"), "critical", "default", night))
        self.assertFalse(notify.is_silent(dict(s, notify_silent="off"), "warning", "default", night))

    def test_sent_with_disable_notification(self):
        calls = []

        def sender(token, chat, text, silent=False):
            calls.append((text, silent))
        n = notify.Notifier(lambda: {"telegram_enabled": "on", "telegram_token": "t", "telegram_chat_id": "1",
                                     "notify_silent": "on", "notify_silent_start": "00:00", "notify_silent_end": "23:59",
                                     "notify_silent_sound_from": "critical", "notify_group": "off"}, sender=sender)
        n.event("problem", {"device": "nas", "severity": "warning", "problem": "CPU high"})
        n.event("problem", {"device": "nas", "severity": "critical", "problem": "Disk failing"}, critical=True)
        n.event("problem", {"device": "nas", "severity": "warning", "problem": "Port down"}, sound="always")
        # Back online after a critical outage: good news, no sound.
        n.event("device_online", {"device": "nas", "severity": "critical", "duration": "5m"}, critical=False)
        n.event("problem_resolved", {"device": "nas", "severity": "critical", "problem": "Disk failing"})
        n.drain(now=time.time() + 1)
        self.assertEqual([c[1] for c in calls], [True, False, False, True, True])
        with mock.patch.object(notify, "_post") as post:
            notify.send("t", "1", "hello", silent=True)
            self.assertTrue(post.call_args[0][2]["disable_notification"])
            notify.send("t", "1", "hello")
            self.assertNotIn("disable_notification", post.call_args[0][2])

    def test_silent_test_button(self):
        start_api_server()
        token = "123456:" + "A" * 35
        with mock.patch.object(notify, "send") as send:
            status, body, _ = request("POST", "/api/notify/test", {"token": token, "chat_id": "42", "silent": True})
            self.assertEqual(status, 200, body)
            self.assertTrue(send.call_args.kwargs["silent"])
            self.assertIn("without a sound", send.call_args[0][2])
            self.assertTrue(body["silent"])
            self.assertRegex(body["clock"], r"^\d\d:\d\d$")             # the monitor's clock, to spot a wrong time zone
            self.assertIn("silent_now", body)
            request("POST", "/api/notify/test", {"token": token, "chat_id": "42"})
            self.assertFalse(send.call_args.kwargs["silent"])


if __name__ == "__main__":
    unittest.main()
