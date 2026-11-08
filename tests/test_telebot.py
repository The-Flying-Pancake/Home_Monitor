"""Telegram commands: the read-only answers, and the poller that only answers the configured chat."""

import time
import unittest

from tests import _env  # noqa: F401
from tests.helpers import add_device, start_api_server

import database
import telebot

TOKEN = "123456:" + "a" * 35
OWNER = "4242"


def update(uid, text, chat=OWNER, age=0):
    return {"update_id": uid, "message": {"text": text, "date": int(time.time() - age),
                                          "chat": {"id": int(chat), "first_name": "Owner"}}}


class AnswerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("telebot-nas", "198.51.100.170", profile="ping_only")

    def test_commands(self):
        self.assertIsNone(telebot.answer("hello"))
        self.assertIn("/problems", telebot.answer("/help"))
        self.assertIn("/status", telebot.answer("/start"))
        self.assertIn("I do not know /reboot", telebot.answer("/reboot NAS"))
        self.assertIn("devices:", telebot.answer("/status@MyMonitorBot"))
        self.assertTrue(telebot.answer("/problems"))
        self.assertIn("The last 24 hours", telebot.answer("/changes"))
        self.assertIn("Which device", telebot.answer("/device"))
        self.assertIn("No device called", telebot.answer("/device no-such-thing"))
        self.assertIn("telebot-nas (198.51.100.170)", telebot.answer("/device TELEBOT-NAS"))
        self.assertIn("telebot-nas", telebot.answer("/device 198.51.100.170"))
        self.assertIn("telebot-nas", telebot.answer("/device telebot-n"))     # the start of a name is enough

    def test_templates(self):
        values = {"a": "x", "empty": "", "list": "one\ntwo"}
        self.assertEqual(telebot.fill("Head {a}\n{empty}\n{list}\n{empty} \nEnd", values), "Head x\none\ntwo\nEnd")
        self.assertEqual(telebot.fill("{empty} rest", values), "rest")          # a leading empty placeholder leaves no space
        self.assertEqual(telebot.fill("{typo}", values), "{typo}")             # unknown names show, so a typo is seen
        s = {"bot_tpl_status": "Up {up} of {total}\n{down_list}", "bot_tpl_device": "{device} is {state}. {problems_list}",
             "bot_tpl_problem_item": "* {device}"}
        self.assertRegex(telebot.answer("/status", s), r"^Up \d+ of \d+")
        self.assertIn("telebot-nas is ", telebot.answer("/device telebot-nas", s))
        # Every default only uses its own placeholders, and the editor's samples cover them.
        samples = telebot.samples()
        for key, (_, _, default, presets) in telebot.TEMPLATES.items():
            for text in [default] + presets:
                for name in telebot._FIELD.findall(text):
                    self.assertIn(name, telebot.TEMPLATE_PLACEHOLDERS[key], (key, name))
            self.assertLessEqual(len(default), 500)
            if samples[key]:
                self.assertEqual(set(samples[key]), set(telebot.TEMPLATE_PLACEHOLDERS[key]), key)

    def test_settings_and_info(self):
        from tests.helpers import request
        status, body, _ = request("POST", "/api/settings", {"bot_tpl_status": "Hi {up}"})
        self.assertEqual(status, 200, body)
        self.assertEqual(telebot.answer("/status").split("\n")[0][:3], "Hi ")
        request("POST", "/api/settings", {"bot_tpl_status": ""})             # empty: back to the original
        self.assertEqual(database.get_all_settings()["bot_tpl_status"], telebot.TEMPLATES["status"][2])
        info = request("GET", "/api/notify/info")[1]
        self.assertIn("down_list", info["commands"]["status"]["placeholders"])
        self.assertIn("up", info["command_samples"]["status"])

    def test_long_answers_are_clipped(self):
        text = telebot._clip([str(i) for i in range(75)])
        self.assertIn("and 15 more", text)


class PollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def setUp(self):
        database.set_internal_setting(telebot.OFFSET_KEY, "0")
        self.sent, self.queue = [], []
        self.settings = {"telegram_enabled": "on", "telegram_token": TOKEN, "telegram_chat_id": OWNER}

    def bot(self):
        def settings():
            return dict(self.settings, telegram_offset=database.get_all_settings().get(telebot.OFFSET_KEY, "0"))

        def fetch(token, offset, timeout):
            self.offsets.append(offset)
            out, self.queue = self.queue, []
            return out

        self.offsets = []
        return telebot.Bot(settings, fetch=fetch, sender=lambda t, c, text, **kw: self.sent.append((c, text)))

    def test_owner_only_and_offset(self):
        bot = self.bot()
        self.queue = [update(10, "/status"), update(11, "/status", chat="999"), update(12, "just chatting"),
                      update(13, "/problems", age=3600)]
        self.assertEqual(bot.poll_once(), 1)
        self.assertEqual([c for c, _ in self.sent], [OWNER])               # the other chat got nothing
        self.assertEqual(database.get_all_settings()[telebot.OFFSET_KEY], "14")
        bot.poll_once()
        self.assertEqual(self.offsets[-1], 14)                             # confirmed: never answered twice
        self.assertIsNone(bot.last_chat)                                   # no Find my chat running: nothing kept
        audit = [a["message"] for a in database.list_audit_logs(limit=20)]
        self.assertTrue(any("another chat" in m for m in audit))
        self.assertTrue(any("Answered Telegram command /status" in m for m in audit))

    def test_find_chat_only_during_a_search(self):
        bot = self.bot()
        # A stranger wrote before the search started: never picked.
        self.queue = [update(30, "hello", chat="777", age=30)]
        bot.poll_once()
        self.assertIsNone(bot.last_chat)
        bot.start_find()
        self.queue = [update(31, "earlier", chat="777", age=30)]
        bot.poll_once()
        self.assertIsNone(bot.last_chat)                                   # older than the search
        self.queue = [update(32, "hi bot")]
        bot.poll_once()
        self.assertEqual(bot.last_chat, {"id": OWNER, "name": "Owner"})
        # The window closes after FIND_SECONDS.
        bot.start_find(time.time() - telebot.FIND_SECONDS - 1)
        self.queue = [update(33, "late", chat="777")]
        bot.poll_once()
        self.assertIsNone(bot.last_chat)
        self.assertFalse(bot.finding())

    def test_find_chat_route_needs_two_presses(self):
        from unittest import mock
        from tests.helpers import request
        import notify
        import server
        server.BOT.end_find()
        msgs = {"result": []}

        def post(token, method, payload, timeout=15.0):
            return {"username": "homebot"} if method == "getMe" else msgs["result"]
        with mock.patch.object(notify, "_post", side_effect=post):
            msgs["result"] = [update(40, "old message", chat="777", age=60)]
            status, body, _ = request("POST", "/api/notify/find-chat", {"token": TOKEN})
            self.assertEqual((status, body.get("searching")), (200, True))
            status, body, _ = request("POST", "/api/notify/find-chat", {"token": TOKEN})
            self.assertEqual(status, 404)                                  # the stranger's old message does not count
            msgs["result"] = [update(40, "old message", chat="777", age=60), update(41, "me")]
            status, body, _ = request("POST", "/api/notify/find-chat", {"token": TOKEN})
            self.assertEqual((status, body["chat_id"], body["chat_name"]), (200, OWNER, "Owner"))
        self.assertFalse(server.BOT.finding())

    def test_switched_off(self):
        bot = self.bot()
        self.queue = [update(20, "/status")]
        self.settings["telegram_commands"] = "off"
        self.assertEqual(bot.poll_once(), 0)
        self.assertEqual(self.offsets, [])                                 # does not even ask Telegram
        self.settings.update(telegram_commands="on", telegram_enabled="off")
        self.assertEqual(bot.poll_once(), 0)
        self.assertEqual(self.offsets, [])


if __name__ == "__main__":
    unittest.main()
