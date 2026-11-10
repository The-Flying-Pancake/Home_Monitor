"""The message template engine shared by every Telegram text."""

import time
import tracemalloc
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import request, session_cookie, start_api_server

import auth
import botcmds
import notify
import server
import telebot
import tpl
import workflows

PASSWORD = "template preview passphrase"

V = {"up": 15, "total": 16, "down": 1, "down_list": "Down: NAS", "cpu": "34.6%", "state": "down", "ping": "",
     "list": "b 3\na 10\nc 2", "memory": "61%", "problems": 0, "count": 3, "name": "nas-01", "metric:temp.cpu-0": "55.5"}


class EngineTests(unittest.TestCase):
    def r(self, text, values=V, **kw):
        return tpl.render(text, values, **kw)

    def test_placeholders_and_lines(self):
        self.assertEqual(self.r("{up} of {total}\n{ping}\nend"), "15 of 16\nend")           # empty line dropped
        self.assertEqual(self.r("{nope}"), "{nope}")                                        # unknown left as written
        self.assertEqual(self.r("{nope}", known={"nope"}), "")
        self.assertEqual(self.r("{{literal}}"), "{literal}")
        self.assertEqual(self.r("{ping} rest"), "rest")

    def test_conditions(self):
        t = "{if down > 0}\nDown: {down}\n{elif problems}\nProblems\n{else}\nAll up\n{end}\nafter"
        self.assertEqual(self.r(t), "Down: 1\nafter")
        self.assertEqual(self.r(t, dict(V, down=0, problems=2)), "Problems\nafter")
        self.assertEqual(self.r(t, dict(V, down=0)), "All up\nafter")
        self.assertEqual(self.r('{if state == "down"}🔴{else}🟢{end} x'), "🔴 x")
        self.assertEqual(self.r("{if up >= 15 and not down == 0}yes{end}"), "yes")
        self.assertEqual(self.r("{if ping}p{else}none{end}"), "none")
        self.assertEqual(self.r("{if cpu > 30}hot{end}"), "hot")                            # "34.6%" counts as 34.6
        self.assertEqual(self.r("{if down > 0}\n{if problems}x{else}y{end}\n{end}"), "y")   # nested
        self.assertIn("{?", self.r("{if}x{end}"))
        self.assertIn("{?an if without end}", self.r("{if down}x"))
        self.assertIn("{?end without if}", self.r("x{end}"))

    def test_arithmetic(self):
        self.assertEqual(self.r("{= up / total * 100 | round:1}%"), "93.8%")
        self.assertEqual(self.r("{= (up + down) * 2}"), "32")
        self.assertEqual(self.r("{= max(up, total) - min(1, 2)}"), "15")
        self.assertEqual(self.r("{= round(cpu)}"), "35")
        self.assertEqual(self.r("{= [metric:temp.cpu-0] * 1.8 + 32 | round:1}"), "131.9")
        self.assertIn("division by zero", self.r("{= up / 0}"))
        self.assertIn("unknown name", self.r("{= nope + 1}"))
        self.assertIn("not a number", self.r("{= state + 1}"))
        self.assertIn("{?", self.r("{= 2 ** 3}"))                                            # no exponent
        self.assertIn("{?", self.r("{= __import__}"))

    def test_filters(self):
        cases = {"{name|upper}": "NAS-01", "{name|title}": "Nas-01", "{ping|default:\"n/a\"}": "n/a",
                 "{ping|before:\"ping \"}x": "x", "{cpu|before:\"cpu \"}": "cpu 34.6%", "{cpu|round:0}": "35",
                 "{cpu|fixed:2}": "34.60", "{cpu|int}": "34", "{up|add:5}": "20", "{up|div:4}": "3.75",
                 "{count|plural:device}": "3 devices", "{down|plural:device}": "1 device",
                 "{down|plural:box:boxes}": "1 box", "{memory|bar:10}": "▰▰▰▰▰▰▱▱▱▱", "{name|truncate:3}": "na…",
                 "{name|pad:7}|": "nas-01 |", "{name|replace:nas:NAS}": "NAS-01", "{list|first:2}": "b 3\na 10",
                 "{list|last:1}": "c 2", "{list|sort|join}": "a 10, b 3, c 2", "{list|rsort|first:1}": "c 2",
                 "{list|count}": "3", "{list|join:\" / \"}": "b 3 / a 10 / c 2", "{cpu|upper|default:x}": "34.6%"}
        for t, want in cases.items():
            self.assertEqual(self.r(t), want, t)
        self.assertEqual(self.r("{nums|sort|join}", {"nums": "10\n9\n100"}), "9, 10, 100")   # numbers by value
        self.assertIn("unknown filter", self.r("{up|frob}"))
        self.assertIn("not a number", self.r("{name|round:1}"))

    def test_bounded(self):
        self.assertLessEqual(len(self.r("{list}" * 3000)), tpl.MAX_OUT)
        self.assertLessEqual(len(self.r("x" * 20000)), tpl.MAX_OUT)

    def test_notifications_use_it(self):
        text = notify.render("{device}: {if severity == \"critical\"}🚨{end}{problem|truncate:12} {duration}", {
            "device": "nas-01", "severity": "critical", "problem": "CPU usage 97% (threshold 90%)"})
        self.assertEqual(text, "nas-01: 🚨CPU usage 9…")                    # a known placeholder not supplied is empty
        self.assertEqual(notify.render("{typo}", {}), "{typo}")
        for kind, (_, _, default) in notify.EVENTS.items():                  # every default renders without a mistake
            self.assertNotIn("{?", notify.render(default, notify.SAMPLE), kind)

    def test_tricks_are_valid(self):
        for what, ex in tpl.TRICKS:
            out = tpl.render(ex, V, known=set(V) | {"problem", "list"})
            self.assertNotIn("{?", out, (what, ex, out))


# Each replace makes every "n" twenty: 1, 20, 400, 8000, then 160,000 characters.
GROW = "{device" + ("|replace:n:" + "n" * 20) * 5 + "}"
GROW_VALUES = {"device": "nas-01"}


def peak_of(fn):
    """(result, peak bytes traced while fn runs, seconds)."""
    tracemalloc.start()
    t0 = time.monotonic()
    try:
        out = fn()
        return out, tracemalloc.get_traced_memory()[1], time.monotonic() - t0
    finally:
        tracemalloc.stop()


class LimitTests(unittest.TestCase):
    MIB = 1024 * 1024

    def test_replace_prediction_boundary(self):
        v = "a" * (tpl.MAX_WORK // 2)
        self.assertEqual(len(tpl.render("{v|replace:a:aa}", {"v": v}, max_len=10 ** 6, strict=True)), tpl.MAX_WORK)
        with self.assertRaises(tpl.TemplateLimit):
            tpl.render("{v|replace:a:aa}", {"v": v + "a"}, strict=True)

    def test_chained_replace_is_stopped_cheaply(self):
        out, peak, took = peak_of(lambda: tpl.render(GROW, GROW_VALUES))
        self.assertEqual(out, tpl.FALLBACK)
        self.assertLess(peak, 2 * self.MIB)
        self.assertLess(took, 1)

    def test_join_growth_is_bounded(self):
        lines = "\n".join(f"line {i}" for i in range(2000))
        out, peak, _ = peak_of(lambda: tpl.render('{v|join:"' + "-" * 1000 + '"}', {"v": lines}))
        self.assertEqual(out, tpl.FALLBACK)
        self.assertLess(peak, 2 * self.MIB)

    def test_other_filters_checked_after(self):
        with self.assertRaises(tpl.TemplateLimit):
            tpl.render("{v|upper}", {"v": "ß" * tpl.MAX_WORK}, strict=True)

    def test_line_cap(self):
        many = "\n".join(str(i) for i in range(3000))
        self.assertEqual(len(tpl.render("{v|sort}", {"v": many}, max_len=10 ** 6).split("\n")), tpl.MAX_LINES)
        self.assertEqual(len(tpl.render("{v|unique}", {"v": many}, max_len=10 ** 6).split("\n")), tpl.MAX_LINES)
        self.assertEqual(len(tpl.render("{v|join}", {"v": many}, max_len=10 ** 6).split(", ")), tpl.MAX_LINES)
        self.assertEqual(tpl.render("{v|count}", {"v": many}), "3000")

    def test_long_value_is_clipped_not_refused(self):
        self.assertEqual(tpl.render("{v|truncate:5}", {"v": "x" * (tpl.MAX_WORK + 10)}), "xxxx…")

    def test_total_budget(self):
        big = {"v": "x" * tpl.MAX_WORK}
        out, peak, _ = peak_of(lambda: tpl.render("{v|upper}" * 25, big))
        self.assertEqual(out, tpl.FALLBACK)
        self.assertLess(peak, 8 * self.MIB)
        self.assertNotEqual(tpl.render("{v|upper}" * 3, big), tpl.FALLBACK)      # within the budget

    def test_fallback_and_logged_once(self):
        text = GROW + " logged once " + str(time.time())
        with self.assertLogs("tpl", level="WARNING") as logs:
            for _ in range(3):
                self.assertEqual(tpl.render(text, GROW_VALUES), tpl.FALLBACK)
        self.assertEqual(len(logs.records), 1)
        self.assertNotIn("replace:n", logs.output[0])
        self.assertNotIn("logged once", logs.output[0])

    def test_overflow_is_a_mark(self):
        vals = {"x": "1" * 400, "l": "a\nb"}
        for t in ("{x|int}", "{x|fixed:0}", "{= floor(x)}", "{l|first:1e999}", "{if floor(x) > 1}y{end}"):
            out = tpl.render(t, vals)
            self.assertIn("{?", out, t)

    def test_deep_brackets_are_a_mark(self):
        self.assertIn("{?", tpl.render("{= " + "(" * 190 + "}", {}))
        self.assertIn("{?", tpl.render("{if " + "(" * 190 + "}x{end}", {}))


class CallerTests(unittest.TestCase):
    def test_notify_render_fallback(self):
        stored = GROW + " " * (500 - len(GROW))
        self.assertEqual(notify.render(stored, GROW_VALUES), tpl.FALLBACK)

    def test_notifier_event_uses_builtin_text(self):
        n = notify.Notifier(lambda: {"telegram_enabled": "on", "notify_tpl_device_offline": GROW},
                            sender=lambda *a, **k: None)
        queued = []
        with mock.patch.object(notify, "queue_message", side_effect=lambda text, *a, **k: queued.append(text) or 1):
            n.event("device_offline", {"device": "nas-01", "ip": "192.0.2.5", "problem": ""})
        self.assertEqual(len(queued), 1)
        first, rest = queued[0].split("\n", 1)
        self.assertEqual(first, notify.TOO_LONG_NOTE)
        self.assertIn("nas-01 (192.0.2.5) is offline.", rest)

    def test_telebot_fill_fallback(self):
        self.assertEqual(telebot.fill(GROW, GROW_VALUES), tpl.FALLBACK)

    def test_custom_command_fallback(self):
        calls = []

        def fill(text, values):
            calls.append(text)
            return telebot.fill(text, values)
        items = [{"_name": f"d{i}", "device": f"nas-{i}"} for i in range(50)]
        spec = {"gather": lambda c, now: ({}, items), "label": "test"}
        with mock.patch.dict(botcmds.SOURCES, {"devices": dict(botcmds.SOURCES["devices"], **spec)}):
            out = botcmds.render({"name": "x", "source": "devices", "header": "", "line": GROW, "footer": "{count}"},
                                 fill=fill)
        self.assertEqual(out, tpl.FALLBACK)
        self.assertEqual(len(calls), 1)

    def test_workflow_step_fallback(self):
        sent = []
        with mock.patch.object(workflows, "send_telegram", side_effect=lambda text: sent.append(text) or 1), \
                mock.patch.object(workflows, "_telegram_values", return_value=dict(GROW_VALUES)):
            ok, detail = workflows.WorkflowRun._telegram(object(), {"type": "telegram", "text": GROW})
        self.assertTrue(ok)
        self.assertEqual(sent, [tpl.FALLBACK])


class RouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        for name, role, perms in (("tpl-viewer", "viewer", None), ("tpl-op", "operator", None),
                                  ("tpl-notify", "custom", ["settings.notifications"]),
                                  ("tpl-auto", "custom", ["automation.edit"])):
            body = {"username": name, "password": PASSWORD, "role": role}
            if perms is not None:
                body["permissions"] = perms
            status, resp, _ = request("POST", "/api/users", body)
            assert status == 201, resp

    def login(self, name):
        status, body, headers = request("POST", "/api/auth/login", {"username": name, "password": PASSWORD}, session=False)
        self.assertEqual(status, 200, body)
        return session_cookie(headers)

    def preview(self, cookie, text="{device}", values=None):
        return request("POST", "/api/template/render", {"text": text, "values": values or GROW_VALUES},
                       headers={"Cookie": f"{auth.SESSION_COOKIE}={cookie}"}, session=False)

    def test_chained_replace_returns_error_quickly(self):
        cookie = self.login("tpl-notify")
        (status, body, _), peak, took = peak_of(lambda: self.preview(cookie, GROW))
        self.assertEqual(status, 400, body)
        self.assertIn("too long to build", body["error"])
        self.assertLess(took, 2)
        self.assertLess(peak, 16 * 1024 * 1024)

    def test_viewer_403_editors_200(self):
        self.assertEqual(self.preview(self.login("tpl-viewer"))[0], 403)
        self.assertEqual(self.preview(self.login("tpl-op"))[0], 403)
        status, body, _ = self.preview(self.login("tpl-notify"))
        self.assertEqual((status, body["text"]), (200, "nas-01"))
        self.assertEqual(self.preview(self.login("tpl-auto"))[0], 200)

    def test_rate_limit_per_session(self):
        first, second = self.login("tpl-auto"), self.login("tpl-auto")
        for i in range(server.TEMPLATE_PREVIEW_LIMIT):
            self.assertEqual(self.preview(first)[0], 200, i)
        status, body, _ = self.preview(first)
        self.assertEqual(status, 429, body)
        self.assertIn("Too many previews", body["error"])
        self.assertEqual(self.preview(second)[0], 200)


if __name__ == "__main__":
    unittest.main()
