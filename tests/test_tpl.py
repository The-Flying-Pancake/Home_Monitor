"""The message template engine shared by every Telegram text."""

import unittest

from tests import _env  # noqa: F401

import notify
import tpl

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


if __name__ == "__main__":
    unittest.main()
