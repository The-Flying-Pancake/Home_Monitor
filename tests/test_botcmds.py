"""Your own Telegram commands: checks, every source, picks, filters, the argument, switching
commands off, /help, Telegram's command menu and the builder's API."""

import json
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import botcmds
import database
import pihole
import proxmox
import telebot

WIFI = {"weak_dbm": -75,
        "aps": [{"device_id": 1, "name": "ap-hall", "ip": "198.51.100.2", "status": "online", "clients": 3, "weak": 1,
                 "experience": 90, "bands": {"5 GHz": 2, "2.4 GHz": 1}}],
        "clients": [{"mac": "aa:aa:aa:aa:aa:01", "name": "phone", "ip": "198.51.100.31", "ssid": "Home", "band": "5 GHz",
                     "signal": -60, "tx_mbps": 400, "experience": 95, "ap_id": 1, "ap_name": "ap-hall"},
                    {"mac": "aa:aa:aa:aa:aa:02", "name": "tablet", "ip": "198.51.100.32", "ssid": "Home", "band": "5 GHz",
                     "signal": -80, "experience": 60, "ap_id": 1, "ap_name": "ap-hall"},
                    {"mac": "aa:aa:aa:aa:aa:03", "name": "visitor", "ip": "198.51.100.33", "ssid": "Guest", "band": "2.4 GHz",
                     "signal": -55, "ap_id": 1, "ap_name": "ap-hall"}]}
PVE = {"configured": True, "version": "8.2", "nodes": [{"node": "pve", "status": "online", "cpu": 0.12, "maxcpu": 8, "mem": 8e9,
                                                         "maxmem": 32e9, "uptime": 90000}],
       "guests": [{"vmid": 101, "name": "media-server", "node": "pve", "type": "qemu", "status": "running", "cpu": 0.05, "mem": 2e9,
                   "maxmem": 4e9, "uptime": 3600, "ips": ["198.51.100.40"], "onboot": True},
                  {"vmid": 102, "name": "dns-filter", "node": "pve", "type": "lxc", "status": "stopped", "mem": 0, "maxmem": 1e9,
                   "disk": 2e9, "maxdisk": 8e9, "onboot": True}],
       "storage": [{"storage": "local-lvm", "node": "pve", "status": "available", "disk": 40e9, "maxdisk": 100e9}],
       "backups": [], "failed_tasks": []}


def cmd(**kw):
    base = {"name": "x", "source": "devices", "header": "", "line": "{device}", "footer": ""}
    return botcmds.clean(dict(base, **kw))


class CheckTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(cmd(name="/WiFi")["name"], "wifi")
        for bad in ({"name": "status"}, {"name": "9lives"}, {"name": "a b"}, {"source": "nope"}, {"only": "bogus"},
                    {"line": "", "header": " "}, {"line": "x" * 900}):
            with self.assertRaises(botcmds.CommandError, msg=bad):
                cmd(**bad)
        self.assertEqual(cmd()["description"], "Devices")              # a description by default
        with self.assertRaises(botcmds.CommandError):
            botcmds.save([{"name": "a", "source": "devices", "line": "x"}] * 2, [])


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.a = add_device("botcmd-a", "198.51.100.236", profile="ping_only")
        cls.b = add_device("botcmd-b", "198.51.100.237", profile="ping_only")
        with database.get_connection() as c:
            c.execute("UPDATE devices SET status = 'online', last_ping_ms = 3.2, tags = ? WHERE id = ?;", (json.dumps(["rack"]), cls.a))
            c.execute("UPDATE devices SET status = 'offline' WHERE id = ?;", (cls.b,))
            c.commit()

    def test_devices(self):
        text = botcmds.render(cmd(pick=[str(self.a), str(self.b)], header="{count}: {up} up, {down} down",
                                  line="{mark} {device} {state} ping {ping}"))
        self.assertIn("2: 1 up, 1 down", text)
        self.assertIn("🟢 botcmd-a up ping 3 ms", text)
        self.assertIn("🔴 botcmd-b down", text)
        self.assertNotIn("botcmd-b", botcmds.render(cmd(pick=["tag:rack"])))       # by tag
        self.assertIn("botcmd-a", botcmds.render(cmd(pick=["tag:rack"])))
        down = botcmds.render(cmd(pick=[str(self.a), str(self.b)], only="down"))
        self.assertEqual(down, "botcmd-b")
        self.assertEqual(botcmds.render(cmd(pick=[str(self.a), str(self.b)]), arg="-b"), "botcmd-b")   # the argument narrows
        self.assertEqual(botcmds.render(cmd(pick=[str(self.b)], only="up", footer="{empty}")), "Nothing to show.")
        choices = botcmds.choices("devices")
        self.assertIn("tag:rack", [c["id"] for c in choices["choices"]])

    def test_metric_placeholder(self):
        with database.get_connection() as c:
            c.execute("INSERT OR REPLACE INTO metric_latest (device_id, metric_key, value, timestamp) VALUES (?, 'temp.cpu-0', 55.5, ?);",
                      (self.a, int(time.time())))
            c.commit()
        self.assertEqual(botcmds.render(cmd(pick=[str(self.a)], line="{device} {metric:temp.cpu-0}°C")), "botcmd-a 55.5°C")
        self.assertIn("metric:temp.cpu-0", [m["key"] for m in botcmds.choices("devices")["metrics"]])

    def test_sort_limit_and_templates(self):
        with mock.patch.object(botcmds, "wifi_view", return_value=WIFI):
            strong = botcmds.render(cmd(source="wifi_client", line="{client}", sort="signal", desc=True))
            self.assertEqual(strong, "visitor\nphone\ntablet")                         # -55, -60, -80 dBm
            self.assertEqual(botcmds.render(cmd(source="wifi_client", line="{client}", sort="client")), "phone\ntablet\nvisitor")
            two = botcmds.render(cmd(source="wifi_client", line="{client}", sort="signal", desc=True, limit=2,
                                     footer="{if more > 0}and {more} more{end}"))
            self.assertEqual(two, "visitor\nphone\nand 1 more")
            fancy = botcmds.render(cmd(source="wifi_ssid", line='{if weak > 0}⚠️{else}✅{end} {ssid|upper} {= clients * 10}'))
            self.assertEqual(fancy, "✅ GUEST 10\n⚠️ HOME 20")
        for bad in ({"sort": "nope"}, {"limit": -1}, {"limit": 999}, {"limit": "x"}):
            with self.assertRaises(botcmds.CommandError, msg=bad):
                cmd(**bad)
        self.assertEqual(botcmds.MAX_COMMANDS, 95)

    def test_wifi(self):
        with mock.patch.object(botcmds, "wifi_view", return_value=WIFI):
            ssid = botcmds.render(cmd(source="wifi_ssid", header="{clients} on Wi-Fi", line="{ssid}: {clients} ({weak} weak) {names}"))
            self.assertEqual(ssid, "3 on Wi-Fi\nGuest: 1 (0 weak) visitor\nHome: 2 (1 weak) phone, tablet")
            self.assertEqual(botcmds.render(cmd(source="wifi_ssid", line="{ssid}", pick=["Home"])), "Home")
            self.assertEqual(botcmds.render(cmd(source="wifi_ssid", line="{ssid}", only="weak")), "Home")
            self.assertIn("ap-hall: 3", botcmds.render(cmd(source="wifi_ap", line="{ap}: {clients}")))
            weak = botcmds.render(cmd(source="wifi_client", line="{client} {signal}", only="weak"))
            self.assertEqual(weak, "tablet -80 dBm")
            self.assertEqual([c["id"] for c in botcmds.choices("wifi_ssid")["choices"]], ["Guest", "Home"])

    def test_proxmox(self):
        with mock.patch.object(proxmox, "is_enabled", return_value=True), mock.patch.object(proxmox, "overview", return_value=PVE):
            g = botcmds.render(cmd(source="proxmox_guest", header="{running} running", line="{mark} {name} {state} {memory}"))
            self.assertEqual(g, "1 running\n🟢 media-server running 50%\n🔴 dns-filter stopped")
            self.assertEqual(botcmds.render(cmd(source="proxmox_guest", line="{name}", pick=["pve/102"])), "dns-filter")
            self.assertEqual(botcmds.render(cmd(source="proxmox_guest", line="{name}", only="running")), "media-server")
            self.assertIn("pve: CPU 12%, memory 25%, 1/2", botcmds.render(cmd(source="proxmox_node",
                                                                             line="{node}: CPU {cpu}, memory {memory}, {running}/{guests}")))
            self.assertEqual(botcmds.render(cmd(source="proxmox_storage", line="{storage} {used} {free}")), "local-lvm 40% 60.0 GB")
        with mock.patch.object(proxmox, "is_enabled", return_value=False):
            self.assertEqual(botcmds.render(cmd(source="proxmox_guest", line="{name}")), "Nothing to show.")

    def test_pihole_problems_forecasts(self):
        view = {"device": {"id": 1}, "metrics": {"pihole.queries": {"value": 12000.0}, "pihole.blocked_pct": {"value": 12.34},
                                                 "pihole.blocking": {"value": 1.0}, "dns.ms": {"value": 4.0}},
                "blocked": [{"domain": "ads.example", "count": 50}]}
        with mock.patch.object(pihole, "view", return_value=view):
            text = botcmds.render(cmd(source="pihole", header="{queries} q, {blocked_pct}, {blocking}, DNS {dns_ms}", line="{domain} {hits}"))
            self.assertEqual(text, "12000 q, 12.3%, on, DNS 4 ms\nads.example 50")
        self.assertTrue(botcmds.render(cmd(source="problems", line="{device}: {problem}", footer="{empty}")))
        self.assertTrue(botcmds.render(cmd(source="forecasts", line="{device}", footer="{empty}")))

    def test_every_default_uses_known_placeholders(self):
        for key, spec in botcmds.SOURCES.items():
            known = set(botcmds.placeholders(key)["summary"]) | set(spec["item"]) | {"time", "date", "count", "empty"}
            for part in ("header", "line", "footer"):
                for name in telebot._FIELD.findall(spec["default"][part]):
                    self.assertIn(name, known, (key, part, name))
                    if part != "line":
                        self.assertIn(name, botcmds.placeholders(key)["summary"], (key, part, name))


class BotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        add_device("botcmd-api", "198.51.100.238", profile="ping_only")

    def tearDown(self):
        database.set_internal_setting(botcmds.KEY, "{}")

    def test_answer_help_off_and_menu(self):
        botcmds.save([{"name": "rack", "description": "The rack", "source": "devices", "line": "{device}", "pick": ["tag:none"],
                       "footer": "{empty}"}], ["changes"])
        self.assertEqual(telebot.answer("/rack"), "Nothing to show.")
        self.assertIn("/rack: The rack", telebot.answer("/help"))
        self.assertNotIn("/changes", telebot.answer("/help"))
        self.assertIn("I do not know /changes", telebot.answer("/changes"))        # switched off
        sent = []
        bot = telebot.Bot(lambda: {}, fetch=lambda *a: [], sender=lambda *a, **k: None)
        bot.menu_sender = lambda token, cmds: sent.append([c["command"] for c in cmds])
        bot.sync_menu("t")
        bot.sync_menu("t")                                                            # unchanged: not sent again
        self.assertEqual(sent, [["status", "problems", "device", "rack", "help"]])
        botcmds.save([], [])
        bot.sync_menu("t")
        self.assertEqual(sent[-1], ["status", "problems", "device", "changes", "help"])

    def test_api(self):
        status, view, _ = request("GET", "/api/notify/bot-commands")
        self.assertEqual(status, 200)
        self.assertEqual([c["name"] for c in view["builtin"]], ["status", "problems", "device", "changes"])
        self.assertIn("wifi_ssid", view["sources"])
        self.assertIn("ssid", view["sources"]["wifi_ssid"]["item"])
        status, body, _ = request("POST", "/api/notify/bot-preview", {"builtin": "status", "texts": {"status": "Up {up}"}})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["text"].startswith("Up "))
        status, body, _ = request("POST", "/api/notify/bot-preview", {"command": {"name": "t", "source": "devices", "line": "* {device}"}})
        self.assertTrue(body["text"].startswith("* "), body)
        self.assertEqual(request("POST", "/api/notify/bot-preview", {"command": {"name": "status", "source": "devices", "line": "x"}})[0], 400)
        status, body, _ = request("POST", "/api/notify/bot-commands",
                                  {"custom": [{"name": "rack", "source": "devices", "line": "{device}"}], "off": ["device"],
                                   "texts": {"status": "Hello {up}"}})
        self.assertEqual(status, 200, body)
        self.assertEqual([c["name"] for c in body["custom"]], ["rack"])
        self.assertFalse(next(c for c in body["builtin"] if c["name"] == "device")["on"])
        self.assertEqual(database.get_all_settings()["bot_tpl_status"], "Hello {up}")
        request("POST", "/api/notify/bot-commands", {"custom": [], "off": [], "texts": {"status": ""}})
        self.assertEqual(database.get_all_settings()["bot_tpl_status"], telebot.TEMPLATES["status"][2])
        self.assertEqual(request("GET", "/api/notify/bot-choices?source=nope")[0], 400)
        self.assertEqual(request("GET", "/api/notify/bot-choices?source=devices")[0], 200)


if __name__ == "__main__":
    unittest.main()
