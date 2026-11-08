"""What's changed (changelog.py), the graphs chosen for a device's Overview, and custom SNMP
values named in workflow triggers."""

import json
import re
import unittest

from tests import _env  # noqa: F401
from tests.helpers import TEST_USER, add_device, request, start_api_server

import changelog
import customoids
import database
import server
import workflows


class ChangelogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_notes_are_plain_and_ordered(self):
        ids = [r["id"] for r in changelog.RELEASES]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), len(set(ids)))
        for r in changelog.RELEASES:
            self.assertRegex(r["date"], r"^\d{4}-\d{2}-\d{2}$")
            for text in [r["title"]] + r["items"]:
                self.assertNotIn("—", text)            # no em dashes
                self.assertFalse(re.search(r", (and|or) ", text), text)   # no serial commas
                self.assertTrue(text[0].isupper(), text)
        # The first note is the round that replaced Uptime Kuma.
        self.assertIn("websites", changelog.RELEASES[0]["title"].lower())

    def test_upgraded_install_sees_everything_once(self):
        database.delete_settings([changelog.SEEN_KEY])
        changelog.first_run(database.get_all_settings(), has_accounts=True)
        body = request("GET", "/api/changes")[1]
        self.assertEqual(body["unseen"], [r["id"] for r in changelog.RELEASES])
        self.assertEqual(body["releases"][0]["id"], changelog.LATEST)          # newest first
        self.assertEqual(request("POST", "/api/changes/seen")[0], 200)
        self.assertEqual(request("GET", "/api/changes")[1]["unseen"], [])
        # Already decided: a restart changes nothing.
        changelog.first_run(database.get_all_settings(), has_accounts=True)
        self.assertEqual(changelog.seen(TEST_USER), changelog.LATEST)

    def test_fresh_install_and_new_users_start_read(self):
        database.delete_settings([changelog.SEEN_KEY])
        changelog.first_run({}, has_accounts=False)
        self.assertEqual(changelog.seen("someone-new"), changelog.LATEST)
        # An upgraded install: a user added afterwards starts with nothing unread too.
        database.delete_settings([changelog.SEEN_KEY])
        changelog.first_run({}, has_accounts=True)
        self.assertEqual(changelog.seen("later-user"), 0)
        status, body, _ = request("POST", "/api/users", {"username": "later-user", "password": "a long enough password 1", "role": "viewer"})
        self.assertEqual(status, 201, body)
        self.assertEqual(changelog.seen("later-user"), changelog.LATEST)
        request("DELETE", "/api/users/later-user")


class OverviewGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("ov-dev", "198.51.100.190", profile="generic_device")

    def test_choose_and_reset(self):
        self.assertIsNone(request("GET", f"/api/devices/{self.dev}")[1]["overview_graphs"])
        status, body, _ = request("PUT", f"/api/devices/{self.dev}/overview", {"graphs": ["cpu_usage_pct", "custom.3", "cpu_usage_pct"]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["overview_graphs"], ["cpu_usage_pct", "custom.3"])      # duplicates dropped, order kept
        self.assertEqual(request("GET", f"/api/devices/{self.dev}")[1]["overview_graphs"], ["cpu_usage_pct", "custom.3"])
        self.assertEqual(request("PUT", f"/api/devices/{self.dev}/overview", {"graphs": []})[1]["overview_graphs"], [])
        self.assertIsNone(request("PUT", f"/api/devices/{self.dev}/overview", {"graphs": None})[1]["overview_graphs"])

    def test_refused(self):
        for bad in ({"graphs": "cpu"}, {"graphs": ["x" * 81]}, {"graphs": ["bad id!"]}, {"graphs": [f"g{i}" for i in range(13)]}, {"graphs": [1]}):
            self.assertEqual(request("PUT", f"/api/devices/{self.dev}/overview", bad)[0], 400, bad)
        self.assertEqual(request("PUT", "/api/devices/999999/overview", {"graphs": []})[0], 404)

    def test_deleting_the_device_forgets_its_choice(self):
        dev = add_device("ov-gone", "198.51.100.191", profile="generic_device")
        request("PUT", f"/api/devices/{dev}/overview", {"graphs": ["icmp_ping_ms"]})
        self.assertEqual(request("DELETE", f"/api/devices/{dev}")[0], 200)
        self.assertNotIn(str(dev), json.loads(database.get_all_settings().get(server.OVERVIEW_KEY) or "{}"))


class CustomValueNamesTests(unittest.TestCase):
    def test_trigger_text_uses_the_name(self):
        sched = {"kind": "event", "when": {"type": "metric", "device_id": 5, "metric": "custom.7", "op": "above", "value": 80.0, "for_minutes": 5}}
        self.assertEqual(workflows.event_text(sched, {5: "Switch"}, {"custom.7": "CPU usage"}),
                         "When Switch CPU usage is above 80 for 5 min")
        self.assertEqual(workflows.event_text(sched, {5: "Switch"}), "When Switch custom.7 is above 80 for 5 min")
        self.assertEqual(customoids.metric_key(7), "custom.7")


if __name__ == "__main__":
    unittest.main()
