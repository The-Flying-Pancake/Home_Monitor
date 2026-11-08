"""Groups and tags: custom groups, tag catalogue, device tags, bulk tagging, rename and delete
carrying through to devices and alert rules, and tags as an alert rule scope."""

import unittest

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import alerts
import database
import server
import taxonomy


def tax(**body):
    return request("PUT", "/api/taxonomy", body)


class TaxonomyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.a = add_device("tax-a", "198.51.100.180", profile="ping_only")
        cls.b = add_device("tax-b", "198.51.100.181", profile="generic_device")

    def test_custom_groups(self):
        status, body, _ = tax(kind="group", action="add", name="Upstairs lab")
        self.assertEqual(status, 200, body)
        gid = next(g["id"] for g in body["groups"] if g["name"] == "Upstairs lab")
        self.assertTrue(gid.startswith("c_"))
        self.assertEqual(tax(kind="group", action="add", name="upstairs LAB")[0], 400)     # names are unique
        # A device moved into it shows there; the groups list counts it.
        status, dev, _ = request("GET", f"/api/devices/{self.a}")
        payload = {"hostname": "tax-a", "ip_address": "198.51.100.180", "profile_id": "ping_only", "device_group": gid}
        self.assertEqual(request("PUT", f"/api/devices/{self.a}", payload)[0], 200)
        row = next(d for d in request("GET", "/api/devices")[1]["devices"] if d["id"] == self.a)
        self.assertEqual(row["group"], gid)
        self.assertEqual(next(g for g in request("GET", "/api/taxonomy")[1]["groups"] if g["id"] == gid)["devices"], 1)
        # Built-in groups can be renamed and reordered, not deleted.
        self.assertEqual(tax(kind="group", action="rename", id="switch", name="Network switches")[0], 200)
        self.assertEqual(tax(kind="group", action="delete", id="switch")[0], 400)
        ids = [g["id"] for g in request("GET", "/api/taxonomy")[1]["groups"]]
        self.assertEqual(tax(kind="group", action="order", ids=[gid] + [i for i in ids if i != gid])[0], 200)
        self.assertEqual(request("GET", "/api/taxonomy")[1]["groups"][0]["id"], gid)
        self.assertEqual(tax(kind="group", action="order", ids=ids[:3])[0], 400)          # every group, once
        # Deleting the custom group sends its devices back to their template's group.
        self.assertEqual(tax(kind="group", action="delete", id=gid)[0], 200)
        row = next(d for d in request("GET", "/api/devices")[1]["devices"] if d["id"] == self.a)
        self.assertEqual(row["group"], "other")
        tax(kind="group", action="rename", id="switch", name="Switches")

    def test_tags_on_devices_and_in_bulk(self):
        payload = {"hostname": "tax-b", "ip_address": "198.51.100.181", "profile_id": "generic_device", "tags": ["Garage", "lab"]}
        self.assertEqual(request("PUT", f"/api/devices/{self.b}", payload)[0], 200)
        self.assertEqual(request("GET", f"/api/devices/{self.b}")[1]["device"]["tags"], ["Garage", "lab"])
        # Unknown tags join the catalogue; known ones keep their catalogue spelling.
        cat = {t["name"]: t for t in request("GET", "/api/taxonomy")[1]["tags"]}
        self.assertIn("Garage", cat)
        status, body, _ = request("POST", "/api/devices/tags", {"device_ids": [self.a, self.b], "add": ["GARAGE"], "remove": ["lab"]})
        self.assertEqual((status, body["changed"]), (200, 2), body)
        tags = {d["id"]: d["tags"] for d in request("GET", "/api/devices")[1]["devices"]}
        self.assertEqual((tags[self.a], tags[self.b]), (["Garage"], ["Garage"]))
        self.assertEqual(request("POST", "/api/devices/tags", {"device_ids": [self.a], "add": ["bad\ttag;"]})[0], 400)
        self.assertEqual(request("PUT", f"/api/devices/{self.b}", dict(payload, tags=["ok", "x" * 40]))[0], 400)

    def test_rename_and_delete_carry_through(self):
        tax(kind="tag", action="add", name="critical", colour="red", description="Wake me up")
        request("POST", "/api/devices/tags", {"device_ids": [self.a], "add": ["critical"]})
        database.set_alert_overrides("tag", "critical", [("unreachable", "severity", "critical")])
        self.assertEqual(tax(kind="tag", action="rename", name="critical", new_name="must-stay-up")[0], 200)
        self.assertIn("must-stay-up", taxonomy.device_tags(database.get_device(self.a)))
        targets = {(o["scope"], o["target"]) for o in database.list_alert_overrides()}
        self.assertIn(("tag", "must-stay-up"), targets)
        self.assertNotIn(("tag", "critical"), targets)
        t = next(t for t in request("GET", "/api/taxonomy")[1]["tags"] if t["name"] == "must-stay-up")
        self.assertEqual((t["colour"], t["description"], t["rules"]), ("red", "Wake me up", 1))
        status, body, _ = tax(kind="tag", action="delete", name="must-stay-up")
        self.assertEqual(status, 200, body)
        self.assertNotIn("must-stay-up", taxonomy.device_tags(database.get_device(self.a)))
        self.assertNotIn(("tag", "must-stay-up"), {(o["scope"], o["target"]) for o in database.list_alert_overrides()})


class TagAlertTests(unittest.TestCase):
    def test_tag_layer_order(self):
        rules = alerts.catalogue([])
        overrides = [
            {"scope": "global", "target": "", "rule_id": "cpu", "field": "threshold", "value": "80"},
            {"scope": "tag", "target": "lab", "rule_id": "cpu", "field": "threshold", "value": "95"},
            {"scope": "tag", "target": "noisy", "rule_id": "cpu", "field": "threshold", "value": "99"},
            {"scope": "tag", "target": "lab", "rule_id": "cpu", "field": "enabled", "value": "0"},
            {"scope": "device", "target": "7", "rule_id": "cpu", "field": "enabled", "value": "1"},
        ]
        # Lower in the tag list wins: noisy after lab.
        policy = alerts.Policy(rules, overrides, {"lab": 0, "noisy": 1})
        values, source = policy.resolve("cpu", "", 7, tags=["noisy", "lab"])
        self.assertEqual((values["threshold"], source["threshold"]), (99.0, "tag:noisy"))
        self.assertEqual((values["enabled"], source["enabled"]), (True, "device"))   # the device still has the last word
        values, _ = policy.resolve("cpu", "", 8, tags=["lab"])
        self.assertEqual((values["threshold"], values["enabled"]), (95.0, False))
        values, _ = policy.resolve("cpu", "", 8, tags=[])
        self.assertEqual(values["threshold"], 80.0)
        # for_device reads the tags straight from the database row (a JSON list).
        get = policy.for_device({"id": 9, "profile_id": "", "tags": '["lab"]'})
        self.assertFalse(get("cpu")["enabled"])

    def test_tag_scope_api(self):
        start_api_server()
        dev = add_device("tax-alert", "198.51.100.182")
        request("POST", "/api/devices/tags", {"device_ids": [dev], "add": ["office"]})
        status, body, _ = request("PUT", "/api/alert-rules", {"scope": "tag", "target": "office",
                                                              "changes": [{"rule_id": "unreachable", "field": "severity", "value": "info"}]})
        self.assertEqual(status, 200, body)
        view = request("GET", f"/api/alert-rules?scope=device&target={dev}")[1]
        r = next(r for r in view["rules"] if r["id"] == "unreachable")
        self.assertEqual((r["effective"]["severity"], r["source"]["severity"]), ("info", "tag:office"))
        self.assertEqual(view["device_tags"], ["office"])
        # The evaluation uses it: an unreachable device with this tag opens an info problem.
        device = dict(database.get_device(dev), status="offline")
        problems = server.device_problems(device, {}, {}, server.alert_policy().for_device(device))
        self.assertEqual(next(p for p in problems if p["key"] == "unreachable")["severity"], "info")
        overview = request("GET", "/api/alert-rules?scope=overview")[1]
        self.assertIn(("tag", "office"), {(g["scope"], g["target"]) for g in overview["groups"]})
        self.assertEqual(request("GET", "/api/alert-rules?scope=tag&target=nope")[0], 404)


if __name__ == "__main__":
    unittest.main()
