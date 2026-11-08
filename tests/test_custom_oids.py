"""Custom OIDs: validation, polling (gauge, counter rate, timeticks, text), thresholds, API and walk browser."""

import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import customoids
import database
import server


class ParseTests(unittest.TestCase):
    def test_validation(self):
        ok = customoids.parse({"scope": "device", "target": "3", "oid": ".1.3.6.1.4.1.9.9.1.0", "label": "CPU", "kind": "gauge"},
                              ["unifi_switch"], [3])
        self.assertEqual((ok["oid"], ok["scale"], ok["alert_op"]), ("1.3.6.1.4.1.9.9.1.0", 1.0, None))
        for bad, msg in (({"scope": "device", "target": "9", "oid": "1.3.6.1.4", "label": "x"}, "Unknown device"),
                         ({"scope": "template", "target": "nope", "oid": "1.3.6.1.4", "label": "x"}, "Unknown template"),
                         ({"scope": "device", "target": "3", "oid": "cpuLoad", "label": "x"}, "numeric OID"),
                         ({"scope": "device", "target": "3", "oid": "1.3.6.1.4", "label": ""}, "name"),
                         ({"scope": "device", "target": "3", "oid": "1.3.6.1.4", "label": "x", "kind": "float"}, "Type"),
                         ({"scope": "device", "target": "3", "oid": "1.3.6.1.4", "label": "x", "scale": 0}, "Scale"),
                         ({"scope": "device", "target": "3", "oid": "1.3.6.1.4", "label": "x", "kind": "string",
                           "alert_op": "above", "alert_value": 1}, "threshold")):
            with self.assertRaises(ValueError) as ctx:
                customoids.parse(bad, ["unifi_switch"], [3])
            self.assertIn(msg, str(ctx.exception))


class PollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = database.get_device(add_device("coid-switch", "192.0.2.181", profile="unifi_switch"))

    def test_kinds_thresholds_and_template_scope(self):
        mk = lambda **kw: customoids.add(customoids.parse(dict({"scope": "device", "target": str(self.dev["id"])}, **kw),
                                                          ["unifi_switch"], [self.dev["id"]]))
        temp = mk(oid="1.3.6.1.4.1.99.1.0", label="Temp", unit="C", kind="gauge", scale=0.1,
                  alert_op="above", alert_value=60, alert_severity="high")
        octets = mk(oid="1.3.6.1.4.1.99.2.0", label="Octets", kind="counter")
        up = mk(oid="1.3.6.1.4.1.99.3.0", label="Up", kind="timeticks")
        name = mk(oid="1.3.6.1.4.1.99.4.0", label="Model", kind="string")
        tpl = customoids.add(customoids.parse({"scope": "template", "target": "unifi_switch", "oid": "1.3.6.1.4.1.99.5.0",
                                               "label": "Fan", "kind": "gauge"}, ["unifi_switch"], [self.dev["id"]]))
        answers = {"1.3.6.1.4.1.99.1.0": 655, "1.3.6.1.4.1.99.2.0": 1000, "1.3.6.1.4.1.99.3.0": 12345,
                   "1.3.6.1.4.1.99.4.0": "USW-Flex", "1.3.6.1.4.1.99.5.0": 4200}
        with mock.patch.object(customoids.poller, "snmp_get_many", return_value=answers):
            first = customoids.poll(self.dev, now=1000.0)
            answers["1.3.6.1.4.1.99.2.0"] = 6000
            second = customoids.poll(self.dev, now=1010.0)
        self.assertEqual(first[f"custom.{temp}"], 65.5)
        self.assertNotIn(f"custom.{octets}", first)                 # a rate needs two polls
        self.assertEqual(second[f"custom.{octets}"], 500.0)         # 5000 octets in 10 s
        self.assertEqual(first[f"custom.{up}"], 123.45)
        self.assertEqual(first[f"custom.{tpl}"], 4200.0)            # the template's definition applies too
        texts = database.get_device_table(self.dev["id"], "custom")
        self.assertEqual(texts[str(name)]["value"], "USW-Flex")
        info = customoids.metric_info(self.dev)
        self.assertEqual(info[f"custom.{temp}"]["label"], "Temp (C)")
        self.assertNotIn(f"custom.{name}", info)                    # text has no graph
        probs = server.custom_oid_problems(self.dev)
        self.assertEqual([(p["key"], p["severity"]) for p in probs], [(f"custom:{temp}", "high")])
        self.assertIn("Temp is 65.5 C", probs[0]["message"])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("coid-api", "192.0.2.182", profile="generic_device")

    def test_add_list_delete_and_walk(self):
        status, body, _ = request("POST", "/api/custom-oids", {"scope": "device", "target": str(self.dev), "oid": "1.3.6.1.4.1.5.1.0",
                                                               "label": "Load", "kind": "gauge"})
        self.assertEqual(status, 201, body)
        def_id = body["id"]
        self.assertEqual(request("POST", "/api/custom-oids", {"scope": "device", "target": str(self.dev), "oid": "bad", "label": "x"})[0], 400)
        listed = request("GET", f"/api/custom-oids?device={self.dev}")[1]
        self.assertEqual([d["label"] for d in listed["definitions"]], ["Load"])
        self.assertEqual(listed["enterprise"], "1.3.6.1.4.1")
        with mock.patch.object(customoids.poller, "snmp_walk", return_value={"1.0": 42, "2.0": "text"}):
            walk = request("GET", f"/api/devices/{self.dev}/snmp-walk?oid=1.3.6.1.4.1.5")[1]
        self.assertEqual(walk["rows"], [{"oid": "1.3.6.1.4.1.5.1.0", "type": "number", "value": 42},
                                        {"oid": "1.3.6.1.4.1.5.2.0", "type": "text", "value": "text"}])
        self.assertEqual(request("GET", f"/api/devices/{self.dev}/snmp-walk?oid=nope")[0], 400)
        self.assertEqual(request("DELETE", f"/api/custom-oids/{def_id}")[0], 200)
        self.assertEqual(request("DELETE", f"/api/custom-oids/{def_id}")[0], 404)

    def test_enterprise_root(self):
        self.assertEqual(customoids.enterprise_root({"inventory": {"sys_object_id": ".1.3.6.1.4.1.41112.1.6"}}), "1.3.6.1.4.1.41112")
        self.assertEqual(customoids.enterprise_root({"inventory": {}}), "1.3.6.1.4.1")


if __name__ == "__main__":
    unittest.main()
