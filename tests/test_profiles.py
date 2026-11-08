"""Vendor profiles: identification, profile-defined tables and profile alerts.

The sample values follow each vendor's published MIB; they are not captures
from real hardware.
"""

import json
import unittest

from tests import _env  # noqa: F401
from tests.helpers import add_device, start_api_server

import database
import poller as p
import server


def profile(pid):
    return next(x for x in p.load_hardware_profiles() if x["profile_id"] == pid)


class IdentifyTests(unittest.TestCase):
    def setUp(self):
        self.profiles = p.load_hardware_profiles()

    def match(self, descr, objid, present=()):
        m = p.match_profile(self.profiles, descr, objid, "", set(present))
        return m["profile_id"] if m else None

    def test_vendor_oid_beats_plain_linux(self):
        linux = ("Linux nas 4.4.302+ #72806 SMP x86_64", "1.3.6.1.4.1.8072.3.2.10")
        self.assertEqual(self.match(*linux), "linux_host")
        self.assertEqual(self.match(*linux, present=["1.3.6.1.4.1.6574.1.1.0"]), "synology_dsm")
        self.assertEqual(self.match(*linux, present=["1.3.6.1.4.1.50536.1.1.1.2.1"]), "truenas")

    def test_ups_and_printers(self):
        self.assertEqual(self.match("APC Web/SNMP Management Card", "1.3.6.1.4.1.318.1.3.27",
                                    ["1.3.6.1.4.1.318.1.1.1.1.1.1.0", "1.3.6.1.2.1.33.1.2.1.0"]), "apc_ups")
        self.assertEqual(self.match("Network Management Card", "1.3.6.1.4.1.534.1",
                                    ["1.3.6.1.2.1.33.1.2.1.0"]), "ups_standard")
        self.assertEqual(self.match("Brother NC-8300w", "1.3.6.1.4.1.2435.2.3.9.1",
                                    ["1.3.6.1.2.1.43.5.1.1.16.1"]), "printer")

    def test_network_vendors(self):
        self.assertEqual(self.match("RouterOS RB5009UG+S+", "1.3.6.1.4.1.14988.1"), "mikrotik")
        self.assertEqual(self.match("pfSense fw.home 2.7.2-RELEASE FreeBSD 14.0", "1.3.6.1.4.1.12325.1.1.2.1.1"), "bsd_firewall")
        self.assertEqual(self.match("JetStream 24-Port Gigabit Smart Switch", "1.3.6.1.4.1.11863.1.1.3"), "managed_switch")
        self.assertEqual(self.match("Cisco IOS Software, C2960 Software, Version 15.0(2)SE11", "1.3.6.1.4.1.9.1.1208"), "cisco")
        self.assertEqual(self.match("VMware ESXi 8.0.2 build-22380479 VMware, Inc. x86_64", "1.3.6.1.4.1.6876.4.1"), "vmware_esxi")
        self.assertEqual(self.match("EdgeOS v2.0.9-hotfix.7", "1.3.6.1.4.1.41112.1.5"), "ubiquiti_edgeos")

    def test_probe_oids_are_collected(self):
        oids = p.signature_probe_oids(self.profiles)
        self.assertIn("1.3.6.1.4.1.6574.1.1.0", oids)
        self.assertEqual(len(oids), len(set(oids)))

    def test_every_profile_is_well_formed(self):
        tables = {"disks", "volumes", "health"}
        for prof in self.profiles:
            keys = {m["key"] for m in prof["metrics"]}
            self.assertEqual(len(keys), len(prof["metrics"]), prof["profile_id"])
            for a in prof.get("alerts", []):
                self.assertIn(a["key"], keys, (prof["profile_id"], a))
            for t in prof.get("table_defs", []):
                self.assertIn(t["table"], tables, prof["profile_id"])
            json.dumps(prof)


class DefinedTableTests(unittest.TestCase):
    def test_synology_disks_and_raid(self):
        disks, raid = profile("synology_dsm")["table_defs"]
        rows, metrics = p.build_defined_rows(disks, {2: {"1": "Disk 1", "2": "Disk 2"}, 3: {"1": "WD40EFRX", "2": "ST4000"},
                                                     5: {"1": 1, "2": 5}, 6: {"1": 38, "2": 41}, 13: {"1": 1}})
        self.assertTrue(rows["1"]["ok"])
        self.assertEqual((rows["2"]["smart"], rows["2"]["ok"], rows["2"]["severity"]), ("Crashed", False, "critical"))
        self.assertEqual(metrics, {"disk.1.temp_c": 38.0, "disk.2.temp_c": 41.0})
        rows, metrics = p.build_defined_rows(raid, {2: {"1": "Volume 1"}, 3: {"1": 11}, 4: {"1": 250}, 5: {"1": 1000}})
        self.assertEqual((rows["1"]["status"], rows["1"]["used_bytes"], rows["1"]["used_pct"], rows["1"]["ok"]),
                         ("Degraded", 750, 75.0, False))
        self.assertEqual(metrics, {"vol.1.used_pct": 75.0})

    def test_printer_supplies(self):
        spec = profile("printer")["table_defs"][0]
        rows, metrics = p.build_defined_rows(spec, {6: {"1.1": "Black Toner", "1.2": "Drum"}, 8: {"1.1": 3000, "1.2": 100},
                                                    9: {"1.1": 150, "1.2": -3}})
        self.assertEqual((rows["1.1"]["pct"], rows["1.1"]["ok"]), (5.0, False))
        self.assertNotIn("pct", rows["1.2"])       # -3 means "some remaining": shown, not alarmed
        self.assertNotIn("ok", rows["1.2"])
        self.assertEqual(metrics, {"supply.1.1.pct": 5.0})

    def test_unknown_state_is_shown_not_alarmed(self):
        spec = profile("dell_idrac")["table_defs"][0]
        rows, _ = p.build_defined_rows(spec, {8: {"1": "CPU1 Temp", "2": "Inlet"}, 5: {"1": 3, "2": 99}, 6: {"1": 452, "2": 210}})
        self.assertEqual((rows["temp.1"]["value"], rows["temp.1"]["ok"]), (45.2, True))
        self.assertEqual((rows["temp.2"]["status"], rows["temp.2"]["ok"]), ("state 99", True))


class AlertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("ups-dev", "192.0.2.77")

    def problems(self, m, tables=None):
        d = dict(database.get_device(self.dev), status="online", snmp_status="ok")
        return {x["key"]: x for x in server.device_problems(d, m, tables or {"interfaces": {"1": {}}}, None, None, profile("ups_standard"))}

    def test_ups_alerts(self):
        probs = self.problems({"ups_output_source": 5, "ups_charge_pct": 42, "ups_load_pct": 30, "ups_battery_status": 2})
        self.assertEqual(probs["alert:ups_output_source.1"]["message"], "UPS running on battery")
        self.assertEqual(probs["alert:ups_output_source.1"]["severity"], "critical")
        self.assertEqual(probs["alert:ups_charge_pct"]["message"], "UPS battery at 42%")
        self.assertNotIn("alert:ups_load_pct", probs)
        probs = self.problems({"ups_output_source": 3, "ups_battery_status": 3})
        self.assertEqual(probs["alert:ups_battery_status"]["message"], "UPS battery Low")
        self.assertFalse(any(k.startswith("alert:ups_output_source") for k in probs))

    def test_health_rows_raise_problems(self):
        probs = self.problems({}, {"interfaces": {"1": {}}, "health": {
            "psu.1": {"name": "PS1 Status", "kind": "power supply", "status": "Critical", "ok": False, "severity": "critical"},
            "1.1": {"name": "Black Toner", "kind": "supply", "pct": 5.0, "ok": False, "severity": "warning"},
            "fan.1": {"name": "Fan 1", "kind": "fan", "status": "OK", "ok": True}}})
        self.assertEqual(probs["health:psu.1"]["message"], "Power supply PS1 Status: Critical")
        self.assertEqual(probs["health:1.1"]["message"], "Supply Black Toner: 5%")
        self.assertNotIn("health:fan.1", probs)


class MemoryTests(unittest.TestCase):
    def test_byte_and_percent_memory(self):
        self.assertAlmostEqual(p.memory_used_pct({"mem_used_bytes": 300, "mem_free_bytes": 700}), 30.0)
        self.assertAlmostEqual(p.memory_used_pct({"mem_total_bytes": 1000, "mem_free_bytes": 250}), 75.0)
        self.assertAlmostEqual(p.memory_used_pct({"mem_used_pct": 41.0}), 41.0)


if __name__ == "__main__":
    unittest.main()
