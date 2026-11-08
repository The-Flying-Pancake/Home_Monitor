"""SNMP BER codec, value parsing, profile matching, interface classification, counters, cron."""

import unittest
from datetime import datetime

from tests import _env  # noqa: F401

import poller as p
import ssh_runner


class BerTests(unittest.TestCase):
    def test_oid_roundtrip(self):
        for oid in ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.41112.1.6.1.2.1.8.1", "2.999.3", "1.3.6.1.4.1.24681.1.2.1.0"]:
            self.assertEqual(p._decode_oid(p._encode_oid(oid)[2:]), oid)

    def test_minimal_integers(self):
        self.assertEqual(p._encode_integer(-1), b"\x02\x01\xff")
        self.assertEqual(p._encode_integer(-128), b"\x02\x01\x80")
        self.assertEqual(p._encode_integer(128), b"\x02\x02\x00\x80")
        for v in (0, 1, 127, 255, 256, -129, 2 ** 31 - 1):
            _, raw, _ = p._decode_tlv(p._encode_integer(v))
            self.assertEqual(int.from_bytes(raw, "big", signed=True), v)

    def test_truncated_input_rejected(self):
        for bad in (b"\x04\x05ab", b"\x30", b"\x04\x84\x00"):
            with self.assertRaises(ValueError):
                p._decode_tlv(bad)

    def test_response_parse_and_exceptions(self):
        # GetResponse with sysName = "lab" and a noSuchObject varbind.
        vb1 = p._tlv(0x30, p._encode_oid("1.3.6.1.2.1.1.5.0") + p._tlv(0x04, b"lab"))
        vb2 = p._tlv(0x30, p._encode_oid("1.3.6.1.2.1.1.9.0") + b"\x80\x00")
        pdu = p._tlv(0xA2, p._encode_integer(42) + p._encode_integer(0) + p._encode_integer(0) + p._tlv(0x30, vb1 + vb2))
        msg = p._tlv(0x30, p._encode_integer(1) + p._tlv(0x04, b"c") + pdu)
        rid, err, vbs = p.parse_snmp_response(msg)
        self.assertEqual((rid, err), (42, 0))
        self.assertEqual(vbs[0], ("1.3.6.1.2.1.1.5.0", "lab"))
        self.assertIs(vbs[1][1], p.NO_SUCH_OBJECT)
        self.assertFalse(p.has_value(vbs[1][1]))

    def test_binary_octet_string_as_mac(self):
        self.assertEqual(p._decode_octet_string(bytes.fromhex("fcecdaf7f634")), "fc:ec:da:f7:f6:34")


class ParsingTests(unittest.TestCase):
    def test_typed_values(self):
        cases = [("12 %", "string_pct", 12.0), ("45 C/113 F", "string_temp", 45.0), ("1.9 GB", "string_mb", 1945.6),
                 ("512 MB", "string_mb", 512.0), ("1200 RPM", "string_int", 1200.0), (12345, "timeticks", 123.45),
                 ("0.06", "string_float", 0.06), (7, "integer", 7.0)]
        for raw, t, want in cases:
            self.assertAlmostEqual(p.parse_metric_value(raw, t), want, places=2)
        self.assertIsNone(p.parse_metric_value("n/a", "string_pct"))
        self.assertIsNone(p.parse_metric_value(p.NO_SUCH_INSTANCE, "integer"))

    def test_derived_metrics(self):
        d = p.derive_metrics({"mem_total_kb": 1000, "mem_avail_kb": 200, "mem_buffer_kb": 100, "mem_cached_kb": 200, "cpu_idle_pct": 88})
        self.assertAlmostEqual(d["mem_used_pct"], 50.0)
        self.assertEqual(d["cpu_usage_pct"], 12.0)
        self.assertAlmostEqual(p.derive_metrics({"mem_total_mb": 1000, "mem_free_mb": 640})["mem_used_pct"], 36.0)
        self.assertAlmostEqual(p.derive_metrics({"mem_hr_size_units": 200, "mem_hr_used_units": 50})["mem_used_pct"], 25.0)

    def test_counter_wrap_and_reset(self):
        self.assertEqual(p.counter_delta(10, 2 ** 32 - 10), 20)  # 32-bit wrap
        self.assertIsNone(p.counter_delta(5, 2 ** 40))           # 64-bit decrease = reset
        self.assertIsNone(p._rate_bps(10 ** 12, 0, 1, ceiling_bps=1e9))  # above link speed


class ProfileTests(unittest.TestCase):
    """sysDescr / sysObjectID / sysName values observed on real UniFi, QNAP and Proxmox hardware."""

    def setUp(self):
        self.profiles = p.load_hardware_profiles()

    def match(self, descr, objid, name=""):
        m = p.match_profile(self.profiles, descr, objid, name)
        return m["profile_id"] if m else None

    def test_real_devices(self):
        self.assertEqual(self.match("Ubiquiti UniFi UCG-Ultra 5.1.33 Linux 5.4.213 ipq5322", "1.3.6.1.4.1.8072.3.2.10"), "unifi_gateway")
        self.assertEqual(self.match("Linux UBNT 3.18.24 #0 Thu Aug 30 12:10:54 2018 mips", "1.3.6.1.4.1.8072.3.2.10", "USW-LITE-8-POE"), "unifi_switch")
        self.assertEqual(self.match("UAP-nanoHD 6.7.57.15670", "1.3.6.1.4.1.41112"), "unifi_ap")
        self.assertEqual(self.match("Linux TS-X41 5.2.11.3661", "1.3.6.1.4.1.55062"), "qnap_nas")
        self.assertEqual(self.match("Linux pve 7.0.14-26-pve #1 SMP", "1.3.6.1.4.1.8072.3.2.10"), "linux_host")
        self.assertEqual(self.match("Hardware: Intel64 Software: Windows Version 10.0", "1.3.6.1.4.1.311.1.1.3.1.1"), "windows_host")

    def test_every_profile_is_well_formed(self):
        modes = {"raw", "change", "hourly", "none"}
        for prof in self.profiles:
            for m in prof["metrics"]:
                self.assertIn(m.get("history", "raw"), modes, (prof["profile_id"], m["key"]))
                self.assertTrue(m.get("oid") or m.get("walk") or m.get("if_name"), (prof["profile_id"], m["key"]))


class ClassifierTests(unittest.TestCase):
    def test_interface_kinds(self):
        cases = {"eth0": "port", "0/24": "port", "enp1s0": "port", "switch0.20": "vlan", "br0": "bridge",
                 "vmbr0": "bridge", "wifi1": "radio", "wifi0ap3": "ssid", "ra0": "ssid", "rai4": "ssid",
                 "apcli0": "virtual", "wdsi1": "virtual", "lo": "virtual", "tap100i0": "guest",
                 "veth205i0": "guest", "fwbr205i0": "virtual", "ip6_vti0": "virtual"}
        for label, kind in cases.items():
            self.assertEqual(p.classify_interface(label, 6), kind, label)


class HostTableTests(unittest.TestCase):
    def test_physical_disk_filter_and_slug(self):
        keep = ["sda", "nvme0n1", "vdb", "mmcblk0"]
        drop = ["sda1", "nvme0n1p2", "loop0", "dm-3", "zd16"]
        self.assertTrue(all(p.PHYSICAL_DISK.fullmatch(n) for n in keep))
        self.assertFalse(any(p.PHYSICAL_DISK.fullmatch(n) for n in drop))
        self.assertEqual(p.metric_slug("Sensor 1"), "sensor_1")
        self.assertEqual(p.metric_slug("Tctl"), "tctl")

    def test_software_names(self):
        self.assertEqual(p.split_software("libc6_2.41-12_amd64"), {"name": "libc6", "version": "2.41-12", "arch": "amd64"})
        self.assertEqual(p.split_software("7-Zip 24.08 (x64)")["name"], "7-Zip (x64)")
        self.assertEqual(p.split_software("Microsoft .NET Host FX Resolver - 8.0.33")["version"], "8.0.33")
        self.assertEqual(p.split_software("NordVPN"), {"name": "NordVPN", "version": "", "arch": ""})


class CronTests(unittest.TestCase):
    def test_matching(self):
        cases = [("*/15 * * * *", datetime(2026, 10, 30, 19, 45), True), ("*/15 * * * *", datetime(2026, 10, 30, 19, 46), False),
                 ("0 3 * * 0", datetime(2026, 11, 1, 3, 0), True), ("0 3 * * 7", datetime(2026, 11, 1, 3, 0), True),
                 ("0 9-17 * * 1-5", datetime(2026, 10, 31, 12, 0), False), ("30 2 1 * *", datetime(2026, 11, 1, 2, 30), True)]
        for expr, when, want in cases:
            self.assertEqual(ssh_runner.cron_matches(expr, when), want, expr)

    def test_validation(self):
        for bad in ("* * *", "61 * * * *", "*/0 * * * *", "a * * * *", "5-1 * * * *"):
            with self.assertRaises(ValueError):
                ssh_runner.parse_cron(bad)

    def test_fingerprint_format(self):
        fp = ssh_runner.fingerprint("AAAAC3NzaC1lZDI1NTE5AAAAIEHQoVXsFD8q3azM1yd040KuislcWUT4Nu8ZVcoWbRVX")
        self.assertTrue(fp.startswith("SHA256:") and not fp.endswith("="))


if __name__ == "__main__":
    unittest.main()
