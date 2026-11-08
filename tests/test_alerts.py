"""Alert rules: override inheritance, the trigger set under overrides, waits, Telegram choices, the API and migration."""

import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, start_api_server

import alerts
import database
import poller
import server


def policy(*overrides):
    rows = [{"scope": s, "target": t, "rule_id": r, "field": f, "value": alerts.encode(f, v)} for s, t, r, f, v in overrides]
    return alerts.Policy(alerts.catalogue(poller.load_hardware_profiles()), rows)


class PolicyTests(unittest.TestCase):
    def test_inheritance_and_sources(self):
        p = policy(("global", "", "cpu", "threshold", 95.0), ("template", "qnap_nas", "cpu", "severity", "high"),
                   ("device", "7", "cpu", "threshold", 99.0), ("device", "7", "cpu", "for_minutes", 30))
        values, source = p.resolve("cpu", "qnap_nas", 7)
        self.assertEqual((values["threshold"], values["severity"], values["for_minutes"], values["telegram"]), (99.0, "high", 30, "default"))
        self.assertEqual((source["threshold"], source["severity"], source["telegram"]), ("device", "template", "default"))
        # Another NAS gets the template severity and the global threshold.
        values, _ = p.resolve("cpu", "qnap_nas", 8)
        self.assertEqual((values["threshold"], values["severity"]), (95.0, "high"))
        # A switch gets only the global change.
        values, _ = p.resolve("cpu", "unifi_switch", 9)
        self.assertEqual((values["threshold"], values["severity"]), (95.0, "warning"))
        # What the device would inherit without its own override.
        self.assertEqual(p.resolve("cpu", "qnap_nas", 7, upto="template")[0]["threshold"], 95.0)
        self.assertEqual(p.resolve("cpu", "qnap_nas", 7, upto="default")[0]["threshold"], 90)

    def test_profile_rules_have_unique_ids(self):
        rules = alerts.profile_rules(next(x for x in poller.load_hardware_profiles() if x["profile_id"] == "ups_standard"))
        ids = [r["id"] for r in rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("p:ups_standard:ups_output_source.1", ids)
        self.assertEqual(alerts.rule_id_for_key("alert:ups_charge_pct", "ups_standard"), "p:ups_standard:ups_charge_pct")
        self.assertEqual(alerts.rule_id_for_key("storage:31", "linux_host"), "disk_full")
        self.assertEqual(alerts.rule_id_for_key("watch:process:sshd", "linux_host"), "watch")

    def test_validation(self):
        cpu = alerts.catalogue([])["cpu"]
        unreachable = alerts.catalogue([])["unreachable"]
        self.assertEqual(alerts.parse_value(cpu, "threshold", 97), 97.0)
        for field, value in (("threshold", 101), ("threshold", "90"), ("threshold", True), ("severity", "urgent"),
                             ("for_minutes", -1), ("for_minutes", 2.5), ("telegram", "sometimes"), ("enabled", "yes"),
                             ("resolved", "maybe"), ("colour", "red")):
            with self.assertRaises(ValueError, msg=(field, value)):
                alerts.parse_value(cpu, field, value)
        with self.assertRaises(ValueError):
            alerts.parse_value(unreachable, "threshold", 5)
        self.assertEqual(alerts.parse_value(alerts.catalogue([])["health"], "severity", ""), "")
        with self.assertRaises(ValueError):
            alerts.parse_value(cpu, "severity", "")       # "as reported" only exists for component faults

    def test_should_send(self):
        self.assertTrue(alerts.should_send({"telegram": "default"}, "high", "warning"))
        self.assertFalse(alerts.should_send({"telegram": "default"}, "warning", "critical"))
        self.assertTrue(alerts.should_send({"telegram": "always"}, "info", "critical"))
        self.assertFalse(alerts.should_send({"telegram": "never"}, "critical", "info"))


class TriggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("alerts-dev", "192.0.2.131", profile="qnap_nas")

    def problems(self, p, m=None, tables=None, device=None):
        d = dict(database.get_device(self.dev), status="online", snmp_status="ok")
        d.update(device or {})
        return {x["key"]: x for x in server.device_problems(d, m or {}, tables or {"interfaces": {"1": {}}}, p.for_device(d))}

    def test_threshold_severity_and_off(self):
        m = {"cpu_usage_pct": 95.0, "mem_used_pct": 95.0}
        probs = self.problems(policy(), m)
        self.assertEqual((probs["cpu"]["severity"], probs["cpu"]["for_s"]), ("warning", 600))
        probs = self.problems(policy(("template", "qnap_nas", "cpu", "threshold", 98.0)), m)
        self.assertNotIn("cpu", probs)
        probs = self.problems(policy(("device", str(self.dev), "cpu", "severity", "high"), ("global", "", "mem", "enabled", False)), m)
        self.assertEqual(probs["cpu"]["severity"], "high")
        self.assertNotIn("mem", probs)
        self.assertIn("threshold 90%", probs["cpu"]["message"])

    def test_component_severity_as_reported_or_overridden(self):
        tables = {"interfaces": {"1": {}}, "health": {"fan.1": {"name": "Fan 1", "kind": "fan", "status": "Failed", "ok": False, "severity": "critical"}}}
        self.assertEqual(self.problems(policy(), tables=tables)["health:fan.1"]["severity"], "critical")
        self.assertEqual(self.problems(policy(("global", "", "health", "severity", "info")), tables=tables)["health:fan.1"]["severity"], "info")

    def test_unreachable_waits_only_when_asked(self):
        self.assertEqual(self.problems(policy(), device={"status": "offline"})["unreachable"]["for_s"], 0)
        p = policy(("device", str(self.dev), "unreachable", "for_minutes", 3))
        self.assertEqual(self.problems(p, device={"status": "offline"})["unreachable"]["for_s"], 180)

    def test_port_error_threshold(self):
        tables = {"interfaces": {"3": {"kind": "port", "label": "eth0", "in_errors_delta": 4}}}
        self.assertIn("port_errors:3", self.problems(policy(), tables=tables))
        self.assertNotIn("port_errors:3", self.problems(policy(("global", "", "port_errors", "threshold", 10.0)), tables=tables))


class WaitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("wait-dev", "192.0.2.132")

    def problem(self, key, wait):
        return {"device_id": self.dev, "hostname": "wait-dev", "key": key, "severity": "warning", "message": key, "for_s": wait}

    def listed(self):
        return {p["problem_key"] for p in database.list_active_problems() if p["device_id"] == self.dev}

    def test_pending_until_the_wait_passes(self):
        t = 1_000_000
        res = database.sync_problems([self.problem("cpu", 600)], lambda k: 0, now=t)
        self.assertEqual((res["opened"], self.listed()), ([], set()))
        res = database.sync_problems([self.problem("cpu", 600)], lambda k: 0, now=t + 300)
        self.assertEqual(res["opened"], [])
        res = database.sync_problems([self.problem("cpu", 600)], lambda k: 0, now=t + 600)
        self.assertEqual([p["key"] for p in res["opened"]], ["cpu"])
        self.assertEqual(self.listed(), {"cpu"})
        res = database.sync_problems([], lambda k: 0, now=t + 660)
        self.assertEqual([p["problem_key"] for p in res["resolved"]], ["cpu"])

    def test_pending_condition_that_clears_opens_nothing(self):
        t = 2_000_000
        database.sync_problems([self.problem("mem", 600)], lambda k: 0, now=t)
        res = database.sync_problems([], lambda k: 0, now=t + 120)
        self.assertEqual((res["opened"], res["resolved"]), ([], []))
        # Starting again restarts the wait.
        database.sync_problems([self.problem("mem", 600)], lambda k: 0, now=t + 180)
        self.assertEqual(database.sync_problems([self.problem("mem", 600)], lambda k: 0, now=t + 600)["opened"], [])
        self.assertTrue(database.acknowledge_problem(self.dev, "mem", True) is None)    # pending: not acknowledgeable
        database.sync_problems([], lambda k: 0, now=t + 700)


class NotifyDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("notify-rule-dev", "192.0.2.133")

    def setUp(self):
        database.set_alert_overrides("device", str(self.dev), [("unreachable", f, None) for f in alerts.FIELDS])
        with database.get_connection() as c:
            c.execute("DELETE FROM problems_active WHERE device_id = ?", (self.dev,))
            c.execute("UPDATE devices SET status = 'offline' WHERE id = ?", (self.dev,))
            c.commit()

    def tearDown(self):
        with database.get_connection() as c:
            c.execute("UPDATE devices SET status = 'unknown' WHERE id = ?", (self.dev,))
            c.commit()

    def run_job(self, **settings):
        sent = []
        # notify_new_devices on: this device was just added and would otherwise be in its quiet period.
        base = {"telegram_enabled": "on", "notify_min_severity": "warning", "notify_repeat_hours": "0", "notify_new_devices": "on"}
        with mock.patch.object(server.NOTIFIER, "event", side_effect=lambda kind, values, critical=False, **kw: sent.append((kind, values))), \
                mock.patch.object(database, "get_all_settings", return_value=dict(base, **settings)):
            # The job's own state is not needed: an instance without __init__ runs it and its reminder step.
            server.PollScheduler.__new__(server.PollScheduler)._problem_job(0)
        return [(k, v.get("device")) for k, v in sent if v.get("device") == "notify-rule-dev"]

    def test_minimum_severity_and_rule_override(self):
        self.assertEqual(self.run_job(), [("device_offline", "notify-rule-dev")])
        with database.get_connection() as c:
            c.execute("DELETE FROM problems_active WHERE device_id = ?", (self.dev,))
            c.commit()
        self.assertEqual(self.run_job(notify_min_severity="critical"), [("device_offline", "notify-rule-dev")])
        with database.get_connection() as c:
            c.execute("DELETE FROM problems_active WHERE device_id = ?", (self.dev,))
            c.commit()
        database.set_alert_overrides("device", str(self.dev), [("unreachable", "telegram", "never")])
        self.assertEqual(self.run_job(), [])

    def test_reminder_for_unacknowledged_problem(self):
        self.run_job()
        with database.get_connection() as c:
            c.execute("UPDATE problems_active SET raised_at = ?, since = ? WHERE device_id = ?",
                      (int(time.time()) - 7300, int(time.time()) - 7300, self.dev))
            c.commit()
        self.assertEqual(self.run_job(notify_repeat_hours="2", notify_repeat_severity="critical"),
                         [("reminder", "notify-rule-dev")])
        self.assertEqual(self.run_job(notify_repeat_hours="2", notify_repeat_severity="critical"), [])     # just reminded
        database.acknowledge_problem(self.dev, "unreachable", True)
        with database.get_connection() as c:
            c.execute("UPDATE problems_active SET last_notified = 0 WHERE device_id = ?", (self.dev,))
            c.commit()
        self.assertEqual(self.run_job(notify_repeat_hours="2"), [])      # acknowledged: no reminder


class ShutdownSettleTests(unittest.TestCase):
    """A device shutting down: SNMP stops a moment before ping. Only "offline" should reach Telegram."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("settle-dev", "192.0.2.247")
        cls.started = int(time.time())

    def setUp(self):
        server.PENDING_SETTLE.clear()
        with database.get_connection() as c:
            c.execute("DELETE FROM problems_active WHERE device_id = ?", (self.dev,))
            c.commit()

    def tearDown(self):
        self.setUp()

    @classmethod
    def tearDownClass(cls):
        # Its events (written at the pretend future times too) would crowd other tests' notification bell.
        with database.get_connection() as c:
            c.execute("DELETE FROM events WHERE device_id = ? OR timestamp >= ?", (cls.dev, cls.started))
            c.commit()

    def problem(self, key, message):
        return {"device_id": self.dev, "hostname": "settle-dev", "key": key, "rule": key, "severity": "warning",
                "message": message, "for_s": 0, "telegram": "always", "sound": "default"}

    def run_at(self, t, problems):
        sent = []
        base = {"telegram_enabled": "on", "notify_min_severity": "warning", "notify_repeat_hours": "0", "notify_new_devices": "on"}
        with mock.patch.object(server.NOTIFIER, "event", side_effect=lambda kind, values, critical=False, **kw: sent.append((kind, values.get("problem"), values.get("device")))), \
                mock.patch.object(database, "get_all_settings", return_value=base), \
                mock.patch.object(server, "evaluate_problems", return_value=problems), \
                mock.patch.object(server.time, "time", return_value=t):
            server.PollScheduler.__new__(server.PollScheduler)._problem_job(0)
        return [(k, m) for k, m, d in sent if d == "settle-dev"]

    def test_shutdown_sends_only_offline(self):
        t = 1_800_000_000
        snmp = self.problem("snmp", "SNMP agent not responding (host answers ping)")
        down = self.problem("unreachable", "Device unreachable (no ICMP reply)")
        self.assertEqual(self.run_at(t, [snmp]), [])                                   # held
        self.assertEqual(self.run_at(t + 20, [down]), [("device_offline", "Device unreachable (no ICMP reply)")])
        self.assertEqual(server.PENDING_SETTLE, {})
        self.assertEqual(self.run_at(t + 200, [down]), [])
        # Back up: one "online", no SNMP "resolved" for a warning that was never sent.
        self.assertEqual([k for k, _ in self.run_at(t + 400, [])], ["device_online"])

    def test_snmp_alone_is_sent_after_the_wait(self):
        t = 1_800_001_000
        snmp = self.problem("snmp", "SNMP agent not responding (host answers ping)")
        self.assertEqual(self.run_at(t, [snmp]), [])
        self.assertEqual(self.run_at(t + 60, [snmp]), [])                              # 60 s ping + 30 s
        self.assertEqual(self.run_at(t + 95, [snmp]), [("problem", snmp["message"])])
        self.assertNotIn("problem", [k for k, _ in self.run_at(t + 300, [])])      # sent once only

    def test_offline_found_after_the_snmp_warning_still_drops_it(self):
        # Ping fails later but SNMP stays listed (a service check, say): the held warning is dropped, and its resolve too.
        t = 1_800_002_000
        svc = self.problem("service_down", "Web page not answering")
        down = self.problem("unreachable", "Device unreachable (no ICMP reply)")
        self.assertEqual(self.run_at(t, [svc]), [])
        self.assertEqual([k for k, _ in self.run_at(t + 30, [svc, down])], ["device_offline"])
        self.assertEqual(server.PENDING_SETTLE, {})
        self.assertEqual([k for k, _ in self.run_at(t + 300, [])], ["device_online"])

    def test_guest_stopped_on_an_offline_device_is_covered(self):
        # Proxmox reports the stopped guest a minute after ping failed: the offline message covers it.
        t = 1_800_003_000
        down = self.problem("unreachable", "Device unreachable (no ICMP reply)")
        guest = dict(self.problem("pve_guest_down:pve/200", "Guest media-server (200) is stopped, although it starts at boot"),
                     rule="pve_guest_down")
        self.assertEqual([k for k, _ in self.run_at(t, [down])], ["device_offline"])
        self.assertEqual(self.run_at(t + 60, [down, guest]), [])
        self.assertEqual([k for k, _ in self.run_at(t + 300, [])], ["device_online"])
        self.assertEqual([k for k, _ in self.run_at(t + 3600, [])], [])            # its resolve stays quiet too


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("rules-api-dev", "192.0.2.134", profile="qnap_nas")

    def rule(self, body, rule_id):
        return next(r for r in body["rules"] if r["id"] == rule_id)

    def test_get_put_and_inherit(self):
        status, body, _ = request("GET", "/api/alert-rules?scope=global")
        self.assertEqual(status, 200)
        self.assertEqual(self.rule(body, "cpu")["effective"]["threshold"], 90)
        self.assertIn("high", body["severities"])
        change = {"scope": "template", "target": "qnap_nas", "changes": [{"rule_id": "cpu", "field": "threshold", "value": 97}]}
        status, body, _ = request("PUT", "/api/alert-rules", change)
        self.assertEqual((status, self.rule(body, "cpu")["here"]), (200, {"threshold": 97.0}))
        _, body, _ = request("GET", f"/api/alert-rules?scope=device&target={self.dev}")
        cpu = self.rule(body, "cpu")
        self.assertEqual((cpu["effective"]["threshold"], cpu["source"]["threshold"], cpu["inherited"]["threshold"]), (97.0, "template", 97.0))
        reset = {"scope": "template", "target": "qnap_nas", "changes": [{"rule_id": "cpu", "field": "threshold", "value": None}]}
        _, body, _ = request("PUT", "/api/alert-rules", reset)
        self.assertEqual(self.rule(body, "cpu")["here"], {})

    def test_rejects_bad_changes(self):
        bad = [
            {"scope": "global", "target": "", "changes": [{"rule_id": "cpu", "field": "severity", "value": "urgent"}]},
            {"scope": "global", "target": "", "changes": [{"rule_id": "cpu", "field": "threshold", "value": 500}]},
            {"scope": "global", "target": "", "changes": [{"rule_id": "nope", "field": "enabled", "value": False}]},
            {"scope": "template", "target": "qnap_nas", "changes": [{"rule_id": "p:apc_ups:ups_charge_pct", "field": "enabled", "value": False}]},
            {"scope": "device", "target": "999999", "changes": [{"rule_id": "cpu", "field": "enabled", "value": False}]},
            {"scope": "planet", "target": "", "changes": [{"rule_id": "cpu", "field": "enabled", "value": False}]},
            {"scope": "global", "target": "", "changes": []},
        ]
        for b in bad:
            self.assertIn(request("PUT", "/api/alert-rules", b)[0], (400, 404), b)

    def test_device_overrides_removed_with_the_device(self):
        dev = add_device("rules-gone", "192.0.2.135")
        request("PUT", "/api/alert-rules", {"scope": "device", "target": str(dev), "changes": [{"rule_id": "cpu", "field": "enabled", "value": False}]})
        self.assertTrue(any(o["target"] == str(dev) for o in database.list_alert_overrides()))
        request("DELETE", f"/api/devices/{dev}")
        self.assertFalse(any(o["scope"] == "device" and o["target"] == str(dev) for o in database.list_alert_overrides()))


class MigrationTests(unittest.TestCase):
    def test_old_thresholds_become_global_overrides(self):
        start_api_server()
        database.ensure_settings([("threshold_cpu_pct", "90", ""), ("notify_on_watch", "on", "")])
        database.update_setting("threshold_cpu_pct", "85")
        database.update_setting("notify_on_watch", "off")
        server.migrate_alert_settings(database.get_all_settings())
        overrides = {(o["rule_id"], o["field"]): o["value"] for o in database.list_alert_overrides() if o["scope"] == "global"}
        self.assertEqual(overrides[("cpu", "threshold")], "85.0")
        self.assertEqual(overrides[("watch", "telegram")], "never")
        self.assertNotIn("threshold_cpu_pct", database.get_all_settings())
        database.set_alert_overrides("global", "", [("cpu", "threshold", None), ("watch", "telegram", None)])


class CounterResetTests(unittest.TestCase):
    def test_error_counter_reset_is_not_a_wrap(self):
        self.assertIsNone(poller.counter_delta(0, 1, wraps=False))
        self.assertEqual(poller.counter_delta(0, 1), 2 ** 32 - 1)        # octet counters still wrap
        self.assertEqual(poller.counter_delta(5, 2, wraps=False), 3)


if __name__ == "__main__":
    unittest.main()
