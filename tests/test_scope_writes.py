"""Device access on write routes and in workflow content (REV-02): a user limited to some devices
acts only on those devices; network-wide changes and objects everyone shares need every device."""

import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from tests.helpers import add_device, request, session_cookie, start_api_server

import auth
import database
import maintenance
import rbac
import server
import taxonomy
import workflows

PASSWORD = "scope writes passphrase"
PERMS = ["problems.ack", "devices.manage", "map.edit", "dashboard.edit", "automation.run", "automation.edit",
         "credentials.use", "settings.system"]


def login(name, scope=None):
    body = {"username": name, "password": PASSWORD, "role": "custom", "permissions": PERMS}
    if scope is not None:
        body["device_scope"] = scope
    status, res, _ = request("POST", "/api/users", body)
    assert status == 201, res
    _, _, headers = request("POST", "/api/auth/login", {"username": name, "password": PASSWORD}, session=False)
    return {"Cookie": f"{auth.SESSION_COOKIE}={session_cookie(headers)}"}


class ScopeWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.in1 = add_device("sw-in1", "203.0.113.221")
        cls.in2 = add_device("sw-in2", "203.0.113.222")
        cls.out = add_device("sw-out", "203.0.113.223")
        taxonomy.tag_devices([cls.in1, cls.in2], ["sw-in"], [])
        taxonomy.tag_devices([cls.in1, cls.out], ["sw-mix"], [])
        cls.group = taxonomy.add_group("Scope writes inside")
        database.set_device_overrides(cls.in1, cls.group, None, None, {})
        cls.saved_windows = database.get_all_settings().get(maintenance.KEY) or "[]"
        cls.scoped = login("sw-scoped", {"all": False, "devices": [cls.in1, cls.in2]})
        cls.wide = login("sw-wide")

    @classmethod
    def tearDownClass(cls):
        for name in ("sw-scoped", "sw-wide"):
            database.delete_user(name)
        database.set_internal_setting(maintenance.KEY, cls.saved_windows)
        for dev in (cls.in1, cls.in2, cls.out):
            database.delete_device(dev)

    def setUp(self):
        database.set_internal_setting(maintenance.KEY, self.saved_windows)

    def as_(self, who, method, path, body=None):
        return request(method, path, body, headers=who, session=False)

    def scoped_user(self):
        user = rbac.User(database.get_user("sw-scoped"))
        user.bind_devices(database.device_profiles())
        return user

    # --- Problems -----------------------------------------------------------------------------

    def test_ack_outside_scope_is_404(self):
        now = int(time.time())
        with database.get_connection() as c:
            for dev in (self.in1, self.out):
                c.execute("INSERT OR REPLACE INTO problems_active (device_id, problem_key, severity, message, since, last_seen, "
                          "raised_at) VALUES (?, 'sw-test', 'warning', 'Scope test', ?, ?, ?);", (dev, now, now, now))
            c.commit()
        try:
            body = {"device_id": self.out, "problem_key": "sw-test", "acknowledged": True}
            status, res, _ = self.as_(self.scoped, "POST", "/api/problems/ack", body)
            missing = self.as_(self.scoped, "POST", "/api/problems/ack", dict(body, device_id=self.in1, problem_key="nope"))
            self.assertEqual((status, res), (missing[0], missing[1]))        # the same answer as a missing problem
            self.assertEqual(status, 404)
            acked = {p["device_id"]: p.get("acknowledged") for p in database.list_active_problems() if p["problem_key"] == "sw-test"}
            self.assertFalse(acked[self.out])
            self.assertEqual(self.as_(self.scoped, "POST", "/api/problems/ack", dict(body, device_id=self.in1))[0], 200)
        finally:
            with database.get_connection() as c:
                c.execute("DELETE FROM problems_active WHERE problem_key = 'sw-test';")
                c.execute("DELETE FROM events WHERE device_id IN (?, ?, ?);", (self.in1, self.in2, self.out))
                c.commit()

    # --- Maintenance --------------------------------------------------------------------------

    def window(self, who, scope, target=""):
        return self.as_(who, "POST", "/api/maintenance", {"scope": scope, "target": target, "minutes": 30})

    def test_maintenance_targets(self):
        for scope, target in (("all", ""), ("device", str(self.out)), ("tag", "sw-mix"), ("tag", "sw-nobody-has-this"),
                              ("group", "no-such-group")):
            status, res, _ = self.window(self.scoped, scope, target)
            self.assertEqual(status, 403, (scope, target, res))
            self.assertIn("outside your device access", res["error"])
        for scope, target in (("device", str(self.in1)), ("tag", "sw-in"), ("group", self.group)):
            status, res, _ = self.window(self.scoped, scope, target)
            self.assertEqual(status, 201, (scope, target, res))
        self.assertEqual(self.window(self.wide, "all")[0], 201)

    def test_maintenance_end_outside_is_404(self):
        wid = self.window(self.wide, "device", str(self.out))[1]["window"]["id"]
        status, res, _ = self.as_(self.scoped, "POST", f"/api/maintenance/{wid}/end", {})
        self.assertEqual((status, res["error"]), (404, "No such maintenance window"))
        self.assertEqual(next(w for w in maintenance.windows() if w["id"] == wid)["state"], "active")
        self.assertEqual(self.as_(self.wide, "POST", f"/api/maintenance/{wid}/end", {})[0], 200)

    def test_maintenance_list_is_filtered(self):
        out_id = self.window(self.wide, "device", str(self.out))[1]["window"]["id"]
        all_id = self.window(self.wide, "all")[1]["window"]["id"]
        status, res, _ = self.window(self.scoped, "device", str(self.in1))
        in_id = res["window"]["id"]
        self.assertEqual([w["id"] for w in res["windows"] if w["id"] in (out_id, all_id, in_id)], [in_id])
        listed = self.as_(self.scoped, "GET", "/api/maintenance")[1]
        ids = {w["id"] for w in listed["windows"]}
        self.assertIn(in_id, ids)
        self.assertFalse(ids & {out_id, all_id})
        self.assertNotIn("all", listed["scopes"])
        self.assertIn("all", self.as_(self.wide, "GET", "/api/maintenance")[1]["scopes"])
        ended = self.as_(self.scoped, "POST", f"/api/maintenance/{in_id}/end", {})[1]
        self.assertFalse({w["id"] for w in ended["windows"]} & {out_id, all_id})
        extras = self.as_(self.scoped, "GET", "/api/dashboard/extras?want=maintenance,pihole")[1]
        self.assertFalse({w["id"] for w in extras["maintenance"]["windows"]} & {out_id, all_id})
        self.assertIn("every device", extras["pihole"]["error"])
        wide = self.as_(self.wide, "GET", "/api/dashboard/extras?want=maintenance")[1]
        self.assertTrue({out_id, all_id} <= {w["id"] for w in wide["maintenance"]["windows"]})

    # --- Network-wide routes and shared objects -------------------------------------------------

    ROUTES = [("POST", "/api/pihole/blocking"), ("POST", "/api/wifi/reconnect"), ("POST", "/api/inventory"),
              ("POST", "/api/inventory/known"), ("PUT", "/api/inventory/quiet-ssids"), ("PUT", "/api/inventory/wifi-networks"),
              ("PUT", "/api/inventory/aa:bb:cc:dd:ee:ff"), ("DELETE", "/api/inventory/aa:bb:cc:dd:ee:ff"),
              ("POST", "/api/map/objects"), ("DELETE", "/api/map/objects/999999"), ("POST", "/api/map/links"),
              ("PUT", "/api/map/positions"), ("PUT", "/api/dashboard"), ("POST", "/api/dashboards"),
              ("DELETE", "/api/dashboards/sw-none"), ("PUT", "/api/taxonomy"), ("POST", "/api/backups/passphrase")]

    def test_changed_alerts_lists_everything_and_respects_scope(self):
        """Settings, Notifications, Changed alerts: every change in one list, with links; a user limited to
        some devices sees changes on their devices only and none of the inventory's network-wide rules."""
        import inventory
        now = time.time()
        database.set_alert_overrides("device", str(self.in1), [("unreachable", "for_minutes", "5")])
        database.set_alert_overrides("device", str(self.out), [("unreachable", "telegram", "never")])
        maintenance.add("device", str(self.in2), now - 60, now + 3600, "New disk", "admin", now=now)
        maintenance.add("device", str(self.out), now + 7200, now + 9000, "", "admin", now=now)
        inventory.set_quiet_ssids(["Guest"])
        inventory.set_wifi_net_alerts({"Guest": "off"})
        try:
            status, body, _ = self.as_(self.wide, "GET", "/api/alerts/changed")
            self.assertEqual(status, 200, body)
            dev = {g["name"]: g for g in body["rules"] if g["scope"] == "device"}
            self.assertEqual(dev["sw-in1"]["link"], f"#/settings/alerts/device/{self.in1}")
            self.assertEqual(dev["sw-in1"]["changes"][0]["value"], 5)
            self.assertIn("sw-out", dev)
            states = {w["what"]: w["state"] for w in body["maintenance"]}
            self.assertEqual(states.get("sw-in2"), "active")
            self.assertEqual(states.get("sw-out"), "scheduled")
            self.assertEqual(body["inventory"]["quiet_networks"], ["Guest"])
            self.assertEqual(body["inventory"]["network_wifi"], [{"name": "Guest", "rule": "off"}])
            status, body, _ = self.as_(self.scoped, "GET", "/api/alerts/changed")
            self.assertEqual(status, 200, body)
            names = {g["name"] for g in body["rules"]}
            self.assertIn("sw-in1", names)
            self.assertNotIn("sw-out", names)
            self.assertNotIn("All devices", names)
            self.assertEqual([w["what"] for w in body["maintenance"]], ["sw-in2"])
            self.assertIsNone(body["inventory"])
        finally:
            database.set_alert_overrides("device", str(self.in1), [("unreachable", "for_minutes", None)])
            database.set_alert_overrides("device", str(self.out), [("unreachable", "telegram", None)])
            database.delete_settings([inventory.QUIET_SSIDS_KEY, inventory.WIFI_NET_ALERT_KEY])

    def test_network_wide_routes_refused_when_scoped(self):
        self.assertEqual(len(self.ROUTES), len(rbac.UNSCOPED_ROUTES))
        with mock.patch.object(server.pihole, "set_blocking") as block, mock.patch.object(server.unifi, "reconnect") as recon:
            for method, path in self.ROUTES:
                self.assertTrue(rbac.needs_all_devices(method, path), path)
                body = None if method == "DELETE" else {"enabled": False, "minutes": 5, "mac": "aa:bb:cc:dd:ee:ff"}
                status, res, _ = self.as_(self.scoped, method, path, body)
                self.assertEqual((status, res.get("error")), (403, "This needs access to every device."), (method, path))
            block.assert_not_called()
            recon.assert_not_called()
        # Without a device limit the gate lets them through (these answer "not found").
        for method, path in (("DELETE", "/api/map/objects/999999"), ("DELETE", "/api/dashboards/sw-none")):
            self.assertNotEqual(self.as_(self.wide, method, path)[0], 403, path)
        self.assertFalse(rbac.needs_all_devices("POST", "/api/devices/tags"))

    def test_network_routes_need_step_up(self):
        self.assertEqual(rbac.route_tier("POST", "/api/pihole/blocking"), 2)
        self.assertEqual(rbac.route_tier("POST", "/api/wifi/reconnect"), 2)

    def test_scoped_user_not_asked_to_confirm_first(self):
        with auth.SESSIONS.lock:
            for sess in auth.SESSIONS.sessions.values():
                if sess["username"] == "sw-scoped":
                    sess["tier2_until"] = sess["tier3_until"] = 0
        try:
            status, res, _ = self.as_(self.scoped, "POST", "/api/pihole/blocking", {"enabled": False, "minutes": 5})
            self.assertEqual((status, res.get("auth")), (403, None))
            self.assertEqual(res["error"], "This needs access to every device.")
        finally:
            type(self).scoped = login_again("sw-scoped")

    # --- Proxmox guests and upstream devices ----------------------------------------------------

    def test_proxmox_guest_rule(self):
        layout = {"guests": [{"node": "pve", "vmid": 101, "device_id": self.in1}, {"node": "pve", "vmid": 102, "device_id": self.out},
                             {"node": "pve", "vmid": 103, "device_id": None}]}
        with mock.patch.object(server.proxmox, "layout", return_value=layout), \
                mock.patch.object(server.proxmox, "guest_action", return_value="ok") as act:
            for vmid in (102, 103, 104):
                status, res, _ = self.as_(self.scoped, "POST", "/api/proxmox/guest",
                                          {"node": "pve", "type": "qemu", "vmid": vmid, "action": "reboot"})
                self.assertEqual((status, res["error"]), (404, "Guest not found"), vmid)
            act.assert_not_called()
            body = {"node": "pve", "type": "qemu", "vmid": 101, "action": "reboot"}
            self.assertEqual(self.as_(self.scoped, "POST", "/api/proxmox/guest", body)[0], 200)
            self.assertEqual(self.as_(self.wide, "POST", "/api/proxmox/guest", dict(body, vmid=102))[0], 200)
            self.assertEqual(act.call_count, 2)
        with database.get_connection() as c:
            c.execute("DELETE FROM events WHERE device_id IN (?, ?);", (self.in1, self.out))
            c.commit()

    def test_upstream_must_be_in_scope(self):
        body = {"hostname": "sw-new", "ip_address": "203.0.113.224", "profile_id": "generic_device", "upstream_device_id": self.out}
        status, res, _ = self.as_(self.scoped, "POST", "/api/devices", body)
        self.assertEqual((status, res["error"]), (400, "The upstream device does not exist"))
        put = {"hostname": "sw-in2", "ip_address": "203.0.113.222", "profile_id": "generic_device", "upstream_device_id": self.out}
        status, res, _ = self.as_(self.scoped, "PUT", f"/api/devices/{self.in2}", put)
        self.assertEqual((status, res["error"]), (400, "The upstream device does not exist"))
        self.assertIsNone(database.get_device(self.in2).get("upstream_device_id"))
        # An administrator set it: the limited user can still save the device with it unchanged.
        self.assertEqual(self.as_(self.wide, "PUT", f"/api/devices/{self.in2}", put)[0], 200)
        self.assertEqual(self.as_(self.scoped, "PUT", f"/api/devices/{self.in2}", put)[0], 200)
        self.assertEqual(self.as_(self.scoped, "PUT", f"/api/devices/{self.in2}", dict(put, upstream_device_id=self.in1))[0], 200)
        status, res, _ = self.as_(self.wide, "POST", "/api/devices", body)
        self.assertEqual(status, 201, res)
        database.delete_device(res["device_id"])
        database.set_device_overrides(self.in2, None, None, None, {})

    # --- Workflows ----------------------------------------------------------------------------

    def graph(self, step, schedule=None):
        sched = schedule or {"kind": "manual"}
        return {"name": "Scope reach", "graph": {
            "nodes": [{"id": "t", "type": "trigger", "schedule": sched}, dict(step, id="s1")],
            "edges": [{"from": "t", "to": "s1", "kind": "ok"}]}}

    def reaching(self):
        """Workflows that reach past sw-scoped, each with the words of its reason."""
        event = {"kind": "event", "when": {"type": "offline", "device_id": self.out}}
        return [
            (self.graph({"type": "wait", "seconds": 1}, event), "outside the device access"),
            (self.graph({"type": "mute", "scope": "all"}), "keeps every device quiet"),
            (self.graph({"type": "mute", "scope": "tag", "target": "sw-mix"}), "a group or tag quiet"),
            (self.graph({"type": "mute", "scope": "tag", "target": "sw-nobody-has-this"}), "a group or tag quiet"),
            (self.graph({"type": "pve_snapshot", "node": "pve", "guest_type": "qemu", "vmid": 102}), "Proxmox guest"),
            (self.graph({"type": "pve_snapshot", "node": "pve", "guest_type": "qemu", "vmid": 109}), "Proxmox guest"),
        ]

    LAYOUT = property(lambda self: {"guests": [{"node": "pve", "vmid": 101, "device_id": self.in1},
                                               {"node": "pve", "vmid": 102, "device_id": self.out}]})

    def test_workflow_save_reach(self):
        with mock.patch.object(server.proxmox, "layout", return_value=self.LAYOUT):
            for payload, why in self.reaching():
                status, res, _ = self.as_(self.scoped, "POST", "/api/workflows", payload)
                self.assertEqual(status, 403, (payload, res))
                self.assertIn(why, res["error"])
            made = []
            inside = [self.graph({"type": "mute", "scope": "tag", "target": "sw-in"}),
                      self.graph({"type": "pve_snapshot", "node": "pve", "guest_type": "qemu", "vmid": 101}),
                      self.graph({"type": "wait", "seconds": 1},
                                 {"kind": "event", "when": {"type": "offline", "device_id": self.in1}})]
            try:
                for payload in inside:
                    status, res, _ = self.as_(self.scoped, "POST", "/api/workflows", payload)
                    self.assertEqual(status, 201, (payload, res))
                    made.append(res["id"])
                for payload, _why in self.reaching():
                    status, res, _ = self.as_(self.wide, "POST", "/api/workflows", payload)
                    self.assertEqual(status, 201, (payload, res))
                    made.append(res["id"])
            finally:
                for wid in made:
                    database.delete_workflow(wid)

    def saved(self, payload, author):
        fields = server.parse_workflow_payload(payload)
        return database.save_workflow(None, dict(fields, saved_by=author))

    def test_workflow_run_time_reach(self):
        sched = server.PollScheduler.__new__(server.PollScheduler)
        with mock.patch.object(server.proxmox, "layout", return_value=self.LAYOUT):
            for payload, why in self.reaching():
                wid = self.saved(payload, "sw-scoped")
                try:
                    wf = database.get_workflow(wid)
                    self.assertIn(why, server.workflow_author_problem(wf))
                    with mock.patch.object(workflows.MANAGER, "start") as start:
                        sched._start_scheduled(wf, "schedule: test")
                        start.assert_not_called()
                finally:
                    database.delete_workflow(wid)
        forget_skip_events("Scope reach")

    def test_manual_run_reach(self):
        with mock.patch.object(server.proxmox, "layout", return_value=self.LAYOUT):
            for payload, why in self.reaching():
                wid = self.saved(payload, "tester")
                try:
                    with mock.patch.object(workflows.MANAGER, "start") as start:
                        status, res, _ = self.as_(self.scoped, "POST", f"/api/workflows/{wid}/run")
                    self.assertEqual(status, 403, res)
                    start.assert_not_called()
                finally:
                    database.delete_workflow(wid)

    def test_workflow_list_hides_further_reaching(self):
        with mock.patch.object(server.proxmox, "layout", return_value=self.LAYOUT):
            ids = [self.saved(payload, "tester") for payload, _why in self.reaching()]
            inside = self.saved(self.graph({"type": "mute", "scope": "tag", "target": "sw-in"}), "tester")
            try:
                listed = {w["id"] for w in self.as_(self.scoped, "GET", "/api/workflows")[1]["workflows"]}
                self.assertFalse(listed & set(ids))
                self.assertIn(inside, listed)
                wide = {w["id"] for w in self.as_(self.wide, "GET", "/api/workflows")[1]["workflows"]}
                self.assertTrue(set(ids) <= wide)
            finally:
                for wid in ids + [inside]:
                    database.delete_workflow(wid)

    def test_workflow_scope_notice_once(self):
        notice = "saved workflow(s) reach further than the person who saved them"
        wid = self.saved(self.graph({"type": "mute", "scope": "all"}), "sw-scoped")
        try:
            database.set_internal_setting(server.WORKFLOW_SCOPE_MARKER, "")
            self.assertEqual(server.check_workflow_scope(), 1)
            self.assertEqual(server.check_workflow_scope(), 0)
            admins = [u["username"] for u in database.list_users() if u.get("role") == "admin" and not u.get("disabled")]
            with database.get_connection() as c:
                rows = c.execute("SELECT actor, message FROM events WHERE message LIKE ?;", ("%" + notice + "%",)).fetchall()
            self.assertEqual(sorted(r[0] for r in rows), sorted(admins))
            self.assertTrue(rows[0][1].startswith("1 saved workflow(s)"))
        finally:
            database.delete_workflow(wid)
            database.set_internal_setting(server.WORKFLOW_SCOPE_MARKER, "1")
            with database.get_connection() as c:
                c.execute("DELETE FROM events WHERE message LIKE ?;", ("%" + notice + "%",))
                c.commit()


def forget_skip_events(name):
    """The skipped-run notices a test made: they would crowd the administrator's bell in later tests."""
    with database.get_connection() as c:
        c.execute("DELETE FROM events WHERE message LIKE ?;", (f"Workflow {name}: Run skipped%",))
        c.commit()


def login_again(name):
    _, _, headers = request("POST", "/api/auth/login", {"username": name, "password": PASSWORD}, session=False)
    return {"Cookie": f"{auth.SESSION_COOKIE}={session_cookie(headers)}"}


if __name__ == "__main__":
    unittest.main()
