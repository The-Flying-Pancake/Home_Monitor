"""Users and roles: permission table, device access, user management API, blocking, notifications, event log."""

import time
import unittest

from tests import _env  # noqa: F401
from tests.helpers import TEST_USER, add_device, login, request, session_cookie, start_api_server

import auth
import database
import rbac
import server

PASSWORD = "another long passphrase"


def login_as(username: str, password: str = PASSWORD):
    status, body, headers = request("POST", "/api/auth/login", {"username": username, "password": password}, session=False)
    return status, body, session_cookie(headers)


def as_user(cookie: str, method: str, path: str, body=None):
    return request(method, path, body, headers={"Cookie": f"{auth.SESSION_COOKIE}={cookie}"}, session=False)


class PermissionTableTests(unittest.TestCase):
    def test_unlisted_mutation_needs_admin(self):
        self.assertEqual(rbac.route_permission("POST", "/api/something-new"), "admin")
        self.assertEqual(rbac.route_permission("DELETE", "/api/devices/3"), "devices.manage")
        self.assertEqual(rbac.route_permission("POST", "/api/devices/3/poll"), "devices.poll")
        self.assertIsNone(rbac.route_permission("GET", "/api/devices"))
        self.assertEqual(rbac.route_permission("GET", "/api/audit"), "audit.view")
        self.assertEqual(rbac.route_permission("GET", "/api/users"), "users.manage")

    def test_roles(self):
        viewer = rbac.User({"username": "v", "role": "viewer"})
        self.assertFalse(any(viewer.can(p) for p in rbac.PERMISSION_KEYS))
        admin = rbac.User({"username": "a", "role": "admin", "device_scope": '{"all": false, "devices": [1]}'})
        self.assertTrue(all(admin.can(p) for p in rbac.PERMISSION_KEYS))
        self.assertIsNone(admin.scope)  # an administrator always sees every device
        custom = rbac.User({"username": "c", "role": "custom", "permissions": '["problems.ack", "bogus"]'})
        self.assertEqual(custom.perms, {"problems.ack"})
        self.assertTrue(rbac.allowed(custom, "POST", "/api/problems/ack"))
        self.assertFalse(rbac.allowed(custom, "POST", "/api/devices/1/poll"))
        self.assertFalse(rbac.allowed(custom, "POST", "/api/unknown"))

    def test_scope(self):
        u = rbac.User({"username": "s", "role": "operator",
                       "device_scope": '{"all": false, "profiles": ["unifi_ap"], "devices": [7]}'})
        u.bind_devices([{"id": 1, "profile_id": "unifi_ap"}, {"id": 2, "profile_id": "qnap_nas"}, {"id": 7, "profile_id": "linux_host"}])
        self.assertEqual(u.allowed_ids, {1, 7})
        self.assertEqual([r["device_id"] for r in u.visible([{"device_id": 1}, {"device_id": 2}, {"device_id": None}])], [1])
        self.assertEqual(rbac.parse_scope({"all": False, "profiles": ["x", "unifi_ap"], "devices": [5, "7", 99]},
                                          ["unifi_ap"], [5, 7]), {"all": False, "profiles": ["unifi_ap"], "devices": [5, 7]})
        self.assertEqual(rbac.parse_scope("nonsense", [], []), {"all": True})


class UserApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.d1 = add_device("users-a", "192.0.2.201")
        cls.d2 = add_device("users-b", "192.0.2.202")

    def make_user(self, name, role="operator", scope=None, permissions=None):
        body = {"username": name, "password": PASSWORD, "role": role}
        if scope is not None:
            body["device_scope"] = scope
        if permissions is not None:
            body["permissions"] = permissions
        status, resp, _ = request("POST", "/api/users", body)
        self.assertEqual(status, 201, resp)
        return resp["user"]

    def test_list_never_sends_hashes(self):
        status, body, _ = request("GET", "/api/users")
        self.assertEqual(status, 200)
        self.assertTrue(body["users"])
        self.assertNotIn("password_hash", str(body))
        self.assertTrue(any(u["you"] and u["role"] == "admin" for u in body["users"]))

    def test_operator_with_device_access(self):
        self.make_user("op1", scope={"all": False, "devices": [self.d1]})
        status, _, cookie = login_as("op1")
        self.assertEqual(status, 200)
        status, body, _ = as_user(cookie, "GET", "/api/auth/status")
        self.assertEqual((body["user"]["role"], body["user"]["scoped"]), ("operator", True))
        ids = [d["id"] for d in as_user(cookie, "GET", "/api/devices")[1]["devices"]]
        self.assertEqual(ids, [self.d1])
        self.assertEqual(as_user(cookie, "GET", f"/api/devices/{self.d2}")[0], 404)
        self.assertEqual(as_user(cookie, "GET", f"/api/devices/{self.d1}")[0], 200)
        # Operators poll and acknowledge, but cannot delete devices, change settings or see users.
        self.assertEqual(as_user(cookie, "POST", f"/api/devices/{self.d1}/poll", {})[0], 200)
        self.assertEqual(as_user(cookie, "POST", f"/api/devices/{self.d2}/poll", {})[0], 404)
        self.assertEqual(as_user(cookie, "DELETE", f"/api/devices/{self.d1}")[0], 403)
        self.assertEqual(as_user(cookie, "POST", "/api/settings", {"default_poll_interval": "61"})[0], 403)
        self.assertEqual(as_user(cookie, "GET", "/api/users")[0], 403)
        self.assertEqual(as_user(cookie, "PUT", "/api/alert-rules", {"scope": "global", "target": "", "changes": []})[0], 403)

    def test_viewer_is_read_only(self):
        self.make_user("view1", role="viewer")
        _, _, cookie = login_as("view1")
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)
        self.assertEqual(as_user(cookie, "POST", "/api/devices/poll-all", {})[0], 403)
        self.assertEqual(as_user(cookie, "PUT", "/api/dashboard", {"widgets": []})[0], 403)

    def test_custom_settings_permission_per_section(self):
        self.make_user("tg1", role="custom", permissions=["settings.notifications"])
        _, _, cookie = login_as("tg1")
        self.assertEqual(as_user(cookie, "POST", "/api/settings", {"notify_quiet": "off"})[0], 200)
        status, body, _ = as_user(cookie, "POST", "/api/settings", {"default_poll_interval": "75"})
        self.assertEqual(status, 403)
        self.assertIn("poll interval", body["error"])

    def test_block_logs_out_and_refuses_login(self):
        self.make_user("blk1")
        _, _, cookie = login_as("blk1")
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 200)
        self.assertEqual(request("PUT", "/api/users/blk1", {"disabled": True})[0], 200)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 401)
        status, body, _ = login_as("blk1")
        self.assertEqual(status, 403)
        self.assertIn("blocked", body["error"])
        self.assertEqual(request("PUT", "/api/users/blk1", {"disabled": False})[0], 200)
        self.assertEqual(login_as("blk1")[0], 200)

    def test_logout_and_password_reset_end_sessions(self):
        self.make_user("lo1")
        _, _, cookie = login_as("lo1")
        status, body, _ = request("POST", "/api/users/lo1/logout", {})
        self.assertEqual((status, body["ended"]), (200, 1))
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 401)
        _, _, cookie = login_as("lo1")
        self.assertEqual(request("POST", "/api/users/lo1/password", {"password": "a different long one"})[0], 200)
        self.assertEqual(as_user(cookie, "GET", "/api/devices")[0], 401)
        self.assertEqual(login_as("lo1", "a different long one")[0], 200)

    def test_last_admin_and_self_protection(self):
        self.assertEqual(request("PUT", f"/api/users/{TEST_USER}", {"role": "viewer"})[0], 409)
        self.assertEqual(request("PUT", f"/api/users/{TEST_USER}", {"disabled": True})[0], 409)
        self.assertEqual(request("DELETE", f"/api/users/{TEST_USER}")[0], 409)
        self.make_user("adm2", role="admin")
        self.assertEqual(request("DELETE", "/api/users/adm2")[0], 200)
        self.assertIsNone(database.get_user("adm2"))

    def test_user_manager_cannot_escalate(self):
        self.make_user("um1", role="custom", permissions=["users.manage", "devices.poll"])
        self.make_user("um-op", role="operator")
        self.make_user("um-low", role="custom", permissions=["devices.poll"])
        _, _, c = login_as("um1")
        # Not themselves: no role, permission or device access change.
        self.assertEqual(as_user(c, "PUT", "/api/users/um1", {"role": "admin"})[0], 403)
        self.assertEqual(as_user(c, "PUT", "/api/users/um1", {"role": "custom", "permissions": ["users.manage", "devices.poll",
                                                                                              "settings.system"]})[0], 403)
        self.assertEqual(as_user(c, "PUT", "/api/users/um1", {"device_scope": {"all": True}})[0], 403)
        self.assertEqual(as_user(c, "PUT", "/api/users/um1", {"display_name": "Me"})[0], 200)
        # Not new administrators, not Manage users, nothing they do not hold.
        new = {"username": "um-new", "password": PASSWORD}
        self.assertEqual(as_user(c, "POST", "/api/users", dict(new, role="admin"))[0], 403)
        self.assertEqual(as_user(c, "POST", "/api/users", dict(new, role="operator"))[0], 403)
        self.assertEqual(as_user(c, "POST", "/api/users", dict(new, role="custom", permissions=["users.manage"]))[0], 403)
        self.assertEqual(as_user(c, "POST", "/api/users", dict(new, role="custom", permissions=["devices.manage"]))[0], 403)
        status, body, _ = as_user(c, "POST", "/api/users", dict(new, role="custom", permissions=["devices.poll"]))
        self.assertEqual(status, 201, body)
        self.assertEqual(as_user(c, "PUT", "/api/users/um-low", {"role": "admin"})[0], 403)
        self.assertEqual(as_user(c, "PUT", "/api/users/um-low", {"role": "custom", "permissions": ["settings.system"]})[0], 403)
        # Hands off administrators and users with more rights.
        for method, path, body in (("POST", f"/api/users/{TEST_USER}/password", {"password": "a takeover password"}),
                                   ("POST", f"/api/users/{TEST_USER}/2fa-reset", {}),
                                   ("POST", f"/api/users/{TEST_USER}/logout", {}),
                                   ("PUT", f"/api/users/{TEST_USER}", {"disabled": True}),
                                   ("DELETE", f"/api/users/{TEST_USER}", None),
                                   ("POST", "/api/users/um-op/password", {"password": "a takeover password"})):
            status, res, _ = as_user(c, method, path, body)
            self.assertEqual(status, 403, (method, path, res))
        self.assertEqual(login(), None)                                       # the admin password is unchanged
        self.assertEqual(as_user(c, "POST", "/api/users/um-low/logout", {})[0], 200)
        # An administrator keeps full control.
        self.assertEqual(request("PUT", "/api/users/um1", {"role": "viewer"})[0], 200)
        for name in ("um1", "um-op", "um-low", "um-new"):
            request("DELETE", f"/api/users/{name}")

    def test_vault_details_need_system_settings(self):
        self.make_user("vault-view", role="viewer")
        _, _, c = login_as("vault-view")
        vault = as_user(c, "GET", "/api/system")[1]["vault"]
        self.assertNotIn("key_path", vault)
        self.assertNotIn("error", vault)
        self.assertIn("enabled", vault)
        self.assertIn("key_path", request("GET", "/api/system")[1]["vault"])
        request("DELETE", "/api/users/vault-view")

    def test_update_routes(self):
        """Settings, Updates: status for those who see System settings; acting is for administrators, and a
        development copy (no update helper) says so instead of pretending."""
        status = request("GET", "/api/system")[1]["update"]
        self.assertFalse(status["installed"])
        self.assertIn("Home_Monitor", status["repository"])
        code, body = request("POST", "/api/updates/check", {})[:2]
        self.assertEqual(code, 409)
        self.assertIn("installed monitor", body["error"])
        self.make_user("upd-op", role="operator")
        _, _, c = login_as("upd-op")
        self.assertEqual(as_user(c, "POST", "/api/updates/check", {})[0], 403)
        self.assertEqual(as_user(c, "POST", "/api/updates/install", {})[0], 403)
        request("DELETE", "/api/users/upd-op")

    def test_update_waiting_skip_and_history(self):
        """The red number, skipping a version, the daily check and the history with its logs."""
        import json
        import os
        import shutil
        import tempfile
        from unittest import mock
        data_dir = os.path.dirname(os.path.abspath(database.DB_FILE))
        result = os.path.join(data_dir, "update-check.result.json")
        tmp = tempfile.mkdtemp(prefix="hm-hist-", dir=_env.TMP)

        def known(latest):
            with open(result, "w", encoding="utf-8") as f:
                json.dump({"ok": True, "newer": True, "latest": latest, "current": server.APP_VERSION, "time": int(time.time()),
                           "changes": [{"version": latest, "notes": "Better things", "evil": "x"}]}, f)
        try:
            known("98.0.0")
            self.assertEqual(request("GET", "/api/updates/summary")[1]["waiting"], 1)
            u = request("GET", "/api/system")[1]["update"]
            self.assertEqual(u["check"]["changes"], [{"version": "98.0.0", "name": "", "published": "", "notes": "Better things"}])
            # Skipping needs the version that is waiting; then the number goes until a newer one comes.
            self.assertEqual(request("POST", "/api/updates/skip", {"version": "97.0.0"})[0], 409)
            self.assertEqual(request("POST", "/api/updates/skip", {"version": "98.0.0"})[0], 200)
            self.assertEqual(request("GET", "/api/updates/summary")[1]["waiting"], 0)
            known("99.0.0")
            self.assertEqual(request("GET", "/api/updates/summary")[1]["waiting"], 1)
            known("98.0.0")
            request("POST", "/api/updates/unskip", {})
            self.assertEqual(request("GET", "/api/updates/summary")[1]["waiting"], 1)

            # History: listed from root's file; a log opens only by a number that is in it.
            hist, logs = os.path.join(tmp, "update-history.json"), os.path.join(tmp, "update-logs")
            os.makedirs(logs)
            with open(hist, "w", encoding="utf-8") as f:
                json.dump([{"id": 5, "time": 1, "kind": "upgrade", "from": "0.6.0", "to": "0.9.0", "ok": False, "error": "x", "log": True},
                           {"id": "../x", "kind": "bad"}], f)
            for n, text in ((5, "the log"), (6, "not in the history")):
                with open(os.path.join(logs, f"{n}.log"), "w", encoding="utf-8") as f:
                    f.write(text)
            with mock.patch.object(server, "UPDATE_HISTORY", hist), mock.patch.object(server, "UPDATE_LOGS", logs):
                rows = request("GET", "/api/updates/history")[1]["history"]
                self.assertEqual([(r["id"], r["ok"], r["log"]) for r in rows], [(5, False, True)])
                self.assertEqual(request("GET", "/api/updates/history/5/log")[1]["log"], "the log")
                self.assertEqual(request("GET", "/api/updates/history/6/log")[0], 404)
                for bad in ("/api/updates/history/..%2F..%2Fetc%2Fpasswd/log", "/api/updates/history/5/../../x/log",
                            "/api/updates/history/-1/log"):
                    self.assertNotEqual(request("GET", bad)[0], 200, bad)
                self.make_user("hist-op", role="operator")
                _, _, c = login_as("hist-op")
                self.assertEqual(as_user(c, "GET", "/api/updates/history")[0], 403)
                self.assertEqual(as_user(c, "GET", "/api/updates/history/5/log")[0], 403)
                self.assertEqual(as_user(c, "GET", "/api/updates/summary")[1]["waiting"], 0)
                self.assertEqual(as_user(c, "POST", "/api/updates/skip", {"version": "98.0.0"})[0], 403)
                request("DELETE", "/api/users/hist-op")

            # The daily check asks root once a day, only on an installed monitor and when it is on.
            installed = dict(server.update_status(), installed=True, check={"time": time.time() - 25 * 3600})
            with mock.patch.object(server, "update_status", return_value=installed), \
                    mock.patch.object(server, "request_root_action") as ask:
                self.assertTrue(server.auto_update_check())
                ask.assert_called_once_with("update-check")
                installed["check"] = {"time": time.time() - 3600}
                self.assertFalse(server.auto_update_check())
                installed["check"] = {"time": 0}
                database.update_setting("update_auto_check", "off")
                self.assertFalse(server.auto_update_check())
                database.update_setting("update_auto_check", "on")
        finally:
            database.set_internal_setting(server.UPDATE_SKIP_KEY, "")
            os.remove(result)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_check_saved_before_an_update_is_judged_again(self):
        """After updating to the version a check found, that check no longer says newer (it showed
        "You skipped" on the owner's box after 0.9.0 to 0.10.0)."""
        import json
        import os
        result = os.path.join(os.path.dirname(os.path.abspath(database.DB_FILE)), "update-check.result.json")
        with open(result, "w", encoding="utf-8") as f:
            json.dump({"ok": True, "newer": True, "latest": server.APP_VERSION, "current": "0.0.1", "time": int(time.time()),
                       "changes": [{"version": server.APP_VERSION, "notes": "x"}]}, f)
        try:
            u = request("GET", "/api/system")[1]["update"]
            self.assertFalse(u["check"]["newer"])
            self.assertEqual(u["check"]["current"], server.APP_VERSION)
            self.assertNotIn("changes", u["check"])
            self.assertEqual(u["waiting"], 0)
        finally:
            os.remove(result)

    def test_demo_routes(self):
        """Settings, Demo data: hidden (off) on a monitor without demo data; removing is for administrators."""
        self.assertEqual(request("GET", "/api/system")[1]["demo"], {"on": False, "devices": 0})
        code, body = request("POST", "/api/demo/remove", {})[:2]
        self.assertEqual(code, 409)
        self.assertIn("no demo data", body["error"])
        self.assertEqual(rbac.route_tier("POST", "/api/demo/remove"), 2)
        self.make_user("demo-op", role="operator")
        _, _, c = login_as("demo-op")
        self.assertEqual(as_user(c, "POST", "/api/demo/remove", {})[0], 403)
        request("DELETE", "/api/users/demo-op")

    def test_update_progress_is_read_carefully(self):
        import json
        import os
        tmp = os.path.join(_env.TMP, "hm-progress")
        os.makedirs(tmp, exist_ok=True)
        with open(os.path.join(tmp, "update-progress.json"), "w", encoding="utf-8") as f:
            json.dump({"state": "running", "to": "0.9.0", "current": "backup", "time": int(time.time()),
                       "steps": {"backup": "run", "evil": "x"}, "extra": "<script>"}, f)
        p = server.update_progress(tmp, True)
        self.assertEqual(p["steps"]["backup"], "run")
        self.assertNotIn("evil", p["steps"])
        self.assertNotIn("extra", p)
        self.assertEqual(list(p["steps"]), list(server.UPDATE_STEPS))

    def test_validation(self):
        self.assertEqual(request("POST", "/api/users", {"username": "bad name", "password": PASSWORD})[0], 400)
        self.assertEqual(request("POST", "/api/users", {"username": "short1", "password": "short"})[0], 400)
        self.assertEqual(request("POST", "/api/users", {"username": "r1", "password": PASSWORD, "role": "god"})[0], 400)
        self.assertEqual(request("POST", "/api/users", {"username": "s1", "password": PASSWORD,
                                                         "device_scope": {"all": False}})[0], 400)
        self.assertEqual(request("POST", "/api/users", {"username": TEST_USER, "password": PASSWORD})[0], 409)


class NotificationAndEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.dev = add_device("events-a", "192.0.2.203")

    def test_action_error_becomes_event_and_notification(self):
        before = request("GET", "/api/notifications")[1]
        self.assertTrue(issubclass(server.ActionError, server.RequestError))
        database.add_event(None, "warning", "action", "Could not run workflow Test: no SSH credential", actor=TEST_USER)
        # Another user's failed action is not in this user's bell.
        database.add_event(None, "warning", "action", "Someone else's failure", actor="someone-else")
        after = request("GET", "/api/notifications")[1]
        self.assertNotIn("Someone else's failure", [e["message"] for e in after["items"]])
        self.assertEqual(after["unread"], before["unread"] + 1)
        top = after["items"][0]
        self.assertEqual((top["event_type"], top["device_id"], top["actor"]), ("action", None, TEST_USER))
        status, body, _ = request("POST", "/api/notifications/read", {"upto": top["timestamp"]})
        self.assertEqual(status, 200)
        self.assertEqual(request("GET", "/api/notifications")[1]["unread"], 0)

    def test_event_log_filters_and_pages(self):
        now = int(time.time())
        for i in range(60):
            database.add_event(self.dev, "critical" if i % 3 == 0 else "info", "pagetest", f"Paging event {i}", timestamp=now - i)
        status, body, _ = request("GET", "/api/events?type=pagetest&per_page=25&page=2")
        self.assertEqual(status, 200)
        self.assertEqual((body["total"], body["pages"], body["page"], len(body["events"])), (60, 3, 2, 25))
        self.assertEqual(body["events"][0]["message"], "Paging event 25")
        body = request("GET", "/api/events?type=pagetest&severity=critical")[1]
        self.assertEqual(body["total"], 20)
        body = request("GET", "/api/events?q=event%2059")[1]
        self.assertEqual([e["message"] for e in body["events"]], ["Paging event 59"])
        body = request("GET", f"/api/events?device={self.dev}&from={now - 4}&type=pagetest")[1]
        self.assertEqual(body["total"], 5)
        self.assertIn("pagetest", body["types"])
        # LIKE wildcards in the search are literal.
        self.assertEqual(request("GET", "/api/events?q=%25%25%25")[1]["total"], 0)


if __name__ == "__main__":
    unittest.main()
