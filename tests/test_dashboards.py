"""Several dashboards: create blank or from a template, rename tiles and dashboards, switch, delete; the extras data."""

import unittest

from tests import _env  # noqa: F401
from tests.helpers import request, start_api_server

import database
import server


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_api_server()

    def tearDown(self):
        for d in database.list_dashboards():
            if d["name"] != "default":
                database.delete_dashboard(d["name"])

    def test_templates_are_valid_and_twenty(self):
        self.assertEqual(len(server.DASHBOARD_TEMPLATES), 20)
        self.assertEqual(len({t["id"] for t in server.DASHBOARD_TEMPLATES}), 20)
        for t in server.DASHBOARD_TEMPLATES:
            layout = server.parse_dashboard_layout({"columns": t["columns"], "layout": t["widgets"]})
            self.assertEqual(len({w["id"] for w in layout["widgets"]}), len(layout["widgets"]), t["id"])
            for w in layout["widgets"]:
                self.assertIn(w["type"], server.WIDGET_TYPES)

    def test_create_switch_rename_delete(self):
        status, body, _ = request("GET", "/api/dashboards")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["templates"]), 20)
        status, made, _ = request("POST", "/api/dashboards", {"title": "Proxmox room", "template": "proxmox"})
        self.assertEqual(status, 201, made)
        status, dash, _ = request("GET", f"/api/dashboard?name={made['name']}")
        self.assertEqual((status, dash["title"]), (200, "Proxmox room"))
        self.assertIn("proxmox", [w["type"] for w in dash["layout"]])
        names = [d["name"] for d in dash["dashboards"]]
        self.assertIn("default", names)                       # the Overview stays in the list
        self.assertIn(made["name"], names)
        # Rename a tile and the dashboard; control characters are dropped.
        dash["layout"][0]["name"] = "Guests\x07 upstairs"
        status, saved, _ = request("PUT", "/api/dashboard", {"name": made["name"], "title": "Rack", "layout": dash["layout"],
                                                             "columns": dash["columns"]})
        self.assertEqual((status, saved["title"]), (200, "Rack"))
        again = request("GET", f"/api/dashboard?name={made['name']}")[1]
        self.assertEqual(again["layout"][0]["name"], "Guests upstairs")
        self.assertEqual(again["title"], "Rack")
        # Blank one, then delete both extra dashboards; the last one cannot go.
        blank = request("POST", "/api/dashboards", {"title": "Mine", "template": ""})[1]
        self.assertEqual(request("GET", f"/api/dashboard?name={blank['name']}")[1]["layout"], [])
        self.assertEqual(request("DELETE", f"/api/dashboards/{blank['name']}")[0], 200)
        self.assertEqual(request("DELETE", f"/api/dashboards/{made['name']}")[0], 200)
        self.assertEqual(request("GET", f"/api/dashboard?name={made['name']}")[0], 404)
        if len(database.list_dashboards()) == 1:
            self.assertEqual(request("DELETE", f"/api/dashboards/{database.list_dashboards()[0]['name']}")[0], 400)

    def test_rejects_bad_input(self):
        self.assertEqual(request("POST", "/api/dashboards", {"title": "", "template": ""})[0], 400)
        self.assertEqual(request("POST", "/api/dashboards", {"title": "x", "template": "nope"})[0], 400)
        self.assertEqual(request("GET", "/api/dashboard?name=../etc")[0], 400)
        self.assertEqual(request("PUT", "/api/dashboard", {"name": "missing", "layout": [], "columns": 4})[0], 404)
        status, _, _ = request("PUT", "/api/dashboard", {"layout": [{"id": "x", "type": "nope"}], "columns": 4})
        self.assertEqual(status, 400)

    def test_extras(self):
        status, body, _ = request("GET", "/api/dashboard/extras?want=storage,maintenance,workflows,host_actions,new_devices,pihole,proxmox,bogus")
        self.assertEqual(status, 200)
        self.assertNotIn("bogus", body)
        self.assertIn("rows", body["storage"])
        self.assertIn("windows", body["maintenance"])
        self.assertIn("runs", body["workflows"])
        self.assertIn("runs", body["host_actions"])
        self.assertIn("rows", body["new_devices"])
        self.assertTrue("error" in body["pihole"] or "metrics" in body["pihole"])
        self.assertTrue("error" in body["proxmox"] or "guests" in body["proxmox"])


if __name__ == "__main__":
    unittest.main()
