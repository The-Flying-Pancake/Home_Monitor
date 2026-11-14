"""The release app (deploy/release_app.pyw): its steps, what asks first, and how commands are run."""

import importlib.machinery
import importlib.util
import os
import sys
import unittest
from unittest import mock

from tests import _env

PATH = os.path.join(_env.ROOT, "deploy", "release_app.pyw")


def load():
    loader = importlib.machinery.SourceFileLoader("release_app", PATH)
    spec = importlib.util.spec_from_loader("release_app", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@unittest.skipUnless(os.path.exists(PATH), "the release app is kept in the private repository only")
class ReleaseAppTests(unittest.TestCase):
    def setUp(self):
        self.app = load()

    def test_steps_in_order_and_only_publish_and_release_ask(self):
        labels = [s[0] for s in self.app.STEPS]
        self.assertEqual(labels, ["1. Check", "2. Publish (dry run)", "3. Publish", "4. Build and sign", "5. Release", "6. Verify"])
        asks = {s[0]: s[2] for s in self.app.STEPS if s[2]}
        self.assertEqual(asks, {"3. Publish": "publish", "5. Release": "release"})

    def test_version_read_from_server(self):
        import server
        self.assertEqual(self.app.app_version(), server.APP_VERSION)

    def test_commands_are_argument_lists_in_the_project(self):
        seen = []

        class Proc:
            stdout = iter(["one\n", "two\n"])

            def wait(self):
                return 3

        def popen(cmd, **kw):
            seen.append((cmd, kw))
            return Proc()
        out = []
        with mock.patch.object(self.app.subprocess, "Popen", popen):
            code = self.app.run(["git", "status"], out.append)
        self.assertEqual(code, 3)
        cmd, kw = seen[0]
        self.assertEqual(cmd, ["git", "status"])
        self.assertNotIn("shell", kw)
        self.assertEqual(kw["cwd"], _env.ROOT)
        self.assertIn("one\n", out)
        # The publish step pushes with the version in the message, through publish.py only.
        with mock.patch.object(self.app, "run", return_value=0) as r:
            self.assertTrue(self.app.STEPS[2][3](out.append))
        args = r.call_args[0][0]
        self.assertEqual(args[1:], ["deploy/publish.py", "--push", "-m", f"Home Monitor {self.app.app_version()}"])

    def test_check_stops_on_a_wrong_identity(self):
        answers = {("git", "config", "user.email"): "someone@example.com"}
        with mock.patch.object(self.app, "capture", side_effect=lambda cmd: answers.get(tuple(cmd), "")), \
                mock.patch.object(self.app.shutil, "which", return_value=None):
            out = []
            self.assertFalse(self.app.step_check(out.append))
        text = "".join(out)
        self.assertIn("STOP  Git commits as the GitHub no-reply address", text)
        self.assertIn("Fix the STOP lines first", text)

    def test_console_python_for_the_steps(self):
        with mock.patch.object(self.app.sys, "executable", os.path.join("C:", os.sep, "Python", "pythonw.exe")):
            self.assertTrue(self.app.python()[0].lower().endswith("python.exe"))


if __name__ == "__main__":
    unittest.main()
