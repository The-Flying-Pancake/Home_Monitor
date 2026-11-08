"""Starting again after an update: the new version gets its port even right after the old one stopped
(0.10.0 to 0.11.0 on the owner's box failed with "Address already in use" and was put back)."""

import errno
import os
import unittest
from unittest import mock

from tests import _env  # noqa: F401

import server

ROOT = _env.ROOT


class RestartTests(unittest.TestCase):
    def test_address_reuse_on_linux_only(self):
        # Linux: binding over closed connections still winding down (TIME_WAIT); never a second listener.
        # Windows: off, because there it would let two programs share the port.
        self.assertEqual(server.ThreadingServer.allow_reuse_address, os.name != "nt")

    def test_port_still_taken_is_waited_for(self):
        busy = OSError(errno.EADDRINUSE, "Address already in use")
        made = object()
        with mock.patch.object(server, "ThreadingServer", side_effect=[busy, busy, made]) as ts, \
                mock.patch.object(server.time, "sleep") as sleep:
            self.assertIs(server.open_listener(tries=5, wait=2.0), made)
        self.assertEqual(ts.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_gives_up_after_a_minute_and_on_other_errors(self):
        busy = OSError(errno.EADDRINUSE, "Address already in use")
        with mock.patch.object(server, "ThreadingServer", side_effect=busy), mock.patch.object(server.time, "sleep"):
            with self.assertRaises(OSError):
                server.open_listener(tries=3)
        denied = OSError(errno.EACCES, "Permission denied")
        with mock.patch.object(server, "ThreadingServer", side_effect=denied) as ts, mock.patch.object(server.time, "sleep") as sleep:
            with self.assertRaises(OSError):
                server.open_listener(tries=3)
        self.assertEqual((ts.call_count, sleep.call_count), (1, 0))      # not a busy port: no waiting

    def test_port_opens_before_anything_starts(self):
        src = open(os.path.join(ROOT, "server.py"), encoding="utf-8").read()
        body = src.split("def start_server() -> None:")[1].split("\ndef ")[0]
        self.assertLess(body.index("open_listener()"), body.index("NOTIFIER.start()"))
        self.assertLess(body.index("open_listener()"), body.index("scheduler.run_forever"))

    def test_service_waits_between_restarts(self):
        tpl = open(os.path.join(ROOT, "deploy", "install-template.sh"), encoding="utf-8").read()
        self.assertIn("Restart=on-failure\nRestartSec=5", tpl)


if __name__ == "__main__":
    unittest.main()
