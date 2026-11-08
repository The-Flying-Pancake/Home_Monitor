"""Isolated runtime for the test suite. Import this before any project module.

Points the application at a temporary database, vault key file and TCP port,
so tests never touch the real monitor.db, the real vault key or the server
running on 8080. Everything is deleted when the interpreter exits.
"""

import atexit
import os
import shutil
import socket
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="hm-test-")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = free_port()
os.environ.update(
    MONITOR_DB_PATH=os.path.join(TMP, "data", "monitor.db"),
    MONITOR_KEY_FILE=os.path.join(TMP, "key", "vault.key"),
    MONITOR_PORT=str(PORT),
    # The test servers listen on 127.0.0.1; one test switches this off to check the refusal.
    MONITOR_ALLOW_LOOPBACK_CHECKS="1",
)
os.environ.pop("MONITOR_MASTER_KEY", None)
os.makedirs(os.path.join(TMP, "data"), exist_ok=True)
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
