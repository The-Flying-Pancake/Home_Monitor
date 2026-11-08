"""First visit on a fresh install: the account is created in the browser and the setup guide follows.

Run by run_all.py --browser. A separate server with an empty database and a setup code, opened
at an address that already ends in #/dashboard (what browser autocomplete gives after an
earlier visit to the same address). The setup guide must open all the same.
"""

import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from tests.cdp import Browser  # noqa: E402
from tests._env import free_port  # noqa: E402


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="hm-firstrun-")
    port = free_port()
    env = dict(os.environ, MONITOR_DB_PATH=os.path.join(tmp, "monitor.db"), MONITOR_PORT=str(port),
               MONITOR_KEY_FILE=os.path.join(tmp, "vault.key"), MONITOR_SETUP_TOKEN="first-run-code")
    srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py")], env=env, cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    b = None
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/api/auth/status", timeout=2).read()
                break
            except OSError:
                time.sleep(0.5)
        b = Browser(free_port(), width=1400, height=900)
        b.send("Page.enable")
        b.send("Runtime.enable")
        b.send("Page.navigate", {"url": base + "/#/dashboard"})
        b.wait_for("document.readyState === 'complete'")
        b.wait_for("!document.getElementById('auth-screen').classList.contains('hidden') && document.getElementById('auth-screen').dataset.mode === 'setup'")
        # Field order: username, password, repeat password, setup code (with the shown-once warning).
        order = b.eval("[...document.querySelectorAll('#auth-fields input')].filter(i => i.offsetParent).map(i => i.id)")
        assert order == ["auth-username", "auth-password", "auth-password2", "auth-token"], order
        assert "setup-code.sh" in b.eval("document.querySelector('#auth-token-group .auth-warning').textContent")
        b.eval("document.getElementById('auth-username').value = 'owner';"
               "document.getElementById('auth-password').value = 'a long first password';"
               "document.getElementById('auth-password2').value = 'a long first password';"
               "document.getElementById('auth-token').value = 'first-run-code';"
               "document.getElementById('auth-submit').click(); true")
        b.wait_for("document.getElementById('auth-screen').classList.contains('hidden')")
        b.wait_for("!document.getElementById('view-setup').classList.contains('hidden')", timeout=15)
        assert b.eval("window.location.hash") == "#/setup"
        # Until setup is done only the wizard is reachable: the menu is replaced by its steps.
        assert b.eval("document.getElementById('app-shell').classList.contains('setup-locked')")
        assert b.eval("getComputedStyle(document.querySelector('.side-nav')).display") == "none"
        assert b.eval("document.querySelectorAll('#setup-side-steps li').length") == 11      # Services joined the steps
        b.eval("window.location.hash = '#/devices'; true")
        time.sleep(1)
        assert b.eval("window.location.hash") == "#/setup", b.eval("window.location.hash")
        assert not b.eval("document.getElementById('view-setup').classList.contains('hidden')")
        print("  PASS  First visit: field order, setup guide opens (address had #/dashboard), the rest stays locked")
        return 0
    except Exception as exc:
        print(f"  FAIL  First visit: setup guide did not open: {type(exc).__name__}: {exc}")
        return 1
    finally:
        if b:
            b.close()
        srv.terminate()


if __name__ == "__main__":
    sys.exit(main())
