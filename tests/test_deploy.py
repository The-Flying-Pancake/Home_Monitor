"""Deployment: the built installer's payload, sitectl key derivation, backup / restore, site settings apply."""

import base64
import io
import json
import re
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

from tests import _env  # noqa: F401

ROOT = _env.ROOT
SITECTL = os.path.join(ROOT, "deploy", "sitectl.py")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def sitectl(*args, stdin=""):
    return subprocess.run([sys.executable, SITECTL, *args], input=stdin.encode(), capture_output=True)


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Built into a temporary file so the test never rewrites the project's home_monitor.sh.
        cls.tmp = tempfile.mkdtemp(prefix="hm-build-")
        cls.out = os.path.join(cls.tmp, "home_monitor.sh")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "deploy", "build.py"), "--reset-settings"], capture_output=True,
                           cwd=ROOT, env=dict(os.environ, HM_BUILD_OUT=cls.out))
        assert r.returncode == 0, r.stdout.decode() + r.stderr.decode()
        cls.text = read(cls.out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_payload_contents(self):
        b64 = self.text.split("\n__PAYLOAD_BEGIN__\n")[1].split("\n__PAYLOAD_END__")[0]
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b64)), mode="r:gz") as tar:
            names = tar.getnames()
        for must in ("server.py", "vault.py", "setup.py", "sitectl.py", "web/index.html", "web/setup.js", "profiles/linux_host.json"):
            self.assertIn(must, names)
        # No data, keys, logs or development material ship inside the installer.
        for name in names:
            self.assertFalse(name.endswith((".db", ".key", ".log")) or name.startswith(("tests/", "monitor")), name)
            self.assertNotIn("vault.json", name)

    def test_payload_has_every_import(self):
        """The packed app runs on its own: every module it imports is in the payload or in Python
        itself (plus cryptography). 0.8.0 shipped poller.py importing demo.py without packing it, and
        the new version could not start."""
        import ast
        b64 = self.text.split("\n__PAYLOAD_BEGIN__\n")[1].split("\n__PAYLOAD_END__")[0]
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b64)), mode="r:gz") as tar:
            sources = {m.name: tar.extractfile(m).read().decode("utf-8") for m in tar.getmembers()
                       if m.isfile() and m.name.endswith(".py") and "/" not in m.name}
        self.assertIn("demo.py", sources)            # an install with demo data needs it
        packed = {n[:-3] for n in sources}
        allowed = set(sys.stdlib_module_names) | {"cryptography"} | packed
        missing = []
        for name, src in sources.items():
            for node in ast.walk(ast.parse(src, name)):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    mods = [node.module]
                else:
                    continue
                for mod in mods:
                    top = mod.split(".")[0]
                    if top in allowed:
                        continue
                    missing.append(f"{name}: import {mod}")
        self.assertEqual(missing, [])

    def test_packed_app_starts(self):
        """The packed server, poller and compat check import cleanly from the payload alone."""
        b64 = self.text.split("\n__PAYLOAD_BEGIN__\n")[1].split("\n__PAYLOAD_END__")[0]
        d = tempfile.mkdtemp(prefix="hm-payload-", dir=_env.TMP)
        try:
            with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b64)), mode="r:gz") as tar:
                tar.extractall(d, filter="data")
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            env.update(MONITOR_DB_PATH=os.path.join(d, "t.db"), MONITOR_KEY_FILE=os.path.join(d, "t.key"))
            r = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                                "import server, poller, compat, sitectl, updatectl; print(poller.demo is not None)", d],
                               capture_output=True, text=True, cwd=d, env=env)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            self.assertEqual(r.stdout.strip().splitlines()[-1], "True")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_installer_python_snippets_compile(self):
        """Every Python snippet inside the installer compiles (a stray line break in one made the
        upgrade's data check crash instead of reporting)."""
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", tpl, re.S)
        self.assertTrue(blocks)
        for src in blocks:
            compile(src, "<installer PY block>", "exec")
        for src in re.findall(r"python3 -c '([^']*)'", tpl):
            compile(src, "<installer python3 -c>", "exec")

    def test_settings_folder_made_before_use(self):
        """Upgrading an install from before 0.8.0: the folder exists before settings.env goes into it."""
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        body = tpl.split("files_into_place() {")[1].split("\n}\n")[0]
        self.assertLess(body.index("install -d -m 0750 -o root -g ${SERVICE_USER} ${INSTALL_DIR}"),
                        body.index("${INSTALL_DIR}/settings.env"))

    def test_installer_settings(self):
        block = self.text.split("# >>> SETTINGS")[1].split("# <<< SETTINGS")[0]
        for line in ("CTID=201", 'MAC_ADDRESS=""', 'TEMPLATE_STORAGE=""', 'DISK_STORAGE=""',
                     'IP_ADDRESS="dhcp"', 'RESTORE="no"', 'SNMP_COMMUNITY="public"'):
            self.assertIn(line, block)
        for line in ('TEMPLATE_SERIES="ubuntu-24.04-standard"', "UNPRIVILEGED=0", 'login="yes"', "prohibit-password",
                     "api.telegram.org", "snmpd", "python3-cryptography", "syncthing", "-timezone", 'BACKUP_PASSPHRASE=""',
                     'ADMIN_NET=""', 'ROOT_SSH_KEY=""'):
            self.assertIn(line, self.text)
        for line in ("UNPRIVILEGED=0", 'BACKUP_PASSPHRASE=""', 'ADMIN_NET=""', 'ROOT_SSH_KEY=""'):
            self.assertIn(line, block)
        # The Syncthing apt key is carried in the file (pinned), not downloaded at install time.
        self.assertIn("FBA2E162F2F44657B38F0309E5665F9BD5970C47", self.text)
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", self.text)
        self.assertNotIn("curl -fsSL https://syncthing.net/release-key.txt", self.text)
        # The application is checked against the checksum build.py wrote.
        self.assertRegex(self.text, r'PAYLOAD_SHA256="[0-9a-f]{64}"')
        # Root never sources a file the app's user could change, and no root work happens in /tmp.
        self.assertNotIn('. "$CONF"', self.text)
        self.assertNotIn("/tmp/hm-", self.text)
        self.assertNotIn("/tmp/bootstrap.sh", self.text)
        # Unattended: the only question is the root password (and REBUILD when destroying a container).
        self.assertNotIn("passphrase (12+", self.text)
        self.assertNotIn("VAULT_PASS", self.text)
        # Secrets are never put on a command line inside the container: the SNMP community goes on stdin.
        self.assertIn('printf \'%s\\n\' "$SNMP_COMMUNITY" | pct exec', self.text)
        self.assertNotRegex(self.text, r"bootstrap\.sh tools \"\$SNMP_COMMUNITY")

    def fake_host(self, settings=None):
        """A PATH with stub Proxmox commands that log their arguments; returns (env, log path, home_monitor.sh copy)."""
        fake = os.path.join(self.tmp, "fakebin")
        os.makedirs(fake, exist_ok=True)
        calls = os.path.join(self.tmp, "calls.log")
        state = os.path.join(self.tmp, "ct-created")
        for p in (calls, state, state + ".health"):
            if os.path.exists(p):
                os.remove(p)
        q = lambda p: p.replace("\\", "/")
        stubs = {
            "pct": f'''#!/usr/bin/env bash
echo "pct $*" >> "{q(calls)}"
case "$1" in
  status) [[ -f "{q(state)}" ]] && echo "status: running" || exit 2 ;;
  create) touch "{q(state)}" ;;
  exec) shift 2; [[ "$1" == "--" ]] && shift
        case "$*" in
          *"hostname -I"*) echo "192.168.1.51 fd00::51" ;;
          *hm-precheck.sh\\ *) printf '%b' "${{HM_FAKE_PRECHECK:-OK|fake container\\n}}"; echo HM_CHECK_DONE ;;
          *"sitectl.py backup"*) echo "{q(self.tmp)}/data/backups/pre-upgrade/monitor-backup-20261104-120000.tar.gz" ;;
          *"is-active --quiet homelab-monitor"*)
            # HM_FAKE_UNHEALTHY=n: the first n health checks fail (a new version that does not start).
            n=$(cat "{q(state)}.health" 2>/dev/null || echo 0); echo $((n + 1)) > "{q(state)}.health"
            (( n < ${{HM_FAKE_UNHEALTHY:-0}} )) && exit 1 ;;
          *bootstrap.sh\\ tools*) read -r c; echo "community received on stdin: ${{#c}} chars" ;;
          *"cat /var/lib/homelab-monitor/restored-from"*) exit 1 ;;
          # The installer's Restore: the backups the container can see, and the check of the one picked.
          *find-backups*) printf '%s' "${{HM_FAKE_BACKUPS-}}" ;;
          *"sitectl.py verify"*) [[ -n "${{HM_FAKE_VERIFY_FAIL-}}" ]] && {{ echo "ERROR: The database in this backup is damaged" >&2; exit 1; }} ;;
          *"sitectl.py site-of"*) printf '%b' "${{HM_FAKE_SITE-}}" ;;
        esac ;;
  config) [[ -n "${{HM_FAKE_UNPRIV-}}" ]] && echo "unprivileged: 1"; [[ -f "{q(state)}" ]] || exit 2 ;;
esac
exit 0
''',
            # The host mounts an NFS share itself only for an unprivileged container (logged, nothing mounted).
            "mount": f'#!/usr/bin/env bash\necho "host-mount $*" >> "{q(calls)}"\nfor f in cert.pem key.pem config.xml; do : > "${{@: -1}}/$f"; done\nexit 0\n',
            "umount": f'#!/usr/bin/env bash\necho "host-umount $*" >> "{q(calls)}"\nrm -f "$1"/*\nexit 0\n',
            "pveam": '''#!/usr/bin/env bash
case "$1" in
  available) echo "system          ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
             echo "system          ubuntu-24.04-standard_24.04-2_amd64.tar.zst" ;;
  list) echo "NAME SIZE" ;;
esac
exit 0
''',
            "pvesm": '''#!/usr/bin/env bash
echo "Name Type Status Total Used Available %"
case "$*" in
  *vztmpl*) echo "local dir active 100 10 90 10.00%" ;;
  *rootdir*) echo "local-lvm lvmthin active 500 100 400 20.00%"; echo "data dir active 2000 100 1900 5.00%" ;;
esac
''',
            "pveversion": "#!/usr/bin/env bash\necho pve-manager/8.2.4\n",
        }
        for name, body in stubs.items():
            path = os.path.join(fake, name)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(body)
            os.chmod(path, 0o755)
        script = os.path.join(self.tmp, "infra-test.sh")
        text = self.text
        for k, v in (settings or {}).items():
            text = re.sub(rf'^{k}=.*$', f'{k}={v}', text, count=1, flags=re.M)
        with open(script, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        sep = ";" if os.name == "nt" else ":"
        # Proxmox's container configs (/etc/pve/lxc): empty until a test tags a container.
        lxc = os.path.join(self.tmp, "lxc")
        shutil.rmtree(lxc, ignore_errors=True)
        os.makedirs(lxc)
        env = dict(os.environ, HM_FAKE_HOST="1", NO_COLOR="1", PATH=fake + sep + os.environ["PATH"], HM_PVE_LXC_DIR=q(lxc))
        return env, calls, script

    def tag_ct(self, ctid=201, tags="homelab-monitor", extra=""):
        """Writes a container config as Proxmox keeps it, with its tags (and a snapshot section below)."""
        nl = chr(10)
        with open(os.path.join(self.tmp, "lxc", f"{ctid}.conf"), "w", encoding="utf-8", newline=nl) as f:
            f.write(nl.join(["arch: amd64", "hostname: Monitor", extra.rstrip(nl), f"tags: {tags}", "", "[snap1]", "tags: other", ""]))

    def run_fake(self, settings=None, stdin="a long root pw\na long root pw\n"):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls, script = self.fake_host(settings)
        r = subprocess.run([bash, script], input=stdin.encode(), capture_output=True, env=env, timeout=120)
        log = read(calls) if os.path.exists(calls) else ""
        return r, log

    def test_fake_install_runs_every_step(self):
        r, calls = self.run_fake()
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Your monitor is up and running", out)
        self.assertIn("http://192.168.1.51:8080", out)
        self.assertIn("Setup code", out)
        # Storage picked automatically: templates on local, the disk on local-lvm (preferred when present).
        create = next(l for l in calls.splitlines() if l.startswith("pct create"))
        self.assertIn("local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst", create)
        self.assertIn("-rootfs local-lvm:20", create)
        self.assertNotIn("hwaddr=", create)                      # blank MAC: Proxmox picks one
        self.assertIn("-timezone host", create)
        self.assertIn("-tags homelab-monitor", create)            # how --upgrade finds it later
        for phase in ("bootstrap.sh packages", "bootstrap.sh tools", "bootstrap.sh syncthing"):
            self.assertIn(phase, calls)
        # Neither the SNMP community nor the root password reaches the container on a command line.
        self.assertNotRegex(calls, r"pct exec[^\n]*public")
        self.assertNotIn("restore.sh --latest", calls)

    def test_fake_install_with_demo_data(self):
        """DEMO="yes": the seed runs as the monitor's own user after the web interface answers; a
        restore wins over demo data; anything but yes or no is refused."""
        r, calls = self.run_fake({"DEMO": '"yes"'})
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        seed = [l for l in calls.splitlines() if "demo.py seed" in l]
        self.assertEqual(len(seed), 1, calls)
        self.assertIn("runuser -u homelab-monitor", seed[0])
        self.assertIn("Settings, Demo data removes them", out)
        self.assertLess(calls.index("hostname -I"), calls.index("demo.py seed"))
        r, calls = self.run_fake({"DEMO": '"yes"', "RESTORE": '"latest"', "BACKUP_NFS": '"192.0.2.10:/Backups/Monitor"'})
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertNotIn("demo.py seed", calls)
        r, calls = self.run_fake({"DEMO": '"maybe"'})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("DEMO: yes or no", r.stderr.decode(errors="replace"))
        r, calls = self.run_fake()
        self.assertNotIn("demo.py seed", calls)

    def test_fake_install_with_chosen_storage_and_restore(self):
        r, calls = self.run_fake({"DISK_STORAGE": '"data"', "RESTORE": '"latest"',
                                  "BACKUP_NFS": '"192.0.2.10:/Backups/Monitor"', "IP_ADDRESS": '"192.168.1.60/24"',
                                  "GATEWAY": '"192.168.1.1"', "MAC_ADDRESS": '"02:00:00:00:00:01"'})
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        create = next(l for l in calls.splitlines() if l.startswith("pct create"))
        self.assertIn("-rootfs data:20", create)
        self.assertIn("ip=192.168.1.60/24,firewall=1,gw=192.168.1.1", create)
        self.assertIn("hwaddr=02:00:00:00:00:01", create)
        self.assertIn("restore.sh --latest", calls)

    def test_fake_install_refuses_bad_storage_and_existing_ct(self):
        r, calls = self.run_fake({"DISK_STORAGE": '"nope"'})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('Storage "nope" cannot hold container disks', r.stderr.decode(errors="replace"))
        self.assertNotIn("pct create", calls)
        r, _ = self.run_fake({"RESTORE": '"latest"'})
        self.assertIn("needs SYNCTHING_KEYS_NFS or BACKUP_NFS", r.stderr.decode(errors="replace"))
        # A container that already exists is never destroyed without --rebuild.
        env, calls_path, script = self.fake_host()
        with open(os.path.join(self.tmp, "ct-created"), "w"):
            pass
        r = subprocess.run([shutil.which("bash"), script], input=b"x\n", capture_output=True, env=env, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already exists", r.stderr.decode(errors="replace"))
        self.assertNotIn("destroy", read(calls_path))

    # ---- --local: no Proxmox, the machine the installer runs on is the target
    def fake_local(self, settings=None, os_release='ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n',
                   proxmox=False, installed=False):
        """No pct on PATH; every command meant for the target goes through hm-fake-local, which logs it."""
        fake = os.path.join(self.tmp, "fakelocal")
        shutil.rmtree(fake, ignore_errors=True)
        os.makedirs(fake)
        calls = os.path.join(self.tmp, "local-calls.log")
        state = os.path.join(self.tmp, "local-installed")
        for p in (calls, state, state + ".health"):
            if os.path.exists(p):
                os.remove(p)
        if installed:
            open(state, "w").close()
        q = lambda p: p.replace("\\", "/")
        stubs = {
            "hm-fake-local": f'''#!/usr/bin/env bash
echo "local $*" >> "{q(calls)}"
case "$*" in
  "test -f /etc/systemd/system/homelab-monitor.service") [[ -f "{q(state)}" ]] || exit 1 ;;
  *"hostname -I"*) echo "192.168.1.70" ;;
  *hm-precheck.sh\\ *) echo "OK|fake machine"; echo HM_CHECK_DONE ;;
  *"sitectl.py backup"*) echo "/var/lib/homelab-monitor/backups/pre-upgrade/monitor-backup-20261105-120000.tar.gz" ;;
  *bootstrap.sh\\ tools*) read -r c; echo "community received on stdin: ${{#c}} chars" ;;
  *"cat /var/lib/homelab-monitor/restored-from"*) exit 1 ;;
  *find-backups*) echo "/var/lib/homelab-monitor/backups/monitor-backup-20261108-033000.tar.gz|1794108600|1200000|0.5.0|key|this container" ;;
esac
exit 0
''',
            "apt-get": "#!/usr/bin/env bash\nexit 0\n",
            "systemctl": "#!/usr/bin/env bash\nexit 0\n",
        }
        if proxmox:
            stubs["pveversion"] = "#!/usr/bin/env bash\necho pve-manager/8.2.4\n"
        for name, body in stubs.items():
            path = os.path.join(fake, name)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(body)
            os.chmod(path, 0o755)
        osr = os.path.join(self.tmp, "os-release")
        with open(osr, "w", encoding="utf-8", newline="\n") as f:
            f.write(os_release)
        script = os.path.join(self.tmp, "infra-local.sh")
        text = self.text
        for k, v in (settings or {}).items():
            text = re.sub(rf'^{k}=.*$', f'{k}={v}', text, count=1, flags=re.M)
        with open(script, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        sep = ";" if os.name == "nt" else ":"
        # The real fakebin (pct, pveam, pvesm) is left off PATH: this machine is not a Proxmox host.
        path = sep.join(p for p in os.environ["PATH"].split(sep) if not p.rstrip("/\\").endswith("fakebin"))
        env = dict(os.environ, HM_FAKE_HOST="1", NO_COLOR="1", HM_FAKE_OS_RELEASE=q(osr), HM_HEALTH_TRIES="2",
                   PATH=fake + sep + path)
        return env, calls, script

    def run_local(self, *args, stdin="INSTALL\n", **kw):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls, script = self.fake_local(**kw)
        r = subprocess.run([bash, script, *args], input=stdin.encode(), capture_output=True, env=env, timeout=180)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        return r, out, read(calls) if os.path.exists(calls) else ""

    def test_local_install_skips_the_container(self):
        r, out, calls = self.run_local("--local", settings={"NTP_SERVER": '"192.168.1.1"'})
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("This machine becomes the monitor", out)
        self.assertIn("Your monitor is up and running", out)
        self.assertIn("http://192.168.1.70:8080", out)
        self.assertIn("Setup code", out)
        self.assertIn("--local --upgrade", out)
        self.assertNotIn("Root password", out)                  # no password asked: the machine's logins stay
        self.assertNotIn("pct ", calls)
        for step in ("bootstrap.sh packages", "bootstrap.sh syncthing", "install -m 0600", "systemctl enable --now"):
            self.assertIn(step, calls)
        # The tools phase knows it is --local (no SSH changes) and gets the LAN time server.
        self.assertRegex(calls, r"bootstrap\.sh tools +local 192\.168\.1\.1")
        self.assertNotIn("public", calls)                       # the SNMP community still goes on stdin
        self.assertIn('[[ "$target" == "local" ]] || pkgs+=(openssh-server)', self.text)

    def test_local_install_refusals(self):
        r, out, calls = self.run_local("--local", stdin="no\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Cancelled. Nothing was changed.", out)
        self.assertNotIn("bootstrap", calls)
        r, out, _ = self.run_local("--local", proxmox=True)
        self.assertIn("This is a Proxmox host", out)
        r, out, _ = self.run_local("--local", os_release='ID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04"\n')
        self.assertIn("22.04 or newer", out)
        r, out, _ = self.run_local("--local", os_release='ID=fedora\nVERSION_ID="40"\nPRETTY_NAME="Fedora 40"\n')
        self.assertIn("Debian 12 or newer", out)
        r, out, _ = self.run_local("--local", "--rebuild")
        self.assertEqual(r.returncode, 1)
        self.assertIn("with --local there is none", out)
        r, out, calls = self.run_local("--local", installed=True)
        self.assertIn("already installed on this machine", out)
        self.assertNotIn("bootstrap", calls)
        r, out, _ = self.run_local("--local", settings={"NTP_SERVER": '"1.2.3.4; reboot"'})
        self.assertIn("NTP_SERVER should be", out)
        # Without --local, a machine that is not a Proxmox host is pointed at --local.
        r, out, _ = self.run_local()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--local", out)

    def test_local_upgrade_and_check(self):
        r, out, calls = self.run_local("--local", "--check", installed=True)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("This machine can be upgraded in place", out)
        self.assertIn("--local --upgrade", out)
        self.assertNotIn("sitectl.py backup", calls)
        r, out, calls = self.run_local("--upgrade", "--local", installed=True)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Upgrading this machine", out)
        self.assertIn("Upgraded to", out)
        self.assertNotIn("pct ", calls)
        self.assertLess(calls.find("hm-precheck.sh"), calls.find("sitectl.py backup"))
        r, out, _ = self.run_local("--local", "--upgrade")
        self.assertIn("not installed on this machine", out)

    def test_update_here_uses_the_settings_recorded_on_the_box(self):
        """Update in the web page runs a clean release's home_monitor.sh on the box itself: the box's own
        settings (port, reach, target) apply, not the release's defaults, and the backup goes to pre-update."""
        r, out, calls = self.run_local("--update-here", stdin="", installed=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("No recorded settings", out)                  # never on the release's own defaults
        settings = os.path.join(self.tmp, "settings.env")
        with open(settings, "w", encoding="utf-8", newline="\n") as f:
            f.write('PORT="9090"\nTARGET="container"\nADMIN_NET="192.168.5.0/24"\nCTID="201"\nHOSTNAME="Monitor"\nEVIL="$(reboot)"\n')
        env, calls_path, script = self.fake_local(installed=True)
        env.update(HM_SETTINGS_ENV=settings.replace("\\", "/"), HM_UPDATE_BACKUP="pre-update")
        r = subprocess.run([shutil.which("bash"), script, "--update-here"], input=b"", capture_output=True, env=env, timeout=180)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        calls = read(calls_path)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Upgraded to", out)
        self.assertIn("--dest /var/lib/homelab-monitor/backups/pre-update", calls)
        self.assertIn("http://127.0.0.1:9090/api/auth/status", calls)   # the box's port, not 8080
        self.assertIn("hm-ingress.service", calls)                       # a container keeps its inbound firewall
        self.assertIn("hm-update.path", calls)
        self.assertNotIn("reboot", calls)                                # only known names are read
        self.assertFalse(any(l.startswith("pct ") for l in calls.splitlines()))

    def test_update_parts_are_in_the_build(self):
        b64 = self.text.split("\n__PAYLOAD_BEGIN__\n")[1].split("\n__PAYLOAD_END__")[0]
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b64)), mode="r:gz") as tar:
            names = tar.getnames()
            signers = tar.extractfile("release-signers").read().decode()
        self.assertIn("updatectl.py", names)
        self.assertIn('namespaces="home-monitor-release" ssh-ed25519 ', signers)
        # GitHub is reachable for root only; the app's own user stays offline.
        self.assertIn("meta skuid 0 ip daddr @github4 tcp dport 443 accept", self.text)
        self.assertIn("PathChanged=${DATA_DIR}/requests/update-install", self.text)
        self.assertIn("updatectl.py prune", self.text)

    def test_local_restore(self):
        r, out, calls = self.run_local("--local", "--restore", stdin="1" + chr(10) + "RESTORE" + chr(10), installed=True)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Restoring this machine", out)
        self.assertIn("Restored", out)
        self.assertIn("sitectl.py restore /root/hm-restore.tar.gz", calls)
        self.assertNotIn("pct ", calls)

    def run_upgrade(self, mode="--upgrade", stdin="", **env_extra):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls_path, script = self.fake_host()
        with open(os.path.join(self.tmp, "ct-created"), "w"):
            pass                                                # CT exists and runs
        if env_extra.pop("untagged", None) is None:
            self.tag_ct(201, "media;homelab-monitor")          # found by its tag among others
        env.update(HM_HEALTH_TRIES="2", **env_extra)
        r = subprocess.run([bash, script, mode], input=stdin.encode(), capture_output=True, env=env, timeout=180)
        return r, r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace"), (read(calls_path) if os.path.exists(calls_path) else "")

    def test_windows_line_endings_repair_themselves(self):
        # A copy with CTID edited on Windows: every line ended in CR and nothing ran.
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls_path, script = self.fake_host({"CTID": "305"})
        with open(script, "rb") as f:
            text = f.read()
        with open(script, "wb") as f:
            f.write(text.replace(b"\n", b"\r\n"))
        r = subprocess.run([bash, script, "--help"], capture_output=True, env=env, timeout=60)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Windows line endings", out)
        self.assertIn("./home_monitor.sh --upgrade", out)
        with open(script, "rb") as f:
            fixed = f.read()
        self.assertNotIn(b"\r", fixed)
        self.assertIn(b"\nCTID=305\n", fixed)                    # the edit survives the repair
        # And it then works for real: an upgrade check against the fake host.
        with open(os.path.join(self.tmp, "ct-created"), "w"):
            pass
        self.tag_ct(305)
        r = subprocess.run([bash, script, "--check"], capture_output=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace"))
        self.assertIn("pct exec 305", read(calls_path))

    def test_built_file_has_linux_line_endings(self):
        self.assertNotIn("\r", self.text)

    def test_upgrade_checks_backs_up_then_replaces(self):
        r, out, calls = self.run_upgrade()
        self.assertEqual(r.returncode, 0, out)
        order = [calls.find(x) for x in ("hm-precheck.sh /opt", "sitectl.py backup", "systemctl stop homelab-monitor",
                                         "is-active --quiet homelab-monitor", "LAYOUT=")]
        self.assertTrue(all(i >= 0 for i in order) and order == sorted(order), (order, calls))
        self.assertIn("Upgraded to", out)
        self.assertIn("pre-upgrade/monitor-backup-", out)
        self.assertNotIn("apt-get install", calls)              # nothing was missing

    def test_upgrade_without_the_tag_stops_and_says_how(self):
        r, out, calls = self.run_upgrade(untagged=True)
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("No container on this host has the tag homelab-monitor", out)
        self.assertIn('pct set $ID --tags "homelab-monitor${T:+;$T}"', out)
        self.assertEqual(calls, "")                                # nothing asked of Proxmox at all

    def test_upgrade_never_changes_the_container(self):
        r, out, calls = self.run_upgrade()
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("found by its tag: CT 201 (Monitor)", out)
        for verb in ("pct set", "pct resize", "pct create", "pct destroy"):
            self.assertNotIn(verb, calls)

    def test_install_refuses_a_second_monitor_without_a_person(self):
        env, calls_path, script = self.fake_host()
        self.tag_ct(150)
        r = subprocess.run([shutil.which("bash"), script], input=b"pw" + bytes([10]), capture_output=True, env=env, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already on this host: CT 150", r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace"))
        self.assertFalse(os.path.exists(calls_path) and "pct create" in read(calls_path))

    def test_rebuild_keeps_the_containers_own_settings(self):
        env, calls_path, script = self.fake_host({"CTID": "999", "CORES": "2", "MEMORY": "1024"})
        with open(os.path.join(self.tmp, "ct-created"), "w"):
            pass
        self.tag_ct(201, extra=chr(10).join(["cores: 4", "memory: 3072", "swap: 256", "rootfs: data:vm-201-disk-0,size=8G",
                              "net0: name=eth0,bridge=vmbr1,firewall=1,hwaddr=BC:24:11:00:00:01,ip=10.0.0.9/24,gw=10.0.0.1,type=veth"]))
        r = subprocess.run([shutil.which("bash"), script, "--rebuild"], input=chr(10).join(["REBUILD", "a long root pw", "a long root pw", ""]).encode(),
                           capture_output=True, env=env, timeout=120)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        create = next(l for l in read(calls_path).splitlines() if l.startswith("pct create"))
        self.assertTrue(create.startswith("pct create 201 "), create)   # the tagged one, not CTID 999 from the settings
        for part in ("-cores 4", "-memory 3072", "-swap 256", "-rootfs data:8",
                     "-net0 name=eth0,bridge=vmbr1,firewall=1,hwaddr=BC:24:11:00:00:01,ip=10.0.0.9/24,gw=10.0.0.1,type=veth"):
            self.assertIn(part, create)

    def test_check_only_changes_nothing(self):
        r, out, calls = self.run_upgrade("--check")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("can be upgraded in place", out)
        for change in ("sitectl.py backup", "systemctl stop", "pct push 201 /root/.hm-files", "apt-get"):
            self.assertNotIn(change, calls)

    def test_blocked_upgrade_says_rebuild_and_changes_nothing(self):
        r, out, calls = self.run_upgrade(HM_FAKE_PRECHECK="OK|Python 3.12\nBLOCK|Data: Written by a newer build\n")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("Written by a newer build", out)
        self.assertIn("cannot be upgraded in place", out)
        self.assertIn("--rebuild", out)
        for change in ("sitectl.py backup", "systemctl stop", "apt-get"):
            self.assertNotIn(change, calls)

    def test_missing_packages_are_installed_first(self):
        r, out, calls = self.run_upgrade(HM_FAKE_PRECHECK="FIX|nftables is missing|installs it\nPKG|nftables\n")
        self.assertEqual(r.returncode, 0, out)
        self.assertLess(calls.find("apt-get install -y -qq nftables"), calls.find("sitectl.py backup"))

    def test_failed_start_rolls_back(self):
        # The new version never answers (2 tries); the rolled-back one does.
        r, out, calls = self.run_upgrade(HM_FAKE_UNHEALTHY="2")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("Rolled back", out)
        self.assertIn("sitectl.py restore", calls)
        self.assertIn("/opt/homelab-monitor.old /opt/homelab-monitor", calls)
        self.assertNotIn("LAYOUT=", calls)                      # the marker is only written on success

    BACKUPS = chr(10).join([
        "/var/lib/homelab-monitor/backups/monitor-backup-20261108-033000.tar.gz|1794108600|1200000|0.5.0|key|this container",
        "/mnt/Syncthing/Monitor/monitor-backup-20261107-033000.tar.gz|1794022200|1100000|0.4.0|key|Syncthing folder",
        ""])
    CHANGES_TO_THE_CONTAINER = ("pct set", "pct resize", "pct create", "pct destroy", "pct stop")

    def test_restore_lists_the_backups_and_restores_the_one_picked(self):
        r, out, calls = self.run_upgrade("--restore", stdin="2" + chr(10) + "RESTORE" + chr(10), HM_FAKE_BACKUPS=self.BACKUPS)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("found by its tag: CT 201 (Monitor)", out)
        self.assertIn("Syncthing folder", out)
        self.assertIn("Restoring CT 201", out)                  # the same progress screen as an install
        self.assertIn("Restored", out)
        self.assertIn("monitor-backup-20261107-033000.tar.gz", out)
        # The picked path reaches the container as an argument, never inside a shell command.
        self.assertIn("pct exec 201 -- cp -- /mnt/Syncthing/Monitor/monitor-backup-20261107-033000.tar.gz /root/hm-restore.tar.gz", calls)
        self.assertNotIn("cp '", calls)
        order = [calls.find(x) for x in ("sitectl.py verify", "--dest /var/lib/homelab-monitor/backups/pre-restore",
                                         "find /var/lib/homelab-monitor -mindepth 1", "/root/.hm-app.tar.gz", "sitectl.py restore /root/hm-restore.tar.gz",
                                         "is-active --quiet homelab-monitor")]
        self.assertTrue(all(i >= 0 for i in order) and order == sorted(order), (order, calls))
        for verb in self.CHANGES_TO_THE_CONTAINER:
            self.assertNotIn(verb, calls)                        # only the files inside it change

    def test_restore_without_backups_stops_and_changes_nothing(self):
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "RESTORE" + chr(10), HM_FAKE_BACKUPS="")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("No backups were found", out)
        self.assertIn("pct push 201 monitor-backup-<date>.tar.gz", out)
        for change in ("-mindepth 1", "sitectl.py restore", "systemctl stop"):
            self.assertNotIn(change, calls)

    def test_restore_cancelled_or_refused_changes_nothing(self):
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "no" + chr(10), HM_FAKE_BACKUPS=self.BACKUPS)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Nothing done", out)
        self.assertNotIn("-mindepth 1", calls)
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "RESTORE" + chr(10), HM_FAKE_BACKUPS=self.BACKUPS, HM_FAKE_VERIFY_FAIL="1")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("The database in this backup is damaged. Nothing was changed.", out)
        for change in ("-mindepth 1", "sitectl.py restore", "systemctl stop"):
            self.assertNotIn(change, calls)

    def test_failed_restore_puts_the_old_data_back(self):
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "RESTORE" + chr(10), HM_FAKE_BACKUPS=self.BACKUPS, HM_FAKE_UNHEALTHY="2")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("Restore failed", out)
        self.assertIn("Put back", out)
        self.assertIn("sitectl.py restore " + self.tmp.replace(chr(92), "/") + "/data/backups/pre-upgrade/monitor-backup-20261104-120000.tar.gz", calls)

    def test_restore_shows_the_site_settings_and_asks_for_a_sealed_key(self):
        backups = self.BACKUPS.replace("|0.5.0|key|", "|0.7.0|sealed key|")
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "RESTORE" + chr(10) + "the backup passphrase" + chr(10),
                                         HM_FAKE_BACKUPS=backups,
                                         HM_FAKE_SITE="NFS: nas:/media on /mnt/media (ro,nosuid,nodev,noexec)\n!NFS mount 1 folder: a folder below /mnt or /srv\n")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("(passphrase)", out)
        self.assertIn("NFS: nas:/media on /mnt/media", out)
        self.assertIn("Refused, not applied: NFS mount 1 folder", out)
        self.assertIn("verify /root/hm-restore.tar.gz --passphrase-stdin", calls)
        self.assertIn("restore /root/hm-restore.tar.gz --data /var/lib/homelab-monitor --key /etc/homelab-monitor/vault.key --passphrase-stdin", calls)
        self.assertNotIn("the backup passphrase", calls)         # typed, passed on stdin, never on a command line

    def test_security_settings_on_a_new_container(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly000000000000000000000 admin@example"
        r, calls = self.run_fake({"ROOT_SSH_KEY": f'"{key}"', "ADMIN_NET": '"192.168.1.0/24 fd00::/8"', "UNPRIVILEGED": "1",
                                  "BACKUP_PASSPHRASE": '"a long backup passphrase"', "RESTORE": '"latest"',
                                  "SYNCTHING_KEYS_NFS": '"192.0.2.10:/Keys/Monitor"'})
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        create = next(l for l in calls.splitlines() if l.startswith("pct create"))
        self.assertIn("-unprivileged 1", create)
        self.assertIn("-features nesting=1 ", create)            # no mount=nfs: it cannot mount anyway
        self.assertIn("-ssh-public-keys", create)
        self.assertNotIn("-password", create)                     # set afterwards on stdin
        self.assertIn("-- chpasswd", calls)
        self.assertNotIn("a long root pw", calls)
        self.assertNotIn("a long backup passphrase", calls)
        self.assertRegex(calls, r"bootstrap\.sh tools .* key")
        # The host mounts the identity share read-only and copies the three files in.
        self.assertIn("host-mount -t nfs -o ro,nosuid,nodev,noexec 192.0.2.10:/Keys/Monitor", calls)
        self.assertIn("/root/.hm-stkeys/config.xml --perms 0600", calls)
        self.assertLess(calls.find("/root/.hm-stkeys/cert.pem"), calls.find("restore.sh --latest"))
        self.assertIn("Kind       unprivileged", out)
        self.assertIn("root with your key only", out)
        self.assertIn("from 192.168.1.0/24 fd00::/8", out)

    def test_bad_security_settings_are_refused(self):
        for k, v, msg in (("ADMIN_NET", '"192.168.1.0/24;reboot"', "ADMIN_NET"), ("ROOT_SSH_KEY", '"not a key"', "ROOT_SSH_KEY"),
                          ("BACKUP_PASSPHRASE", '"short"', "BACKUP_PASSPHRASE"), ("UNPRIVILEGED", "2", "UNPRIVILEGED")):
            r, calls = self.run_fake({k: v})
            self.assertNotEqual(r.returncode, 0, k)
            self.assertIn(msg, r.stderr.decode(errors="replace"))
            self.assertNotIn("pct create", calls)

    def test_inbound_firewall_rules(self):
        self.assertIn("type filter hook input priority 0; policy drop;", self.text)
        self.assertIn('tcp dport { 22, ${PORT} } accept', self.text)
        self.assertIn("update @ssh4 { ip saddr limit rate over 10/minute } drop", self.text)
        self.assertIn("th dport { 22000, 21027 } accept", self.text)
        self.assertIn("systemctl enable hm-ingress.service", self.text)

    def test_damaged_application_is_never_installed(self):
        env, calls_path, script = self.fake_host()
        text = read(script)
        head, rest = text.split("\n__PAYLOAD_BEGIN__\n", 1)
        body, tail = rest.split("\n__PAYLOAD_END__", 1)
        i = len(body) // 2
        body = body[:i] + ("A" if body[i] != "A" else "B") + body[i + 1:]
        with open(script, "w", encoding="utf-8", newline="\n") as f:
            f.write(head + "\n__PAYLOAD_BEGIN__\n" + body + "\n__PAYLOAD_END__" + tail)
        r = subprocess.run([shutil.which("bash"), script], input=b"a long root pw\na long root pw\n", capture_output=True, env=env, timeout=60)
        err = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue("does not match its checksum" in err or "is damaged" in err, err)
        self.assertNotIn("pct create", read(calls_path) if os.path.exists(calls_path) else "")

    def test_upgrade_uses_the_progress_screen(self):
        r, out, calls = self.run_upgrade()
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Upgrading CT 201 to", out)
        for step in ("ready", "copy", "check", "repair (skipped)", "backup", "replace", "health"):
            self.assertIn("... " + step, out)
        self.assertIn("What the check found", out)

    def test_settings_block_survives_rebuild(self):
        edited = self.text.replace('DISK_STORAGE=""', 'DISK_STORAGE="data"').replace("CTID=201", "CTID=305")
        # Drop one setting to see it come back with its default.
        edited = edited.replace('VLAN_TAG=""                   # blank for none\n', "")
        sys.path.insert(0, os.path.join(ROOT, "deploy"))
        import build
        template = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        merged = build.merge_settings(template, self.out + ".edited")
        self.assertEqual(merged, template)                       # no current file: template as is
        with open(self.out + ".edited", "w", encoding="utf-8") as f:
            f.write(edited)
        merged = build.merge_settings(template, self.out + ".edited")
        self.assertIn('DISK_STORAGE="data"', merged)
        self.assertIn("CTID=305", merged)
        self.assertIn('VLAN_TAG=""', merged)                     # missing setting added back
        self.assertIn("__PAYLOAD__", merged)                     # the rest is the fresh template


class SitectlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-sitectl-")
        self.data = os.path.join(self.tmp, "data")
        self.key = os.path.join(self.tmp, "key", "vault.key")
        os.makedirs(self.data)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_db(self, site=None):
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, description TEXT, updated_at INTEGER NOT NULL)")
        if site is not None:
            conn.execute("INSERT INTO settings VALUES ('site_settings', ?, '', 0)", (json.dumps(site),))
        # The restore checks it is a monitor database (settings and devices tables) before replacing anything.
        conn.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE, "
                     "profile_id TEXT NOT NULL, created_at INTEGER NOT NULL)")
        conn.execute("CREATE TABLE marker (v TEXT)")
        conn.execute("INSERT INTO marker VALUES ('original')")
        conn.commit()
        conn.close()

    def test_passphrase_key_round_trip(self):
        r = sitectl("derive-key", "--data", self.data, "--key", self.key, stdin="correct horse battery\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        first = read(self.key)
        # The server seals its check value with the derived key on first start.
        env = dict(os.environ, MONITOR_KEY_FILE=self.key)
        code = ("import sys; sys.path.insert(0, %r); from vault import Vault; v = Vault(); v.load(%r); "
                "print(v.enabled, v.error)") % (ROOT, self.data)
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "True None", out.stderr)
        os.remove(self.key)
        self.assertEqual(sitectl("derive-key", "--data", self.data, "--key", self.key, stdin="wrong passphrase!!\n").returncode, 2)
        self.assertEqual(sitectl("derive-key", "--data", self.data, "--key", self.key, stdin="correct horse battery\n").returncode, 0)
        self.assertEqual(read(self.key), first)          # same passphrase + stored salt = same key
        self.assertEqual(sitectl("derive-key", "--data", self.data, "--key", self.key, stdin="short\n").returncode, 1)

    def test_migrate_from_key_file_install(self):
        """Data sealed with a random key file (the Windows copy) moves to a passphrase key on first start."""
        old_key = os.path.join(self.tmp, "old", "vault.key")
        db = os.path.join(self.data, "monitor.db")
        seed = ("import sys, os; sys.path.insert(0, %r); import database, server; server.initialise(); "
                "database.add_credential('root', 'password', 'root', 'secret-pw-123'); print('seeded')") % ROOT
        env = dict(os.environ, MONITOR_DB_PATH=db, MONITOR_KEY_FILE=old_key)
        r = subprocess.run([sys.executable, "-c", seed], env=env, capture_output=True, text=True)
        self.assertIn("seeded", r.stdout, r.stderr)
        # Restore side: the old key beside the data, a new key derived from the passphrase.
        shutil.copy(old_key, os.path.join(self.data, "vault.key"))
        r = sitectl("derive-key", "--data", self.data, "--key", self.key, "--migrate", stdin="new container passphrase\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        check = ("import sys; sys.path.insert(0, %r); import database, server; server.initialise(); "
                 "c = database.list_credentials()[0]; print(database.get_credential_secret(c['id'])['secret'])") % ROOT
        env = dict(os.environ, MONITOR_DB_PATH=db, MONITOR_KEY_FILE=self.key)
        r = subprocess.run([sys.executable, "-c", check], env=env, capture_output=True, text=True)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "secret-pw-123", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.data, "vault.key")))    # old key removed after re-encryption
        # From now on the passphrase alone opens it.
        os.remove(self.key)
        self.assertEqual(sitectl("derive-key", "--data", self.data, "--key", self.key, stdin="new container passphrase\n").returncode, 0)

    def test_backup_restore(self):
        self.make_db({"syncthing": {"enabled": False}, "nfs": {"enabled": False}})
        with open(os.path.join(self.data, "vault.json"), "w") as f:
            json.dump({"salt": "c2FsdA==", "check": "enc1:x"}, f)
        os.makedirs(os.path.dirname(self.key))
        with open(self.key, "w") as f:
            f.write("the-real-key\n")
        dest = os.path.join(self.tmp, "backups")
        for _ in range(3):
            r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", dest, "--keep", "2")
            self.assertEqual(r.returncode, 0, r.stderr)
        archive = r.stdout.decode().strip()
        self.assertLessEqual(len(os.listdir(dest)), 2)
        with tarfile.open(archive) as tar:
            names = tar.getnames()
            manifest = json.load(tar.extractfile("manifest.json"))
        self.assertEqual(sorted(names), ["manifest.json", "monitor.db", "site.json", "vault.json", "vault.key"])
        self.assertTrue(manifest["includes_key"])
        # A rebuilt container has a different key: the restore puts the backup's key back.
        with open(self.key, "w") as f:
            f.write("a-new-containers-key\n")
        # Change the live data, then restore the backup over it.
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        conn.execute("UPDATE marker SET v = 'changed'")
        conn.commit()
        conn.close()
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key)
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT v FROM marker").fetchone()[0], "original")
        conn.close()
        self.assertEqual(read(self.key), "the-real-key\n")
        self.assertTrue(os.path.exists(os.path.join(self.data, "site-restored.json")))
        self.assertTrue(any(d.startswith("pre-restore-") for d in os.listdir(self.data)))

    def test_backup_goes_to_syncthing_folder(self):
        """The Syncthing folder from the database is used only when it passes the setup checks (below /mnt
        or /srv, no links); anything else, such as a folder a changed database names, gets the local folder."""
        import sitecheck
        self.assertEqual(sitecheck.folder("/mnt/Syncthing/Monitor/", "x"), "/mnt/Syncthing/Monitor")
        folder = os.path.join(self.tmp, "sync").replace("\\", "/")
        self.make_db({"syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": folder}})
        r = sitectl("backup", "--data", self.data)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.realpath(r.stdout.decode().strip()).startswith(os.path.realpath(os.path.join(self.data, "backups"))), r.stdout)
        self.assertIn("instead", r.stderr.decode())
        self.assertFalse(os.path.exists(folder))

    def test_old_backup_without_key(self):
        """A format 1 backup (no key) restores the data and leaves no key: restore.sh then asks once."""
        self.make_db({})
        dest = os.path.join(self.tmp, "old")
        r = sitectl("backup", "--data", self.data, "--dest", dest)
        archive = r.stdout.decode().strip()
        with tarfile.open(archive) as tar:
            self.assertNotIn("vault.key", tar.getnames())
        os.makedirs(os.path.dirname(self.key))
        with open(self.key, "w") as f:
            f.write("fresh-container-key\n")
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.key))
        kept = [d for d in os.listdir(self.data) if d.startswith("pre-restore-")]
        self.assertTrue(os.path.exists(os.path.join(self.data, kept[0], "vault.key")))

    def test_find_backups_everywhere_and_verify(self):
        """The installer's Restore lists backups from the container, Syncthing and any mounted share, newest first."""
        sync = os.path.join(self.tmp, "sync")
        share = os.path.join(self.tmp, "nas share")
        self.make_db({"syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": sync}})
        made = []
        for dest in (os.path.join(self.data, "backups", "pre-upgrade"), sync, os.path.join(share, "Monitor")):
            r = sitectl("backup", "--data", self.data, "--dest", dest)
            self.assertEqual(r.returncode, 0, r.stderr)
            made.append(r.stdout.decode().strip())
            time.sleep(1.1)                                     # distinct names and times
        mounts = os.path.join(self.tmp, "mounts")
        with open(mounts, "w", encoding="utf-8", newline=chr(10)) as f:
            f.write("/dev/sda1 / ext4 rw 0 0" + chr(10))
            f.write("nas:/share " + share.replace(" ", chr(92) + "040") + " nfs4 rw 0 0" + chr(10))
        r = sitectl("find-backups", "--data", self.data, "--mounts", mounts)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.decode().strip().splitlines()
        self.assertEqual(len(lines), 3, lines)
        paths = [l.split("|")[0] for l in lines]
        self.assertEqual([os.path.realpath(p) for p in paths], [os.path.realpath(p) for p in reversed(made)])
        fields = lines[0].split("|")
        self.assertEqual(fields[4], "no key")
        self.assertEqual(fields[5], "share nas:/share")
        self.assertIn("Syncthing folder", lines[1])
        self.assertIn("this container", lines[2])
        self.assertEqual(sitectl("verify", made[0]).returncode, 0)
        # Nothing found: no lines, still a clean exit (the installer says so and stops).
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        r = sitectl("find-backups", "--data", empty, "--mounts", mounts + ".none")
        self.assertEqual((r.returncode, r.stdout.decode().strip()), (0, ""))

    def test_verify_refuses_a_damaged_file(self):
        bad = os.path.join(self.tmp, "monitor-backup-20260101-000000.tar.gz")
        with open(bad, "wb") as f:
            f.write(b"not a tar file at all")
        r = sitectl("verify", bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cannot be read", r.stderr.decode())

    def test_restore_rejects_foreign_archives(self):
        evil = os.path.join(self.tmp, "evil.tar.gz")
        with tarfile.open(evil, "w:gz") as tar:
            info = tarfile.TarInfo("../../etc/passwd")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        r = sitectl("restore", evil, "--data", self.data)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a Homelab Monitor backup", r.stderr.decode())

    def test_apply_site_dry_run_and_fstab(self):
        fstab = os.path.join(self.tmp, "fstab")
        with open(fstab, "w") as f:
            f.write("UUID=x / ext4 defaults 0 1\nnas:/old /mnt/old nfs defaults 0 0\n")
        site = os.path.join(self.tmp, "site.json")
        with open(site, "w") as f:
            json.dump({"nfs": {"enabled": True, "mounts": [{"source": "nas:/old", "target": "/mnt/old", "options": "defaults"},
                                                           {"source": "nas:/media", "target": "/mnt/media", "options": "ro"}]},
                       "syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": "/mnt/Syncthing/Monitor"}}, f)
        r = sitectl("apply-site", site, "--fstab", fstab, "--dry-run")
        out = r.stdout.decode()
        self.assertEqual(r.returncode, 0, r.stderr)
        # An entry written before 0.7.0 gets nosuid, nodev and noexec; a new one has them from the start.
        self.assertIn("update", out)
        self.assertIn("nas:/old /mnt/old nfs defaults,nosuid,nodev,noexec 0 0", out)
        self.assertIn("add to", out)
        self.assertIn("nas:/media /mnt/media nfs ro,nosuid,nodev,noexec 0 0", out)
        self.assertIn("+ mount -t nfs -o ro,nosuid,nodev,noexec nas:/keys", out)
        self.assertIn("+ systemctl enable --now syncthing@syncthing", out)
        self.assertNotIn("/mnt/media", read(fstab))     # dry run writes nothing


    def test_find_backups_skips_names_a_shell_could_run(self):
        """A file on a share named to break out of a quoted command is never listed (it would be copied as root)."""
        self.make_db({})
        r = sitectl("backup", "--data", self.data, "--dest", os.path.join(self.data, "backups"))
        good = r.stdout.decode().strip()
        for evil in ("monitor-backup-x';touch pwned;'.tar.gz", "monitor-backup-$(id).tar.gz", "monitor-backup-a b.tar.gz"):
            try:
                shutil.copy(good, os.path.join(self.data, "backups", evil))
            except OSError:
                continue                                    # a name this file system cannot hold
        r = sitectl("find-backups", "--data", self.data, "--mounts", os.path.join(self.tmp, "none"))
        lines = r.stdout.decode().strip().splitlines()
        self.assertEqual([os.path.basename(l.split("|")[0]) for l in lines], [os.path.basename(good)])

    def test_sealed_key_backup(self):
        """With a backup passphrase the key travels sealed: the share alone opens nothing."""
        self.make_db({})
        os.makedirs(os.path.dirname(self.key))
        with open(self.key, "w") as f:
            f.write("the-real-key-0123456789\n")
        pf = os.path.join(self.tmp, "backup-passphrase")
        with open(pf, "w") as f:
            f.write("a long backup passphrase\n")
        dest = os.path.join(self.tmp, "b")
        r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", dest, "--passphrase-file", pf)
        self.assertEqual(r.returncode, 0, r.stderr)
        archive = r.stdout.decode().strip()
        with tarfile.open(archive) as tar:
            names = tar.getnames()
            manifest = json.load(tar.extractfile("manifest.json"))
            sealed = tar.extractfile("vault.key.sealed").read()
        self.assertNotIn("vault.key", names)
        self.assertTrue(manifest["key_sealed"])
        self.assertNotIn(b"the-real-key", sealed)
        r = sitectl("find-backups", "--data", self.data, "--also", dest, "--mounts", os.path.join(self.tmp, "none"))
        self.assertIn("|sealed key|", r.stdout.decode())
        none = os.path.join(self.tmp, "no-such-file")
        # No passphrase, or a wrong one: refused with 4 and nothing touched.
        self.assertEqual(sitectl("verify", archive, "--passphrase-file", none).returncode, 4)
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-stdin", stdin="wrong one\n")
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertEqual(read(self.key), "the-real-key-0123456789\n")
        with open(self.key, "w") as f:
            f.write("a-new-containers-key\n")
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-stdin", stdin="a long backup passphrase\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(self.key), "the-real-key-0123456789\n")

    def test_site_settings_are_checked_by_root(self):
        """What root applies is checked again: no system folders, no extra fstab lines, no exec or suid."""
        fstab = os.path.join(self.tmp, "fstab")
        with open(fstab, "w") as f:
            f.write("UUID=x / ext4 defaults 0 1\n")
        bad = [
            {"nfs": {"enabled": True, "mounts": [{"source": "nas:/x", "target": "/etc/cron.d"}]}},
            {"nfs": {"enabled": True, "mounts": [{"source": "nas:/x", "target": "/opt/homelab-monitor"}]}},
            {"nfs": {"enabled": True, "mounts": [{"source": "nas:/x", "target": "/mnt/a", "options": "defaults\nevil:/ /root nfs"}]}},
            {"nfs": {"enabled": True, "mounts": [{"source": "nas:/x\n/dev/sda1", "target": "/mnt/a"}]}},
            {"nfs": {"enabled": True, "mounts": [{"source": "nas:/x", "target": "/mnt/a", "options": "exec,suid"}]}},
            {"syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": "/usr/lib/systemd/system"}},
            {"syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": "/var"}},
            {"syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": "/mnt/../etc"}},
        ]
        site = os.path.join(self.tmp, "site.json")
        for raw in bad:
            with open(site, "w") as f:
                json.dump(raw, f)
            r = sitectl("apply-site", site, "--fstab", fstab)
            self.assertNotEqual(r.returncode, 0, raw)
            self.assertIn("refused", r.stderr.decode(), raw)
            self.assertEqual(read(fstab), "UUID=x / ext4 defaults 0 1\n")
        # site-of shows what a backup would apply, and marks what would be refused.
        self.make_db(bad[0])
        r = sitectl("backup", "--data", self.data, "--dest", os.path.join(self.tmp, "b"))
        out = sitectl("site-of", r.stdout.decode().strip()).stdout.decode()
        self.assertTrue(out.startswith("!"), out)

    def test_unprivileged_container_does_not_mount(self):
        site = os.path.join(self.tmp, "site.json")
        with open(site, "w") as f:
            json.dump({"nfs": {"enabled": True, "mounts": [{"source": "nas:/media", "target": "/mnt/media"}]}}, f)
        env = dict(os.environ, HM_FAKE_UNPRIVILEGED="1")
        r = subprocess.run([sys.executable, SITECTL, "apply-site", site, "--dry-run"], capture_output=True, env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pct set <CT> -mp0", r.stderr.decode())
        with open(site, "w") as f:
            json.dump({"syncthing": {"enabled": True, "keys_source": "nas:/keys", "data_folder": "/mnt/Syncthing/Monitor"}}, f)
        r = subprocess.run([sys.executable, SITECTL, "apply-site", site, "--dry-run"], capture_output=True, env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SYNCTHING_KEYS_NFS", r.stderr.decode())

    def test_syncthing_config_is_checked(self):
        import sitecheck
        home = "/var/lib/syncthing"
        ok = (b'<configuration version="37"><folder id="m" path="/mnt/Syncthing/Monitor"></folder>'
              b'<gui enabled="true"><address>0.0.0.0:8384</address></gui></configuration>')
        out = sitecheck.check_syncthing_config(ok, "/mnt/Syncthing/Monitor", home)
        self.assertIn(b"127.0.0.1:8384", out)                         # no login: the web interface stays local
        login = ok.replace(b"</address>", b"</address><user>me</user><password>$2a$hash</password>")
        self.assertEqual(sitecheck.check_syncthing_config(login, "/mnt/Syncthing/Monitor", home), login)
        for bad in (ok.replace(b"/mnt/Syncthing/Monitor", b"/etc/systemd/system"),
                    ok.replace(b"/mnt/Syncthing/Monitor", b"/mnt/Syncthing/Monitor/../../../root"),
                    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>' + ok,
                    b"not xml"):
            with self.assertRaises(sitecheck.SiteError):
                sitecheck.check_syncthing_config(bad, "/mnt/Syncthing/Monitor", home)

    def test_result_file_is_not_written_through_a_link(self):
        """Root writes DATA/<kind>.result.json; a link the app user put there is replaced, its target untouched."""
        self.make_db({})
        target = os.path.join(self.tmp, "precious")
        with open(target, "w") as f:
            f.write("keep me\n")
        link = os.path.join(self.data, "backup.result.json")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links need extra rights on this system")
        r = sitectl("backup", "--data", self.data, "--dest", os.path.join(self.tmp, "b"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(target), "keep me\n")
        self.assertFalse(os.path.islink(link))
        self.assertTrue(json.loads(read(link))["ok"])


if __name__ == "__main__":
    unittest.main()
