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


def read_bytes(path):
    with open(path, "rb") as f:
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

    def test_recovery_runs_at_boot_never_during_an_update(self):
        """hm-update-recover is installed and enabled for boot, before the monitor; it is never started
        while installing (an update from the app runs that very code)."""
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        unit = tpl.split('cat > "$FILES/hm-update-recover.service" <<UNIT')[1].split("\nUNIT\n")[0]
        self.assertIn("Before=homelab-monitor.service hm-update.path", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertIn("hm-update-recover.service /etc/systemd/system/", tpl)
        self.assertIn("install -m 0700 update-recover.sh /root/.hm-update-recover.sh", tpl)
        self.assertIn("systemctl enable hm-update-recover.service", tpl)
        self.assertNotRegex(tpl, r"(enable --now|start|restart)[^\n]*hm-update-recover")

    def test_settings_folder_made_before_use(self):
        """Upgrading an install from before 0.8.0: the folder exists before settings.env goes into it."""
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        body = tpl.split("files_into_place() {")[1].split("\n}\n")[0]
        self.assertLess(body.index("install -d -m 0750 -o root -g ${SERVICE_USER} ${INSTALL_DIR}"),
                        body.index("${INSTALL_DIR}/settings.env"))

    def test_unit_has_limits(self):
        """The monitor's service has memory and task limits and one restart pause."""
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        unit = tpl.split('cat > "$FILES/homelab-monitor.service" <<UNIT')[1].split("\nUNIT\n")[0]
        for line in ("MemoryHigh=640M", "MemoryMax=768M", "TasksMax=512"):
            self.assertIn("\n" + line + "\n", unit)
        self.assertEqual(unit.count("RestartSec="), 1)


    def test_reset_admin_asks_only_when_required(self):
        """reset-admin.sh asks about the rule only while sitectl says 2FA is required, and passes the
        answer on as --no-2fa-rule."""
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        script = tpl.split('cat > "$FILES/reset-admin.sh" <<"EOF"')[1].split("\nEOF\n")[0]
        ask = script.index("Also stop requiring 2FA for everyone on this monitor")
        guard = script.rindex('if [[ "$(python3 "$APP/sitectl.py" require-2fa --data "$DATA" 2>/dev/null)" != "off" ]]; then', 0, ask)
        self.assertLess(guard, ask)
        self.assertIn("extra+=(--no-2fa-rule)", script)
        self.assertLess(script.index("extra+=(--no-2fa-rule)"), script.index('reset-password --data "$DATA" --user "$name" "${extra[@]}"'))
        self.assertIn("2FA is no longer required. Turn it on again in Settings, Users and sign-in.", script)

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
        # The kind, a pasted key and ACCEPT are asked only of a person at a terminal (MUST-2 tests below).
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
          # check-auth: HM_FAKE_AUTH_PASS asks for a passphrase first (4); HM_FAKE_AUTH=7 or 8 answers that
          # until the matching word was typed (the flag comes back with the next check).
          *"sitectl.py check-auth"*)
            if [[ -n "${{HM_FAKE_AUTH_PASS-}}" && "$*" != *--passphrase-stdin* ]]; then echo "HM_AUTH=needs-passphrase"; exit 4; fi
            if [[ "${{HM_FAKE_AUTH-}}" == 7 && "$*" != *--accept-unverified* ]]; then
              printf 'This backup cannot be proven unchanged.\nAccounts in it:\n  admin  admin\nStored credentials in it: 2\nHM_AUTH=unverified\n'; exit 7; fi
            if [[ "${{HM_FAKE_AUTH-}}" == 8 && "$*" != *--forget-secrets* ]]; then
              printf 'This backup does not carry the key that opens its stored passwords.\nHM_AUTH=no-key\n'; exit 8; fi
            echo "HM_AUTH=verified" ;;
          *sha256sum*) echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ${{@: -1}}" ;;
          *"test -f /etc/homelab-monitor-install/backup-passphrase"*) [[ -z "${{HM_FAKE_NO_PASSPHRASE-}}" ]] || exit 1 ;;
          *"sitectl.py site-of"*) printf '%b' "${{HM_FAKE_SITE-}}" ;;
          # The upgrade reads the container's own sshd_config: HM_FAKE_SSH_PW says root may use a password.
          *"PermitRootLogin"*) [[ -n "${{HM_FAKE_SSH_PW-}}" ]] || exit 1 ;;
          # The box's own record, and the inbound firewall's check, load and state.
          *"cat /etc/homelab-monitor-install/settings.env"*) printf '%b' "${{HM_FAKE_SETTINGS-}}" ;;
          *"nft -c -f"*) [[ -n "${{HM_FAKE_NFT_FAIL-}}" ]] && exit 1 ;;
          *"restart hm-ingress"*) [[ -n "${{HM_FAKE_INGRESS_FAIL-}}" ]] && exit 1 ;;
          *"is-active --quiet hm-ingress"*) [[ -n "${{HM_FAKE_INGRESS_ACTIVE-}}" ]] || exit 1 ;;
        esac ;;
  push) [[ "$4" == /root/.hm-files.tgz && -n "${{HM_FAKE_KEEP_FILES-}}" ]] && cp "$3" "$HM_FAKE_KEEP_FILES" ;;
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

    def run_fake(self, settings=None, stdin="a long root pw\na long root pw\n", args=(), **env_extra):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls, script = self.fake_host(settings)
        env.update(env_extra)
        r = subprocess.run([bash, script, *args], input=stdin.encode(), capture_output=True, env=env, timeout=180)
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
        # Privileged stays the default, and both warnings are printed (nobody is asked on a pipe).
        self.assertIn("-unprivileged 0", create)
        self.assertIn("-features nesting=1,mount=nfs", create)
        self.assertIn("This container is privileged.", out)
        self.assertIn("Root can log in to the container over SSH with a password.", out)
        self.assertIn("root@192.168.1.51 with the container password you just set", out)
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

    def test_report_from_the_host(self):
        """--report finds the tagged container, copies this build's report.py in, runs it as root with the
        journal, removes it again and saves the output beside the file; nothing else is changed."""
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls_path, script = self.fake_host()
        self.tag_ct(201)
        open(os.path.join(self.tmp, "ct-created"), "w").close()      # the stub's pct status: running
        r = subprocess.run([bash, script, "--report"], capture_output=True, env=env, timeout=120, cwd=self.tmp)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        calls = read(calls_path)
        self.assertIn("pct push 201", calls)
        self.assertIn("/root/.hm-report.py", calls)
        run = next(l for l in calls.splitlines() if "hm-report.py --db" in l)
        self.assertIn("--journal", run)
        self.assertIn("rm -f /root/.hm-report.py", calls)
        self.assertNotIn("pct create", calls)
        self.assertNotIn("systemctl stop", calls)
        self.assertIn("issues/new", out)
        saved = [n for n in os.listdir(self.tmp) if n.startswith("home-monitor-report-")]
        self.assertEqual(len(saved), 1)

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
  "install -m 0600 "*.hm-files.tgz) [[ -n "${{HM_FAKE_KEEP_FILES-}}" ]] && cp "$4" "$HM_FAKE_KEEP_FILES" ;;
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
        self.assertIn("--dest /var/lib/homelab-monitor-safe/pre-update", calls)
        # Root records the copy for Undo (path and checksum) in its own folder.
        self.assertRegex(calls, r"updatectl\.py note-backup --data /var/lib/homelab-monitor --file \S+monitor-backup-\S+ --to ")
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

    def run_upgrade(self, mode="--upgrade", stdin="", ct_extra="", settings=None, **env_extra):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        env, calls_path, script = self.fake_host(settings)
        with open(os.path.join(self.tmp, "ct-created"), "w"):
            pass                                                # CT exists and runs
        if env_extra.pop("untagged", None) is None:
            self.tag_ct(201, "media;homelab-monitor", extra=ct_extra)   # found by its tag among others
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
        self.assertIn("pct exec 201 -- python3 /root/.hm-new/sitectl.py take /mnt/Syncthing/Monitor/monitor-backup-20261107-033000.tar.gz "
                      "--to /root/hm-restore.tar.gz", calls)
        self.assertNotIn("cp '", calls)
        order = [calls.find(x) for x in ("sitectl.py take", "sitectl.py check-auth", "sitectl.py verify",
                                         "--dest /var/lib/homelab-monitor-safe/pre-restore",
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
        # The passphrase is asked when the check needs it, before RESTORE is typed.
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "the backup passphrase" + chr(10) + "RESTORE" + chr(10),
                                         HM_FAKE_BACKUPS=backups, HM_FAKE_AUTH_PASS="1",
                                         HM_FAKE_SITE="NFS: nas:/media on /mnt/media (ro,nosuid,nodev,noexec)\n!NFS mount 1 folder: a folder below /mnt or /srv\n")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("(passphrase)", out)
        self.assertIn("NFS: nas:/media on /mnt/media", out)
        self.assertIn("Refused, not applied: NFS mount 1 folder", out)
        self.assertIn("check-auth /root/hm-restore.tar.gz --key /etc/homelab-monitor/vault.key --passphrase-stdin", calls)
        self.assertIn("verify /root/hm-restore.tar.gz --key /etc/homelab-monitor/vault.key --passphrase-stdin", calls)
        self.assertIn("restore /root/hm-restore.tar.gz --data /var/lib/homelab-monitor --key /etc/homelab-monitor/vault.key "
                      "--record-name monitor-backup-20261108-033000.tar.gz --passphrase-stdin", calls)
        self.assertNotIn("the backup passphrase", calls)         # typed, passed on stdin, never on a command line

    def test_interactive_restore_requires_typed_word(self):
        """A backup that cannot be proven unchanged: the accounts in it are shown before any question,
        and only UNVERIFIED typed lets it through. FORGET likewise for a backup with no usable key."""
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "RESTORE" + chr(10), HM_FAKE_BACKUPS=self.BACKUPS,
                                         HM_FAKE_AUTH="7")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Accounts in it", out)
        self.assertIn("Nothing done", out)
        for change in ("-mindepth 1", "sitectl.py restore", "systemctl stop", "sitectl.py verify"):
            self.assertNotIn(change, calls)
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "UNVERIFIED" + chr(10) + "RESTORE" + chr(10),
                                         HM_FAKE_BACKUPS=self.BACKUPS, HM_FAKE_AUTH="7")
        self.assertEqual(r.returncode, 0, out)
        self.assertLess(out.index("Accounts in it"), out.index("Restoring CT 201"))
        self.assertRegex(calls, r"sitectl\.py verify /root/hm-restore\.tar\.gz [^\n]*--accept-unverified")
        self.assertRegex(calls, r"sitectl\.py restore /root/hm-restore\.tar\.gz [^\n]*--accept-unverified")
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "FORGET" + chr(10) + "RESTORE" + chr(10),
                                         HM_FAKE_BACKUPS=self.BACKUPS, HM_FAKE_AUTH="8")
        self.assertEqual(r.returncode, 0, out)
        self.assertRegex(calls, r"sitectl\.py restore /root/hm-restore\.tar\.gz [^\n]*--forget-secrets")

    def test_safety_copies_go_to_roots_folder(self):
        """Upgrade: the copy made before is root's own, with its checksum; putting it back checks it."""
        r, out, calls = self.run_upgrade()
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("--dest /var/lib/homelab-monitor-safe/pre-upgrade --keep 3 --safety", calls)
        self.assertNotIn("passphrase-before", calls)
        self.assertNotIn("chmod 0700 /var/lib/homelab-monitor/backups", calls)
        r, out, calls = self.run_upgrade(HM_FAKE_UNHEALTHY="2")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("--expect-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", calls)
        # The installer's Restore: what is there now goes to root's folder too, and comes back checked.
        r, out, calls = self.run_upgrade("--restore", stdin="1" + chr(10) + "RESTORE" + chr(10), HM_FAKE_BACKUPS=self.BACKUPS,
                                         HM_FAKE_UNHEALTHY="2")
        self.assertIn("--dest /var/lib/homelab-monitor-safe/pre-restore --keep 3 --safety", calls)
        self.assertRegex(calls, r"sitectl\.py restore \S+/pre-upgrade/monitor-backup-\S+ [^\n]*--expect-sha256 [0-9a-f]{64}")

    def test_no_passphrase_note_at_the_end(self):
        r, out, calls = self.run_upgrade(HM_FAKE_NO_PASSPHRASE="1")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("No backup passphrase is set", out)
        self.assertIn("/root/backup-passphrase.sh", out)
        r, out, calls = self.run_upgrade()
        self.assertNotIn("No backup passphrase is set", out)

    def test_restore_latest_override_setting(self):
        """RESTORE_UNVERIFIED is passed to restore.sh for that one run only; anything but yes or no is refused."""
        r, calls = self.run_fake({"RESTORE": '"latest"', "BACKUP_NFS": '"192.0.2.10:/Backups/Monitor"'})
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertIn("env HM_RESTORE_UNVERIFIED=0 /root/restore.sh --latest", calls)
        r, calls = self.run_fake({"RESTORE": '"latest"', "BACKUP_NFS": '"192.0.2.10:/Backups/Monitor"', "RESTORE_UNVERIFIED": '"yes"'})
        self.assertIn("env HM_RESTORE_UNVERIFIED=1 /root/restore.sh --latest", calls)
        r, calls = self.run_fake({"RESTORE_UNVERIFIED": '"maybe"'})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RESTORE_UNVERIFIED: yes or no", r.stderr.decode(errors="replace"))
        recorded = next(l for l in self.text.splitlines() if l.strip().startswith("for name in CTID HOSTNAME PORT"))
        self.assertNotIn("RESTORE_UNVERIFIED", recorded)           # never kept on the box: one run only

    def test_passphrase_helper_is_installed(self):
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        self.assertIn("backup-passphrase.sh /root/", tpl)
        self.assertIn("7) /root/backup-passphrase.sh ;;", tpl)
        helper = tpl.split('cat > "$FILES/backup-passphrase.sh" <<"EOF"')[1].split("\nEOF\n")[0]
        self.assertIn("set -Eeuo pipefail", helper)
        self.assertIn("read -rsp", helper)                      # hidden
        self.assertIn('printf \'%s\\n\' "$p1" | python3 "$APP/sitectl.py" set-passphrase', helper)   # on stdin
        self.assertIn("/root/backup.sh", helper)                # the first sealed backup straight away
        self.assertIn("-/var/lib/homelab-monitor-safe", tpl)    # the backup unit may prune root's folder

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
        # The last screen says how root really logs in; neither warning applies.
        self.assertIn("with your SSH key only", out)
        self.assertNotIn("container password you just set", out)
        self.assertNotIn("over SSH with a password", out)
        self.assertNotIn("This container is privileged", out)

    # ---- MUST-2: the container's kind and root SSH. HM_TEST_ASK=1 lets the questions read this pipe.
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly000000000000000000000 admin@example"
    PW = "a long root pw\na long root pw\n"

    @staticmethod
    def output(r):
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")

    def created(self, calls):
        return next(l for l in calls.splitlines() if l.startswith("pct create"))

    def test_interactive_privileged_warns_and_needs_the_word(self):
        r, calls = self.run_fake(stdin="\n\nACCEPT\n" + self.PW, HM_TEST_ASK="1")
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("What kind of container?", out)
        self.assertIn("2  Unprivileged (safer;", out)
        self.assertIn("This container is privileged.", out)
        self.assertIn("close to root on this Proxmox host", out)
        self.assertIn("Root can log in to the container over SSH with a password.", out)
        self.assertIn("It is allowed from: every private address.", out)
        self.assertIn("MaxAuthTries 3", out)
        create = self.created(calls)
        self.assertIn("-unprivileged 0", create)
        self.assertIn("mount=nfs", create)
        # Anything but ACCEPT stops before the container is made.
        r, calls = self.run_fake(stdin="\n\nno\n" + self.PW, HM_TEST_ASK="1")
        out = self.output(r)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Cancelled. Nothing was changed.", out)
        self.assertNotIn("pct create", calls)

    def test_choosing_unprivileged(self):
        r, calls = self.run_fake(stdin="2\n\nACCEPT\n" + self.PW, HM_TEST_ASK="1")
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        create = self.created(calls)
        self.assertIn("-unprivileged 1", create)
        self.assertIn("-features nesting=1 ", create)
        self.assertNotIn("mount=nfs", create)
        self.assertNotIn("This container is privileged", out)
        self.assertIn("Kind       unprivileged", out)

    def test_kind_preselected_from_the_setting(self):
        r, calls = self.run_fake({"UNPRIVILEGED": "1"}, stdin="\n\nACCEPT\n" + self.PW, HM_TEST_ASK="1")
        self.assertEqual(r.returncode, 0, self.output(r))
        self.assertIn("-unprivileged 1", self.created(calls))

    def test_pasted_key_means_prohibit_password(self):
        # Unprivileged and a key: neither warning is left, so no ACCEPT is asked (the passwords come next).
        r, calls = self.run_fake(stdin="2\n" + self.KEY + "\n" + self.PW, HM_TEST_ASK="1")
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Root will log in over SSH with that key only.", out)
        self.assertIn("-ssh-public-keys", self.created(calls))
        self.assertRegex(calls, r"bootstrap\.sh tools .* key")
        self.assertIn("with your SSH key only (password logins over SSH are off)", out)
        self.assertNotIn("container password you just set", out)
        # The bootstrap's sshd line: prohibit-password with a key, yes without.
        line = next(l.strip() for l in self.text.splitlines() if l.strip().startswith('login="yes";'))
        for arg, want in (("key", "prohibit-password"), ("", "yes")):
            r = subprocess.run([shutil.which("bash"), "-c", f'set -- tools "" container "" "{arg}"; {line}; printf %s "$login"'],
                               capture_output=True, text=True)
            self.assertEqual(r.stdout, want)

    def test_bad_paste_asks_again(self):
        r, calls = self.run_fake(stdin="\nnot a key\n\nACCEPT\n" + self.PW, HM_TEST_ASK="1")
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("That is not a public key line", out)
        self.assertNotIn("-ssh-public-keys", self.created(calls))

    def test_non_interactive_prints_and_never_asks(self):
        for env in ({}, {"HM_TEST_ASK": "1", "HM_NO_ASK": "1"}):
            r, calls = self.run_fake(**env)
            out = self.output(r)
            self.assertEqual(r.returncode, 0, out)
            self.assertNotIn("What kind of container?", out)
            self.assertIn("This container is privileged.", out)
            self.assertIn("Set UNPRIVILEGED=1 at the top of this file to use it.", out)
            self.assertIn("Root can log in to the container over SSH with a password.", out)
            self.assertIn("Security  Privileged container: root in it is close to root on the Proxmox host.", out)
            self.assertIn("Security  Root can log in over SSH with a password from every private address.", out)
            # The warnings are in the install log too.
            log = re.search(r"Log\s+(/\S+\.log)", out).group(1)
            text = subprocess.run([shutil.which("bash"), "-c", 'cat -- "$1"', "_", log], capture_output=True, text=True).stdout
            self.assertIn("This container is privileged.", text)
            self.assertIn("over SSH with a password", text)

    def test_rebuild_keeps_an_unprivileged_container(self):
        env, calls_path, script = self.fake_host()
        open(os.path.join(self.tmp, "ct-created"), "w").close()
        self.tag_ct(201, extra="unprivileged: 1")
        r = subprocess.run([shutil.which("bash"), script, "--rebuild"], input=("REBUILD\n" + self.PW).encode(),
                           capture_output=True, env=env, timeout=180)
        self.assertEqual(r.returncode, 0, self.output(r))
        create = self.created(read(calls_path))
        self.assertIn("-unprivileged 1", create)
        self.assertIn("-features nesting=1 ", create)

    def test_rebuild_asks_the_kind(self):
        env, calls_path, script = self.fake_host()
        open(os.path.join(self.tmp, "ct-created"), "w").close()
        self.tag_ct(201)
        env["HM_TEST_ASK"] = "1"
        r = subprocess.run([shutil.which("bash"), script, "--rebuild"], input=("2\n\nACCEPT\nREBUILD\n" + self.PW).encode(),
                           capture_output=True, env=env, timeout=180)
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("What kind of container?", out)
        create = self.created(read(calls_path))
        self.assertTrue(create.startswith("pct create 201 "), create)
        self.assertIn("-unprivileged 1", create)

    def test_upgrade_warns_without_asking(self):
        r, out, calls = self.run_upgrade(HM_FAKE_SSH_PW="1")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("This container is privileged.", out)
        self.assertIn("then run --rebuild with RESTORE=\"latest\"", out)
        self.assertIn("Root can log in to the container over SSH with a password.", out)
        self.assertIn("Then run the upgrade again: password logins over SSH are switched off.", out)
        self.assertNotIn("What kind of container?", out)
        r, out, calls = self.run_upgrade(ct_extra="unprivileged: 1")
        self.assertEqual(r.returncode, 0, out)
        self.assertNotIn("This container is privileged", out)
        self.assertNotIn("over SSH with a password", out)

    def test_preview_shows_the_warnings(self):
        r, calls = self.run_fake(args=("--preview",))
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("This container is privileged.", out)
        self.assertIn("Root can log in to the container over SSH with a password.", out)
        self.assertNotIn("pct create", calls)

    # ---- REV-07: strict networks, the firewall checked before it is used, the box's own settings kept.
    def keep_files(self):
        """A path the stubs copy the files bundle to; returns (env addition, reader of one file in it)."""
        path = os.path.join(self.tmp, "kept-files.tgz")
        if os.path.exists(path):
            os.remove(path)

        def member(name):
            with tarfile.open(path, "r:gz") as tar:
                return tar.extractfile("./" + name).read().decode()
        return {"HM_FAKE_KEEP_FILES": path.replace("\\", "/")}, member

    def test_net_checks(self):
        block = self.text.split("# >>> net checks\n")[1].split("# <<< net checks")[0]
        good = ["192.168.1.0/24", "10.1.2.3", "0.0.0.0/0", "fd00::/8", "::1", "::", "1:2:3:4:5:6:7:8", "fe80::1/64", "192.168.1.5/24"]
        bad = ["999.1.1.1", "1.2.3", "10.0.0.0/33", "010.0.0.1", "1.2.3.4/", "fd00::/129", ":::", "1::2::3", "1:2:3", "12345::1",
               ":1::", "1.2.3.4;reboot", "*", "1:2:3:4:5:6:7:8:9"]
        # On stdin: bash started from Windows would expand a * among its arguments.
        script = block + 'while IFS= read -r v; do if valid_net "$v"; then echo "good $v"; else echo "bad $v"; fi; done\n'
        r = subprocess.run([shutil.which("bash"), "-c", script], input=("\n".join(good + bad) + "\n").encode(), capture_output=True)
        self.assertEqual(r.stdout.decode().splitlines(), [f"good {v}" for v in good] + [f"bad {v}" for v in bad], r.stderr)
        r = subprocess.run([shutil.which("bash"), "-c", block + 'net_words "$1"', "_", "10.0.0.0/8, fd00::/8  192.168.1.1"],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.splitlines(), ["10.0.0.0/8", "fd00::/8", "192.168.1.1"])

    def test_snmp_allow_ipv6_goes_under_ip6_saddr(self):
        extra, member = self.keep_files()
        r, calls = self.run_fake({"SNMP_ALLOW": '"192.168.1.5,fd00::/8"'}, **extra)
        self.assertEqual(r.returncode, 0, self.output(r))
        rules = member("ingress.nft")
        self.assertIn("    ip saddr { 192.168.1.5 } udp dport 161 accept", rules)
        self.assertIn("    ip6 saddr { fd00::/8 } udp dport 161 accept", rules)
        self.assertNotRegex(rules, r"ip saddr \{[^}]*:")
        self.assertIn('SNMP_ALLOW="192.168.1.5 fd00::/8"', member("settings.env"))      # commas made spaces
        self.assertIn("bootstrap.sh tools 192.168.1.5 fd00::/8 container", calls)
        self.assertIn('echo "rocommunity6 ${community} ${net} -V hmmonitor"', self.text)
        self.assertIn('agent="udp:161,udp6:161"', self.text)

    def test_rules_checked_before_enabling(self):
        r, calls = self.run_fake()
        self.assertEqual(r.returncode, 0, self.output(r))
        self.assertIn("install -m 0644 ingress.nft /etc/homelab-monitor-egress/ingress.nft.new", calls)
        order = [calls.find(x) for x in ("nft -c -f /etc/homelab-monitor-egress/ingress.nft.new",
                                         "mv -f /etc/homelab-monitor-egress/ingress.nft.new /etc/homelab-monitor-egress/ingress.nft",
                                         "systemctl enable hm-ingress.service", "systemctl restart hm-ingress.service")]
        self.assertTrue(all(i >= 0 for i in order) and order == sorted(order), (order, calls))

    def test_failed_check_never_says_up_and_running(self):
        r, calls = self.run_fake(HM_FAKE_NFT_FAIL="1")
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Running, but the inbound firewall is NOT active", out)
        self.assertIn("Check ADMIN_NET and SNMP_ALLOW at the top of this file", out)
        self.assertNotIn("up and running", out)
        self.assertNotIn("restart hm-ingress", calls)

    def test_failed_load_never_says_up_and_running(self):
        r, calls = self.run_fake(HM_FAKE_INGRESS_FAIL="1")
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("inbound firewall is NOT active", out)
        self.assertNotIn("up and running", out)

    def test_upgrade_with_failed_firewall(self):
        r, out, calls = self.run_upgrade(HM_FAKE_INGRESS_FAIL="1")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("inbound firewall NOT active", out)
        self.assertNotIn("and answering", out)
        r, out, calls = self.run_upgrade(HM_FAKE_NFT_FAIL="1", HM_FAKE_INGRESS_ACTIVE="1")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("and answering", out)
        self.assertIn("previous rules are still in force", out)
        self.assertNotIn("restart hm-ingress", calls)

    RECORD = 'ADMIN_NET="192.168.1.0/24"\\nSNMP_ALLOW="192.168.1.9"\\nSSH_KEY_LINE="{key}"\\nUNPRIVILEGED="0"\\n'

    def record(self, **over):
        rec = self.RECORD.format(key=self.KEY)
        for k, v in over.items():
            rec = re.sub(rf'{k}="[^"]*"', f'{k}="{v}"', rec)
        return rec

    def test_upgrade_blank_keeps_the_record_silently(self):
        extra, member = self.keep_files()
        r, out, calls = self.run_upgrade(HM_FAKE_SETTINGS=self.record(), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("ip saddr { 192.168.1.0/24 } tcp dport { 22, 8080 } accept", member("ingress.nft"))
        self.assertNotIn("10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport", member("ingress.nft"))
        env = member("settings.env")
        self.assertIn('ADMIN_NET="192.168.1.0/24"', env)
        self.assertIn('SSH_KEY_LINE="' + self.KEY + '"', env)
        self.assertIn(self.KEY, member("root-key.pub"))
        self.assertNotIn("differs from what the box uses", out)
        self.assertNotIn("in this file:", out)

    def test_upgrade_different_value_is_asked(self):
        extra, member = self.keep_files()
        settings = {"ADMIN_NET": '"192.168.9.0/24"'}
        r, out, calls = self.run_upgrade(stdin="yes\n", settings=settings, HM_TEST_ASK="1", HM_FAKE_SETTINGS=self.record(), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("ADMIN_NET in this file:", out)
        self.assertIn("ADMIN_NET this box was set with:", out)
        self.assertIn("ip saddr { 192.168.9.0/24 } tcp dport", member("ingress.nft"))
        r, out, calls = self.run_upgrade(stdin="\n", settings=settings, HM_TEST_ASK="1", HM_FAKE_SETTINGS=self.record(), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("ip saddr { 192.168.1.0/24 } tcp dport", member("ingress.nft"))
        # The same list in another order is no difference: nothing is asked.
        r, out, calls = self.run_upgrade(settings={"ADMIN_NET": '"10.0.0.0/8,192.168.1.0/24"'}, HM_TEST_ASK="1",
                                         HM_FAKE_SETTINGS=self.record(ADMIN_NET="192.168.1.0/24 10.0.0.0/8"))
        self.assertNotIn("in this file:", out)

    def test_upgrade_different_value_kept_without_a_person(self):
        extra, member = self.keep_files()
        r, out, calls = self.run_upgrade(settings={"ADMIN_NET": '"192.168.9.0/24"'}, HM_FAKE_SETTINGS=self.record(), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("ADMIN_NET: this file differs from what the box uses, so the box's value was kept. Run this at a terminal", out)
        self.assertIn("Security  ADMIN_NET: this file differs", out)
        self.assertIn("ip saddr { 192.168.1.0/24 } tcp dport", member("ingress.nft"))

    def test_restore_and_rebuild_keep_the_record(self):
        extra, member = self.keep_files()
        r, out, calls = self.run_upgrade("--restore", stdin="1\nRESTORE\n", HM_FAKE_BACKUPS=self.BACKUPS,
                                         HM_FAKE_SETTINGS=self.record(), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("ip saddr { 192.168.1.0/24 } tcp dport", member("ingress.nft"))
        self.assertIn(self.KEY, member("settings.env"))
        env, calls_path, script = self.fake_host()
        open(os.path.join(self.tmp, "ct-created"), "w").close()
        self.tag_ct(201)
        env.update(HM_FAKE_SETTINGS=self.record(), **extra)
        r = subprocess.run([shutil.which("bash"), script, "--rebuild"], input=("REBUILD\n" + self.PW).encode(),
                           capture_output=True, env=env, timeout=180)
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("-ssh-public-keys", self.created(read(calls_path)))
        self.assertIn("ip saddr { 192.168.1.0/24 } tcp dport", member("ingress.nft"))
        self.assertIn("with your SSH key only", out)

    def test_upgrade_does_not_change_the_kind(self):
        extra, member = self.keep_files()
        r, out, calls = self.run_upgrade(settings={"UNPRIVILEGED": "1"}, HM_TEST_ASK="1", HM_FAKE_SETTINGS=self.record(), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("UNPRIVILEGED=1 in this file does not change that", out)
        self.assertIn('UNPRIVILEGED="0"', member("settings.env"))
        r, out, calls = self.run_upgrade(ct_extra="unprivileged: 1", HM_FAKE_SETTINGS=self.record(UNPRIVILEGED="1"), **extra)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn('UNPRIVILEGED="1"', member("settings.env"))
        self.assertNotIn("does not change that", out)

    def test_update_here_drops_bad_recorded_nets(self):
        settings = os.path.join(self.tmp, "settings.env")
        with open(settings, "w", encoding="utf-8", newline="\n") as f:
            f.write('PORT="8080"\nTARGET="container"\nADMIN_NET="192.168.5.0/24 999.1.1.1"\nCTID="201"\nHOSTNAME="Monitor"\n')
        env, calls_path, script = self.fake_local(installed=True)
        extra, member = self.keep_files()
        env.update(HM_SETTINGS_ENV=settings.replace("\\", "/"), **extra)
        r = subprocess.run([shutil.which("bash"), script, "--update-here"], input=b"", capture_output=True, env=env, timeout=180)
        out = self.output(r)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("Ignoring 999.1.1.1 in the recorded ADMIN_NET", out)
        self.assertIn("ip saddr { 192.168.5.0/24 } tcp dport", member("ingress.nft"))
        self.assertNotIn("999.1.1.1", member("ingress.nft"))

    def test_local_says_no_inbound_firewall(self):
        r, out, calls = self.run_local("--local")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("No inbound firewall", out)
        self.assertIn("UDP 161", out)
        self.assertIn("Firewall  none added for incoming traffic: port 8080 (the web page) and UDP 161 (SNMP) are open", out)

    def test_bad_security_settings_are_refused(self):
        for k, v, msg in (("ADMIN_NET", '"192.168.1.0/24;reboot"', "ADMIN_NET"), ("ROOT_SSH_KEY", '"not a key"', "ROOT_SSH_KEY"),
                          ("BACKUP_PASSPHRASE", '"short"', "BACKUP_PASSPHRASE"), ("UNPRIVILEGED", "2", "UNPRIVILEGED"),
                          ("ADMIN_NET", '"999.1.1.1/24"', "ADMIN_NET"), ("SNMP_ALLOW", '"999.1.1.1"', "SNMP_ALLOW"),
                          ("SNMP_ALLOW", '"192.168.1.1;reboot"', "SNMP_ALLOW"), ("ADMIN_NET", '"192.168.1.0/24\n10.0.0.0/8"', "ADMIN_NET")):
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
        self.assertNotIn("|| echo 'The inbound firewall did not load", self.text)    # load_ingress decides now

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


class ReleaseDocsTests(unittest.TestCase):
    """REV-11: the signature check is part of the install steps, with the key and its fingerprint."""

    @staticmethod
    def readme():
        # In the public repository the README sits at the top (deploy/publish.py puts public/ there).
        path = os.path.join(ROOT, "public", "README.md")
        return read(path if os.path.exists(path) else os.path.join(ROOT, "README.md"))

    @staticmethod
    def release():
        sys.path.insert(0, os.path.join(ROOT, "deploy"))
        import release
        return release

    def signers(self):
        return read(os.path.join(ROOT, "deploy", "release-signers")).strip()

    def fingerprint(self):
        words = self.signers().split()
        blob = words[words.index("ssh-ed25519") + 1]
        return "SHA256:" + base64.b64encode(__import__("hashlib").sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")

    def test_readme_shows_the_key_and_fingerprint(self):
        guide = read(os.path.join(ROOT, "web", "guide.html"))
        for text in (self.readme(), guide):
            self.assertIn(self.fingerprint(), text)
            self.assertIn("echo '" + self.signers() + "' ", text)

    def test_verify_comes_before_running(self):
        readme = self.readme()
        proxmox = readme.split("### On Proxmox")[1].split("\n### ")[0]
        order = [proxmox.find(x) for x in ("home_monitor.sh.sig", "ssh-keygen -Y verify -f release-signers", "chmod +x")]
        self.assertTrue(all(i >= 0 for i in order) and order == sorted(order), order)
        self.assertIn("-s home_monitor.sh.sig < home_monitor.sh", proxmox)
        guide = read(os.path.join(ROOT, "web", "guide.html"))
        order = [guide.find(x) for x in ("home_monitor.sh.sig", "ssh-keygen -Y verify -f release-signers", "chmod +x home_monitor.sh")]
        self.assertTrue(all(i >= 0 for i in order) and order == sorted(order), order)
        self.assertIn("-s home_monitor.sh.sig &lt; home_monitor.sh", guide)
        # The spare computer path points at the same check before it runs anything.
        local = readme.split("### On a spare computer")[1].split("\n### ")[0]
        self.assertLess(local.find("check it with the block"), local.find("chmod +x"))

    def test_docs_say_what_it_does_not_protect(self):
        flat = lambda t: " ".join(t.split())                      # lines wrap anywhere
        self.assertIn("takes over the project's GitHub account", flat(self.readme()))
        self.assertIn("catches a download that was changed on the way", flat(self.readme()))
        self.assertIn("taking over the project's GitHub account", flat(read(os.path.join(ROOT, "web", "guide.html"))))

    def test_release_notes_carry_the_fingerprint(self):
        release = self.release()
        self.assertRegex(release.key_fingerprint(), r"^SHA256:[A-Za-z0-9+/]{43}$")
        self.assertEqual(release.key_fingerprint(), self.fingerprint())
        notes = release.install_notes("1.2.3")
        self.assertIn(self.fingerprint(), notes)
        self.assertIn("taking over the project's GitHub account", notes)
        self.assertIn("ssh-keygen -Y verify -f deploy/release-signers", notes)


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
        dest = os.path.join(self.data, "backups")
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
        self.assertEqual(r.returncode, 7, r.stderr)              # no passphrase, no tag: not proven unchanged
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--accept-unverified")
        self.assertEqual(r.returncode, 0, r.stderr)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT v FROM marker").fetchone()[0], "original")
        conn.close()
        self.assertEqual(read(self.key), "the-real-key\n")
        self.assertTrue(os.path.exists(os.path.join(self.data, "site-restored.json")))
        self.assertTrue(any(d.startswith("pre-restore-") for d in os.listdir(self.data)))
        # The monitor reports the restore once when it starts again (server.watch_root_results).
        with open(os.path.join(self.data, "restore.result.json"), encoding="utf-8") as f:
            result = json.load(f)
        self.assertEqual((result["ok"], result["file"]), (True, os.path.basename(archive)))

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
        """A format 1 backup (no key) restores the data and leaves no key: restore.sh then asks once.
        What was there is kept in root's own folder (--safe-dir; beside the data when there is none)."""
        self.make_db({})
        dest = os.path.join(self.tmp, "old")
        r = sitectl("backup", "--data", self.data, "--dest", dest)
        archive = r.stdout.decode().strip()
        with tarfile.open(archive) as tar:
            self.assertNotIn("vault.key", tar.getnames())
        os.makedirs(os.path.dirname(self.key))
        with open(self.key, "w") as f:
            f.write("fresh-container-key\n")
        safe = os.path.join(self.tmp, "safe")
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--accept-unverified", "--safe-dir", safe)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.key))
        kept = [d for d in os.listdir(safe) if d.startswith("pre-restore-")]
        self.assertTrue(os.path.exists(os.path.join(safe, kept[0], "vault.key")))
        self.assertFalse(any(d.startswith("pre-restore-") for d in os.listdir(self.data)))

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
        self.assertEqual(sitectl("verify", made[0]).returncode, 7)        # untagged: confirmed on purpose
        self.assertEqual(sitectl("verify", made[0], "--accept-unverified").returncode, 0)
        self.assertEqual(fields[6], "none")
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
        self.assertIn("|tag", r.stdout.decode())
        none = os.path.join(self.tmp, "no-such-file")
        # No passphrase: 4. A wrong one fails the tag first (7) and, confirmed anyway, cannot open the key (4).
        self.assertEqual(sitectl("verify", archive, "--passphrase-file", none).returncode, 4)
        self.assertEqual(sitectl("verify", archive, "--passphrase-file", none, "--accept-unverified").returncode, 4)
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-stdin", stdin="wrong one\n")
        self.assertEqual(r.returncode, 7, r.stderr)
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-stdin", "--accept-unverified",
                    stdin="wrong one\n")
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


KEY_B64 = base64.b64encode(bytes(range(32))).decode()
OTHER_B64 = base64.b64encode(bytes(range(1, 33))).decode()
PASS = "a long backup passphrase"
# What 0.11.2's sitectl.py restore accepted (its _unpack_and_check), kept here so a safety copy made now
# is proven readable by the build an Undo goes back to.
OLD_MEMBERS = ("monitor.db", "vault.json", "vault.key", "vault.key.sealed", "site.json", "manifest.json")


def old_0112_accepts(archive):
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
        if not set(names) <= set(OLD_MEMBERS) or "monitor.db" not in names:
            return False
        if not all(m.isfile() for m in tar.getmembers()):
            return False
        member = tar.extractfile("manifest.json")
        manifest = json.load(member) if member else {}
    manifest.get("schema"), manifest.get("app_version")           # read with .get only
    return True


class BackupAuthTests(unittest.TestCase):
    """REV-01: where the key goes, the tag, unproven and key-less backups, caps, pruning."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-bkauth-")
        self.data = os.path.join(self.tmp, "data")
        self.keydir = os.path.join(self.tmp, "key")
        self.key = os.path.join(self.keydir, "vault.key")
        self.pf = os.path.join(self.tmp, "pf")
        self.none = os.path.join(self.tmp, "no-passphrase")
        os.makedirs(self.data)
        os.makedirs(self.keydir)
        with open(self.pf, "w") as f:
            f.write(PASS + "\n")
        self.write_key(KEY_B64)
        shutil.copy(self.template, os.path.join(self.data, "monitor.db"))
        shutil.copy(os.path.join(self.tdir, "vault.json"), os.path.join(self.data, "vault.json"))

    @classmethod
    def setUpClass(cls):
        # A database the app made itself (the restore runs this build's migration on a copy), with one
        # account and one credential to show.
        cls.tdir = tempfile.mkdtemp(prefix="hm-bkauth-db-")
        cls.template = os.path.join(cls.tdir, "monitor.db")
        with open(os.path.join(cls.tdir, "k"), "w") as f:
            f.write(KEY_B64 + chr(10))                              # the same key the tests use
        code = ("import sys; sys.path.insert(0, %r); import server; server.initialise(); import sqlite3; "
                "c = sqlite3.connect(%r); "
                "c.execute(\"INSERT INTO accounts (username, password_hash, created_at, updated_at, role) VALUES ('alice', 'x', 0, 0, 'admin')\"); "
                "c.execute(\"INSERT INTO credentials (name, cred_type, username, secret_encrypted, salt, nonce, created_at) "
                "VALUES ('c', 'password', 'root', '', '', '', 0)\"); c.commit(); c.close()") % (ROOT, cls.template)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300,
                           env=dict(os.environ, MONITOR_DB_PATH=cls.template, MONITOR_KEY_FILE=os.path.join(cls.tdir, "k")))
        assert r.returncode == 0, r.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tdir, ignore_errors=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_key(self, b64, path=None):
        with open(path or self.key, "w") as f:
            f.write(b64 + "\n")

    def backup(self, dest, passphrase=True, *extra):
        r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", dest,
                    "--passphrase-file", self.pf if passphrase else self.none, *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.decode().strip().splitlines()[-1]

    @staticmethod
    def contents(archive):
        with tarfile.open(archive) as tar:
            return sorted(tar.getnames()), json.load(tar.extractfile("manifest.json"))

    def repack(self, archive, change):
        """Unpacks, lets change() alter the files, packs again in the same order."""
        work = tempfile.mkdtemp(dir=self.tmp)
        with tarfile.open(archive) as tar:
            names = tar.getnames()
            tar.extractall(work, filter="data")
        change(work)
        out = os.path.join(self.tmp, "monitor-backup-20260101-000000.tar.gz")
        with tarfile.open(out, "w:gz") as tar:
            for n in names:
                tar.add(os.path.join(work, n), arcname=n)
        return out

    def test_offbox_backup_without_passphrase_leaves_the_key_out(self):
        names, manifest = self.contents(self.backup(os.path.join(self.tmp, "share"), passphrase=False))
        self.assertNotIn("vault.key", names)
        self.assertNotIn("vault.key.sealed", names)
        self.assertTrue(manifest["key_withheld"])
        self.assertNotIn("auth", manifest)
        result = json.loads(read(os.path.join(self.data, "backup.result.json")))
        self.assertEqual(result["key"], "withheld")
        self.assertIn("the key was left out of this backup", result["output"])

    def test_offbox_through_a_link_counts_as_off_the_box(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        try:
            os.symlink(outside, os.path.join(self.data, "backups"), target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links need extra rights on this system")
        names, manifest = self.contents(self.backup(os.path.join(self.data, "backups"), passphrase=False))
        self.assertNotIn("vault.key", names)

    def test_local_backup_without_passphrase_keeps_the_key(self):
        names, manifest = self.contents(self.backup(os.path.join(self.data, "backups"), passphrase=False))
        self.assertIn("vault.key", names)
        self.assertNotIn("auth", manifest)
        self.assertEqual(manifest["format"], 3)

    def test_every_archive_with_a_passphrase_has_a_tag(self):
        for dest in (os.path.join(self.data, "backups"), os.path.join(self.tmp, "share")):
            names, manifest = self.contents(self.backup(dest))
            self.assertIn("vault.key.sealed", names)
            self.assertNotIn("vault.key", names)
            self.assertEqual(manifest["auth"]["alg"], "HMAC-SHA-256")
        archive = self.backup(os.path.join(self.tmp, "share"))
        r = sitectl("check-auth", archive, "--key", self.key, "--passphrase-file", self.pf)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"HM_AUTH=verified", r.stdout)

    def test_tampered_member_fails_verification(self):
        archive = self.backup(os.path.join(self.tmp, "share"))

        def change(work):
            conn = sqlite3.connect(os.path.join(work, "monitor.db"))
            conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at, role) VALUES ('mallory', 'x', 0, 0, 'admin')")
            conn.commit()
            conn.close()
        bad = self.repack(archive, change)
        for cmd in ("check-auth", "verify"):
            r = sitectl(cmd, bad, "--key", self.key, "--passphrase-file", self.pf)
            self.assertEqual(r.returncode, 7, (cmd, r.stderr))
        r = sitectl("restore", bad, "--data", self.data, "--key", self.key, "--passphrase-file", self.pf)
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertIn(b"mallory", r.stdout)                         # the accounts are shown first
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM accounts WHERE username = 'mallory'").fetchone()[0], 0)   # nothing restored
        conn.close()

    def test_missing_tag_fails_when_a_passphrase_is_set(self):
        archive = self.backup(os.path.join(self.tmp, "share"))

        def change(work):
            path = os.path.join(work, "manifest.json")
            m = json.loads(read(path))
            m.pop("auth")
            with open(path, "w") as f:
                json.dump(m, f)
        r = sitectl("verify", self.repack(archive, change), "--key", self.key, "--passphrase-file", self.pf)
        self.assertEqual(r.returncode, 7, r.stderr)

    def test_sealed_key_cannot_be_opened_without_the_passphrase(self):
        sys.path.insert(0, os.path.join(ROOT, "deploy"))
        import sitectl as sc
        blob = sc.seal_key(KEY_B64.encode(), PASS)
        self.assertNotIn(KEY_B64.encode(), blob)
        self.assertEqual(sc.unseal_key(blob, PASS), KEY_B64.encode())
        with self.assertRaises(SystemExit) as e:
            sc.unseal_key(blob, "not the passphrase")
        self.assertEqual(e.exception.code, 4)

    def test_tag_and_seal_use_separate_contexts(self):
        sys.path.insert(0, os.path.join(ROOT, "deploy"))
        import hashlib
        import sitectl as sc
        archive = self.backup(os.path.join(self.tmp, "share"))
        work = tempfile.mkdtemp(dir=self.tmp)
        with tarfile.open(archive) as tar:
            tar.extractall(work, filter="data")
            manifest = json.load(tar.extractfile("manifest.json"))
        seal = json.loads(read(os.path.join(work, "vault.key.sealed")))
        auth = manifest["auth"]
        self.assertNotEqual(seal["salt"], auth["salt"])
        tag = base64.b64decode(auth["tag"])
        self.assertTrue(sc.check_tag(work, manifest, PASS))
        # The seal's key (no label, its own salt) never makes the tag, and the tag's key never opens the seal.
        seal_key = hashlib.scrypt(PASS.encode(), salt=base64.b64decode(seal["salt"]), n=seal["n"], r=8, p=1,
                                  maxmem=256 * 1024 * 1024, dklen=32)
        self.assertNotEqual(sc._tag_over(seal_key, work, manifest), tag)
        tag_key = sc._tag_key(PASS, base64.b64decode(auth["salt"]), auth["n"], 8, 1)
        import vault
        with self.assertRaises(Exception):
            vault.AESGCM(tag_key).decrypt(base64.b64decode(seal["nonce"]), base64.b64decode(seal["data"]),
                                          b"homelab-monitor backup key")
        self.assertFalse(sc.check_tag(work, manifest, "a different passphrase"))

    def format2(self):
        """A backup as 0.11.2 made it: key in the clear, no tag."""
        work = tempfile.mkdtemp(dir=self.tmp)
        shutil.copy(os.path.join(self.data, "monitor.db"), os.path.join(work, "monitor.db"))
        self.write_key(KEY_B64, os.path.join(work, "vault.key"))
        with open(os.path.join(work, "manifest.json"), "w") as f:
            json.dump({"app": "homelab-monitor", "format": 2, "includes_key": True, "key_sealed": False}, f)
        out = os.path.join(self.tmp, "monitor-backup-20251101-000000.tar.gz")
        with tarfile.open(out, "w:gz") as tar:
            for n in ("monitor.db", "vault.key", "manifest.json"):
                tar.add(os.path.join(work, n), arcname=n)
        return out

    def test_format2_backup_restores_through_warning_path(self):
        archive = self.format2()
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-file", self.pf)
        self.assertEqual(r.returncode, 7, r.stderr)
        out = r.stdout.decode()
        self.assertIn("cannot be proven unchanged", out)
        self.assertIn("alice  admin", out)
        self.assertIn("Stored credentials in it: 1", out)
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-file", self.pf,
                    "--accept-unverified")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_summary_strips_terminal_control_characters(self):
        archive = self.format2()

        def change(work):
            conn = sqlite3.connect(os.path.join(work, "monitor.db"))
            conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at, role) VALUES (?, 'x', 0, 0, 'admin')", ("evil\x1b]0;owned\x07name" + "x" * 100,))
            conn.commit()
            conn.close()
        r = sitectl("check-auth", self.repack(archive, change), "--key", self.key)
        self.assertEqual(r.returncode, 7)
        out = r.stdout.decode()
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("evil]0;ownedname", out)
        self.assertNotIn("x" * 70, out)                             # cut to 64 characters

    def vault_meta(self, key_b64):
        import vault
        check = vault.Vault._seal(vault.AESGCM(base64.b64decode(key_b64)), vault.CHECK_PLAINTEXT, "vault:check")
        with open(os.path.join(self.data, "vault.json"), "w") as f:
            json.dump({"check": check}, f)

    def test_keyless_restore_keeps_the_key_on_the_same_box(self):
        self.vault_meta(KEY_B64)
        archive = self.backup(os.path.join(self.tmp, "share"), passphrase=False)
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--passphrase-file", self.none,
                    "--accept-unverified")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(self.key).strip(), KEY_B64)          # the live key opens it: it stays

    def test_keyless_restore_needs_forget_on_a_new_box(self):
        # A real database: the app's own start, a credential, a community and 2FA on an account.
        data = os.path.join(self.tmp, "real")
        os.makedirs(data)
        db, key = os.path.join(data, "monitor.db"), os.path.join(self.tmp, "real.key")
        seed = ("import sys; sys.path.insert(0, %r); import database, server; server.initialise(); "
                "database.add_credential('root', 'password', 'root', 'secret-pw-123'); "
                "import sqlite3; from vault import VAULT; c = sqlite3.connect(%r); "
                "c.execute(\"INSERT INTO accounts (username, password_hash, created_at, updated_at, role, totp_secret, totp_enabled) "
                "VALUES ('bob', 'x', 0, 0, 'admin', ?, 1)\", (VAULT.encrypt('JBSWY3DP', 'account:totp'),)); "
                "c.execute(\"INSERT INTO devices (hostname, ip_address, profile_id, created_at, snmp_community) "
                "VALUES ('d', '192.0.2.9', 'generic_device', 0, ?)\", (VAULT.encrypt('private', 'device:snmp_community'),)); "
                "c.commit(); print('seeded')") % (ROOT, db)
        env = dict(os.environ, MONITOR_DB_PATH=db, MONITOR_KEY_FILE=key)
        r = subprocess.run([sys.executable, "-c", seed], env=env, capture_output=True, text=True, timeout=300)
        self.assertIn("seeded", r.stdout, r.stderr)
        archive = sitectl("backup", "--data", data, "--key", key, "--dest", os.path.join(self.tmp, "share"),
                          "--passphrase-file", self.none).stdout.decode().strip().splitlines()[-1]
        # A new box: another key, which does not open the backup's data.
        new = os.path.join(self.tmp, "new")
        os.makedirs(new)
        new_key = os.path.join(self.tmp, "new.key")
        self.write_key(OTHER_B64, new_key)
        base = ("restore", archive, "--data", new, "--key", new_key, "--passphrase-file", self.none, "--accept-unverified")
        r = sitectl(*base)
        self.assertEqual(r.returncode, 8, r.stderr)
        self.assertIn(b"must be entered again", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(new, "monitor.db")))
        r = sitectl(*base, "--forget-secrets")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conn = sqlite3.connect(os.path.join(new, "monitor.db"))
        self.assertEqual(conn.execute("SELECT secret_encrypted FROM credentials").fetchone()[0], "")
        self.assertEqual(conn.execute("SELECT snmp_community FROM devices WHERE hostname = 'd'").fetchone()[0], "")
        self.assertEqual(conn.execute("SELECT totp_enabled, totp_secret FROM accounts WHERE username = 'bob'").fetchone(), (0, None))
        self.assertTrue(conn.execute("SELECT COUNT(*) FROM audit_log WHERE message LIKE 'Restored a backup without its key%'").fetchone()[0])
        conn.close()
        self.assertNotIn("check", json.loads(read(os.path.join(new, "vault.json"))))
        self.assertEqual(read(new_key).strip(), OTHER_B64)
        check = ("import sys; sys.path.insert(0, %r); import database, server; server.initialise(); "
                 "c = database.list_credentials()[0]; print(repr(database.get_credential_secret(c['id'])['secret'])); "
                 "print([d['hostname'] for d in database.list_devices()])") % ROOT
        r = subprocess.run([sys.executable, "-c", check], env=dict(os.environ, MONITOR_DB_PATH=os.path.join(new, "monitor.db"),
                           MONITOR_KEY_FILE=new_key), capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)                 # the app starts on the cleared copy
        self.assertIn("''", r.stdout)
        self.assertIn("'d'", r.stdout)

    def test_unpack_size_cap(self):
        big = os.path.join(self.tmp, "monitor-backup-20260101-000001.tar.gz")
        with tarfile.open(big, "w:gz") as tar:
            for name, size in (("site.json", 1024 * 1024 + 1), ("monitor.db", 10)):
                info = tarfile.TarInfo(name)
                info.size = size
                tar.addfile(info, io.BytesIO(b"x" * size))
        r = sitectl("verify", big)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"larger than a restore allows", r.stderr)

    def test_duplicate_member_refused(self):
        dup = os.path.join(self.tmp, "monitor-backup-20260101-000002.tar.gz")
        with tarfile.open(dup, "w:gz") as tar:
            for _ in range(2):
                tar.add(os.path.join(self.data, "monitor.db"), arcname="monitor.db")
        r = sitectl("verify", dup, "--accept-unverified")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"same file twice", r.stderr)

    def test_pre_restore_pruned(self):
        sys.path.insert(0, os.path.join(ROOT, "deploy"))
        import sitectl as sc
        now = time.time()
        safe, legacy = os.path.join(self.tmp, "safe"), self.data
        ages = {safe: (1, 5, 40), legacy: (2, 3, 60)}                 # days old
        for folder, days in ages.items():
            for d in days:
                path = os.path.join(folder, f"pre-restore-{d:03d}")
                os.makedirs(path)
                os.utime(path, (now - d * 86400,) * 2)
        sc.prune_pre_restore([safe, legacy], now)
        left = sorted(n for f in ages for n in os.listdir(f) if n.startswith("pre-restore-"))
        self.assertEqual(left, ["pre-restore-001", "pre-restore-002", "pre-restore-003"])
        # Only old ones: the newest always stays.
        for n in os.listdir(safe):
            shutil.rmtree(os.path.join(safe, n))
        for n in [n for n in os.listdir(legacy) if n.startswith("pre-restore-")]:
            shutil.rmtree(os.path.join(legacy, n))
        for d in (45, 50):
            os.makedirs(os.path.join(safe, f"pre-restore-{d}"))
            os.utime(os.path.join(safe, f"pre-restore-{d}"), (now - d * 86400,) * 2)
        sc.prune_pre_restore([safe], now)
        self.assertEqual(os.listdir(safe), ["pre-restore-45"])

    def test_safety_backup_has_the_key_and_old_member_names(self):
        safe = os.path.join(self.tmp, "safe")
        archive = self.backup(os.path.join(safe, "pre-update"), True, "--safety", "--safe-dir", safe)
        names, manifest = self.contents(archive)
        self.assertIn("vault.key", names)                           # in the clear: Undo never needs the passphrase
        self.assertNotIn("vault.key.sealed", names)
        self.assertTrue(set(names) <= set(OLD_MEMBERS))
        self.assertIn("auth", manifest)
        # Outside root's folder it is refused.
        r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", os.path.join(self.tmp, "x"), "--safety",
                    "--safe-dir", safe)
        self.assertNotEqual(r.returncode, 0)
        # Checked by the checksum root recorded, whatever the passphrase is now.
        import hashlib
        digest = hashlib.sha256(read_bytes(archive)).hexdigest()
        r = sitectl("verify", archive, "--passphrase-file", self.none, "--expect-sha256", digest)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = sitectl("verify", archive, "--passphrase-file", self.none, "--expect-sha256", "0" * 64, "--accept-unverified")
        self.assertEqual(r.returncode, 7, r.stderr)

    def test_old_sitectl_restores_a_safety_backup(self):
        safe = os.path.join(self.tmp, "safe")
        for passphrase in (True, False):
            archive = self.backup(os.path.join(safe, "pre-update"), passphrase, "--safety", "--safe-dir", safe)
            self.assertTrue(old_0112_accepts(archive))
            time.sleep(1.1)
        # Every other kind of backup made now is readable by 0.11.2 too.
        self.assertTrue(old_0112_accepts(self.backup(os.path.join(self.tmp, "share"))))

    def test_set_passphrase_file_mode_and_length(self):
        target = os.path.join(self.tmp, "install", "backup-passphrase")
        r = sitectl("set-passphrase", "--data", self.data, "--file", target, stdin="too short\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(target))
        r = sitectl("set-passphrase", "--data", self.data, "--file", target, stdin=PASS + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(target), PASS + "\n")
        self.assertNotIn(PASS.encode(), r.stdout + r.stderr)
        if os.name == "posix":
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE message = 'Backup passphrase set from the container shell'")
                         .fetchone()[0], 1)
        conn.close()

    def test_passphrase_request_from_settings(self):
        """Settings, Backups leaves the passphrase sealed with the vault key; root saves it and removes the request."""
        import base64
        import vault
        target = os.path.join(self.tmp, "install", "backup-passphrase")
        requests_dir = os.path.join(self.data, "requests")
        os.makedirs(requests_dir, exist_ok=True)
        req = os.path.join(requests_dir, "backup-passphrase")
        key = base64.b64decode(read(self.key).strip())

        def ask(token):
            with open(req, "w", encoding="ascii") as f:
                f.write(token + "\n")
            return sitectl("passphrase-request", "--data", self.data, "--key", self.key, "--file", target, "--no-backup")

        def result():
            with open(os.path.join(self.data, "passphrase.result.json"), encoding="utf-8") as f:
                return json.load(f)

        # Sealed with another key, or not sealed at all: refused, nothing saved, request gone.
        other = vault.Vault._seal(vault.AESGCM(bytes(32)), PASS, "backup-passphrase-request")
        for token in (other, PASS):
            r = ask(token)
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(os.path.exists(target))
            self.assertFalse(os.path.exists(req))
            self.assertFalse(result()["ok"])
        # Too short, though sealed properly.
        r = ask(vault.Vault._seal(vault.AESGCM(key), "short", "backup-passphrase-request"))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(target))
        self.assertIn("12 characters", result()["output"])
        # The real thing.
        r = ask(vault.Vault._seal(vault.AESGCM(key), PASS, "backup-passphrase-request"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(target), PASS + "\n")
        self.assertFalse(os.path.exists(req))
        self.assertTrue(result()["ok"])
        self.assertNotIn(PASS, json.dumps(result()))
        self.assertNotIn(PASS.encode(), r.stdout + r.stderr)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE message LIKE 'Backup passphrase saved%'").fetchone()[0], 1)
        conn.close()
        # Fired again with no request (the path unit also sees the removal): nothing happens.
        self.assertEqual(sitectl("passphrase-request", "--data", self.data, "--key", self.key, "--file", target,
                                 "--no-backup").returncode, 0)

    def test_take_copies_a_plain_file_only(self):
        archive = self.backup(os.path.join(self.tmp, "share"))
        to = os.path.join(self.tmp, "copy.tar.gz")
        r = sitectl("take", archive, "--to", to)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read_bytes(to), read_bytes(archive))
        link = os.path.join(self.tmp, "link.tar.gz")
        try:
            os.symlink(archive, link)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links need extra rights on this system")
        r = sitectl("take", link, "--to", to + "2")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(to + "2"))


class RestoreScriptTests(unittest.TestCase):
    """The real /root/restore.sh from the template, its paths moved into a temporary folder, with
    stand-ins for systemctl and chown: RESTORE="latest" refuses an unproven backup unless the override is on."""

    def setUp(self):
        self.bash = shutil.which("bash")
        if not self.bash:
            self.skipTest("bash not available")
        self.tmp = tempfile.mkdtemp(prefix="hm-restoresh-")
        q = lambda p: p.replace("\\", "/")
        self.data, self.safe = os.path.join(self.tmp, "data"), os.path.join(self.tmp, "safe")
        self.keydir, self.root = os.path.join(self.tmp, "etc-hm"), os.path.join(self.tmp, "root")
        for d in (self.data, os.path.join(self.safe, "from-share"), self.keydir, self.root):
            os.makedirs(d)
        self.key = os.path.join(self.keydir, "vault.key")
        conf = os.path.join(self.tmp, "install.conf")
        with open(conf, "w", newline="\n") as f:
            f.write('BACKUP_NFS="192.0.2.10:/Backups/Monitor"\nUNPRIVILEGED="1"\n')
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        body = tpl.split('cat > "$FILES/restore.sh" <<"EOF"\n')[1].split("\nEOF\n")[0]
        for a, b in (("DATA=/var/lib/homelab-monitor\n", f"DATA='{q(self.data)}'\n"),
                     ("APP=/opt/homelab-monitor\n", f"APP='{q(os.path.join(ROOT, 'deploy'))}'\n"),
                     ("KEY=/etc/homelab-monitor/vault.key\n", f"KEY='{q(self.key)}'\n"),
                     ("SAFE=/var/lib/homelab-monitor-safe\n", f"SAFE='{q(self.safe)}'\n"),
                     ("CONF=/etc/homelab-monitor-install/install.conf\n", f"CONF='{q(conf)}'\n"),
                     ('[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }\n', ""),
                     ("mktemp -d /root/.hm-restore.XXXXXX", f"mktemp -d '{q(self.root)}/.hm-restore.XXXXXX'"),
                     ("/etc/homelab-monitor/setup.env", q(os.path.join(self.keydir, "setup.env"))),
                     ("$APP/sitectl.py", '"$APP/sitectl.py"')):
            self.assertIn(a, body)
            body = body.replace(a, b)
        self.script = os.path.join(self.tmp, "restore.sh")
        with open(self.script, "w", newline="\n") as f:
            f.write(body)
        fake = os.path.join(self.tmp, "bin")
        os.makedirs(fake)
        self.calls = os.path.join(self.tmp, "calls.log")
        stubs = {"python3": f'#!/usr/bin/env bash\nexec "{q(sys.executable)}" "$@"\n',
                 "systemctl": f'#!/usr/bin/env bash\necho "systemctl $*" >> "{q(self.calls)}"\n',
                 "chown": f'#!/usr/bin/env bash\necho "chown $*" >> "{q(self.calls)}"\n'}
        for name, text in stubs.items():
            with open(os.path.join(fake, name), "w", newline="\n") as f:
                f.write(text)
            os.chmod(os.path.join(fake, name), 0o755)
        sep = ";" if os.name == "nt" else ":"
        self.env = dict(os.environ, PATH=fake + sep + os.environ["PATH"], NO_COLOR="1")
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        conn.executescript("""CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, description TEXT, updated_at INTEGER NOT NULL);
            CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE,
                                  profile_id TEXT NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE marker (v TEXT); INSERT INTO marker VALUES ('live');""")
        conn.commit()
        conn.close()
        with open(self.key, "w") as f:
            f.write(KEY_B64 + "\n")
        # An unproven backup (no passphrase, so no tag) with its key, as a host copy would bring in.
        made = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", os.path.join(self.data, "backups"),
                       "--passphrase-file", os.path.join(self.tmp, "none")).stdout.decode().strip().splitlines()[-1]
        self.archive = os.path.join(self.safe, "from-share", os.path.basename(made))
        shutil.move(made, self.archive)
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        conn.execute("UPDATE marker SET v = 'changed since'")
        conn.commit()
        conn.close()

    def tearDown(self):
        if getattr(self, "tmp", None):
            shutil.rmtree(self.tmp, ignore_errors=True)

    def marker(self):
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        try:
            return conn.execute("SELECT v FROM marker").fetchone()[0]
        finally:
            conn.close()

    def run_script(self, **env):
        return subprocess.run([self.bash, self.script, "--latest"], capture_output=True, env=dict(self.env, **env),
                              timeout=300, stdin=subprocess.DEVNULL)

    def test_restore_latest_refuses_an_unauthenticated_archive(self):
        r = self.run_script()
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 1, out)
        self.assertIn('RESTORE="latest" refused this backup', out)
        self.assertEqual(self.marker(), "changed since")              # data untouched
        self.assertFalse(os.path.exists(self.calls) and "systemctl stop" in read(self.calls))
        self.assertEqual(os.listdir(self.root), [])                   # the private copy is cleared away

    def test_restore_latest_override_passes(self):
        r = self.run_script(HM_RESTORE_UNVERIFIED="1")
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("RESTORE_UNVERIFIED is yes", out)
        self.assertEqual(self.marker(), "live")
        self.assertEqual(read(os.path.join(self.data, "restored-from")).strip(), os.path.basename(self.archive))


class RootWriteTests(unittest.TestCase):
    """REV-03: a link the app's account puts in its folders never redirects a root write or read."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hm-rootw-")
        self.data = os.path.join(self.tmp, "data")
        self.keydir = os.path.join(self.tmp, "etc")
        self.key = os.path.join(self.keydir, "vault.key")
        os.makedirs(self.data)
        os.makedirs(self.keydir)
        with open(self.key, "w") as f:
            f.write(KEY_B64 + "\n")
        conn = sqlite3.connect(os.path.join(self.data, "monitor.db"))
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, description TEXT, updated_at INTEGER NOT NULL)")
        conn.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE, "
                     "profile_id TEXT NOT NULL, created_at INTEGER NOT NULL)")
        conn.commit()
        conn.close()
        self.precious = os.path.join(self.tmp, "precious")
        with open(self.precious, "w") as f:
            f.write("root only\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def link(self, at, target=None):
        if os.name != "posix":
            self.skipTest("following links is a POSIX matter (checked on Linux)")
        os.symlink(target or self.precious, at)

    def untouched(self):
        self.assertEqual(read(self.precious), "root only\n")

    def test_symlink_does_not_redirect_derive_key(self):
        self.link(self.key + ".new")
        os.remove(self.key)
        self.link(self.key)
        r = sitectl("derive-key", "--data", self.data, "--key", self.key, stdin="correct horse battery\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.untouched()
        self.assertFalse(os.path.islink(self.key))

    def test_symlink_does_not_redirect_new_setup_code(self):
        env = os.path.join(self.keydir, "setup.env")
        self.link(env)
        self.link(env + ".new", os.path.join(self.tmp, "precious2"))
        r = sitectl("new-setup-code", "--data", self.data, "--env", env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.untouched()
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "precious2")))
        self.assertIn("MONITOR_SETUP_TOKEN=", read(env))

    def test_symlink_does_not_redirect_restored_from(self):
        archive = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", os.path.join(self.data, "backups")
                          ).stdout.decode().strip().splitlines()[-1]
        self.link(os.path.join(self.data, "restored-from"))
        r = sitectl("restore", archive, "--data", self.data, "--key", self.key, "--accept-unverified",
                    "--record-name", "monitor-backup-x.tar.gz", "--safe-dir", os.path.join(self.tmp, "safe"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.untouched()
        self.assertEqual(read(os.path.join(self.data, "restored-from")), "monitor-backup-x.tar.gz\n")

    def test_symlink_does_not_redirect_vault_json_read(self):
        self.link(os.path.join(self.data, "vault.json"))
        r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", os.path.join(self.data, "backups"))
        self.assertNotEqual(r.returncode, 0)                      # refused rather than packing root's file
        self.assertEqual([n for n in os.listdir(os.path.join(self.data, "backups")) if n.endswith(".tar.gz")]
                         if os.path.isdir(os.path.join(self.data, "backups")) else [], [])

    def test_symlink_does_not_redirect_key_read(self):
        os.remove(self.key)
        self.link(self.key)
        r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", os.path.join(self.data, "backups"))
        self.assertNotEqual(r.returncode, 0)

    def test_symlink_does_not_redirect_monitor_db(self):
        db = os.path.join(self.data, "monitor.db")
        os.rename(db, os.path.join(self.tmp, "other.db"))
        self.link(db, os.path.join(self.tmp, "other.db"))
        r = sitectl("backup", "--data", self.data, "--key", self.key, "--dest", os.path.join(self.data, "backups"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"is a link", r.stderr)

    def test_symlink_does_not_redirect_backups_folder(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        self.link(os.path.join(self.data, "backups"), outside)
        sys.path.insert(0, ROOT)
        import safefile
        with self.assertRaises(OSError):
            safefile.atomic_write(os.path.join(self.data, "backups"), "x", b"y")
        self.assertEqual(os.listdir(outside), [])

    def test_setup_code_is_owned_and_private(self):
        env = os.path.join(self.keydir, "setup.env")
        r = sitectl("new-setup-code", "--data", self.data, "--env", env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(env), "MONITOR_SETUP_TOKEN=" + r.stdout.decode().strip() + "\n")
        if os.name == "posix":
            self.assertEqual(os.stat(env).st_mode & 0o777, 0o600)
        tpl = read(os.path.join(ROOT, "deploy", "install-template.sh"))
        script = tpl.split('cat > "$FILES/setup-code.sh" <<"EOF"')[1].split("\nEOF\n")[0]
        self.assertNotIn("chown", script)
        self.assertNotIn("chmod", script)

    def test_put_key_and_ask(self):
        r = sitectl("put-key", "--key", self.key, stdin="not a key\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(read(self.key).strip(), KEY_B64)
        r = sitectl("put-key", "--key", self.key, stdin=OTHER_B64 + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read(self.key).strip(), OTHER_B64)
        os.makedirs(os.path.join(self.data, "requests"))
        r = sitectl("ask", "--kind", "site", "--data", self.data)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(read(os.path.join(self.data, "requests", "site")).isdigit())

    def test_chown_is_never_a_following_chown(self):
        texts = {n: read(os.path.join(ROOT, "deploy", n)) for n in ("install-template.sh", "sitectl.py", "updatectl.py")}
        texts["compat.py"] = read(os.path.join(ROOT, "compat.py"))
        for name, text in texts.items():
            for m in re.finditer(r"chown\b[^\n;&|]*", text):
                line = m.group(0)
                if re.search(r"(^|\s|\")-R\b|\"-R\"", line):
                    self.fail(f"{name}: a recursive chown that follows links: {line}")
                self.assertNotRegex(line, r"chown \S+ \"\$ENV\"", name)
        tpl = texts["install-template.sh"]
        self.assertGreaterEqual(tpl.count("chown -hR"), 6)
        self.assertNotIn('> "$KEY"', tpl)                           # the key is never written by a shell redirect
        self.assertNotIn("touch ${DATA_DIR}/requests", tpl)
        self.assertNotIn("tee \"${DATA_DIR}/restored-from\"", tpl)
        self.assertIn("[ ! -L ${KEY_DIR}/install.conf ]", tpl)
        self.assertIn("if [ -L ${DATA_DIR}/requests ]; then rm -f ${DATA_DIR}/requests; fi", tpl)


if __name__ == "__main__":
    unittest.main()
