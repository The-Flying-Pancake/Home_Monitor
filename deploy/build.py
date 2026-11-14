"""Builds home_monitor.sh (project root): the Proxmox installer with the application embedded.

  py -3.15 deploy/build.py                  rebuild, keeping the SETTINGS block of the current home_monitor.sh
  py -3.15 deploy/build.py --reset-settings rebuild with the template's default settings

Regenerate it after any change to the app, the profiles, sitectl.py or the template
(deploy/install-template.sh). The block between "# >>> SETTINGS" and "# <<< SETTINGS" at the
top of home_monitor.sh is the only part meant for editing by hand; this script carries it over into
the new file, so local values (storage, CT ID, MAC, restore source) survive a rebuild. A
setting added to the template but missing from the kept block is appended to it with its
default, and reported.

The payload is a tar.gz of the application files (modules, templates, web
files and sitectl.py), base64 encoded between the payload markers, so the
installer is one self-contained file to copy to the Proxmox host. Nothing
is downloaded for the app itself. Every bash script in the result is
checked with `bash -n` when bash is available.
"""

import base64
import glob
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MODULES = ["server.py", "poller.py", "database.py", "vault.py", "ssh_runner.py", "auth.py", "topology.py",
           "workflows.py", "snmpfix.py", "notify.py", "discovery.py", "setup.py", "alerts.py", "schedule.py", "rbac.py",
           "availability.py", "proxmox.py", "customoids.py", "totp.py", "compat.py", "taxonomy.py", "tls.py", "changelog.py", "maintenance.py", "forecast.py",
           "inventory.py", "hostactions.py", "lanhttp.py", "pihole.py", "unifi.py", "digest.py", "telebot.py", "botcmds.py", "tpl.py", "sitecheck.py", "safefile.py",
           "demo.py", "report.py", "snmpv3.py", "pdfdoc.py", "reports.py"]
WEB = ["index.html", "app.js", "map.js", "workflows.js", "wftemplates.js", "hostactions.js", "telegram.js", "workflows.css", "setup.js", "alerts.js", "theme.js", "shell.js", "users.js", "security.js","adddevice.js", "backups.js", "updates.js", "snmp.js",
       "charts.js", "availability.js", "proxmox.js", "taxonomy.js", "tls.js", "changes.js", "lan.js", "inventory.js", "reports.js", "botcmds.js", "guide.js", "guide.html", "style.css"]


BUILT = time.strftime("%Y-%m-%d %H:%M")


def payload() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(src: str, arc: str) -> None:
            info = tar.gettarinfo(src, arcname=arc)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = 0o644
            with open(src, "rb") as f:
                tar.addfile(info, f)
        for m in MODULES:
            add(os.path.join(ROOT, m), m)
        for p in sorted(glob.glob(os.path.join(ROOT, "profiles", "*.json"))):
            add(p, f"profiles/{os.path.basename(p)}")
        for w in WEB:
            add(os.path.join(ROOT, "web", w), f"web/{w}")
        add(os.path.join(ROOT, "deploy", "sitectl.py"), "sitectl.py")
        add(os.path.join(ROOT, "deploy", "updatectl.py"), "updatectl.py")
        # The public half of the release key: Update installs only what it signed.
        add(os.path.join(ROOT, "deploy", "release-signers"), "release-signers")
        # When this build was made, shown in Settings, System, so a container's build can be told apart.
        stamp = BUILT.encode("ascii")
        info = tarfile.TarInfo("BUILD")
        info.size, info.mode, info.mtime = len(stamp), 0o644, int(time.time())
        tar.addfile(info, io.BytesIO(stamp))
    return buf.getvalue()


def find_bash() -> str:
    """A real bash. On Windows, Git Bash first: the bash.exe in System32 is WSL's stub, which fails
    when no Linux is installed (and PowerShell finds it before Git Bash)."""
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", ""),
                     os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")):
            cand = os.path.join(base, "Git", "bin", "bash.exe") if base else ""
            if cand and os.path.exists(cand):
                return cand
        found = shutil.which("bash") or ""
        windir = os.environ.get("WINDIR", r"C:\Windows").lower()
        return "" if found.lower().startswith(windir) or "windowsapps" in found.lower() else found
    return shutil.which("bash") or ""


def bash_check(path: str) -> None:
    bash = find_bash()
    if not bash:
        print("bash not found: syntax check skipped")
        return
    text = open(path, encoding="utf-8").read()
    # The installer itself, then each script it writes out through a quoted heredoc.
    scripts = {"installer": text.split("\n__PAYLOAD_BEGIN__\n")[0]}
    # A heredoc into a variable's own temp file is named after the variable (BOOT: bootstrap.sh, PRECHECK: precheck.sh).
    for var, name, _, body in re.findall(r'cat > "\$(\w+)(?:/([\w.-]+))?" <<["\'](\w+)["\']\n(.*?)\n\3\n', text, re.S):
        if not name or name.endswith(".sh"):
            scripts[name or {"BOOT": "bootstrap.sh"}.get(var, var.lower() + ".sh")] = body
    for name, body in scripts.items():
        r = subprocess.run([bash, "-n"], input=body.encode(), capture_output=True)
        if r.returncode:
            raise SystemExit(f"bash -n failed for {name}:\n{r.stderr.decode()}")
        print(f"bash -n ok: {name}")


SETTINGS_RE = re.compile(r"^# >>> SETTINGS.*?^# <<< SETTINGS$", re.S | re.M)
OUTPUT = os.path.join(ROOT, "home_monitor.sh")
LEGACY = os.path.join(ROOT, "infra.sh")      # the installer's name before 0.10.0: its settings are carried over once


def setting_names(block: str) -> list:
    return re.findall(r"^([A-Z_]+)=", block, re.M)


def merge_settings(template: str, current_path: str) -> str:
    """The template with its SETTINGS block replaced by the one in the current home_monitor.sh."""
    try:
        with open(current_path, encoding="utf-8") as f:
            current = f.read()
    except FileNotFoundError:
        return template
    kept = SETTINGS_RE.search(current)
    fresh = SETTINGS_RE.search(template)
    if not kept or not fresh:
        return template
    block = kept.group(0)
    missing = [n for n in setting_names(fresh.group(0)) if n not in setting_names(block)]
    if missing:
        lines = [l for l in fresh.group(0).splitlines() if re.match(r"^(%s)=" % "|".join(missing), l)]
        block = block.replace("# <<< SETTINGS", "# Added by build.py (new in this version):\n" + "\n".join(lines) + "\n\n# <<< SETTINGS")
        print("New settings added with their defaults: " + ", ".join(missing))
    print(f"Kept the SETTINGS block from the current {os.path.basename(current_path)}")
    return template[:fresh.start()] + block + template[fresh.end():]


def main() -> None:
    import server
    template = open(os.path.join(ROOT, "deploy", "install-template.sh"), encoding="utf-8").read()
    if "--reset-settings" not in sys.argv:
        template = merge_settings(template, OUTPUT if os.path.exists(OUTPUT) else LEGACY)
    raw = payload()
    data = base64.encodebytes(raw).decode("ascii").rstrip("\n")
    # The installer checks the unpacked application against this before using it.
    out = (template.replace("__VERSION__", server.APP_VERSION).replace("__BUILT__", BUILT)
           .replace("__PAYLOAD_SHA256__", hashlib.sha256(raw).hexdigest()).replace("__PAYLOAD__", data))
    # Linux line endings only: a settings block kept from a home_monitor.sh saved on Windows must not
    # carry carriage returns into the new file (nothing in it, the payload included, needs one).
    out = out.replace("\r", "")
    path = os.environ.get("HM_BUILD_OUT") or OUTPUT
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print(f"Wrote {path} ({len(out) // 1024} KB, app {server.APP_VERSION})")
    bash_check(path)


if __name__ == "__main__":
    main()
