"""Makes a signed release of infra.sh for the public repository's Releases page.

  py -3 deploy/release.py                 build and sign into dist/ (nothing is uploaded)
  py -3 deploy/release.py --publish       the same, then create the GitHub release vX.Y.Z

What it does:
  1. Builds a clean infra.sh into dist/ with the template's default settings (deploy/build.py
     --reset-settings), never with the settings block of a local infra.sh.
  2. Signs it with the release key (ssh-keygen -Y sign), then checks the signature against
     deploy/release-signers, the public key every installed copy uses to accept an Update.
  3. Writes SHA256SUMS and the release notes for this version (deploy/changelog_md.py).
  4. With --publish: creates the release on GitHub with infra.sh, infra.sh.sig and SHA256SUMS.
     Publish the source first (deploy/publish.py --push) so the release's tag points at it.

The release key's private half stays on the machine that makes releases, outside every repository:
HM_RELEASE_KEY, or ~/.homelab-monitor/release-signing-key by default. Keep a copy of it somewhere
safe: without it no installed copy accepts an Update (a new key means one manual upgrade with
infra.sh on every box).
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
REPO = "The-Flying-Pancake/Home_Monitor"
KEY = os.environ.get("HM_RELEASE_KEY") or os.path.join(os.path.expanduser("~"), ".homelab-monitor", "release-signing-key")
SIGNERS = os.path.join(ROOT, "deploy", "release-signers")
IDENTITY, NAMESPACE = "release@home-monitor", "home-monitor-release"


def app_version() -> str:
    with open(os.path.join(ROOT, "server.py"), encoding="utf-8") as f:
        return re.search(r'^APP_VERSION = "([0-9.]+)"', f.read(), re.M).group(1)


def check_private(text: str) -> None:
    """With a deploy/private-words.txt beside this file (kept by whoever makes releases), the installer
    and every file packed inside it must match none of its patterns."""
    words = os.path.join(ROOT, "deploy", "private-words.txt")
    if not os.path.exists(words):
        return
    import base64
    import io
    import tarfile
    pats = []
    with open(words, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                pats.append(re.compile(line[5:]) if line.startswith("(?-i)") else re.compile(line, re.I))
    head, rest = text.split("\n__PAYLOAD_BEGIN__\n", 1)
    parts = {"infra.sh": head}
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(rest.split("\n__PAYLOAD_END__")[0])), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile():
                parts[m.name] = tar.extractfile(m).read().decode("utf-8", "replace")
    hits = [f"{name}:{n}: {p.pattern}" for name, body in parts.items() for n, line in enumerate(body.splitlines(), 1)
            for p in pats if p.search(line)]
    if hits:
        raise SystemExit("Not released: the build matches deploy/private-words.txt\n  " + "\n  ".join(hits[:40]))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--publish", action="store_true")
    args = ap.parse_args()
    if not os.path.exists(KEY):
        raise SystemExit(f"No release key at {KEY} (set HM_RELEASE_KEY)")
    version = app_version()
    shutil.rmtree(DIST, ignore_errors=True)
    os.makedirs(DIST)
    out = os.path.join(DIST, "infra.sh")
    subprocess.run([sys.executable, os.path.join(ROOT, "deploy", "build.py"), "--reset-settings"], check=True, cwd=ROOT,
                   env=dict(os.environ, HM_BUILD_OUT=out))
    with open(out, encoding="utf-8") as f:
        text = f.read()
    if f'VERSION="{version}"' not in text:
        raise SystemExit("The build does not carry the app's version")
    check_private(text)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", KEY, "-n", NAMESPACE, out], check=True, capture_output=True,
                   stdin=subprocess.DEVNULL)
    with open(out, "rb") as data:
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", SIGNERS, "-I", IDENTITY, "-n", NAMESPACE, "-s", out + ".sig"],
                           stdin=data, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("The signature does not match deploy/release-signers: wrong key? " + r.stderr)
    sums = []
    for name in ("infra.sh", "infra.sh.sig"):
        with open(os.path.join(DIST, name), "rb") as f:
            sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {name}")
    with open(os.path.join(DIST, "SHA256SUMS"), "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(sums) + "\n")
    sys.path.insert(0, os.path.join(ROOT, "deploy"))
    import changelog_md
    notes = changelog_md.notes_for(version) + (
        "\n### Installing or upgrading\n\n"
        "- **From the web page:** Settings, Updates, then Check for updates (installs made with 0.8.0 or later).\n"
        "- **On the Proxmox host:** download `infra.sh`, then `bash infra.sh` for a new install or `bash infra.sh --upgrade`.\n"
        "- **Check the download:** `sha256sum -c SHA256SUMS`, or verify the signature with `release-signers` from the repository:\n"
        f"  `ssh-keygen -Y verify -f deploy/release-signers -I {IDENTITY} -n {NAMESPACE} -s infra.sh.sig < infra.sh`\n")
    with open(os.path.join(DIST, "NOTES.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(notes)
    print(f"Release {version} ready in {DIST}: infra.sh, infra.sh.sig, SHA256SUMS, NOTES.md")
    if args.publish:
        gh = shutil.which("gh") or r"C:\Program Files\GitHub CLI\gh.exe"
        subprocess.run([gh, "release", "create", f"v{version}", os.path.join(DIST, "infra.sh"), os.path.join(DIST, "infra.sh.sig"),
                        os.path.join(DIST, "SHA256SUMS"), "--repo", REPO, "--title", f"Home Monitor {version}",
                        "--notes-file", os.path.join(DIST, "NOTES.md"), "--target", "main"], check=True)
        print(f"Published https://github.com/{REPO}/releases/tag/v{version}")


if __name__ == "__main__":
    main()
