"""Container-side helper for the deploy, backup and restore scripts. Standard library plus the app's vault.

  sitectl.py derive-key  --data DIR --key FILE [--migrate]   passphrase on stdin (older backups)
  sitectl.py backup      --data DIR --key FILE [--dest DIR] [--keep 7] [--passphrase-file F]
                         default destination: Syncthing folder from setup, else DIR/backups
  sitectl.py restore     ARCHIVE --data DIR --key FILE [--passphrase-file F | --passphrase-stdin]
  sitectl.py verify      ARCHIVE [--passphrase-file F | --passphrase-stdin]   the restore's checks only
  sitectl.py find-backups --data DIR [--also DIR]            backups here, in Syncthing and on mounted shares
  sitectl.py site-of     ARCHIVE                             the site settings a backup would apply
  sitectl.py export-site --data DIR --out FILE
  sitectl.py apply-site  FILE [--fstab /etc/fstab] [--dry-run]
  sitectl.py accounts    --data DIR                          user names, role and 2FA (read only)
  sitectl.py reset-password --data DIR --user NAME [--reset-2fa]   new password on stdin
  sitectl.py new-setup-code --data DIR --env FILE            only while no account exists

The last three back /root/reset-admin.sh and /root/setup-code.sh: root on the container is the
final authority when the web login is lost. A new setup code is refused once any account
exists, so the code cannot be used to take over an install that is already set up.

A backup is everything needed to bring the monitor back with no questions:
the database, vault.json, the vault key, the site settings and a manifest.
The key travels with the data so restoring never needs a passphrase; the
backup folder must therefore be kept as private as a password (it is on a
NAS through Syncthing, or on an NFS share). The database alone,
copied anywhere, still has every secret encrypted. With a backup passphrase
set (BACKUP_PASSPHRASE in infra.sh, kept on the container in
/etc/homelab-monitor-install/backup-passphrase, root only) the key is sealed
with it instead (vault.key.sealed): a copy of the share alone opens nothing.

Root runs this file, and what it reads (the database, a backup) can be written by others: the
site settings are checked again here (sitecheck.py) before anything is mounted, copied or
given a new owner, and files are written without following symbolic links.
Older backups (format 1) carried no key: they were opened with a passphrase
through derive-key, or with the key line pasted by restore.sh.
Site settings (NFS mounts, Syncthing) are written into each backup as
site.json and re-applied on restore; applying is idempotent.

Across builds (compat.py): the manifest records the database schema and app version. Restore
checks the backup's database against this build before anything is replaced: a backup from a
newer build is refused (upgrade the app first), a damaged one is refused, and an older one is
migrated on a private copy first (the trial), so a restore that would fail stops with the
current data untouched. What an old backup carries that this build no longer has is kept as is.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (HERE, os.path.dirname(HERE)):
    if os.path.exists(os.path.join(candidate, "vault.py")) and candidate not in sys.path:
        sys.path.insert(0, candidate)

import vault  # noqa: E402
import sitecheck  # noqa: E402

try:
    import compat  # noqa: E402  (the app's own checker; present in every build that ships this file)
except ImportError:
    compat = None


def _schema_of(db: str) -> int:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return int(conn.execute("PRAGMA user_version;").fetchone()[0])
    finally:
        conn.close()


def _app_version() -> str:
    # Beside this file in the container; one folder up in the source tree (deploy/).
    for folder in (HERE, os.path.dirname(HERE)):
        try:
            with open(os.path.join(folder, "server.py"), encoding="utf-8") as f:
                for line in f:
                    if line.startswith("APP_VERSION = "):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            continue
    return ""

BACKUP_MEMBERS = ("monitor.db", "vault.json", "vault.key", "vault.key.sealed", "site.json", "manifest.json")
INSTALL_DIR = "/etc/homelab-monitor-install"
PASSPHRASE_FILE = os.path.join(INSTALL_DIR, "backup-passphrase")
# A backup's file name: what the backup command writes, nothing a shell could read as code.
BACKUP_NAME = re.compile(r"monitor-backup-[A-Za-z0-9._-]{1,80}\.tar\.gz")
# Characters a backup's full path may hold (a share's folder can have spaces).
BACKUP_PATH = re.compile(r"[A-Za-z0-9._/ @+:-]{1,400}")
SEAL_N = 2 ** 17
SYNCTHING_HOME = "/var/lib/syncthing"
SYNCTHING_FILES = ("cert.pem", "key.pem", "config.xml")


def fail(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def read_meta(data: str) -> dict:
    try:
        with open(os.path.join(data, "vault.json"), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def derive_key(args) -> None:
    passphrase = sys.stdin.readline().rstrip("\n")
    if len(passphrase) < 12:
        fail("The passphrase must be at least 12 characters")
    meta = read_meta(args.data)
    if not meta.get("salt"):
        meta["salt"] = base64.b64encode(os.urandom(16)).decode()
        os.makedirs(args.data, exist_ok=True)
        with open(os.path.join(args.data, "vault.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=base64.b64decode(meta["salt"]), **vault.SCRYPT_PARAMS)
    if meta.get("check") and not args.migrate and vault.AESGCM is not None:
        try:
            ok = vault.Vault._open(vault.AESGCM(key), meta["check"], "vault:check") == vault.CHECK_PLAINTEXT
        except Exception:
            ok = False
        if not ok:
            fail("That passphrase does not match the one these backups were made with", 2)
    os.makedirs(os.path.dirname(args.key), mode=0o700, exist_ok=True)
    tmp = args.key + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(base64.b64encode(key).decode() + "\n")
    os.replace(tmp, args.key)
    print(f"Key written to {args.key}")


def site_from_db(db: str) -> dict:
    if not os.path.exists(db):
        return {}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = 'site_settings';").fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    try:
        return json.loads(row[0]) if row and row[0] else {}
    except ValueError:
        return {}


def export_site(args) -> None:
    site = site_from_db(os.path.join(args.data, "monitor.db"))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(site, f, indent=2)
    print(f"Site settings written to {args.out}")


def _passphrase(args) -> str:
    """The backup passphrase: typed (stdin), else the file root keeps, else none."""
    if getattr(args, "passphrase_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    path = getattr(args, "passphrase_file", None) or PASSPHRASE_FILE
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def seal_key(key: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    k = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=SEAL_N, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32)
    data = vault.AESGCM(k).encrypt(nonce, key, b"homelab-monitor backup key")
    return json.dumps({"format": 1, "kdf": "scrypt", "n": SEAL_N, "r": 8, "p": 1,
                       "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
                       "data": base64.b64encode(data).decode()}).encode()


def unseal_key(blob: bytes, passphrase: str) -> bytes:
    """The vault key from vault.key.sealed; exits with 4 when the passphrase is missing or wrong."""
    if not passphrase:
        fail("This backup's key is sealed with a backup passphrase. Give it (BACKUP_PASSPHRASE in infra.sh, "
             "or type it when asked)", 4)
    try:
        meta = json.loads(blob)
        n, r, p = int(meta["n"]), int(meta["r"]), int(meta["p"])
        if not (2 ** 14 <= n <= 2 ** 20 and 1 <= r <= 16 and 1 <= p <= 4):
            raise ValueError("unexpected parameters")
        k = hashlib.scrypt(passphrase.encode("utf-8"), salt=base64.b64decode(meta["salt"]), n=n, r=r, p=p,
                           maxmem=512 * 1024 * 1024, dklen=32)
        return vault.AESGCM(k).decrypt(base64.b64decode(meta["nonce"]), base64.b64decode(meta["data"]),
                                       b"homelab-monitor backup key")
    except Exception:
        fail("The backup passphrase does not open this backup's key", 4)


def backup(args) -> None:
    db = os.path.join(args.data, "monitor.db")
    if not os.path.exists(db):
        fail(f"No database at {db}")
    if not args.dest:
        st = site_from_db(db).get("syncthing") or {}
        args.dest = os.path.join(args.data, "backups")
        if st.get("enabled") and st.get("data_folder"):
            # The folder comes from the database: used only when it passes the same checks as setup.
            try:
                folder = sitecheck.folder(st["data_folder"], "Syncthing backup folder")
                sitecheck.no_symlinks(folder)
                args.dest = folder
            except sitecheck.SiteError as exc:
                print(f"Note: {exc}. Backing up to {args.dest} instead.", file=sys.stderr)
    os.makedirs(args.dest, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    work = tempfile.mkdtemp(prefix="hm-backup-")
    try:
        # The SQLite backup API gives a consistent copy while the service keeps writing.
        src, dst = sqlite3.connect(db), sqlite3.connect(os.path.join(work, "monitor.db"))
        src.backup(dst)
        src.close()
        dst.close()
        meta = os.path.join(args.data, "vault.json")
        if os.path.exists(meta):
            shutil.copy2(meta, os.path.join(work, "vault.json"))
        has_key = bool(args.key) and os.path.exists(args.key)
        passphrase = _passphrase(args) if has_key else ""
        sealed = has_key and bool(passphrase)
        if sealed:
            if vault.AESGCM is None:
                fail("Sealing the key needs the cryptography package")
            with open(args.key, "rb") as f:
                blob = seal_key(f.read(), passphrase)
            with open(os.path.join(work, "vault.key.sealed"), "wb") as f:
                f.write(blob)
        elif has_key:
            shutil.copy2(args.key, os.path.join(work, "vault.key"))
            os.chmod(os.path.join(work, "vault.key"), 0o600)
        with open(os.path.join(work, "site.json"), "w", encoding="utf-8") as f:
            json.dump(site_from_db(db), f, indent=2)
        with open(os.path.join(work, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump({"app": "homelab-monitor", "created": stamp, "host": socket.gethostname(), "format": 2,
                       "schema": _schema_of(os.path.join(work, "monitor.db")), "app_version": _app_version(),
                       "includes_key": has_key, "key_sealed": sealed, "contents": [m for m in BACKUP_MEMBERS if m != "manifest.json"]}, f, indent=2)
        name = os.path.join(args.dest, f"monitor-backup-{stamp}.tar.gz")
        # The archive holds the key: readable by its owner only. A new file with a random name
        # (never a path someone else could have put a link at), renamed into place when complete.
        fd, part = tempfile.mkstemp(prefix=".monitor-backup-", suffix=".part", dir=args.dest)
        try:
            with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
                for member in BACKUP_MEMBERS:
                    path = os.path.join(work, member)
                    if os.path.exists(path):
                        tar.add(path, arcname=member)
            os.replace(part, name)
        except BaseException:
            if os.path.exists(part):
                os.remove(part)
            raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    kept = sorted(f for f in os.listdir(args.dest) if f.startswith("monitor-backup-") and f.endswith(".tar.gz"))
    for old in kept[:-args.keep] if args.keep > 0 else []:
        os.remove(os.path.join(args.dest, old))
    write_result(args.data, "backup", True, f"Backup written: {name}", file=os.path.basename(name), folder=args.dest)
    print(name)


def _unpack_and_check(archive: str, work: str, passphrase: str = "") -> None:
    """Unpacks a backup into work and checks it against this build; fails (nothing touched) if it cannot be restored.
    A sealed key is opened with the passphrase into work/vault.key."""
    if not os.path.exists(archive):
        fail(f"No such backup: {archive}")
    try:
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
            # Only the known flat members: no paths, links or devices can come out of an archive.
            if not set(names) <= set(BACKUP_MEMBERS) or "monitor.db" not in names:
                fail("This file is not a Homelab Monitor backup")
            for m in tar.getmembers():
                if not m.isfile():
                    fail("Backup contains an unexpected entry")
                with tar.extractfile(m) as src, open(os.path.join(work, m.name), "wb") as dst:
                    shutil.copyfileobj(src, dst)
    except (tarfile.TarError, OSError, EOFError) as exc:
        fail(f"This backup cannot be read ({type(exc).__name__}: {exc})")
    sealed = os.path.join(work, "vault.key.sealed")
    if os.path.exists(sealed):
        if vault.AESGCM is None:
            fail("Opening a sealed key needs the cryptography package")
        with open(sealed, "rb") as f:
            key = unseal_key(f.read(), passphrase)
        fd = os.open(os.path.join(work, "vault.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        os.remove(sealed)
    check = sqlite3.connect(os.path.join(work, "monitor.db"))
    try:
        ok = check.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
    except sqlite3.DatabaseError:
        ok = False
    finally:
        check.close()
    if not ok:
        fail("The database in this backup is damaged")
    if compat is not None:
        # Can this build run on it? Checked (and an older one migrated on a copy) before anything is replaced.
        key = os.path.join(work, "vault.key")
        report = compat.check(os.path.join(work, "monitor.db"), key if os.path.exists(key) else None,
                              run_trial=os.path.exists(key))
        print(f"Backup check: {report['message']}")
        if report.get("trial"):
            print(f"Backup check: {report['trial']['message']}")
        for note in report["notes"]:
            print(f"Note: {note}")
        if report["exit"] != 0:
            fail("This backup cannot be restored by this build; the current data was not touched", report["exit"])


def verify(args) -> None:
    """Only the checks a restore makes first: can this build restore the backup? Changes nothing."""
    work = tempfile.mkdtemp(prefix="hm-verify-")
    try:
        _unpack_and_check(args.archive, work, _passphrase(args))
        print(f"Backup can be restored: {os.path.basename(args.archive)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


SHARE_TYPES = ("nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "virtiofs")


def _backup_folders(data: str, mounts_file: str) -> list:
    """(folder, where, depth) to search: the container's own folder, the Syncthing folder, its NFS mounts, any other share."""
    found = [(os.path.join(data, "backups"), "this container", 2)]
    site = site_from_db(os.path.join(data, "monitor.db"))
    st = site.get("syncthing") or {}
    if st.get("data_folder"):
        found.append((st["data_folder"], "Syncthing folder", 2))
    for m in (site.get("nfs") or {}).get("mounts", []):
        if m.get("target"):
            found.append((m["target"], f"share {m.get('source') or m['target']}", 3))
    try:
        with open(mounts_file, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2] in SHARE_TYPES:
                    found.append((parts[1].replace("\\040", " "), f"share {parts[0]}", 3))
    except OSError:
        pass
    return found


def find_backups(args) -> None:
    """One line per backup, newest first: path|unix time|bytes|app version|key included|where it was found."""
    seen, rows = set(), []
    folders = _backup_folders(args.data, args.mounts) + [(d, "folder " + d, 3) for d in args.also or []]
    for folder, where, depth in folders:
        if not os.path.isdir(folder):
            continue
        base = folder.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(folder):
            if root.count(os.sep) - base >= depth:
                dirs[:] = []
            for name in files:
                if not BACKUP_NAME.fullmatch(name):
                    continue
                path = os.path.join(root, name)
                real = os.path.realpath(path)
                # Only plain names and paths: the installer shows and copies what is listed here.
                if real in seen or not BACKUP_PATH.fullmatch(path.replace(os.sep, '/')) or os.path.islink(path):
                    continue
                seen.add(real)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                version, has_key = "", ""
                try:
                    with tarfile.open(path, "r:gz") as tar:
                        member = tar.extractfile("manifest.json")
                        manifest = json.load(member) if member else {}
                    version = str(manifest.get("app_version") or "")
                    has_key = "sealed key" if manifest.get("key_sealed") else "key" if manifest.get("includes_key") else "no key"
                except (tarfile.TarError, OSError, EOFError, KeyError, ValueError):
                    version = "unreadable"
                rows.append((st.st_mtime, f"{path}|{int(st.st_mtime)}|{st.st_size}|{version}|{has_key}|{where}"))
    for _, line in sorted(rows, reverse=True)[: args.limit]:
        print(line)


def site_lines(site: dict) -> list:
    """What applying these site settings would do, one line each; a line starting with ! is refused."""
    try:
        clean = sitecheck.check_site(site)
    except sitecheck.SiteError as exc:
        return [f"!{exc}"]
    out = []
    st = clean["syncthing"]
    if st["enabled"]:
        out.append(f"Syncthing: identity from {st['keys_source']}, backups in {st['data_folder']}")
    for m in clean["nfs"].get("mounts", []):
        out.append(f"NFS: {m['source']} on {m['target']} ({m['options']})")
    return out or ["Nothing: NFS and Syncthing are off"]


def site_of(args) -> None:
    """The site settings inside a backup, as lines (nothing is applied)."""
    try:
        with tarfile.open(args.archive, "r:gz") as tar:
            member = tar.extractfile("site.json") if "site.json" in tar.getnames() else None
            site = json.load(member) if member else {}
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        fail(f"This backup cannot be read ({type(exc).__name__})")
    for line in site_lines(site):
        print(line)


def restore(args) -> None:
    work = tempfile.mkdtemp(prefix="hm-restore-")
    try:
        _unpack_and_check(args.archive, work, _passphrase(args))
        os.makedirs(args.data, exist_ok=True)
        keep = os.path.join(args.data, f"pre-restore-{time.strftime('%Y%m%d-%H%M%S')}")
        moved = [f for f in os.listdir(args.data) if f.startswith(("monitor.db", "vault.json"))]
        if moved:
            os.makedirs(keep)
            for f in moved:
                shutil.move(os.path.join(args.data, f), os.path.join(keep, f))
        for member in ("monitor.db", "vault.json"):
            if os.path.exists(os.path.join(work, member)):
                shutil.move(os.path.join(work, member), os.path.join(args.data, member))
        if os.path.exists(os.path.join(work, "site.json")):
            shutil.move(os.path.join(work, "site.json"), os.path.join(args.data, "site-restored.json"))
        if args.key:
            if os.path.exists(args.key):
                os.makedirs(keep, exist_ok=True)
                shutil.move(args.key, os.path.join(keep, "vault.key"))
                moved.append("vault.key")
            if os.path.exists(os.path.join(work, "vault.key")):
                os.makedirs(os.path.dirname(args.key) or ".", mode=0o700, exist_ok=True)
                shutil.move(os.path.join(work, "vault.key"), args.key)
                os.chmod(args.key, 0o600)
        print(f"Restored into {args.data}" + (f"; previous files kept in {keep}" if moved else ""))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(cmd: list, dry: bool) -> None:
    print("+ " + " ".join(cmd))
    if not dry:
        subprocess.run(cmd, check=True)


def can_mount() -> bool:
    """False in an unprivileged container (root is mapped to another user and cannot mount NFS)."""
    if os.environ.get("HM_FAKE_UNPRIVILEGED"):
        return False
    try:
        with open("/proc/self/uid_map", encoding="ascii") as f:
            first = f.read().split()
    except OSError:
        return True
    return first[:3] == ["0", "0", "4294967295"]


def _write_root_file(path: str, data: bytes, mode: int) -> None:
    """Writes path through a new file in the same folder, then renames it: a link put at path is replaced, not followed."""
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".hm-", dir=folder)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _fstab_update(fstab_path: str, mounts: list, dry: bool) -> None:
    try:
        with open(fstab_path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    changed = False
    for m in mounts:
        line = f"{m['source']} {m['target']} nfs {m['options']} 0 0"
        found = False
        for i, old in enumerate(lines):
            parts = old.split()
            if old.lstrip().startswith("#") or len(parts) < 4 or parts[1] != m["target"]:
                continue
            found = True
            # An entry this tool wrote earlier, without the hardening: brought up to date.
            if parts[0] == m["source"] and parts[2] == "nfs" and parts[3] != m["options"]:
                print(f"  update {fstab_path}: {line}")
                lines[i] = line
                changed = True
            else:
                print("  already in fstab")
        if not found:
            print(f"  add to {fstab_path}: {line}")
            lines.append(line)
            changed = True
    if changed and not dry:
        with open(fstab_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def _syncthing_identity(st: dict, cfg: str, dry: bool) -> None:
    """cert.pem, key.pem and a checked config.xml into Syncthing's folder, from the identity share
    (mounted read-only here) or from the folder the Proxmox host copied them into."""
    staged = os.path.isdir(sitecheck.STAGING) and all(
        os.path.exists(os.path.join(sitecheck.STAGING, f)) for f in SYNCTHING_FILES)
    tmp = None
    if st["keys_source"] == sitecheck.STAGING or (staged and not can_mount()):
        src = sitecheck.STAGING
        print(f"Syncthing identity from {src} (copied in by the Proxmox host) into {cfg}")
    elif not can_mount():
        fail("This container is unprivileged and cannot mount NFS shares. Set SYNCTHING_KEYS_NFS at the top of "
             "infra.sh and run bash infra.sh --upgrade on the Proxmox host: it copies the Syncthing identity in")
    else:
        print(f"Syncthing identity from {st['keys_source']} into {cfg}")
        tmp = tempfile.mkdtemp(prefix="hm-stkeys-")
        src = tmp
    try:
        if tmp:
            run(["mount", "-t", "nfs", "-o", "ro,nosuid,nodev,noexec", st["keys_source"], tmp], dry)
        if dry:
            return
        missing = [f for f in SYNCTHING_FILES if not os.path.isfile(os.path.join(src, f))]
        if missing:
            fail(f"{st['keys_source']} is missing {', '.join(missing)}")
        files = {}
        for name in SYNCTHING_FILES:
            with open(os.path.join(src, name), "rb") as f:
                files[name] = f.read(4 * 1024 * 1024)
        try:
            files["config.xml"] = sitecheck.check_syncthing_config(files["config.xml"], st["data_folder"], SYNCTHING_HOME)
        except sitecheck.SiteError as exc:
            fail(str(exc))
        run(["systemctl", "stop", "syncthing@syncthing"], dry)
        sitecheck.no_symlinks(cfg)
        os.makedirs(cfg, exist_ok=True)
        for name, data in files.items():
            _write_root_file(os.path.join(cfg, name), data, 0o644 if name == "cert.pem" else 0o600)
    finally:
        if tmp and not dry:
            subprocess.run(["umount", tmp])
        if tmp and os.path.isdir(tmp) and not os.listdir(tmp):
            os.rmdir(tmp)


def apply_site(args) -> None:
    with open(args.file, encoding="utf-8") as f:
        raw = json.load(f)
    dry = args.dry_run
    try:
        site = sitecheck.check_site(raw)
    except sitecheck.SiteError as exc:
        fail(f"Site settings refused, nothing was applied: {exc}")
    nfs, st = site["nfs"], site["syncthing"]
    try:
        for path in [m["target"] for m in nfs.get("mounts", [])] + ([st["data_folder"]] if st["enabled"] else []):
            sitecheck.no_symlinks(path)
    except sitecheck.SiteError as exc:
        fail(f"Site settings refused, nothing was applied: {exc}")
    if nfs["enabled"]:
        mounts = nfs["mounts"]
        for m in mounts:
            print(f"NFS {m['source']} -> {m['target']}")
        if not can_mount():
            missing = [m for m in mounts if not os.path.ismount(m["target"])]
            for m in mounts:
                if m not in missing:
                    print(f"  {m['target']} is mounted (passed in by the Proxmox host)")
            if missing:
                fail("This container is unprivileged and cannot mount NFS shares. On the Proxmox host, mount "
                     + ", ".join(m["source"] for m in missing) + " and pass it in, for example: pct set <CT> -mp0 "
                     "/mnt/pve/<storage>,mp=" + missing[0]["target"])
        else:
            _fstab_update(args.fstab, mounts, dry)
            for m in mounts:
                if not dry:
                    os.makedirs(m["target"], exist_ok=True)
                    if subprocess.run(["mountpoint", "-q", m["target"]]).returncode != 0:
                        run(["mount", m["target"]], dry)
    if st["enabled"]:
        cfg = os.path.join(SYNCTHING_HOME, ".config", "syncthing")
        _syncthing_identity(st, cfg, dry)
        if not dry:
            os.makedirs(st["data_folder"], exist_ok=True)
        # The folder is below /mnt or /srv with no links (checked above); chown -R does not follow links inside it.
        run(["chown", "-R", "syncthing:syncthing", SYNCTHING_HOME, st["data_folder"]], dry)
        run(["systemctl", "enable", "--now", "syncthing@syncthing"], dry)
    if not st["enabled"] and not dry and subprocess.run(["systemctl", "is-enabled", "--quiet", "syncthing@syncthing"]).returncode == 0:
        run(["systemctl", "disable", "--now", "syncthing@syncthing"], dry)
        print("Syncthing is off in the site settings: stopped. Backups are kept locally again.")
    if not nfs["enabled"] and not st["enabled"]:
        print("Nothing to apply: NFS and Syncthing are off in these site settings")


# --- Requests from the web app -------------------------------------------------------------
# The app runs as an unprivileged user and cannot mount shares or start Syncthing. It writes a
# request file under DATA/requests; a systemd path unit runs these commands as root and they
# leave DATA/<kind>.result.json for the Settings page. Only fixed actions exist: the request
# file's content is never executed or trusted.

def write_result(data: str, kind: str, ok: bool, output: str, **extra) -> None:
    """DATA/<kind>.result.json for the Settings page. Root writes it into a folder the app owns, so it
    goes through a new file with a random name and is renamed into place: a link someone put at
    the result's path is replaced, never written through, and the owner change does not follow links."""
    path = os.path.join(data, f"{kind}.result.json")
    fd, tmp = tempfile.mkstemp(prefix=f".{kind}.", suffix=".new", dir=data)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dict({"time": int(time.time()), "ok": ok, "output": output[-4000:]}, **extra), f)
        owner = os.stat(data)
        try:
            os.chown(tmp, owner.st_uid, owner.st_gid, follow_symlinks=False)
        except (AttributeError, PermissionError, NotImplementedError):
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def site_request(args) -> None:
    """Applies the site settings stored in the database (NFS mounts, Syncthing) and records the outcome."""
    import contextlib
    import io
    site = site_from_db(os.path.join(args.data, "monitor.db"))
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    with tmp:
        json.dump(site, tmp)
    out = io.StringIO()
    ok = True
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            apply_site(argparse.Namespace(file=tmp.name, fstab=args.fstab, dry_run=False))
    except SystemExit as exc:
        ok = exc.code in (0, None)
    except Exception as exc:  # recorded for the administrator; the unit's journal has the trace
        ok = False
        print(f"{type(exc).__name__}: {exc}", file=out)
    finally:
        os.remove(tmp.name)
    write_result(args.data, "site", ok, out.getvalue() or "Nothing to apply")
    print(out.getvalue())
    if not ok:
        sys.exit(1)


def _accounts(data: str) -> list:
    db = os.path.join(data, "monitor.db")
    if not os.path.exists(db):
        return []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(accounts);")}
        if not cols:
            return []
        extra = ", ".join(c for c in ("role", "disabled", "totp_enabled") if c in cols)
        rows = conn.execute(f"SELECT username{', ' + extra if extra else ''} FROM accounts ORDER BY username;").fetchall()
        names = ["username"] + [c for c in ("role", "disabled", "totp_enabled") if c in cols]
        return [dict(zip(names, r)) for r in rows]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def accounts(args) -> None:
    for a in _accounts(args.data):
        print(f"{a['username']}\t{a.get('role') or 'admin'}\t{'blocked' if a.get('disabled') else 'active'}\t"
              f"{'2fa' if a.get('totp_enabled') else 'no-2fa'}")


def reset_password(args) -> None:
    """New password (stdin) for one account; optionally turns its 2FA off. The service is restarted
    by the calling script, which ends every session (they live in memory)."""
    import auth
    password = sys.stdin.readline().rstrip("\n")
    problem = auth.password_problem(password)
    if problem:
        fail(problem)
    if args.user not in {a["username"] for a in _accounts(args.data)}:
        fail(f"No account named {args.user}")
    conn = sqlite3.connect(os.path.join(args.data, "monitor.db"))
    try:
        now = int(time.time())
        conn.execute("UPDATE accounts SET password_hash = ?, disabled = 0, updated_at = ? WHERE username = ?;",
                     (auth.hash_password(password), now, args.user))
        if args.reset_2fa:
            conn.execute("UPDATE accounts SET totp_secret = NULL, totp_enabled = 0, totp_recovery = '[]', "
                         "totp_last_step = NULL WHERE username = ?;", (args.user,))
        conn.execute("INSERT INTO audit_log (timestamp, category, message, details) VALUES (?, 'auth', ?, ?);",
                     (now, f"Password reset from the container shell for {args.user}",
                      "2FA turned off too" if args.reset_2fa else "2FA unchanged"))
        conn.commit()
    finally:
        conn.close()
    print(f"Password reset for {args.user}")


def tls_off(args) -> None:
    """Plain HTTP again (a certificate that locks everyone out); the stored certificate is kept."""
    conn = sqlite3.connect(os.path.join(args.data, "monitor.db"))
    try:
        now = int(time.time())
        conn.execute("INSERT INTO settings (key, value, description, updated_at) VALUES ('tls_mode', 'off', '', ?) "
                     "ON CONFLICT (key) DO UPDATE SET value = 'off', updated_at = excluded.updated_at;", (now,))
        conn.execute("INSERT INTO audit_log (timestamp, category, message, details) VALUES (?, 'system', ?, '');",
                     (now, "HTTPS switched off from the container shell"))
        conn.commit()
    finally:
        conn.close()
    print("HTTPS is off; the web interface answers on plain HTTP.")


def new_setup_code(args) -> None:
    """Writes a fresh MONITOR_SETUP_TOKEN, only while no account exists (second lock: /api/auth/setup
    refuses as soon as an account exists, whatever the code)."""
    if _accounts(args.data):
        fail("An account already exists, so the setup code is no longer used. Log in, or reset a password "
             "with /root/reset-admin.sh.", 3)
    code = base64.b32encode(os.urandom(15)).decode().rstrip("=")
    tmp = args.env + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(f"MONITOR_SETUP_TOKEN={code}\n")
    os.replace(tmp, args.env)
    print(code)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("derive-key")
    p.add_argument("--data", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--migrate", action="store_true", help="skip the check: the data is still sealed with an older key")
    p.set_defaults(fn=derive_key)
    p = sub.add_parser("backup")
    p.add_argument("--data", required=True)
    p.add_argument("--key", help="vault key file to include")
    p.add_argument("--dest")
    p.add_argument("--keep", type=int, default=7)
    p.add_argument("--passphrase-file", help=f"seal the key with the passphrase in this file (default {PASSPHRASE_FILE})")
    p.set_defaults(fn=backup)
    for name, fn in (("restore", restore), ("verify", verify)):
        p = sub.add_parser(name)
        p.add_argument("archive")
        if name == "restore":
            p.add_argument("--data", required=True)
            p.add_argument("--key", help="where the restored vault key goes")
        p.add_argument("--passphrase-file", help=f"for a sealed key (default {PASSPHRASE_FILE})")
        p.add_argument("--passphrase-stdin", action="store_true", help="for a sealed key: read the passphrase from stdin")
        p.set_defaults(fn=fn)
    p = sub.add_parser("site-of")
    p.add_argument("archive")
    p.set_defaults(fn=site_of)
    p = sub.add_parser("find-backups")
    p.add_argument("--data", required=True)
    p.add_argument("--also", action="append", help="another folder to search")
    p.add_argument("--mounts", default="/proc/mounts")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(fn=find_backups)
    p = sub.add_parser("export-site")
    p.add_argument("--data", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=export_site)
    p = sub.add_parser("site-request")
    p.add_argument("--data", required=True)
    p.add_argument("--fstab", default="/etc/fstab")
    p.set_defaults(fn=site_request)
    p = sub.add_parser("apply-site")
    p.add_argument("file")
    p.add_argument("--fstab", default="/etc/fstab")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=apply_site)
    p = sub.add_parser("accounts")
    p.add_argument("--data", required=True)
    p.set_defaults(fn=accounts)
    p = sub.add_parser("reset-password")
    p.add_argument("--data", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--reset-2fa", action="store_true")
    p.set_defaults(fn=reset_password)
    p = sub.add_parser("tls-off")
    p.add_argument("--data", required=True)
    p.set_defaults(fn=tls_off)
    p = sub.add_parser("new-setup-code")
    p.add_argument("--data", required=True)
    p.add_argument("--env", required=True)
    p.set_defaults(fn=new_setup_code)
    args = ap.parse_args()
    if args.fn is backup:
        # A failed backup is recorded as well, so Settings, Backups shows it rather than the last success.
        try:
            args.fn(args)
        except SystemExit as exc:
            if exc.code not in (0, None):
                write_result(args.data, "backup", False, "Backup failed (see the command output or journal)")
            raise
        except Exception as exc:
            write_result(args.data, "backup", False, f"Backup failed: {type(exc).__name__}: {exc}")
            raise
        return
    args.fn(args)


if __name__ == "__main__":
    main()
