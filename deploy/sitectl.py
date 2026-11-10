"""Container-side helper for the deploy, backup and restore scripts. Standard library plus the app's vault.

  sitectl.py derive-key  --data DIR --key FILE [--migrate]   passphrase on stdin (older backups)
  sitectl.py backup      --data DIR --key FILE [--dest DIR] [--keep 7] [--passphrase-file F] [--safety]
                         default destination: Syncthing folder from setup, else DIR/backups
  sitectl.py restore     ARCHIVE --data DIR --key FILE [--passphrase-file F | --passphrase-stdin]
                         [--accept-unverified] [--forget-secrets] [--expect-sha256 HEX] [--record-name NAME]
  sitectl.py verify      ARCHIVE [same options]                the restore's checks only
  sitectl.py check-auth  ARCHIVE --key FILE [same options]     can the backup be proven unchanged? (no trial)
  sitectl.py take        ARCHIVE --to FILE                     a private copy of a backup to work on
  sitectl.py set-passphrase --data DIR                         the backup passphrase, on stdin
  sitectl.py find-backups --data DIR [--also DIR]            backups here, in Syncthing and on mounted shares
  sitectl.py site-of     ARCHIVE                             the site settings a backup would apply
  sitectl.py export-site --data DIR --out FILE
  sitectl.py apply-site  FILE [--fstab /etc/fstab] [--dry-run]
  sitectl.py accounts    --data DIR                          user names, role and 2FA (read only)
  sitectl.py reset-password --data DIR --user NAME [--reset-2fa]   new password on stdin
  sitectl.py new-setup-code --data DIR --env FILE            only while no account exists
  sitectl.py put-key     --key FILE                          a pasted key line (stdin) into place
  sitectl.py ask         --kind site --data DIR              a request for root, as the app would make it

The last three back /root/reset-admin.sh and /root/setup-code.sh: root on the container is the
final authority when the web login is lost. A new setup code is refused once any account
exists, so the code cannot be used to take over an install that is already set up.

A backup holds the database, vault.json, the site settings, a manifest and (depending on where it
goes) the vault key. With a backup passphrase (set with /root/backup-passphrase.sh, or
BACKUP_PASSPHRASE in home_monitor.sh; kept in /etc/homelab-monitor-install/backup-passphrase, root
only) every archive carries a tag that proves it unchanged, and the key travels sealed with the
passphrase (vault.key.sealed), so a copy of the share alone opens nothing. Without one, the key
stays only in backups kept inside the container: a backup that leaves the box (Syncthing, a share)
goes without it. Root's own safety copies (before an update, an upgrade, a restore or an undo) live
in /var/lib/homelab-monitor-safe, which only root can read, and always carry the key in the clear so
that Undo works whatever the passphrase is now. A restore checks the tag first: a backup it cannot
prove unchanged is shown (accounts and stored credential count) and needs a typed confirmation, or
--accept-unverified. Exit codes: 4 a passphrase is needed, 7 not proven unchanged, 8 no usable key.

Root runs this file, and what it reads (the database, a backup) can be written by others: the
site settings are checked again here (sitecheck.py) before anything is mounted, copied or
given a new owner. Every file root writes into a folder the app's account can change goes through
safefile.atomic_write (a new file made with O_EXCL and O_NOFOLLOW, owner and mode set on it, then
renamed), and files root reads there (vault.json, the key) are read only when they are plain files.
Changes to the database from the shell (reset-password, tls-off) run as the monitor's own account.
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
import gzip
import hashlib
import hmac
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
import safefile  # noqa: E402

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
# Root's own folder for safety copies (before an update, upgrade, restore or undo): the app cannot read it.
SAFE_DIR = "/var/lib/homelab-monitor-safe"
# The tag: HMAC-SHA-256 with a key from the passphrase, its own scrypt salt and label (sealing has others).
TAG_LABEL = b"homelab-monitor backup tag v1"
TAG_DOMAIN = b"homelab-monitor backup v1\x00"
TAG_N = 2 ** 17
# Unpacking limits: the whole archive, every small member, and room left on the disk.
MAX_TOTAL = 16 * 1024 ** 3
MAX_SMALL = 1024 * 1024
FREE_MARGIN = 256 * 1024 ** 2
PRE_RESTORE_KEEP, PRE_RESTORE_DAYS = 3, 30
EXIT_PASSPHRASE, EXIT_UNVERIFIED, EXIT_NO_KEY = 4, 7, 8
RECORD_NAME = re.compile(r"[A-Za-z0-9._-]{1,120}")
SYNCTHING_HOME = "/var/lib/syncthing"
SYNCTHING_FILES = ("cert.pem", "key.pem", "config.xml")


def fail(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def read_meta(data: str) -> dict:
    try:
        return json.loads(safefile.read_regular(os.path.join(data, "vault.json"), 1024 * 1024))
    except FileNotFoundError:
        return {}


def _owner_of(folder: str):
    """(uid, gid) of a folder, for files root puts in it (None when not root: nothing to set)."""
    if not safefile.is_root():
        return None
    st = os.stat(folder)
    return st.st_uid, st.st_gid


def _service_or_owner(folder: str):
    try:
        return safefile.service_ids() or _owner_of(folder)
    except KeyError:
        return _owner_of(folder)


ROOT_ACTOR = ("root", "container shell")


def _audit(conn, category: str, message: str, details: str = "", actor=ROOT_ACTOR) -> None:
    """One audit row written by root's scripts. Who and from where go in their own columns when the
    database has them: just after a restore it may still be one from before they existed."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log);")}
    if "actor" in cols and "source" in cols:
        conn.execute("INSERT INTO audit_log (timestamp, category, message, details, actor, source) VALUES (?, ?, ?, ?, ?, ?);",
                     (int(time.time()), category, message, details, actor[0], actor[1]))
    else:
        conn.execute("INSERT INTO audit_log (timestamp, category, message, details) VALUES (?, ?, ?, ?);",
                     (int(time.time()), category, message, details))


# The same, as a program the service account runs (set_passphrase writes as that account).
_AUDIT_PROGRAM = (
    "import sqlite3, sys, time\n"
    "c = sqlite3.connect(sys.argv[1])\n"
    "cols = {r[1] for r in c.execute('PRAGMA table_info(audit_log);')}\n"
    "row = (int(time.time()), sys.argv[2], sys.argv[3], sys.argv[4])\n"
    "if 'actor' in cols and 'source' in cols:\n"
    "    c.execute('INSERT INTO audit_log (timestamp, category, message, details, actor, source) VALUES (?, ?, ?, ?, ?, ?);', row + (sys.argv[5], sys.argv[6]))\n"
    "else:\n"
    "    c.execute('INSERT INTO audit_log (timestamp, category, message, details) VALUES (?, ?, ?, ?);', row)\n"
    "c.commit()\n"
    "c.close()\n")


def _no_link(path: str) -> str:
    """A database root opens with SQLite (which cannot refuse a link): a link is refused first."""
    if os.path.islink(path):
        fail(f"{path} is a link, so it was not used")
    return path


def derive_key(args) -> None:
    passphrase = sys.stdin.readline().rstrip("\n")
    if len(passphrase) < 12:
        fail("The passphrase must be at least 12 characters")
    meta = read_meta(args.data)
    if not meta.get("salt"):
        meta["salt"] = base64.b64encode(os.urandom(16)).decode()
        os.makedirs(args.data, exist_ok=True)
        safefile.atomic_write(args.data, "vault.json", json.dumps(meta, indent=2).encode("utf-8"), 0o600,
                              _service_or_owner(args.data))
    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=base64.b64decode(meta["salt"]), **vault.SCRYPT_PARAMS)
    if meta.get("check") and not args.migrate and vault.AESGCM is not None:
        try:
            ok = vault.Vault._open(vault.AESGCM(key), meta["check"], "vault:check") == vault.CHECK_PLAINTEXT
        except Exception:
            ok = False
        if not ok:
            fail("That passphrase does not match the one these backups were made with", 2)
    folder = os.path.dirname(os.path.abspath(args.key))
    os.makedirs(folder, mode=0o700, exist_ok=True)
    safefile.atomic_write(folder, os.path.basename(args.key), (base64.b64encode(key).decode() + "\n").encode("ascii"),
                          0o600, _service_or_owner(folder))
    print(f"Key written to {args.key}")


KEY_LINE = re.compile(r"[A-Za-z0-9+/]{43}=")


def put_key(args) -> None:
    """A key line pasted at restore.sh (stdin) into place, owned by the monitor's account, never through a link."""
    line = sys.stdin.readline().strip()
    if not KEY_LINE.fullmatch(line):
        fail("That is not a key line from vault.key")
    folder = os.path.dirname(os.path.abspath(args.key))
    os.makedirs(folder, mode=0o700, exist_ok=True)
    safefile.atomic_write(folder, os.path.basename(args.key), (line + "\n").encode("ascii"), 0o600, _service_or_owner(folder))
    print(f"Key written to {args.key}")


def ask(args) -> None:
    """A request file as the app writes it (its content is only a time), owned by the monitor's account."""
    folder = os.path.join(args.data, "requests")
    safefile.atomic_write(folder, args.kind, str(int(time.time())).encode("ascii"), 0o600, _service_or_owner(folder))


def site_from_db(db: str) -> dict:
    if not os.path.exists(db) or os.path.islink(db):
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
    """The backup passphrase: typed (stdin), else the file root keeps, else none. Read once per run."""
    if getattr(args, "_passphrase_read", None) is not None:
        return args._passphrase_read
    args._passphrase_read = _read_passphrase(args)
    return args._passphrase_read


def _read_passphrase(args) -> str:
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
        fail("This backup's key is sealed with a backup passphrase. Give it (BACKUP_PASSPHRASE in home_monitor.sh, "
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


def _safe_dir(args) -> str:
    """Root's safety folder: --safe-dir, else the fixed one when running as root. Empty when there is
    none (the test suite, a development copy): safety copies then stay beside the data as before."""
    return getattr(args, "safe_dir", None) or (SAFE_DIR if safefile.is_root() else "")


def _inside(path: str, folder: str) -> bool:
    if not folder:
        return False
    p, f = (os.path.normcase(os.path.realpath(x)) for x in (path, folder))
    return p == f or p.startswith(f.rstrip(os.sep) + os.sep)


def _place(args) -> str:
    """safe (root's own folder), local (DATA/backups, inside the container) or away (anything else,
    including a link that points outward: the real path decides)."""
    if _inside(args.dest, _safe_dir(args)):
        return "safe"
    if _inside(args.dest, os.path.join(args.data, "backups")):
        return "local"
    return "away"


def _canonical(manifest: dict) -> bytes:
    return json.dumps({k: v for k, v in manifest.items() if k != "auth"}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _tag_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=TAG_LABEL + salt, n=n, r=r, p=p,
                          maxmem=512 * 1024 * 1024, dklen=32)


def _tag_over(key: bytes, folder: str, manifest: dict) -> bytes:
    """HMAC over every member present, in BACKUP_MEMBERS order: name, length, bytes. The manifest
    counts in canonical form without its own auth field."""
    mac = hmac.new(key, TAG_DOMAIN, hashlib.sha256)
    for member in BACKUP_MEMBERS:
        if member == "manifest.json":
            body = _canonical(manifest)
            mac.update(member.encode() + b"\x00" + len(body).to_bytes(8, "big"))
            mac.update(body)
            continue
        path = os.path.join(folder, member)
        if not os.path.isfile(path):
            continue
        mac.update(member.encode() + b"\x00" + os.path.getsize(path).to_bytes(8, "big"))
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                mac.update(chunk)
    return mac.digest()


def make_tag(folder: str, manifest: dict, passphrase: str) -> dict:
    salt = os.urandom(16)
    tag = _tag_over(_tag_key(passphrase, salt, TAG_N, 8, 1), folder, manifest)
    return {"v": 1, "alg": "HMAC-SHA-256", "kdf": "scrypt", "n": TAG_N, "r": 8, "p": 1,
            "salt": base64.b64encode(salt).decode(), "tag": base64.b64encode(tag).decode()}


def check_tag(folder: str, manifest: dict, passphrase: str) -> bool:
    """True when the tag in the manifest proves the unpacked members unchanged with this passphrase."""
    auth = manifest.get("auth")
    try:
        n, r, p = int(auth["n"]), int(auth["r"]), int(auth["p"])
        if auth.get("v") != 1 or auth.get("alg") != "HMAC-SHA-256" or auth.get("kdf") != "scrypt":
            return False
        if not (2 ** 17 <= n <= 2 ** 20 and 1 <= r <= 16 and 1 <= p <= 4):
            return False
        salt, tag = base64.b64decode(auth["salt"], validate=True), base64.b64decode(auth["tag"], validate=True)
        if not (16 <= len(salt) <= 64) or len(tag) != 32:
            return False
        return hmac.compare_digest(_tag_over(_tag_key(passphrase, salt, n, r, p), folder, manifest), tag)
    except (TypeError, KeyError, ValueError, MemoryError):
        return False


def backup(args) -> None:
    db = os.path.join(args.data, "monitor.db")
    if not os.path.exists(db):
        fail(f"No database at {db}")
    _no_link(db)
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
    safe = _safe_dir(args)
    if safe and _inside(args.dest, safe):
        os.makedirs(safe, mode=0o700, exist_ok=True)
        os.makedirs(args.dest, mode=0o700, exist_ok=True)
    else:
        os.makedirs(args.dest, exist_ok=True)
    place = _place(args)
    if getattr(args, "safety", False) and place != "safe":
        fail(f"A safety copy goes into root's own folder ({safe or SAFE_DIR}), not {args.dest}")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    work = tempfile.mkdtemp(prefix="hm-backup-")
    key_state = "none"
    try:
        # The SQLite backup API gives a consistent copy while the service keeps writing.
        src, dst = sqlite3.connect(db), sqlite3.connect(os.path.join(work, "monitor.db"))
        src.backup(dst)
        src.close()
        dst.close()
        # vault.json and the key are read only when they are plain files (a link could point anywhere).
        meta = os.path.join(args.data, "vault.json")
        if os.path.lexists(meta):
            with open(os.path.join(work, "vault.json"), "wb") as f:
                f.write(safefile.read_regular(meta, 1024 * 1024))
        has_key = bool(args.key) and os.path.lexists(args.key)
        key_bytes = safefile.read_regular(args.key, 4096) if has_key else b""
        passphrase = _passphrase(args)
        # Where the key goes (see the module notes): root's folder always in the clear (Undo must work
        # whatever the passphrase is later); sealed when a passphrase exists; in the clear inside the
        # container; left out of a backup that leaves the box without a passphrase.
        sealed = withheld = False
        if has_key and place == "safe":
            key_state = "clear-safe"
        elif has_key and passphrase:
            sealed, key_state = True, "sealed"
        elif has_key and place == "local":
            key_state = "clear-local"
        elif has_key:
            withheld, key_state = True, "withheld"
        if sealed:
            if vault.AESGCM is None:
                fail("Sealing the key needs the cryptography package")
            blob = seal_key(key_bytes, passphrase)
            with open(os.path.join(work, "vault.key.sealed"), "wb") as f:
                f.write(blob)
        elif has_key and not withheld:
            fd = os.open(os.path.join(work, "vault.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key_bytes)
        with open(os.path.join(work, "site.json"), "w", encoding="utf-8") as f:
            json.dump(site_from_db(db), f, indent=2)
        manifest = {"app": "homelab-monitor", "created": stamp, "host": socket.gethostname(), "format": 3,
                    "schema": _schema_of(os.path.join(work, "monitor.db")), "app_version": _app_version(),
                    "includes_key": has_key and not withheld, "key_sealed": sealed, "key_withheld": withheld,
                    "contents": [m for m in BACKUP_MEMBERS if m != "manifest.json"]}
        if passphrase:
            manifest["auth"] = make_tag(work, manifest, passphrase)
        with open(os.path.join(work, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        name = os.path.join(args.dest, f"monitor-backup-{stamp}.tar.gz")
        # Packed in root's private work folder, then put into the destination through a new file with
        # a random name in the folder opened without following links (O_EXCL, O_NOFOLLOW), readable
        # by its owner only, renamed into place when complete.
        packed = os.path.join(work, "archive.tar.gz")
        with tarfile.open(packed, mode="w:gz") as tar:
            for member in BACKUP_MEMBERS:
                path = os.path.join(work, member)
                if os.path.exists(path):
                    tar.add(path, arcname=member)
        safefile.atomic_copy(args.dest, os.path.basename(name), packed, 0o600)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    kept = sorted(f for f in safefile.listdir(args.dest) if f.startswith("monitor-backup-") and f.endswith(".tar.gz"))
    for old in kept[:-args.keep] if args.keep > 0 else []:
        safefile.unlink_in(args.dest, old)
    message = f"Backup written: {name}"
    if key_state == "withheld":
        message += ". No backup passphrase is set, so the key was left out of this backup."
        print("Note: No backup passphrase is set, so the key was left out of this backup.", file=sys.stderr)
    if place != "safe":
        write_result(args.data, "backup", True, message, file=os.path.basename(name), folder=args.dest, key=key_state,
                     tagged=bool(passphrase))
    print(name)


class _TooBig(Exception):
    pass


class _Capped:
    """A reader that stops once more than limit bytes came through (the unpacked size of an archive)."""

    def __init__(self, f, limit: int):
        self.f, self.limit, self.count = f, limit, 0

    def read(self, n: int = -1) -> bytes:
        data = self.f.read(n if n is not None and n >= 0 else 1024 * 1024)
        self.count += len(data)
        if self.count > self.limit:
            raise _TooBig()
        return data


def _members(archive: str):
    """(TarFile in stream mode, TarInfo) pairs, read in one forward pass through a capped reader."""
    raw = open(archive, "rb")
    try:
        gz = gzip.GzipFile(fileobj=raw, mode="rb")
        tar = tarfile.open(fileobj=_Capped(gz, MAX_TOTAL + 1024 * 1024), mode="r|")
        for m in tar:
            yield tar, m
    finally:
        raw.close()


def small_member(archive: str, name: str):
    """One small member's bytes (the manifest or the site settings) through the capped reader, or None."""
    members = _members(archive)
    try:
        for tar, m in members:
            if m.name == name and m.isfile() and m.size <= MAX_SMALL:
                return tar.extractfile(m).read(MAX_SMALL)
        return None
    finally:
        members.close()


def _unpack(archive: str, work: str) -> list:
    """Every member into work, checked one by one before it is written; returns the names."""
    if not os.path.exists(archive):
        fail(f"No such backup: {archive}")
    names = []
    try:
        for tar, m in _members(archive):
            # Only the known flat members: no paths, links or devices can come out of an archive.
            if m.name not in BACKUP_MEMBERS:
                fail("This file is not a Homelab Monitor backup")
            if m.name in names:
                fail("This backup holds the same file twice, so it is refused")
            if not m.isfile():
                fail("Backup contains an unexpected entry")
            if m.size > (MAX_TOTAL if m.name == "monitor.db" else MAX_SMALL):
                fail(f"{m.name} in this backup is larger than a restore allows")
            if m.size > shutil.disk_usage(work).free - FREE_MARGIN:
                fail("There is not enough free disk space to unpack this backup")
            names.append(m.name)
            src = tar.extractfile(m)
            fd = os.open(os.path.join(work, m.name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as dst:
                left = m.size
                while left > 0:
                    chunk = src.read(min(left, 1024 * 1024))
                    if not chunk:
                        break
                    dst.write(chunk)
                    left -= len(chunk)
    except _TooBig:
        fail("This backup is larger than a restore allows")
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        fail(f"This backup cannot be read ({type(exc).__name__}: {exc})")
    if "monitor.db" not in names:
        fail("This file is not a Homelab Monitor backup")
    return names


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(text, width: int = 64) -> str:
    return _CONTROL.sub("", str(text if text is not None else ""))[:width]


def summary(db: str) -> list:
    """What an unproven backup would bring in: its accounts with their roles, and how many stored
    credentials it holds. Names come from the file, so control characters are removed."""
    lines = []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table';")}
            rows = []
            if "accounts" in tables:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(accounts);")}
                rows = conn.execute("SELECT username" + (", role" if "role" in cols else ", NULL") +
                                    " FROM accounts ORDER BY username;").fetchall()
            creds = conn.execute("SELECT COUNT(*) FROM credentials;").fetchone()[0] if "credentials" in tables else 0
        finally:
            conn.close()
    except sqlite3.Error:
        return ["Accounts in it: (could not be read)"]
    lines.append("Accounts in it:")
    for username, role in rows[:50]:
        lines.append(f"  {_clean(username)}  {_clean(role or 'admin', 20)}")
    if len(rows) > 50:
        lines.append(f"  and {len(rows) - 50} more")
    if not rows:
        lines.append("  none")
    lines.append(f"Stored credentials in it: {int(creds)}")
    return lines


def _key_opens(key_file: str, check: str) -> bool:
    """True when this key file opens the vault check value (so the data it protects can be read)."""
    if not key_file or not check or vault.AESGCM is None:
        return False
    try:
        key = base64.b64decode(safefile.read_regular(key_file, 4096).decode("ascii").strip())
        return vault.Vault._open(vault.AESGCM(key), check, "vault:check") == vault.CHECK_PLAINTEXT
    except Exception:
        return False


def _forget(work: str) -> None:
    """Clears every stored secret in the unpacked copy (its key is gone for good) and drops the vault
    check, so the monitor starts on a fresh key; one audit row says what happened."""
    import database
    conn = sqlite3.connect(os.path.join(work, "monitor.db"))
    try:
        cleared = database.forget_secrets(conn)
        try:
            _audit(conn, "system", "Restored a backup without its key: stored secrets were cleared",
                   f"{cleared} secret(s) cleared; they must be entered again")
        except sqlite3.Error:
            pass
        conn.commit()
    finally:
        conn.close()
    meta_path = os.path.join(work, "vault.json")
    meta = {}
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        pass
    meta.pop("check", None)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


NO_KEY_TEXT = ("This backup does not carry the key that opens its stored passwords and this box does not have it "
               "either. Stored passwords, SSH keys, tokens and 2FA secrets will be cleared and must be entered again.")
UNVERIFIED_TEXT = ("This backup cannot be proven unchanged. It may be an older backup, it may have been made without a "
                   "passphrase or it may have been changed after it was made.")


def _assess(archive: str, work: str, args, run_checks: bool = True) -> dict:
    """Unpacks a backup into work and decides whether it may be restored. Fails (nothing touched) with
    4 when a passphrase is needed, 7 when it cannot be proven unchanged (without --accept-unverified),
    8 when no usable key exists (without --forget-secrets), and the compat codes from the checks.
    A sealed key is opened with the passphrase into work/vault.key."""
    passphrase = _passphrase(args)
    expect = (getattr(args, "expect_sha256", None) or "").strip().lower()
    if expect and not os.path.exists(archive):
        fail(f"No such backup: {archive}")
    if expect and not hmac.compare_digest(_sha256_file(archive), expect):
        fail("This backup is not the copy root recorded when it was made, so it was not used. Nothing was changed.",
             EXIT_UNVERIFIED)
    _unpack(archive, work)
    try:
        with open(os.path.join(work, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict):
            manifest = {}
    except (OSError, ValueError):
        manifest = {}
    tagged = isinstance(manifest.get("auth"), dict)
    if expect:
        outcome = "root-record"
    elif tagged and not passphrase:
        fail("This backup carries a tag made with a backup passphrase. Give the passphrase (it is kept in "
             "/etc/homelab-monitor-install/backup-passphrase, or type it when asked)", EXIT_PASSPHRASE)
    elif tagged and check_tag(work, manifest, passphrase):
        outcome = "verified"
    else:
        outcome = "unverified"
    out = {"outcome": outcome, "tagged": tagged, "manifest": manifest, "keep_live_key": False, "forgotten": False}
    if outcome == "unverified":
        print(UNVERIFIED_TEXT)
        print("")
        for line in summary(os.path.join(work, "monitor.db")):
            print(line)
        if not getattr(args, "accept_unverified", False):
            fail("Not restored: this backup cannot be proven unchanged. Confirm it on purpose to restore it anyway",
                 EXIT_UNVERIFIED)
    else:
        print("Backup check: " + ("the copy root recorded when it was made" if outcome == "root-record"
                                  else "proven unchanged with the backup passphrase"))
    sealed = os.path.join(work, "vault.key.sealed")
    if os.path.exists(sealed):
        if vault.AESGCM is None:
            fail("Opening a sealed key needs the cryptography package")
        with open(sealed, "rb") as f:
            key = unseal_key(f.read(), passphrase)
        fd = os.open(os.path.join(work, "vault.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        os.remove(sealed)
    live_key = getattr(args, "key", None) or ""
    if not os.path.exists(os.path.join(work, "vault.key")) and manifest.get("key_withheld"):
        try:
            with open(os.path.join(work, "vault.json"), encoding="utf-8") as f:
                check = (json.load(f) or {}).get("check") or ""
        except (OSError, ValueError, AttributeError):
            check = ""
        if _key_opens(live_key, check):
            out["keep_live_key"] = True
            print("The backup carries no key; the key on this box opens it, so it stays.")
        elif getattr(args, "forget_secrets", False):
            out["forgotten"] = True
        else:
            print(NO_KEY_TEXT)
            fail("Not restored: no usable key for this backup's stored secrets", EXIT_NO_KEY)
    if not run_checks:
        return out
    if out["forgotten"]:
        _forget(work)
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
        key = key if os.path.exists(key) else (live_key if out["keep_live_key"] else None)
        report = compat.check(os.path.join(work, "monitor.db"), key, run_trial=bool(key) or out["forgotten"])
        print(f"Backup check: {report['message']}")
        if report.get("trial"):
            print(f"Backup check: {report['trial']['message']}")
        for note in report["notes"]:
            print(f"Note: {note}")
        if report["exit"] != 0:
            fail("This backup cannot be restored by this build; the current data was not touched", report["exit"])
    return out


def verify(args) -> None:
    """Only the checks a restore makes first: can this build restore the backup? Changes nothing."""
    work = tempfile.mkdtemp(prefix="hm-verify-")
    try:
        _assess(args.archive, work, args)
        print(f"Backup can be restored: {os.path.basename(args.archive)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check_auth(args) -> None:
    """Before any question is asked: can this backup be proven unchanged, and is there a key for it?
    Prints the outcome (HM_AUTH=...) and exits 0, 4, 7 or 8. No trial is run."""
    work = tempfile.mkdtemp(prefix="hm-auth-")
    try:
        try:
            out = _assess(args.archive, work, args, run_checks=False)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            try:
                with open(os.path.join(work, "manifest.json"), encoding="utf-8") as f:
                    tagged = isinstance((json.load(f) or {}).get("auth"), dict)
            except (OSError, ValueError, AttributeError):
                tagged = False
            label = {EXIT_PASSPHRASE: "needs-passphrase", EXIT_UNVERIFIED: "unverified-tagged" if tagged else "unverified",
                     EXIT_NO_KEY: "no-key"}.get(code, "refused")
            print(f"HM_AUTH={label}")
            raise
        print(f"HM_AUTH={out['outcome']}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def take(args) -> None:
    """A private copy of a backup (regular files only, never through a link, capped), so the file
    cannot change between the checks and the restore."""
    try:
        fd = os.open(args.archive, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        fail(f"This backup cannot be opened ({type(exc).__name__}): a plain file is needed, not a link")
    try:
        import stat as _stat
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            fail("This backup is not a plain file")
        if st.st_size > MAX_TOTAL:
            fail("This backup is larger than a restore allows")
        folder = os.path.dirname(os.path.abspath(args.to))
        if st.st_size > shutil.disk_usage(folder).free - FREE_MARGIN:
            fail("There is not enough free disk space for a copy of this backup")
        if os.path.lexists(args.to):
            os.remove(args.to)
        out = os.open(args.to, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                      | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(out, "wb") as dst:
            copied = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_TOTAL:
                    fail("This backup is larger than a restore allows")
                dst.write(chunk)
    finally:
        os.close(fd)
    print(args.to)


def set_passphrase(args) -> None:
    """The backup passphrase (stdin) into root's file through a new file and a rename; one audit row,
    written as the monitor's own account."""
    passphrase = sys.stdin.readline().rstrip("\n")
    if len(passphrase) < 12:
        fail("The backup passphrase must be at least 12 characters")
    path = getattr(args, "file", None) or PASSPHRASE_FILE
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    safefile.atomic_write(folder, os.path.basename(path), (passphrase + "\n").encode("utf-8"), 0o600,
                          (0, 0) if safefile.is_root() else None)
    db = os.path.join(args.data, "monitor.db")
    if os.path.exists(db):
        try:
            ids = safefile.service_ids()
        except KeyError:
            ids = None
        kw = {"user": ids[0], "group": ids[1], "extra_groups": []} if ids else {}
        subprocess.run([sys.executable, "-I", "-c", _AUDIT_PROGRAM, db, "system", "Backup passphrase set from the container shell",
                        "", *ROOT_ACTOR], capture_output=True, **kw)
    print(f"Backup passphrase saved in {path}")


def prune_pre_restore(folders: list, now: float = None) -> list:
    """pre-restore-* copies: the newest 3 are kept, others older than 30 days go; the newest one always stays."""
    now = time.time() if now is None else now
    found = []
    for folder in folders:
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for n in names:
            path = os.path.join(folder, n)
            if n.startswith("pre-restore-") and os.path.isdir(path) and not os.path.islink(path):
                found.append((os.path.getmtime(path), n, path))
    found.sort(reverse=True)
    gone = []
    for i, (mtime, _, path) in enumerate(found):
        if i == 0:
            continue
        if i >= PRE_RESTORE_KEEP or now - mtime > PRE_RESTORE_DAYS * 86400:
            shutil.rmtree(path, ignore_errors=True)
            gone.append(path)
    return gone


SHARE_TYPES = ("nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "virtiofs")


def _backup_folders(data: str, mounts_file: str, safe: str = "") -> list:
    """(folder, where, depth) to search: the container's own folder, root's safety folder, the Syncthing
    folder, its NFS mounts, any other share."""
    found = [(os.path.join(data, "backups"), "this container", 2)]
    if safe:
        found.append((safe, "kept by root", 2))
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
    """One line per backup, newest first: path|unix time|bytes|app version|key|where it was found|tag or none.
    key is one of: key, sealed key, withheld, no key."""
    seen, rows = set(), []
    folders = _backup_folders(args.data, args.mounts, _safe_dir(args)) + [(d, "folder " + d, 3) for d in args.also or []]
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
                version, has_key, tag = "", "", "none"
                try:
                    raw = small_member(path, "manifest.json")
                    manifest = json.loads(raw) if raw else {}
                    if not isinstance(manifest, dict):
                        manifest = {}
                    version = str(manifest.get("app_version") or "")
                    has_key = ("sealed key" if manifest.get("key_sealed") else "key" if manifest.get("includes_key")
                               else "withheld" if manifest.get("key_withheld") else "no key")
                    tag = "tag" if isinstance(manifest.get("auth"), dict) else "none"
                except (tarfile.TarError, OSError, EOFError, KeyError, ValueError, _TooBig):
                    version = "unreadable"
                rows.append((st.st_mtime, f"{path}|{int(st.st_mtime)}|{st.st_size}|{version}|{has_key}|{where}|{tag}"))
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
        raw = small_member(args.archive, "site.json")
        site = json.loads(raw) if raw else {}
    except (tarfile.TarError, OSError, EOFError, ValueError, _TooBig) as exc:
        fail(f"This backup cannot be read ({type(exc).__name__})")
    for line in site_lines(site if isinstance(site, dict) else {}):
        print(line)


def restore(args) -> None:
    work = tempfile.mkdtemp(prefix="hm-restore-")
    record = getattr(args, "record_name", None)
    if record and not RECORD_NAME.fullmatch(record):
        fail("--record-name: a plain file name is expected")
    try:
        out = _assess(args.archive, work, args)
        os.makedirs(args.data, exist_ok=True)
        # What is there now is kept in root's own folder (beside the data when there is none).
        keep_in = _safe_dir(args) or args.data
        if keep_in != args.data:
            os.makedirs(keep_in, mode=0o700, exist_ok=True)
        keep = os.path.join(keep_in, f"pre-restore-{time.strftime('%Y%m%d-%H%M%S')}")
        moved = [f for f in os.listdir(args.data) if f.startswith(("monitor.db", "vault.json"))]
        if moved:
            os.makedirs(keep, mode=0o700)
            for f in moved:
                shutil.move(os.path.join(args.data, f), os.path.join(keep, f))
        # Into the data folder (the app's account can change it): new files made without following a
        # link, owned by that account, renamed into place. Read from root's private copy.
        owner = _service_or_owner(args.data)
        for member, target in (("monitor.db", "monitor.db"), ("vault.json", "vault.json"), ("site.json", "site-restored.json")):
            if os.path.exists(os.path.join(work, member)):
                safefile.atomic_copy(args.data, target, os.path.join(work, member), 0o600, owner)
        # A backup without its key keeps the key on this box when it opens the data (or the secrets
        # were cleared); an older backup without a key (format 1) moves it away as before.
        keep_key = out["keep_live_key"] or out["forgotten"]
        if args.key and not keep_key:
            if os.path.exists(args.key):
                os.makedirs(keep, mode=0o700, exist_ok=True)
                shutil.move(args.key, os.path.join(keep, "vault.key"))
                moved.append("vault.key")
            if os.path.exists(os.path.join(work, "vault.key")):
                folder = os.path.dirname(os.path.abspath(args.key))
                os.makedirs(folder, mode=0o700, exist_ok=True)
                safefile.atomic_copy(folder, os.path.basename(args.key), os.path.join(work, "vault.key"), 0o600,
                                     _service_or_owner(folder))
        if record:
            safefile.atomic_write(args.data, "restored-from", (record + "\n").encode("utf-8"), 0o600, owner)
        # The monitor reads this when it starts again: one audit row and one alert (watch_root_results).
        write_result(args.data, "restore", True, "Restored", file=os.path.basename(args.archive))
        print(f"Restored into {args.data}" + (f"; previous files kept in {keep}" if moved else ""))
        if out["forgotten"]:
            print("Stored passwords, SSH keys, tokens and 2FA secrets were cleared: enter them again in the app.")
        for gone in prune_pre_restore([p for p in {keep_in, args.data}]):
            print(f"Removed an older copy: {gone}")
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
             "home_monitor.sh and run bash home_monitor.sh --upgrade on the Proxmox host: it copies the Syncthing identity in")
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
        # The folder is below /mnt or /srv with no links (checked above); chown -hR never follows a link inside it.
        run(["chown", "-hR", "syncthing:syncthing", SYNCTHING_HOME, st["data_folder"]], dry)
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
    body = json.dumps(dict({"time": int(time.time()), "ok": ok, "output": output[-4000:]}, **extra)).encode("utf-8")
    safefile.atomic_write(data, f"{kind}.result.json", body, 0o600, _owner_of(data))


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
    if not os.path.exists(db) or os.path.islink(db):
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


def _drop_to_service() -> None:
    """Root changes the database only as the monitor's own account, so every file SQLite makes
    (the journal, the WAL) belongs to it and no root-owned file is left in the data folder."""
    if not safefile.is_root():
        return
    try:
        uid, gid = safefile.service_ids()
    except (KeyError, TypeError):
        fail("The monitor's own account is missing, so nothing was changed")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def reset_password(args) -> None:
    """New password (stdin) for one account; optionally turns its 2FA off. The service is restarted
    by the calling script, which ends every session (they live in memory)."""
    _drop_to_service()
    import auth
    password = sys.stdin.readline().rstrip("\n")
    problem = auth.password_problem(password)
    if problem:
        fail(problem)
    if args.user not in {a["username"] for a in _accounts(args.data)}:
        fail(f"No account named {args.user}")
    conn = sqlite3.connect(_no_link(os.path.join(args.data, "monitor.db")))
    try:
        now = int(time.time())
        conn.execute("UPDATE accounts SET password_hash = ?, disabled = 0, updated_at = ? WHERE username = ?;",
                     (auth.hash_password(password), now, args.user))
        if args.reset_2fa:
            conn.execute("UPDATE accounts SET totp_secret = NULL, totp_enabled = 0, totp_recovery = '[]', "
                         "totp_last_step = NULL WHERE username = ?;", (args.user,))
        if getattr(args, "no_2fa_rule", False):
            # Break-glass for someone with no phone to set 2FA up with.
            conn.execute("UPDATE settings SET value = 'off', updated_at = ? WHERE key = 'require_2fa';", (now,))
            _audit(conn, "auth", "2FA requirement turned off from the container shell")
        _audit(conn, "auth", f"Password reset from the container shell for {args.user}",
               "2FA turned off too" if args.reset_2fa else "2FA unchanged")
        conn.commit()
    finally:
        conn.close()
    print(f"Password reset for {args.user}")


def require_2fa(args) -> None:
    """Prints the 2FA rule (off, admins or all), for reset-admin.sh."""
    try:
        conn = sqlite3.connect(f"file:{_no_link(os.path.join(args.data, 'monitor.db'))}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT value FROM settings WHERE key = 'require_2fa';").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        row = None
    print(row[0] if row and row[0] in ("off", "admins", "all") else "off")


def tls_off(args) -> None:
    """Plain HTTP again (a certificate that locks everyone out); the stored certificate is kept."""
    _drop_to_service()
    conn = sqlite3.connect(_no_link(os.path.join(args.data, "monitor.db")))
    try:
        now = int(time.time())
        conn.execute("INSERT INTO settings (key, value, description, updated_at) VALUES ('tls_mode', 'off', '', ?) "
                     "ON CONFLICT (key) DO UPDATE SET value = 'off', updated_at = excluded.updated_at;", (now,))
        _audit(conn, "system", "HTTPS switched off from the container shell")
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
    # Into the key folder (the app's account can change it): a new file, private, owned by the monitor's
    # account, set on the open file and renamed into place, never through a link.
    folder = os.path.dirname(os.path.abspath(args.env))
    safefile.atomic_write(folder, os.path.basename(args.env), f"MONITOR_SETUP_TOKEN={code}\n".encode("ascii"), 0o600,
                          _service_or_owner(folder))
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
    p.add_argument("--safety", action="store_true", help="a root safety copy: the destination must be in root's own folder")
    p.add_argument("--safe-dir", help=f"root's own folder for safety copies (default {SAFE_DIR} when root)")
    p.set_defaults(fn=backup)
    for name, fn in (("restore", restore), ("verify", verify), ("check-auth", check_auth)):
        p = sub.add_parser(name)
        p.add_argument("archive")
        if name == "restore":
            p.add_argument("--data", required=True)
            p.add_argument("--record-name", help="written to DATA/restored-from once restored")
        p.add_argument("--key", help="the vault key file on this box (where a restored key goes)")
        p.add_argument("--passphrase-file", help=f"for a tag or a sealed key (default {PASSPHRASE_FILE})")
        p.add_argument("--passphrase-stdin", action="store_true", help="read the passphrase from stdin")
        p.add_argument("--accept-unverified", action="store_true", help="restore a backup that cannot be proven unchanged")
        p.add_argument("--forget-secrets", action="store_true", help="no usable key: clear the stored secrets")
        p.add_argument("--expect-sha256", help="the checksum root recorded for this file (a safety copy)")
        p.add_argument("--safe-dir", help=f"root's own folder (default {SAFE_DIR} when root)")
        p.set_defaults(fn=fn)
    p = sub.add_parser("take")
    p.add_argument("archive")
    p.add_argument("--to", required=True)
    p.set_defaults(fn=take)
    p = sub.add_parser("set-passphrase")
    p.add_argument("--data", required=True)
    p.add_argument("--file", help=f"where the passphrase is kept (default {PASSPHRASE_FILE})")
    p.set_defaults(fn=set_passphrase)
    p = sub.add_parser("site-of")
    p.add_argument("archive")
    p.set_defaults(fn=site_of)
    p = sub.add_parser("find-backups")
    p.add_argument("--data", required=True)
    p.add_argument("--also", action="append", help="another folder to search")
    p.add_argument("--mounts", default="/proc/mounts")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--safe-dir", help=f"root's own folder (default {SAFE_DIR} when root)")
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
    p.add_argument("--no-2fa-rule", action="store_true", help="also stop requiring 2FA for everyone")
    p.set_defaults(fn=reset_password)
    p = sub.add_parser("require-2fa")
    p.add_argument("--data", required=True)
    p.set_defaults(fn=require_2fa)
    p = sub.add_parser("tls-off")
    p.add_argument("--data", required=True)
    p.set_defaults(fn=tls_off)
    p = sub.add_parser("new-setup-code")
    p.add_argument("--data", required=True)
    p.add_argument("--env", required=True)
    p.set_defaults(fn=new_setup_code)
    p = sub.add_parser("put-key")
    p.add_argument("--key", required=True)
    p.set_defaults(fn=put_key)
    p = sub.add_parser("ask")
    p.add_argument("--kind", choices=("site",), required=True)
    p.add_argument("--data", required=True)
    p.set_defaults(fn=ask)
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
