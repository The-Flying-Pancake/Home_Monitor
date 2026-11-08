"""AES-256-GCM secret storage for credentials and SNMP community strings.

Secrets are stored as tokens of the form "enc1:<base64(nonce || ciphertext)>".
Each token is bound to a context string (for example "device:snmp_community")
through the GCM associated data, so a ciphertext copied into a different
field fails authentication instead of decrypting.

Master key sources, in order:
  1. MONITOR_MASTER_KEY environment variable: a passphrase stretched with
     scrypt using the random salt in vault.json.
  2. A 32-byte random key file: MONITOR_KEY_FILE, or the per-machine default
     from default_key_path(). Created on first start. The default lives
     outside the data folder on purpose: a key stored beside the database it
     protects (or in a cloud-synced folder) gives no protection to a copy.

A key file found beside the database (the original location) is migrated:
a new key is generated at the default path, every secret is re-encrypted
with it (database.rekey_secrets), and the old file is deleted, so copies of
the old key held by a sync client's history no longer decrypt anything.

vault.json holds the salt and an encrypted check value, so a wrong
passphrase is detected at startup instead of producing unreadable data.
Losing the key (or passphrase) makes stored secrets unrecoverable: they must
be entered again.
"""

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any, Dict, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # Debian: apt install python3-cryptography
    AESGCM = None
    InvalidTag = Exception

log = logging.getLogger("vault")

PREFIX = "enc1:"
NONCE_BYTES = 12
CHECK_PLAINTEXT = "homelab-monitor vault check"
# Storing secrets unencrypted (no cryptography package) needs this set to 1, on purpose.
PLAINTEXT_ENV = "MONITOR_ALLOW_PLAINTEXT"
NO_CRYPTO = ("The cryptography package is not installed, so secrets cannot be stored encrypted. Install it "
             "(apt install python3-cryptography, or pip install cryptography) and restart, or set "
             "MONITOR_ALLOW_PLAINTEXT=1 to store secrets unencrypted.")
# Not raised to 2 ** 17: vault.json does not record these, and deploy/sitectl.py derives the same key
# from them, so a change would lock existing passphrase vaults and backups.
SCRYPT_PARAMS = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}


class VaultError(Exception):
    """Raised when a secret cannot be encrypted or decrypted."""


def default_key_path() -> str:
    """Per-machine key location outside the project and data folders."""
    if os.name == "nt":
        base = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "HomelabMonitor")
    elif os.path.isdir("/etc/homelab-monitor") and os.access("/etc/homelab-monitor", os.W_OK):
        base = "/etc/homelab-monitor"
    else:
        base = os.path.join(os.path.expanduser("~"), ".config", "homelab-monitor")
    return os.path.join(base, "vault.key")


def plaintext_allowed() -> bool:
    return os.environ.get(PLAINTEXT_ENV) == "1"


class Vault:
    def __init__(self) -> None:
        self._aead = None
        self._old_aead = None
        self.legacy_key_path: Optional[str] = None
        self.source: Optional[str] = None
        self.key_path: Optional[str] = None
        self.meta_path: Optional[str] = None
        self.error: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return self._aead is not None

    def load(self, base_dir: str) -> None:
        """Loads or creates the master key. On failure the vault stays locked and error is set."""
        self.meta_path = os.path.join(base_dir, "vault.json")
        if AESGCM is None:
            self.error = NO_CRYPTO if not plaintext_allowed() else \
                "The cryptography package is not installed; secrets are stored unencrypted (MONITOR_ALLOW_PLAINTEXT=1)."
            log.warning(self.error)
            return
        meta = self._read_meta()
        try:
            passphrase = os.environ.get("MONITOR_MASTER_KEY")
            if passphrase:
                salt = base64.b64decode(meta["salt"]) if meta.get("salt") else secrets.token_bytes(16)
                key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, **SCRYPT_PARAMS)
                meta["salt"] = base64.b64encode(salt).decode()
                self.source = "MONITOR_MASTER_KEY environment variable"
            else:
                self.key_path = os.environ.get("MONITOR_KEY_FILE") or default_key_path()
                legacy = os.path.join(base_dir, "vault.key")
                if os.path.exists(legacy) and os.path.abspath(legacy) != os.path.abspath(self.key_path):
                    self.legacy_key_path = legacy
                    self._old_aead = AESGCM(self._load_or_create_key_file(legacy))
                key = self._load_or_create_key_file(self.key_path)
                self.source = "key file"
        except (OSError, ValueError, KeyError) as exc:
            self.error = f"Could not load the master key: {exc}"
            log.error(self.error)
            return

        aead = AESGCM(key)
        if meta.get("check"):
            if not self._check(aead, meta["check"]):
                # Mid-migration: the check is still sealed with the legacy key.
                if not (self._old_aead and self._check(self._old_aead, meta["check"])):
                    self._old_aead = None
                    self.error = ("The master key does not match the one used to encrypt existing secrets. "
                                  "The vault is locked; restore the original key or passphrase.")
                    log.error(self.error)
                    return
            elif self._old_aead and not self._check(self._old_aead, meta["check"]):
                # Migration already completed except for deleting the legacy file.
                self._old_aead = None
        else:
            meta["check"] = self._seal(aead, CHECK_PLAINTEXT, "vault:check")
            meta["created"] = meta.get("created") or time.time()
        meta["version"] = 1
        self._write_meta(meta)
        self._aead = aead
        self.error = None

    @property
    def rekey_pending(self) -> bool:
        return self._old_aead is not None

    def _check(self, aead, token: str) -> bool:
        try:
            return self._open(aead, token, "vault:check") == CHECK_PLAINTEXT
        except (InvalidTag, ValueError):
            return False

    def reencrypt(self, token: Optional[str], context: str) -> Optional[str]:
        """Re-seals a token under the current key. Tokens already under it are returned unchanged."""
        if not self.is_token(token):
            return token
        try:
            self._open(self._aead, token, context)
            return token
        except (InvalidTag, ValueError):
            pass
        if self._old_aead is None:
            raise VaultError(f"Cannot decrypt secret for {context}")
        return self._seal(self._aead, self._open(self._old_aead, token, context), context)

    def finish_rekey(self) -> None:
        """Seals the check value with the new key and deletes the legacy key file."""
        meta = self._read_meta()
        meta["check"] = self._seal(self._aead, CHECK_PLAINTEXT, "vault:check")
        meta["rekeyed"] = time.time()
        self._write_meta(meta)
        self._old_aead = None
        if self.legacy_key_path and os.path.exists(self.legacy_key_path):
            os.remove(self.legacy_key_path)
            log.info("Deleted legacy key file %s", self.legacy_key_path)
        self.legacy_key_path = None

    def _read_meta(self) -> Dict[str, Any]:
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _write_meta(self, meta: Dict[str, Any]) -> None:
        """Atomic: a temporary file in the same folder (mode 0600) replaces vault.json, so a crash
        or full disk never leaves a half-written salt or check value."""
        tmp = f"{self.meta_path}.{secrets.token_hex(6)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.meta_path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _load_or_create_key_file(path: str) -> bytes:
        if os.path.exists(path):
            with open(path, "r", encoding="ascii") as f:
                key = base64.b64decode(f.read().strip())
            if len(key) != 32:
                raise ValueError(f"{path} does not hold a 32-byte key")
            return key
        key = secrets.token_bytes(32)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        # O_EXCL: never overwrite a key that appeared in the meantime. Mode 0600 on POSIX.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(base64.b64encode(key).decode() + "\n")
        log.info("Created new vault key file %s", path)
        return key

    @staticmethod
    def _seal(aead, plaintext: str, context: str) -> str:
        nonce = secrets.token_bytes(NONCE_BYTES)
        ct = aead.encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return PREFIX + base64.b64encode(nonce + ct).decode()

    @staticmethod
    def _open(aead, token: str, context: str) -> str:
        raw = base64.b64decode(token[len(PREFIX):])
        return aead.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], context.encode("utf-8")).decode("utf-8")

    @staticmethod
    def is_token(value: Any) -> bool:
        return isinstance(value, str) and value.startswith(PREFIX)

    def encrypt(self, plaintext: str, context: str) -> str:
        """Returns a token. Without the cryptography package a secret is refused (VaultError), unless
        MONITOR_ALLOW_PLAINTEXT=1 allows storing it unencrypted; a locked vault always refuses."""
        if plaintext is None or plaintext == "" or self.is_token(plaintext):
            return plaintext
        if not self.enabled:
            if AESGCM is None and plaintext_allowed():
                return plaintext
            raise VaultError(self.error or (NO_CRYPTO if AESGCM is None else "Vault is locked"))
        return self._seal(self._aead, plaintext, context)

    def decrypt(self, value: Optional[str], context: str) -> Optional[str]:
        """Returns the plaintext of a token. Non-token values (legacy plaintext) pass through."""
        if not self.is_token(value):
            return value
        if not self.enabled:
            raise VaultError(self.error or "Vault is locked")
        try:
            return self._open(self._aead, value, context)
        except (InvalidTag, ValueError) as exc:
            # During a key migration some tokens are still under the legacy key.
            if self._old_aead is not None:
                try:
                    return self._open(self._old_aead, value, context)
                except (InvalidTag, ValueError):
                    pass
            raise VaultError(f"Cannot decrypt secret for {context}") from exc

    def status(self) -> Dict[str, Any]:
        same_dir_as_db = bool(self.key_path and self.meta_path and
                              os.path.dirname(os.path.abspath(self.key_path)) == os.path.dirname(os.path.abspath(self.meta_path)))
        return {"enabled": self.enabled, "source": self.source, "key_path": self.key_path,
                "key_beside_database": same_dir_as_db, "error": self.error}


VAULT = Vault()
