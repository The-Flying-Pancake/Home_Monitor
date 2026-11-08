"""Encryption at rest: the vault itself, what lands in the database file, and what the API exposes."""

import base64
import logging
import os
import tempfile
import unittest

from tests import _env  # noqa: F401
from tests.helpers import add_device, raw_bytes, request, start_api_server

import database
import vault
from vault import VAULT, Vault, VaultError

SECRET_COMMUNITY = "Zebra-Community-7f3a"
SECRET_PASSWORD = "Pa55word-Unique-91c2"
SECRET_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nTESTKEYMATERIAL-4d1e\n-----END OPENSSH PRIVATE KEY-----"


class VaultUnitTests(unittest.TestCase):
    """A standalone Vault in its own folder, independent of the shared test database."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="hm-vault-")
        self.key = os.path.join(self.dir, "k", "vault.key")
        os.environ["MONITOR_KEY_FILE"] = self.key
        self.v = Vault()
        self.v.load(self.dir)

    @staticmethod
    def _read(path):
        with open(path, encoding="ascii") as f:
            return f.read()

    def tearDown(self):
        os.environ["MONITOR_KEY_FILE"] = os.path.join(_env.TMP, "key", "vault.key")
        os.environ.pop("MONITOR_MASTER_KEY", None)

    def test_roundtrip_and_token_format(self):
        token = self.v.encrypt("hello", "ctx:a")
        self.assertTrue(token.startswith("enc1:"))
        self.assertNotIn("hello", token)
        self.assertEqual(self.v.decrypt(token, "ctx:a"), "hello")

    def test_aes_256_gcm_with_fresh_nonce(self):
        raw = base64.b64decode(self.v.encrypt("x", "c")[5:])
        self.assertEqual(len(raw), 12 + 1 + 16)  # 96-bit nonce, 1-byte ciphertext, 128-bit GCM tag
        self.assertEqual(len(base64.b64decode(self._read(self.key).strip())), 32)  # 256-bit key
        self.assertNotEqual(self.v.encrypt("same", "c"), self.v.encrypt("same", "c"))

    def test_context_binding(self):
        token = self.v.encrypt("secret", "device:snmp_community")
        with self.assertRaises(VaultError):
            self.v.decrypt(token, "credential:password")

    def test_tampering_detected(self):
        token = self.v.encrypt("secret", "c")
        raw = bytearray(base64.b64decode(token[5:]))
        raw[14] ^= 0x01
        with self.assertRaises(VaultError):
            self.v.decrypt("enc1:" + base64.b64encode(bytes(raw)).decode(), "c")

    def test_key_file_created_private_and_not_overwritten(self):
        self.assertTrue(os.path.exists(self.key))
        before = self._read(self.key)
        Vault().load(self.dir)
        self.assertEqual(self._read(self.key), before)
        if os.name != "nt":
            self.assertEqual(os.stat(self.key).st_mode & 0o777, 0o600)

    def test_wrong_key_locks_vault(self):
        os.remove(self.key)
        other = Vault()
        other.load(self.dir)  # new key, but vault.json check was sealed with the old one
        self.assertFalse(other.enabled)
        self.assertIn("does not match", other.error)
        with self.assertRaises(VaultError):
            other.encrypt("x", "c")

    def test_passphrase_mode(self):
        d = tempfile.mkdtemp(prefix="hm-pass-")
        os.environ["MONITOR_MASTER_KEY"] = "correct horse battery staple"
        a = Vault(); a.load(d)
        self.assertTrue(a.enabled)
        self.assertIsNone(a.key_path)
        token = a.encrypt("v", "c")
        b = Vault(); b.load(d)
        self.assertEqual(b.decrypt(token, "c"), "v")
        os.environ["MONITOR_MASTER_KEY"] = "wrong"
        c = Vault(); c.load(d)
        self.assertFalse(c.enabled)

    def test_legacy_key_beside_data_is_rotated(self):
        d = tempfile.mkdtemp(prefix="hm-legacy-")
        os.environ["MONITOR_KEY_FILE"] = os.path.join(d, "vault.key")  # old layout: key beside data
        old = Vault(); old.load(d)
        token = old.encrypt("rotate-me", "c")
        os.environ["MONITOR_KEY_FILE"] = os.path.join(d, "elsewhere", "vault.key")
        new = Vault(); new.load(d)
        self.assertTrue(new.rekey_pending)
        rotated = new.reencrypt(token, "c")
        self.assertNotEqual(rotated, token)
        new.finish_rekey()
        self.assertFalse(os.path.exists(os.path.join(d, "vault.key")))
        self.assertEqual(new.decrypt(rotated, "c"), "rotate-me")
        with self.assertRaises(VaultError):
            new.decrypt(token, "c")  # the old token is dead once migration finishes

    def test_no_plaintext_without_the_cryptography_package(self):
        from unittest import mock
        with mock.patch.object(vault, "AESGCM", None), mock.patch.dict(os.environ, {"MONITOR_ALLOW_PLAINTEXT": ""}):
            v = Vault()
            v.load(self.dir)
            self.assertFalse(v.enabled)
            with self.assertRaises(VaultError) as cm:
                v.encrypt("a secret", "device:snmp_community")
            self.assertIn("cryptography package", str(cm.exception))
            self.assertIn("MONITOR_ALLOW_PLAINTEXT=1", str(cm.exception))
            self.assertEqual(v.decrypt("old plaintext", "device:snmp_community"), "old plaintext")   # old values still read
            self.assertEqual(v.encrypt("", "device:snmp_community"), "")
        with mock.patch.object(vault, "AESGCM", None), mock.patch.dict(os.environ, {"MONITOR_ALLOW_PLAINTEXT": "1"}):
            v = Vault()
            v.load(self.dir)
            self.assertEqual(v.encrypt("a secret", "device:snmp_community"), "a secret")       # allowed on purpose only
        # A vault that never loaded refuses too, instead of storing plain text.
        with self.assertRaises(VaultError):
            Vault().encrypt("a secret", "x")

    def test_meta_written_atomically_and_private(self):
        from unittest import mock
        meta = os.path.join(self.dir, "vault.json")
        before = self._read(meta)
        with mock.patch.object(vault.json, "dump", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.v._write_meta({"salt": "x"})
        self.assertEqual(self._read(meta), before)                          # the old file is intact
        self.assertEqual([f for f in os.listdir(self.dir) if f.endswith(".tmp")], [])
        self.v._write_meta(dict(__import__("json").loads(before), note="rewritten"))
        self.assertIn("rewritten", self._read(meta))
        if os.name != "nt":
            self.assertEqual(os.stat(meta).st_mode & 0o777, 0o600)

    def test_default_key_path_outside_data_folder(self):
        path = vault.default_key_path()
        self.assertNotIn(os.path.dirname(os.path.abspath(database.DB_FILE)), path)


class AtRestTests(unittest.TestCase):
    """Secrets in the shared test database, inspected as raw file bytes."""

    @classmethod
    def setUpClass(cls):
        start_api_server()
        cls.device_id = add_device("vault-dev", "192.0.2.10", community=SECRET_COMMUNITY)
        status, body, _ = request("POST", "/api/credentials", {"name": "vault-pw", "cred_type": "password",
                                                              "username": "root", "secret": SECRET_PASSWORD})
        assert status == 201, body
        status, body, _ = request("POST", "/api/credentials", {"name": "vault-key", "cred_type": "ssh_key",
                                                              "username": "root", "secret": SECRET_KEY})
        assert status == 201, body
        request("POST", "/api/settings", {"default_snmp_community": SECRET_COMMUNITY + "-default"})

    def test_vault_enabled(self):
        self.assertTrue(VAULT.enabled, VAULT.error)

    def test_no_plaintext_in_database_files(self):
        data = raw_bytes()
        for secret in (SECRET_COMMUNITY, SECRET_PASSWORD, "TESTKEYMATERIAL-4d1e", SECRET_COMMUNITY + "-default"):
            self.assertNotIn(secret.encode(), data, f"{secret} found in database bytes")

    def test_columns_hold_tokens(self):
        with database.get_connection() as c:
            self.assertTrue(c.execute("SELECT snmp_community FROM devices WHERE id = ?", (self.device_id,)).fetchone()[0].startswith("enc1:"))
            for (v,) in c.execute("SELECT secret_encrypted FROM credentials"):
                self.assertTrue(v.startswith("enc1:"))
            self.assertTrue(c.execute("SELECT value FROM settings WHERE key='default_snmp_community'").fetchone()[0].startswith("enc1:"))

    def test_application_reads_plaintext_in_process(self):
        self.assertEqual(database.get_device(self.device_id)["snmp_community"], SECRET_COMMUNITY)
        creds = {c["name"]: c["id"] for c in database.list_credentials()}
        self.assertEqual(database.get_credential_secret(creds["vault-pw"])["secret"], SECRET_PASSWORD)

    def test_api_never_returns_secrets(self):
        for path in ("/api/devices", f"/api/devices/{self.device_id}", "/api/settings", "/api/credentials",
                     "/api/system", "/api/automation", "/api/workflows", "/api/dashboard", "/api/problems", "/api/events", "/api/audit"):
            status, body, _ = request("GET", path)
            text = str(body)
            for secret in (SECRET_COMMUNITY, SECRET_PASSWORD, "TESTKEYMATERIAL"):
                self.assertNotIn(secret, text, f"{secret} exposed by {path}")
        _, settings, _ = request("GET", "/api/settings")
        self.assertEqual(settings["default_snmp_community"], "")
        self.assertTrue(settings["default_snmp_community__set"])

    def test_edit_with_empty_community_keeps_secret(self):
        status, _, _ = request("PUT", f"/api/devices/{self.device_id}", {"hostname": "vault-dev", "ip_address": "192.0.2.10",
                                                                          "profile_id": "generic_device", "snmp_community": ""})
        self.assertEqual(status, 200)
        self.assertEqual(database.get_device(self.device_id)["snmp_community"], SECRET_COMMUNITY)

    def test_add_with_empty_community_uses_default(self):
        dev = add_device("vault-default", "192.0.2.11")
        self.assertEqual(database.get_device(dev)["snmp_community"], SECRET_COMMUNITY + "-default")

    def test_plaintext_migration_leaves_no_residue(self):
        with database.get_connection() as c:
            c.execute("UPDATE devices SET snmp_community = ? WHERE id = ?", ("Legacy-Plain-55aa", self.device_id))
            c.commit()
        self.assertEqual(database.encrypt_existing_secrets(), 1)
        database.compact_secure()
        self.assertNotIn(b"Legacy-Plain-55aa", raw_bytes())
        self.assertEqual(database.get_device(self.device_id)["snmp_community"], "Legacy-Plain-55aa")
        database.update_device(self.device_id, "vault-dev", "192.0.2.10", "generic_device", SECRET_COMMUNITY, 161)

    def test_secrets_not_logged(self):
        records = []
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r.getMessage())
        logging.getLogger().addHandler(handler)
        try:
            request("POST", "/api/credentials", {"name": "log-check", "cred_type": "password", "username": "u",
                                                 "secret": "Never-Logged-0b7c"})
            request("POST", "/api/credentials", {"name": "", "cred_type": "password", "secret": "Never-Logged-0b7c"})
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertFalse(any("Never-Logged-0b7c" in m for m in records))
        _, audit, _ = request("GET", "/api/audit")
        self.assertNotIn("Never-Logged-0b7c", str(audit))


if __name__ == "__main__":
    unittest.main()
