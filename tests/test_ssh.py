"""SSH runner: what reaches the ssh process, host key pinning and secret handling (subprocess mocked)."""

import os
import subprocess
import unittest
from unittest import mock

from tests import _env  # noqa: F401

import ssh_runner

KEY = [{"key_type": "ssh-ed25519", "key_b64": "AAAAC3NzaC1lZDI1NTE5AAAAIEHQoVXsFD8q3azM1yd040KuislcWUT4Nu8ZVcoWbRVX"}]


class RunnerTests(unittest.TestCase):
    def run_with(self, credential, returncode=0, stdout=b"ok\n"):
        seen = {}

        def fake_run(args, **kw):
            seen["args"] = list(args)
            seen["env"] = kw.get("env", {})
            seen["shell"] = kw.get("shell")
            kh = next(a.split("=", 1)[1] for a in args if a.startswith("UserKnownHostsFile="))
            with open(kh, encoding="utf-8") as f:
                seen["known_hosts"] = f.read()
            if "-i" in args:
                key_path = args[args.index("-i") + 1]
                with open(key_path, encoding="utf-8") as f:
                    seen["key_on_disk"] = f.read()
                seen["key_path"] = key_path
            if "SSH_ASKPASS" in seen["env"]:
                seen["askpass"] = seen["env"]["SSH_ASKPASS"]
                seen["askpass_exists"] = os.path.exists(seen["askpass"])
            seen["work_dir"] = os.path.dirname(kh)
            return subprocess.CompletedProcess(args, returncode, stdout, b"")

        with mock.patch.object(ssh_runner, "ssh_binary", return_value="ssh"), \
                mock.patch.object(ssh_runner.subprocess, "run", side_effect=fake_run):
            result = ssh_runner.run_command("192.0.2.50", 2222, credential, "uptime", KEY, 30)
        return result, seen

    def test_password_never_in_argv_and_pinned(self):
        result, seen = self.run_with({"cred_type": "password", "username": "root", "secret": "Argv-Secret-7e1"})
        self.assertEqual(result["status"], "completed")
        self.assertFalse(seen["shell"])
        self.assertNotIn("Argv-Secret-7e1", " ".join(seen["args"]))
        self.assertIn("StrictHostKeyChecking=yes", seen["args"])
        self.assertIn("IdentityAgent=none", seen["args"])
        self.assertEqual(seen["env"]["HM_SSH_PASSWORD"], "Argv-Secret-7e1")
        self.assertEqual(seen["env"]["SSH_ASKPASS_REQUIRE"], "force")
        self.assertTrue(seen["askpass_exists"])
        self.assertIn("[192.0.2.50]:2222 ssh-ed25519 " + KEY[0]["key_b64"], seen["known_hosts"])
        self.assertEqual(seen["args"][-3:], ["--", "192.0.2.50", "uptime"])
        self.assertFalse(os.path.exists(seen["work_dir"]))   # temp dir with helper removed

    def test_key_file_written_then_deleted(self):
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        result, seen = self.run_with({"cred_type": "ssh_key", "username": "root", "secret": key})
        self.assertEqual(seen["key_on_disk"].strip(), key)
        self.assertIn("IdentitiesOnly=yes", seen["args"])
        self.assertIn("BatchMode=yes", seen["args"])
        self.assertNotIn("HM_SSH_PASSWORD", seen["env"])
        self.assertFalse(os.path.exists(seen["key_path"]))
        self.assertFalse(os.path.exists(seen["work_dir"]))

    def test_key_passphrase_goes_to_askpass_not_argv(self):
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        result, seen = self.run_with({"cred_type": "ssh_key", "username": "root", "secret": key, "passphrase": "Pass-Phrase-9q"})
        self.assertNotIn("Pass-Phrase-9q", " ".join(seen["args"]))
        self.assertEqual(seen["env"]["HM_SSH_PASSWORD"], "Pass-Phrase-9q")
        self.assertTrue(seen["askpass_exists"])
        self.assertNotIn("BatchMode=yes", seen["args"])        # BatchMode would stop the passphrase prompt
        self.assertIn("PasswordAuthentication=no", seen["args"])
        self.assertFalse(os.path.exists(seen["work_dir"]))

    def test_ssh_failure_and_exit_codes(self):
        self.assertEqual(self.run_with({"cred_type": "password", "username": "u", "secret": "s"}, 255, b"")[0]["status"], "error")
        r, _ = self.run_with({"cred_type": "password", "username": "u", "secret": "s"}, 3)
        self.assertEqual((r["status"], r["exit_code"]), ("completed", 3))

    def test_output_capped(self):
        r, _ = self.run_with({"cred_type": "password", "username": "u", "secret": "s"}, 0, b"x" * 200000)
        self.assertEqual(len(r["stdout"]), ssh_runner.MAX_OUTPUT)

    def test_timeout(self):
        def slow(args, **kw):
            raise subprocess.TimeoutExpired(args, 1, output=b"partial")
        with mock.patch.object(ssh_runner, "ssh_binary", return_value="ssh"), \
                mock.patch.object(ssh_runner.subprocess, "run", side_effect=slow):
            r = ssh_runner.run_command("192.0.2.50", 22, {"cred_type": "password", "username": "u", "secret": "s"}, "sleep 9", KEY, 1)
        self.assertEqual((r["status"], r["stdout"]), ("timeout", "partial"))


@unittest.skipUnless(ssh_runner.keygen_available(), "ssh-keygen not installed")
class KeyPairTests(unittest.TestCase):
    def test_generate_and_read_back_public_key(self):
        private, public = ssh_runner.generate_keypair("homelab-monitor test")
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", private)
        self.assertTrue(public.startswith("ssh-ed25519 "))
        self.assertTrue(ssh_runner.valid_public_key(public))
        # The public half is read from the private key file itself, no ssh-keygen call needed.
        with mock.patch.object(ssh_runner.shutil, "which", return_value=None):
            self.assertEqual(ssh_runner.public_key_of(private), " ".join(public.split()[:2]))
        self.assertTrue(ssh_runner.public_fingerprint(public).startswith("SHA256:"))

    def test_generate_cleans_up_and_uses_argv_list(self):
        seen = {}
        real = subprocess.run

        def spy(args, **kw):
            seen["args"], seen["shell"] = list(args), kw.get("shell")
            seen["dir"] = os.path.dirname(args[args.index("-f") + 1])
            return real(args, **kw)

        with mock.patch.object(ssh_runner.subprocess, "run", side_effect=spy):
            ssh_runner.generate_keypair("x")
        self.assertFalse(seen["shell"])
        self.assertFalse(os.path.exists(seen["dir"]))


class PublicKeyParsingTests(unittest.TestCase):
    def test_validation(self):
        self.assertTrue(ssh_runner.valid_public_key("ssh-ed25519 " + KEY[0]["key_b64"] + " me@host"))
        self.assertFalse(ssh_runner.valid_public_key("ssh-rsa " + KEY[0]["key_b64"]))     # blob says ed25519
        self.assertFalse(ssh_runner.valid_public_key("ssh-ed25519 not*base64"))
        self.assertFalse(ssh_runner.valid_public_key("ssh-ed25519 " + KEY[0]["key_b64"] + "\nrm -rf /"))

    def test_unreadable_key_gives_none(self):
        with mock.patch.object(ssh_runner.shutil, "which", return_value=None):
            self.assertIsNone(ssh_runner.public_key_of("-----BEGIN RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY-----"))
            self.assertIsNone(ssh_runner.public_key_of("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"))


if __name__ == "__main__":
    unittest.main()
