"""SSH command execution (workflow steps, Fix SNMP) through the system OpenSSH client.

Uses the platform ssh binary (Windows OpenSSH, Debian openssh-client) with
explicit argument lists and shell=False, so no third-party SSH library is
needed. Every connection is pinned to host keys the administrator approved:

  * fetch_host_key() connects with StrictHostKeyChecking=accept-new into a
    throwaway known_hosts file and the "none" auth method, so the server's
    key is recorded without sending any credential.
  * run_command() writes only the approved keys into a per-run known_hosts
    file and connects with StrictHostKeyChecking=yes.

Credentials never touch the command line:
  * ssh_key: the decrypted key is written to a per-run file in a private
    temporary directory (readable by its owner only) and deleted after the run.
    A key passphrase is answered by the askpass helper below, like a password.
  * password: delivered by an SSH_ASKPASS helper (SSH_ASKPASS_REQUIRE=force)
    that reads it from an environment variable set only for that ssh child.

The user's own ~/.ssh/config, agent and default identities are ignored
(-F <empty per-run file>, IdentityAgent=none, IdentitiesOnly=yes). An empty
file is used rather than the null device: Windows OpenSSH rejects "nul" as a
config path in some code paths.
"""

import base64
import hashlib
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

MAX_OUTPUT = 64 * 1024
CONNECT_TIMEOUT = 10


def ssh_binary() -> Optional[str]:
    return shutil.which("ssh")


def fingerprint(key_b64: str) -> str:
    """OpenSSH-style SHA256 fingerprint of a base64 public key blob."""
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _known_hosts_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _base_args(port: int, work: str, known_hosts: str, strict: str) -> List[str]:
    empty = os.path.join(work, "empty")
    if not os.path.exists(empty):
        open(empty, "w").close()
    return [
        ssh_binary(), "-F", empty,
        "-o", f"StrictHostKeyChecking={strict}",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"GlobalKnownHostsFile={empty}",
        "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2",
        "-o", "IdentityAgent=none",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
    ]


def _private_dir() -> str:
    path = tempfile.mkdtemp(prefix="hm-ssh-")
    os.chmod(path, stat.S_IRWXU)
    return path


def _write_private(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text if text.endswith("\n") else text + "\n")


def fetch_host_key(host: str, port: int = 22, timeout: float = 15.0) -> Dict[str, Any]:
    """Returns the host key the server presents, without authenticating."""
    if not ssh_binary():
        return {"error": "OpenSSH client (ssh) not found on this machine"}
    work = _private_dir()
    try:
        kh = os.path.join(work, "known_hosts")
        args = _base_args(port, work, kh, "accept-new") + [
            "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
            "-l", "hm-hostkey-scan", "--", host, "exit",
        ]
        try:
            proc = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=timeout, shell=False)
        except subprocess.TimeoutExpired:
            return {"error": f"Timed out connecting to {host}:{port}"}
        try:
            with open(kh, "r", encoding="utf-8") as f:
                lines = [ln.split() for ln in f if ln.strip()]
        except FileNotFoundError:
            lines = []
        if not lines:
            return {"error": (proc.stderr or "No host key received").strip()[:300]}
        _, key_type, key_b64 = lines[0][:3]
        return {"key_type": key_type, "key_b64": key_b64, "fingerprint": fingerprint(key_b64)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _askpass_helper(work: str) -> str:
    """Writes a helper that prints HM_SSH_PASSWORD, for SSH_ASKPASS."""
    script = os.path.join(work, "askpass.py")
    with open(script, "w", encoding="utf-8") as f:
        f.write("import os, sys\nsys.stdout.write(os.environ.get('HM_SSH_PASSWORD', '') + '\\n')\n")
    if os.name == "nt":
        helper = os.path.join(work, "askpass.cmd")
        with open(helper, "w", encoding="utf-8") as f:
            f.write(f'@"{sys.executable}" "{script}"\r\n')
    else:
        helper = os.path.join(work, "askpass.sh")
        with open(helper, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n')
        os.chmod(helper, stat.S_IRWXU)
    return helper


def _read_capped(pipe, keep: List[bytes]) -> None:
    """Reads a pipe to its end, keeping only the first MAX_OUTPUT bytes. The rest is read and dropped,
    so the child never blocks on a full pipe and its real exit code is kept."""
    kept = 0
    try:
        while True:
            chunk = pipe.read1(65536)
            if not chunk:
                break
            if kept < MAX_OUTPUT:
                part = chunk[:MAX_OUTPUT - kept]
                keep.append(part)
                kept += len(part)
    except (OSError, ValueError):
        pass


def _feed(pipe, data: bytes) -> None:
    try:
        pipe.write(data)
    except (OSError, ValueError):
        pass
    finally:
        try:
            pipe.close()
        except OSError:
            pass


def _capture(args: List[str], env: Dict[str, str], timeout: float,
             input_data: Optional[bytes] = None) -> "tuple[Optional[int], bytes, bytes, bool]":
    """Runs a child with its output read while it streams, each pipe capped at MAX_OUTPUT.

    Returns (returncode, stdout, stderr, timed_out). On a timeout the child is killed and the output
    read so far is returned. One reader thread per pipe: selectors do not work on Windows pipes.
    """
    proc = subprocess.Popen(args, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, shell=False)
    out: List[bytes] = []
    err: List[bytes] = []
    threads = [threading.Thread(target=_read_capped, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=_read_capped, args=(proc.stderr, err), daemon=True)]
    if input_data is not None:
        threads.append(threading.Thread(target=_feed, args=(proc.stdin, input_data), daemon=True))
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for t in threads:
        t.join(2.0 if timed_out else None)
    # A pipe still held open by a stray grandchild is left to its daemon reader: closing it here would
    # wait on the reader's lock.
    for pipe, reader in ((proc.stdout, threads[0]), (proc.stderr, threads[1])):
        if not reader.is_alive():
            try:
                pipe.close()
            except OSError:
                pass
    return (None if timed_out else proc.returncode), b"".join(out), b"".join(err), timed_out


def run_command(host: str, port: int, credential: Dict[str, Any], command: str,
                approved_keys: List[Dict[str, str]], timeout: int, input_data: Optional[bytes] = None) -> Dict[str, Any]:
    """Runs one command on one host. Returns exit code, output and timing.

    input_data is sent to the remote command's standard input; use it for
    content that must not appear in a process argument list (secrets).

    status is "completed" when the remote command ran (any exit code),
    "error" for connection, authentication or host-key failures, "timeout".
    """
    started = time.time()
    if not ssh_binary():
        return {"status": "error", "exit_code": None, "stdout": "", "stderr": "OpenSSH client (ssh) not found",
                "duration": 0.0}
    work = _private_dir()
    try:
        kh = os.path.join(work, "known_hosts")
        with open(kh, "w", encoding="utf-8") as f:
            for k in approved_keys:
                f.write(f"{_known_hosts_name(host, port)} {k['key_type']} {k['key_b64']}\n")
        args = _base_args(port, work, kh, "yes") + ["-l", credential["username"] or "root"]
        env = dict(os.environ)
        if credential["cred_type"] == "ssh_key":
            key_file = os.path.join(work, "id_key")
            _write_private(key_file, credential["secret"])
            args += ["-i", key_file, "-o", "IdentitiesOnly=yes",
                     "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
            if credential.get("passphrase"):
                # The key passphrase prompt goes to the same askpass helper; BatchMode would suppress it.
                env.update(SSH_ASKPASS=_askpass_helper(work), SSH_ASKPASS_REQUIRE="force", DISPLAY=":0",
                           HM_SSH_PASSWORD=credential["passphrase"])
                args += ["-o", "NumberOfPasswordPrompts=1"]
            else:
                args += ["-o", "BatchMode=yes"]
        else:
            env.update(SSH_ASKPASS=_askpass_helper(work), SSH_ASKPASS_REQUIRE="force", DISPLAY=":0",
                       HM_SSH_PASSWORD=credential["secret"])
            args += ["-o", "PubkeyAuthentication=no", "-o", "IdentitiesOnly=yes",
                     "-o", "PreferredAuthentications=password,keyboard-interactive",
                     "-o", "NumberOfPasswordPrompts=1"]
        # The command is one argv element; OpenSSH hands it to the remote login shell.
        args += ["--", host, command]
        returncode, out, err, timed_out = _capture(args, env, timeout, input_data)
        if timed_out:
            return {"status": "timeout", "exit_code": None, "stdout": out.decode("utf-8", "replace"),
                    "stderr": f"Timed out after {timeout} s", "duration": time.time() - started}
        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
        # ssh itself exits 255 on connection, authentication or host-key failure.
        status = "error" if returncode == 255 and not stdout else "completed"
        return {"status": status, "exit_code": returncode, "stdout": stdout, "stderr": stderr,
                "duration": time.time() - started}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --- SSH key pairs ---

_PUBLIC_KEY = re.compile(r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|"
                         r"sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,3})(?: [^\r\n]{0,200})?")


class SshKeyError(RuntimeError):
    pass


def keygen_available() -> bool:
    return bool(shutil.which("ssh-keygen"))


def valid_public_key(text: str) -> bool:
    """One OpenSSH public key line whose blob names the same key type."""
    m = _PUBLIC_KEY.fullmatch(text or "")
    if not m:
        return False
    try:
        blob = base64.b64decode(m.group(2), validate=True)
        n = struct.unpack(">I", blob[:4])[0]
        return blob[4:4 + n].decode("ascii") == m.group(1)
    except (ValueError, struct.error, UnicodeDecodeError):
        return False


def _openssh_public(private_text: str) -> Optional[str]:
    """The public key stored in the clear inside an "OPENSSH PRIVATE KEY" file, even when the
    private part is passphrase-protected (openssh-key-v1: magic, cipher, kdf, kdf options, count, public blob)."""
    m = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.+?)-----END OPENSSH PRIVATE KEY-----", private_text, re.S)
    if not m:
        return None
    try:
        data = base64.b64decode("".join(m.group(1).split()), validate=True)
        magic = b"openssh-key-v1\x00"
        if not data.startswith(magic):
            return None
        pos = len(magic)

        def string() -> bytes:
            nonlocal pos
            n = struct.unpack(">I", data[pos:pos + 4])[0]
            out = data[pos + 4:pos + 4 + n]
            if len(out) != n:
                raise ValueError("truncated")
            pos += 4 + n
            return out

        string(), string(), string()                  # cipher, kdf name, kdf options
        if struct.unpack(">I", data[pos:pos + 4])[0] < 1:
            return None
        pos += 4
        blob = string()
        key_type = blob[4:4 + struct.unpack(">I", blob[:4])[0]].decode("ascii")
    except (ValueError, struct.error, UnicodeDecodeError):
        return None
    line = f"{key_type} {base64.b64encode(blob).decode('ascii')}"
    return line if valid_public_key(line) else None


def public_key_of(private_text: str) -> Optional[str]:
    """Public half of a private key: read from an OpenSSH format file, otherwise from ssh-keygen -y
    for an unencrypted PEM key. None when it cannot be worked out without the passphrase."""
    found = _openssh_public(private_text)
    if found:
        return found
    keygen = shutil.which("ssh-keygen")
    if not keygen:
        return None
    work = _private_dir()
    try:
        path = os.path.join(work, "id_key")
        _write_private(path, private_text)
        # -P "" (an empty passphrase, not a secret): an encrypted key fails instead of prompting.
        proc = subprocess.run([keygen, "-y", "-P", "", "-f", path], stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=15, shell=False)
        line = proc.stdout.strip()
        return line if proc.returncode == 0 and valid_public_key(line) else None
    except (OSError, subprocess.TimeoutExpired):
        return None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def generate_keypair(comment: str) -> tuple:
    """New ed25519 key pair from ssh-keygen. Returns (private key text, public key line).

    The private key has no passphrase of its own (a passphrase would have to go on the ssh-keygen
    command line); it is protected by the vault instead. The temporary directory is removed at once.
    """
    keygen = shutil.which("ssh-keygen")
    if not keygen:
        raise SshKeyError("ssh-keygen not found on this machine")
    comment = re.sub(r"[^A-Za-z0-9 ._@-]", "", comment)[:80]
    work = _private_dir()
    try:
        path = os.path.join(work, "id_ed25519")
        try:
            proc = subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SshKeyError(str(exc)[:200])
        if proc.returncode != 0:
            raise SshKeyError((proc.stderr or "ssh-keygen failed").strip()[:200])
        with open(path, "r", encoding="utf-8") as f:
            private = f.read()
        with open(path + ".pub", "r", encoding="utf-8") as f:
            public = f.read().strip()
        if not valid_public_key(public):
            raise SshKeyError("ssh-keygen produced an unexpected public key")
        return private, public
    finally:
        shutil.rmtree(work, ignore_errors=True)


def public_fingerprint(public_line: str) -> Optional[str]:
    parts = (public_line or "").split()
    return fingerprint(parts[1]) if len(parts) >= 2 and valid_public_key(public_line) else None


# --- Cron Schedules ---
#
# Five fields: minute hour day-of-month month day-of-week (0 or 7 = Sunday).
# Each field accepts *, a number, a-b ranges, comma lists and */n or a-b/n steps.

_FIELDS = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]


def _parse_field(text: str, lo: int, hi: int) -> set:
    values = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            step = int(step_text)
            if step < 1:
                raise ValueError("step must be at least 1")
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
        else:
            start = end = int(part)
        if not (lo <= start <= hi and lo <= end <= hi and start <= end):
            raise ValueError(f"{part} is outside {lo}-{hi}")
        values.update(range(start, end + 1, step))
    return values


def parse_cron(expr: str) -> List[set]:
    """Validates a cron expression and returns the allowed values per field. Raises ValueError."""
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError("A schedule needs 5 fields: minute hour day month weekday")
    parsed = [_parse_field(f, lo, hi) for f, (lo, hi) in zip(fields, _FIELDS)]
    if 7 in parsed[4]:
        parsed[4].add(0)
    return parsed


def cron_matches(expr: str, when: datetime) -> bool:
    minute, hour, dom, month, dow = parse_cron(expr)
    # Standard cron: when both day fields are restricted, either may match.
    dom_any, dow_any = len(dom) == 31, len(dow) >= 7
    weekday = (when.weekday() + 1) % 7
    day_ok = (when.day in dom or weekday in dow) if not (dom_any or dow_any) else (when.day in dom and weekday in dow)
    return when.minute in minute and when.hour in hour and when.month in month and day_ok
