"""Shared fixtures: an in-process API server on the isolated port and a JSON client."""

import json
import threading
import time
import urllib.error
import urllib.request

from tests import _env  # noqa: F401  (must precede project imports)

import auth
import database
import server

_httpd = None
TEST_USER = "tester"
TEST_PASSWORD = "correct horse battery"
_cookie = {"value": None}
_logged_in = {"at": 0.0}


def start_api_server() -> None:
    """Initialises the isolated database and vault, then serves the API in a thread (no scheduler)."""
    global _httpd
    if _httpd is not None:
        # One login serves every module. Its confirmation (auth.TIER2_SECONDS) runs out while slow
        # suites such as the installer tests run, so a module starting later logs in afresh.
        if time.monotonic() - _logged_in["at"] > auth.TIER2_SECONDS / 2:
            login()
        return
    # Cheap hashes keep the suite fast; production parameters are checked in test_auth.py.
    auth.SCRYPT_N = 2 ** 10
    server.initialise()
    _httpd = server.ThreadingServer(("127.0.0.1", _env.PORT), server.ApiRequestHandler)
    threading.Thread(target=_httpd.serve_forever, daemon=True).start()
    if database.get_account() is None:
        request("POST", "/api/auth/setup", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
    login()


def session_cookie(headers: dict):
    """Value of the session Set-Cookie header in a response, or None."""
    for k, v in headers.items():
        if k.lower() == "set-cookie" and v.startswith(auth.SESSION_COOKIE + "="):
            return v.split(";", 1)[0].split("=", 1)[1] or None
    return None


def login() -> None:
    status, body, headers = request("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASSWORD}, session=False)
    assert status == 200, body
    _cookie["value"] = session_cookie(headers)
    _logged_in["at"] = time.monotonic()


def request(method: str, path: str, body=None, headers=None, raw: bytes = None, session: bool = True):
    """Returns (status, parsed JSON or None, response headers). session=False sends no session cookie."""
    url = f"http://127.0.0.1:{_env.PORT}{path}"
    hdrs = {"Content-Type": "application/json"} if (body is not None or method in ("POST", "PUT")) else {}
    if session and _cookie["value"]:
        hdrs["Cookie"] = f"{auth.SESSION_COOKIE}={_cookie['value']}"
    hdrs.update(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else (b"{}" if method in ("POST", "PUT") else None))
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text.strip().startswith(("{", "[")) else text), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode()
        exc.close()
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text
        return exc.code, payload, dict(exc.headers)


def add_device(name: str, ip: str, community: str = "", profile: str = "generic_device") -> int:
    status, body, _ = request("POST", "/api/devices", {"hostname": name, "ip_address": ip,
                                                        "profile_id": profile, "snmp_community": community})
    assert status == 201, body
    return body["device_id"]


def raw_bytes() -> bytes:
    """Database file plus WAL contents after a checkpoint, as an attacker with a file copy would see them."""
    with database.get_connection() as conn:
        conn.execute("PRAGMA wal_checkpoint(FULL);")
    data = b""
    for suffix in ("", "-wal", "-shm"):
        try:
            with open(database.DB_FILE + suffix, "rb") as f:
                data += f.read()
        except FileNotFoundError:
            pass
    return data
