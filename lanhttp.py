"""A small HTTP(S) JSON client for services on the local network (Pi-hole, UniFi).

Everything here talks to addresses the administrator typed in; the container's firewall lets the
monitor reach private addresses only, so this never leaves the network.

HTTPS: verified against the system CA store by default. Home equipment usually presents its own
self-signed certificate; the administrator then pins it by its SHA-256 fingerprint (fetched and shown for
comparison, as for Proxmox). A pinned connection accepts that certificate and nothing else; the
check happens after the handshake and before anything is sent.
"""

import hashlib
import http.client
import json
import socket
import ssl
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

TIMEOUT = 8
MAX_BODY = 8 * 1024 * 1024


class LanError(Exception):
    pass


def normalise_fingerprint(text: str) -> str:
    hexs = "".join(ch for ch in (text or "").lower() if ch in "0123456789abcdef")
    if hexs and len(hexs) != 64:
        raise LanError("A SHA-256 fingerprint has 64 hex digits (32 pairs)")
    return hexs


def pretty_fingerprint(hexs: str) -> str:
    return ":".join(hexs[i:i + 2] for i in range(0, len(hexs), 2)).upper()


def parse_url(url: str, what: str = "the service") -> Tuple[str, str, int]:
    """(scheme, host, port) of a base address such as https://192.168.1.1 or http://pi.hole."""
    u = urlparse((url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise LanError(f"Enter the address of {what}, starting with http:// or https://")
    if u.path not in ("", "/") or u.query or u.username:
        raise LanError("Only the address and port, nothing after them")
    return u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)


def fetch_fingerprint(url: str) -> str:
    """The SHA-256 fingerprint of the certificate the host presents, for the administrator to compare and pin."""
    scheme, host, port = parse_url(url)
    if scheme != "https":
        raise LanError("Only an https:// address has a certificate")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        raise LanError(f"Could not reach {host}:{port}: {exc}")
    return pretty_fingerprint(hashlib.sha256(der).hexdigest())


class Response:
    def __init__(self, status: int, headers: Dict[str, str], cookies: Dict[str, str], body: bytes) -> None:
        self.status, self.headers, self.cookies, self.body = status, headers, cookies, body

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8") or "null")
        except ValueError:
            raise LanError(f"The answer was not JSON (HTTP {self.status})")


def request(base: str, method: str, path: str, fingerprint: str = "", headers: Optional[Dict[str, str]] = None,
            body: Any = None, timeout: float = TIMEOUT) -> Response:
    """One request to base + path. body is sent as JSON. Raises LanError with plain words."""
    scheme, host, port = parse_url(base)
    hdrs = {"Accept": "application/json", "User-Agent": "HomelabMonitor/1"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if scheme == "https":
        if fingerprint:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.connect()
        if scheme == "https" and fingerprint:
            der = conn.sock.getpeercert(binary_form=True)
            if hashlib.sha256(der).hexdigest() != fingerprint:
                raise LanError(f"The certificate of {host} does not match the pinned fingerprint. If it was renewed, "
                               "fetch the new fingerprint, compare it and save it.")
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY)
        cookies = {}
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                cookies[name.strip()] = rest.split(";", 1)[0]
        return Response(resp.status, {k.lower(): v for k, v in resp.getheaders()}, cookies, raw)
    except ssl.SSLCertVerificationError:
        raise LanError(f"The certificate of {host} is not trusted. Home equipment usually has a self-signed one: "
                       "fetch its fingerprint, compare it and pin it.")
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise LanError(f"Could not reach {host}:{port}: {exc}")
    finally:
        conn.close()
