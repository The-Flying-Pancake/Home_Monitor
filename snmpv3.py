"""SNMPv3: requests with the user-based security model (USM, RFC 3414).

A v3 device is reached with a user name and, depending on the security level, one or two passwords:
  authNoPriv   every message is signed (the device proves who it is, nothing can be changed on the way)
  authPriv     signed and encrypted (nobody on the network can read the values either)
Signing: HMAC-SHA-1-96 ("SHA", RFC 3414) or HMAC-SHA-256-192 ("SHA-256", RFC 7860). Encryption: AES-128
in CFB mode ("AES", RFC 3826). noAuthNoPriv is not offered: it is no better than a v2c community.

How a request goes:
  1. Discovery (once per device, and again when the device restarts): an empty, unsigned request makes
     the device answer with a report carrying its engine ID, how often it has started (boots) and for
     how long it has run (time). Passwords are never sent; keys are made from them for that engine ID.
  2. The request is signed (and encrypted) with keys "localised" to that engine (RFC 3414 A.2), so a key
     taken from one device opens nothing on another. Boots and time must be within 150 seconds of the
     device's own, which stops old messages being replayed.
  3. The answer is checked: same message ID, a valid signature, then decrypted. A report instead of an
     answer says what is wrong (unknown user, wrong password, ...); last_error() gives it in plain words
     for Test connection.

The BER encoding is shared with the v2c code in poller.py. Standard library plus cryptography (for AES).
"""

import hashlib
import hmac
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:          # the app needs cryptography anyway (the vault); without it v3 privacy is off
    Cipher = None
# AES in CFB mode (RFC 3826): newer cryptography keeps it under "decrepit" (old modes kept for protocols
# like this one); older versions, such as Debian's, only have the first place.
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers.modes import CFB
    except ImportError:
        CFB = None

LEVELS = ("authPriv", "authNoPriv")
AUTH_PROTOCOLS = {"SHA": (hashlib.sha1, 12), "SHA-256": (hashlib.sha256, 24)}
# Only for the SNMP check: recognising a device set to MD5, to tell its owner to choose SHA. A device is
# never polled with it (Credential.problems refuses it).
DIAGNOSTIC_AUTH = {"MD5": (hashlib.md5, 12)}


def auth_info(protocol: str):
    """(hash function, signature length) of an authentication protocol, the diagnostic ones included."""
    return AUTH_PROTOCOLS.get(protocol) or DIAGNOSTIC_AUTH[protocol]
PRIV_PROTOCOLS = ("AES",)
MIN_PASSWORD = 8                 # RFC 3414: shorter passwords are refused by agents
MAX_USER = 32

PDU_REPORT = 0xA8
MSG_MAX_SIZE = 65507
FLAG_AUTH, FLAG_PRIV, FLAG_REPORTABLE = 0x01, 0x02, 0x04
SECURITY_MODEL_USM = 3
SNMP_VERSION_3 = 3
TIME_WINDOW = 150

# What a report means, in words for the person setting the device up (usmStats, RFC 3414 section 5).
REPORTS = {
    "1.3.6.1.6.3.15.1.1.1.0": "The device does not allow this security level for the user",
    "1.3.6.1.6.3.15.1.1.2.0": "The device's clock window did not match (it may have just restarted)",
    "1.3.6.1.6.3.15.1.1.3.0": "The device does not know this user name",
    "1.3.6.1.6.3.15.1.1.4.0": "The device's engine ID changed",
    "1.3.6.1.6.3.15.1.1.5.0": "Wrong authentication password (or wrong authentication protocol)",
    "1.3.6.1.6.3.15.1.1.6.0": "Wrong privacy password (or wrong privacy protocol)",
}
NOT_IN_TIME_WINDOW = "1.3.6.1.6.3.15.1.1.2.0"
UNKNOWN_ENGINE_ID = "1.3.6.1.6.3.15.1.1.4.0"


class V3Error(ValueError):
    pass


@dataclass(frozen=True)
class Credential:
    """One device's v3 settings. The passwords stay in memory only as long as a poll needs them."""
    user: str
    level: str = "authPriv"
    auth_protocol: str = "SHA"
    auth_password: str = ""
    priv_protocol: str = "AES"
    priv_password: str = ""

    def problems(self) -> List[str]:
        out = []
        if not self.user or len(self.user) > MAX_USER or any(ord(c) < 32 for c in self.user):
            out.append(f"The user name is 1 to {MAX_USER} characters")
        if self.level not in LEVELS:
            out.append("The security level is authPriv or authNoPriv")
        if self.auth_protocol not in AUTH_PROTOCOLS:
            out.append("The authentication protocol is SHA or SHA-256")
        if len(self.auth_password) < MIN_PASSWORD:
            out.append(f"The authentication password is at least {MIN_PASSWORD} characters")
        if self.level == "authPriv":
            if self.priv_protocol not in PRIV_PROTOCOLS:
                out.append("The privacy protocol is AES")
            if len(self.priv_password) < MIN_PASSWORD:
                out.append(f"The privacy password is at least {MIN_PASSWORD} characters")
            if Cipher is None or CFB is None:
                out.append("Encryption needs the cryptography package")
        return out

    def __repr__(self) -> str:              # never the passwords, in a log or a traceback
        return f"Credential(user={self.user!r}, level={self.level!r}, auth={self.auth_protocol}, priv={self.priv_protocol})"


# --- Keys (RFC 3414 appendix A.2; RFC 7860 for SHA-256) ---

@lru_cache(maxsize=64)
def password_to_key(password: str, protocol: str) -> bytes:
    """Ku: the hash of the password repeated to one megabyte."""
    hashfn = auth_info(protocol)[0]
    pw = password.encode("utf-8")
    if not pw:
        raise V3Error("Empty password")
    size = 1048576
    data = (pw * (size // len(pw) + 1))[:size]
    return hashfn(data).digest()


def localize_key(ku: bytes, engine_id: bytes, protocol: str) -> bytes:
    """Kul: the key for one engine, so a key from one device opens nothing on another."""
    hashfn = auth_info(protocol)[0]
    return hashfn(ku + engine_id + ku).digest()


def keys_for(cred: Credential, engine_id: bytes) -> Tuple[bytes, bytes]:
    """The localised authentication key and AES-128 key (the privacy key is localised with the
    authentication protocol's hash, then cut to 16 bytes)."""
    auth = localize_key(password_to_key(cred.auth_password, cred.auth_protocol), engine_id, cred.auth_protocol)
    priv = b""
    if cred.level == "authPriv":
        priv = localize_key(password_to_key(cred.priv_password, cred.auth_protocol), engine_id, cred.auth_protocol)[:16]
    return auth, priv


def sign(key: bytes, protocol: str, message: bytes) -> bytes:
    hashfn, size = auth_info(protocol)
    return hmac.new(key, message, hashfn).digest()[:size]


def _aes(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    if Cipher is None or CFB is None:
        raise V3Error("Encryption needs the cryptography package")
    c = Cipher(algorithms.AES(key), CFB(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


# --- Messages ---

def _ber():
    import poller
    return poller


def _int(v: int) -> bytes:
    return _ber()._encode_integer(v)


def _oct(v: bytes) -> bytes:
    p = _ber()
    return p._tlv(p.TAG_OCTET_STRING, v)


def _seq(v: bytes) -> bytes:
    p = _ber()
    return p._tlv(p.TAG_SEQUENCE, v)


def pdu(pdu_type: int, request_id: int, oids: List[str], max_repetitions: int = 0,
        values: Optional[List[Tuple[str, bytes]]] = None) -> bytes:
    """A PDU. GETBULK carries non-repeaters (0) and max-repetitions where the error fields are.
    values: (oid, BER-encoded value) pairs, for a response (the test agent)."""
    p = _ber()
    if values is None:
        values = [(o, b"\x05\x00") for o in oids]
    varbinds = b"".join(_seq(p._encode_oid(o) + v) for o, v in values)
    f3 = max_repetitions if pdu_type == p.PDU_GETBULK else 0
    return p._tlv(pdu_type, _int(request_id) + _int(0) + _int(f3) + _seq(varbinds))


def _security_params(engine_id: bytes, boots: int, etime: int, user: bytes, auth: bytes, priv: bytes) -> bytes:
    return _seq(_oct(engine_id) + _int(boots) + _int(etime) + _oct(user) + _oct(auth) + _oct(priv))


def build(msg_id: int, cred: Optional[Credential], engine_id: bytes, boots: int, etime: int,
          inner_pdu: bytes, reportable: bool = True, keys: Optional[Tuple[bytes, bytes]] = None) -> bytes:
    """A whole v3 message. cred None: the unsigned discovery request (no user)."""
    flags = FLAG_REPORTABLE if reportable else 0
    scoped = _seq(_oct(engine_id) + _oct(b"") + inner_pdu)
    if cred is None:
        sec = _security_params(engine_id, boots, etime, b"", b"", b"")
        return _message(msg_id, flags, sec, scoped)
    auth_key, priv_key = keys if keys is not None else keys_for(cred, engine_id)
    flags |= FLAG_AUTH
    salt = b""
    data = scoped
    if cred.level == "authPriv":
        flags |= FLAG_PRIV
        salt = secrets.token_bytes(8)
        iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + salt
        data = _oct(_aes(priv_key, iv, scoped, True))
    size = auth_info(cred.auth_protocol)[1]
    user = cred.user.encode("utf-8")
    blank = _message(msg_id, flags, _security_params(engine_id, boots, etime, user, b"\x00" * size, salt), data)
    digest = sign(auth_key, cred.auth_protocol, blank)
    return _message(msg_id, flags, _security_params(engine_id, boots, etime, user, digest, salt), data)


def _message(msg_id: int, flags: int, sec: bytes, data: bytes) -> bytes:
    header = _seq(_int(msg_id) + _int(MSG_MAX_SIZE) + _oct(bytes([flags])) + _int(SECURITY_MODEL_USM))
    return _seq(_int(SNMP_VERSION_3) + header + _oct(sec) + data)


@dataclass
class Parsed:
    msg_id: int
    flags: int
    engine_id: bytes
    boots: int
    time: int
    user: bytes
    auth: bytes
    salt: bytes
    auth_at: int                  # where the signature sits in the raw message (to check it)
    data_tag: int
    data: bytes


def parse(raw: bytes) -> Parsed:
    """The outer layers of a v3 message (signature and encryption are checked by the caller)."""
    p = _ber()
    tag, body, end = p._decode_tlv(raw, 0)
    if tag != p.TAG_SEQUENCE:
        raise ValueError("Message is not a SEQUENCE")
    base = end - len(body)
    _, ver, off = p._decode_tlv(body, 0)
    if int.from_bytes(ver, "big") != SNMP_VERSION_3:
        raise ValueError("Not an SNMPv3 message")
    _, header, off = p._decode_tlv(body, off)
    _, mid, h = p._decode_tlv(header, 0)
    _, _, h = p._decode_tlv(header, h)                        # msgMaxSize
    _, flags, h = p._decode_tlv(header, h)
    _, model, h = p._decode_tlv(header, h)
    if int.from_bytes(model, "big") != SECURITY_MODEL_USM:
        raise ValueError("Not the user-based security model")
    _, sec, off = p._decode_tlv(body, off)
    sec_at = base + off - len(sec)
    _, sp, s_end = p._decode_tlv(sec, 0)
    sp_at = sec_at + s_end - len(sp)
    fields, o = [], 0
    for _ in range(6):
        _, v, o = p._decode_tlv(sp, o)
        fields.append((v, sp_at + o - len(v)))
    data_tag, data, _ = p._decode_tlv(body, off)
    return Parsed(msg_id=int.from_bytes(mid, "big", signed=True), flags=flags[0] if flags else 0,
                  engine_id=fields[0][0], boots=int.from_bytes(fields[1][0], "big") if fields[1][0] else 0,
                  time=int.from_bytes(fields[2][0], "big") if fields[2][0] else 0, user=fields[3][0],
                  auth=fields[4][0], salt=fields[5][0], auth_at=fields[4][1], data_tag=data_tag, data=data)


def open_scoped(raw: bytes, m: Parsed, cred: Optional[Credential], keys: Optional[Tuple[bytes, bytes]]) -> bytes:
    """The scoped PDU of a message: the signature checked and the data decrypted when they are there."""
    p = _ber()
    if m.flags & FLAG_AUTH:
        if cred is None or keys is None:
            raise V3Error("A signed message where none was expected")
        size = auth_info(cred.auth_protocol)[1]
        if len(m.auth) != size:
            raise V3Error("The signature has the wrong length")
        blank = raw[:m.auth_at] + b"\x00" * size + raw[m.auth_at + size:]
        if not hmac.compare_digest(sign(keys[0], cred.auth_protocol, blank), m.auth):
            raise V3Error("The signature does not match")
    if m.flags & FLAG_PRIV:
        if not m.flags & FLAG_AUTH or len(m.salt) != 8 or m.data_tag != p.TAG_OCTET_STRING:
            raise V3Error("Badly encrypted message")
        iv = m.boots.to_bytes(4, "big") + m.time.to_bytes(4, "big") + m.salt
        return _aes(keys[1], iv, m.data, False)
    if m.data_tag != p.TAG_SEQUENCE:
        raise V3Error("Expected a plain scoped PDU")
    return p._tlv(p.TAG_SEQUENCE, m.data)


def parse_pdu(scoped: bytes) -> Tuple[int, int, int, List[Tuple[str, Any]]]:
    """(pdu tag, request id, error status, varbinds) from a scoped PDU."""
    p = _ber()
    _, body, _ = p._decode_tlv(scoped, 0)
    _, _, off = p._decode_tlv(body, 0)            # contextEngineID
    _, _, off = p._decode_tlv(body, off)          # contextName
    pdu_tag, pdu_body, _ = p._decode_tlv(body, off)
    _, rid, o = p._decode_tlv(pdu_body, 0)
    _, err, o = p._decode_tlv(pdu_body, o)
    _, _, o = p._decode_tlv(pdu_body, o)
    _, vbl, _ = p._decode_tlv(pdu_body, o)
    out, v = [], 0
    while v < len(vbl):
        _, vb, v = p._decode_tlv(vbl, v)
        oid_tag, oid_raw, w = p._decode_tlv(vb, 0)
        if oid_tag != p.TAG_OID:
            raise ValueError("Varbind name is not an OID")
        val_tag, val_raw, _ = p._decode_tlv(vb, w)
        out.append((p._decode_oid(oid_raw), p._decode_value(val_tag, val_raw)))
    return pdu_tag, int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big") if err else 0, out


# --- Talking to a device ---

_ENGINES: Dict[Tuple[str, int], Dict[str, Any]] = {}
_ERRORS: Dict[str, str] = {}
_LOCK = threading.Lock()


def last_error(ip: str) -> str:
    """Why the last v3 request to this address failed, in plain words ("" when it did not)."""
    with _LOCK:
        return _ERRORS.get(ip, "")


def _set_error(ip: str, text: str) -> None:
    with _LOCK:
        if text:
            _ERRORS[ip] = text
        else:
            _ERRORS.pop(ip, None)


def _engine(ip: str, port: int) -> Optional[Dict[str, Any]]:
    with _LOCK:
        e = _ENGINES.get((ip, port))
        return dict(e) if e else None


def _remember(ip: str, port: int, engine_id: bytes, boots: int, etime: int) -> None:
    with _LOCK:
        _ENGINES[(ip, port)] = {"id": engine_id, "boots": boots, "time": etime, "at": time.monotonic()}


def forget(ip: str, port: int = 161) -> None:
    with _LOCK:
        _ENGINES.pop((ip, port), None)


def _exchange(sock: socket.socket, packet: bytes, msg_id: int, timeout: float) -> Optional[Tuple[bytes, Parsed]]:
    sock.send(packet)
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data = sock.recv(65535)
        except socket.timeout:
            return None
        try:
            m = parse(data)
        except (ValueError, IndexError):
            continue
        if m.msg_id == msg_id:
            return data, m


def discover(sock: socket.socket, ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    """The device's engine ID, boots and time, from the report to an empty unsigned request."""
    p = _ber()
    msg_id = secrets.randbits(31)
    got = _exchange(sock, build(msg_id, None, b"", 0, 0, pdu(p.PDU_GET, secrets.randbits(31), [])), msg_id, timeout)
    if got is None:
        return None
    _, m = got
    if not m.engine_id:
        _set_error(ip, "The device answered without an engine ID: it may not speak SNMPv3")
        return None
    _remember(ip, port, m.engine_id, m.boots, m.time)
    return _engine(ip, port)


def request(ip: str, port: int, pdu_type: int, oids: List[str], cred: Credential, timeout: float,
            retries: int, max_repetitions: int = 0, diagnostic: bool = False) -> Optional[List[Tuple[str, Any]]]:
    """One v3 request; the varbinds of the answer, or None (no answer, a refusal, a bad signature).
    last_error(ip) says why. diagnostic: the SNMP check trying a protocol a device is never set to."""
    problems = [] if diagnostic and cred.auth_protocol in DIAGNOSTIC_AUTH else cred.problems()
    if problems:
        _set_error(ip, problems[0])
        return None
    p = _ber()
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((ip, port))
        for _attempt in range(max(0, retries) + 1):
            engine = _engine(ip, port) or discover(sock, ip, port, timeout)
            if engine is None:
                if not last_error(ip):
                    _set_error(ip, "No answer to SNMPv3 (check the address, port and that SNMPv3 is on)")
                continue
            keys = keys_for(cred, engine["id"])
            resynced = False
            while True:
                boots = engine["boots"]
                etime = max(0, engine["time"] + int(time.monotonic() - engine["at"]))
                msg_id, request_id = secrets.randbits(31), secrets.randbits(31)
                packet = build(msg_id, cred, engine["id"], boots, etime,
                               pdu(pdu_type, request_id, oids, max_repetitions), keys=keys)
                got = _exchange(sock, packet, msg_id, timeout)
                if got is None:
                    _set_error(ip, "No answer to SNMPv3 (check the address, port and that SNMPv3 is on)")
                    break
                raw, m = got
                try:
                    scoped = open_scoped(raw, m, cred, keys)
                    tag, rid, err, varbinds = parse_pdu(scoped)
                except (V3Error, ValueError, IndexError) as exc:
                    # An unsigned report (unknown user, wrong digest) cannot be signed by the device.
                    if not m.flags & FLAG_AUTH and m.data_tag == p.TAG_SEQUENCE:
                        try:
                            tag, rid, err, varbinds = parse_pdu(p._tlv(p.TAG_SEQUENCE, m.data))
                        except (ValueError, IndexError):
                            _set_error(ip, f"Unreadable answer: {exc}")
                            return None
                    else:
                        _set_error(ip, f"The answer could not be checked: {exc}")
                        return None
                if tag == PDU_REPORT:
                    oid = varbinds[0][0] if varbinds else ""
                    if oid == NOT_IN_TIME_WINDOW and not resynced and m.engine_id == engine["id"]:
                        _remember(ip, port, m.engine_id, m.boots, m.time)
                        engine, resynced = _engine(ip, port), True
                        continue
                    if oid == UNKNOWN_ENGINE_ID and not resynced:
                        forget(ip, port)
                        engine = discover(sock, ip, port, timeout)
                        if engine is None:
                            return None
                        keys, resynced = keys_for(cred, engine["id"]), True
                        continue
                    _set_error(ip, REPORTS.get(oid, f"The device refused the request ({oid or 'report'})"))
                    return None
                if not m.flags & FLAG_AUTH:
                    _set_error(ip, "The answer was not signed")
                    return None
                if rid != request_id:
                    continue
                # The device's clock moves on: remember it, so the next request is in its window.
                _remember(ip, port, m.engine_id, m.boots, m.time)
                if err != 0:
                    _set_error(ip, f"The device answered with error {err}")
                    return None
                _set_error(ip, "")
                return varbinds
        return None
    except OSError:
        _set_error(ip, "No answer to SNMPv3 (the device or network refused it)")
        return None
    finally:
        sock.close()
