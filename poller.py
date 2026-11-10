"""Lightweight polling engine and protocol implementation for ICMP and SNMPv2c.

Implements standard library socket-level ASN.1 BER encoding and decoding
for SNMPv2c GET, GETNEXT and GETBULK alongside subprocess-based ICMP ping
execution. Zero external dependencies required.
"""

import glob
import ipaddress
import json
import logging
import math
import os
import platform
import re
import secrets
import socket
import subprocess
import time
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

import database

try:
    # The demo simulation (an install with demo data). Optional: the poller runs without it, and while
    # demo mode is off every device is polled over the network.
    import demo
except ImportError:
    demo = None


def _simulated(host: Any) -> bool:
    return demo is not None and demo.handles(host)


def _simulated_url(url: str) -> bool:
    return demo is not None and demo.handles_url(url)

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"

log = logging.getLogger("poller")


# --- ICMP Ping Implementation ---

def ping_host(ip_address: str, timeout_seconds: float = 2.0) -> Tuple[bool, Optional[float]]:
    """Executes an ICMP echo request using platform-native ping utilities.

    Returns a tuple of (is_alive, latency_ms). The address must already be
    validated by the caller: it is passed as a discrete argv element with
    shell=False, and a leading '-' is rejected here as a second guard against
    option injection.
    """
    if not ip_address or ip_address.startswith("-"):
        return False, None
    if _simulated(ip_address):
        return demo.ping_address(ip_address)

    is_windows = platform.system().lower() == "windows"
    timeout_ms = int(timeout_seconds * 1000)

    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]
    else:
        timeout_sec_int = max(1, int(timeout_seconds))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec_int), ip_address]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds + 1.0,
            shell=False
        )
        if proc.returncode != 0:
            return False, None

        output = proc.stdout
        # Windows ping exits 0 for "Destination host unreachable" replies from
        # an intermediate router, so a reply line with a TTL is required.
        if is_windows and "TTL=" not in output.upper():
            return False, None

        # Windows latency: "time=1ms" or "time<1ms"
        match_win = re.search(r"time[<=](\d+(?:\.\d+)?)ms", output, re.IGNORECASE)
        if match_win:
            return True, float(match_win.group(1))

        # Linux latency: "time=0.456 ms"
        match_nix = re.search(r"time=(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
        if match_nix:
            return True, float(match_nix.group(1))

        return True, 1.0
    except (subprocess.TimeoutExpired, OSError):
        return False, None


# --- Minimal ASN.1 BER SNMPv2c Implementation ---

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x46
TAG_UINTEGER32 = 0x47

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5

SNMP_VERSION_2C = 1
MAX_DATAGRAM = 65535


class SnmpNoValue:
    """Marker for the SNMPv2 varbind exceptions (RFC 3416 section 3).

    Distinct from None (no response) and from an empty OctetString, so a
    device that answers noSuchObject is never mistaken for a real value.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name

    def __bool__(self) -> bool:
        return False


NO_SUCH_OBJECT = SnmpNoValue("noSuchObject")
NO_SUCH_INSTANCE = SnmpNoValue("noSuchInstance")
END_OF_MIB_VIEW = SnmpNoValue("endOfMibView")
_EXCEPTION_TAGS = {0x80: NO_SUCH_OBJECT, 0x81: NO_SUCH_INSTANCE, 0x82: END_OF_MIB_VIEW}


def has_value(val: Any) -> bool:
    """True when a decoded varbind carries data (not None and not an SNMP exception)."""
    return val is not None and not isinstance(val, SnmpNoValue)


def _encode_length(length: int) -> bytes:
    """Encodes a length field according to ASN.1 BER definite-form rules."""
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    """Wraps a value in a tag and BER length."""
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(val: int) -> bytes:
    """Encodes a signed integer as minimal two's complement."""
    # One extra bit for the sign: magnitude of ~val for negatives keeps -128 to one octet.
    size = (val if val >= 0 else ~val).bit_length() // 8 + 1
    return _tlv(TAG_INTEGER, val.to_bytes(size, "big", signed=True))


def _encode_subid(value: int) -> bytes:
    """Encodes one OID sub-identifier in base-128 with continuation bits."""
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(out))


def _encode_oid(oid_str: str) -> bytes:
    """Encodes a dotted decimal OID string into ASN.1 BER bytes."""
    parts = [int(p) for p in oid_str.strip(".").split(".")]
    if len(parts) < 2 or parts[0] > 2 or (parts[0] < 2 and parts[1] > 39):
        raise ValueError(f"Invalid OID: {oid_str}")
    # The first two arcs share one sub-identifier, which may exceed 127 under arc 2.
    body = _encode_subid(parts[0] * 40 + parts[1])
    for part in parts[2:]:
        if part < 0:
            raise ValueError(f"Invalid OID: {oid_str}")
        body += _encode_subid(part)
    return _tlv(TAG_OID, body)


def _decode_oid(data: bytes) -> str:
    """Decodes BER OID content octets to dotted decimal form."""
    subids = []
    value = 0
    for b in data:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            subids.append(value)
            value = 0
    if not subids:
        return ""
    first = subids[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(x) for x in head + subids[1:])


def _decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Decodes one Tag-Length-Value element with bounds checking.

    Returns (tag, value, next_offset). Raises ValueError on truncated or
    malformed input instead of silently returning a short slice.
    """
    if offset + 2 > len(data):
        raise ValueError("Truncated BER header")
    tag = data[offset]
    first_len = data[offset + 1]
    offset += 2

    if first_len < 0x80:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        if num_octets == 0 or num_octets > 4 or offset + num_octets > len(data):
            raise ValueError("Unsupported or truncated BER length")
        length = int.from_bytes(data[offset:offset + num_octets], "big")
        offset += num_octets

    end = offset + length
    if end > len(data):
        raise ValueError("BER value exceeds buffer")
    return tag, data[offset:end], end


def _decode_octet_string(raw: bytes) -> str:
    """Returns printable text as-is and binary data (MACs, BSSIDs) as colon hex."""
    try:
        text = raw.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return text.rstrip("\x00")
    except UnicodeDecodeError:
        pass
    return ":".join(f"{b:02x}" for b in raw)


def _decode_value(tag: int, raw: bytes) -> Any:
    """Converts a varbind value TLV to a Python value."""
    if tag == TAG_INTEGER:
        return int.from_bytes(raw, "big", signed=True)
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64, TAG_UINTEGER32):
        return int.from_bytes(raw, "big", signed=False)
    if tag == TAG_OCTET_STRING:
        return _decode_octet_string(raw)
    if tag == TAG_OID:
        return _decode_oid(raw)
    if tag == TAG_IPADDRESS and len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if tag == TAG_NULL:
        return None
    if tag in _EXCEPTION_TAGS:
        return _EXCEPTION_TAGS[tag]
    return raw.hex()


_NUMERIC_TEXT = re.compile(r"-?\d{1,20}(\.\d{1,10})?", re.ASCII)


def _snmp_number(value: Any) -> Any:
    """A column that should be a number: the number, numeric text as a number, anything else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str) and _NUMERIC_TEXT.fullmatch(value):
        return float(value) if "." in value else int(value)
    return None


def _numeric_columns(row: Optional[Dict[str, Any]], columns: Iterable[str]) -> Optional[Dict[str, Any]]:
    """A copy of a table row with the named columns passed through _snmp_number."""
    if row is None:
        return None
    return {**row, **{key: _snmp_number(row.get(key)) for key in columns if key in row}}


def build_snmp_packet(
    pdu_type: int,
    community: str,
    oids: List[str],
    request_id: int,
    non_repeaters: int = 0,
    max_repetitions: int = 0
) -> bytes:
    """Constructs an SNMPv2c request message.

    For GETBULK the error-status and error-index fields carry non-repeaters
    and max-repetitions (RFC 3416 section 4.2.3).
    """
    varbinds = b"".join(_tlv(TAG_SEQUENCE, _encode_oid(o) + b"\x05\x00") for o in oids)
    if pdu_type == PDU_GETBULK:
        f2, f3 = non_repeaters, max_repetitions
    else:
        f2, f3 = 0, 0
    pdu_body = (
        _encode_integer(request_id) + _encode_integer(f2) + _encode_integer(f3)
        + _tlv(TAG_SEQUENCE, varbinds)
    )
    message = (
        _encode_integer(SNMP_VERSION_2C)
        + _tlv(TAG_OCTET_STRING, community.encode("utf-8"))
        + _tlv(pdu_type, pdu_body)
    )
    return _tlv(TAG_SEQUENCE, message)


def build_snmp_get_packet(community: str, oid_str: str, request_id: int = 1) -> bytes:
    """Constructs an SNMPv2c GET request packet for a single OID."""
    return build_snmp_packet(PDU_GET, community, [oid_str], request_id)


def parse_snmp_response(raw_data: bytes) -> Tuple[int, int, List[Tuple[str, Any]]]:
    """Parses an SNMPv2c Response PDU.

    Returns (request_id, error_status, varbinds) where varbinds is a list of
    (dotted_oid, value). Raises ValueError on malformed input.
    """
    tag, body, _ = _decode_tlv(raw_data, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError("Message is not a SEQUENCE")

    _, _, off = _decode_tlv(body, 0)          # version
    _, _, off = _decode_tlv(body, off)        # community
    pdu_tag, pdu_body, _ = _decode_tlv(body, off)
    if pdu_tag != PDU_RESPONSE:
        raise ValueError(f"Unexpected PDU type 0x{pdu_tag:02x}")

    _, rid_bytes, off = _decode_tlv(pdu_body, 0)
    _, err_bytes, off = _decode_tlv(pdu_body, off)
    _, _, off = _decode_tlv(pdu_body, off)    # error-index
    _, vbl, _ = _decode_tlv(pdu_body, off)

    request_id = int.from_bytes(rid_bytes, "big", signed=True)
    error_status = int.from_bytes(err_bytes, "big", signed=False) if err_bytes else 0

    varbinds = []
    off = 0
    while off < len(vbl):
        _, vb, off = _decode_tlv(vbl, off)
        oid_tag, oid_raw, vb_off = _decode_tlv(vb, 0)
        if oid_tag != TAG_OID:
            raise ValueError("Varbind name is not an OID")
        val_tag, val_raw, _ = _decode_tlv(vb, vb_off)
        varbinds.append((_decode_oid(oid_raw), _decode_value(val_tag, val_raw)))
    return request_id, error_status, varbinds


def _snmp_request(
    ip_address: str,
    port: int,
    pdu_type: int,
    community: str,
    oids: List[str],
    timeout_seconds: float,
    retries: int,
    max_repetitions: int = 0
) -> Optional[List[Tuple[str, Any]]]:
    """Sends one SNMP request with retries and returns the response varbinds.

    The socket is connect()ed so the OS discards datagrams from any other
    source address. Responses whose request-id does not match are treated as
    stale (late replies to an earlier attempt) and ignored. Returns None on
    timeout, transport error or a non-zero error-status.
    """
    if _simulated(ip_address):
        return None     # Demo devices answer through demo.py, never over the network
    request_id = secrets.randbits(31)
    packet = build_snmp_packet(pdu_type, community, oids, request_id, 0, max_repetitions)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((ip_address, port))
        for _attempt in range(max(0, retries) + 1):
            sock.send(packet)
            deadline = time.monotonic() + timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data = sock.recv(MAX_DATAGRAM)
                except socket.timeout:
                    break
                try:
                    rid, err, varbinds = parse_snmp_response(data)
                except ValueError as exc:
                    log.debug("Discarding malformed SNMP reply from %s: %s", ip_address, exc)
                    continue
                if rid != request_id:
                    continue
                if err != 0:
                    return None
                return varbinds
        return None
    except OSError:
        # Includes ICMP port-unreachable surfaced as ConnectionResetError on Windows.
        return None
    finally:
        sock.close()


def snmp_get(
    ip_address: str,
    oid_str: str,
    community: str = "public",
    port: int = 161,
    timeout_seconds: float = 2.0,
    retries: int = 0
) -> Any:
    """Sends a single SNMPv2c GET and returns the decoded value.

    Returns None when there is no response and an SnmpNoValue marker when the
    agent reports the OID as absent.
    """
    varbinds = _snmp_request(ip_address, port, PDU_GET, community, [oid_str], timeout_seconds, retries)
    if not varbinds:
        return None
    return varbinds[0][1]


def snmp_get_many(
    ip_address: str,
    oids: List[str],
    community: str = "public",
    port: int = 161,
    timeout_seconds: float = 2.0,
    retries: int = 0,
    chunk_size: int = 20
) -> Dict[str, Any]:
    """GETs several scalar OIDs in batched PDUs. Missing OIDs are omitted from the result."""
    results: Dict[str, Any] = {}
    for i in range(0, len(oids), chunk_size):
        chunk = oids[i:i + chunk_size]
        varbinds = _snmp_request(ip_address, port, PDU_GET, community, chunk, timeout_seconds, retries)
        if varbinds is None:
            continue
        for oid, val in varbinds:
            if has_value(val):
                results[oid] = val
    return results


def _oid_key(oid: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in oid.split("."))


def snmp_walk(
    ip_address: str,
    base_oid: str,
    community: str = "public",
    port: int = 161,
    timeout_seconds: float = 2.0,
    retries: int = 0,
    max_repetitions: int = 25,
    max_rows: int = 5000
) -> Dict[str, Any]:
    """Walks a subtree with GETBULK and returns {index_suffix: value}.

    The index suffix is the part of each OID after base_oid, e.g. walking
    ifDescr returns {"1": "eth0", "2": "eth1"}. Stops at the end of the
    subtree, at endOfMibView, on a non-increasing OID (broken agent) or at
    max_rows.
    """
    base = base_oid.strip(".")
    prefix = base + "."
    rows: Dict[str, Any] = {}
    cursor = base
    while len(rows) < max_rows:
        varbinds = _snmp_request(
            ip_address, port, PDU_GETBULK, community, [cursor],
            timeout_seconds, retries, max_repetitions=max_repetitions
        )
        if not varbinds:
            break
        done = False
        for oid, val in varbinds:
            if val is END_OF_MIB_VIEW or not oid.startswith(prefix):
                done = True
                break
            if _oid_key(oid) <= _oid_key(cursor):
                done = True
                break
            if has_value(val):
                rows[oid[len(prefix):]] = val
            cursor = oid
        if done:
            break
    return rows


# --- Typed Metric Value Parsing ---

_LEADING_NUMBER = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*([A-Za-z%]*)")
_TO_MB = {"": 1.0, "B": 1.0 / (1024 * 1024), "KB": 1.0 / 1024, "MB": 1.0, "GB": 1024.0, "TB": 1024.0 * 1024}


def parse_metric_value(raw: Any, value_type: str) -> Optional[float]:
    """Converts a raw SNMP value to a float according to the profile type hint.

    String types cover agents (notably QNAP) that return numbers with units
    attached, e.g. "12 %", "45 C/113 F", "1.9 GB", "1200 RPM".
    Returns None when the value cannot be interpreted.
    """
    if not has_value(raw):
        return None
    if value_type == "timeticks":
        return float(raw) / 100.0 if isinstance(raw, int) else None
    if isinstance(raw, (int, float)):
        return float(raw)
    if not isinstance(raw, str):
        return None

    match = _LEADING_NUMBER.match(raw)
    if not match:
        return None
    number = float(match.group(1))
    if value_type == "string_mb":
        factor = _TO_MB.get(match.group(2).upper())
        return number * factor if factor is not None else None
    return number


def _aggregate(values: List[float], how: str) -> Optional[float]:
    if not values:
        return None
    if how == "sum":
        return float(sum(values))
    if how == "avg":
        return sum(values) / len(values)
    if how == "max":
        return max(values)
    if how == "min":
        return min(values)
    if how == "count":
        return float(len(values))
    return values[0]


# --- Hardware Profile Matching & Device Probing ---

def load_hardware_profiles() -> List[Dict[str, Any]]:
    """Loads all pre-seeded hardware profile definitions from the profiles directory."""
    profiles = []
    pattern = os.path.join(PROFILES_DIR, "*.json")
    for file_path in sorted(glob.glob(pattern)):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                profiles.append(json.load(f))
        except (OSError, ValueError) as exc:
            log.warning("Skipping unreadable profile %s: %s", file_path, exc)
    return profiles


def signature_probe_oids(profiles: List[Dict[str, Any]]) -> List[str]:
    """Vendor OIDs whose presence identifies a profile ("match_exists" signatures)."""
    oids = {sig["oid"] for prof in profiles for sig in prof.get("signature_oids", []) if sig.get("match_exists")}
    return sorted(oids)


def identify_device(ip_address: str, system: Dict[str, Any], profiles: List[Dict[str, Any]],
                    community: str, port: int = 161, timeout_seconds: float = 2.0,
                    retries: int = 0) -> Optional[Dict[str, Any]]:
    """Matches a profile from the system group, plus one GET of the vendor OIDs some profiles test for.

    Agents such as Synology DSM and most UPS cards report the bare net-snmp
    or a generic sysObjectID, so their profiles test for a MIB object instead.
    """
    present: set = set()
    probe = signature_probe_oids(profiles)
    if system and probe:
        present = set(snmp_get_many(ip_address, probe, community, port, timeout_seconds, retries))
    return match_profile(profiles, str(system.get("1.3.6.1.2.1.1.1.0", "")), str(system.get("1.3.6.1.2.1.1.2.0", "")),
                         str(system.get("1.3.6.1.2.1.1.5.0", "")), present)


def match_profile(
    profiles: List[Dict[str, Any]],
    sys_descr: str,
    sys_object_id: str,
    sys_name: str = "",
    present_oids: Optional[set] = None
) -> Optional[Dict[str, Any]]:
    """Selects the most specific profile for a device.

    The profile with the highest match_priority among those with any matching
    signature wins, so vendor profiles take precedence over generic OS
    profiles that match broad strings such as "Linux". On a tie a sysObjectID
    or vendor-OID match outranks sysDescr, which outranks sysName
    (operator-editable). sysObjectID signatures match as an OID prefix (many
    embedded agents report the bare net-snmp Linux OID, so vendor profiles
    also carry string or "match_exists" signatures). String signatures match
    case-insensitively as substrings. "match_exists" signatures match when the
    OID answered (present_oids, see identify_device).
    """
    best = None
    best_rank = (-1, -1)
    strings = {"1.3.6.1.2.1.1.1.0": (sys_descr.lower(), 2), "1.3.6.1.2.1.1.5.0": (sys_name.lower(), 1)}
    for prof in profiles:
        priority = int(prof.get("match_priority", 0))
        for sig in prof.get("signature_oids", []):
            sig_oid = sig.get("oid")
            if sig.get("match_exists"):
                hit = sig_oid in (present_oids or ())
                kind = 3
            elif sig_oid == "1.3.6.1.2.1.1.2.0":
                prefix = sig.get("match_prefix", "").strip(".")
                hit = bool(prefix) and (sys_object_id == prefix or sys_object_id.startswith(prefix + "."))
                kind = 3
            elif sig_oid in strings:
                haystack, kind = strings[sig_oid]
                needle = sig.get("match_contains", "").lower()
                hit = bool(needle) and needle in haystack
            else:
                continue
            if hit and (priority, kind) > best_rank:
                best, best_rank = prof, (priority, kind)
    return best


def probe_device(
    ip_address: str,
    community: str = "public",
    port: int = 161,
    timeout_seconds: float = 2.0
) -> Dict[str, Any]:
    """Probes an address via ICMP and SNMP to auto-detect its hardware profile."""
    alive, latency_ms = ping_host(ip_address, timeout_seconds)
    if not alive:
        return {
            "success": False,
            "ip_address": ip_address,
            "error": "Host unreachable via ICMP echo"
        }

    system = snmp_get_many(
        ip_address,
        ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"],
        community, port, timeout_seconds, retries=1
    )
    descr_str = str(system.get("1.3.6.1.2.1.1.1.0", ""))
    obj_id_str = str(system.get("1.3.6.1.2.1.1.2.0", ""))
    sys_name = str(system.get("1.3.6.1.2.1.1.5.0", ""))

    matched = identify_device(ip_address, system, load_hardware_profiles(), community, port, timeout_seconds, retries=1)

    return {
        "success": True,
        "ip_address": ip_address,
        "latency_ms": latency_ms,
        "snmp_active": bool(system),
        "sys_name": sys_name,
        "sys_descr": descr_str,
        "sys_object_id": obj_id_str,
        "profile_id": matched["profile_id"] if matched else "generic_device",
        "profile_name": matched["name"] if matched else "Generic Network Device (MIB-II)"
    }


# --- Polling ---

def _poll_settings() -> Tuple[float, int]:
    """Reads the global SNMP timeout and retry count with safe fallbacks."""
    settings = database.get_all_settings()
    try:
        timeout = min(10.0, max(0.5, float(settings.get("default_timeout", "2.0"))))
    except ValueError:
        timeout = 2.0
    try:
        retries = min(5, max(0, int(settings.get("default_retries", "1"))))
    except ValueError:
        retries = 1
    return timeout, retries


def ping_device(device: Dict[str, Any], timeout_seconds: float = 1.5) -> Tuple[str, Optional[float]]:
    """Pings a device, updates its status and records latency.

    Up/down events come from the problem engine (server.ProblemEngine), which
    logs the unreachable problem opening and resolving with its duration.
    """
    if _simulated(device["ip_address"]):
        alive, ping_ms = demo.ping(device)
    else:
        alive, ping_ms = ping_host(device["ip_address"], timeout_seconds=timeout_seconds)
    port = device.get("service_port") or 0
    if port:
        # Port check: the service is up when the port accepts a connection. ICMP still gives
        # reachability and latency; a host that blocks ping but serves the port is up.
        open_, connect_ms, extra = service_check(device, timeout_seconds)
        status = "online" if open_ else "degraded" if alive else "offline"
        database.update_device_status(device["id"], status=status, ping_ms=ping_ms)
        metrics = {"service_up": 1.0 if open_ else 0.0, **extra}
        if alive:
            metrics["icmp_ping_ms"] = ping_ms or 0.0
        if open_:
            metrics["tcp_connect_ms"] = connect_ms
        database.record_metrics(device["id"], metrics)
        return status, ping_ms
    status = "online" if alive else "offline"
    database.update_device_status(device["id"], status=status, ping_ms=ping_ms)
    if alive:
        database.record_metrics(device["id"], {"icmp_ping_ms": ping_ms or 0.0})
    return status, ping_ms


HTTP_MAX_BODY = 512 * 1024


def _status_ok(code: int, spec: str) -> bool:
    """'200-399' or '200,204,301-302': whether the HTTP status is one the administrator expects."""
    for part in (spec or "200-399").replace(" ", "").split(","):
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo <= code <= hi:
                    return True
            elif part and int(part) == code:
                return True
        except ValueError:
            continue
    return False


def _own_address(host: str) -> str:
    """Why a web check may not fetch this host, or "": the monitor's own loopback and link-local
    addresses are refused (they reach services meant only for this machine, such as Syncthing's
    web interface). MONITOR_ALLOW_LOOPBACK_CHECKS=1 allows them, for a monitor that watches its own host."""
    if os.environ.get("MONITOR_ALLOW_LOOPBACK_CHECKS") == "1" or not host:
        return ""
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return ""                       # unresolvable: the fetch itself reports it
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return f"Web checks cannot fetch this machine's own or link-local addresses ({a})"
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect: urllib then raises HTTPError with the 3xx status."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_check(url: str, expect: Optional[Dict[str, Any]] = None, timeout_seconds: float = 5.0) -> Dict[str, Any]:
    """Fetches url (GET, no redirects followed) and judges it.

    Up when the status matches expect["status"] (default 200-399) and, if expect["keyword"] is
    set, the first 512 KiB of the body contain it. expect["insecure"] skips certificate checks
    for self-signed internal services; otherwise the system trust store applies.
    A redirect is the result itself (its 3xx status, and the host it points to under "redirect"):
    following it could reach any other host, the monitor's own services included.
    Returns {"up", "status", "ms", "error", "redirect"}.
    """
    import ssl
    import urllib.error
    import urllib.request
    from urllib.parse import urljoin, urlparse
    expect = expect or {}
    if not url.lower().startswith(("http://", "https://")):
        return {"up": False, "status": None, "ms": None, "error": "URL must start with http:// or https://"}
    if _simulated_url(url):
        return demo.http(url, expect)
    refused = _own_address(urlparse(url).hostname or "")
    if refused:
        return {"up": False, "status": None, "ms": None, "error": refused}
    ctx = ssl.create_default_context()
    if expect.get("insecure"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "HomelabMonitor/1 (status check)"})
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    start = time.perf_counter()
    redirect = None
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            code = resp.status
            body = resp.read(HTTP_MAX_BODY) if expect.get("keyword") else b""
    except urllib.error.HTTPError as exc:
        code, body = exc.code, b""
        if 300 <= code < 400 and exc.headers.get("Location"):
            redirect = urlparse(urljoin(url, exc.headers["Location"])).hostname or None
        exc.close()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"up": False, "status": None, "ms": None, "error": str(reason)[:200]}
    ms = round((time.perf_counter() - start) * 1000, 2)
    if not _status_ok(code, expect.get("status", "")):
        return {"up": False, "status": code, "ms": ms, "redirect": redirect,
                "error": f"HTTP {code}" + (f" (redirects to {redirect}, not followed)" if redirect else "")}
    keyword = expect.get("keyword") or ""
    if keyword and keyword.encode("utf-8") not in body:
        return {"up": False, "status": code, "ms": ms, "redirect": redirect,
                "error": f"'{keyword}' not found on the page" + (f" (HTTP {code}, redirects to {redirect})" if redirect else "")}
    return {"up": True, "status": code, "ms": ms, "error": None, "redirect": redirect}


CERT_CHECK_SECONDS = 3600
_cert_seen: Dict[str, Tuple[float, Optional[float]]] = {}


def cert_days_left(url: str, timeout_seconds: float = 5.0) -> Optional[float]:
    """Days until the certificate an https:// address presents expires (negative once it has).

    Read from the handshake without judging trust, so a self-signed internal service is covered
    too. None for http:// or when no certificate could be read."""
    import ssl
    from urllib.parse import urlparse
    u = urlparse(url)
    if u.scheme.lower() != "https" or not u.hostname:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((u.hostname, u.port or 443), timeout=timeout_seconds) as raw, \
                ctx.wrap_socket(raw, server_hostname=u.hostname) as tls:
            der = tls.getpeercert(binary_form=True)
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=__import__("datetime").timezone.utc)
        return round((after.timestamp() - time.time()) / 86400, 1)
    except Exception:
        return None


def service_check(device: Dict[str, Any], timeout_seconds: float) -> Tuple[bool, Optional[float], Dict[str, float]]:
    """The port check's own test (TCP or HTTP). Returns (up, response ms, extra metrics).
    An https:// check also reports the days its certificate has left (read at most hourly)."""
    if _simulated(device["ip_address"]):
        return demo.service(device)
    if device.get("service_kind") == "http" and device.get("service_url"):
        r = http_check(device["service_url"], device.get("service_expect") or {}, max(3.0, timeout_seconds * 2))
        extra = {"http_status": float(r["status"])} if r["status"] is not None else {}
        url = device["service_url"]
        seen = _cert_seen.get(url)
        if url.lower().startswith("https://") and (seen is None or time.time() - seen[0] > CERT_CHECK_SECONDS):
            _cert_seen[url] = seen = (time.time(), cert_days_left(url, max(3.0, timeout_seconds * 2)))
        if seen and seen[1] is not None:
            extra["tls_days_left"] = seen[1]
        return r["up"], r["ms"], extra
    ok, ms = tcp_check(device["ip_address"], device["service_port"], timeout_seconds)
    return ok, ms, {}


def tcp_check(host: str, port: int, timeout_seconds: float = 2.0) -> Tuple[bool, Optional[float]]:
    """Opens and closes a TCP connection. Returns (accepted, milliseconds to connect).

    Only the handshake: nothing is sent, so any TCP service can be checked without
    speaking its protocol. A refused or timed-out connection counts as down.
    """
    if not host or not 0 < int(port) < 65536:
        return False, None
    if _simulated(host):
        return demo.tcp(host, int(port))
    start = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=max(0.5, timeout_seconds)):
            return True, round((time.perf_counter() - start) * 1000, 2)
    except (OSError, ValueError):
        return False, None


def _snmp_fetch(device: Dict[str, Any], specs: List[Dict[str, Any]], timeout_seconds: float,
                retries: int) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """The network part of poll_snmp_metrics: GETs and walks. Returns the resolved specs and values."""
    ip = device["ip_address"]
    community = device.get("snmp_community") or "public"
    port = device.get("snmp_port") or 161
    results: Dict[str, float] = {}

    walk_cache: Dict[str, Dict[str, Any]] = {}

    def walk(oid: str) -> Dict[str, Any]:
        if oid not in walk_cache:
            walk_cache[oid] = snmp_walk(ip, oid, community, port, timeout_seconds, retries)
        return walk_cache[oid]

    if any(s.get("if_name") for s in specs):
        if_index = {name: idx for idx, name in walk(IF_NAME_OID).items()}
        resolved = []
        for spec in specs:
            if spec.get("if_name"):
                idx = if_index.get(spec["if_name"])
                if idx is None:
                    log.warning("Device %s: interface %s not found for %s", device["id"], spec["if_name"], spec["key"])
                    continue
                spec = dict(spec, oid=f"{spec['column']}.{idx}")
            resolved.append(spec)
        specs = resolved

    scalar_specs = [s for s in specs if s.get("oid")]
    raw = snmp_get_many(ip, [s["oid"] for s in scalar_specs], community, port, timeout_seconds, retries)
    for spec in scalar_specs:
        if spec["oid"] not in raw:
            continue
        # Agents answer with an empty or whitespace string for sensors the model
        # lacks (QNAP TS-x41 CPU temperature returns "\n"): treat as absent.
        if isinstance(raw[spec["oid"]], str) and not raw[spec["oid"]].strip():
            continue
        value = parse_metric_value(raw[spec["oid"]], spec.get("type", ""))
        if value is None:
            log.warning("Device %s: cannot parse %s value %r as %s",
                        device["id"], spec["key"], raw[spec["oid"]], spec.get("type"))
            continue
        results[spec["key"]] = value * spec.get("scale", 1)

    for spec in specs:
        if not spec.get("walk"):
            continue
        rows = walk(spec["walk"])
        if spec.get("filter_walk"):
            filt = walk(spec["filter_walk"])
            rows = {idx: v for idx, v in rows.items() if str(filt.get(idx)) == str(spec.get("filter_equals"))}
        values = []
        for idx in sorted(rows, key=lambda s: _oid_key(s)):
            parsed = parse_metric_value(rows[idx], spec.get("type", ""))
            if parsed is not None:
                values.append(parsed)
        value = _aggregate(values, spec.get("aggregate", "first"))
        if value is not None:
            results[spec["key"]] = value * spec.get("scale", 1)
    return specs, results


def poll_snmp_metrics(
    device: Dict[str, Any],
    profile: Optional[Dict[str, Any]],
    timeout_seconds: float = 2.0,
    retries: int = 1,
    store: bool = True
) -> Dict[str, float]:
    """Collects all profile metrics for one device and, if store is set, records them.

    store=False is used by live mode: values are returned for the in-memory
    live buffer and nothing is written or evaluated for events.

    Optional "scale" multiplies the parsed value (tenths of a degree or volt).
    Scalar metrics ("oid") are fetched in batched GETs. Interface metrics
    ("if_name" + "column") resolve the ifIndex by walking ifName, since
    ifIndex numbering differs between firmware builds, then join the scalar
    GET. Table metrics ("walk") walk a column and reduce it with "aggregate"
    (sum, avg, max, min, count, first), optionally restricted to rows where
    the "filter_walk" column equals "filter_equals".
    """
    ip = device["ip_address"]
    now = int(time.time())

    specs = list(profile.get("metrics", [])) if profile else []
    if not any(s.get("key") == "uptime_seconds" for s in specs):
        specs.insert(0, {"key": "uptime_seconds", "oid": "1.3.6.1.2.1.1.3.0", "type": "timeticks", "history": "none"})

    if _simulated(ip):
        results = demo.snmp_metrics(device, specs, now)
    else:
        specs, results = _snmp_fetch(device, specs, timeout_seconds, retries)

    results.update(derive_metrics(results))

    if not store:
        return results

    # The agent counts as responding when sysUpTime came back.
    snmp_status = "ok" if "uptime_seconds" in results else "no_response"
    previous_status = database.set_snmp_status(device["id"], snmp_status)
    if previous_status in ("ok", "no_response") and previous_status != snmp_status:
        if snmp_status == "ok":
            database.add_event(device["id"], "info", "snmp", "SNMP agent is responding again")
        else:
            database.add_event(device["id"], "warning", "snmp",
                               "SNMP agent stopped responding (host still answers ping): check the community string or agent")

    if "uptime_seconds" in results:
        previous = {m["metric_key"]: m for m in database.get_latest_metrics(device["id"])}.get("uptime_seconds")
        if previous and results["uptime_seconds"] + 60 < previous["value"]:
            database.add_event(device["id"], "warning", "reboot",
                               f"Device restarted (uptime reset from {previous['value'] / 86400:.1f} days)")

    log_value_changes(device["id"], specs, results)

    if results:
        history = {s["key"]: s["history"] for s in specs if s.get("history")}
        database.record_metrics(device["id"], results, timestamp=now, history=history)
    return results


def memory_used_pct(m: Dict[str, float]) -> Optional[float]:
    """Used memory excluding buffers and page cache, which the kernel reclaims on demand.

    UCD-SNMP agents report KB with separate buffer and cache figures; QNAP
    reports total and free in MB; Windows reports hrStorageRam size and used.
    """
    total = m.get("mem_total_kb")
    if total and "mem_avail_kb" in m:
        free = m["mem_avail_kb"] + m.get("mem_buffer_kb", 0) + m.get("mem_cached_kb", 0)
    elif m.get("mem_total_mb") and "mem_free_mb" in m:
        total, free = m["mem_total_mb"], m["mem_free_mb"]
    elif m.get("mem_hr_size_units") and "mem_hr_used_units" in m:
        # hrStorageRam rows (Windows): size and used share one allocation unit, so the ratio needs no scaling.
        total, free = m["mem_hr_size_units"], m["mem_hr_size_units"] - m["mem_hr_used_units"]
    elif "mem_free_bytes" in m and (m.get("mem_total_bytes") or "mem_used_bytes" in m):
        # Cisco memory pools report used and free; HP ProCurve reports total and free.
        total = m.get("mem_total_bytes") or m["mem_used_bytes"] + m["mem_free_bytes"]
        free = m["mem_free_bytes"]
        if not total:
            return None
    elif "mem_used_pct" in m:
        # Agents that report a percentage directly (FortiGate).
        return max(0.0, min(100.0, m["mem_used_pct"]))
    else:
        return None
    return max(0.0, min(100.0, 100.0 * (1 - free / total)))


def derive_metrics(results: Dict[str, float]) -> Dict[str, float]:
    """Computes the comparable summary values stored as history.

    The raw inputs (free, buffer and cache memory, CPU idle) are kept as
    latest values only, so one memory and one CPU series is stored per device
    instead of four.
    """
    derived: Dict[str, float] = {}
    mem = memory_used_pct(results)
    if mem is not None:
        derived["mem_used_pct"] = round(mem, 2)
    if "cpu_usage_pct" not in results and "cpu_idle_pct" in results:
        derived["cpu_usage_pct"] = max(0.0, 100.0 - results["cpu_idle_pct"])
    return derived


def log_value_changes(device_id: int, specs: List[Dict[str, Any]], results: Dict[str, float]) -> None:
    """Logs an event when a profile metric marked "event": true changes value.

    Used for near-static values stored on change (radio channel, Tx power,
    WAN link) so the event log shows when a change happened. Optional
    "values" maps raw numbers to words (e.g. {"1": "up", "2": "down"}) and
    "warn_on" lists new values that deserve a warning.
    """
    tracked = [s for s in specs if s.get("event") and s["key"] in results]
    if not tracked:
        return
    previous = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(device_id)}
    for spec in tracked:
        old, new = previous.get(spec["key"]), results[spec["key"]]
        if old is None or old == new:
            continue
        words = spec.get("values", {})
        unit = f" {spec['unit_label']}" if spec.get("unit_label") else ""
        fmt = lambda v: words.get(str(int(v)), f"{v:g}{unit}")
        severity = "warning" if str(int(new)) in spec.get("warn_on", []) else "info"
        database.add_event(device_id, severity, "change",
                           f"{spec.get('label', spec['key'])} changed {fmt(old)} -> {fmt(new)}")


# --- SNMP Table Collection (inventory, interfaces, FDB, ARP, wireless, storage) ---

SYSTEM_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_contact": "1.3.6.1.2.1.1.4.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
}

IF_COLUMNS = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "if_type": "1.3.6.1.2.1.2.2.1.3",
    "mtu": "1.3.6.1.2.1.2.2.1.4",
    "speed_bps32": "1.3.6.1.2.1.2.2.1.5",
    "mac": "1.3.6.1.2.1.2.2.1.6",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "in_octets32": "1.3.6.1.2.1.2.2.1.10",
    "in_discards": "1.3.6.1.2.1.2.2.1.13",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_octets32": "1.3.6.1.2.1.2.2.1.16",
    "out_discards": "1.3.6.1.2.1.2.2.1.19",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "in_ucast": "1.3.6.1.2.1.31.1.1.1.7",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "out_ucast": "1.3.6.1.2.1.31.1.1.1.11",
    "speed_mbps": "1.3.6.1.2.1.31.1.1.1.15",
    "alias": "1.3.6.1.2.1.31.1.1.1.18",
}
OPER_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
# IANAifType values that are physical Ethernet ports (ethernetCsmacd, gigabitEthernet).
PHYSICAL_IF_TYPES = {6, 117}
GRAPHED_IF_KINDS = {"port", "vlan", "bridge", "radio", "guest"}

UNIFI_RADIO = "1.3.6.1.4.1.41112.1.6.1.1.1"
UNIFI_VAP = "1.3.6.1.4.1.41112.1.6.1.2.1"
UNIFI_RADIO_COLS = {2: "name", 3: "band", 4: "rx_packets", 5: "tx_packets", 6: "util_pct",
                    7: "util_rx_pct", 8: "util_tx_pct", 9: "other_bss_pct"}
UNIFI_VAP_COLS = {2: "bssid", 4: "channel", 6: "ssid", 7: "name", 8: "clients", 9: "band",
                  10: "rx_bytes", 16: "tx_bytes", 21: "tx_power_dbm", 22: "up", 23: "usage"}

# Columns that are numbers by definition. A device can answer any of them with text, so they are
# made numbers (or None) before anything uses or stores them.
IF_NUMERIC_COLUMNS = ("if_type", "mtu", "speed_bps32", "admin", "oper", "in_octets32", "in_discards", "in_errors",
                      "out_octets32", "out_discards", "out_errors", "in_octets", "in_ucast", "out_octets",
                      "out_ucast", "speed_mbps")
UNIFI_RADIO_NUMERIC = ("rx_packets", "tx_packets", "util_pct", "util_rx_pct", "util_tx_pct", "other_bss_pct")
UNIFI_VAP_NUMERIC = ("channel", "clients", "rx_bytes", "tx_bytes", "tx_power_dbm")

QNAP_DISK = "1.3.6.1.4.1.24681.1.3.11.1"
QNAP_VOLUME = "1.3.6.1.4.1.24681.1.3.17.1"
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"
HR_SW_RUN_NAME = "1.3.6.1.2.1.25.4.2.1.2"   # hrSWRunName: process name (Linux truncates to 15 characters)
HR_SW_RUN_PATH = "1.3.6.1.2.1.25.4.2.1.4"
LANMGR_SERVICE = "1.3.6.1.4.1.77.1.2.3.1"   # LanMgr-Mib-II svSvcTable (Windows): 1 name, 3 operating state
LANMGR_STATES = {1: "running", 2: "continue pending", 3: "pause pending", 4: "paused"}
HR_SW_INSTALLED_NAME = "1.3.6.1.2.1.25.6.3.1.2"
SOFTWARE_REFRESH_SECONDS = 3600              # installed software changes rarely; the walk is several hundred rows
DEB_PACKAGE = re.compile(r"(?P<name>[^_]+)_(?P<version>[^_]+)_(?P<arch>[^_]+)")
TRAILING_VERSION = re.compile(r"(?P<name>.*?\S)(?:\s+-\s+|\s+v?|\s*-\s*v?)(?P<version>\d+(?:\.\d+)+[^\s(]*)(?P<suffix>\s*\([^)]*\))?")
LM_TEMP = "1.3.6.1.4.1.2021.13.16.2.1"      # LM-SENSORS-MIB lmTempSensorsTable: 2 name, 3 value (millidegrees C)
UCD_DISKIO = "1.3.6.1.4.1.2021.13.15.1.1"   # UCD-DISKIO-MIB: 2 device, 12 read bytes (64-bit), 13 written bytes (64-bit)
# Whole physical or virtual disks only: partitions, loop and device-mapper rows double count the same I/O.
PHYSICAL_DISK = re.compile(r"(sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+)")


def split_software(raw: str) -> Dict[str, str]:
    """Splits an hrSWInstalledName into name, version and architecture.

    Debian agents report "package_version_arch"; Windows reports display
    names that usually end in a version ("Veeam Agent - 6.3.1"). Anything
    else is kept whole with no version.
    """
    raw = raw.strip()
    m = DEB_PACKAGE.fullmatch(raw)
    if m:
        return m.groupdict()
    m = TRAILING_VERSION.fullmatch(raw)
    if m:
        # A trailing "(x64)" belongs to the name, so an update keeps the same key.
        return {"name": m["name"] + (m["suffix"] or ""), "version": m["version"], "arch": ""}
    return {"name": raw, "version": "", "arch": ""}


def metric_slug(name: str) -> str:
    """Lowercase key fragment for a sensor or device name ("Sensor 1" -> "sensor_1")."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")[:32] or "x"
HR_STORAGE_TYPES = {"1.3.6.1.2.1.25.2.1.2": "ram", "1.3.6.1.2.1.25.2.1.3": "virtual",
                    "1.3.6.1.2.1.25.2.1.4": "disk", "1.3.6.1.2.1.25.2.1.5": "removable",
                    "1.3.6.1.2.1.25.2.1.7": "cdrom", "1.3.6.1.2.1.25.2.1.9": "flash",
                    "1.3.6.1.2.1.25.2.1.10": "network"}

COUNTER32_MAX = 2 ** 32

_VIRTUAL_IF = re.compile(r"^(lo|dummy|teql|ifb|ip6?_?vti|ip6tnl|ip6gre|gre|sit|miireg|imq|tun|ppp|bond\d|wg|wgsrv)", re.I)


def classify_interface(label: str, if_type: Optional[int]) -> str:
    """Buckets an interface for display: port, vlan, bridge, radio, ssid or virtual.

    IANAifType alone is not enough: UniFi reports VAPs, bridges and VLAN
    sub-interfaces as ethernetCsmacd, so names decide first.
    """
    if if_type == 24 or _VIRTUAL_IF.match(label):
        return "virtual"
    # Atheros/Qualcomm APs name VAPs wifiNapM or athN; MediaTek APs (UniFi nanoHD)
    # use raN (2.4 GHz) and raiN (5 GHz), with apcli*/wds* for mesh and WDS links.
    if re.match(r"^(wifi\d+ap\d+|ath\d+|rai?\d+)$", label):
        return "ssid"
    if re.match(r"^(apclii?|wdsi?)\d+$", label):
        return "virtual"
    # Proxmox: tap<vmid>i<n> are VM NICs, veth<vmid>i<n> container NICs (per-guest
    # traffic), fwbr/fwpr/fwln are per-guest firewall plumbing, vmbrN are bridges.
    if re.match(r"^(tap|veth)\d+i\d+$", label):
        return "guest"
    if re.match(r"^fw(br|pr|ln)\d+", label):
        return "virtual"
    if re.match(r"^vmbr\d+", label):
        return "bridge"
    if re.match(r"^wifi\d+$", label):
        return "radio"
    if "." in label:
        return "vlan"
    if label.startswith("br") or label.startswith("switch"):
        return "bridge"
    if if_type in PHYSICAL_IF_TYPES or re.match(r"^(eth|en|\d+/\d+)", label):
        return "port"
    return "virtual"


def counter_delta(current: Optional[int], previous: Optional[int], wraps: bool = True) -> Optional[int]:
    """Difference between two counter samples, handling 32-bit wrap.

    A decrease on a counter that has never exceeded 32 bits is treated as a
    wrap. Any other decrease is a reset (device reboot or counter clear) and
    yields None rather than a bogus spike. wraps=False is for counters that
    never get near 2^32 between polls (errors, discards), where any decrease
    is a reset: a reboot taking eth0 errors from 1 to 0 is not 4294967295 errors.
    """
    if current is None or previous is None:
        return None
    delta = current - previous
    if delta >= 0:
        return delta
    if wraps and previous < COUNTER32_MAX and current < COUNTER32_MAX:
        return delta + COUNTER32_MAX
    return None


def _rate_bps(current: Optional[int], previous: Optional[int], seconds: float,
              ceiling_bps: Optional[float] = None) -> Optional[float]:
    delta = counter_delta(current, previous)
    if delta is None or seconds <= 0:
        return None
    bps = delta * 8 / seconds
    # A rate above the link speed means the counter jumped (reset mid-interval or agent bug).
    if ceiling_bps and bps > ceiling_bps * 1.05:
        return None
    return bps


def _table_columns(rows: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    """Splits a walk of a table entry ('col.index' suffixes) into {col: {index: value}}."""
    cols: Dict[int, Dict[str, Any]] = {}
    for suffix, value in rows.items():
        col, _, index = suffix.partition(".")
        if index:
            cols.setdefault(int(col), {})[index] = value
    return cols


def _defined_value(raw: Any, col: Dict[str, Any]) -> Any:
    """One cell of a profile-defined table: optional word map, then numeric scale."""
    if raw is None:
        return None
    if "map" in col:
        return col["map"].get(str(raw), f"state {raw}")
    if "scale" in col or col.get("type") == "number":
        number = parse_metric_value(raw, "")
        return None if number is None else round(number * col.get("scale", 1), 3)
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    return raw.strip() if isinstance(raw, str) else raw


def build_defined_rows(spec: Dict[str, Any], cols: Dict[int, Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, float]]:
    """Builds snapshot rows from a "table_defs" entry of a profile.

    spec keys:
      table     target snapshot table: "disks", "volumes" or "health"
      walk      the table entry OID; columns are numbered beneath it
      columns   {field: column number or {"col", "map", "scale", "type"}}
      fixed     constant fields added to every row (e.g. {"kind": "fan"})
      key       column whose presence makes a row (default: the first column listed)
      id_prefix prefix for row keys, so several definitions can share one table
      pct       [numerator, denominator] fields: sets "pct" when both are valid
      ok        a rule or list of rules, each {"field"} plus "values" (good states),
                "bad" (fault states) or "min" / "max": sets "ok" from the rules whose
                field has a value
      severity  problem severity when ok is false (default warning)
      metrics   [{"field", "key"}]: numeric fields also stored as metrics;
                "{index}" in key is replaced by the row index
    Volumes gain used_bytes and used_pct from size_bytes plus used_bytes or free_bytes.
    """
    columns = {f: ({"col": c} if isinstance(c, int) else c) for f, c in spec.get("columns", {}).items()}
    if not columns:
        return {}, {}
    key_col = spec.get("key", next(iter(columns.values()))["col"])
    rows: Dict[str, Any] = {}
    metrics: Dict[str, float] = {}
    for index in cols.get(key_col, {}):
        row: Dict[str, Any] = dict(spec.get("fixed", {}))
        for field, col in columns.items():
            row[field] = _defined_value(cols.get(col["col"], {}).get(index), col)
        size = row.get("size_bytes")
        if isinstance(size, (int, float)) and size > 0:
            if row.get("used_bytes") is None and isinstance(row.get("free_bytes"), (int, float)):
                row["used_bytes"] = size - row["free_bytes"]
            if isinstance(row.get("used_bytes"), (int, float)):
                row["used_pct"] = round(100.0 * row["used_bytes"] / size, 2)
        if spec.get("pct"):
            num, den = (row.get(f) for f in spec["pct"])
            # Printer-MIB uses negative levels for "unknown" and "some remaining".
            if isinstance(num, (int, float)) and isinstance(den, (int, float)) and num >= 0 and den > 0:
                row["pct"] = round(min(100.0, 100.0 * num / den), 1)
        verdicts = []
        for rule in spec.get("ok", []) if isinstance(spec.get("ok"), list) else [spec.get("ok")] if spec.get("ok") else []:
            v = row.get(rule["field"])
            if v is None:
                continue
            if "values" in rule:
                verdicts.append(v in rule["values"])
            elif "bad" in rule:
                # Only listed states count as faults, so an unexpected code is shown but not alarmed.
                verdicts.append(v not in rule["bad"])
            elif isinstance(v, (int, float)):
                verdicts.append(rule.get("min", float("-inf")) <= v <= rule.get("max", float("inf")))
        if verdicts:
            row["ok"] = all(verdicts)
            if not row["ok"]:
                row["severity"] = spec.get("severity", "warning")
        for m in spec.get("metrics", []):
            v = row.get(m["field"])
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                metrics[m["key"].replace("{index}", index)] = float(v)
        rows[spec.get("id_prefix", "") + index] = row
    return rows, metrics


def _mac_from_index(index: str) -> str:
    """Converts a MAC encoded as six decimal sub-identifiers into colon hex."""
    parts = index.split(".")[-6:]
    return ":".join(f"{int(p):02x}" for p in parts)


class TableCollector:
    """Collects SNMP tables for one device and stores them as snapshots.

    Rates are derived from the previous snapshot of the same table, so the
    first poll after a restart produces counters only and the second poll
    onwards produces rates.
    """

    def __init__(self, device: Dict[str, Any], profile: Optional[Dict[str, Any]],
                 timeout_seconds: float, retries: int) -> None:
        self.device = device
        self.profile = profile or {}
        self.ip = device["ip_address"]
        self.community = device.get("snmp_community") or "public"
        self.port = device.get("snmp_port") or 161
        self.timeout = timeout_seconds
        self.retries = retries
        self.now = int(time.time())
        self._defined: Dict[str, Dict[str, Any]] = {}

    def walk(self, oid: str) -> Dict[str, Any]:
        return snmp_walk(self.ip, oid, self.community, self.port, self.timeout, self.retries,
                         max_repetitions=40)

    def run(self) -> List[str]:
        """Runs every collector enabled for the profile. Returns the tables written."""
        written = []
        self.collect_inventory()
        for name in self.profile.get("tables", ["interfaces"]):
            method = getattr(self, f"collect_{name}", None)
            if method is None:
                log.warning("Profile %s lists unknown table %s", self.profile.get("profile_id"), name)
                continue
            try:
                if method():
                    written.append(name)
            except Exception:
                log.exception("Device %s: %s collection failed", self.device["id"], name)
        for spec in self.profile.get("table_defs", []):
            try:
                if self.collect_defined(spec):
                    written.append(spec["table"])
            except Exception:
                log.exception("Device %s: %s table definition failed", self.device["id"], spec.get("table"))
        return written

    def collect_defined(self, spec: Dict[str, Any]) -> bool:
        """A table described in the profile JSON (see build_defined_rows)."""
        rows, metrics = build_defined_rows(spec, _table_columns(self.walk(spec["walk"])))
        if not rows:
            return False
        # Several definitions may feed one table (iDRAC fans, PSUs and temperatures all go to health).
        table = spec["table"]
        if spec.get("merge"):
            merged = dict(self._defined.get(table, {}))
            merged.update(rows)
            rows = merged
        self._defined[table] = rows
        database.replace_device_table(self.device["id"], table, rows, self.now)
        if metrics:
            database.record_metrics(self.device["id"], metrics, self.now)
        return True

    def collect_inventory(self) -> None:
        oids = dict(SYSTEM_OIDS)
        oids.update(self.profile.get("inventory_oids", {}))
        raw = snmp_get_many(self.ip, list(oids.values()), self.community, self.port, self.timeout, self.retries)
        if not raw:
            return
        inv = {key: str(raw[oid]) for key, oid in oids.items() if oid in raw}
        # Profiles may extract model and firmware from sysDescr (or another system
        # field given as {"from": field, "pattern": regex}) when no dedicated OID exists.
        for key, rule in self.profile.get("inventory_regex", {}).items():
            if key in inv:
                continue
            source, pattern = ("sys_descr", rule) if isinstance(rule, str) else (rule["from"], rule["pattern"])
            match = re.search(pattern, inv.get(source, ""), re.IGNORECASE)
            if match:
                inv[key] = match.group(1).upper() if source == "sys_name" else match.group(1)
        old = self.device.get("inventory") or {}
        labels = {"firmware": "Firmware", "model": "Hardware model", "sys_name": "System name",
                  "sys_location": "Location"}
        for key, label in labels.items():
            if old.get(key) and inv.get(key) and old[key] != inv[key]:
                database.add_event(self.device["id"], "info", "inventory",
                                   f"{label} changed from {old[key]} to {inv[key]}", self.now)
        database.update_inventory(self.device["id"], inv)

    def collect_interfaces(self) -> bool:
        cols = {key: self.walk(oid) for key, oid in IF_COLUMNS.items()}
        indexes = set(cols["descr"]) | set(cols["name"])
        if not indexes:
            return False
        previous = database.get_device_table(self.device["id"], "interfaces")

        rows: Dict[str, Dict[str, Any]] = {}
        rate_metrics: Dict[str, float] = {}
        for idx in indexes:
            r = _numeric_columns({key: cols[key].get(idx) for key in IF_COLUMNS}, IF_NUMERIC_COLUMNS)
            # Prefer 64-bit counters and ifHighSpeed, fall back to the 32-bit ifTable columns.
            if r["in_octets"] is None:
                r["in_octets"] = r["in_octets32"]
            if r["out_octets"] is None:
                r["out_octets"] = r["out_octets32"]
            if not r["speed_mbps"] and r["speed_bps32"]:
                r["speed_mbps"] = r["speed_bps32"] / 1_000_000
            for key in ("in_octets32", "out_octets32", "speed_bps32"):
                r.pop(key)
            r["if_index"] = int(idx)
            r["oper_text"] = OPER_STATUS.get(r["oper"], "unknown")
            r["admin_text"] = "up" if r["admin"] == 1 else "down" if r["admin"] == 2 else "testing"
            r["label"] = r["name"] or r["descr"] or idx
            r["kind"] = classify_interface(r["label"], r["if_type"])

            prev = _numeric_columns(previous.get(idx), IF_NUMERIC_COLUMNS)
            if prev:
                seconds = self.now - prev["updated_at"]
                ceiling = (r["speed_mbps"] or 0) * 1_000_000 or None
                r["in_bps"] = _rate_bps(r["in_octets"], prev.get("in_octets"), seconds, ceiling)
                r["out_bps"] = _rate_bps(r["out_octets"], prev.get("out_octets"), seconds, ceiling)
                for key in ("in_errors", "out_errors", "in_discards", "out_discards"):
                    r[f"{key}_delta"] = counter_delta(r[key], prev.get(key), wraps=False)
                # Rate history only for interfaces that are up and worth graphing; virtual
                # and per-SSID interfaces would multiply metric rows for little value.
                if r["oper"] == 1 and r["kind"] in GRAPHED_IF_KINDS:
                    if r["in_bps"] is not None:
                        rate_metrics[f"if.{idx}.in_bps"] = r["in_bps"]
                    if r["out_bps"] is not None:
                        rate_metrics[f"if.{idx}.out_bps"] = r["out_bps"]
                self._port_state_event(r, prev)
            rows[idx] = r

        database.replace_device_table(self.device["id"], "interfaces", rows, self.now)
        if rate_metrics:
            database.record_metrics(self.device["id"], rate_metrics, self.now)
        return True

    def _port_state_event(self, cur: Dict[str, Any], prev: Dict[str, Any]) -> None:
        """Logs link up/down, admin enable/disable and speed renegotiation.

        Limited to physical ports, VLANs and radios: SSID and virtual
        interfaces on APs and gateways toggle often and would flood the log.
        """
        if cur["kind"] not in ("port", "vlan", "radio"):
            return
        name = cur["label"] + (f" ({cur['alias']})" if cur.get("alias") and cur["alias"] != cur["label"] else "")
        dev = self.device["id"]
        if prev.get("admin") is not None and cur["admin"] is not None and prev["admin"] != cur["admin"]:
            database.add_event(dev, "info", "port",
                               f"Port {name} administratively {'enabled' if cur['admin'] == 1 else 'disabled'}", self.now)
        if prev.get("oper") is not None and cur["oper"] is not None and prev["oper"] != cur["oper"]:
            went_down = cur["oper"] != 1 and prev["oper"] == 1
            severity = "warning" if went_down and cur["admin"] == 1 and cur["kind"] == "port" else "info"
            database.add_event(dev, severity, "port",
                               f"Port {name} link {prev.get('oper_text', '?')} -> {cur['oper_text']}", self.now)
        elif (cur["oper"] == 1 and prev.get("speed_mbps") and cur.get("speed_mbps")
              and prev["speed_mbps"] != cur["speed_mbps"]):
            database.add_event(dev, "warning" if cur["speed_mbps"] < prev["speed_mbps"] else "info", "port",
                               f"Port {name} speed changed {prev['speed_mbps']:g} -> {cur['speed_mbps']:g} Mbps", self.now)

    def collect_fdb(self) -> bool:
        """Bridge forwarding table: which MAC addresses were learned on which port."""
        port_to_if = {k: v for k, v in self.walk("1.3.6.1.2.1.17.1.4.1.2").items()}
        rows: Dict[str, Dict[str, Any]] = {}
        # BRIDGE-MIB (index mac) is the complete table on UniFi firmware. Q-BRIDGE
        # (index vlan.mac) covers only some VLANs there, so it only adds the VLAN id.
        ports = self.walk("1.3.6.1.2.1.17.4.3.1.2")
        status = self.walk("1.3.6.1.2.1.17.4.3.1.3")
        for index, bridge_port in ports.items():
            if status.get(index) == 4:  # self: the switch's own address
                continue
            rows[_mac_from_index(index)] = {"bridge_port": bridge_port, "vlan": None}
        for index, bridge_port in self.walk("1.3.6.1.2.1.17.7.1.2.2.1.2").items():
            vlan, mac_index = index.split(".", 1)
            entry = rows.setdefault(_mac_from_index(mac_index), {"bridge_port": bridge_port, "vlan": None})
            entry["vlan"] = int(vlan)
        if not rows:
            return False
        for row in rows.values():
            row["if_index"] = int(port_to_if.get(str(row["bridge_port"]), row["bridge_port"]))
        database.replace_device_table(self.device["id"], "fdb", rows, self.now)
        return True

    def collect_arp(self) -> bool:
        """IPv4 neighbour table (ipNetToMediaPhysAddress), index ifIndex.a.b.c.d."""
        raw = self.walk("1.3.6.1.2.1.4.22.1.2")
        rows = {}
        for index, mac in raw.items():
            parts = index.split(".")
            if len(parts) != 5 or not isinstance(mac, str) or mac in ("", "00:00:00:00:00:00"):
                continue
            rows[".".join(parts[1:])] = {"mac": mac.lower(), "if_index": int(parts[0])}
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "arp", rows, self.now)
        return True

    def collect_wireless(self) -> bool:
        """UniFi radio and per-SSID (VAP) tables."""
        radio_cols = _table_columns(self.walk(UNIFI_RADIO))
        vap_cols = _table_columns(self.walk(UNIFI_VAP))
        if not radio_cols and not vap_cols:
            return False

        radios = {}
        for idx in radio_cols.get(2, {}):
            radios[idx] = _numeric_columns({name: radio_cols.get(col, {}).get(idx)
                                            for col, name in UNIFI_RADIO_COLS.items()}, UNIFI_RADIO_NUMERIC)
        database.replace_device_table(self.device["id"], "radios", radios, self.now)

        previous = database.get_device_table(self.device["id"], "ssids")
        ssids = {}
        for idx in vap_cols.get(6, {}):
            row = _numeric_columns({name: vap_cols.get(col, {}).get(idx)
                                    for col, name in UNIFI_VAP_COLS.items()}, UNIFI_VAP_NUMERIC)
            prev = _numeric_columns(previous.get(idx), UNIFI_VAP_NUMERIC)
            if prev:
                seconds = self.now - prev["updated_at"]
                row["rx_bps"] = _rate_bps(row["rx_bytes"], prev.get("rx_bytes"), seconds)
                row["tx_bps"] = _rate_bps(row["tx_bytes"], prev.get("tx_bytes"), seconds)
            ssids[idx] = row
        database.replace_device_table(self.device["id"], "ssids", ssids, self.now)
        return True

    def collect_storage(self) -> bool:
        """HOST-RESOURCES-MIB hrStorageTable: RAM, swap, disks and mount points."""
        cols = _table_columns(self.walk(HR_STORAGE))
        rows = {}
        for idx, descr in cols.get(3, {}).items():
            units = cols.get(4, {}).get(idx) or 0
            size = cols.get(5, {}).get(idx) or 0
            used = cols.get(6, {}).get(idx) or 0
            if size <= 0 or units <= 0:
                continue
            # Skip tiny tmpfs mounts (systemd credentials, /run/lock): always near-empty, only noise.
            if size * units < 64 * 1024 * 1024 and str(descr).startswith("/run"):
                continue
            rows[idx] = {
                "descr": descr,
                "kind": HR_STORAGE_TYPES.get(str(cols.get(2, {}).get(idx)), "other"),
                "size_bytes": size * units,
                "used_bytes": used * units,
                "used_pct": 100.0 * used / size,
            }
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "storage", rows, self.now)
        # Disks and mount points also keep a history, for the "full in N days" forecast (forecast.py).
        used = {f"stor.{idx}.used_pct": round(r["used_pct"], 2) for idx, r in rows.items() if r["kind"] in ("disk", "flash")}
        if used:
            database.record_metrics(self.device["id"], used, self.now)
        return True

    def collect_sensors(self) -> bool:
        """lm-sensors temperatures (CPU package, NVMe, board), stored as sensor.<name>.temp_c."""
        cols = _table_columns(self.walk(LM_TEMP))
        rows, temps = {}, {}
        for idx, name in cols.get(2, {}).items():
            raw = cols.get(3, {}).get(idx)
            # Millidegrees; drivers report 0 or absurd values for absent probes.
            if not isinstance(raw, int) or not 0 < raw < 150000:
                continue
            slug = metric_slug(name)
            rows[idx] = {"name": name, "slug": slug, "temp_c": round(raw / 1000, 1)}
            temps[f"sensor.{slug}.temp_c"] = raw / 1000
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "sensors", rows, self.now)
        database.record_metrics(self.device["id"], temps, self.now)
        return True

    def collect_diskio(self) -> bool:
        """Read and write throughput per whole disk from UCD-DISKIO-MIB 64-bit byte counters."""
        cols = _table_columns(self.walk(UCD_DISKIO))
        previous = database.get_device_table(self.device["id"], "diskio")
        rows, rates = {}, {}
        for idx, name in cols.get(2, {}).items():
            if not PHYSICAL_DISK.fullmatch(str(name)):
                continue
            row = {"name": name, "read_bytes": cols.get(12, {}).get(idx), "written_bytes": cols.get(13, {}).get(idx)}
            prev = previous.get(idx)
            if prev and prev.get("name") == name:
                seconds = self.now - prev["updated_at"]
                # _rate_bps returns bits per second; disk throughput is shown in bytes per second.
                rd = _rate_bps(row["read_bytes"], prev.get("read_bytes"), seconds)
                wr = _rate_bps(row["written_bytes"], prev.get("written_bytes"), seconds)
                row["read_Bps"] = rd / 8 if rd is not None else None
                row["write_Bps"] = wr / 8 if wr is not None else None
                slug = metric_slug(name)
                if row["read_Bps"] is not None:
                    rates[f"dio.{slug}.read_Bps"] = row["read_Bps"]
                if row["write_Bps"] is not None:
                    rates[f"dio.{slug}.write_Bps"] = row["write_Bps"]
            rows[idx] = row
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "diskio", rows, self.now)
        if rates:
            database.record_metrics(self.device["id"], rates, self.now)
        return True

    def collect_processes(self) -> bool:
        """Running process names with instance counts (hrSWRunTable), for watched-process problems."""
        counts: Dict[str, int] = {}
        names = self.walk(HR_SW_RUN_NAME)
        # Linux kernel threads (kworker/*, ksoftirqd/*) have no executable path; Windows
        # leaves the path empty for many user processes, so only filter elsewhere.
        paths = {} if self.profile.get("profile_id") == "windows_host" else self.walk(HR_SW_RUN_PATH)
        for idx, name in names.items():
            if not isinstance(name, str) or not name.strip():
                continue
            if paths and not str(paths.get(idx) or "").strip():
                continue
            counts[name.strip()] = counts.get(name.strip(), 0) + 1
        if not counts:
            return False
        database.replace_device_table(self.device["id"], "processes",
                                      {n: {"name": n, "count": c} for n, c in counts.items()}, self.now)
        return True

    def collect_services(self) -> bool:
        """Windows services the agent lists as started (LanMgr svSvcTable)."""
        cols = _table_columns(self.walk(LANMGR_SERVICE))
        rows = {}
        for idx, name in cols.get(1, {}).items():
            if isinstance(name, str) and name.strip():
                state = cols.get(3, {}).get(idx)
                rows[name.strip()] = {"name": name.strip(), "state": LANMGR_STATES.get(state, f"state {state}")}
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "services", rows, self.now)
        return True

    def collect_software(self) -> bool:
        """Installed software (hrSWInstalledTable), refreshed hourly, with install / remove / update events."""
        previous = database.get_device_table(self.device["id"], "software")
        if previous and self.now - max(r["updated_at"] for r in previous.values()) < SOFTWARE_REFRESH_SECONDS:
            return True
        rows: Dict[str, Dict[str, str]] = {}
        for raw in self.walk(HR_SW_INSTALLED_NAME).values():
            if isinstance(raw, str) and raw.strip():
                item = split_software(raw)
                rows[item["name"]] = item
        if not rows:
            return False
        if previous:
            log_software_changes(self.device["id"], previous, rows)
        database.replace_device_table(self.device["id"], "software", rows, self.now)
        return True

    def collect_qnap_disks(self) -> bool:
        """QNAP NAS-MIB numeric disk table: bay name, temperature (C), model, capacity, SMART."""
        cols = _table_columns(self.walk(QNAP_DISK))
        rows, temps = {}, {}
        for idx, name in cols.get(2, {}).items():
            temp = cols.get(3, {}).get(idx)
            rows[idx] = {
                "name": name,
                "temp_c": temp if isinstance(temp, int) and temp > 0 else None,
                "status_code": cols.get(4, {}).get(idx),
                "model": cols.get(5, {}).get(idx),
                "size_bytes": cols.get(6, {}).get(idx),
                "smart": cols.get(7, {}).get(idx),
            }
            if rows[idx]["temp_c"] is not None:
                temps[f"disk.{idx}.temp_c"] = float(rows[idx]["temp_c"])
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "disks", rows, self.now)
        database.record_metrics(self.device["id"], temps, self.now)
        return True

    def collect_qnap_volumes(self) -> bool:
        """QNAP NAS-MIB numeric volume table: name, filesystem, total and free (KB), status."""
        cols = _table_columns(self.walk(QNAP_VOLUME))
        rows, used = {}, {}
        for idx, descr in cols.get(2, {}).items():
            total_kb = cols.get(4, {}).get(idx) or 0
            free_kb = cols.get(5, {}).get(idx) or 0
            pct_used = 100.0 * (total_kb - free_kb) / total_kb if total_kb else None
            rows[idx] = {
                "descr": str(descr).strip("[]"),
                "filesystem": cols.get(3, {}).get(idx),
                "size_bytes": total_kb * 1024,
                "used_bytes": (total_kb - free_kb) * 1024,
                "used_pct": pct_used,
                "status": cols.get(6, {}).get(idx),
            }
            if pct_used is not None:
                used[f"vol.{idx}.used_pct"] = pct_used
        if not rows:
            return False
        database.replace_device_table(self.device["id"], "volumes", rows, self.now)
        database.record_metrics(self.device["id"], used, self.now)
        return True


SOFTWARE_EVENT_LIMIT = 10


def log_software_changes(device_id: int, old: Dict[str, Dict[str, Any]], new: Dict[str, Dict[str, Any]]) -> None:
    """Logs installed, removed and updated software. A large batch (a full upgrade) becomes one summary event."""
    changes = []
    for name in sorted(set(new) - set(old)):
        changes.append(f"Installed {name} {new[name].get('version', '')}".rstrip())
    for name in sorted(set(old) - set(new)):
        changes.append(f"Removed {name} {old[name].get('version', '')}".rstrip())
    for name in sorted(set(old) & set(new)):
        if old[name].get("version") != new[name].get("version"):
            changes.append(f"Updated {name} {old[name].get('version')} to {new[name].get('version')}")
    if not changes:
        return
    if len(changes) > SOFTWARE_EVENT_LIMIT:
        database.add_event(device_id, "info", "software",
                           f"{len(changes)} software changes: " + "; ".join(changes[:SOFTWARE_EVENT_LIMIT]) + "; ...")
        return
    for text in changes:
        database.add_event(device_id, "info", "software", text)


def collect_tables(device: Dict[str, Any], profile: Optional[Dict[str, Any]],
                   timeout_seconds: float = 2.0, retries: int = 1) -> List[str]:
    """Collects inventory and the profile's SNMP tables for a device."""
    if _simulated(device["ip_address"]):
        return demo.collect_tables(device, profile)
    return TableCollector(device, profile, timeout_seconds, retries).run()


def poll_single_device(device: Dict[str, Any], profiles_cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Executes an ICMP ping and, if the host answers, a full SNMP metric poll."""
    if profiles_cache is None:
        profiles_cache = {p["profile_id"]: p for p in load_hardware_profiles()}
    timeout, retries = _poll_settings()

    status, ping_ms = ping_device(device)
    result: Dict[str, Any] = {
        "device_id": device["id"],
        "status": status,
        "ping_ms": ping_ms,
        "metrics": {}
    }
    if status == "online":
        result["metrics"]["icmp_ping_ms"] = ping_ms or 0.0
        profile = profiles_cache.get(device.get("profile_id", "generic_device"))
        result["metrics"].update(poll_snmp_metrics(device, profile, timeout, retries))
        result["tables"] = collect_tables(device, profile, timeout, retries)
    return result


# --- Live Mode Sampling ---

LIVE_IF_COLUMNS = {"in_octets": "1.3.6.1.2.1.31.1.1.1.6", "out_octets": "1.3.6.1.2.1.31.1.1.1.10"}


def live_sample(device: Dict[str, Any], profile: Optional[Dict[str, Any]],
                timeout_seconds: float = 2.0, retries: int = 0) -> Dict[str, Any]:
    """Takes one live-mode sample: ping, profile metrics and interface octet counters.

    Nothing is written to the database. The caller derives interface rates
    from consecutive samples and keeps them in memory.
    """
    if _simulated(device["ip_address"]):
        return demo.live_sample(device, profile)
    alive, ping_ms = ping_host(device["ip_address"], min(timeout_seconds, 2.0))
    sample: Dict[str, Any] = {"timestamp": time.time(), "alive": alive, "metrics": {}, "counters": {}}
    if device.get("service_port"):
        open_, connect_ms, _ = service_check(device, min(timeout_seconds, 2.0))
        sample["alive"] = alive or open_
        sample["metrics"]["service_up"] = 1.0 if open_ else 0.0
        if alive:
            sample["metrics"]["icmp_ping_ms"] = ping_ms or 0.0
        if open_:
            sample["metrics"]["tcp_connect_ms"] = connect_ms
        return sample
    if not alive:
        return sample
    sample["metrics"]["icmp_ping_ms"] = ping_ms or 0.0
    sample["metrics"].update(poll_snmp_metrics(device, profile, timeout_seconds, retries, store=False))
    ip = device["ip_address"]
    community = device.get("snmp_community") or "public"
    port = device.get("snmp_port") or 161
    ins = snmp_walk(ip, LIVE_IF_COLUMNS["in_octets"], community, port, timeout_seconds, retries, max_repetitions=40)
    outs = snmp_walk(ip, LIVE_IF_COLUMNS["out_octets"], community, port, timeout_seconds, retries, max_repetitions=40)
    sample["counters"] = {idx: (ins.get(idx), outs.get(idx)) for idx in set(ins) | set(outs)}
    return sample
