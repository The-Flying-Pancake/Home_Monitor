"""HTTPS for the web interface: off, a self-signed certificate made here, or your own.

The mode, the certificate (PEM, public) and its private key live in the settings table; the key
is vault-encrypted like every other secret (context "setting:tls_key") and never sent to the
browser. Because they are in the database, a normal backup carries them and a restore brings
them back; nothing is kept in files beside it.

Self-signed: an EC P-256 certificate for this machine's names and addresses (plus any extra
names the administrator gives), valid 825 days, the longest Apple devices accept. It is made again when
it is within 30 days of expiry or when the machine's name or address changes, so the browser
warning never turns into an outright mismatch. Its SHA-256 fingerprint is shown so it can be
checked once and trusted.

Own certificate: a PEM chain (server certificate first) and an unencrypted PEM key, checked
before it is stored: the key must belong to the certificate, it must not have expired and
Python's ssl must load the pair. A daily check warns (event, bell, Telegram) from 21 days before
it expires.

Upgrades: an install from before HTTPS existed keeps plain HTTP (bookmarks and other tools that
check it keep working) and asks an admin once in the app. A fresh install starts self-signed
when the service sets MONITOR_TLS_DEFAULT=self-signed (the container does).

The server (server.py) serves both on one port: a connection whose first byte is a TLS handshake
is wrapped, plain HTTP from another machine is redirected to https, plain HTTP from this machine
itself (health checks, the installer) is answered as before.

The cryptography library (already used by the vault) makes and reads certificates; ssl serves.
"""

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import socket
import ssl
import tempfile
import threading
from typing import Any, Dict, List, Optional, Tuple

import database

log = logging.getLogger("tls")

MODES = ("off", "self-signed", "own")
MODE_KEY = "tls_mode"
CERT_KEY = "tls_cert"
KEY_KEY = "tls_key"            # in database.SECRET_SETTINGS: encrypted at rest
NAMES_KEY = "tls_extra_names"  # extra names for the self-signed certificate (JSON list)
PROMPT_KEY = "tls_prompt"      # "pending": ask an admin to choose (installs upgraded from before HTTPS)
WARNED_KEY = "tls_warned"      # expiry date already warned about, and on which day (no repeat the same day)

SELF_SIGNED_DAYS = 825
RENEW_DAYS = 30
WARN_DAYS = 21
MAX_PEM = 48 * 1024
MAX_NAMES = 10


class TlsError(ValueError):
    pass


# --- Certificate details ------------------------------------------------------

def _utc(cert, attr: str) -> datetime.datetime:
    value = getattr(cert, attr + "_utc", None)  # cryptography 42+
    if value is None:
        value = getattr(cert, attr).replace(tzinfo=datetime.timezone.utc)
    return value


def _split_pem(text: str) -> List[bytes]:
    blocks, cur = [], None
    for line in text.replace("\r", "").split("\n"):
        if line.strip() == "-----BEGIN CERTIFICATE-----":
            cur = [line]
        elif cur is not None:
            cur.append(line)
            if line.strip() == "-----END CERTIFICATE-----":
                blocks.append(("\n".join(cur) + "\n").encode("ascii", "replace"))
                cur = None
    return blocks


def describe(cert_pem: str) -> Dict[str, Any]:
    """What the page shows about a certificate: names, dates, issuer, fingerprint."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    blocks = _split_pem(cert_pem)
    if not blocks:
        raise TlsError("No certificate found: paste the PEM text that starts with -----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(blocks[0])
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n) for n in san.get_values_for_type(x509.DNSName)] + \
                [str(n) for n in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    der = cert.public_bytes(serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest().upper()
    return {"subject": cn[0].value if cn else cert.subject.rfc4514_string(),
            "issuer": issuer[0].value if issuer else cert.issuer.rfc4514_string(),
            "self_signed": cert.issuer == cert.subject,
            "names": names,
            "not_before": int(_utc(cert, "not_valid_before").timestamp()),
            "not_after": int(_utc(cert, "not_valid_after").timestamp()),
            "fingerprint": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
            "chain": len(blocks)}


# --- This machine's names ----------------------------------------------------

def _own_addresses() -> List[str]:
    """The addresses other machines reach this one on. The UDP connect sends nothing; it only
    asks the routing table which interface would be used."""
    found = set()
    for probe in ("10.255.255.255", "192.168.255.255", "172.31.255.255"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 1))
            found.add(s.getsockname()[0])
        except OSError:
            pass
        finally:
            s.close()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    return sorted(a for a in found if not ipaddress.ip_address(a).is_loopback and not a.startswith("0."))


def machine_names(extra: Optional[List[str]] = None) -> List[str]:
    """Names and addresses for the self-signed certificate, in a stable order."""
    host = socket.gethostname().lower()
    names = [host, f"{host}.lan", f"{host}.local", f"{host}.home", "localhost"]
    names += [n.strip().lower() for n in os.environ.get("MONITOR_HOSTNAMES", "").split(",") if n.strip()]
    names += list(extra or [])
    ips = _own_addresses() + ["127.0.0.1"]
    out: List[str] = []
    for n in names + ips:
        if n and n not in out:
            out.append(n)
    return out


def clean_names(text: str) -> List[str]:
    """Extra names typed by the administrator: host names or addresses, comma or space separated."""
    out: List[str] = []
    for raw in text.replace(",", " ").split():
        n = raw.strip().lower().rstrip(".")
        if not n:
            continue
        try:
            ipaddress.ip_address(n)
        except ValueError:
            labels = n.split(".")
            if len(n) > 253 or not all(l and len(l) <= 63 and all(c.isalnum() or c == "-" for c in l)
                                       and not l.startswith("-") and not l.endswith("-") for l in labels):
                raise TlsError(f"{raw} is not a host name or address")
        if n not in out:
            out.append(n)
    if len(out) > MAX_NAMES:
        raise TlsError(f"At most {MAX_NAMES} extra names")
    return out


# --- Making and checking -----------------------------------------------------

def make_self_signed(names: List[str], now: Optional[datetime.datetime] = None) -> Tuple[str, str]:
    """(certificate PEM, key PEM) for the given names, signed by its own key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    now = now or datetime.datetime.now(datetime.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    alt = []
    for n in names:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            alt.append(x509.DNSName(n))
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0][:64]),
                         x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Homelab Monitor (self-signed)")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=SELF_SIGNED_DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode("ascii")
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii"), key_pem


def check_pair(cert_pem: str, key_pem: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Checks an uploaded certificate and key; returns describe() of the certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    if not cert_pem.strip() or not key_pem.strip():
        raise TlsError("Paste both the certificate and its private key")
    if len(cert_pem) > MAX_PEM or len(key_pem) > MAX_PEM:
        raise TlsError("That is far larger than a certificate and key")
    if "ENCRYPTED" in key_pem:
        raise TlsError("The key has a passphrase. Remove it first: openssl pkey -in key.pem -out key-plain.pem")
    info = describe(cert_pem)
    try:
        key = serialization.load_pem_private_key(key_pem.encode("ascii", "replace"), password=None)
    except (ValueError, TypeError):
        raise TlsError("The private key could not be read: paste the PEM text that starts with -----BEGIN ... PRIVATE KEY-----")
    leaf = x509.load_pem_x509_certificate(_split_pem(cert_pem)[0])
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, pub) != leaf.public_key().public_bytes(serialization.Encoding.DER, pub):
        raise TlsError("This key does not belong to the certificate (put the server certificate first, then any intermediates)")
    now = now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
    if info["not_after"] <= now:
        raise TlsError("This certificate has expired")
    build_context(cert_pem, key_pem)
    return info


def build_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """A server context for the pair. ssl only loads from files, so the pair is written to a
    private temporary folder (in memory where the system has one) and removed straight after."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        folder = tempfile.mkdtemp(prefix="hm-tls-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
    except OSError:
        folder = tempfile.mkdtemp(prefix="hm-tls-")
    paths = [os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")]
    try:
        for path, text in zip(paths, (cert_pem, key_pem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii", errors="replace") as f:
                f.write(text)
        ctx.load_cert_chain(paths[0], paths[1])
    except ssl.SSLError as exc:
        raise TlsError(f"The certificate and key could not be loaded: {exc.reason or exc}")
    finally:
        for path in paths:
            try:
                os.remove(path)
            except OSError:
                pass
        os.rmdir(folder)
    return ctx


# --- Stored state and the live context ---------------------------------------

class Server:
    """The context the listener uses; None while HTTPS is off. Swapped in place on a change,
    so switching needs no restart."""

    def __init__(self) -> None:
        self.context: Optional[ssl.SSLContext] = None
        self.lock = threading.Lock()

    def set(self, ctx: Optional[ssl.SSLContext]) -> None:
        with self.lock:
            self.context = ctx


SERVER = Server()


def _settings() -> Dict[str, str]:
    return database.get_all_settings()


def mode() -> str:
    m = _settings().get(MODE_KEY, "off")
    return m if m in MODES else "off"


def extra_names() -> List[str]:
    try:
        names = json.loads(_settings().get(NAMES_KEY) or "[]")
        return [str(n) for n in names][:MAX_NAMES]
    except ValueError:
        return []


def _store(new_mode: str, cert_pem: str, key_pem: str) -> None:
    database.set_internal_setting(CERT_KEY, cert_pem)
    from vault import VAULT
    database.set_internal_setting(KEY_KEY, VAULT.encrypt(key_pem, f"setting:{KEY_KEY}"))
    database.set_internal_setting(MODE_KEY, new_mode)
    database.set_internal_setting(WARNED_KEY, "")


def _self_signed_current(s: Dict[str, str], names: List[str], now: float) -> bool:
    """True when the stored self-signed certificate still covers these names and is not near expiry."""
    try:
        info = describe(s.get(CERT_KEY) or "")
    except Exception:
        return False
    return info["self_signed"] and set(names) <= set(info["names"]) and info["not_after"] - now > RENEW_DAYS * 86400


def ensure_self_signed(force: bool = False) -> bool:
    """Makes (or remakes) the self-signed certificate when needed. True when a new one was made."""
    s = _settings()
    names = machine_names(extra_names())
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    if not force and s.get(KEY_KEY) and _self_signed_current(s, names, now):
        return False
    cert, key = make_self_signed(names)
    _store("self-signed", cert, key)
    database.add_audit("system", "Made a new self-signed HTTPS certificate", ", ".join(names))
    return True


def load() -> None:
    """Called at start: applies the stored mode, making a self-signed certificate when one is due."""
    s = _settings()
    m = mode()
    if m == "self-signed":
        try:
            ensure_self_signed()
        except Exception:
            log.exception("Could not make a self-signed certificate; serving plain HTTP")
            SERVER.set(None)
            return
        s = _settings()
    if m == "off" or not s.get(CERT_KEY) or not s.get(KEY_KEY):
        SERVER.set(None)
        return
    try:
        SERVER.set(build_context(s[CERT_KEY], s[KEY_KEY]))
    except TlsError as exc:
        # A stored pair that no longer loads (it should not happen): plain HTTP rather than no access at all.
        log.error("HTTPS certificate could not be loaded (%s); serving plain HTTP", exc)
        database.add_event(None, "warning", "system", f"HTTPS is off: the stored certificate could not be loaded ({exc})")
        SERVER.set(None)


def first_run(existing: Dict[str, str], has_accounts: bool) -> None:
    """Decides the mode the first time this build starts on a database. An install from before
    HTTPS keeps plain HTTP and asks; a fresh one follows MONITOR_TLS_DEFAULT."""
    if MODE_KEY in existing:
        return
    if has_accounts:
        database.set_internal_setting(MODE_KEY, "off")
        database.set_internal_setting(PROMPT_KEY, "pending")
        return
    default = os.environ.get("MONITOR_TLS_DEFAULT", "off")
    database.set_internal_setting(MODE_KEY, default if default in ("off", "self-signed") else "off")


def set_off() -> None:
    database.set_internal_setting(MODE_KEY, "off")
    database.set_internal_setting(PROMPT_KEY, "")
    SERVER.set(None)


def set_self_signed(names: List[str]) -> None:
    # A new certificate only when the names changed (or the stored one is not a current self-signed
    # one, see ensure_self_signed): switching back, or re-saving, keeps the one already trusted.
    changed = set(names) != set(extra_names())
    database.set_internal_setting(NAMES_KEY, json.dumps(names))
    ensure_self_signed(force=changed)
    database.set_internal_setting(PROMPT_KEY, "")
    load()


def set_own(cert_pem: str, key_pem: str) -> Dict[str, Any]:
    info = check_pair(cert_pem, key_pem)
    _store("own", cert_pem.strip() + "\n", key_pem.strip() + "\n")
    database.set_internal_setting(PROMPT_KEY, "")
    load()
    return info


def dismiss_prompt() -> None:
    database.set_internal_setting(PROMPT_KEY, "")


def public_state() -> Dict[str, Any]:
    """For the settings page: never the key."""
    s = _settings()
    m = mode()
    out: Dict[str, Any] = {"mode": m, "active": SERVER.context is not None, "prompt": s.get(PROMPT_KEY) == "pending",
                           "extra_names": extra_names(), "machine_names": machine_names(),
                           "certificate": None}
    if m != "off" and s.get(CERT_KEY):
        try:
            out["certificate"] = describe(s[CERT_KEY])
        except Exception:
            out["certificate"] = None
    return out


def certificate_pem() -> str:
    """The public certificate, for downloading and trusting it on a computer or phone."""
    return _settings().get(CERT_KEY, "") if mode() != "off" else ""


def daily_check(notify, now: Optional[float] = None) -> Optional[str]:
    """Renews a self-signed certificate that is due; warns about an own one that expires soon.
    notify(days, date) sends the message. Returns what was done, for the tests."""
    m = mode()
    now = now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
    if m == "self-signed":
        if ensure_self_signed():
            load()
            return "renewed"
        return None
    if m != "own":
        return None
    s = _settings()
    try:
        info = describe(s.get(CERT_KEY) or "")
    except Exception:
        return None
    days = int((info["not_after"] - now) // 86400)
    if days > WARN_DAYS:
        return None
    date = datetime.datetime.fromtimestamp(info["not_after"], datetime.timezone.utc).strftime("%Y-%m-%d")
    today = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y-%m-%d")
    # Once a week until the last week, then every day.
    warned = (s.get(WARNED_KEY) or "").split("|")
    if len(warned) == 2 and warned[0] == date:
        last = datetime.datetime.strptime(warned[1], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc).timestamp()
        if now - last < (86400 if days <= 7 else 7 * 86400) - 3600:
            return None
    database.set_internal_setting(WARNED_KEY, f"{date}|{today}")
    text = (f"The HTTPS certificate expires on {date} ({max(days, 0)} days). Upload a new one in Settings, HTTPS."
            if days >= 0 else f"The HTTPS certificate expired on {date}. Upload a new one in Settings, HTTPS.")
    database.add_event(None, "warning" if days > 7 else "high", "system", text)
    notify(max(days, 0), date)
    return "warned"
