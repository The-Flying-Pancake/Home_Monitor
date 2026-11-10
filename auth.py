"""Web UI authentication: password hashing, sessions and login rate limiting.

Local user accounts (roles in rbac.py). Passwords are hashed with scrypt
(hashlib, standard library) using a per-account salt; the parameters are
stored in the hash string so they can be raised later without breaking
existing accounts. Sessions live in memory only: a restart logs everyone
out, and nothing that grants access is ever written to disk. The browser
holds a random token in an HttpOnly, SameSite=Strict cookie; the server
keeps only its SHA-256.
"""

import base64
import hashlib
import hmac
import secrets
import threading
import time
from typing import Any, Callable, Dict, Optional

# OWASP minimum for scrypt (128 MiB, about 0.3 s per check). Tests lower N.
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

SESSION_COOKIE = "hm_session"
SESSION_IDLE_SECONDS = 12 * 3600
SESSION_MAX_SECONDS = 7 * 86400
# Step-up tiers (rbac.TIER_ROUTES): tier 2 = password, tier 3 = password and authenticator code
# (password alone while the user has no 2FA). A confirmation lasts this long; logging in counts
# as one (with the code when 2FA is on).
TIER2_SECONDS = 600
TIER3_SECONDS = 900
CHALLENGE_SECONDS = 300             # between the password and the authenticator code at login
RECOVERY_CODE_SECONDS = 600         # Telegram code for a forgotten password

FAIL_WINDOW_SECONDS = 900
FAIL_FREE_ATTEMPTS = 5
LOCK_BASE_SECONDS = 30
LOCK_MAX_SECONDS = 900
MAX_TRACKED = 10000                 # clients and usernames the limiter remembers at most

# Each scrypt check takes about 128 MiB: at most this many run at once, so parallel logins cannot
# exhaust memory. A check that waits longer than HASH_WAIT_SECONDS for a slot gives up (Busy).
HASH_SLOTS = threading.BoundedSemaphore(2)
HASH_WAIT_SECONDS = 5.0


class Busy(Exception):
    """Every password hashing slot is taken; the request should be answered with 503."""


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    if not HASH_SLOTS.acquire(timeout=HASH_WAIT_SECONDS):
        raise Busy("Busy, try again in a moment")
    try:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=dklen)
    finally:
        HASH_SLOTS.release()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = _scrypt(password, base64.b64decode(salt), int(n), int(r), int(p), len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def password_problem(password: str) -> Optional[str]:
    """Reason a new password is rejected, or None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters"
    if len(set(password)) < 4:
        return "Password is too repetitive"
    return None


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionStore:
    """In-memory sessions keyed by the SHA-256 of the cookie token."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def create(self, username: str, tier3: bool = True) -> str:
        """A new session. tier3: the login itself satisfied tier 3 (code given, or no 2FA set up)."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self._expire(now)
            self.sessions[_token_id(token)] = {"username": username, "created": now, "last": now,
                                               "tier2_until": now + TIER2_SECONDS,
                                               "tier3_until": now + TIER3_SECONDS if tier3 else 0}
        return token

    def get(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        now = time.time()
        with self.lock:
            s = self.sessions.get(_token_id(token))
            if not s:
                return None
            if now - s["last"] > SESSION_IDLE_SECONDS or now - s["created"] > SESSION_MAX_SECONDS:
                del self.sessions[_token_id(token)]
                return None
            s["last"] = now
            return dict(s)

    def confirm(self, token: str, tier: int) -> None:
        """Records a step-up: tier 2 (password) or tier 3 (password and code), which also covers tier 2."""
        now = time.time()
        with self.lock:
            s = self.sessions.get(_token_id(token))
            if s:
                s["tier2_until"] = now + TIER2_SECONDS
                if tier >= 3:
                    s["tier3_until"] = now + TIER3_SECONDS

    def put(self, token: Optional[str], key: str, value: Any) -> None:
        """Server-side scratch value on a session (2FA enrolment in progress); never sent to the browser."""
        with self.lock:
            s = self.sessions.get(_token_id(token)) if token else None
            if s is not None:
                s[key] = value

    def take(self, token: Optional[str], key: str) -> Any:
        with self.lock:
            s = self.sessions.get(_token_id(token)) if token else None
            return s.get(key) if s else None

    def allow(self, token: Optional[str], key: str, limit: int, window: float) -> bool:
        """A per-session rate limit in a fixed window: True while fewer than limit calls were made
        in the current window of window seconds. A missing session is never allowed."""
        now = time.time()
        with self.lock:
            s = self.sessions.get(_token_id(token)) if token else None
            if s is None:
                return False
            start, count = s.get(key) or (0.0, 0)
            if now - start >= window:
                start, count = now, 0
            if count >= limit:
                return False
            s[key] = (start, count + 1)
            return True

    def revoke(self, token: Optional[str]) -> None:
        if token:
            with self.lock:
                self.sessions.pop(_token_id(token), None)

    def revoke_all(self, except_token: Optional[str] = None) -> None:
        keep = _token_id(except_token) if except_token else None
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if k == keep}

    def revoke_user(self, username: str, except_token: Optional[str] = None) -> int:
        """Ends every session of one user (blocked, deleted, logged out, or their own password change)."""
        keep = _token_id(except_token) if except_token else None
        with self.lock:
            gone = [k for k, s in self.sessions.items() if s["username"] == username and k != keep]
            for k in gone:
                del self.sessions[k]
            return len(gone)

    def by_user(self) -> Dict[str, Dict[str, Any]]:
        """Open session count and last activity per username."""
        now = time.time()
        out: Dict[str, Dict[str, Any]] = {}
        with self.lock:
            self._expire(now)
            for s in self.sessions.values():
                u = out.setdefault(s["username"], {"sessions": 0, "last_active": 0})
                u["sessions"] += 1
                u["last_active"] = max(u["last_active"], int(s["last"]))
        return out

    def _expire(self, now: float) -> None:
        for k in [k for k, s in self.sessions.items()
                  if now - s["last"] > SESSION_IDLE_SECONDS or now - s["created"] > SESSION_MAX_SECONDS]:
            del self.sessions[k]


class Challenges:
    """Short-lived, single-purpose tokens kept in memory: the step between password and
    authenticator code at login, and the Telegram code of a password recovery."""

    def __init__(self, one_per_user: bool = False) -> None:
        self.lock = threading.Lock()
        self.items: Dict[str, Dict[str, Any]] = {}
        # One live token per user: a new one voids the earlier ones (the login step).
        self.one_per_user = one_per_user

    def issue(self, username: str, ttl: float, secret: Optional[str] = None) -> str:
        """Returns the token. With secret, the token is only an id and the secret (hashed) must be shown later."""
        token = secrets.token_urlsafe(24)
        with self.lock:
            now = time.time()
            self.items = {k: v for k, v in self.items.items()
                          if v["expires"] > now and not (self.one_per_user and v["username"] == username)}
            self.items[_token_id(token)] = {"username": username, "expires": now + ttl, "attempts": 0,
                                            "secret": _token_id(secret) if secret else None}
        return token

    def check(self, token: str, secret: Optional[str] = None, max_attempts: int = 5) -> Optional[str]:
        """The username when the token (and secret, if one was issued) is valid; consumes it on success.
        Each failed secret counts; after max_attempts the token is void."""
        with self.lock:
            key = _token_id(token or "")
            item = self.items.get(key)
            if not item or item["expires"] < time.time():
                self.items.pop(key, None)
                return None
            if item["secret"] is not None:
                if not secret or not hmac.compare_digest(item["secret"], _token_id(secret)):
                    item["attempts"] += 1
                    if item["attempts"] >= max_attempts:
                        del self.items[key]
                    return None
            del self.items[key]
            return item["username"]

    def peek(self, token: str) -> Optional[str]:
        """The username of a live token without consuming it (the code step of a login)."""
        with self.lock:
            item = self.items.get(_token_id(token or ""))
            return item["username"] if item and item["expires"] > time.time() else None

    def fail(self, token: str, max_attempts: int = 5) -> None:
        with self.lock:
            key = _token_id(token or "")
            item = self.items.get(key)
            if item:
                item["attempts"] += 1
                if item["attempts"] >= max_attempts:
                    del self.items[key]

    def drop(self, token: str) -> None:
        with self.lock:
            self.items.pop(_token_id(token or ""), None)


class LoginLimiter:
    """Failed password and code tracking per client address and per username, so neither many
    addresses against one account nor one address against many accounts escapes it. After
    FAIL_FREE_ATTEMPTS failures in the window, each further failure doubles a lockout, capped at
    LOCK_MAX_SECONDS. Entries older than the window are pruned, and at most MAX_TRACKED are kept."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: Dict[str, list] = {}
        # Called as on_lockout(client, username, keys) when a key has just been locked out, after the
        # lock is released (server.py: the audit row and the security alert).
        self.on_lockout: Optional[Callable[[str, Optional[str], list], None]] = None

    def _locked_out(self, client: str, username: Optional[str], started: list) -> None:
        if started and self.on_lockout is not None:
            try:
                self.on_lockout(client, username, started)
            except Exception:
                pass

    @staticmethod
    def _keys(client: str, username: Optional[str]) -> list:
        return [client] + (["user:" + username.lower()] if username else [])

    def _wait(self, key: str, now: float) -> float:
        recent = [t for t in self.failures.get(key, []) if now - t < FAIL_WINDOW_SECONDS]
        if recent:
            self.failures[key] = recent
        else:
            self.failures.pop(key, None)
        over = len(recent) - FAIL_FREE_ATTEMPTS
        if over < 0:
            return 0.0
        wait = min(LOCK_MAX_SECONDS, LOCK_BASE_SECONDS * 2 ** over)
        return max(0.0, recent[-1] + wait - now)

    def locked_for(self, client: str, username: Optional[str] = None) -> float:
        now = time.time()
        with self.lock:
            return max(self._wait(k, now) for k in self._keys(client, username))

    def failed(self, client: str, username: Optional[str] = None) -> None:
        now = time.time()
        with self.lock:
            started = self._record(client, username, now)
        self._locked_out(client, username, started)

    def reserve(self, client: str, username: Optional[str] = None) -> float:
        """Pay first: checks the lockout and counts one failure in the same locked step, so parallel
        requests cannot each take a free guess. Returns the wait (nothing recorded) while locked out,
        otherwise 0. A right answer then clears the counters (succeeded) or takes the charge back (refund)."""
        now = time.time()
        with self.lock:
            wait = max(self._wait(k, now) for k in self._keys(client, username))
            if wait > 0:
                return wait
            started = self._record(client, username, now)
        self._locked_out(client, username, started)
        return 0.0

    def refund(self, client: str, username: Optional[str] = None) -> None:
        """Takes back one failure counted by reserve."""
        with self.lock:
            for k in self._keys(client, username):
                ts = self.failures.get(k)
                if ts:
                    ts.pop()
                if not ts:
                    self.failures.pop(k, None)

    def _record(self, client: str, username: Optional[str], now: float) -> list:
        """Counts one failure; returns the keys that have just reached the lockout (exactly
        FAIL_FREE_ATTEMPTS recent failures), so a lockout is reported once when it starts."""
        started = []
        for k in self._keys(client, username):
            # The newest attempts are all a lockout needs; older ones only use memory.
            self.failures[k] = (self.failures.get(k, []) + [now])[-(FAIL_FREE_ATTEMPTS + 20):]
            if sum(1 for t in self.failures[k] if now - t < FAIL_WINDOW_SECONDS) == FAIL_FREE_ATTEMPTS:
                started.append(k)
        self._prune(now)
        return started

    def succeeded(self, client: str, username: Optional[str] = None) -> None:
        with self.lock:
            for k in self._keys(client, username):
                self.failures.pop(k, None)

    def _prune(self, now: float) -> None:
        for k in [k for k, ts in self.failures.items() if not ts or now - ts[-1] >= FAIL_WINDOW_SECONDS]:
            del self.failures[k]
        if len(self.failures) > MAX_TRACKED:
            for k in sorted(self.failures, key=lambda k: self.failures[k][-1])[:len(self.failures) - MAX_TRACKED]:
                del self.failures[k]


SESSIONS = SessionStore()
LIMITER = LoginLimiter()
LOGIN_CHALLENGES = Challenges(one_per_user=True)
RECOVERY_CHALLENGES = Challenges()
