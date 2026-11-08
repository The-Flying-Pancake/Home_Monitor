"""Two-factor authentication: TOTP codes (RFC 6238), recovery codes and a QR code for enrolment.

TOTP: HMAC-SHA1, 30 second steps, 6 digits, one step of clock drift accepted either way.
That is what every authenticator app (Google, Microsoft, Aegis, 1Password, Bitwarden) uses
by default. The shared secret is 20 random bytes, shown as base32 and inside an otpauth://
URI in the QR code. The caller stores it encrypted with the vault.

The QR encoder writes byte mode at error correction level M, versions 1 to 10 (up to 213
bytes: an otpauth URI is about 120), as SVG, so enrolment needs no image library and no
request leaves the monitor.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

STEP = 30
DIGITS = 6
DRIFT = 1               # steps accepted either side of now
ISSUER = "Homelab Monitor"
RECOVERY_COUNT = 8


# --- TOTP ---

def new_secret() -> str:
    """A base32 secret (no padding), as authenticator apps expect it."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def code_at(secret_b32: str, when: Optional[float] = None) -> str:
    return hotp(secret_b32, int((time.time() if when is None else when) // STEP))


def verify(secret_b32: str, code: str, when: Optional[float] = None, last_step: Optional[int] = None) -> Optional[int]:
    """The time step the code matches (within DRIFT), or None. A step at or before last_step is
    refused, so a code seen once (shoulder surfing, a proxy log) cannot be replayed."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != DIGITS or not secret_b32:
        return None
    now = int((time.time() if when is None else when) // STEP)
    for step in range(now - DRIFT, now + DRIFT + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(hotp(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, account: str, issuer: str = ISSUER) -> str:
    label = quote(f"{issuer}:{account}", safe=":@")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


# --- Recovery codes ---

def new_recovery_codes(n: int = RECOVERY_COUNT) -> List[str]:
    """Codes like 7KQ2-M9XD: no 0/O or 1/I, so they survive being read off paper."""
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    out = []
    for _ in range(n):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        out.append(f"{raw[:4]}-{raw[4:]}")
    return out


def normalise_recovery(code: str) -> str:
    return "".join(ch for ch in str(code).upper() if ch.isalnum())


def hash_recovery(code: str) -> str:
    # 40 bits of entropy per code and a single use each: a salted SHA-256 is enough here.
    salt = secrets.token_hex(8)
    return f"{salt}${hashlib.sha256((salt + normalise_recovery(code)).encode()).hexdigest()}"


def match_recovery(code: str, hashes: List[str]) -> Optional[int]:
    """Index of the stored hash this code matches, or None."""
    norm = normalise_recovery(code)
    if len(norm) != 8:
        return None
    for i, h in enumerate(hashes):
        try:
            salt, digest = h.split("$", 1)
        except ValueError:
            continue
        if hmac.compare_digest(hashlib.sha256((salt + norm).encode()).hexdigest(), digest):
            return i
    return None


# --- QR code (byte mode, level M) ---

# version: (data codewords per block for each block in order, EC codewords per block)
_BLOCKS_M = {
    1: ([16], 10), 2: ([28], 16), 3: ([44], 26), 4: ([32] * 2, 18), 5: ([43] * 2, 24),
    6: ([27] * 4, 16), 7: ([31] * 4, 18), 8: ([38] * 2 + [39] * 2, 22), 9: ([36] * 3 + [37] * 2, 22),
    10: ([43] * 4 + [44], 26),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38],
          8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}

# GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1.
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def rs_encode(data: List[int], n_ec: int) -> List[int]:
    """Reed-Solomon error correction codewords for one block."""
    gen = [1]
    for i in range(n_ec):
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= _gf_mul(c, _EXP[i])
        gen = nxt
    rem = list(data) + [0] * n_ec
    for i in range(len(data)):
        factor = rem[i]
        if factor:
            for j in range(1, len(gen)):
                rem[i + j] ^= _gf_mul(gen[j], factor)
    return rem[len(data):]


def _bch(value: int, poly: int, poly_bits: int) -> int:
    v = value << (poly_bits - 1)
    for shift in range(v.bit_length() - poly_bits, -1, -1):
        if v & (1 << (shift + poly_bits - 1)):
            v ^= poly << shift
    return v


def format_bits(mask: int) -> int:
    """15-bit format information for level M (indicator 00) and the mask."""
    data = (0b00 << 3) | mask
    return ((data << 10) | _bch(data, 0b10100110111, 11)) ^ 0b101010000010010


def version_bits(version: int) -> int:
    return (version << 12) | _bch(version, 0b1111100100101, 13)


def _codewords(payload: bytes, version: int) -> List[int]:
    blocks, n_ec = _BLOCKS_M[version]
    capacity = sum(blocks)
    bits: List[int] = []

    def put(value: int, length: int) -> None:
        bits.extend((value >> (length - 1 - i)) & 1 for i in range(length))

    put(0b0100, 4)                                    # byte mode
    put(len(payload), 8 if version < 10 else 16)
    for b in payload:
        put(b, 8)
    put(0, min(4, capacity * 8 - len(bits)))          # terminator
    while len(bits) % 8:
        bits.append(0)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad, i = [0xEC, 0x11], 0
    while len(data) < capacity:
        data.append(pad[i % 2])
        i += 1
    split, ecs, pos = [], [], 0
    for size in blocks:
        split.append(data[pos:pos + size])
        ecs.append(rs_encode(data[pos:pos + size], n_ec))
        pos += size
    out = [blk[i] for i in range(max(blocks)) for blk in split if i < len(blk)]
    out += [blk[i] for i in range(n_ec) for blk in ecs]
    return out


def _capacity(version: int) -> int:
    header = 4 + (8 if version < 10 else 16)
    return (sum(_BLOCKS_M[version][0]) * 8 - header) // 8


def qr_matrix(text: str) -> List[List[int]]:
    """The QR symbol as rows of 0 / 1 (1 = dark), quiet zone not included."""
    payload = text.encode("utf-8")
    version = next((v for v in range(1, 11) if _capacity(v) >= len(payload)), None)
    if version is None:
        raise ValueError("Text too long for a QR code up to version 10")
    size = 17 + 4 * version
    grid: List[List[Optional[int]]] = [[None] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def setm(r: int, c: int, v: int) -> None:
        grid[r][c] = v
        reserved[r][c] = True

    def finder(r0: int, c0: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if 0 <= rr < size and 0 <= cc < size:
                    dark = 0 <= r <= 6 and 0 <= c <= 6 and (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                    setm(rr, cc, 1 if dark else 0)

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    for i in range(8, size - 8):
        setm(6, i, 1 if i % 2 == 0 else 0)
        setm(i, 6, 1 if i % 2 == 0 else 0)
    centres = _ALIGN[version]
    for r in centres:
        for c in centres:
            if _on_finder(r, c, centres):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    setm(r + dr, c + dc, 1 if max(abs(dr), abs(dc)) != 1 else 0)
    setm(size - 8, 8, 1)                               # dark module
    # Reserve the format areas (filled once the mask is chosen).
    for i in range(9):
        if not reserved[8][i]:
            reserved[8][i] = True
        if not reserved[i][8]:
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True
    if version >= 7:
        vb = version_bits(version)
        for i in range(18):
            bit = (vb >> i) & 1
            r, c = i // 3, i % 3 + size - 11
            setm(r, c, bit)
            setm(c, r, bit)

    # Data placement: two-column zigzag from the bottom right, skipping the timing column.
    words = _codewords(payload, version)
    bits = [(w >> (7 - i)) & 1 for w in words for i in range(8)]
    idx = 0
    col = size - 1
    upward = True
    data_cells = []
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for r in rows:
            for c in (col, col - 1):
                if not reserved[r][c]:
                    data_cells.append((r, c))
                    grid[r][c] = bits[idx] if idx < len(bits) else 0
                    idx += 1
        upward = not upward
        col -= 2

    masks = [
        lambda r, c: (r + c) % 2 == 0,
        lambda r, c: r % 2 == 0,
        lambda r, c: c % 3 == 0,
        lambda r, c: (r + c) % 3 == 0,
        lambda r, c: (r // 2 + c // 3) % 2 == 0,
        lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
        lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
        lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
    ]

    def build(mask: int) -> List[List[int]]:
        m = [[(grid[r][c] or 0) for c in range(size)] for r in range(size)]
        for r, c in data_cells:
            if masks[mask](r, c):
                m[r][c] ^= 1
        fb = format_bits(mask)
        bitsf = [(fb >> (14 - i)) & 1 for i in range(15)]
        # Around the top-left finder.
        coords_a = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8), (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
        # Split between bottom-left and top-right.
        coords_b = [(size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8), (size - 5, 8), (size - 6, 8), (size - 7, 8),
                    (8, size - 8), (8, size - 7), (8, size - 6), (8, size - 5), (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1)]
        for b, (r, c) in zip(bitsf, coords_a):
            m[r][c] = b
        for b, (r, c) in zip(bitsf, coords_b):
            m[r][c] = b
        m[size - 8][8] = 1
        return m

    best, best_score = None, None
    for mask in range(8):
        m = build(mask)
        score = _penalty(m)
        if best_score is None or score < best_score:
            best, best_score = m, score
    return best


def _penalty(m: List[List[int]]) -> int:
    """ISO 18004 mask evaluation (rules 1 to 4)."""
    n = len(m)
    score = 0
    for lines in (m, [list(col) for col in zip(*m)]):
        for row in lines:
            run, prev = 0, None
            for v in row:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += run - 2
                    run, prev = 1, v
            if run >= 5:
                score += run - 2
            s = "".join(map(str, row))
            score += 40 * (s.count("10111010000") + s.count("00001011101"))
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    dark = sum(map(sum, m))
    score += abs(dark * 20 - n * n * 10) // (n * n) * 10
    return score


def qr_svg(text: str, module: int = 6, quiet: int = 4) -> str:
    """The QR code as a standalone SVG (black on white whatever the page theme: scanners need contrast)."""
    m = qr_matrix(text)
    n = len(m)
    dim = (n + 2 * quiet) * module
    path = []
    for r, row in enumerate(m):
        c = 0
        while c < n:
            if row[c]:
                start = c
                while c < n and row[c]:
                    c += 1
                path.append(f"M{(start + quiet) * module},{(r + quiet) * module}h{(c - start) * module}v{module}h{-(c - start) * module}z")
            else:
                c += 1
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" width="{dim}" height="{dim}" '
            f'shape-rendering="crispEdges"><rect width="{dim}" height="{dim}" fill="#ffffff"/>'
            f'<path fill="#000000" d="{"".join(path)}"/></svg>')


def decode_matrix(m: List[List[int]]) -> Tuple[int, str]:
    """Reads a symbol made by qr_matrix back (mask from the format bits, byte segment).
    Used by the tests as an independent path through the placement and masking rules."""
    n = len(m)
    version = (n - 17) // 4
    bits_a = [m[r][c] for r, c in [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8), (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]]
    fb = int("".join(map(str, bits_a)), 2)
    mask = next(k for k in range(8) if format_bits(k) == fb)
    reserved = _reserved_map(version)
    masks = [
        lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0,
        lambda r, c: (r + c) % 3 == 0, lambda r, c: (r // 2 + c // 3) % 2 == 0,
        lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
        lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
    ]
    bits = []
    col, upward = n - 1, True
    while col > 0:
        if col == 6:
            col -= 1
        for r in (range(n - 1, -1, -1) if upward else range(n)):
            for c in (col, col - 1):
                if not reserved[r][c]:
                    bits.append(m[r][c] ^ (1 if masks[mask](r, c) else 0))
        upward = not upward
        col -= 2
    blocks, n_ec = _BLOCKS_M[version]
    total = sum(blocks)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, (total + n_ec * len(blocks)) * 8, 8)]
    # De-interleave the data codewords.
    data_blocks = [[] for _ in blocks]
    k = 0
    for i in range(max(blocks)):
        for b, size in enumerate(blocks):
            if i < size:
                data_blocks[b].append(words[k])
                k += 1
    data = [w for blk in data_blocks for w in blk]
    stream = "".join(f"{w:08b}" for w in data)
    assert stream[:4] == "0100", "not byte mode"
    count_len = 8 if version < 10 else 16
    length = int(stream[4:4 + count_len], 2)
    body = stream[4 + count_len:4 + count_len + 8 * length]
    return mask, bytes(int(body[i:i + 8], 2) for i in range(0, len(body), 8)).decode("utf-8")


def _on_finder(r: int, c: int, centres: List[int]) -> bool:
    """Alignment centres that would sit on a finder pattern (three corners) are left out."""
    first, last = centres[0], centres[-1]
    return (r, c) in ((first, first), (first, last), (last, first))


def _reserved_map(version: int) -> List[List[bool]]:
    size = 17 + 4 * version
    res = [[False] * size for _ in range(size)]
    for r0, c0 in ((0, 0), (0, size - 7), (size - 7, 0)):
        for r in range(-1, 8):
            for c in range(-1, 8):
                if 0 <= r0 + r < size and 0 <= c0 + c < size:
                    res[r0 + r][c0 + c] = True
    for i in range(size):
        res[6][i] = res[i][6] = True
    for r in _ALIGN[version]:
        for c in _ALIGN[version]:
            if _on_finder(r, c, _ALIGN[version]):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    res[r + dr][c + dc] = True
    for i in range(9):
        res[8][i] = res[i][8] = True
    for i in range(8):
        res[8][size - 1 - i] = res[size - 1 - i][8] = True
    if version >= 7:
        for i in range(18):
            r, c = i // 3, i % 3 + size - 11
            res[r][c] = res[c][r] = True
    return res
