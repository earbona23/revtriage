"""Ed25519 signature verification on the standard library alone (RFC 8032).

Why implement a curve by hand instead of importing one? Because of what this tool is
for. revtriage is pointed at hostile files by definition, and its headline property is
that it has *zero* third-party runtime dependencies — the whole supply chain is this one
project. A licence check must not be the thing that breaks that promise by pulling in
`cryptography` or `pynacl`. So the verifier is ~120 lines of `int` arithmetic over the
Edwards-25519 group, using only `hashlib.sha512` from the stdlib.

This is the classic reference implementation (djb / RFC 8032 appendix), unrolled into
extended homogeneous coordinates so scalar multiplication is a double-and-add rather than
an inversion per point. It is not constant-time, and it does not need to be: it verifies
public licence tokens, a value already sitting in plaintext on disk. There is no secret
here to leak through timing. The *signing* key never ships — it lives in `.secrets/`,
which `.gitignore` excludes, and is used only by `scripts/mint_license.py`.
"""

from __future__ import annotations

import hashlib

# Curve constants for Edwards-25519 (RFC 8032, section 5.1).
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_D2 = (2 * _D) % _P
# Square root of -1 mod p, used to recover x from y.
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int | None:
    """Solve the curve equation for x given y and the desired low bit (`sign`)."""
    if y >= _P:
        return None
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if (x * x - xx) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Base point B in extended coordinates (X, Y, Z, T) with Z = 1, T = X*Y.
_BY = (4 * _inv(5)) % _P
_BX = _recover_x(_BY, 0)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)
# Neutral element (identity) of the group.
_IDENTITY = (0, 1, 1, 0)


def _point_add(p: tuple, q: tuple) -> tuple:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * _D2 * t2 % _P
    dd = z1 * 2 * z2 % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(point: tuple, scalar: int) -> tuple:
    result = _IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_equal(p: tuple, q: tuple) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % _P != 0:
        return False
    return (y1 * z2 - y2 * z1) % _P == 0


def _encode_point(point: tuple) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x = (x * zi) % _P
    y = (y * zi) % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(encoded: bytes) -> tuple | None:
    value = int.from_bytes(encoded, "little")
    sign = (value >> 255) & 1
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def _clamp(digest: bytes) -> int:
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar


# -- public API ----------------------------------------------------------------------


def public_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte Ed25519 seed."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is exactly 32 bytes")
    a = _clamp(hashlib.sha512(seed).digest())
    return _encode_point(_scalar_mult(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature. Used only by the offline minting script."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    prefix = h[32:]
    public = _encode_point(_scalar_mult(_B, a))
    r = _sha512_int(prefix + message) % _L
    big_r = _encode_point(_scalar_mult(_B, r))
    k = _sha512_int(big_r + public + message) % _L
    s = (r + k * a) % _L
    return big_r + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on any malformed input rather than
    raising, so a corrupt or hostile licence file can never crash the check — it just
    fails to validate, which is the safe direction."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    big_r = _decode_point(signature[:32])
    point_a = _decode_point(public_key)
    if big_r is None or point_a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _sha512_int(signature[:32] + public_key + message) % _L
    left = _scalar_mult(_B, s)
    right = _point_add(big_r, _scalar_mult(point_a, k))
    return _point_equal(left, right)


# The public half of the revtriage licensing key. The signing seed that matches this is
# generated once into .secrets/ (never committed) and used only by scripts/mint_license.py.
# Anyone can verify a licence with the key below; only the holder of the seed can issue one.
LICENSE_PUBLIC_KEY_HEX = "48338d38656f14693ef055807e2c6e1325e4f84c74e8af18307123c5a163deb2"


def license_public_key() -> bytes:
    return bytes.fromhex(LICENSE_PUBLIC_KEY_HEX)
