# crypto/ecdsa.py

import hashlib
import secrets

from crypto.ecc import G, n, Point, is_on_curve, point_add, scalar_multiply


# ============================================================
# Key Generation
#
# NOTE: This is a SEPARATE keypair from the one used for ECDH in
# crypto/ecdh.py. Even though both live on P-256 and both are just
# (private int, public point) pairs, a signing key and a key-agreement
# key must never be the same key material -- generate a fresh keypair
# here for ECDSA use only.
# ============================================================

def generate_private_key() -> int:
    """
    Securely generate a random ECDSA private key d satisfying 1 <= d < n.
    """
    d = 0
    while d == 0:
        d = secrets.randbelow(n)
    return d


def generate_public_key(d: int) -> Point:
    """
    Generate the ECDSA public key Q = dG corresponding to private key d.
    """
    if not (1 <= d < n):
        raise ValueError("private key d must satisfy 1 <= d < n")

    return scalar_multiply(d, G)


def generate_keypair() -> tuple[int, Point]:
    """
    Convenience helper: generate a fresh (private_key, public_key) pair.
    """
    d = generate_private_key()
    Q = generate_public_key(d)
    return d, Q


# ============================================================
# Internal helpers
# ============================================================

def _mod_inverse_n(value: int) -> int:
    """
    Multiplicative inverse of value modulo n (the group order).

    n is prime for P-256, so Fermat's little theorem applies, same as
    the mod-p inverse in ecc.py -- but this one must be taken mod n,
    since ECDSA's r, s, and nonce arithmetic all live in Z_n, not Z_p.
    """
    value = value % n
    if value == 0:
        raise ZeroDivisionError("cannot invert 0 mod n")
    return pow(value, n - 2, n)


def _hash_to_int(message: bytes) -> int:
    """
    Hash message with SHA-256 and convert the digest to an integer,
    truncated to the bit length of n as specified by FIPS 186-4 (for
    P-256 the SHA-256 digest is the same bit length as n, so this is a
    no-op truncation here, but it's included for correctness/generality).
    """
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, byteorder="big")

    z_bits = z.bit_length()
    n_bits = n.bit_length()
    if z_bits > n_bits:
        z >>= (z_bits - n_bits)

    return z


def _generate_nonce() -> int:
    """
    Securely generate a fresh per-signature nonce k satisfying 1 <= k < n.
    """
    k = 0
    while k == 0:
        k = secrets.randbelow(n)
    return k


def _as_bytes(message: bytes | str) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be bytes or str")
# ============================================================
# Signing
# ============================================================

def sign(message: bytes | str, private_key: int) -> tuple[int, int]:
    """
    Produce an ECDSA signature (r, s) for message using private_key.

    A fresh secure nonce k is generated for every signature. If either
    r or s comes out to 0 (which would leak or weaken the key), a new
    nonce is drawn and signing is retried.
    """
    if not (1 <= private_key < n):
        raise ValueError("private key must satisfy 1 <= d < n")

    message_bytes = _as_bytes(message)
    z = _hash_to_int(message_bytes)

    while True:
        k = _generate_nonce()

        R = scalar_multiply(k, G)
        if R is None:
            continue

        r = R[0] % n
        if r == 0:
            continue

        k_inv = _mod_inverse_n(k)
        s = (k_inv * (z + r * private_key)) % n
        if s == 0:
            continue

        return (r, s)


# ============================================================
# Verification
# ============================================================

def verify(message: bytes | str, signature: tuple[int, int], public_key: Point) -> bool:
    """
    Verify an ECDSA signature (r, s) over message against public_key.

    Returns True only if the public key is valid, r and s are both in
    the valid range [1, n), and the standard ECDSA verification
    equation holds.
    """
    # Validate the public key first.
    if not is_valid_public_key(public_key):
        return False

    if signature is None:
        return False

    try:
        r, s = signature
    except (TypeError, ValueError):
        return False

    if not (isinstance(r, int) and isinstance(s, int)):
        return False

    if not (1 <= r < n and 1 <= s < n):
        return False

    message_bytes = _as_bytes(message)
    z = _hash_to_int(message_bytes)

    w = _mod_inverse_n(s)
    u1 = (z * w) % n
    u2 = (r * w) % n

    P = point_add(scalar_multiply(u1, G), scalar_multiply(u2, public_key))

    if P is None:
        return False

    return (P[0] % n) == r


# ============================================================
# Public key validation
#
# Reuses the same on-curve / range / non-infinity checks used for ECDH
# public keys, since the underlying validity requirements for any
# P-256 point are identical regardless of whether it's used for
# signing or key agreement.
# ============================================================

def is_valid_public_key(Q: Point) -> bool:
    from crypto.ecc import p

    if not isinstance(Q, tuple) or len(Q) != 2:
        return False

    x, y = Q

    if not (isinstance(x, int) and isinstance(y, int)):
        return False

    if not (0 <= x < p and 0 <= y < p):
        return False

    if not is_on_curve(Q):
        return False

    return True
