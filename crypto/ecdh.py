# crypto/ecdh.py

import secrets

from crypto.ecc import G, n, p, Point, is_on_curve, scalar_multiply


# P-256 coordinates contain 256 bits, which equals 32 bytes.
P256_COORDINATE_SIZE = 32


# ============================================================
# Key Generation
# ============================================================

def generate_private_key() -> int:
    """
    Securely generate a random private key d satisfying 1 <= d < n.
    """
    # secrets.randbelow(n) returns a value in [0, n-1].
    # Loop to exclude 0 because a private key of 0 is invalid.
    # The probability of obtaining 0 is extremely small.
    d = 0
    while d == 0:
        d = secrets.randbelow(n)

    return d


def generate_public_key(d: int) -> Point:
    """
    Generate the public key Q = dG corresponding to private key d.
    """
    if not isinstance(d, int) or isinstance(d, bool):
        raise TypeError("private key d must be an integer")

    if not (1 <= d < n):
        raise ValueError("private key d must satisfy 1 <= d < n")

    public_key = scalar_multiply(d, G)

    # A valid private key multiplied by the P-256 generator should
    # never produce the point at infinity.
    if public_key is None:
        raise ValueError("public-key generation resulted in point at infinity")

    return public_key


def generate_keypair() -> tuple[int, Point]:
    """
    Generate and return a fresh ECDH private-key and public-key pair.

    This key pair must be used only for ECDH. A separate key pair
    must be generated for ECDSA signatures.
    """
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)

    return private_key, public_key


# ============================================================
# Validation
# ============================================================

def is_valid_public_key(Q: Point) -> bool:
    """
    Validate another party's public key before using it in ECDH.

    Checks:
        - Q has the expected tuple format
        - Q is not None (not the point at infinity)
        - Q contains exactly two coordinates
        - Q's coordinates are integers
        - Q's coordinates are in the valid field range [0, p)
        - Q lies on the P-256 curve
    """
    # None represents the point at infinity in ecc.py.
    if Q is None:
        return False

    # Reject strings, lists, tuples of the wrong size, and other
    # malformed values before trying to unpack the coordinates.
    if not isinstance(Q, tuple) or len(Q) != 2:
        return False

    x, y = Q

    # bool is a subclass of int in Python, so reject it explicitly.
    if (
        not isinstance(x, int)
        or isinstance(x, bool)
        or not isinstance(y, int)
        or isinstance(y, bool)
    ):
        return False

    # Coordinates must be elements of the finite field GF(p).
    if not (0 <= x < p and 0 <= y < p):
        return False

    # The point must satisfy the P-256 curve equation.
    if not is_on_curve(Q):
        return False

    return True


# ============================================================
# Shared Secret Computation
# ============================================================

def compute_shared_secret(d: int, Q_other: Point) -> Point:
    """
    Compute the ECDH shared point S = d * Q_other.

    The other party's public key is validated before it is used.

    This function returns the complete shared point (Sx, Sy).
    Protocol code should normally use shared_secret_bytes() instead,
    because HKDF requires a byte string rather than a Python tuple.
    """
    if not isinstance(d, int) or isinstance(d, bool):
        raise TypeError("private key d must be an integer")

    if not (1 <= d < n):
        raise ValueError("private key d must satisfy 1 <= d < n")

    if not is_valid_public_key(Q_other):
        raise ValueError(
            "invalid public key: expected a non-infinity P-256 point "
            "with integer coordinates in range"
        )

    shared_point = scalar_multiply(d, Q_other)

    # A validated P-256 public key and a valid private key should not
    # produce the point at infinity, but check defensively anyway.
    if shared_point is None:
        raise ValueError(
            "shared secret computation resulted in point at infinity"
        )

    return shared_point


def shared_secret_bytes(d: int, Q_other: Point) -> bytes:
    """
    Compute an ECDH shared secret and encode it for use with HKDF.

    ECDH produces a shared elliptic-curve point S = (Sx, Sy). The
    x-coordinate Sx is encoded as exactly 32 bytes in big-endian order.

    The fixed length preserves leading zero bytes and gives both parties
    the same unambiguous input for HKDF.

    The returned bytes must not be used directly as an AES key.
    They must first be passed through HKDF-SHA-256 to derive a
    key-wrapping key.
    """
    shared_point = compute_shared_secret(d, Q_other)
    shared_x = shared_point[0]

    return shared_x.to_bytes(
        P256_COORDINATE_SIZE,
        byteorder="big"
    )