# crypto/ecc.py

# ============================================================
# NIST P-256 / secp256r1 Parameters
# ============================================================

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296

Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


# ============================================================
# Point Representation
# ============================================================
# AS definition 
# Normal point: (x, y)
# Point at infinity: None

Point = tuple[int, int] | None

G: Point = (Gx, Gy)


# ============================================================
# Basic Validation
# ============================================================

def is_on_curve(P: Point) -> bool:
    """
    Return True if P is a valid point on P-256.

    Remember:
        y^2 = x^3 + ax + b (mod p)

    Point at infinity (None) is considered valid.
    """

    if P is None:
        return True

    x, y = P

    left = (y * y) % p
    right = (x**3 + a * x + b) % p

    return left == right


def mod_inverse(value: int) -> int:
    """
    Return the multiplicative inverse of value modulo p.

    The result x must satisfy:

        value * x = 1 (mod p)
    """

    # p is prime, so Fermat's little theorem gives us the inverse directly:
    # value^(p-2) = value^-1 (mod p)
    value = value % p
    if value == 0:
        raise ZeroDivisionError("cannot invert 0 mod p")

    return pow(value, p - 2, p)


# ============================================================
# ECC Operations
# ============================================================

def point_add(P: Point, Q: Point) -> Point:
    """
    Add two elliptic-curve points.

    Must handle:
        P + O
        O + Q
        P + (-P)
        P + Q
        P + P (doubling)
    """

    # P + O = P, O + Q = Q
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = O   (same x, y values are negatives of each other mod p)
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if x1 == x2 and y1 == y2:
        # Point doubling
        if y1 == 0:
            return None
        m = ((3 * x1 * x1 + a) * mod_inverse(2 * y1)) % p
    else:
        # Standard point addition
        m = ((y2 - y1) * mod_inverse(x2 - x1)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def scalar_multiply(k: int, P: Point) -> Point:
    """
    Calculate kP using a double-and-add strategy.
    """

    if P is None or k % n == 0:
        return None

    if k < 0:
        # -k * P = k * (-P), where -P is (x, -y mod p)
        k = -k
        x, y = P
        P = (x, (-y) % p)

    result: Point = None
    addend: Point = P

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


# ============================================================
# Simple Correctness Checks
# ============================================================

if __name__ == "__main__":

    print("Testing P-256 parameters...")

    print("G is on curve:", is_on_curve(G))

    # Important P-256 property:
    # nG should equal the Point at Infinity.
    print("nG = infinity:", scalar_multiply(n, G) is None)

    # A few extra sanity checks
    P2 = scalar_multiply(2, G)
    print("2G is on curve:", is_on_curve(P2))
    print("2G == G + G:", P2 == point_add(G, G))

    P3 = scalar_multiply(3, G)
    print("3G == 2G + G:", P3 == point_add(P2, G))

    # (n+1)G should equal G again
    print("(n+1)G == G:", scalar_multiply(n + 1, G) == G)
