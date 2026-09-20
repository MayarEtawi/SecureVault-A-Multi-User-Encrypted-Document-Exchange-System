# crypto/ecc.py

from __future__ import annotations


# ============================================================
# P-256 Curve Parameters
# ============================================================

# P-256 works over the finite field GF(p).
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

# Curve equation:
#
#     y² = x³ + ax + b (mod p)
#
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# Standard P-256 generator coordinates.
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296

Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

# Generator point.
G = (Gx, Gy)

# Order of the generator point G.
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


# A normal point is represented by a tuple (x, y).
# None represents the point at infinity.
Point = tuple[int, int] | None


# ============================================================
# Modular Arithmetic
# ============================================================

def modular_inverse(value: int, modulus: int = p) -> int:
    """
    Calculate the multiplicative inverse of value modulo modulus.

    The result satisfies:

        value * inverse = 1 (mod modulus)

    The modulus is p by default because elliptic-curve point arithmetic
    is normally performed inside the finite field GF(p).
    """
    value %= modulus

    if value == 0:
        raise ZeroDivisionError("zero has no modular inverse")

    # p and n are prime, so Fermat's little theorem can be used:
    #
    #     value^(-1) = value^(modulus - 2) mod modulus
    return pow(value, modulus - 2, modulus)


# ============================================================
# Point Validation
# ============================================================

def is_on_curve(point: Point) -> bool:
    """
    Return True if point satisfies the P-256 curve equation.

    None represents the point at infinity, which is part of the
    elliptic-curve group.
    """
    if point is None:
        return True

    if not isinstance(point, tuple) or len(point) != 2:
        return False

    x, y = point

    # bool is a subclass of int in Python, so reject it explicitly.
    if (
        not isinstance(x, int)
        or isinstance(x, bool)
        or not isinstance(y, int)
        or isinstance(y, bool)
    ):
        return False

    if not (0 <= x < p and 0 <= y < p):
        return False

    left_side = (y * y) % p
    right_side = (pow(x, 3, p) + a * x + b) % p

    return left_side == right_side


# ============================================================
# Point Addition
# ============================================================

def point_add(point1: Point, point2: Point) -> Point:
    """
    Add two points on the P-256 elliptic curve.

    None represents the point at infinity and acts as the identity:

        P + infinity = P
        infinity + P = P
    """
    if point1 is None:
        return point2

    if point2 is None:
        return point1

    if not is_on_curve(point1) or not is_on_curve(point2):
        raise ValueError("cannot add a point that is not on the curve")

    x1, y1 = point1
    x2, y2 = point2

    # If the points have the same x-coordinate but opposite
    # y-coordinates, their sum is the point at infinity.
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if point1 == point2:
        # Point doubling:
        #
        #     slope = (3*x1² + a) / (2*y1) mod p
        #
        if y1 == 0:
            return None

        numerator = (3 * x1 * x1 + a) % p
        denominator = modular_inverse(2 * y1, p)
        slope = (numerator * denominator) % p

    else:
        # Addition of two different points:
        #
        #     slope = (y2 - y1) / (x2 - x1) mod p
        #
        numerator = (y2 - y1) % p
        denominator = modular_inverse(x2 - x1, p)
        slope = (numerator * denominator) % p

    # Calculate the result point.
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p

    result = (x3, y3)

    # This defensive check helps detect implementation mistakes.
    if not is_on_curve(result):
        raise ValueError("point addition produced an invalid point")

    return result


# ============================================================
# Scalar Multiplication
# ============================================================

def scalar_multiply(scalar: int, point: Point) -> Point:
    """
    Calculate scalar * point using the double-and-add algorithm.

    For example, a public key is calculated as:

        Q = dG

    where d is the private key and G is the P-256 generator.
    """
    if not isinstance(scalar, int) or isinstance(scalar, bool):
        raise TypeError("scalar must be an integer")

    if scalar < 0:
        raise ValueError("scalar must not be negative")

    if not is_on_curve(point):
        raise ValueError("point is not on the P-256 curve")

    # Multiplying by zero or multiplying the point at infinity
    # produces the point at infinity.
    if scalar == 0 or point is None:
        return None

    result = None
    current_point = point
    remaining_scalar = scalar

    # Double-and-add processes the scalar one binary bit at a time.
    while remaining_scalar > 0:
        # If the current bit is 1, add the current point to the result.
        if remaining_scalar & 1:
            result = point_add(result, current_point)

        # Double the point for the next scalar bit.
        current_point = point_add(current_point, current_point)

        # Move to the next bit.
        remaining_scalar >>= 1

    if not is_on_curve(result):
        raise ValueError("scalar multiplication produced an invalid point")

    return result