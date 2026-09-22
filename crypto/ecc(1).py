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


def is_valid_public_key(point: Point) -> bool:
    """
    Return True if point is a valid P-256 public key.

    A public key must:
        - Be a valid point on the curve.
        - Not be the point at infinity.
        - Belong to the correct subgroup.
    """
    # The point at infinity must not be accepted as a public key.
    if point is None:
        return False

    # The public key must satisfy the P-256 curve equation.
    if not is_on_curve(point):
        return False

    # P-256 has a cofactor of 1, so every valid curve point
    # belongs to the correct subgroup.
    #
    # This multiplication also confirms that the point has
    # the expected group order.
    return scalar_multiply(n, point) is None


def is_valid_private_key(private_key: int) -> bool:
    """
    Return True if private_key is a valid P-256 private key.

    A private key must satisfy:

        1 <= private_key < n
    """
    if not isinstance(private_key, int) or isinstance(private_key, bool):
        return False

    return 1 <= private_key < n


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
    # Validate both points before performing any operation.
    if not is_on_curve(point1) or not is_on_curve(point2):
        raise ValueError("cannot add a point that is not on the curve")

    if point1 is None:
        return point2

    if point2 is None:
        return point1

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
# Scalar Multiplication (Montgomery ladder)
# ============================================================
#
# WHY THIS SHAPE, IN PLAIN WORDS:
#
# The simplest way to compute scalar * point is "double-and-add":
# walk over each bit of the scalar, always double, and only add
# the point when the bit is 1. The problem is that this makes the
# number of point_add() calls depend on how many 1-bits the scalar
# (our private key) has. Someone who can measure how long the
# operation takes, even roughly, can use that to guess the private
# key bit by bit. This is called a timing attack.
#
# The Montgomery ladder fixes this by doing the *same* two point
# operations on *every* bit, whether the bit is 0 or 1. Only which
# of two running values gets updated changes -- not how much work
# is done. So the running time no longer depends on the bits of
# the private key.
#
# The two running values are:
#   R0 -> currently holds (bits processed so far) * point
#   R1 -> currently holds (bits processed so far + 1) * point
#
# At every step we do exactly one point_add (to move R0 and R1
# closer together or further apart) and one doubling. Which
# variable ends up holding which result depends on the bit, but
# the *amount* of work is identical either way.

def scalar_multiply(scalar: int, point: Point) -> Point:
    """
    Calculate scalar * point using a Montgomery-ladder-style
    double-and-add, so every bit of scalar costs the same amount
    of work. This avoids leaking the scalar (e.g. a private key)
    through timing.
    """
    if not isinstance(scalar, int) or isinstance(scalar, bool):
        raise TypeError("scalar must be an integer")

    if scalar < 0:
        raise ValueError("scalar must not be negative")

    if not is_on_curve(point):
        raise ValueError("point is not on the P-256 curve")

    if scalar == 0 or point is None:
        return None

    r0 = None    # 0 * point so far
    r1 = point   # 1 * point so far

    # Walk the bits from the most significant to the least
    # significant. Every single bit -- 0 or 1 -- costs exactly
    # one point_add and one doubling, in a fixed order.
    for i in range(scalar.bit_length() - 1, -1, -1):
        bit = (scalar >> i) & 1

        if bit == 0:
            r1 = point_add(r0, r1)
            r0 = point_add(r0, r0)
        else:
            r0 = point_add(r0, r1)
            r1 = point_add(r1, r1)

    if not is_on_curve(r0):
        raise ValueError("scalar multiplication produced an invalid point")

    return r0
