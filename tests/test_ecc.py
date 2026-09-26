# test_ecc.py
"""
Pytest suite for crypto/ecc.py.

Run with:  pytest test_ecc.py -v
"""

import pytest

from crypto.ecc import (
    G,
    a,
    b,
    n,
    p,
    is_on_curve,
    is_valid_private_key,
    is_valid_public_key,
    mod_inverse,
    point_add,
    scalar_multiply,
)


# A point NOT on the curve, used across several tests.
OFF_CURVE_POINT = (1, 1)

# Known low-order test vector: y^2 = x^3 + 2x + 3 (mod 5), from the
# slides -- not P-256, only used to sanity-check point_add's algebra
# against a hand-worked example.
SMALL_P = 5
SMALL_A = 2
SMALL_B = 3


def small_curve_add(P1, P2):
    """Same formulas as point_add, but over the tiny mod-5 curve, for
    cross-checking against the hand-worked slide example."""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % SMALL_P == 0:
        return None
    if P1 == P2:
        m = ((3 * x1 * x1 + SMALL_A) * pow(2 * y1, SMALL_P - 2, SMALL_P)) % SMALL_P
    else:
        m = ((y2 - y1) * pow(x2 - x1, SMALL_P - 2, SMALL_P)) % SMALL_P
    x3 = (m * m - x1 - x2) % SMALL_P
    y3 = (m * (x1 - x3) - y1) % SMALL_P
    return (x3, y3)


# ============================================================
# mod_inverse
# ============================================================

class TestModInverse:
    def test_inverse_round_trips(self):
        value = 12345
        inv = mod_inverse(value)
        assert (value * inv) % p == 1

    def test_inverse_of_one_is_one(self):
        assert mod_inverse(1) == 1

    def test_zero_raises(self):
        with pytest.raises(ZeroDivisionError):
            mod_inverse(0)

    def test_multiple_of_modulus_raises(self):
        with pytest.raises(ZeroDivisionError):
            mod_inverse(p)

    def test_custom_modulus(self):
        # 3 * 4 = 12 = 1 (mod 11)
        assert mod_inverse(3, 11) == 4


# ============================================================
# is_on_curve
# ============================================================

class TestIsOnCurve:
    def test_infinity_is_valid(self):
        assert is_on_curve(None) is True

    def test_generator_is_valid(self):
        assert is_on_curve(G) is True

    def test_off_curve_point_is_invalid(self):
        assert is_on_curve(OFF_CURVE_POINT) is False

    def test_rejects_wrong_length_tuple(self):
        assert is_on_curve((1, 2, 3)) is False

    def test_rejects_non_tuple(self):
        assert is_on_curve([G[0], G[1]]) is False
        assert is_on_curve("not a point") is False

    def test_rejects_bool_coordinates(self):
        assert is_on_curve((True, False)) is False

    def test_rejects_negative_coordinate(self):
        assert is_on_curve((-1, G[1])) is False

    def test_rejects_coordinate_out_of_range(self):
        assert is_on_curve((p, G[1])) is False
        assert is_on_curve((G[0], p)) is False


# ============================================================
# is_valid_public_key
# ============================================================

class TestIsValidPublicKey:
    def test_generator_is_valid(self):
        assert is_valid_public_key(G) is True

    def test_infinity_is_invalid(self):
        assert is_valid_public_key(None) is False

    def test_off_curve_point_is_invalid(self):
        assert is_valid_public_key(OFF_CURVE_POINT) is False

    def test_2g_is_valid(self):
        assert is_valid_public_key(scalar_multiply(2, G)) is True


# ============================================================
# is_valid_private_key
# ============================================================

class TestIsValidPrivateKey:
    def test_in_range_is_valid(self):
        assert is_valid_private_key(1) is True
        assert is_valid_private_key(n - 1) is True
        assert is_valid_private_key(12345) is True

    def test_zero_is_invalid(self):
        assert is_valid_private_key(0) is False

    def test_n_is_invalid(self):
        assert is_valid_private_key(n) is False

    def test_negative_is_invalid(self):
        assert is_valid_private_key(-1) is False

    def test_non_int_is_invalid(self):
        assert is_valid_private_key(3.0) is False
        assert is_valid_private_key("5") is False

    def test_bool_is_invalid(self):
        assert is_valid_private_key(True) is False


# ============================================================
# point_add
# ============================================================

class TestPointAdd:
    def test_identity_left(self):
        assert point_add(None, G) == G

    def test_identity_right(self):
        assert point_add(G, None) == G

    def test_infinity_plus_infinity(self):
        assert point_add(None, None) is None

    def test_point_plus_its_negative_is_infinity(self):
        neg_g = (G[0], (-G[1]) % p)
        assert point_add(G, neg_g) is None

    def test_doubling_matches_add_self(self):
        assert point_add(G, G) == scalar_multiply(2, G)

    def test_result_is_on_curve(self):
        result = point_add(G, scalar_multiply(2, G))
        assert is_on_curve(result)

    def test_addition_is_commutative(self):
        p2 = scalar_multiply(2, G)
        p3 = scalar_multiply(3, G)
        assert point_add(p2, p3) == point_add(p3, p2)

    def test_rejects_off_curve_input(self):
        with pytest.raises(ValueError):
            point_add(OFF_CURVE_POINT, G)

    def test_against_hand_worked_slide_example(self):
        # From the slides: on y^2 = x^3 + 2x + 3 (mod 5),
        # (1,4) + (3,1) = (2,0)
        assert small_curve_add((1, 4), (3, 1)) == (2, 0)


# ============================================================
# scalar_multiply
# ============================================================

class TestScalarMultiply:
    def test_zero_times_point_is_infinity(self):
        assert scalar_multiply(0, G) is None

    def test_one_times_point_is_itself(self):
        assert scalar_multiply(1, G) == G

    def test_two_times_point_matches_doubling(self):
        assert scalar_multiply(2, G) == point_add(G, G)

    def test_three_times_point_matches_repeated_add(self):
        p2 = scalar_multiply(2, G)
        assert scalar_multiply(3, G) == point_add(p2, G)

    def test_n_times_generator_is_infinity(self):
        # Fundamental P-256 property: the generator has order n.
        assert scalar_multiply(n, G) is None

    def test_n_plus_one_times_generator_wraps_to_generator(self):
        assert scalar_multiply(n + 1, G) == G

    def test_scalar_multiply_by_zero_point_is_infinity(self):
        assert scalar_multiply(5, None) is None

    def test_negative_scalar(self):
        neg_g = (G[0], (-G[1]) % p)
        assert scalar_multiply(-1, G) == neg_g

    def test_multiple_of_order_is_infinity(self):
        assert scalar_multiply(2 * n, G) is None

    def test_result_is_always_on_curve(self):
        for k in (2, 3, 5, 17, 1000):
            assert is_on_curve(scalar_multiply(k, G))

    def test_rejects_non_int_scalar(self):
        with pytest.raises(TypeError):
            scalar_multiply(2.0, G)

    def test_rejects_bool_scalar(self):
        with pytest.raises(TypeError):
            scalar_multiply(True, G)

    def test_rejects_off_curve_point(self):
        with pytest.raises(ValueError):
            scalar_multiply(2, OFF_CURVE_POINT)


# ============================================================
# ECDH sanity check (both sides derive the same shared point)
# ============================================================

class TestEcdhSharedSecret:
    def test_shared_secret_matches(self):
        alpha = 12345         # Alice's private scalar
        beta = 67890          # Bob's private scalar

        A = scalar_multiply(alpha, G)   # Alice's public key
        B = scalar_multiply(beta, G)    # Bob's public key

        assert is_valid_public_key(A)
        assert is_valid_public_key(B)

        shared_alice = scalar_multiply(alpha, B)
        shared_bob = scalar_multiply(beta, A)

        assert shared_alice == shared_bob
        assert is_on_curve(shared_alice)
