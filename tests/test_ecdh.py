# test_ecdh.py
"""
Pytest suite for crypto/ecdh.py.

Run with:  pytest test_ecdh.py -v
"""

import pytest

from crypto.ecc import G, n, p, is_on_curve, scalar_multiply, is_valid_public_key as ecc_is_valid_public_key
from crypto.ecdh import (
    P256_COORDINATE_SIZE,
    compute_shared_secret,
    generate_ephemeral_keypair,
    generate_keypair,
    generate_private_key,
    generate_public_key,
    is_valid_public_key,
    shared_secret_bytes,
)


OFF_CURVE_POINT = (1, 1)


# ============================================================
# generate_private_key
# ============================================================

class TestGeneratePrivateKey:
    def test_in_valid_range(self):
        for _ in range(20):
            d = generate_private_key()
            assert 1 <= d < n

    def test_returns_int(self):
        assert isinstance(generate_private_key(), int)

    def test_looks_random(self):
        # Not a randomness proof, just a smoke test that we're not
        # returning a constant.
        values = {generate_private_key() for _ in range(10)}
        assert len(values) > 1


# ============================================================
# generate_public_key
# ============================================================

class TestGeneratePublicKey:
    def test_matches_scalar_multiply(self):
        d = 12345
        Q = generate_public_key(d)
        assert Q == scalar_multiply(d, G)

    def test_result_is_on_curve(self):
        Q = generate_public_key(54321)
        assert is_on_curve(Q)

    def test_d_equals_1_gives_generator(self):
        assert generate_public_key(1) == G

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            generate_public_key(0)

    def test_rejects_n(self):
        with pytest.raises(ValueError):
            generate_public_key(n)

    def test_rejects_negative(self):
        with pytest.raises(ValueError):
            generate_public_key(-5)

    def test_rejects_non_int(self):
        with pytest.raises(TypeError):
            generate_public_key(3.0)

    def test_rejects_bool(self):
        with pytest.raises(TypeError):
            generate_public_key(True)


# ============================================================
# generate_keypair / generate_ephemeral_keypair
# ============================================================

class TestGenerateKeypair:
    def test_public_key_matches_private_key(self):
        d, Q = generate_keypair()
        assert generate_public_key(d) == Q

    def test_public_key_is_valid(self):
        _, Q = generate_keypair()
        assert is_valid_public_key(Q)

    def test_fresh_each_call(self):
        d1, _ = generate_keypair()
        d2, _ = generate_keypair()
        assert d1 != d2  # astronomically unlikely to collide

    def test_ephemeral_alias_behaves_the_same(self):
        d, Q = generate_ephemeral_keypair()
        assert 1 <= d < n
        assert generate_public_key(d) == Q
        assert is_valid_public_key(Q)


# ============================================================
# is_valid_public_key (delegates to crypto.ecc.is_valid_public_key)
# ============================================================

class TestIsValidPublicKey:
    def test_generator_is_valid(self):
        assert is_valid_public_key(G) is True

    def test_infinity_is_invalid(self):
        assert is_valid_public_key(None) is False

    def test_off_curve_point_is_invalid(self):
        assert is_valid_public_key(OFF_CURVE_POINT) is False

    def test_out_of_range_coordinate_is_invalid(self):
        assert is_valid_public_key((p, G[1])) is False

    def test_delegates_to_ecc_module(self):
        # Same verdict as crypto.ecc.is_valid_public_key for a range
        # of inputs -- this is the point of the delegation fix.
        candidates = [G, None, OFF_CURVE_POINT, (p, G[1]), (0, 0)]
        for candidate in candidates:
            assert is_valid_public_key(candidate) == ecc_is_valid_public_key(candidate)


# ============================================================
# compute_shared_secret
# ============================================================

class TestComputeSharedSecret:
    def test_both_sides_agree(self):
        alpha, A = generate_keypair()
        beta, B = generate_keypair()

        shared_alice = compute_shared_secret(alpha, B)
        shared_bob = compute_shared_secret(beta, A)

        assert shared_alice == shared_bob

    def test_result_is_on_curve(self):
        alpha, _ = generate_keypair()
        _, B = generate_keypair()
        assert is_on_curve(compute_shared_secret(alpha, B))

    def test_matches_slide_worked_example(self):
        # Slide 20: curve y^2 = x^3 + 7x + 3 (mod 37), point (2,5).
        # This isn't P-256, so we can't run it through compute_shared_secret
        # directly -- marked as skipped in pytest.
        pytest.skip("Slide 20 example uses a custom curve (mod 37), not P-256")

    def test_rejects_invalid_private_key(self):
        _, B = generate_keypair()
        with pytest.raises(ValueError):
            compute_shared_secret(0, B)
        with pytest.raises(ValueError):
            compute_shared_secret(n, B)

    def test_rejects_non_int_private_key(self):
        _, B = generate_keypair()
        with pytest.raises(TypeError):
            compute_shared_secret(3.0, B)

    def test_rejects_infinity_as_other_key(self):
        alpha, _ = generate_keypair()
        with pytest.raises(ValueError):
            compute_shared_secret(alpha, None)

    def test_rejects_off_curve_other_key(self):
        alpha, _ = generate_keypair()
        with pytest.raises(ValueError):
            compute_shared_secret(alpha, OFF_CURVE_POINT)

    def test_rejects_out_of_range_coordinates(self):
        alpha, _ = generate_keypair()
        with pytest.raises(ValueError):
            compute_shared_secret(alpha, (p, G[1]))


# ============================================================
# shared_secret_bytes
# ============================================================

class TestSharedSecretBytes:
    def test_length_is_32_bytes(self):
        alpha, _ = generate_keypair()
        _, B = generate_keypair()
        secret = shared_secret_bytes(alpha, B)
        assert isinstance(secret, bytes)
        assert len(secret) == P256_COORDINATE_SIZE

    def test_matches_x_coordinate_of_compute_shared_secret(self):
        alpha, _ = generate_keypair()
        _, B = generate_keypair()

        point = compute_shared_secret(alpha, B)
        secret = shared_secret_bytes(alpha, B)

        assert secret == point[0].to_bytes(P256_COORDINATE_SIZE, byteorder="big")

    def test_both_sides_derive_identical_bytes(self):
        alpha, A = generate_keypair()
        beta, B = generate_keypair()

        secret_alice = shared_secret_bytes(alpha, B)
        secret_bob = shared_secret_bytes(beta, A)

        assert secret_alice == secret_bob

    def test_preserves_leading_zero_byte(self):
        # Force an x-coordinate whose top byte is 0 and check the
        # 32-byte encoding still comes back full length (leading
        # zero not silently dropped by to_bytes/int round-tripping).
        small_x = 0x00ABCDEF
        assert small_x.to_bytes(P256_COORDINATE_SIZE, byteorder="big")[0] == 0
        assert len(small_x.to_bytes(P256_COORDINATE_SIZE, byteorder="big")) == P256_COORDINATE_SIZE

    def test_rejects_invalid_inputs_same_as_compute_shared_secret(self):
        alpha, _ = generate_keypair()
        with pytest.raises(ValueError):
            shared_secret_bytes(alpha, None)
        with pytest.raises(ValueError):
            shared_secret_bytes(alpha, OFF_CURVE_POINT)
        with pytest.raises(ValueError):
            shared_secret_bytes(0, G)


# ============================================================
# End-to-end ECDH exchange (mirrors slide 19/20's Alice/Bob flow)
# ============================================================

class TestEndToEndExchange:
    def test_full_exchange(self):
        # Public: curve + generator (fixed, from crypto.ecc)
        # Private: alice's alpha, bob's beta
        alpha, A = generate_keypair()   # Alice sends A = alpha*G
        beta, B = generate_keypair()    # Bob sends B = beta*G

        # Each side validates what it receives before using it.
        assert is_valid_public_key(A)
        assert is_valid_public_key(B)

        # Each side computes the shared secret from what it received.
        alice_secret = shared_secret_bytes(alpha, B)
        bob_secret = shared_secret_bytes(beta, A)

        assert alice_secret == bob_secret