# test_keywrap.py
"""
Pytest suite for crypto/keywrap.py.

Run with:  pytest test_keywrap.py -v

NOTE: this file assumes the module lives at crypto/keywrap.py, and it
runs against stand-in implementations of crypto/gcm.py and
crypto/hkdf.py (real AES-128-GCM and real HKDF-SHA-256) written
because those two modules weren't provided. If the real project's
gcm.py/hkdf.py interfaces differ, or the real module path differs,
this file needs to be reconciled with them.
"""

import dataclasses

import pytest

from crypto.ecc import G, scalar_multiply
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.gcm import AuthenticationError
from crypto.key_wrap import (
    DOCUMENT_KEY_SIZE,
    WRAPPING_SALT_SIZE,
    WrappedDocumentKey,
    build_key_wrap_context,
    encode_public_key,
    unwrap_document_key,
    wrap_document_key,
)


OFF_CURVE_POINT = (1, 1)
KDOC = b"0123456789ABCDEF"  # 16 bytes

SENDER = "alice"
RECIPIENT = "bob"
DOC_ID = "doc-42"
VERSION = 3


def make_recipient_keypair():
    return generate_ecdh_keypair()


# ============================================================
# WrappedDocumentKey dataclass
# ============================================================

class TestWrappedDocumentKeyDataclass:
    def test_is_frozen(self):
        _, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            wrapped.salt = b"x" * WRAPPING_SALT_SIZE


# ============================================================
# encode_public_key
# ============================================================

class TestEncodePublicKey:
    def test_length_is_65_bytes(self):
        key = scalar_multiply(2, G)
        assert len(encode_public_key(key)) == 65

    def test_starts_with_0x04(self):
        key = scalar_multiply(2, G)
        assert encode_public_key(key)[0:1] == b"\x04"

    def test_rejects_infinity(self):
        with pytest.raises(ValueError):
            encode_public_key(None)

    def test_rejects_off_curve_point(self):
        with pytest.raises(ValueError):
            encode_public_key(OFF_CURVE_POINT)


# ============================================================
# build_key_wrap_context
# ============================================================

class TestBuildKeyWrapContext:
    def test_starts_with_prefix(self):
        eph_key = scalar_multiply(2, G)
        context = build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, eph_key)
        assert context.startswith(b"SecureVault-KeyWrap-Context-v1")

    def test_deterministic(self):
        eph_key = scalar_multiply(2, G)
        c1 = build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, eph_key)
        c2 = build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, eph_key)
        assert c1 == c2

    @pytest.mark.parametrize("field", ["sender_id", "recipient_id", "document_id"])
    def test_rejects_non_string_id(self, field):
        eph_key = scalar_multiply(2, G)
        kwargs = dict(
            sender_id=SENDER, recipient_id=RECIPIENT, document_id=DOC_ID,
        )
        kwargs[field] = 12345
        with pytest.raises(TypeError):
            build_key_wrap_context(
                kwargs["sender_id"], kwargs["recipient_id"], kwargs["document_id"],
                VERSION, eph_key,
            )

    @pytest.mark.parametrize("field", ["sender_id", "recipient_id", "document_id"])
    def test_rejects_empty_id(self, field):
        eph_key = scalar_multiply(2, G)
        kwargs = dict(
            sender_id=SENDER, recipient_id=RECIPIENT, document_id=DOC_ID,
        )
        kwargs[field] = ""
        with pytest.raises(ValueError):
            build_key_wrap_context(
                kwargs["sender_id"], kwargs["recipient_id"], kwargs["document_id"],
                VERSION, eph_key,
            )

    def test_rejects_non_int_version(self):
        eph_key = scalar_multiply(2, G)
        with pytest.raises(TypeError):
            build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, 3.5, eph_key)

    def test_rejects_bool_version(self):
        eph_key = scalar_multiply(2, G)
        with pytest.raises(TypeError):
            build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, True, eph_key)

    def test_rejects_version_zero(self):
        eph_key = scalar_multiply(2, G)
        with pytest.raises(ValueError):
            build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, 0, eph_key)

    def test_rejects_version_at_or_above_2_64(self):
        eph_key = scalar_multiply(2, G)
        with pytest.raises(ValueError):
            build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, 2**64, eph_key)

    def test_rejects_invalid_ephemeral_key(self):
        with pytest.raises(ValueError):
            build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, OFF_CURVE_POINT)

    @pytest.mark.parametrize(
        "override",
        [
            {"sender_id": "mallory"},
            {"recipient_id": "mallory"},
            {"document_id": "doc-99"},
            {"version": VERSION + 1},
        ],
    )
    def test_changing_a_field_changes_the_context(self, override):
        eph_key = scalar_multiply(2, G)
        base = build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, eph_key)
        kwargs = dict(
            sender_id=SENDER, recipient_id=RECIPIENT, document_id=DOC_ID,
            version=VERSION,
        )
        kwargs.update(override)
        changed = build_key_wrap_context(
            kwargs["sender_id"], kwargs["recipient_id"], kwargs["document_id"],
            kwargs["version"], eph_key,
        )
        assert base != changed

    def test_changing_ephemeral_key_changes_the_context(self):
        key1 = scalar_multiply(2, G)
        key2 = scalar_multiply(5, G)
        c1 = build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, key1)
        c2 = build_key_wrap_context(SENDER, RECIPIENT, DOC_ID, VERSION, key2)
        assert c1 != c2

    def test_length_prefixes_prevent_ambiguity(self):
        eph_key = scalar_multiply(2, G)
        c1 = build_key_wrap_context("ab", "cd", DOC_ID, VERSION, eph_key)
        c2 = build_key_wrap_context("a", "bcd", DOC_ID, VERSION, eph_key)
        assert c1 != c2


# ============================================================
# wrap_document_key
# ============================================================

class TestWrapDocumentKey:
    def test_returns_wrapped_document_key(self):
        _, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        assert isinstance(wrapped, WrappedDocumentKey)

    def test_ephemeral_public_key_is_valid_and_distinct_from_recipient(self):
        _, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        from crypto.ecc import is_valid_public_key
        assert is_valid_public_key(wrapped.ephemeral_public_key)
        assert wrapped.ephemeral_public_key != recipient_pub

    def test_salt_and_nonce_have_expected_sizes(self):
        _, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        assert len(wrapped.salt) == WRAPPING_SALT_SIZE
        assert len(wrapped.nonce) == 12  # standard GCM nonce size
        assert len(wrapped.tag) == 16    # standard GCM tag size

    def test_fresh_ephemeral_key_and_salt_each_call(self):
        _, recipient_pub = make_recipient_keypair()
        w1 = wrap_document_key(KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION)
        w2 = wrap_document_key(KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION)
        assert w1.ephemeral_public_key != w2.ephemeral_public_key
        assert w1.salt != w2.salt
        assert w1.encrypted_key != w2.encrypted_key

    def test_rejects_non_bytes_document_key(self):
        _, recipient_pub = make_recipient_keypair()
        with pytest.raises(TypeError):
            wrap_document_key("not bytes", recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION)

    def test_rejects_wrong_length_document_key(self):
        _, recipient_pub = make_recipient_keypair()
        with pytest.raises(ValueError):
            wrap_document_key(b"short", recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION)

    def test_rejects_invalid_recipient_public_key(self):
        with pytest.raises(ValueError):
            wrap_document_key(KDOC, OFF_CURVE_POINT, SENDER, RECIPIENT, DOC_ID, VERSION)
        with pytest.raises(ValueError):
            wrap_document_key(KDOC, None, SENDER, RECIPIENT, DOC_ID, VERSION)

    def test_rejects_invalid_context_fields(self):
        _, recipient_pub = make_recipient_keypair()
        with pytest.raises(ValueError):
            wrap_document_key(KDOC, recipient_pub, "", RECIPIENT, DOC_ID, VERSION)
        with pytest.raises(ValueError):
            wrap_document_key(KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, 0)


# ============================================================
# wrap_document_key + unwrap_document_key -- round trip
# ============================================================

class TestRoundTrip:
    def test_recipient_recovers_original_key(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        recovered = unwrap_document_key(
            wrapped, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        assert recovered == KDOC

    def test_recovered_key_has_correct_length(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        recovered = unwrap_document_key(
            wrapped, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        assert len(recovered) == DOCUMENT_KEY_SIZE

    def test_different_wraps_of_same_key_both_recover_correctly(self):
        # Different ephemeral keys/salts/nonces each time, but each
        # independently unwraps to the same original Kdoc.
        recipient_priv, recipient_pub = make_recipient_keypair()
        w1 = wrap_document_key(KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION)
        w2 = wrap_document_key(KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION)
        assert unwrap_document_key(w1, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION) == KDOC
        assert unwrap_document_key(w2, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION) == KDOC


# ============================================================
# unwrap_document_key -- rejection cases
# ============================================================

class TestUnwrapRejections:
    def test_rejects_non_wrapped_key_type(self):
        recipient_priv, _ = make_recipient_keypair()
        with pytest.raises(TypeError):
            unwrap_document_key(
                "not a wrapped key", recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_wrong_recipient_private_key(self):
        # Wrapped for the real recipient, but a different party's
        # private key is used to unwrap: shared secret differs, so
        # the derived wrapping key differs, so GCM auth must fail.
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrong_priv, _ = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                wrapped, wrong_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    @pytest.mark.parametrize("field", ["sender_id", "recipient_id", "document_id"])
    def test_rejects_mismatched_context_string(self, field):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        kwargs = dict(sender_id=SENDER, recipient_id=RECIPIENT, document_id=DOC_ID)
        kwargs[field] = "someone-else"
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                wrapped, recipient_priv,
                kwargs["sender_id"], kwargs["recipient_id"], kwargs["document_id"],
                VERSION,
            )

    def test_rejects_mismatched_version(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                wrapped, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION + 1
            )

    def test_rejects_tampered_ciphertext(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        flipped_byte = bytes([wrapped.encrypted_key[0] ^ 0xFF]) + wrapped.encrypted_key[1:]
        tampered = dataclasses.replace(wrapped, encrypted_key=flipped_byte)
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_tampered_tag(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        flipped_byte = bytes([wrapped.tag[0] ^ 0xFF]) + wrapped.tag[1:]
        tampered = dataclasses.replace(wrapped, tag=flipped_byte)
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_tampered_nonce(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        flipped_byte = bytes([wrapped.nonce[0] ^ 0xFF]) + wrapped.nonce[1:]
        tampered = dataclasses.replace(wrapped, nonce=flipped_byte)
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_tampered_salt(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        flipped_byte = bytes([wrapped.salt[0] ^ 0xFF]) + wrapped.salt[1:]
        tampered = dataclasses.replace(wrapped, salt=flipped_byte)
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_tampered_ephemeral_key_swapped_for_another_valid_point(self):
        # Swap in a *different but still on-curve* ephemeral key -- this
        # changes both the ECDH shared secret the recipient derives and
        # the AAD context, so it must still fail authentication, not
        # silently succeed with the wrong shared secret.
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        other_valid_point = scalar_multiply(9999, G)
        tampered = dataclasses.replace(wrapped, ephemeral_public_key=other_valid_point)
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_off_curve_ephemeral_key_as_authentication_error(self):
        # is_valid_public_key fails -> the function must raise
        # AuthenticationError specifically (per its own code), not
        # ValueError, so callers can't distinguish "bad point" from
        # "bad ciphertext" -- both look like the generic auth failure.
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        tampered = dataclasses.replace(wrapped, ephemeral_public_key=OFF_CURVE_POINT)
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )

    def test_rejects_wrong_length_salt_as_authentication_error(self):
        recipient_priv, recipient_pub = make_recipient_keypair()
        wrapped = wrap_document_key(
            KDOC, recipient_pub, SENDER, RECIPIENT, DOC_ID, VERSION
        )
        tampered = dataclasses.replace(wrapped, salt=b"short")
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                tampered, recipient_priv, SENDER, RECIPIENT, DOC_ID, VERSION
            )


# ============================================================
# End-to-end: two recipients, cross-unwrap must fail
# ============================================================

class TestEndToEnd:
    def test_only_intended_recipient_can_unwrap(self):
        alice_priv, alice_pub = make_recipient_keypair()
        bob_priv, bob_pub = make_recipient_keypair()

        wrapped_for_alice = wrap_document_key(
            KDOC, alice_pub, SENDER, "alice", DOC_ID, VERSION
        )

        # Alice (the real recipient) recovers it correctly.
        assert unwrap_document_key(
            wrapped_for_alice, alice_priv, SENDER, "alice", DOC_ID, VERSION
        ) == KDOC

        # Bob, using his own private key, must not be able to.
        with pytest.raises(AuthenticationError):
            unwrap_document_key(
                wrapped_for_alice, bob_priv, SENDER, "alice", DOC_ID, VERSION
            )
            