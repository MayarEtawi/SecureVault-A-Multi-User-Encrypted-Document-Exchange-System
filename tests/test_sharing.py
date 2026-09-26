"""Tests for crypto/sharing.py protocol and edge cases."""

import time
import pytest

from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from crypto.ecdsa import sign as ecdsa_sign
from crypto.freshness import VersionTracker, ReplayError
from crypto.key_wrap import DOCUMENT_KEY_SIZE
from crypto.sharing import (
    ShareRecord,
    create_share,
    open_share,
)
from pki.ca import DEFAULT_CA_NAME, issue_certificate
from pki.certificate import UserCertificate


# ============================================================
# Test Fixtures & Helpers
# ============================================================

@pytest.fixture
def ca_keypair():
    """Generate CA signing keypair."""
    private_key, public_key = generate_ecdsa_keypair()
    return private_key, public_key


@pytest.fixture
def alice_keys():
    """Alice's ECDH and ECDSA keypairs."""
    ecdh_priv, ecdh_pub = generate_ecdh_keypair()
    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    return {
        "username": "alice",
        "ecdh_priv": ecdh_priv,
        "ecdh_pub": ecdh_pub,
        "ecdsa_priv": ecdsa_priv,
        "ecdsa_pub": ecdsa_pub,
    }


@pytest.fixture
def bob_keys():
    """Bob's ECDH and ECDSA keypairs."""
    ecdh_priv, ecdh_pub = generate_ecdh_keypair()
    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    return {
        "username": "bob",
        "ecdh_priv": ecdh_priv,
        "ecdh_pub": ecdh_pub,
        "ecdsa_priv": ecdsa_priv,
        "ecdsa_pub": ecdsa_pub,
    }


@pytest.fixture
def alice_cert(alice_keys, ca_keypair):
    ca_priv, _ = ca_keypair
    now = int(time.time())
    return issue_certificate(
        ca_private_key=ca_priv,
        username=alice_keys["username"],
        ecdh_public_key=alice_keys["ecdh_pub"],
        ecdsa_public_key=alice_keys["ecdsa_pub"],
        issuer=DEFAULT_CA_NAME,
        valid_from=now - 10,
        validity_seconds=3600,
    )


@pytest.fixture
def bob_cert(bob_keys, ca_keypair):
    ca_priv, _ = ca_keypair
    now = int(time.time())
    return issue_certificate(
        ca_private_key=ca_priv,
        username=bob_keys["username"],
        ecdh_public_key=bob_keys["ecdh_pub"],
        ecdsa_public_key=bob_keys["ecdsa_pub"],
        issuer=DEFAULT_CA_NAME,
        valid_from=now - 10,
        validity_seconds=3600,
    )


# ============================================================
# Unit Tests
# ============================================================

class TestSharingProtocol:

    def test_successful_share_roundtrip(self, alice_keys, alice_cert, bob_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair
        doc_key = b"A" * DOCUMENT_KEY_SIZE
        doc_id = "doc-123"
        version = 1
        tracker = VersionTracker()

        # Alice creates share for Bob
        record = create_share(
            document_key=doc_key,
            document_id=doc_id,
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=version,
        )

        # Bob opens share
        unwrapped = open_share(
            record=record,
            sender_certificate=alice_cert,
            recipient_username=bob_keys["username"],
            recipient_ecdh_private_key=bob_keys["ecdh_priv"],
            trusted_ca_public_key=ca_pub,
            version_tracker=tracker,
        )

        assert unwrapped == doc_key

    def test_serialization_roundtrip(self, alice_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair
        doc_key = b"B" * DOCUMENT_KEY_SIZE

        record = create_share(
            document_key=doc_key,
            document_id="doc-serialization",
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=1,
        )

        serialized = record.to_bytes()
        deserialized = ShareRecord.from_bytes(serialized)

        assert deserialized == record

    def test_invalid_document_key_length(self, alice_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair
        invalid_key = b"short_key"

        with pytest.raises(ValueError, match="document_key must be exactly"):
            create_share(
                document_key=invalid_key,
                document_id="doc-1",
                sender_username=alice_keys["username"],
                sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
                recipient_certificate=bob_cert,
                trusted_ca_public_key=ca_pub,
                version=1,
            )

    def test_rejects_untrusted_recipient_certificate(self, alice_keys, bob_cert):
        _, wrong_ca_pub = generate_ecdsa_keypair()
        doc_key = b"X" * DOCUMENT_KEY_SIZE

        with pytest.raises(ValueError, match="recipient certificate failed CA verification"):
            create_share(
                document_key=doc_key,
                document_id="doc-1",
                sender_username=alice_keys["username"],
                sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
                recipient_certificate=bob_cert,
                trusted_ca_public_key=wrong_ca_pub,
                version=1,
            )

    def test_open_rejects_untrusted_sender_certificate(self, alice_keys, alice_cert, bob_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair
        _, wrong_ca_pub = generate_ecdsa_keypair()
        doc_key = b"Z" * DOCUMENT_KEY_SIZE

        record = create_share(
            document_key=doc_key,
            document_id="doc-1",
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=1,
        )

        with pytest.raises(ValueError, match="sender certificate failed CA verification"):
            open_share(
                record=record,
                sender_certificate=alice_cert,
                recipient_username=bob_keys["username"],
                recipient_ecdh_private_key=bob_keys["ecdh_priv"],
                trusted_ca_public_key=wrong_ca_pub,
                version_tracker=VersionTracker(),
            )

    def test_open_rejects_wrong_recipient(self, alice_keys, alice_cert, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair

        record = create_share(
            document_key=b"M" * DOCUMENT_KEY_SIZE,
            document_id="doc-1",
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=1,
        )

        with pytest.raises(ValueError, match="record is not addressed to this recipient"):
            open_share(
                record=record,
                sender_certificate=alice_cert,
                recipient_username="charlie",  # Mismatched recipient
                recipient_ecdh_private_key=12345,
                trusted_ca_public_key=ca_pub,
                version_tracker=VersionTracker(),
            )

    def test_open_rejects_tampered_signature(self, alice_keys, alice_cert, bob_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair

        record = create_share(
            document_key=b"T" * DOCUMENT_KEY_SIZE,
            document_id="doc-tamper",
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=1,
        )

        # Forged signature
        forged_record = ShareRecord(**{**record.__dict__, "signature": (12345, 67890)})

        with pytest.raises(ValueError, match="invalid signature on share record"):
            open_share(
                record=forged_record,
                sender_certificate=alice_cert,
                recipient_username=bob_keys["username"],
                recipient_ecdh_private_key=bob_keys["ecdh_priv"],
                trusted_ca_public_key=ca_pub,
                version_tracker=VersionTracker(),
            )

    def test_open_rejects_tampered_ciphertext(self, alice_keys, alice_cert, bob_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair

        record = create_share(
            document_key=b"K" * DOCUMENT_KEY_SIZE,
            document_id="doc-cipher-tamper",
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=1,
        )

        # Tamper wrapped_key encrypted bytes
        w = record.wrapped_key
        tampered_bytes = bytearray(w.encrypted_key)
        tampered_bytes[0] ^= 0xFF
        w_tampered = w.__class__(
            ephemeral_public_key=w.ephemeral_public_key,
            salt=w.salt,
            nonce=w.nonce,
            encrypted_key=bytes(tampered_bytes),
            tag=w.tag,
        )

        # Re-sign modified record so signature passes but unwrap fails
        rec_tampered = ShareRecord(**{**record.__dict__, "wrapped_key": w_tampered})
        sig = ecdsa_sign(rec_tampered.signable_bytes(), alice_keys["ecdsa_priv"])
        rec_signed = ShareRecord(**{**rec_tampered.__dict__, "signature": sig})

        with pytest.raises(ValueError, match="failed to unwrap document key"):
            open_share(
                record=rec_signed,
                sender_certificate=alice_cert,
                recipient_username=bob_keys["username"],
                recipient_ecdh_private_key=bob_keys["ecdh_priv"],
                trusted_ca_public_key=ca_pub,
                version_tracker=VersionTracker(),
            )

    def test_replay_protection_enforcement(self, alice_keys, alice_cert, bob_keys, bob_cert, ca_keypair):
        _, ca_pub = ca_keypair
        doc_key = b"R" * DOCUMENT_KEY_SIZE
        doc_id = "doc-replay"
        tracker = VersionTracker()

        record_v1 = create_share(
            document_key=doc_key,
            document_id=doc_id,
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=1,
        )

        # First consumption -> Success
        res1 = open_share(
            record=record_v1,
            sender_certificate=alice_cert,
            recipient_username=bob_keys["username"],
            recipient_ecdh_private_key=bob_keys["ecdh_priv"],
            trusted_ca_public_key=ca_pub,
            version_tracker=tracker,
        )
        assert res1 == doc_key

        # Replayed v1 -> ReplayError
        with pytest.raises(ReplayError, match="Stale document rejected"):
            open_share(
                record=record_v1,
                sender_certificate=alice_cert,
                recipient_username=bob_keys["username"],
                recipient_ecdh_private_key=bob_keys["ecdh_priv"],
                trusted_ca_public_key=ca_pub,
                version_tracker=tracker,
            )

        # Version 2 -> Success
        record_v2 = create_share(
            document_key=doc_key,
            document_id=doc_id,
            sender_username=alice_keys["username"],
            sender_ecdsa_private_key=alice_keys["ecdsa_priv"],
            recipient_certificate=bob_cert,
            trusted_ca_public_key=ca_pub,
            version=2,
        )

        res2 = open_share(
            record=record_v2,
            sender_certificate=alice_cert,
            recipient_username=bob_keys["username"],
            recipient_ecdh_private_key=bob_keys["ecdh_priv"],
            trusted_ca_public_key=ca_pub,
            version_tracker=tracker,
        )
        assert res2 == doc_key