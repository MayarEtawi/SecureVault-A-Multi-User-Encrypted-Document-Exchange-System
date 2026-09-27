# tests/test_certificate.py

from dataclasses import replace

from crypto.ecc import n
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from pki.ca import (
    generate_ca_keypair,
    issue_certificate,
    verify_certificate,
)


TEST_TIME = 1_000_000
VALIDITY_SECONDS = 3600


def create_test_certificate():
    """
    Create a CA, Omar's keys, and a valid certificate.
    """

    ca_private_key, ca_public_key = generate_ca_keypair()

    omar_ecdh_private, omar_ecdh_public = generate_ecdh_keypair()
    omar_ecdsa_private, omar_ecdsa_public = generate_ecdsa_keypair()

    certificate = issue_certificate(
        ca_private_key=ca_private_key,
        username="Omar",
        ecdh_public_key=omar_ecdh_public,
        ecdsa_public_key=omar_ecdsa_public,
        valid_from=TEST_TIME,
        validity_seconds=VALIDITY_SECONDS,
    )

    return (
        ca_private_key,
        ca_public_key,
        omar_ecdh_private,
        omar_ecdsa_private,
        certificate,
    )


# ============================================================
# Successful Certificate Verification
# ============================================================

def test_valid_certificate_is_accepted():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    accepted = verify_certificate(
        certificate=certificate,
        trusted_ca_public_key=ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    )

    assert accepted is True


def test_certificate_contains_separate_public_keys():
    _, _, _, _, certificate = create_test_certificate()

    assert certificate.ecdh_public_key is not None
    assert certificate.ecdsa_public_key is not None
    assert certificate.ecdh_public_key != certificate.ecdsa_public_key


# ============================================================
# Identity and Issuer Tests
# ============================================================

def test_wrong_expected_username_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    accepted = verify_certificate(
        certificate=certificate,
        trusted_ca_public_key=ca_public_key,
        expected_username="Trudy",
        current_time=TEST_TIME + 100,
    )

    assert accepted is False


def test_modified_username_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    tampered_certificate = replace(
        certificate,
        username="Trudy",
    )

    accepted = verify_certificate(
        tampered_certificate,
        ca_public_key,
        expected_username="Trudy",
        current_time=TEST_TIME + 100,
    )

    assert accepted is False


def test_modified_issuer_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    tampered_certificate = replace(
        certificate,
        issuer="Trudy Fake CA",
    )

    accepted = verify_certificate(
        tampered_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    )

    assert accepted is False


# ============================================================
# Public-Key Substitution Tests
# ============================================================

def test_replaced_ecdh_public_key_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()
    _, attacker_public_key = generate_ecdh_keypair()

    tampered_certificate = replace(
        certificate,
        ecdh_public_key=attacker_public_key,
    )

    assert verify_certificate(
        tampered_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False


def test_replaced_ecdsa_public_key_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()
    _, attacker_public_key = generate_ecdsa_keypair()

    tampered_certificate = replace(
        certificate,
        ecdsa_public_key=attacker_public_key,
    )

    assert verify_certificate(
        tampered_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False


def test_fake_ca_public_key_is_rejected():
    _, _, _, _, certificate = create_test_certificate()

    _, fake_ca_public_key = generate_ca_keypair()

    assert verify_certificate(
        certificate,
        fake_ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False


# ============================================================
# Time Validation Tests
# ============================================================

def test_certificate_used_before_start_time_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    assert verify_certificate(
        certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME - 1,
    ) is False


def test_expired_certificate_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    assert verify_certificate(
        certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + VALIDITY_SECONDS + 1,
    ) is False


# ============================================================
# Signature and Format Tests
# ============================================================

def test_modified_ca_signature_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    r, s = certificate.ca_signature

    tampered_certificate = replace(
        certificate,
        ca_signature=((r + 1) % n, s),
    )

    assert verify_certificate(
        tampered_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False


def test_missing_ca_signature_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    unsigned_certificate = replace(
        certificate,
        ca_signature=None,
    )

    assert verify_certificate(
        unsigned_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False


def test_modified_serial_number_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    changed_serial = bytearray(certificate.serial_number)
    changed_serial[0] ^= 0x01

    tampered_certificate = replace(
        certificate,
        serial_number=bytes(changed_serial),
    )

    assert verify_certificate(
        tampered_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False


def test_invalid_serial_number_length_is_rejected():
    _, ca_public_key, _, _, certificate = create_test_certificate()

    malformed_certificate = replace(
        certificate,
        serial_number=b"short",
    )

    assert verify_certificate(
        malformed_certificate,
        ca_public_key,
        expected_username="Omar",
        current_time=TEST_TIME + 100,
    ) is False
