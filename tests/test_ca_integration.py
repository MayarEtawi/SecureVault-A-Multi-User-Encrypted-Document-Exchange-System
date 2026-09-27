from dataclasses import replace

import pytest

from server.server import handle_request
from server import storage
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from crypto.freshness import VersionTracker
from crypto.sharing import create_share, open_share
from pki.ca import generate_ca_keypair, issue_certificate, verify_certificate


@pytest.fixture(autouse=True)
def clear_server_storage():
    storage.users.clear()
    storage.documents.clear()
    storage.shares.clear()
    yield
    storage.users.clear()
    storage.documents.clear()
    storage.shares.clear()


def make_certificate(ca_private, username):
    ecdh_private, ecdh_public = generate_ecdh_keypair()
    ecdsa_private, ecdsa_public = generate_ecdsa_keypair()

    certificate = issue_certificate(
        ca_private, username, ecdh_public, ecdsa_public
    )
    return ecdh_private, ecdsa_private, certificate


def test_wrong_recipient_certificate_from_server_is_rejected():
    ca_private, ca_public = generate_ca_keypair()
    _, _, trudy_certificate = make_certificate(ca_private, "Trudy")

    # The server claims this is Omar's record, but the CA certificate says Trudy.
    assert handle_request({
        "type": "REGISTER",
        "username": "Omar",
        "credential_record": {"certificate": trudy_certificate},
    })["status"] is True

    response = handle_request({
        "type": "GET_USER",
        "username": "Omar",
    })

    assert response["status"] is True
    returned_certificate = response["credential_record"]["certificate"]

    assert not verify_certificate(
        returned_certificate,
        ca_public,
        expected_username="Omar",
    )


def make_share():
    ca_private, ca_public = generate_ca_keypair()
    _, sender_private, sender_certificate = make_certificate(
        ca_private, "Layla"
    )
    recipient_private, _, recipient_certificate = make_certificate(
        ca_private, "Omar"
    )

    record = create_share(
        document_key=bytes(range(16)),
        document_id="test-document",
        sender_username="Layla",
        sender_ecdsa_private_key=sender_private,
        recipient_certificate=recipient_certificate,
        trusted_ca_public_key=ca_public,
        version=1,
    )

    return record, sender_certificate, recipient_private, ca_public


def test_receiver_rejects_changed_sender_certificate():
    record, sender_certificate, recipient_private, ca_public = make_share()
    _, attacker_public = generate_ecdsa_keypair()

    altered_certificate = replace(
        sender_certificate,
        ecdsa_public_key=attacker_public,
    )

    with pytest.raises(ValueError, match="sender certificate"):
        open_share(
            record=record,
            sender_certificate=altered_certificate,
            recipient_username="Omar",
            recipient_ecdh_private_key=recipient_private,
            trusted_ca_public_key=ca_public,
            version_tracker=VersionTracker(),
        )


def test_receiver_rejects_changed_signed_share_field():
    record, sender_certificate, recipient_private, ca_public = make_share()
    altered_record = replace(record, document_id="different-document")

    with pytest.raises(ValueError, match="invalid signature"):
        open_share(
            record=altered_record,
            sender_certificate=sender_certificate,
            recipient_username="Omar",
            recipient_ecdh_private_key=recipient_private,
            trusted_ca_public_key=ca_public,
            version_tracker=VersionTracker(),
        )
