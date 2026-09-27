import uuid

from client.socket_client import send_request
from crypto.ecdsa import generate_public_key
from crypto.sharing import create_share
from pki.ca import verify_certificate


def share_document(
    document_id: str,
    document_key: bytes,
    recipient_username: str,
    session: dict,
    trusted_ca_public_key,
    version: int
):
    """Protect the document key for one recipient and store a signed share."""

    recipient_username = recipient_username.strip()

    if not recipient_username:
        print("Share failed: enter a recipient username")
        return None

    if recipient_username == session["username"]:
        print("Share failed: choose another user")
        return None

    # A missing trusted CA key means we cannot authenticate public keys.
    if trusted_ca_public_key is None:
        print("Share failed: trusted CA key is not available")
        return None

    # Check the sender's own certificate and signing key.
    sender_certificate = session.get("certificate")

    if not verify_certificate(
        sender_certificate,
        trusted_ca_public_key,
        expected_username=session["username"]
    ):
        print("Share failed: sender certificate is invalid")
        return None

    signing_public_key = generate_public_key(
        session["ecdsa_private_key"]
    )

    if signing_public_key != sender_certificate.ecdsa_public_key:
        print("Share failed: sender signing key does not match certificate")
        return None

    # Ask the server for the recipient's credential record.
    response = send_request({
        "type": "GET_USER",
        "username": recipient_username
    })

    if not response.get("status"):
        print("Share failed: recipient not found")
        return None

    recipient_record = response["credential_record"]
    recipient_certificate = recipient_record.get("certificate")

    # The server supplies the certificate, but the CA signature
    # determines whether its public keys can be trusted.
    if not verify_certificate(
        recipient_certificate,
        trusted_ca_public_key,
        expected_username=recipient_username
    ):
        print("Share failed: recipient certificate is invalid")
        return None

    # Protect Kdoc with the recipient's certified ECDH key,
    # then sign the share with the sender's ECDSA private key.
    try:
        share_record = create_share(
            document_key=document_key,
            document_id=document_id,
            sender_username=session["username"],
            sender_ecdsa_private_key=session["ecdsa_private_key"],
            recipient_certificate=recipient_certificate,
            trusted_ca_public_key=trusted_ca_public_key,
            version=version
        )
    except (TypeError, ValueError):
        print("Share failed: could not create a valid share")
        return None

    share_id = str(uuid.uuid4())

    # The server receives the protected, signed record;
    # it does not receive the plaintext document key.
    save_response = send_request({
        "type": "SHARE",
        "share_id": share_id,
        "share_record": share_record
    })

    if not save_response.get("status"):
        print("Share failed: server did not store the share")
        return None

    print("Share successful")
    print("Recipient:", recipient_username)

    return share_id
