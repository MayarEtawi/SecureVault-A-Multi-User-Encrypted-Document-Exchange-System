"""Verify a signed share and download its encrypted document locally."""

from client.socket_client import send_request
from client.download import download_file
from client.version_store import get_version, save_version
from crypto.sharing import ShareRecord, open_share
from crypto.freshness import ReplayError, VersionTracker
from pki.ca import verify_certificate


def list_incoming_shares(username: str):
    response = send_request({"type": "GET_SHARES"})
    if not response.get("status"):
        return []
    return [(share_id, record) for share_id, record in response["shares"].items()
            if isinstance(record, ShareRecord) and record.recipient_username == username]


def receive_share(share_record: ShareRecord, session: dict,
                  trusted_ca_public_key, output_path: str) -> bool:
    if not isinstance(share_record, ShareRecord) or share_record.recipient_username != session["username"]:
        print("Receive failed: invalid share")
        return False
    response = send_request({"type": "GET_USER", "username": share_record.sender_username})
    if not response.get("status"):
        print("Receive failed: invalid share")
        return False
    certificate = response["credential_record"].get("certificate")
    if not verify_certificate(certificate, trusted_ca_public_key,
                              expected_username=share_record.sender_username):
        print("Receive failed: invalid share")
        return False
    known_version = get_version(session["username"], share_record.document_id)
    if share_record.version <= known_version:
        print("Receive failed: stale share")
        return False
    try:
        document_key = open_share(
            share_record, certificate, session["username"],
            session["ecdh_private_key"], trusted_ca_public_key, VersionTracker()
        )
    except (ReplayError, ValueError, TypeError):
        print("Receive failed: invalid share")
        return False
    if not download_file(share_record.document_id, document_key, output_path,
                         minimum_version=share_record.version,
                         expected_owner=share_record.sender_username):
        return False
    save_version(session["username"], share_record.document_id, share_record.version)
    return True
