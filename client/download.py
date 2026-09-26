import os
import tempfile
from pathlib import Path

from client.socket_client import send_request
from document.verify import verify_document, DocumentVerificationError


def download_file(
    document_id: str,
    document_key: bytes,
    output_path: str,
    minimum_version: int = 1,
    expected_owner: str | None = None,
):
    """Download, verify, then save a document."""

    try:
        response = send_request({
            "type": "DOWNLOAD_DOCUMENT",
            "document_id": document_id
        })

        if not response.get("status"):
            print("Download failed: document not found")
            return False

        protected_document = response["document"]

        # verify_document checks the GCM tag before returning plaintext.
        plaintext, metadata = verify_document( protected_document,document_key)

        # Check that the server returned the document we requested.
        if metadata["document_id"] != document_id:
            print("Download failed: document verification failed")
            return False
        if expected_owner is not None and metadata["owner_id"] != expected_owner:
            print("Download failed: document owner mismatch")
            return False
        # Reject a version older than the last trusted version.
        if metadata["version"] < minimum_version:
            print("Download failed: stale document")
            return False

        # Save only after all checks have passed.
        destination = Path(output_path)
        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=".securevault_",
                delete=False
            ) as temporary_file:
                temporary_path = temporary_file.name
                temporary_file.write(plaintext)

            os.replace(temporary_path, destination)

        finally:
            if temporary_path and os.path.exists(temporary_path):
                os.remove(temporary_path)

        print("Download successful")
        print("Filename:", metadata["filename"])
        return True

    except (DocumentVerificationError, KeyError, TypeError, ValueError):
        print("Download failed: document verification failed")
        return False

    except OSError:
        print("Download failed: could not save the file")
        return False
