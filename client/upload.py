import os
import time
import uuid

from document.protect import protect_document
from client.socket_client import send_request


def upload_file(file_path, owner_id, document_id=None, version=1):
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # New document gets a new ID; an update keeps its existing ID.
    if document_id is None:
        document_id = str(uuid.uuid4())

    metadata = {
        "document_id": document_id,
        "owner_id": owner_id,
        "version": version,
        "filename": os.path.basename(file_path),
        "file_type": "file",
        "file_size": len(plaintext),
        "timestamp": str(time.time())
    }

    # Encrypt once, locally.
    protected_document, document_key = protect_document(
        plaintext,
        metadata
    )

    # Send the protected document once.
    response = send_request({
        "type": "UPLOAD_DOCUMENT",
        "document_id": document_id,
        "owner_id": owner_id,
        "document": protected_document,
        "filename": metadata["filename"]
    })

    if not response.get("status"):
        return None

    return {
        "document_id": document_id,
        "document_key": document_key,
        "version": version
    }
