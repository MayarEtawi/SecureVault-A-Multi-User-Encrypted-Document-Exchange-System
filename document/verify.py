"""Authenticate and decrypt an AES-GCM protected document."""

from crypto.gcm import (AES128_KEY_SIZE,AuthenticationError,GCMProtectedData,decrypt_gcm,)

from .format import parse_document
from .metadata import (decode_private,decode_public,)


# preventing trudy from figuring the exact reason for failure, we raise the same exception for all errors
class DocumentVerificationError(Exception):
    """Raised when the received document cannot be trusted."""


#takes a key and (add,ciphertext,nonce,tag) and returns the palintext and the metadata)
def verify_document(protected_document: bytes,document_key: bytes,) -> tuple[bytes, dict]:
    """
    Verify and decrypt a protected document.

    Nothing from the encrypted payload is used until the
    AES-GCM authentication tag has been verified.
    """
    if not isinstance(protected_document, bytes):
        raise TypeError("Protected document must be bytes")

    if not isinstance(document_key, bytes):
        raise TypeError("Document key must be bytes")

    if len(document_key) != AES128_KEY_SIZE:
        raise DocumentVerificationError("Document verification failed")

    try:
        parsed = parse_document(protected_document)
        protected = GCMProtectedData(nonce=parsed["nonce"],ciphertext=parsed["ciphertext"],tag=parsed["tag"],)

        # AES-GCM verifies the tag before returning this payload.
        private_payload = decrypt_gcm(protected,parsed["aad"],document_key,)

        public_metadata = decode_public(
            parsed["metadata"]
        )

        filename, file_type, plaintext = decode_private(
            private_payload
        )

        if public_metadata["file_size"] != len(plaintext):
            raise DocumentVerificationError(
                "Document verification failed"
            )

        # Reconstruct the complete metadata after decryption.
        metadata = {
            "document_id": public_metadata["document_id"],
            "owner_id": public_metadata["owner_id"],
            "version": public_metadata["version"],
            "filename": filename,
            "file_type": file_type,
            "file_size": public_metadata["file_size"],
            "timestamp": public_metadata["timestamp"],
        }

        return plaintext, metadata

    except DocumentVerificationError:
        raise

    except (
        AuthenticationError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        raise DocumentVerificationError(
            "Document verification failed"
        ) from None
