"""Authenticate and decrypt an AES-GCM protected document."""

"""
Module summary:
- verify_document(): Takes packed byte data and key, parses fields, decrypts and verifies tag with AES-GCM,
  decodes public and private metadata, checks file sizes, and returns decrypted plaintext with full metadata dictionary.
"""

from crypto.gcm import (
    AES128_KEY_SIZE,
    AuthenticationError,
    GCMProtectedData,
    decrypt_gcm,
)

from .format import parse_document
from .metadata import (
    decode_private,
    decode_public,
)


# Standard custom error to stop attackers from knowing exact reason for failure
class DocumentVerificationError(Exception):
    """Raised when the received document cannot be trusted."""


def verify_document(protected_document: bytes, document_key: bytes) -> tuple[bytes, dict]:
    """
    Verify and decrypt a protected document stream.

    No data inside the encrypted payload is used until
    the AES-GCM authentication tag passes verification first.
    """

    # Check input protected document is bytes type
    if not isinstance(protected_document, bytes):
        raise TypeError("Protected document must be bytes")

    # Check document key parameter is bytes type
    if not isinstance(document_key, bytes):
        raise TypeError("Document key must be bytes")

    # Check key size matches exact AES-128 key length requirement
    if len(document_key) != AES128_KEY_SIZE:
        raise DocumentVerificationError("Document verification failed")

    try:
        # Parse packed binary document into format fields
        parsed = parse_document(protected_document)

        # Build GCM structure object holding nonce, ciphertext, and tag
        protected = GCMProtectedData(
            nonce=parsed["nonce"],
            ciphertext=parsed["ciphertext"],
            tag=parsed["tag"],
        )

        # Decrypt payload. AES-GCM verifies tag integrity before giving plaintext
        private_payload = decrypt_gcm(
            protected,
            parsed["aad"],
            document_key,
        )

        # Decode public metadata dictionary from header bytes
        public_metadata = decode_public(
            parsed["metadata"]
        )

        # Decode decrypted private payload into file_type string and raw content bytes
        file_type, plaintext = decode_private(
            private_payload
        )

        # Check declared metadata file size matches real plaintext byte length
        if public_metadata["file_size"] != len(plaintext):
            raise DocumentVerificationError(
                "Document verification failed"
            )

        # Put together all public and private metadata into full dictionary
        metadata = {
            "document_id": public_metadata["document_id"],
            "owner_id": public_metadata["owner_id"],
            "version": public_metadata["version"],
            "filename": public_metadata["filename"],
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
        # Catch any parsing, formatting, or tag errors and raise generic verification failure
        raise DocumentVerificationError(
            "Document verification failed"
        ) from None
