"""Authenticate and decrypt an AES-GCM protected document."""

from crypto.gcm import (
    AES128_KEY_SIZE,
    AuthenticationError,
    GCMProtectedData,
    decrypt_gcm,
)

from .format import parse_document
from .metadata import decode_metadata


class DocumentVerificationError(Exception):
    """Raised when the received document cannot be trusted."""


def verify_document(
    protected_document: bytes,
    document_key: bytes,
) -> tuple[bytes, dict]:
    """
    Verify and decrypt a protected document.

    The plaintext is returned only after successful GCM
    authentication and metadata validation.
    """

    if not isinstance(protected_document, bytes):
        raise TypeError("Protected document must be bytes")

    if not isinstance(document_key, bytes):
        raise TypeError("Document key must be bytes")

    if len(document_key) != AES128_KEY_SIZE:
        raise DocumentVerificationError(
            "Document verification failed"
        )

    try:
        parsed = parse_document(protected_document)

        protected = GCMProtectedData(
            nonce=parsed["nonce"],
            ciphertext=parsed["ciphertext"],
            tag=parsed["tag"],
        )

        plaintext = decrypt_gcm(
            protected,
            parsed["aad"],
            document_key,
        )

        metadata = decode_metadata(
            parsed["metadata"]
        )

        if metadata["file_size"] != len(plaintext):
            raise DocumentVerificationError(
                "Document verification failed"
            )

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