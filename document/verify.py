Skip to content
MayarEtawi
project_1
Repository navigation
Code
Issues
Pull requests
Agents
Actions
Projects
Security and quality
Insights
Settings
project_1/document
/
verify.py
in
main

Edit

Preview
Indent mode

Spaces
Indent size

4
Line wrap mode

No wrap
Editing verify.py file contents
  1
  2
  3
  4
  5
  6
  7
  8
  9
 10
 11
 12
 13
 14
 15
 16
 17
 18
 19
 20
 21
 22
 23
 24
 25
 26
 27
 28
 29
 30
 31
 32
 33
 34
 35
 36
 37
 38
 39
 40
 41
 42
 43
 44
 45
 46
 47
 48
 49
 50
 51
 52
 53
 54
 55
 56
 57
 58
 59
 60
 61
 62
 63
 64
 65
 66
 67
 68
 69
 70
 71
 72
 73
 74
 75
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
Use Control + Shift + m to toggle the tab key moving focus. Alternatively, use esc then tab to move to the next interactive element on the page.
