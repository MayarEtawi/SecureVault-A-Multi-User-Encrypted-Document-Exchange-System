"""Create a signed certificate enrollment request."""

# ==============================================================================
# IMPORTS & DEPENDENCIES
# ==============================================================================

import json
import secrets
from pathlib import Path

from crypto.ecdsa import sign
from pki.certificate import encode_public_key

# ==============================================================================
# PROTOCOL CONSTANTS
# ==============================================================================

# Domain-separation tag to prevent cross-protocol signature replay attacks
REQUEST_PREFIX = b"SecureVault-Enrollment-Request-v1"

# Required byte length for cryptographically random request tokens
REQUEST_ID_SIZE = 16

# ==============================================================================
# CANONICAL BINARY ENCODING
# ==============================================================================

def request_bytes(username, ecdh_public_key, ecdsa_public_key, request_id):
    """
    Construct the deterministic binary payload for applicant signing.

    Ensures fields are formatted unambiguously to prevent ambiguity attacks.
    """
    
    # 1. Validate and clean username input
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must not be empty")

    name = username.strip().encode("utf-8")
    if len(name) > 128:
        raise ValueError("username is too long")

    # 2. Validate request token size
    if not isinstance(request_id, bytes) or len(request_id) != REQUEST_ID_SIZE:
        raise ValueError("request_id must be 16 bytes")

    # 3. Concatenate fields deterministically
    return (
        REQUEST_PREFIX
        + len(name).to_bytes(2, "big")  # 2-byte length prefix
        + name                           # Raw UTF-8 name bytes
        + encode_public_key(ecdh_public_key)    # Serialized ECDH key
        + encode_public_key(ecdsa_public_key)   # Serialized ECDSA key
        + request_id                            # Random nonce
    )

# ==============================================================================
# REQUEST CREATION & PERSISTENCE
# ==============================================================================

def save_enrollment_request(
    path,
    username,
    ecdh_public_key,
    ecdsa_public_key,
    ecdsa_private_key,
):
    """
    Generate, sign, and write a certificate enrollment request to JSON.

    Signs the binary payload with the applicant's ECDSA private key to prove 
    possession of the identity key prior to submission.
    """
    
    # Clean username string
    username = username.strip()
    
    # Generate a fresh 16-byte cryptographically secure random identifier
    request_id = secrets.token_bytes(REQUEST_ID_SIZE)

    # Build canonical payload and generate ECDSA signature tuple (r, s)
    body = request_bytes(
        username,
        ecdh_public_key,
        ecdsa_public_key,
        request_id,
    )
    signature = sign(body, ecdsa_private_key)

    # Format output request payload with hex-encoded byte fields
    request = {
        "username": username,
        "ecdh_public_key": encode_public_key(ecdh_public_key).hex(),
        "ecdsa_public_key": encode_public_key(ecdsa_public_key).hex(),
        "request_id": request_id.hex(),
        "request_signature": [signature[0], signature[1]],
    }

    # Atomically write JSON request file (fails if file already exists)
    with Path(path).open("x", encoding="utf-8") as file:
        json.dump(request, file, indent=2)
