

from secrets import compare_digest

from crypto.sha256 import sha256


# SHA-256 processes keys and messages using 64-byte blocks.
SHA256_BLOCK_SIZE = 64

# HMAC-SHA-256 always produces a 32-byte authentication tag.
HMAC_TAG_SIZE = 32

# Fixed padding bytes defined by the HMAC construction.
INNER_PAD_BYTE = 0x36
OUTER_PAD_BYTE = 0x5C


def normalize_key(key: bytes) -> bytes:
    """Convert any HMAC key into one 64-byte SHA-256 key block."""
    if not isinstance(key, bytes):
        raise TypeError("HMAC key must be bytes")

    if len(key) == 0:
        raise ValueError("HMAC key must not be empty")

    # Keys longer than one SHA-256 block are hashed first.
    if len(key) > SHA256_BLOCK_SIZE:
        key = sha256(key)

    # Short keys are extended to 64 bytes using zero bytes.
    return key + b"\x00" * (SHA256_BLOCK_SIZE - len(key))


def xor_with_byte(data: bytes, value: int) -> bytes:
    """XOR every byte in data with the same byte value."""
    return bytes(byte ^ value for byte in data)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Return the 32-byte HMAC-SHA-256 tag for message."""
    if not isinstance(message, bytes):
        raise TypeError("HMAC message must be bytes")

    key_block = normalize_key(key)

    # Create K' XOR ipad and K' XOR opad.
    inner_padded_key = xor_with_byte(key_block, INNER_PAD_BYTE)
    outer_padded_key = xor_with_byte(key_block, OUTER_PAD_BYTE)

    # Inner hash = SHA256((K' XOR ipad) || message)
    inner_hash = sha256(inner_padded_key + message)

    # Final tag = SHA256((K' XOR opad) || inner hash)
    return sha256(outer_padded_key + inner_hash)


def verify_hmac(
    authentication_key: bytes,
    authenticated_data: bytes,
    received_tag: bytes,
) -> bool:
    """Return True only when received_tag is a valid 32-byte HMAC tag."""
    if not isinstance(received_tag, bytes):
        raise TypeError("HMAC tag must be bytes")

    # Reject incorrect lengths before comparison.
    if len(received_tag) != HMAC_TAG_SIZE:
        return False

    expected_tag = hmac_sha256(authentication_key, authenticated_data)

    # compare_digest reduces timing leakage during tag comparison.
    # It does not calculate HMAC; hmac_sha256() above does that.
    return compare_digest(received_tag, expected_tag)


def run_self_tests() -> None:
    """Test against published HMAC-SHA-256 known-answer vectors."""
    test_vectors = [
        (
            bytes.fromhex("0b" * 20),
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843",
        ),
        (
            bytes.fromhex("aa" * 20),
            bytes.fromhex("dd" * 50),
            "773ea91e36800e46854db8ebd09181a7"
            "2959098b3ef8c122d9635514ced565fe",
        ),
        # This vector checks the rule for keys longer than 64 bytes.
        (
            bytes.fromhex("aa" * 131),
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f"
            "8e0bc6213728c5140546040f0ee37f54",
        ),
    ]

    for key, message, expected_hex_tag in test_vectors:
        calculated_tag = hmac_sha256(key, message)
        assert calculated_tag.hex() == expected_hex_tag
        assert verify_hmac(key, message, calculated_tag)

        changed_message = message + b"!"
        assert not verify_hmac(key, changed_message, calculated_tag)

    print("All HMAC-SHA-256 self-tests passed.")


if __name__ == "__main__":
    run_self_tests()
