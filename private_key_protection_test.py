from dataclasses import replace

from private_key_protection import (
    protect_private_key,
    recover_private_key
)

from ecdh import generate_keypair as generate_ecdh_keypair
from ecdsa import generate_keypair as generate_ecdsa_keypair
from gcm import AuthenticationError


PASSWORD = "Mayar123"


def test_ecdh_private_key_recovery():
    """
    Test protecting and recovering an ECDH private key.
    """

    original_private_key, public_key = generate_ecdh_keypair()

    protected_key = protect_private_key(
        password=PASSWORD,
        private_key=original_private_key,
        key_type="ECDH"
    )

    recovered_private_key = recover_private_key(
        password=PASSWORD,
        protected=protected_key
    )

    assert recovered_private_key == original_private_key

    print("ECDH private-key recovery test passed")


def test_ecdsa_private_key_recovery():
    """
    Test protecting and recovering an ECDSA private key.
    """

    original_private_key, public_key = generate_ecdsa_keypair()

    protected_key = protect_private_key(
        password=PASSWORD,
        private_key=original_private_key,
        key_type="ECDSA"
    )

    recovered_private_key = recover_private_key(
        password=PASSWORD,
        protected=protected_key
    )

    assert recovered_private_key == original_private_key

    print("ECDSA private-key recovery test passed")


def test_wrong_password():
    """
    A wrong password must not recover the private key.
    """

    original_private_key, public_key = generate_ecdh_keypair()

    protected_key = protect_private_key(
        password=PASSWORD,
        private_key=original_private_key,
        key_type="ECDH"
    )

    try:
        recover_private_key(
            password="WrongPassword",
            protected=protected_key
        )

        # Reaching this line means the test failed
        assert False, "Wrong password was accepted"

    except AuthenticationError:
        print("Wrong-password rejection test passed")


def test_modified_ciphertext():
    """
    Modifying one ciphertext byte must be detected by AES-GCM.
    """

    original_private_key, public_key = generate_ecdh_keypair()

    protected_key = protect_private_key(
        password=PASSWORD,
        private_key=original_private_key,
        key_type="ECDH"
    )

    modified_ciphertext = bytearray(
        protected_key.ciphertext
    )

    # Change one bit in the first ciphertext byte
    modified_ciphertext[0] ^= 0x01

    tampered_key = replace(
        protected_key,
        ciphertext=bytes(modified_ciphertext)
    )

    try:
        recover_private_key(
            password=PASSWORD,
            protected=tampered_key
        )

        assert False, "Modified ciphertext was accepted"

    except AuthenticationError:
        print("Ciphertext-modification test passed")


def test_modified_tag():
    """
    Modifying the authentication tag must be detected.
    """

    original_private_key, public_key = generate_ecdsa_keypair()

    protected_key = protect_private_key(
        password=PASSWORD,
        private_key=original_private_key,
        key_type="ECDSA"
    )

    modified_tag = bytearray(protected_key.tag)

    # Change one bit in the tag
    modified_tag[0] ^= 0x01

    tampered_key = replace(
        protected_key,
        tag=bytes(modified_tag)
    )

    try:
        recover_private_key(
            password=PASSWORD,
            protected=tampered_key
        )

        assert False, "Modified tag was accepted"

    except AuthenticationError:
        print("Authentication-tag modification test passed")


if __name__ == "__main__":
    test_ecdh_private_key_recovery()
    test_ecdsa_private_key_recovery()
    test_wrong_password()
    test_modified_ciphertext()
    test_modified_tag()

    print("\nAll private-key protection tests passed")