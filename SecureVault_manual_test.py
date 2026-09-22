"""
Complete tests for SecureVault authentication and private-key protection.

Place this file in the same folder as:
Register.py
Login.py
password_protection.py
private_key_protection.py
ecdh.py
ecdsa.py
gcm.py
"""

from dataclasses import replace

from Register import register_user, users
from Login import login_user, login_and_unlock

from password_protection import (
    hash_password,
    verify_password
)

from private_key_protection import (
    recover_private_key,
    protect_private_key
)

from ecdh import (
    generate_public_key as generate_ecdh_public_key
)

from ecdsa import (
    generate_public_key as generate_ecdsa_public_key
)

from gcm import AuthenticationError


# ============================================================
# Manual operations
# ============================================================

def show_registered_users():
    """Show safe information without printing secret values."""

    if not users:
        print("No users are registered in this run.")
        return

    print("\nRegistered users:")

    for username, credential_record in users.items():
        password_record = credential_record[
            "password_protection"
        ]

        public_keys = credential_record["public_keys"]
        protected_keys = credential_record[
            "protected_private_keys"
        ]

        print(f"\nUsername: {username}")

        print(
            "Salt length:",
            len(password_record["salt"]),
            "bytes"
        )

        print(
            "Password hash length:",
            len(password_record["password_hash"]),
            "bytes"
        )

        print(
            "ECDH public key exists:",
            public_keys["ecdh"] is not None
        )

        print(
            "ECDSA public key exists:",
            public_keys["ecdsa"] is not None
        )

        print(
            "ECDH private key is protected:",
            protected_keys["ecdh"] is not None
        )

        print(
            "ECDSA private key is protected:",
            protected_keys["ecdsa"] is not None
        )

        print("Plaintext password stored: No")
        print("Plaintext private keys stored: No")
def change_password(
    username: str,
    old_password: str,
    new_password: str
) -> bool:

    if not isinstance(username, str):
        raise TypeError("username must be a string")

    if not isinstance(old_password, str):
        raise TypeError("old password must be a string")

    if not isinstance(new_password, str):
        raise TypeError("new password must be a string")

    username = username.strip()

    if username == "":
        return False

    if old_password == "" or new_password == "":
        return False

    if len(new_password) < 8:
        return False

    if old_password == new_password:
        return False

    # Verify old password and recover the private keys
    session = login_and_unlock(
        username,
        old_password
    )

    if session is None:
        return False

    # Generate a new Argon2id password record
    new_password_record = hash_password(
        new_password
    )

    # Re-encrypt the same private keys using the new password
    new_protected_ecdh_key = protect_private_key(
        password=new_password,
        private_key=session["ecdh_private_key"],
        key_type="ECDH"
    )

    new_protected_ecdsa_key = protect_private_key(
        password=new_password,
        private_key=session["ecdsa_private_key"],
        key_type="ECDSA"
    )

    credential_record = users[username]

    # Replace the old password record
    credential_record["password_protection"] = (
        new_password_record
    )

    # Replace the old encrypted private keys
    credential_record["protected_private_keys"] = {
        "ecdh": new_protected_ecdh_key,
        "ecdsa": new_protected_ecdsa_key
    }

    return True


def manual_registration():
    username = input("Create username: ")
    password = input(
        "Create password (at least 8 characters): "
    )

    if register_user(username, password):
        print("Registration successful")
    else:
        print(
            "Registration failed: username may be empty, "
            "duplicated, or password may be too short."
        )


def manual_login():
    username = input("Username: ")
    password = input("Password: ")

    if login_user(username, password):
        print("Login successful")
    else:
        print("Invalid username or password")


def manual_login_and_unlock():
    username = input("Username: ")
    password = input("Password: ")

    session = login_and_unlock(username, password)

    if session is None:
        print("Login or private-key recovery failed")
        return

    print("Login successful")
    print("ECDH private key recovered: Yes")
    print("ECDSA private key recovered: Yes")

    # Do not print private key values
    print("Private key values were not displayed")


# ============================================================
# Test 1: Password protection
# ============================================================

def test_password_protection():

    password = "Mayar123"

    first_record = hash_password(password)
    second_record = hash_password(password)

    assert verify_password(
        password,
        first_record
    ) is True, "Correct password was rejected"

    assert verify_password(
        "WrongPassword",
        first_record
    ) is False, "Wrong password was accepted"

    assert len(first_record["salt"]) == 16, \
        "Salt length must be 16 bytes"

    assert len(first_record["password_hash"]) == 32, \
        "Password hash length must be 32 bytes"

    assert first_record["salt"] != second_record["salt"], \
        "Two password records used the same salt"

    assert (
        first_record["password_hash"]
        != second_record["password_hash"]
    ), "Same password produced the same hash with different salts"

    assert "password" not in first_record, \
        "Plaintext password was stored"

    print("Test 1 passed: Password protection")


# ============================================================
# Test 2: Registration
# ============================================================

def test_registration():

    users.clear()

    assert register_user(
        "mayar",
        "Mayar123"
    ) is True, "Valid registration failed"

    assert "mayar" in users, \
        "Registered user was not stored"

    assert register_user(
        "mayar",
        "Another123"
    ) is False, "Duplicate username was accepted"

    assert register_user(
        "",
        "Mayar123"
    ) is False, "Empty username was accepted"

    assert register_user(
        "   ",
        "Mayar123"
    ) is False, "Spaces-only username was accepted"

    assert register_user(
        "layla",
        ""
    ) is False, "Empty password was accepted"

    assert register_user(
        "layla",
        "123"
    ) is False, "Short password was accepted"

    record = users["mayar"]

    assert record["username"] == "mayar", \
        "Stored username is incorrect"

    assert "password" not in record, \
        "Plaintext password was stored"

    assert record["public_keys"]["ecdh"] is not None, \
        "ECDH public key was not stored"

    assert record["public_keys"]["ecdsa"] is not None, \
        "ECDSA public key was not stored"

    assert (
        record["protected_private_keys"]["ecdh"]
        is not None
    ), "Protected ECDH private key was not stored"

    assert (
        record["protected_private_keys"]["ecdsa"]
        is not None
    ), "Protected ECDSA private key was not stored"

    print("Test 2 passed: Registration")


# ============================================================
# Test 3: Different users receive different values
# ============================================================

def test_different_users():

    users.clear()

    assert register_user(
        "mayar",
        "SamePassword123"
    ) is True

    assert register_user(
        "layla",
        "SamePassword123"
    ) is True

    mayar_record = users["mayar"]
    layla_record = users["layla"]

    mayar_password = mayar_record[
        "password_protection"
    ]

    layla_password = layla_record[
        "password_protection"
    ]

    assert (
        mayar_password["salt"]
        != layla_password["salt"]
    ), "Different users received the same salt"

    assert (
        mayar_password["password_hash"]
        != layla_password["password_hash"]
    ), "Same password produced equal stored hashes"

    assert (
        mayar_record["public_keys"]["ecdh"]
        != layla_record["public_keys"]["ecdh"]
    ), "Different users received the same ECDH public key"

    assert (
        mayar_record["public_keys"]["ecdsa"]
        != layla_record["public_keys"]["ecdsa"]
    ), "Different users received the same ECDSA public key"

    print("Test 3 passed: Different users use different values")


# ============================================================
# Test 4: Login
# ============================================================

def test_login():

    users.clear()

    register_user("mayar", "Mayar123")

    assert login_user(
        "mayar",
        "Mayar123"
    ) is True, "Correct login was rejected"

    assert login_user(
        "mayar",
        "WrongPassword"
    ) is False, "Wrong password was accepted"

    assert login_user(
        "unknown",
        "Mayar123"
    ) is False, "Unknown username was accepted"

    assert login_user(
        "   mayar   ",
        "Mayar123"
    ) is True, "Username spaces were not handled"

    assert login_user(
        "mayar",
        "mayar123"
    ) is False, "Password was not case-sensitive"

    assert login_user(
        "",
        "Mayar123"
    ) is False, "Empty username was accepted"

    assert login_user(
        "mayar",
        ""
    ) is False, "Empty password was accepted"

    print("Test 4 passed: Login")


# ============================================================
# Test 5: Login and private-key recovery
# ============================================================

def test_login_and_key_recovery():

    users.clear()

    register_user("mayar", "Mayar123")

    session = login_and_unlock(
        "mayar",
        "Mayar123"
    )

    assert session is not None, \
        "Correct password did not unlock private keys"

    assert session["username"] == "mayar", \
        "Session contains wrong username"

    assert isinstance(
        session["ecdh_private_key"],
        int
    ), "Recovered ECDH private key is invalid"

    assert isinstance(
        session["ecdsa_private_key"],
        int
    ), "Recovered ECDSA private key is invalid"

    record = users["mayar"]

    calculated_ecdh_public_key = (
        generate_ecdh_public_key(
            session["ecdh_private_key"]
        )
    )

    calculated_ecdsa_public_key = (
        generate_ecdsa_public_key(
            session["ecdsa_private_key"]
        )
    )

    assert (
        calculated_ecdh_public_key
        == record["public_keys"]["ecdh"]
    ), "Recovered ECDH private key does not match public key"

    assert (
        calculated_ecdsa_public_key
        == record["public_keys"]["ecdsa"]
    ), "Recovered ECDSA private key does not match public key"

    assert login_and_unlock(
        "mayar",
        "WrongPassword"
    ) is None, "Wrong password unlocked private keys"

    assert login_and_unlock(
        "unknown",
        "Mayar123"
    ) is None, "Unknown user obtained a session"

    print("Test 5 passed: Login and private-key recovery")


# ============================================================
# Helper for expected AES-GCM failures
# ============================================================

def expect_authentication_failure(
    password,
    protected_key,
    test_name
):

    try:
        recover_private_key(
            password,
            protected_key
        )

    except AuthenticationError:
        print(f"{test_name} passed")
        return

    raise AssertionError(
        f"{test_name} failed: modified data was accepted"
    )


# ============================================================
# Test 6: Ciphertext tampering
# ============================================================

def test_ciphertext_tampering():

    users.clear()

    register_user("mayar", "Mayar123")

    protected_key = users["mayar"][
        "protected_private_keys"
    ]["ecdh"]

    modified_ciphertext = bytearray(
        protected_key.ciphertext
    )

    modified_ciphertext[0] ^= 0x01

    tampered_key = replace(
        protected_key,
        ciphertext=bytes(modified_ciphertext)
    )

    expect_authentication_failure(
        "Mayar123",
        tampered_key,
        "Test 6: Ciphertext tampering"
    )


# ============================================================
# Test 7: Authentication-tag tampering
# ============================================================

def test_tag_tampering():

    users.clear()

    register_user("mayar", "Mayar123")

    protected_key = users["mayar"][
        "protected_private_keys"
    ]["ecdh"]

    modified_tag = bytearray(
        protected_key.tag
    )

    modified_tag[0] ^= 0x01

    tampered_key = replace(
        protected_key,
        tag=bytes(modified_tag)
    )

    expect_authentication_failure(
        "Mayar123",
        tampered_key,
        "Test 7: Authentication-tag tampering"
    )


# ============================================================
# Test 8: Nonce tampering
# ============================================================

def test_nonce_tampering():

    users.clear()

    register_user("mayar", "Mayar123")

    protected_key = users["mayar"][
        "protected_private_keys"
    ]["ecdh"]

    modified_nonce = bytearray(
        protected_key.nonce
    )

    modified_nonce[0] ^= 0x01

    tampered_key = replace(
        protected_key,
        nonce=bytes(modified_nonce)
    )

    expect_authentication_failure(
        "Mayar123",
        tampered_key,
        "Test 8: Nonce tampering"
    )


# ============================================================
# Test 9: Key-type/AAD tampering
# ============================================================

def test_key_type_tampering():

    users.clear()

    register_user("mayar", "Mayar123")

    protected_key = users["mayar"][
        "protected_private_keys"
    ]["ecdh"]

    tampered_key = replace(
        protected_key,
        key_type="ECDSA"
    )

    expect_authentication_failure(
        "Mayar123",
        tampered_key,
        "Test 9: Key-type/AAD tampering"
    )


# ============================================================
# Test 10: Wrong password cannot decrypt private key
# ============================================================

def test_wrong_password_recovery():

    users.clear()

    register_user("mayar", "Mayar123")

    protected_key = users["mayar"][
        "protected_private_keys"
    ]["ecdh"]

    expect_authentication_failure(
        "WrongPassword",
        protected_key,
        "Test 10: Wrong-password recovery"
    )


# ============================================================
# Test 11: Protected private-key structure
# ============================================================

def test_protected_key_structure():

    users.clear()

    register_user("mayar", "Mayar123")

    record = users["mayar"]

    ecdh_key = record[
        "protected_private_keys"
    ]["ecdh"]

    ecdsa_key = record[
        "protected_private_keys"
    ]["ecdsa"]

    assert ecdh_key.key_type == "ECDH", \
        "Wrong ECDH key type"

    assert ecdsa_key.key_type == "ECDSA", \
        "Wrong ECDSA key type"

    assert len(ecdh_key.salt) == 16, \
        "ECDH protection salt must be 16 bytes"

    assert len(ecdsa_key.salt) == 16, \
        "ECDSA protection salt must be 16 bytes"

    assert len(ecdh_key.nonce) == 12, \
        "ECDH GCM nonce must be 12 bytes"

    assert len(ecdsa_key.nonce) == 12, \
        "ECDSA GCM nonce must be 12 bytes"

    assert len(ecdh_key.tag) == 16, \
        "ECDH GCM tag must be 16 bytes"

    assert len(ecdsa_key.tag) == 16, \
        "ECDSA GCM tag must be 16 bytes"

    assert len(ecdh_key.ciphertext) == 32, \
        "Encrypted ECDH private key must be 32 bytes"

    assert len(ecdsa_key.ciphertext) == 32, \
        "Encrypted ECDSA private key must be 32 bytes"

    assert ecdh_key.salt != ecdsa_key.salt, \
        "Both private keys used the same salt"

    assert ecdh_key.nonce != ecdsa_key.nonce, \
        "Both private keys used the same nonce"

    print("Test 11 passed: Protected-key structure")

def test_change_password_with_wrong_old_password():

    users.clear()

    register_user(
        "mayar",
        "Mayar123"
    )

    original_record = users["mayar"]

    original_password_record = (
        original_record["password_protection"]
    )

    original_protected_keys = (
        original_record["protected_private_keys"]
    )

    result = change_password( 
        "mayar",
        "WrongPassword",
        "NewMayar456"
    )

    assert result is False, \
        "Wrong old password was accepted"

    # Stored records must not be modified
    assert (
        users["mayar"]["password_protection"]
        is original_password_record
    ), "Password record changed after failed operation"

    assert (
        users["mayar"]["protected_private_keys"]
        is original_protected_keys
    ), "Protected keys changed after failed operation"

    # Original password must still work
    assert login_user(
        "mayar",
        "Mayar123"
    ) is True, \
        "Original password stopped working"

    print("Wrong-old-password test passed")


# ============================================================
# Run all automatic tests
# ============================================================

def run_all_tests():

    print("\n=== Running SecureVault Tests ===\n")

    test_password_protection()
    test_registration()
    test_different_users()
    test_login()
    test_login_and_key_recovery()
    test_ciphertext_tampering()
    test_tag_tampering()
    test_nonce_tampering()
    test_key_type_tampering()
    test_wrong_password_recovery()
    test_protected_key_structure()
    test_change_password_with_wrong_old_password()

    users.clear()

    print("\nAll SecureVault authentication and key tests passed")


# ============================================================
# Main menu
# ============================================================

def main():

    while True:

        print("\n=== SecureVault Test Menu ===")
        print("1. Register a user")
        print("2. Login")
        print("3. Login and unlock private keys")
        print("4. Show registered users")
        print("5. Run all automatic tests")
        print("6. Clear temporary users")
        print("7. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            manual_registration()

        elif choice == "2":
            manual_login()

        elif choice == "3":
            manual_login_and_unlock()

        elif choice == "4":
            show_registered_users()

        elif choice == "5":
            run_all_tests()

        elif choice == "6":
            users.clear()
            print("Temporary users cleared")

        elif choice == "7":
            print("Test finished")
            break

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()