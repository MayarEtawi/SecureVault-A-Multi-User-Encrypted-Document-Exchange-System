from password_protection import hash_password

from ecdh import generate_keypair as generate_ecdh_keypair
from ecdsa import generate_keypair as generate_ecdsa_keypair

from private_key_protection import protect_private_key


# Temporary storage for registered users
# Later, the server will store these records
users = {}


def register_user(username: str, password: str):

    if not isinstance(username, str):
        raise TypeError("username must be a string")

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    # Remove spaces from the beginning and end
    username = username.strip()

    # Reject empty username or password
    if username == "" or password == "":
        return False

    # Require at least 8 characters
    if len(password) < 8:
        return False

    # Reject duplicate usernames
    if username in users:
        return False

    # ========================================================
    # 1. Protect the login password using Argon2id
    # ========================================================

    password_record = hash_password(password)

    # ========================================================
    # 2. Generate a separate ECDH key pair
    # ========================================================

    ecdh_private_key, ecdh_public_key = (generate_ecdh_keypair())

    # ========================================================
    # 3. Generate a separate ECDSA key pair
    # ========================================================

    ecdsa_private_key, ecdsa_public_key = (generate_ecdsa_keypair())

    # ========================================================
    # 4. Protect the ECDH private key using AES-GCM
    # ========================================================

    protected_ecdh_private_key = protect_private_key( password=password,private_key=ecdh_private_key,key_type="ECDH")

    # ========================================================
    # 5. Protect the ECDSA private key using AES-GCM
    # ========================================================

    protected_ecdsa_private_key = protect_private_key(password=password,private_key=ecdsa_private_key,key_type="ECDSA")

    # ========================================================
    # 6. Create the complete credential record
    # ========================================================

    credential_record = {
        "username": username,

        # Stored Argon2id password verifier
        "password_protection": password_record,

        # Public keys do not need to be secret
        "public_keys": {
            "ecdh": ecdh_public_key,
            "ecdsa": ecdsa_public_key
        },

        # Only encrypted private keys are stored
        "protected_private_keys": {
            "ecdh": protected_ecdh_private_key,
            "ecdsa": protected_ecdsa_private_key
        },

        # Added later by the Certificate Authority
        "certificate": None
    }

    # Store the credential record
    users[username] = credential_record

    return True
