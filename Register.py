from password_protection import hash_password
# Temporary storage for registered users
# Later, the server will store these records
users = {}


def register_user(username: str, password: str) -> bool:
    # Remove spaces from the beginning and end
    username = username.strip()

    # Reject empty username or password
    if username == "" or password == "":
        return False

    # Reject duplicate usernames
    if username in users:
        return False

    # Call the existing function from password_protection.py
    password_record = hash_password(password)

    # Create the user's credential record
    credential_record = {
        "username": username,
        "password_protection": password_record,

        # These will be added during integration
        "public_keys": None,
        "certificate": None,
        "protected_private_keys": None
    }

    # Store the credential record
    users[username] = credential_record

    return True


# Registration test
username = input("Create username: ")
password = input("Create password: ")

if register_user(username, password):
    print("Registration successful")

    record = users[username]

    print("\nStored credential record:")
    print("Username:", record["username"])
    print(
        "Salt:",
        record["password_protection"]["salt"].hex()
    )
    print(
        "Password hash:",
        record["password_protection"]["password_hash"].hex()
    )

else:
    print("Registration failed")