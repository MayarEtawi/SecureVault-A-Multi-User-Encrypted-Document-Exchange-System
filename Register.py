from password_protection import hash_password
# Temporary storage for registered users
# Later, the server will store these records
users = {}


def register_user(username: str, password: str) :
   
    if not isinstance(username, str):
        raise TypeError("username must be a string")

    if not isinstance(password, str):
        raise TypeError("password must be a string")
     # Remove spaces from the beginning and end
    username = username.strip()
    # Reject empty username or password
    if username == "" or password == "":
        return False
    if len(password) < 8:
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


