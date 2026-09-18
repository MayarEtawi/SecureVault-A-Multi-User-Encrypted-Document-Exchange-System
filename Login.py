from Register import users ,register_user
from password_protection import verify_password


def login_user(username: str, password: str) :
    """
    Verify a registered user's username and password.
    """

    if not isinstance(username, str):
        raise TypeError("username must be a string")

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    # Remove spaces from the beginning and end
    username = username.strip()

    # Get the stored credential record
    credential_record = users.get(username)

    # Reject an unknown username
    if credential_record is None:
        return False

    # Get the stored Argon2id information
    password_record = credential_record["password_protection"]

    # Verify the entered password
    return verify_password(password, password_record)

if __name__ == "__main__":
    

    print("=== Registration ===")

    register_username = input("Create username: ")
    register_password = input("Create password: ")

    if not register_user(register_username, register_password):
        print("Registration failed")
        raise SystemExit

    print("Registration successful")

    print("\n=== Login ===")

    login_username = input("Username: ")
    login_password = input("Password: ")

    if login_user(login_username, login_password):
        print("Login successful")
    else:
        print("Invalid username or password")