from auth.Register import register_user
from auth.Login import login_user, login_and_unlock
from client.download import download_file
from client.upload import upload_file
from client.socket_client import send_request
from client.version_store import save_version ,get_version
from client.share import share_document
from client.receive_share import list_incoming_shares, receive_share
from pki.ca_admin import load_ca_public_key
from pathlib import Path
from auth.certificate_enrollment import request_certificate_offline
import os
from crypto.freshness import VersionTracker, ReplayError
TRUSTED_CA_PUBLIC_PATH = Path(os.environ.get(
    "SECUREVAULT_TRUSTED_CA_PUBLIC",
    str(Path(__file__).resolve().parent / "client" / "trusted_ca_public.json")
))
uploaded_documents = {}
# from client.download import download_file
# from client.share import share_document

uploaded_filenames = {}  # (username, filename) -> document_id
session = None


share_version_tracker = VersionTracker()

def register():
    username = input("Username: ")
    password = input("Password: ")

    trusted_ca_public_key = load_ca_public_key(
        "client/trusted_ca_public.json"
    )

    if register_user(
        username,
        password,
        request_certificate_offline,
        trusted_ca_public_key,
    ):
        print("Registration successful")
    else:
        print("Registration failed")


def login():

    global session
    username = input("Username: ")
    password = input("Password: ")

    session = login_and_unlock(username,password)

    if session:
        print("Login successful")
    else:
        print("Invalid username or password")

def upload():
    if session is None:
        print("Please login first")
        return

    path = input("Document path: ").strip()

    # Windows file paths: take the filename after the last backslash.
    filename = path.replace("\\", "/").split("/")[-1]
    username = session["username"]
    file_identity = (username, filename)

    # If this filename was uploaded before, reuse its document ID.
    document_id = uploaded_filenames.get(file_identity)

    if document_id is None:
        # First upload: upload_file generates a new ID, version 1.
        result = upload_file(path, username)
    else:
        # Existing document: same ID, next version.
        next_version = get_version(username, document_id) + 1

        result = upload_file(path,username,document_id=document_id,version=next_version)

    if result is None:
        print("Upload failed")
        return

    document_id = result["document_id"]

    uploaded_filenames[file_identity] = document_id
    uploaded_documents[document_id] = result["document_key"]

    save_version(username, document_id,result["version"])

    print("Upload successful")
    print("Filename:", filename)
    print("Version:", result["version"])
    
def download():
    if session is None:
        print("Please login first")
        return

    response = send_request({
        "type": "LIST_DOCUMENTS",
        "owner_id": session["username"]
    })

    documents = response.get("documents", [])

    if not documents:
        print("You have no documents")
        return

    print("\nYour documents:")
    for number, item in enumerate(documents, start=1):
     print(f"{number}. {item['filename']}")

    try:
        choice = int(input("Choose document number: "))
    except ValueError:
        print("Invalid choice")
        return

    if not 1 <= choice <= len(documents):
        print("Invalid choice")
        return

    document_id = documents[choice - 1]["document_id"]

    if document_id not in uploaded_documents:
        print("Document key not available in this session")
        return

    output_path = input("Save path: ").strip()

    download_file(
    document_id,
    uploaded_documents[document_id],
    output_path,
    minimum_version=get_version(session["username"], document_id)
)

def share():
    if session is None:
        print("Please login first")
        return
    documents = send_request({"type": "LIST_DOCUMENTS", "owner_id": session["username"]}).get("documents", [])
    available = [item for item in documents if item["document_id"] in uploaded_documents]
    if not available:
        print("No document keys available in this session")
        return
    for number, item in enumerate(available, 1):
        print(f"{number}. {item['filename']}")
    try:
        selected = int(input("Choose document number: "))
        if not 1 <= selected <= len(available):
            raise ValueError
        ca_public = load_ca_public_key(str(TRUSTED_CA_PUBLIC_PATH))
    except (ValueError, OSError):
        print("Invalid selection or trusted CA key unavailable")
        return
    document_id = available[selected - 1]["document_id"]
    recipient = input("Recipient username: ").strip()
    share_document(document_id, uploaded_documents[document_id], recipient,
                   session, ca_public, get_version(session["username"], document_id))


def receive():
    if session is None:
        print("Please login first")
        return
    shares = list_incoming_shares(session["username"])
    if not shares:
        print("No incoming shares")
        return
    for number, (_, record) in enumerate(shares, 1):
        print(f"{number}. From {record.sender_username}: {record.document_id} (version {record.version})")
    try:
        selected = int(input("Choose share number: "))
        if not 1 <= selected <= len(shares):
            raise ValueError
        ca_public = load_ca_public_key(str(TRUSTED_CA_PUBLIC_PATH))
    except (ValueError, OSError):
        print("Invalid selection or trusted CA key unavailable")
        return
    output_path = input("Save path: ").strip()
    if output_path:
        receive_share(shares[selected - 1][1], session, ca_public, output_path)
    else:
        print("Save path required")


def menu():

    while True:

        print("""
========================
      SecureVault
========================

1. Register
2. Login
3. Upload document
4. Download document
5. Share document
6. Receive shared document
7. Exit

========================""")


        choice = input("Enter you Choose: ")
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            upload()
        elif choice == "4":
            download()
        elif choice == "5":
            share()
        elif choice == "6":
            receive()
        elif choice == "7":
                    print( "Goodbye")
                    break
        else:
            print( "Invalid choice")

if __name__ == "__main__":

    menu()