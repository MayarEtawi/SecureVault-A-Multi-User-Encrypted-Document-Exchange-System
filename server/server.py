import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)
import socket
import pickle

from storage import get_document_record, save_user, get_user, get_all_users,save_document,get_document,list_user_documents,save_share,get_share,get_all_shares



HOST = "127.0.0.1"
PORT = 5001



def handle_request(request):

    request_type = request["type"]


    # =========================
    # REGISTER
    # =========================

    if request_type == "REGISTER":

        result = save_user(
            request["username"],
            request["credential_record"]
        )

        return {
            "status": result
        }



    # =========================
    # GET USER LOGIN
    # =========================

    elif request_type == "GET_USER":

        user = get_user(
            request["username"]
        )


        if user is None:

            return {
                "status": False
            }


        return {
            "status": True,
            "credential_record": user
        }



    # =========================
    # SHOW USERS
    # =========================

    elif request_type == "GET_USERS":

        return {
            "status": True,
            "users": get_all_users()
        }


    # =========================
    # STORE DOCUMENT
    # =========================
    elif request_type == "UPLOAD_DOCUMENT":
        existing = get_document_record(request["document_id"])

        if existing is not None and existing["owner_id"] != request["owner_id"]:
         return {"status": False}

        save_document(
        request["document_id"],
        request["document"],
        request["owner_id"],
        request["filename"]
    )

        return {"status": True}

    # =========================
    # LIST USER DOCUMENTS
    # =========================
    elif request_type == "LIST_DOCUMENTS":
        return {
            "status": True,
            "documents": list_user_documents(request["owner_id"])
        }

    # =========================
    # GET DOCUMENT
    # =========================
    elif request_type == "DOWNLOAD_DOCUMENT":
        record = get_document_record(request["document_id"])

        if record is None:
            return {"status": False}

        return {
            "status": True,
            "document": record["protected_document"],
            "filename": record["filename"],
        }

    # =========================
    # SHARE RECORD
    # =========================

    elif request_type == "SHARE":

        save_share(
            request["share_id"],
            request["share_record"]
        )


        return {
            "status": True
        }



    # =========================
    # GET SHARES
    # =========================

    elif request_type == "GET_SHARES":

        return {
            "status": True,
            "shares": get_all_shares()
        }



    return {
        "status": False,
        "message": "Unknown request"
    }
def receive_exactly(connection, size):
    data = bytearray()

    while len(data) < size:
        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed before all data arrived")

        data.extend(chunk)

    return bytes(data)


def start_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )


    server.bind(
        (HOST, PORT)
    )


    server.listen()


    print(
        f"Server running on {HOST}:{PORT}"
    )


    while True:

        client, address = server.accept()


        print(
            "Client connected:",
            address
        )


        with client:
            request_size = int.from_bytes(receive_exactly(client, 8),"big")
            data = receive_exactly(client, request_size)

            request = pickle.loads(data)
            response = handle_request(request)

            response_data = pickle.dumps(response)
            client.sendall(len(response_data).to_bytes(8, "big"))
            client.sendall(response_data)



if __name__ == "__main__":

    start_server()
