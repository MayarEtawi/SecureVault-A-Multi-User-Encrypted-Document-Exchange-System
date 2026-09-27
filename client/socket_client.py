import socket
import pickle

HOST = "127.0.0.1"
PORT = 5001


def receive_exactly(connection, size):
    data = bytearray()

    while len(data) < size:
        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed before the full response arrived")

        data.extend(chunk)

    return bytes(data)


def send_request(request):
    payload = pickle.dumps(request)

    with socket.create_connection((HOST, PORT)) as client:
        # First send the message length, then the complete message.
        client.sendall(len(payload).to_bytes(8, "big"))
        client.sendall(payload)

        response_size = int.from_bytes(
            receive_exactly(client, 8),
            "big"
        )
        response = receive_exactly(client, response_size)

    return pickle.loads(response)
