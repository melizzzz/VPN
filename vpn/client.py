import socket
import struct

from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY
from vpn.crypt import generate_s_box, encrypt


def start_client():
    # Utilisation d'IPv4 (AF_INET) car l'adresse IP est en IPv4
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    message = "Bonjour je suis connectée"
    key = ENCRYPTION_KEY
    s_box = generate_s_box()
    nb_keys = 6
    encrypted_msg, iv, schema = encrypt(message, key, s_box, nb_keys)


    schema_bytes = bytes(schema)
    payload = struct.pack(
        f""
    )


    client_socket.send(payload)

    response = client_socket.recv(1024).decode('utf-8')
    print(f"Réponse du serveur : {response}")

    client_socket.close()

if __name__ == "__main__":
    start_client()
