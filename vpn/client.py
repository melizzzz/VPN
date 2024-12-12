import socket
import struct
import crypt
import packet
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        message = input("Please enter your message: ")
        message_bytes = message.encode('utf-8')
        key = ENCRYPTION_KEY
        s_box = crypt.generate_s_box()
        nb_keys = 6

        header = packet.build_ip_header("127.0.0.1", "127.0.0.1")
        payload = header + message_bytes

        encrypted_msg, iv, schema = crypt.encrypt(payload, key, s_box, nb_keys)
        encrypted_msg_bytes = bytes(encrypted_msg)
        client_socket.send(encrypted_msg_bytes)

        response = client_socket.recv(1024).decode('utf-8')
        print(f"Réponse du serveur : {response}")

    except Exception as e:
        print(f"Une erreur est survenue: {e}")
    finally:
        client_socket.close()
        print("Connexion fermée.")

if __name__ == "__main__":
    start_client()