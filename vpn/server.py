import socket
import crypt_utils
import network_utils
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()

    print(f"Serveur en écoute sur {SERVER_IP}:{SERVER_PORT}")

    while True:
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connecté par {addr}")
            while True:
                data = conn.recv(4096)
                if not data:
                    break

                # Déchiffrement Fernet
                msg = network_utils.decrypt_message(ENCRYPTION_KEY, data)

                # Extraire iv, schemas, s_box, payload
                iv, schemas, s_box, payload = network_utils.extract_all_components(msg)  
                # Note: extract_all_components doit être adaptée pour lire tous les schémas

                # Déchiffrement final
                # On passe 'schemas' (une liste de schémas) au lieu de 'schema'
                decrypted_msg = crypt_utils.decrypt(payload, iv, ENCRYPTION_KEY.encode("utf-8"), s_box, schemas, 6)

                # Retirer les 20 octets du header IP, puis décoder en UTF-8
                header_size = 20
                text_data = bytes(decrypted_msg[header_size:])
                try:
                    text_message = text_data.decode('utf-8')
                    print(f"Message déchiffré : {text_message}")
                except UnicodeDecodeError:
                    print("Impossible de décoder le message en UTF-8.")

if __name__ == "__main__":
    start_tcp_server()
