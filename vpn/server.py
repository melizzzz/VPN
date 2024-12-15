import socket
import crypt_utils
import network_utils
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY

def forward_to_target(dest_ip, dest_port, message):
    """Envoie un message à la cible et retourne la réponse."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
            forward_socket.connect((dest_ip, dest_port))
            forward_socket.sendall(message)
            response = forward_socket.recv(4096)  # Taille max des réponses
            return response
    except Exception as e:
        print(f"Erreur lors du forwarding : {e}")
        return None

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
                ip_header_size = 20
                tcp_header_size = 20
                header_size = ip_header_size + tcp_header_size
                text_data = bytes(decrypted_msg[header_size:])
                print(text_data)
                 # Récupérer destination IP/port depuis les headers IP/TCP

                dest_ip = socket.inet_ntoa(payload[16:20]) # Destination IP
                dest_port = int.from_bytes(payload[22:24], "big")  # Destination Port

                # Forwarder les données vers la cible
                response = forward_to_target(dest_ip, dest_port, text_data)
                if response is None:
                    print("Erreur lors du forwarding")
                    break

                # Chiffrer la réponse avant de la renvoyer au client
                encrypted_response, iv, schemas = crypt_utils.encrypt(
                    response, ENCRYPTION_KEY.encode("utf-8"), s_box, len(schemas)
                )

                # Construire le message final
                schemas_count = len(schemas)
                schemas_data = schemas_count.to_bytes(2, 'big')
                for sc in schemas:
                    schemas_data += len(sc).to_bytes(2, 'big') + bytes(sc)

                final_msg = network_utils.encrypt_message(
                    ENCRYPTION_KEY,
                    len(iv).to_bytes(2, "big")
                    + iv
                    + schemas_data
                    + len(s_box).to_bytes(2, "big")
                    + bytes(s_box)
                    + bytes(encrypted_response)
                )

                # Envoyer au client
                conn.send(final_msg)
                try:
                    text_message = text_data.decode('utf-8')
                    print(f"Message déchiffré : {text_message}")
                except UnicodeDecodeError:
                    print("Impossible de décoder le message en UTF-8.")

if __name__ == "__main__":
    start_tcp_server()
