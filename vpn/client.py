import socket
import crypt_utils
import network_utils
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY
import packet


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        message = input("Please enter your message: ")
        key = ENCRYPTION_KEY.encode("utf-8")
        s_box = crypt_utils.generate_s_box()
        nb_keys = 6

        ip_header = packet.build_ip_header("127.0.0.1", "127.0.0.1")
        #tcp_header = packet
        payload = ip_header + message.encode("utf-8")

        # On suppose que crypt_utils.encrypt renvoie maintenant :
        # encrypted_msg, iv, schemas
        # schemas est une liste de schémas, chaque schéma étant une liste d'entiers
        encrypted_msg, iv, schemas = crypt_utils.encrypt(payload, key, s_box, nb_keys)


        # Préparer les données des schémas
        # schemas_data : [2 octets: nombre de schémas] + Pour chaque schéma : [2 octets longueur] + schéma en bytes
        schemas_count = len(schemas)
        schemas_data = schemas_count.to_bytes(2, 'big')
        for sc in schemas:
            # Chaque schéma est une liste d'entiers
            # On s'assure que sc est une liste d'entiers [0..255], compatible avec bytes(sc)
            schemas_data += len(sc).to_bytes(2, 'big') + bytes(sc)

        # Construire le message final :
        # [2 octets len(iv)] + iv + [schemas_data] + [2 octets len(s_box)] + s_box + encrypted_msg
        final_msg = network_utils.encrypt_message(
            ENCRYPTION_KEY,
            len(iv).to_bytes(2, "big")
            + iv
            + schemas_data
            + len(s_box).to_bytes(2, "big")
            + bytes(s_box)
            + bytes(encrypted_msg)
        )

        client_socket.send(final_msg)
        response = client_socket.recv(1024)
        print(f"Réponse du serveur : {network_utils.decrypt_message(ENCRYPTION_KEY, response)}")

    except Exception as e:
        print(f"Une erreur est survenue: {e}")
    finally:
        client_socket.close()
        print("Connexion fermée.")

if __name__ == "__main__":
    start_client()
