import socket
import crypt_utils
import network_utils
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY
import packet

def build_payload(src_ip, src_port):

        dest_ip = '142.250.185.174' #input("Vers quelle IP souhaitez vous envoyer vos données ?: ")
        dest_port = 80 #int(input("Quel est le port de ce dernier ?: "))
        #message = input("Please enter your message: ")
        message = (
    "GET /search?q=python HTTP/1.1\r\n"
    "Host: www.google.com\r\n"
    "Range: bytes=0-999"
    "Connection: close\r\n\r\n"
)
        key = ENCRYPTION_KEY.encode("utf-8")
        s_box = crypt_utils.generate_s_box()
        nb_keys = 6
        
        ip_header = packet.build_ip_header(src_ip, dest_ip)
        tcp_header = packet.build_tcp_header(src_port, dest_port)

        return key, s_box, nb_keys, tcp_header + ip_header  + message.encode('utf-8')




def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        src_ip, src_port = client_socket.getsockname()
        key, s_box, nb_keys, payload = build_payload(src_ip, src_port)
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
        response = client_socket.recv(4096) 
        print(f"Taille de la réponse reçue : {len(response)}")
        print(f"Réponse reçue : {response}")
      

        decrypted_response = network_utils.decrypt_message(ENCRYPTION_KEY, response)
        
        iv, schemas, s_box, payload = network_utils.extract_all_components(decrypted_response)
        text_data = bytes(crypt_utils.decrypt(payload, iv, ENCRYPTION_KEY.encode("utf-8"), s_box, schemas, 6))  # Ignorer les headers IP et TCP

        try:
            print(f"Réponse déchiffrée : {text_data.decode('utf-8')}")
        except UnicodeDecodeError:
            print("Impossible de décoder la réponse.")


    except Exception as e:
        print(f"Une erreur est survenue: {e}")
    finally:
        client_socket.close()
        print("Connexion fermée.")

if __name__ == "__main__":
    start_client()
