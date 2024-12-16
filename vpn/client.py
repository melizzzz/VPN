import socket
import crypt_utils
import network_utils
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY
import packet

def build_payload(src_ip, src_port):
    dest_ip = '216.58.214.174'  # Exemple : IP de Google
    dest_port = 80
    message = (
        "GET /search?q=python HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "Range: bytes=0-999\r\n"
        "Connection: close\r\n\r\n"
    )
    key = ENCRYPTION_KEY.encode("utf-8")
    s_box = crypt_utils.generate_s_box(256)
    nb_keys = 6

    ip_header = packet.build_ip_header(src_ip, dest_ip)
    tcp_header = packet.build_tcp_header(src_port, dest_port)

    return key, s_box, nb_keys, tcp_header + ip_header + message.encode('utf-8')

def prepare_final_message(iv, schemas, s_box, encrypted_msg):
    schemas_count = len(schemas)
    schemas_data = schemas_count.to_bytes(2, 'big')
    for sc in schemas:
        schemas_data += len(sc).to_bytes(2, 'big') + bytes(sc)
    return network_utils.encrypt_message(
        ENCRYPTION_KEY,
        len(iv).to_bytes(2, "big")
        + iv
        + schemas_data
        + len(s_box).to_bytes(2, "big")
        + bytes(s_box)
        + bytes(encrypted_msg)
    )

def recv_all(socket, length):
    data = b""
    while len(data) < length:
        part = socket.recv(length - len(data))
        if not part:
            raise ConnectionError("Connexion interrompue")
        data += part
    return data

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    src_ip, src_port = client_socket.getsockname()
    key, s_box, nb_keys, payload = build_payload(src_ip, src_port)

    encrypted_msg, iv, schemas = crypt_utils.encrypt(payload, key, s_box, nb_keys)
    final_msg = prepare_final_message(iv, schemas, s_box, encrypted_msg)
    client_socket.send(final_msg)

    complete_decrypted_message = b''

    while True:
        try:
            # Lire l'en-tête pour connaître la taille du segment
            header = recv_all(client_socket, 4)
            segment_length = int.from_bytes(header, "big")
            segment = recv_all(client_socket, segment_length)

            decrypted_segment = network_utils.decrypt_message(ENCRYPTION_KEY, segment)
            iv, schemas, s_box, segment_payload = network_utils.extract_all_components(decrypted_segment)
            decrypted_message = crypt_utils.decrypt(segment_payload, iv, ENCRYPTION_KEY.encode("utf-8"), s_box, schemas, 6)
            print("Segment déchiffré:", decrypted_message.decode('utf-8', errors='replace'))
            complete_decrypted_message += decrypted_message
        except ConnectionError:
            print("Connexion fermée par le serveur.")
            break

    print("Message complet déchiffré:", complete_decrypted_message.decode('utf-8', errors='replace'))
    client_socket.close()

if __name__ == "__main__":
    start_client()
