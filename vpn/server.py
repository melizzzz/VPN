import socket
import crypt_utils
import network_utils
from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY

def forward_to_target(dest_ip, dest_port, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
            forward_socket.connect((dest_ip, dest_port))
            forward_socket.sendall(message)
            response = b""
            while True:
                part = forward_socket.recv(4096)
                if not part:
                    break
                response += part
            return response
    except Exception as e:
        print(f"Erreur lors du forwarding : {e}")
        return None

def extract_ip_and_header(decrypted_msg):
    tcp_header_size = 20
    ip_header_size = 20
    header_size = tcp_header_size + ip_header_size

    decrypted_msg = bytes(decrypted_msg)
    tcp_header = decrypted_msg[:tcp_header_size]
    ip_header = decrypted_msg[tcp_header_size:header_size]

    dest_ip = socket.inet_ntoa(ip_header[16:20])  # Destination IP
    dest_port = int.from_bytes(tcp_header[2:4], "big")  # Destination Port

    print(f"Destination IP: {dest_ip}, Destination Port: {dest_port}")
    print(f'Le message reçu par le client : {decrypted_msg[header_size:]}')
    return dest_ip, dest_port, decrypted_msg[header_size:]

def prepare_encrypted_message(encrypted_data, iv, schemas, s_box):
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
        + bytes(encrypted_data)
    )
    return final_msg

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
                try:
                    data = conn.recv(4096)
                except OSError:
                    break
                if not data:
                    break

                msg = network_utils.decrypt_message(ENCRYPTION_KEY, data)
                iv, schemas, s_box, payload = network_utils.extract_all_components(msg)
                decrypted_msg = crypt_utils.decrypt(payload, iv, ENCRYPTION_KEY.encode("utf-8"), s_box, schemas, 6)
                dest_ip, dest_port, text_data = extract_ip_and_header(decrypted_msg)

                response = forward_to_target(dest_ip, dest_port, text_data)
                if response is None:
                    print("Erreur lors du forwarding")
                    break

                # Découpe et envoi des segments chiffrés avec en-tête
                offset = 0
                while offset < len(response):
                    segment = response[offset:offset + 256]
                    encrypted_response, iv, schemas = crypt_utils.encrypt(
                        segment, ENCRYPTION_KEY.encode("utf-8"), s_box, 6
                    )
                    final_msg = prepare_encrypted_message(encrypted_response, iv, schemas, s_box)
                    header = len(final_msg).to_bytes(4, "big")  # En-tête sur 4 octets
                    conn.sendall(header + final_msg)  # Envoi avec l'en-tête
                    offset += 256
                conn.close()
if __name__ == "__main__":
    try:
        start_tcp_server()
    except KeyboardInterrupt:
        print("Serveur arrêté manuellement.")
