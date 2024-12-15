import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080

def forward_to_target(dest_ip, dest_port, message):
    try:
        print(f"Tentative de connexion à {dest_ip}:{dest_port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
            forward_socket.settimeout(10)  # Timeout pour éviter les blocages
            forward_socket.connect((dest_ip, dest_port))
            print(f"Connexion réussie à {dest_ip}:{dest_port}")
            print(f"Envoi du message : {message}")
            forward_socket.sendall(message)
            response = forward_socket.recv(4096)
            print(f"Réponse de la cible : {response.decode('utf-8')}")
            return response
    except Exception as e:
        print(f"Erreur lors du forwarding : {e}")
        return None



def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print(f"Serveur en écoute sur {SERVER_IP}:{SERVER_PORT}")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connecté par {addr}")
        with conn:
            data = conn.recv(4096)
            if not data:
                print("Aucune donnée reçue.")
                break
            print(f"Données reçues du client : {data.decode('utf-8')}")

            # Forwarding vers httpbin.org
            dest_ip = "34.227.92.70"  # IP de httpbin.org
            dest_port = 80
            response = forward_to_target(dest_ip, dest_port, data)

            if response:
                conn.sendall(response)

if __name__ == "__main__":
    start_server()
