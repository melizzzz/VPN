import socket

def forward_to_target(dest_ip, dest_port, message):
    try:
        print(f"Tentative de connexion à {dest_ip}:{dest_port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
            forward_socket.settimeout(10)  # Timeout pour éviter les blocages
            forward_socket.connect((dest_ip, dest_port))
            print(f"Connexion réussie à {dest_ip}:{dest_port}")
            print(f"Envoi du message : {message}")
            forward_socket.sendall(message.encode('utf-8'))
            response = forward_socket.recv(4096)  # Réception de la réponse
            print(f"Réponse de la cible : {response}")
            return response
    except Exception as e:
        print(f"Erreur lors du forwarding : {e}")
        return None

if __name__ == "__main__":
    dest_ip = "142.250.185.174"  # IP de Google
    dest_port = 80  # Port HTTP
    message = (
        "GET / HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "Connection: close\r\n\r\n"
    )
    response = forward_to_target(dest_ip, dest_port, message)
    if response:
        print("Forwarding réussi !")
