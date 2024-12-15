import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"Connecté au serveur {SERVER_IP}:{SERVER_PORT}")

        # Requête HTTP simple
        message = (
            "GET / HTTP/1.1\r\n"
            "Host: httpbin.org\r\n"
            "Connection: close\r\n\r\n"
        )
        print(f"Envoi du message : {message}")
        client_socket.sendall(message.encode('utf-8'))

        response = client_socket.recv(4096)
        print(f"Réponse du serveur : {response.decode('utf-8')}")

    except Exception as e:
        print(f"Erreur côté client : {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
