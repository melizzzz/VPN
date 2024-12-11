import socket

# Adresse et port pour le serveur
HOST = '0.0.0.0'  # Écoute sur toutes les interfaces disponibles
PORT = 443      # Choisis un port libre

def start_tcp_server():
    try:
        # Créer un socket TCP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Permettre la réutilisation de l'adresse
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Lier le socket à l'adresse et au port
        server_socket.bind((HOST, PORT))
        
        # Écouter les connexions entrantes
        server_socket.listen()
        print(f"Serveur TCP en écoute sur {HOST}:{PORT}")
        
        while True:
            # Accepter une nouvelle connexion
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connecté par {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Reçu : {data}")
                    
    except Exception as e:
        print(f"Erreur inattendue : {e}")

if __name__ == "__main__":
    start_tcp_server()
