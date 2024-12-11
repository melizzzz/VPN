import socket

# Adresse et port du serveur
HOST = '127.0.0.1'  # Adresse localhost
PORT = 443          # Doit correspondre au port du serveur

def start_tcp_client():
    try:
        # Créer un socket TCP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connecter au serveur
        client_socket.connect((HOST, PORT))
        print(f"Connecté au serveur {HOST}:{PORT}")
        
        # Envoyer des données
        message = "Hello, serveur!"
        client_socket.sendall(message.encode())
        print(f"Message envoyé : {message}")
        
        # Recevoir une réponse (optionnel)
        # data = client_socket.recv(1024)
        # print(f"Réponse du serveur : {data.decode()}")
        
        # Fermer la connexion
        client_socket.close()
        print("Connexion fermée.")
        
    except Exception as e:
        print(f"Erreur inattendue : {e}")

if __name__ == "__main__":
    start_tcp_client()
