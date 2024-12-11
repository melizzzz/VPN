import socket

# Adresse IP pour le serveur
HOST = '127.0.0.1'  # Adresse localhost pour tests locaux
PORT = 0  # Les sockets bruts ignorent les ports

def start_server():
    try:
        # Créer un socket brut
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        server_socket.bind((HOST, PORT))

        # Configurer pour recevoir tous les paquets
        server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print(f"Serveur en écoute sur {HOST}")

        while True:
            # Recevoir des données
            data, addr = server_socket.recvfrom(65535)  # Taille max d'un paquet IP

            print(f"Reçu un paquet de {addr}:")
            print(f"Paquet brut : {data}")
            ip_header = data[:20]  # En-tête IP (20 octets)
            payload = data[20:]    # Payload
            print(f"En-tête IP : {ip_header}")
            print(f"Payload : {payload.decode(errors='ignore')}")

    except PermissionError:
        print("Erreur : Les sockets bruts nécessitent des privilèges administrateur.")
    except Exception as e:
        print(f"Erreur inattendue : {e}")

if __name__ == "__main__":
    start_server()
