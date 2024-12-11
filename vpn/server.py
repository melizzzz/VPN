import socket
from crypt import encrypt, decrypt, generate_subkey
from config import SERVER_IP, SERVER_PORT, MAX_CONNECTIONS



def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # af_inet6 pour ipv6 et sock_dgram pour udp
    server_socket.bind((SERVER_IP, SERVER_PORT)) #associe le server au port et a l'ip, le server est à l'écoute
    server_socket.listen(MAX_CONNECTIONS)

    print(f'Démarrage du serveur sur {SERVER_IP}:{SERVER_PORT}')

    while True:

        try:
        #client socket gere une connexion avec un client
            #client address contient lip et le port du client
            client_socket, client_address = server_socket.accept()
            print(f'Connexion acceptée - {client_address}')

            message = client_socket.recv(1024).decode('utf-8')
            print(f'Message reçu {message}')

            response = "Message reçu par le serveur"
            client_socket.send(response.encode('utf-8'))

        except Exception as e :
            print(f"Erreur : {e}")

        finally:
            client_socket.close()





if __name__ == "__main__":
    start_server()

    """import socket
import config

# Définir le pool d'adresses IP
IP_POOL = [f"10.8.0.{i}" for i in range(2, 51)]
allocated_ips = []

def assign_ip():
    for ip in IP_POOL:
        if ip not in allocated_ips:
            allocated_ips.append(ip)
            return ip
    return None

def start_server():
    SERVER_IP = config.SERVER_IP  # Écouter sur toutes les interfaces
    SERVER_PORT = config.SERVER_PORT
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print(f"Serveur démarré sur {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connexion acceptée - {client_address}")

        client_ip = assign_ip()
        if client_ip is None:
            client_socket.send("NO_IP".encode('utf-8'))
            client_socket.close()
            print(f"Pas d'IP disponible pour {client_address}")
            continue

        # Envoyer l'IP au client
        client_socket.send(client_ip.encode('utf-8'))
        print(f"IP {client_ip} attribuée à {client_address}")

        # Recevoir un message du client (optionnel)
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(f"Message du client {client_ip}: {message}")
            response = "Message reçu par le serveur"
            client_socket.send(response.encode('utf-8'))
        except Exception as e:
            print(f"Erreur lors de la communication avec {client_ip} : {e}")

        client_socket.close()

if __name__ == "__main__":
    start_server()
"""