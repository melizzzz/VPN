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