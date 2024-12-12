import struct 
import socket

def build_ip_header(src_ip, dst_ip):
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',  # Format des champs
        69,               # Version (4) + longueur de l'en-tête (5 mots de 32 bits)
        0,                # Type of Service
        40,               # Longueur totale (doit être recalculée si on ajoute TCP/UDP)
        54321,            # ID
        0,                # Flags + Fragment Offset
        64,               # TTL
        socket.IPPROTO_TCP,  # Protocole (TCP ici)
        0,                # Checksum (à recalculer si nécessaire)
        socket.inet_aton(src_ip),  # Source IP
        socket.inet_aton(dst_ip)   # Destination IP

    )
    return ip_header

"""
rc_ip = '127.0.0.1'
dst_ip = '127.0.0.1'
ip_header = build_ip_header(src_ip, dst_ip)
payload =b"coucou"
packet = ip_header + payload"""

"""
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.connect((dst_ip, 443))
print("oucou")
sock.sendto(packet, (dst_ip, 443))
sock.close()

"""
"""import socket

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
"""