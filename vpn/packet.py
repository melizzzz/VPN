import struct
import socket

def build_ip_header(src_ip, dst_ip):
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',  # Format des champs
        69,               # Version (4) + longueur de l'en-tête (5 mots de 32 bits)
        0,                # Type of Service
        40,               # Longueur totale
        54321,            # ID
        0,                # Flags + Fragment Offset
        64,               # TTL
        socket.IPPROTO_TCP,  # Protocole TCP
        0,                # Checksum (doit être recalculée si nécessaire)
        socket.inet_aton(src_ip),  # IP source
        socket.inet_aton(dst_ip)   # IP destination
    )
    return ip_header

src_ip = '127.0.0.1'  # Adresse source (localhost)
dst_ip = '127.0.0.1'  # Adresse destination (localhost)

# Construire le paquet
ip_header = build_ip_header(src_ip, dst_ip)
payload = b'message'
packet = ip_header + payload

# Créer le socket brut
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.sendto(packet, (dst_ip, 0))  # Envoyer vers localhost
    print("Paquet envoyé avec succès.")
except PermissionError:
    print("Erreur : Les sockets bruts nécessitent des privilèges administrateur.")
except Exception as e:
    print(f"Erreur inattendue : {e}")
