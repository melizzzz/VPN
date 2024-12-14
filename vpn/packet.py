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

"""def build_tcp_header()"""