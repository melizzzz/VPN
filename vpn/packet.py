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

def build_tcp_header(src_port, dst_port, seq_num=0, ack_num=0, flags=0, window=65535):
    data_offset = 5  # 5 * 4 = 20 bytes (taille minimale de l'en-tête TCP)
    reserved = 0
    tcp_offset_reserved = (data_offset << 4) + reserved
    tcp_flags = flags  # Exemple : SYN=0x02, ACK=0x10

    checksum = 0  # À calculer si nécessaire
    urgent_pointer = 0

    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port,         # Source Port (2 octets)
                             dst_port,         # Destination Port (2 octets)
                             seq_num,          # Sequence Number (4 octets)
                             ack_num,          # Acknowledgment Number (4 octets)
                             tcp_offset_reserved,  # Data Offset + Reserved (1 octet)
                             tcp_flags,        # Flags (1 octet)
                             window,           # Window Size (2 octets)
                             checksum,         # Checksum (2 octets)
                             urgent_pointer)   # Urgent Pointer (2 octets)
    return tcp_header
