# serveur_vpn.py
import os
import fcntl
import struct
import subprocess
import sys
import socket
import threading
import time

# Constantes tirées de linux/if_tun.h
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# Configuration
TUN_NAME = "tun0"                # Nom de l'interface TUN
TUN_IP = "10.0.0.1"              # Adresse IP de l'interface TUN
TUN_NETMASK = "255.255.255.0"    # Masque réseau
VPN_PORT = 5000                   # Port d'écoute du serveur VPN
SERVER_IP = "0.0.0.0"             # Écoute sur toutes les interfaces

clients = []
clients_lock = threading.Lock()

def open_tun_interface(ifname="tun0"):
    # Ouvre /dev/net/tun
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    # Prépare la structure ifreq pour configurer l'interface
    ifr = struct.pack('16sH', ifname.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    # Appel ioctl pour créer/configurer l'interface TUN
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd

def configure_interface(ifname="tun0", addr="10.0.0.1", netmask="255.255.255.0"):
    try:
        subprocess.run(["ip", "addr", "replace", f"{addr}/24", "dev", ifname], check=True)
        subprocess.run(["ip", "link", "set", ifname, "up"], check=True)
        print(f"Interface {ifname} configurée avec IP {addr}/24")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la configuration de l'interface : {e}")
        sys.exit(1)

def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def parse_ip_packet(packet):
    if len(packet) < 20:
        return None
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    payload = packet[iph_length:]
    return (version, ihl, protocol, s_addr, d_addr, payload, packet)

def handle_client(conn, addr, tun_fd):
    print(f"Nouvelle connexion depuis {addr}")
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                break
            os.write(tun_fd, data)
    except Exception as e:
        print(f"Erreur avec le client {addr}: {e}")
    finally:
        conn.close()
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        print(f"Connexion fermée pour {addr}")

def forward_packets(tun_fd):
    raw_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_icmp.settimeout(5)

    while True:
        try:
            packet = os.read(tun_fd, 2048)
            parsed = parse_ip_packet(packet)
            if not parsed:
                continue
            version, ihl, protocol, s_addr, d_addr, payload, original_packet = parsed

            if protocol == socket.IPPROTO_ICMP:
                try:
                    # Reconstruire le paquet ICMP Echo Request
                    icmp_request = struct.pack('!BBHHH', 8, 0, 0, 1234, 1) + payload
                    icmp_checksum_val = checksum(icmp_request)
                    icmp_request = struct.pack('!BBHHH', 8, 0, icmp_checksum_val, 1234, 1) + payload

                    # Construire le paquet IP
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                                            (version << 4) + ihl,
                                            0,  # TOS
                                            20 + 8 + len(payload),
                                            54321,
                                            0x4000,
                                            64,
                                            protocol,
                                            0,  # Checksum initial
                                            socket.inet_aton(s_addr),
                                            socket.inet_aton(d_addr))

                    ip_chksum = checksum(ip_header)
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                                            (version << 4) + ihl,
                                            0,
                                            20 + 8 + len(payload),
                                            54321,
                                            0x4000,
                                            64,
                                            protocol,
                                            ip_chksum,
                                            socket.inet_aton(s_addr),
                                            socket.inet_aton(d_addr))

                    ip_packet = ip_header + icmp_request

                    # Envoyer le paquet ICMP Echo Request
                    raw_icmp.sendto(ip_packet, (d_addr, 0))
                    print(f"Envoi ICMP Echo Request à {d_addr}")

                    # Attendre la réponse
                    try:
                        response, addr = raw_icmp.recvfrom(65535)
                        print(f"Réponse ICMP reçue de {addr[0]}")

                        # Injecter la réponse dans le TUN
                        os.write(tun_fd, response)
                        print(f"Réponse ICMP envoyée au client via le TUN")
                    except socket.timeout:
                        print(f"Aucune réponse ICMP de {d_addr}")
                except Exception as e:
                    print(f"Erreur lors de la construction/envoi de l'ICMP: {e}")
            else:
                print("Protocole non géré (uniquement ICMP).")
        except Exception as e:
            print(f"Erreur de lecture/envoi: {e}")

def main():
    def interface_exists(name):
        return os.path.exists(f"/sys/class/net/{name}")

    if not interface_exists(TUN_NAME):
        print(f"L'interface {TUN_NAME} n'existe pas. Elle sera créée.")
    else:
        print(f"L'interface {TUN_NAME} existe déjà.")

    tun_fd = open_tun_interface(TUN_NAME)
    configure_interface(TUN_NAME, TUN_IP, TUN_NETMASK)

    print("Prêt à lire/écrire des paquets sur l'interface TUN.")

    threading.Thread(target=forward_packets, args=(tun_fd,), daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, VPN_PORT))
    server.listen(5)
    print(f"Serveur VPN en écoute sur {SERVER_IP}:{VPN_PORT}")

    try:
        while True:
            conn, addr = server.accept()
            with clients_lock:
                clients.append(conn)
            threading.Thread(target=handle_client, args=(conn, addr, tun_fd), daemon=True).start()
    except KeyboardInterrupt:
        print("Serveur VPN arrêté.")
    finally:
        server.close()
        os.close(tun_fd)
        with clients_lock:
            for c in clients:
                c.close()

if __name__ == "__main__":
    main()
