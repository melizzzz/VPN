# client_vpn.py
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

def open_tun_interface(ifname="tun1"):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', ifname.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd

def configure_interface(ifname="tun1", addr="10.0.0.2", netmask="255.255.255.0"):
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

def build_raw_icmp_packet(src_ip, dst_ip, payload):
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    tos = 0
    total_length = 20 + 8 + len(payload)
    identification = 54321
    flags_fragment = 0x4000
    ttl = 64
    protocol = socket.IPPROTO_ICMP
    ip_checksum = 0

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ver_ihl, tos, total_length, identification,
                            flags_fragment, ttl, protocol, ip_checksum,
                            src_addr, dst_addr)

    ip_chksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ver_ihl, tos, total_length, identification,
                            flags_fragment, ttl, protocol, ip_chksum,
                            src_addr, dst_addr)

    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 1234
    icmp_seq = 1

    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    icmp_checksum = checksum(icmp_header + payload)
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    ip_packet = ip_header + icmp_header + payload

    return ip_packet

def handle_server_response(conn, tun_fd):
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                break
            os.write(tun_fd, data)
    except Exception as e:
        print(f"Erreur de réception du serveur: {e}")
    finally:
        conn.close()
        print("Connexion au serveur fermée.")

def tun_to_server(tun_fd, conn):
    while True:
        try:
            packet = os.read(tun_fd, 2048)
            if packet:
                conn.sendall(packet)
        except Exception as e:
            print(f"Erreur lors de l'envoi au serveur: {e}")
            break

def main():
    if len(sys.argv) != 4:
        print("Usage: sudo python3 client_vpn.py <VPN_SERVER_IP> <VPN_PORT> <DEST_IP>")
        sys.exit(1)

    VPN_SERVER_IP = sys.argv[1]
    VPN_PORT = int(sys.argv[2])
    DEST_IP = sys.argv[3]

    try:
        socket.inet_aton(DEST_IP)
    except socket.error:
        print("DEST_IP n'est pas une adresse IPv4 valide.")
        sys.exit(1)

    tun_fd = open_tun_interface("tun1")
    configure_interface("tun1", "10.0.0.2", "255.255.255.0")

    print("Prêt à lire/écrire des paquets sur l'interface TUN.")

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((VPN_SERVER_IP, VPN_PORT))
        print(f"Connecté au serveur VPN {VPN_SERVER_IP}:{VPN_PORT}")
    except Exception as e:
        print(f"Erreur de connexion au serveur VPN: {e}")
        sys.exit(1)

    threading.Thread(target=handle_server_response, args=(conn, tun_fd), daemon=True).start()
    threading.Thread(target=tun_to_server, args=(tun_fd, conn), daemon=True).start()

    payload = b"bonjour!"
    packet = build_raw_icmp_packet("10.0.0.2", DEST_IP, payload)
    print("Paquet ICMP construit (hex) :", packet.hex())

    try:
        os.write(tun_fd, packet)
        print("Paquet ICMP envoyé dans l'interface TUN.")
    except Exception as e:
        print(f"Erreur lors de l'envoi du paquet : {e}")
        sys.exit(1)

    time.sleep(2)

    try:
        while True:
            resp = os.read(tun_fd, 2048)
            if resp:
                print("Réponse reçue du TUN (hex) :", resp.hex())

                if len(resp) < 20:
                    print("Paquet reçu trop court pour un paquet IP.")
                    continue

                ip_header = resp[:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                protocol = iph[6]
                src_addr = socket.inet_ntoa(iph[8])
                dst_addr = socket.inet_ntoa(iph[9])

                print(f"Version: {version}, IHL: {ihl}, Protocol: {protocol}")
                print(f"Source: {src_addr}, Destination: {dst_addr}")

                if protocol == socket.IPPROTO_ICMP:
                    if len(resp) < iph_length + 8:
                        print("Paquet ICMP trop court.")
                        continue
                    icmp_header = resp[iph_length:iph_length+8]
                    icmph = struct.unpack('!BBHHH', icmp_header)
                    icmp_type = icmph[0]
                    icmp_code = icmph[1]
                    icmp_id = icmph[2]
                    icmp_seq = icmph[3]
                    print(f"ICMP Type: {icmp_type}, Code: {icmp_code}, ID: {icmp_id}, Seq: {icmp_seq}")

                    if icmp_type == 0:
                        print("Réponse ICMP Echo Reply reçue.")
                    else:
                        print(f"Autre type de message ICMP reçu: Type {icmp_type}")
                else:
                    print("Paquet reçu n'est pas un paquet ICMP.")
    except KeyboardInterrupt:
        print("Client VPN arrêté.")
    finally:
        os.close(tun_fd)
        conn.close()
        print("Interface TUN fermée et connexion au serveur fermée.")

if __name__ == "__main__":
    main()
