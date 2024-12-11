import socket
import struct

from config import SERVER_IP, SERVER_PORT, ENCRYPTION_KEY



def start_client():
    # Utilisation d'IPv4 (AF_INET) car l'adresse IP est en IPv4
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    message = "Bonjour je suis connectée"
    key = ENCRYPTION_KEY
    s_box = generate_s_box()
    nb_keys = 6
    encrypted_msg, iv, schema = encrypt(message, key, s_box, nb_keys)


    schema_bytes = bytes(schema)
    payload = struct.pack(
        f""
    )


    client_socket.send(payload)

    response = client_socket.recv(1024).decode('utf-8')
    print(f"Réponse du serveur : {response}")

    client_socket.close()

if __name__ == "__main__":
    start_client()

"""import socket
import subprocess
import config

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Erreur commande : {cmd}\n{result.stderr}")
    else:
        print(result.stdout)

def set_tap_ip(interface_name, ip, mask="255.255.255.0"):
    cmd = f'netsh interface ip set address name="{interface_name}" static {ip} {mask}'
    run_cmd(cmd)

def add_default_route(interface_name, gateway="10.8.0.1"):
    # Identifier l'index de l'interface
    cmd = 'netsh interface ip show interfaces'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    lines = result.stdout.splitlines()
    idx = None
    for line in lines:
        if interface_name in line:
            parts = line.split()
            if len(parts) > 0 and parts[0].isdigit():
                idx = parts[0]
                break

    if idx:
        # Ajouter une route par défaut via le gateway
        # Supprimer les routes par défaut existantes (optionnel)
        # run_cmd(f'netsh interface ip delete route 0.0.0.0/0 interface={idx} gateway={gateway}')
        # Ajouter une route par défaut
        run_cmd(f'netsh interface ip add route 0.0.0.0/0 interface={idx} gateway={gateway}')
    else:
        print("Impossible de trouver l'index de l'interface TAP.")

def start_client():
    SERVER_IP = config.SERVER_IP # Remplace par l'IP de ton serveur
    SERVER_PORT = config.SERVER_PORT
    interface_name = "TAP-Windows Adapter V9"

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    assigned_ip = client_socket.recv(1024).decode('utf-8')
    if assigned_ip == "NO_IP":
        print("Pas d'IP disponible sur le serveur.")
        client_socket.close()
        return

    print(f"IP attribuée : {assigned_ip}")
    set_tap_ip(interface_name, assigned_ip)

    # Ajouter la route par défaut via le VPN
    add_default_route(interface_name)

    # Envoyer un message au serveur
    message = f"Bonjour, j'ai maintenant {assigned_ip}"
    client_socket.send(message.encode('utf-8'))

    response = client_socket.recv(1024).decode('utf-8')
    print("Réponse du serveur :", response)

    client_socket.close()

if __name__ == "__main__":
    start_client()
"""