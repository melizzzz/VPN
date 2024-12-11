import os
import socket
import struct
import ctypes
from ctypes import wintypes

# Windows-specific constants
TAP_IOCTL_SET_MEDIA_STATUS = 0x4004aa41
TAP_IOCTL_CONFIG_TUN = 0x4004aa42
FILE_DEVICE_UNKNOWN = 0x22
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

# TAP Device Path
TAP_DEVICE_GUID = "EAF2F59F-B7D4-482A-83B7-C876B7E8B30B"  # Remplacez par votre GUID réel
TAP_PATH = rf"\\.\Global\{TAP_DEVICE_GUID}.tap"




def configure_tap():
    # Ouvrir l'adaptateur TAP
    tap_handle = ctypes.windll.kernel32.CreateFileW(
        TAP_PATH,
        wintypes.DWORD(0xC0000000),  # GENERIC_READ | GENERIC_WRITE
        wintypes.DWORD(0),          # Pas de partage
        None,                       # Pas d'attributs de sécurité
        wintypes.DWORD(3),          # OPEN_EXISTING
        wintypes.DWORD(0),          # Aucun drapeau
        None                        # Pas de modèle de fichier
    )
    if tap_handle == -1:
        raise Exception("Impossible d'ouvrir le TAP-Windows Adapter")

    print("TAP-Windows Adapter ouvert avec succès.")

    # Configurer l'interface en mode TUN
    tun_ip = socket.inet_aton("10.0.0.1") + socket.inet_aton("255.255.255.0")
    tun_cmd = struct.pack("4s4s", tun_ip, b"\x00" * 4)

    bytes_returned = wintypes.DWORD(0)
    status = ctypes.windll.kernel32.DeviceIoControl(
        tap_handle,
        TAP_IOCTL_CONFIG_TUN,
        tun_cmd,
        len(tun_cmd),
        None,
        0,
        ctypes.byref(bytes_returned),
        None
    )
    if not status:
        raise Exception("Erreur lors de la configuration du TAP-Windows Adapter")

    print("Interface TAP configurée avec l'adresse 10.0.0.1/24.")

    # Retourne le handle pour lecture/écriture
    return tap_handle

def send_test_packet(tap_handle):
    # Prépare un paquet simulé
    test_packet = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x01\xa6\xec\x0a\x00\x00\x01\x0a\x00\x00\x02"

    bytes_written = wintypes.DWORD(0)
    status = ctypes.windll.kernel32.WriteFile(
        tap_handle,
        test_packet,
        len(test_packet),
        ctypes.byref(bytes_written),
        None
    )
    if not status:
        raise Exception("Erreur lors de l'envoi du paquet sur TAP-Windows Adapter")

    print("Paquet de test envoyé via TAP.")

def listen_tap(tap_handle):
    print("Écoute des paquets sur TAP...")
    buffer = ctypes.create_string_buffer(2048)

    while True:
        bytes_read = wintypes.DWORD(0)
        status = ctypes.windll.kernel32.ReadFile(
            tap_handle,
            buffer,
            len(buffer),
            ctypes.byref(bytes_read),
            None
        )
        if not status:
            raise Exception("Erreur lors de la lecture du TAP-Windows Adapter")

        print(f"Paquet reçu : {buffer.raw[:bytes_read.value]}")

if __name__ == "__main__":
    try:
        # Configure l'interface TAP
        tap_handle = configure_tap()

        # Envoyer un paquet de test
        send_test_packet(tap_handle)

        # Écoute des paquets
        listen_tap(tap_handle)

    except Exception as e:
        print(f"Erreur : {e}")
