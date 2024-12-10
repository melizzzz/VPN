import os


SERVER_IP = '127.0.0.1'
SERVER_PORT = 443  #faisant réf la connexion OpenVPN TCP qui est plus sécurisée

TRANSPORT_PROTOCOL = 'TCP'

# A faire plus loin dans le code, SQL DATABASE

#clé de chiffrement générée avec "python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())""
ENCRYPTION_KEY  = "-f6wE-M2MfkpX3rmibrQwswqr_3UaUZuQlELBzNqrTc="
#ENCRYPTION_KEY = os.getenv('VPNKey')
#if ENCRYPTION_KEY is None :
  #  raise ValueError("Clé de chiffrement non définie")
#print(ENCRYPTION_KEY)
ENCRYPTION_ALGORITHM = 'AES-256-CBC'

LOGGING_LEVEL = 'DEBUG'

MAX_CONNECTIONS = 50
SESSION_TIMEOUT = 3600