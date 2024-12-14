from cryptography.fernet import Fernet


def extract_all_components(data):
    index = 0
    length_iv = int.from_bytes(data[0:index+2], 'big')
    index += 2
    iv = data[index:index+length_iv]
    index += length_iv

    # Lire le nombre de schémas
    schemas_count = int.from_bytes(data[index:index+2], 'big')
    index += 2
    schemas = []
    for _ in range(schemas_count):
        sc_length = int.from_bytes(data[index:index+2], 'big')
        index += 2
        sc = list(data[index:index+sc_length])
        index += sc_length
        schemas.append(sc)

    length_s_box = int.from_bytes(data[index:index+2], 'big')
    index += 2
    s_box = list(data[index:index+length_s_box])
    index += length_s_box

    payload = data[index:]
    return iv, schemas, s_box, payload



def decrypt_with_iv_schema(iv, schema, s_box, data, crypt):
    """Déchiffre un message avec les paramètres donnés."""
    return crypt.decrypt(data, iv, schema, s_box, len(schema))


def encrypt_message(key, msg):
    """Chiffre un message pour le transmettre."""
    f = Fernet(key)
    return f.encrypt(msg)


def decrypt_message(key, encrypted_msg):
    """Déchiffre un message reçu."""
    f = Fernet(key)
    return f.decrypt(encrypted_msg)
