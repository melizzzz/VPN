import os
import random


def generate_iv(bloc_size):
    """Génère un vecteur d'initialisation temporaire."""
    return os.urandom(bloc_size)


def generate_s_box():
    """Génère une S-box aléatoire."""
    s_box = list(range(256))
    random.shuffle(s_box)
    return s_box


def sub_bloc(bloc, s_box):
    """Applique une substitution à un bloc en utilisant une S-box."""
    return [s_box[i] for i in bloc]


def permute_bloc(bloc):
    """Permute un bloc avec un schéma généré aléatoirement."""
    schema = []
    while len(schema) < len(bloc):
        lettre = int.from_bytes(os.urandom(len(bloc))) % len(bloc)
        if lettre not in schema:
            schema.append(lettre)
    bloc_perm = [bloc[i] for i in schema]
    return bloc_perm, schema


def permute_bloc_with_schema(bloc, schema):
    """Permute un bloc en utilisant un schéma existant."""
    return [bloc[i] for i in schema]


def generate_subkey(key, nb_key):
    """Génère des sous-clés à partir de la clé principale."""
    subkeys = []
    for i in range(nb_key):
        subkeys.append(bytes([(b + i) % 256 for b in key]))
    return subkeys


def encrypt(bloc, key, s_box, nb_keys):
    iv = generate_iv(len(bloc))
    bloc = [b ^ iv[i] for i, b in enumerate(bloc)]
    subkeys = generate_subkey(key, nb_keys)

    schemas = []
    for key in subkeys:
        bloc = sub_bloc(bloc, s_box)
        bloc, schema = permute_bloc(bloc)
        schemas.append(schema)
        bloc = [b ^ key[i % len(key)] for i, b in enumerate(bloc)]
    return bloc, iv, schemas

def decrypt(encrypted_bloc, iv, key, s_box, schemas, nb_subkeys):
    subkeys = generate_subkey(key, nb_subkeys)[::-1]

    # Inverser les schémas dans l'ordre inverse d'application
    for keys, schema in zip(subkeys, reversed(schemas)):
        encrypted_bloc = [b ^ keys[i % len(keys)] for i, b in enumerate(encrypted_bloc)]
        encrypted_bloc = permute_bloc_with_schema(
            encrypted_bloc, [schema.index(i) for i in range(len(schema))]
        )

        reverse_s_box_list = [0]*256
        for i, v in enumerate(s_box):
            reverse_s_box_list[v] = i
        encrypted_bloc = sub_bloc(encrypted_bloc, reverse_s_box_list)

    bloc = [b ^ iv[i] for i, b in enumerate(encrypted_bloc)]
    return bloc


"""
def encrypt(bloc, key, s_box, nb_keys):

    iv = generate_iv(len(bloc))
    bloc = [b ^ iv[i] for i, b in enumerate(bloc)]
    subkeys = generate_subkey(key, nb_keys)

    for key in subkeys:
        bloc = sub_bloc(bloc, s_box)
        bloc, schema = permute_bloc(bloc)
        bloc = [b ^ key[i % len(key)] for i, b in enumerate(bloc)]
    return bloc, iv, schema


def decrypt(encrypted_bloc, iv, key, s_box, schema, nb_subkeys):

    subkeys = generate_subkey(key, nb_subkeys)[::-1]
    for keys in subkeys:
        encrypted_bloc = [b ^ keys[i % len(keys)] for i, b in enumerate(encrypted_bloc)]
        encrypted_bloc = permute_bloc_with_schema(
            encrypted_bloc, [schema.index(i) for i in range(len(schema))]
        )

        reverse_s_box_list = [0] * 256
        for i, v in enumerate(s_box):
            reverse_s_box_list[v] = i
        encrypted_bloc = sub_bloc(encrypted_bloc, reverse_s_box_list)

    bloc = [b ^ iv[i] for i, b in enumerate(encrypted_bloc)]
    return bloc 
"""