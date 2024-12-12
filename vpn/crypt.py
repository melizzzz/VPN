import os
import random


def generate_iv(bloc_size):
    #Génère un vecteur d'initialisation temporaire
    return os.urandom(bloc_size)

def generate_s_box():
    s_box = list(range(256))
    random.shuffle(s_box)
    return s_box


def sub_bloc(bloc, s_box):
    return [s_box[i] for i in bloc]


def permute_bloc(bloc):
    #Permute un bloc avec un schema généré aléatoirement
    schema=[]
    while len(schema) < len(bloc):
        lettre = int.from_bytes(os.urandom(len(bloc))) % len(bloc)
        if lettre not in schema :
            schema.append(lettre)
    bloc_perm = [bloc[i] for i in schema]
    return bloc_perm, schema


def permute_bloc_with_schema(bloc,schema):
    #Permute un bloc avec un schema généré aléatoirement
    return [bloc[i] for i in schema]



def generate_subkey(key, nb_key):
    subkeys = []
    for i in range (nb_key):
        subkeys.append(bytes([ (ord(b) + i) % 256 for b in key]))
    return subkeys


def encrypt(bloc, key, s_box, nb_keys):
    iv = generate_iv(len(bloc))
    bloc = [b ^ iv[i] for i, b in enumerate(bloc)]
    subkeys = generate_subkey(key, nb_keys)

    for key in subkeys:
        bloc = sub_bloc(bloc, s_box)
        bloc, schema= permute_bloc(bloc)
        bloc = [b ^ key[i % len(key)] for i, b in enumerate(bloc)]
    return bloc, iv, schema


def decrypt(encrypted_bloc, iv, key, s_box, schema, nb_subkeys):
    subkeys = generate_subkey(key,nb_subkeys)[::-1]

    for keys in subkeys :
        encrypted_bloc = [b ^ keys[i % len(keys)] for i, b in enumerate(encrypted_bloc)]
        encrypted_bloc = permute_bloc_with_schema(encrypted_bloc, [schema.index(i) for i in range(len(schema))])
        reverse_s_box = {v: k for k , v in s_box}
        encrypted_bloc = [encrypted_bloc[k] for k in reverse_s_box]

    bloc = [b ^ iv[i] for i, b in enumerate(encrypted_bloc)]
    return bloc # type: ignore