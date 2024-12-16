import os
import random

def generate_iv(block_size):
    """Generate a random initialization vector."""
    return os.urandom(block_size)

def generate_s_box(block_size):
    """Générer une S-box dynamique en fonction de la taille du bloc."""
    s_box = list(range(block_size))
    random.shuffle(s_box)
    return s_box

def sub_block(block, s_box):
    """Substituer les éléments du bloc en utilisant la S-box adaptée."""
    return [s_box[b % len(s_box)] for b in block]

def permute_block(block):
    """Permuter les éléments du bloc en tenant compte de sa taille."""
    schema = list(range(len(block)))
    random.shuffle(schema)
    permuted_block = [block[i] for i in schema]
    return permuted_block, schema

def generate_subkey(key, block_size):
    """Générer une sous-clé de la même longueur que le bloc."""
    import hashlib
    
    # Si la clé est plus courte que le bloc, l'étendre
    if len(key) < block_size:
        # Utiliser un dérivation de clé basée sur SHA-256
        extended_key = hashlib.sha256(key).digest()
        # Répéter la clé étendue pour atteindre la longueur du bloc
        extended_key = (extended_key * (block_size // len(extended_key) + 1))[:block_size]
        return extended_key
    
    # Si la clé est plus longue que le bloc, la tronquer
    elif len(key) > block_size:
        return key[:block_size]
    
    # Si la clé a exactement la bonne longueur
    return key

def permute_block_with_schema(block, schema):
    """Permute block elements using an existing schema."""
    permuted_block = [0] * len(block)
    for i in range(len(block)):
        permuted_block[schema[i]] = block[i]
    return permuted_block


def encrypt(block, key, s_box, nb_keys=1):
    """Chiffrer un bloc avec des sous-clés générées dynamiquement."""
    iv = generate_iv(len(block))
    block = bytes([b ^ iv[i % len(iv)] for i, b in enumerate(block)])
    
    # Générer des sous-clés de la même longueur que le bloc
    subkeys = [generate_subkey(key, len(block)) for _ in range(nb_keys)]

    schemas = []
    for subkey in subkeys:
        block = bytes(sub_block(list(block), s_box))
        block, schema = permute_block(list(block))
        schemas.append(schema)
        
        # Vérifier que la longueur de subkey correspond à la longueur du bloc
        assert len(subkey) == len(block), f"Subkey length {len(subkey)} != Block length {len(block)}"
        
        block = bytes([b ^ subkey[i] for i, b in enumerate(block)])
    
    return block, iv, schemas

def decrypt(encrypted_block, iv, key, s_box, schemas, nb_subkeys=1):
    subkeys = [generate_subkey(key, len(encrypted_block)) for _ in range(nb_subkeys)][::-1]
    for subkey, schema in zip(subkeys, reversed(schemas)):
        encrypted_block = bytes([b ^ subkey[i] for i, b in enumerate(encrypted_block)])
        encrypted_block = bytes(permute_block_with_schema(list(encrypted_block), schema))

        # Reverse the S-box
        reverse_s_box = [0] * 256
        for i, value in enumerate(s_box):
            reverse_s_box[value] = i
        encrypted_block = bytes(sub_block(list(encrypted_block), reverse_s_box))

    block = bytes([b ^ iv[i % len(iv)] for i, b in enumerate(encrypted_block)])
    return block


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