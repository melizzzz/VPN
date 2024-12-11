from vpn.crypt import *


def decrypt(encrypted_bloc, iv, key, s_box, schema, nb_subkeys):
    subkeys = generate_subkey(key,nb_subkeys)[::-1]

    for keys in subkeys :
        encrypted_bloc = [b ^ keys[i % len(keys)] for i, b in enumerate(encrypted_bloc)]
        encrypted_bloc = permute_bloc_with_schema(encrypted_bloc, [schema.index(i) for i in range(len(schema))])
        reverse_s_box = {v: k for k , v in s_box}
        encrypted_bloc = [encrypted_bloc[k] for k in reverse_s_box]

    bloc = [b ^ iv[i] for i, b in enumerate(encrypted_bloc)]
    return bloc