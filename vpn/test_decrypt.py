def test_decrypt():
    key = b"secret_key"
    s_box = generate_s_box()
    nb_keys = 6

    # Exemple simple
    plaintext = b"Hello, world!"
    encrypted, iv, schemas = encrypt(plaintext, key, s_box, nb_keys)
    decrypted = decrypt(encrypted, iv, key, s_box, schemas, nb_keys)
    assert decrypted == plaintext, f"Erreur : attendu {plaintext}, obtenu {decrypted}"

    print("Test décryptage réussi !")
