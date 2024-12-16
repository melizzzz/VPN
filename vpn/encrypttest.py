import unittest
import crypt_utils
import os

class TestEncryptionDecryption(unittest.TestCase):
    def setUp(self):
        # Cette méthode est appelée avant chaque test
        self.key = os.urandom(32)  # Clé aléatoire de 32 bytes
        self.s_box = crypt_utils.generate_s_box()
        self.nb_keys = 2  # Nombre de sous-clés à utiliser

    def test_encryption_decryption(self):
        # Test avec plusieurs tailles de blocs
        for block_size in [256, 512, 1024, 2048, 4096]:
            with self.subTest(block_size=block_size):
                data = os.urandom(block_size)  # Données aléatoires de la taille du bloc
                encrypted_data, iv, schemas = crypt_utils.encrypt(data, self.key, self.s_box, self.nb_keys)
                decrypted_data = crypt_utils.decrypt(encrypted_data, iv, self.key, self.s_box, schemas, self.nb_keys)
                
                # Vérifier que les données déchiffrées correspondent aux données originales
                self.assertEqual(data, decrypted_data, f"Failed for block size {block_size}")

if __name__ == '__main__':
    unittest.main()
