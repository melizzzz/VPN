# test_fernet.py

from cryptography.fernet import Fernet, InvalidToken

FERNET_KEY = b'g1Y4M6vLwN9qI2fF7Y8aC9ZtB1dXkP3vY4mO5pQ6rS8='

def test_fernet():
    try:
        f = Fernet(FERNET_KEY)
        message = b"Ceci est un message de test."
        encrypted = f.encrypt(message)
        print(f"Message chiffré: {encrypted}")

        decrypted = f.decrypt(encrypted)
        print(f"Message déchiffré: {decrypted}")

        assert message == decrypted, "Le message déchiffré ne correspond pas au message original."
        print("Test Fernet réussi.")
    except InvalidToken:
        print("Erreur: Token invalide.")
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    test_fernet()
