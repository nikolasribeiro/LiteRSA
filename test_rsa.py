import unittest
from rsa import LiteRSA


class TestLiteRSA(unittest.TestCase):

    # Test simple encryption/decription functionallity
    def test_encryption_decryption(self):
        message = "Nicolas Ribeiro"
        rsa = LiteRSA(message)
        encrypted = rsa.encrypt(rsa.public_key)
        decrypted = rsa.decrypt(encrypted)
        self.assertEqual(message, decrypted)

    def test_custom_primes(self):
        message = "Hello, World!"
        rsa1 = LiteRSA(message, prime1=11, prime2=13)
        rsa2 = LiteRSA(message, prime1=17, prime2=19)
        self.assertNotEqual(rsa1.public_key, rsa2.public_key)

    def test_encrypted_comunication_between_two_clients(self):
        msg_client1 = "Hey, Ana!"
        msg_client2 = "hey, Jhon!"

        client1 = LiteRSA(message=msg_client1, prime1=11, prime2=13)
        client2 = LiteRSA(message=msg_client2, prime1=17, prime2=19)

        # Encrypt with the public_key of client2
        encrypted_msg_from_client1 = client1.encrypt(client2.public_key)
        encrypted_msg_from_client2 = client2.encrypt(client1.public_key)

        # Validate that we are receiving different encrypted messages
        self.assertNotEqual(encrypted_msg_from_client1, encrypted_msg_from_client2)

        decoded_msg_for_client2 = client2.decrypt(encrypted_msg_from_client1)
        decoded_msg_for_client1 = client1.decrypt(encrypted_msg_from_client2)

        self.assertEqual(msg_client1, decoded_msg_for_client2)
        self.assertEqual(msg_client2, decoded_msg_for_client1)


if __name__ == "__main__":
    unittest.main()
