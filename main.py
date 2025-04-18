from rsa import LiteRSA


if __name__ == "__main__":
    message = "Nico"
    rsa = LiteRSA(message)

    encoded_message = rsa.encrypt(rsa.public_key)
    print("Mensaje Encriptado RSA: ", encoded_message)

    decoded_message = rsa.decrypt(encoded_message)
    print(f"Mensaje Desencriptado RSA: {decoded_message}")
