from math import gcd  # gcp Greates Common Divisor (Mayor Comun Divisor)
import random


class LiteRSA:
    ## Intento de entender RSA
    def __init__(self, message, prime1=7, prime2=17):
        self._user_msg = message
        self._p: int = prime1  # Numero primo
        self._q: int = prime2  # Otro numero primo

        # La multiplicacion de p y q es lo que se usara como modulo para la encriptacion/desencriptacion
        self._modulo: int = self._p * self._q

        # e_raw va a contener la multiplicacion del total de coprimos que tengan p y q
        # Ejemplo: p = 5, tiene 4 coprimos. 1,2,3,4 ya que solo comparten el 1 como comun divisor.
        self._e_raw: int = (self._p - 1) * (self._q - 1)

        self._e: int = self._get_actual_e()
        self._d: int = self._get_d()
        self._private_key: tuple[int, int] = (self._d, self._modulo)
        self._public_key: tuple[int, int] = (self._e, self._modulo)

    def _get_actual_e(self) -> int:
        # Calculo todos los numeros que van desde 1 hasta el valor total de la multiplicacion de (p-1) * (q-1)
        e_raw = self._e_raw
        possible_candidate: int = 1
        # select_the_value es una variable que me sirve para obtener un numero aleatorio entre 2 y 8, asi no obtengo
        # siempre el mismo valor
        select_the_value = random.randint(2, 8)
        counter = 1

        for i in range(e_raw):
            if gcd(i, e_raw) == 1 and i > 1:
                if i > possible_candidate and counter < select_the_value:
                    possible_candidate = i
                    counter += 1
        return possible_candidate

    # Este valor es el que usare para la clave privada (desencriptar)
    def _get_d(self) -> int:
        # Tengo que hallar un numero que cumpla esta formula: (d * e) % e_raw = 1
        counter = 1
        while (self._e * counter) % self._e_raw != 1:
            counter += 1
        return counter

    @property
    def public_key(self) -> tuple[int, int]:
        """Public key is your own public key. You can send it to establish a secure communication"""
        public_key = (self._e, self._modulo)
        return public_key

    def _RSACode(self, letter, public_key: tuple[int, int]):
        return pow(letter, public_key[0], public_key[1])

    def encrypt(self, public_key: tuple[int, int]) -> str:
        if not public_key:
            raise ValueError("You must provide a public key")

        encrypted_msg = ""
        for letter in self._user_msg:
            ascii_letter = ord(letter)
            if ascii_letter < self._modulo:
                encrypted_msg += f"{self._RSACode(ascii_letter, public_key)} "
        return encrypted_msg

    def decrypt(self, encrypted_message: str) -> str:
        private_key = self._private_key
        decoded_msg = ""
        for encrypted_letter in encrypted_message.split(" "):
            if encrypted_letter != "":
                encrypted_number_letter = int(encrypted_letter)
                decoded_value = pow(
                    encrypted_number_letter, private_key[0], private_key[1]
                )
                decoded_msg += chr(decoded_value)
        return decoded_msg
