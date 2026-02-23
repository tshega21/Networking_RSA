"""
Project 2 - RSA Encryption
This file utilizes RSA to encrypt and decrypt 
messages and analyzes the runtime based on message length
"""

from time import time
from Crypto.Util.number import getPrime
import math


class RSA:
    def __init__(self, e=65537):
        self.e = e

    def key_generation(self):
        """
        Generates an RSA key pair (n, d) for a given public key e.
        Creates two large primes p and q, computes n = p*q, ensures e is coprime with totient of n.
        Calculates the private key d as e's multiplicative inverse relative to totient of n.

        Returns:
            tuple:
                n (int): RSA modulus (product of p and q).
                d (int): Private key for decryption (multiplicative inverse of self.e mod totient(n)).
        """
        p = getPrime(512)
        q = getPrime(512)

        totient_n = (p - 1) * (q - 1)

        while math.gcd(totient_n, self.e) != 1 or p == q:
            p = getPrime(512)
            q = getPrime(512)
            totient_n = (p - 1) * (q - 1)

        n = p * q

        # Find multiplicative inverse of e relative to totient_n
        d = pow(self.e, -1, totient_n)

        return n, d

    def encryption(self, m, n):
        """
        Encrypts an integer message using RSA.

        Args:
            m (int): The plaintext integer message (must be < n)
            n (int): RSA modulus

        Returns:
            int: Ciphertext
        """
        c = pow(m, self.e, n)
        return c

    def decryption(self, c, n, d):
        """
        Decrypts an integer message using RSA.

        Args:
            c (int): The ciphertext integer message (< n)
            d (int): Private key
            n (int): RSA modulus

        Returns:
            int: Plaintext
        """
        m = pow(c, d, n)
        return m

    def encrypt_message(self, message_string, n):
        """
        Encrypts a string message using RSA with message blocking.

        Args:
            message_string (str): The plaintext string to encrypt.
            n (int): RSA modulus.

        Returns:
            list: A list of ciphertext blocks (integers).
        """
        # Calculate safe block size in bytes. We reserve 1 byte for a marker.
        block_size = ((n.bit_length() - 1) // 8) - 1

        message_bytes = message_string.encode('utf-8')
        ciphertext_blocks = []

        for i in range(0, len(message_bytes), block_size):
            block = message_bytes[i:i + block_size]
            # Prepend a \x01 marker byte to preserve leading zeros and exact block length
            block_with_marker = b'\x01' + block
            m = int.from_bytes(block_with_marker, byteorder='big')
            c = self.encryption(m, n)
            ciphertext_blocks.append(c)

        return ciphertext_blocks

    def decrypt_message(self, ciphertext_blocks, d, n):
        """Decrypts a list of ciphertext blocks back into a string message.

        Args:
            ciphertext_blocks (list): A list of encrypted blocks (integers).
            d (int): Private key component.
            n (int): Modulus n.

        Returns:
            str: The decrypted plaintext string.
        """
        message_bytes = bytearray()

        for c in ciphertext_blocks:
            m = self.decryption(c, n, d)
            byte_length = (m.bit_length() + 7) // 8
            block_with_marker = m.to_bytes(byte_length, byteorder='big')
            # Remove the prepended \x01 marker byte
            block = block_with_marker[1:]
            message_bytes.extend(block)

        return message_bytes.decode('utf-8')


def main():
    rsa = RSA()
    n, d = rsa.key_generation()
    # Message Blocking
    print("\n--- Part 1.4: Message Blocking ---")
    long_message = (
        "This is a significantly long message designed to test the RSA message blocking functionality. "
        "CS402 IS SUCH A FUN CLASS! I REALLY LOVE NETWORK SECURITY! HIPHIPHOORAY! "
        "we can only encrypt messages shorter than n at one time. That's why we are doing this."
        "split into smaller blocks, encrypt each block, and then decrypt and reassemble them. Like a Lego!" * 3
    )

    print(f"Original long message length: {len(long_message)} characters")

    t_0_blocking = time()
    ciphertext_blocks = rsa.encrypt_message(long_message, n)
    encryption_time = time() - t_0_blocking
    print(
        f"Encrypted into {len(ciphertext_blocks)} blocks in {encryption_time:.4f} seconds.")

    t_0_decrypt = time()
    decrypted_long_message = rsa.decrypt_message(ciphertext_blocks, d, n)
    decryption_time = time() - t_0_decrypt
    print(f"Decrypted in {decryption_time:.4f} seconds.")

    assert long_message == decrypted_long_message, "Decryption failed! The messages do not match."
    print("Message Blocking successful! Decrypted message exactly matches the original.")


if __name__ == "__main__":
    main()
