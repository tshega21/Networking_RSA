import random
from time import time
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad
import math
# import pandas as pd
# import numpy as np
import matplotlib.pyplot as plt
from numpy.polynomial import Polynomial

"""
Project 2 - RSA Encryption
This file utilizes RSA to encrypt and decrypt 
messages and analyzes the runtime based on message length

def key_generation(e)
def encyrption()

"""
class RSA: 
    def __init__(self, e=65537):
        self.e = e
        self.n, self.d = self.key_generation()
    
    def key_generation(self):
        """
        Generates an RSA key pair (n, d) for a given public key e.
        Creates two large primes p and q, computes n = p*q, ensures e is coprime with totient of n.
        Calculates the private key d as e's multiplicative inverse relative to totient of n.

        Args:
            e (int): Public key (commonly 65537).

        Returns:
            tuple:
                n (int): RSA modulus.
                d (int): Private key for decryption.
        """
        #Should we seed this prime or not? 
        #Should we find our own prime according to what we discussed in class or is getPrime okay?
    
        p = getPrime(512)
        q = getPrime(512)

        totient_n = (p-1)*(q-1)
        
        while (math.gcd(totient_n,self.e)!= 1):
            p = getPrime(512)
            q = getPrime(512)
            totient_n = (p-1)*(q-1)
            
        n = p*q # field n
        
        # find multiplicative inverse of e relative to totient_n
        d = pow(self.e,-1,totient_n)
        
        #returns n, largest value that can be stored using public/private key pair and generated private key
        return n, d

    def encryption(self, m):
        """
        Encrypts an integer message using RSA.
        
        Args:
            m (int): The plaintext integer message (< n)
            e (int): Public key 
            n (int): RSA modulus

        Returns:
            int: Ciphertext
        """
        c = pow(m, self.e, self.n)
        return c

    def decryption(self, c):
        """
        Decrypts an integer message using RSA.
        
        Args:
            c (int): The ciphertext integer message (< n)
            d (int): Private key 
            n (int): RSA modulus

        Returns:
            int: Plaintext
        """
        m = pow(c, self.d, self.n)
        return m


    def encrypt_message(self, message_string):
        """
        Encrypts a string message using RSA with message blocking.

        Args:
            message_string (str): The plaintext string to encrypt.
            e (int): Public key exponent.
            n (int): Modulus n.

        Returns:
            list: A list of ciphertext blocks (integers).
        """
        # Calculate safe block size in bytes. We reserve 1 byte for a marker.
        block_size = ((self.n.bit_length() - 1) // 8) - 1
        
        message_bytes = message_string.encode('utf-8')
        ciphertext_blocks = []
        
        for i in range(0, len(message_bytes), block_size):
            block = message_bytes[i:i+block_size]
            # Prepend a \x01 marker byte to preserve leading zeros and exact block length
            block_with_marker = b'\x01' + block
            m = int.from_bytes(block_with_marker, byteorder='big')
            c = self.encryption(m)
            ciphertext_blocks.append(c)
            
        return ciphertext_blocks

    def decrypt_message(self, ciphertext_blocks):
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
            m = self.decryption(c)
            byte_length = (m.bit_length() + 7) // 8
            block_with_marker = m.to_bytes(byte_length, byteorder='big')
            # Remove the prepended \x01 marker byte
            block = block_with_marker[1:]
            message_bytes.extend(block)
            
        return message_bytes.decode('utf-8')


def main():
    rsa = RSA()
    n, d = rsa.key_generation()
    # messages = [34,30]
    # run_times = []
    # decrypted_messages = []
    # for message in messages:
        
    #     t_0 = time()

    #     c = encryption(message,e,n)
    #     print("cipher text ", c)
    #     d_plaintext = decryption(c,d,n)
    #     print("decrypted plaintext ", d_plaintext)
        
    #     final_time = time()-t_0
    #     run_times.append(final_time)
    #     decrypted_messages.append(d_plaintext)
    #     print("RSA runtime for message ",message, " : ",final_time )
    
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
    ciphertext_blocks = rsa.encrypt_message(long_message)
    encryption_time = time() - t_0_blocking
    print(f"Encrypted into {len(ciphertext_blocks)} blocks in {encryption_time:.4f} seconds.")
    
    t_0_decrypt = time()
    decrypted_long_message = rsa.decrypt_message(ciphertext_blocks)
    decryption_time = time() - t_0_decrypt
    print(f"Decrypted in {decryption_time:.4f} seconds.")
    
    assert long_message == decrypted_long_message, "Decryption failed! The messages do not match."
    print("Message Blocking successful! Decrypted message exactly matches the original.")

    # RSA and AES runtime comparison
    print("\n--- Comparing runtime of RSA and AES ---")
    message_lengths = [16, 32, 64, 128, 256, 512, 1024]  # number of characters
    rsa_times = []
    aes_times = []

    for length in message_lengths:
        # Generate random alphanumeric message
        message = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=length))
        
        # RSA timing
        t0 = time()
        ciphertext_blocks = rsa.encrypt_message(message)
        rsa_times.append(time() - t0)

        # AES timing
        key = b'ThisIsOurOwnPKey'  # AES 128-bit key
        cipher = AES.new(key, AES.MODE_ECB)  # simplest mode for benchmarking

        t0 = time()       
        plaintext_bytes = message.encode('utf-8')
        padded_plaintext = pad(plaintext_bytes, AES.block_size) # padding

        cipher.encrypt(padded_plaintext) # encrypt messages
        aes_times.append(time() - t0)

    # Runtime results
    print("\nRSA encryption times (seconds):", [round(t, 6) for t in rsa_times])
    print("AES encryption times (seconds):", [round(t, 6) for t in aes_times])

    # Plot results
    plt.figure(figsize=(8,5))
    plt.plot(message_lengths, rsa_times, marker='o', label='RSA')
    plt.plot(message_lengths, aes_times, marker='s', label='AES (Cryptodome)')
    plt.xlabel("Message Length (characters)")
    plt.ylabel("Encryption Time (seconds)")
    plt.title("RSA vs AES Encryption Time")
    plt.legend()
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()
    
    