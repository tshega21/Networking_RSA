import random
from time import time
from Crypto.Util.number import getPrime
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from numpy.polynomial import Polynomial
"""
Project 2 - RSA Encryption
This file utilizes RSA to encrypt and decrypt 
messages and analyzes the runtime based on message length

def key_generation(e)
def encyrption()





"""

def key_generation(e):
    """
    Args:
        e (int) - public key
    """
   
    #Should we seed this prime or not? 
    #Should we find our own prime according to what we discussed in class or is getPrime okay?
   
    p = getPrime(512)
    q = getPrime(512)

    totient_n = (p-1)*(q-1)
    
    
    while (math.gcd(totient_n,e)!= 1):
        p = getPrime(512)
        q = getPrime(512)
    
    totient_n = (p-1)*(q-1)
    n = p*q # field n
    
    # find multiplicative inverse of e relative to totient_n
    d = pow(e,-1,totient_n)
    
    #returns n, largest value that can be stored using public/private key pair and generated private key
    return n, d

def encryption(m, e, n):
    """_summary_

    Args:
        m (int): message 
        e (int): _description_
        n (int): 

    Returns:
        _type_: _description_
    """
    c = pow(m,e,n)
    return c
def decryption(c, d, n):
    """_summary_

    Args:
        c (_type_): _description_
        d (_type_): _description_
        n (_type_): _description_

    Returns:
        _type_: _description_
    """
    m = pow(c,d,n)
    return m




def encrypt_message(message_string, e, n):
    """Encrypts a string message using RSA with message blocking.

    Args:
        message_string (str): The plaintext string to encrypt.
        e (int): Public key exponent.
        n (int): Modulus n.

    Returns:
        list: A list of ciphertext blocks (integers).
    """
    # Calculate safe block size in bytes. We reserve 1 byte for a marker.
    block_size = ((n.bit_length() - 1) // 8) - 1
    
    message_bytes = message_string.encode('utf-8')
    ciphertext_blocks = []
    
    for i in range(0, len(message_bytes), block_size):
        block = message_bytes[i:i+block_size]
        # Prepend a \x01 marker byte to preserve leading zeros and exact block length
        block_with_marker = b'\x01' + block
        m = int.from_bytes(block_with_marker, byteorder='big')
        c = encryption(m, e, n)
        ciphertext_blocks.append(c)
        
    return ciphertext_blocks

def decrypt_message(ciphertext_blocks, d, n):
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
        m = decryption(c, d, n)
        byte_length = (m.bit_length() + 7) // 8
        block_with_marker = m.to_bytes(byte_length, byteorder='big')
        # Remove the prepended \x01 marker byte
        block = block_with_marker[1:]
        message_bytes.extend(block)
        
    return message_bytes.decode('utf-8')


def main():
    e = 65537
    n,d = key_generation(e)
    messages = [34,30]
    run_times = []
    decrypted_messages = []
    for message in messages:
        
        t_0 = time()

        c = encryption(message,e,n)
        print("cipher text ", c)
        d_plaintext = decryption(c,d,n)
        print("decrypted plaintext ", d_plaintext)
        
        final_time = time()-t_0
        run_times.append(final_time)
        decrypted_messages.append(d_plaintext)
        print("RSA runtime for message ",message, " : ",final_time )
    
    
    # Message Blocking
    print("\n--- Part 4: Message Blocking ---")
    long_message = (
        "This is a significantly long message designed to test the RSA message blocking functionality. "
        "CS402 IS SUCH A FUN CLASS! I REALLY LOVE NETWORK SECURITY! HIPHIPHOORAY! "
        "we can only encrypt messages shorter than n at one time. That's why we are doing this."
        "split into smaller blocks, encrypt each block, and then decrypt and reassemble them. Like a Lego!" * 3
    )
    
    print(f"Original long message length: {len(long_message)} characters")
    
    t_0_blocking = time()
    ciphertext_blocks = encrypt_message(long_message, e, n)
    encryption_time = time() - t_0_blocking
    print(f"Encrypted into {len(ciphertext_blocks)} blocks in {encryption_time:.4f} seconds.")
    
    t_0_decrypt = time()
    decrypted_long_message = decrypt_message(ciphertext_blocks, d, n)
    decryption_time = time() - t_0_decrypt
    print(f"Decrypted in {decryption_time:.4f} seconds.")
    
    assert long_message == decrypted_long_message, "Decryption failed! The messages do not match."
    print("Message Blocking successful! Decrypted message exactly matches the original.")

if __name__ == "__main__":
    main()
    
    