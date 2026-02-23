import matplotlib.pyplot as plt
import random
from time import time
from Crypto.Cipher import AES as PyAES 
from Crypto.Util.Padding import pad
from project2_part1 import RSA
from part2 import AES

"""
Project 2 - AES and RSA runtime comparison
This file compares the encryption runtimes of RSA and AES
for messages of different lengths. 

"""
# Parameters
message_lengths = [16, 32, 64, 128, 256, 512, 1024]  # in characters
rsa_times = []
aes_times = []
py_aes_times = []

# Seed for reproducibility
seed = 1962481
random.seed(seed)

#  Helper function 
def text_to_bits(text: str) -> str:
    return ''.join(f'{ord(c):08b}' for c in text)

rsa = RSA() # generate keys

# Runtime comparison
for length in message_lengths:
    # Generate random alphanumeric message
    message = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=length))

    # RSA timing
    t0 = time()
    ciphertext_blocks = rsa.encrypt_message(message)
    rsa_times.append(round(time() - t0, 6))

    # AES timing
    t0 = time()
    plaintext_bits = text_to_bits(message)

    # ECB mode
    block_size = 128
    i = 0
    while i < len(plaintext_bits):
        block = plaintext_bits[i:i + block_size]
        # pad block if needed
        if len(block) < block_size:
            block = block.ljust(block_size, '0')
        AES.encryptBlock(block)
        i += block_size

    aes_times.append(round(time() - t0, 6))

    # Python AES timing
    key = b'ThisIsOurOwnPKey'  # AES 128-bit key
    cipher = PyAES.new(key, PyAES.MODE_ECB)  # simplest mode for benchmarking

    t0 = time()       
    plaintext_bytes = message.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, PyAES.block_size) # padding

    cipher.encrypt(padded_plaintext) # encrypt messages
    py_aes_times.append(round(time() - t0, 6))

# Print results
print("\n--- Encryption Times ---")
print("Message lengths:", message_lengths)
print("RSA times (s):", rsa_times)
print("AES times (s):", aes_times)
print("Python AES times (s):", py_aes_times)

# Plot results
plt.figure(figsize=(8,5))
plt.plot(message_lengths, rsa_times, marker='o', label='RSA')
plt.plot(message_lengths, aes_times, marker='s', label='AES')
plt.plot(message_lengths, py_aes_times, marker='v', label='Py-AES')

plt.xlabel("Message Length (characters)")
plt.ylabel("Encryption Time (seconds)")
plt.title("RSA vs AES vs Python-based AES Encryption Time")
plt.legend()
plt.grid(True)
plt.show()