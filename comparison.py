import matplotlib.pyplot as plt
import random
from time import time
from Crypto.Cipher import AES as PyAES
from Crypto.Util.Padding import pad
from project2_part1 import RSA
from aes import AES

"""
Project 2 - AES and RSA runtime comparison
This file compares the encryption runtimes of RSA and AES
for messages of different lengths. 

"""
# Parameters
MODE = "ECB"
message_lengths = [512, 1024, 2048, 5000, 7500, 10000, 25000, 50000,
                   750000, 100000, 250000, 500000, 750000, 1000000]  # in characters
rsa_times = []
rsa_key_times = []
aes_times = []
aes_key_times = []


# Seed for reproducibility
seed = 1962481
random.seed(seed)

#  Helper function


def text_to_bits(text: str) -> str:
    return ''.join(f'{ord(c):08b}' for c in text)


rsa = RSA()  # generate keys
aes = AES()
# Runtime comparison

for length in message_lengths:
    print("Running Message length: ", length)
    rsa_key_time = 0
    rsa_final_time = 0
    aes_key_time = 0
    aes_final_time = 0
    num_runs = 10
    for i in range(num_runs):
        # Generate random alphanumeric message
        message = ''.join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=length))

        # RSA timing
        t0 = time()
        n, d = rsa.key_generation()
        rsa_key_time = rsa_key_time + (time() - t0)

        ciphertext_blocks = rsa.encrypt_message(message, n)
        rsa_final_time = rsa_final_time + (time() - t0)

        # AES timing
        t0 = time()

        key_int = random.getrandbits(128)
        aes_key_time = aes_key_time + (time() - t0)
        key16 = key_int.to_bytes(16, "big")

        msg_bits = text_to_bits(message)

        # first 256 bits
        first256 = msg_bits[:256]
        pt32 = aes.bits_to_bytes(first256)

        if MODE == "ECB":
            ct = aes.ecb_mode(pt32, key16)

        aes_final_time = aes_final_time + (time() - t0)
    rsa_key_times.append(round(rsa_key_time/num_runs, 6))
    rsa_times.append(round(rsa_final_time/num_runs, 6))
    aes_key_times.append(round(aes_key_time/num_runs, 6))
    aes_times.append(round(aes_final_time/num_runs, 6))


# Print results
print("\n--- Encryption Times ---")
print("Message lengths:", message_lengths)
print("RSA times (s):", rsa_times)
print("AES times (s):", aes_times)

# plt.subplot(1,3,1)

# Plot results
plt.figure(figsize=(8, 5))
plt.plot(message_lengths, rsa_times, marker='o', label='RSA')
plt.plot(message_lengths, aes_times, marker='s', label='AES')

plt.xlabel("Message Length (characters)")
plt.ylabel("Encryption Time (seconds)")
plt.title("RSA vs AES Overall Runtime")
plt.legend()
plt.grid(True)
# plt.show

# ______________________________________________________________

print("\n--- Encryption Times ---")
print("Message lengths:", message_lengths)
print("RSA times (s):", rsa_times)
print("RSA Key times (s):", rsa_key_times)

# plt.subplot(1,3,2)

# Plot results RSA Key Gen vs Overall
plt.figure(figsize=(8, 5))
plt.plot(message_lengths, rsa_times, marker='o', label='RSA Overall Runtime')
plt.plot(message_lengths, rsa_key_times,
         marker='s', label='RSA Key Generation')

plt.xlabel("Message Length (characters)")
plt.ylabel("Runtime(seconds)")
plt.title("RSA Key Generation vs Overall Runtime ")
plt.legend()
plt.grid(True)
# plt.show()


# ______________________________________________________________________________


print("\n--- Encryption Times ---")
print("Message lengths:", message_lengths)
print("AES times (s):", aes_times)
print("AES Key times (s):", aes_key_times)

# plt.subplot(1,3,3)

# Plot results RSA Key Gen vs Overall
plt.figure(figsize=(8, 5))
plt.plot(message_lengths, aes_times, marker='o', label='AES Overall Runtime')
plt.plot(message_lengths, aes_key_times,
         marker='s', label='AES Key Generation')

plt.xlabel("Message Length (characters)")
plt.ylabel("Runtime(seconds)")
plt.title("AES Key Generation vs Overall Runtime ")
plt.legend()
plt.grid(True)
plt.show()
