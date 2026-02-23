import random
from typing import List

# -----------------------------
# GLOBAL VARIABLES
# -----------------------------
SEED = 1950775
MODE = "ECB"
# MODE = "CTR"

class AES:

    def text_to_bits(self,text: str, encoding="utf-8") -> str:
            data = text.encode(encoding)
            return ''.join(f'{byte:08b}' for byte in data)

    def bits_to_bytes(self,bitstring: str) -> bytes:
        # Defensive check: bitstring length must be a multiple of 8
        if len(bitstring) % 8 != 0:
            raise ValueError("bitstring length must be a multiple of 8.")
        
        # Convert every 8 bits into a byte
        n = int(bitstring, 2) if bitstring else 0
        return n.to_bytes(len(bitstring) // 8, 'big')

    # ------------------------------
    # AES CONSTANTS
    # ------------------------------
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]

    # Round constants
    RC = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    # ------------------------------
    # Helper Functions
    # ------------------------------
    def bytes_to_state(self,block16: bytes) -> List[List[int]]:
        """
        Convert a 16-byte array into a 4x4 state matrix
        """
        # Defensive programming: check input length
        if len(block16) != 16:
            raise ValueError("Input must be 16 bytes long")
        
        return [list(block16[i:i+4]) for i in range(0, 16, 4)]

    def state_to_bytes(self,state: List[List[int]]) -> bytes:
        """
        Convert a 4x4 state matrix back into a 16-byte array
        """
        return bytes(sum(state, []))

    def xtime02(self,a: int) -> int:
        """
        Multiply a byte by 0x02 in GF(2^8)
        """
        a &= 0xFF
        return ((a << 1) & 0xFF) ^ (0x1B if (a & 0x80) else 0x00)

    def gf_mult(self,a: int, b: int) -> int:
        """
        Multiply two bytes in GF(2^8) 
        """
        a &= 0xFF
        b &= 0xFF
        res = 0
        for _ in range(8):
            if b & 1:
                res ^= a
            a = self.xtime02(a)
            b >>= 1
        return res & 0xFF

    def xor_bytes(self,a: bytes, b: bytes) -> bytes:
        """
        XOR two byte strings of equal length
        """
        if len(a) != len(b):
            raise ValueError("Input byte strings must be of equal length")
        return bytes(x ^ y for x, y in zip(a, b))

    # ------------------------------
    # The round transformations
    # ------------------------------
    def sub_bytes(self,state: List[List[int]]):
        """
        Use an S-box to perform a byte-by-byte substitution of the block
        Designed to be resistant to know cryptanalytic attacks
        """
        for c in range(4):
            for r in range(4):
                state[c][r] = self.S_BOX[state[c][r]]

    def shift_rows(self,state: List[List[int]]):
        """
        A simple permutation: shift row i of the state to the left by i bytes -> diffusion
        """
        for r in range(4):
            row = [state[c][r] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                state[c][r] = row[c]

    def mix_columns(self,state: List[List[int]]):
        """
        Mixing (I have no ideas)
        """
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = self.gf_mult(0x02, s0) ^ self.gf_mult(0x03, s1) ^ s2 ^ s3
            state[1][c] = s0 ^ self.gf_mult(0x02, s1) ^ self.gf_mult(0x03, s2) ^ s3
            state[2][c] = s0 ^ s1 ^ self.gf_mult(0x02, s2) ^ self.gf_mult(0x03, s3)
            state[3][c] = self.gf_mult(0x03, s0) ^ s1 ^ s2 ^ self.gf_mult(0x02, s3)

    def add_round_key(self,state: List[List[int]], round_key: List[List[int]]):
        """
        Bitwise XOR the 128 bits of State with the 128 bits of the round key
        """
        for c in range(4):
            for r in range(4):
                state[c][r] ^= round_key[c][r]

    # ------------------------------
    # Key expansion algorithm
    # ------------------------------
    def rot_word(self,word: List[int]) -> List[int]:
        """
        Perform aa one-byte circular left shift on a word
        """
        return word[1:] + word[:1]

    def sub_word(self,word: List[int]) -> List[int]:
        """
        Perform a byte substitution on each bute of its input, using the S-BOX
        """
        return [self.S_BOX[b] for b in word]

    def key_expansion(self,key: bytes) -> List[bytes]:
        """
        Expand
        """
        # Defensive programming: check key length
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits) long")

        w: List[List[int]] = []
        for i in range(4):
            w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
        
        for i in range(4, 44):
            temp = w[i - 1]
            if i % 4 == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp[0] ^= self.RC[i // 4] # Only perform an XOR of the leftmost byte of the word with the round constant
            w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

        # Group into round keys
        round_keys = []
        for r in range(11):
            round_key = []
            for c in range(4):
                round_key.append(w[4 * r + c])
            round_keys.append(round_key)
        return round_keys

    # ------------------------------
    # Block Cipher Modes of Operation: ECB and CTR
    # ------------------------------
    def ecb_mode(self,plaintext: bytes, key: bytes) -> bytes:
        # Padding 
        if len(plaintext) % 16 != 0:
            padding_length = 16 - (len(plaintext) % 16)
            plaintext += bytes([0] * padding_length)

        out = b""
        for i in range(0, len(plaintext), 16):
            out += self.aes128_encryption_block(plaintext[i:i+16], key)
        return out


    def ctr_mode(self,plaintext: bytes, key: bytes, iv: int = 0) -> bytes:
        out = b""
        counter = iv
        i = 0
        while i < len(plaintext):
            counter_block = counter.to_bytes(16, "big")
            keystream_block = self.aes128_encryption_block(counter_block, key)
            block_size = min(16, len(plaintext) - i)
            out += self.xor_bytes(plaintext[i:i+block_size], keystream_block[:block_size])
            counter = (counter + 1) % (1 << 128)  # Increment counter, wrap around at 2^128
            i += block_size

        return out


    # ------------------------------
    # AES-128 encryption
    # ------------------------------
    def aes128_encryption_block(self,plaintext16: bytes, key16: bytes):
        # Defensive programming: check input lengths
        if len(plaintext16) != 16: 
            raise ValueError("AES block must be 16 bytes long")
        if len(key16) != 16:
            raise ValueError("Key must be 16 bytes long")

        round_keys = self.key_expansion(key16)
        state = self.bytes_to_state(plaintext16)

        # Round 0: AddRoundKey
        self.add_round_key(state, round_keys[0])

        # Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey
        for round in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, round_keys[round])

        # Round 10: SubBytes, ShiftRows, AddRoundKey
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, round_keys[10])

        # Return the encrypted block as bytes
        return self.state_to_bytes(state)

def main():
    aes = AES()
    random.seed(SEED)
    key_int = random.getrandbits(128)
    key16 = key_int.to_bytes(16, "big")

    msg = "All Denison students should take CS402!"
    msg_bits = text_to_bits(msg)

    # first 256 bits
    first256 = msg_bits[:256]
    pt32 = bits_to_bytes(first256)

    if MODE == "ECB":
        ct = ecb_mode(pt32, key16)
    elif MODE == "CTR":
        ct = ctr_mode(pt32, key16, iv=0)
    else:
        raise ValueError("MODE must be 'ECB' or 'CTR'.")

    print("=== Project 1 Part 2 (ECB/CTR) ===")
    print("MODE:", MODE)
    print("SEED:", SEED)
    print("AES-128 key (hex):", key16.hex())
    print("Message:", msg)
    print("Message bits (first 256):", first256)
    print("Plaintext first 256 bits (hex):", pt32.hex())
    if MODE == "CTR":
        print("CTR initial counter (hex):", (0).to_bytes(16, "big").hex())
    print("Ciphertext (hex):", ct.hex())

if __name__ == "__main__":
    main()