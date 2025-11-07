# ----------------------
# AES Utility Functions
# ----------------------
# Import AES S-box for use in key expansion
from aes_core import s_box

# ----------------------
# Round Constants (Rcon)
# ----------------------
# Used in key expansion to make each round key unique.
# Each value corresponds to 2^(i-1) in GF(2^8).

r_con = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# ----------------------
# Helper Functions for Key Expansion
# ----------------------

# Key Expansion
def rotate(word): return word[1:] + word[:1]                #Rotates a 4-byte word left by one byte.                                                          
def sub_word(word): return [s_box[b] for b in word]         #Applies the AES S-box substitution to each byte in a 4-byte word. Used during key expansion to add non-linearity.


# ----------------------
# AES Key Expansion (Key Schedule)
# ----------------------
#Expands a 16-byte (128-bit) cipher key into 44 4-byte words (11 round keys of 16 bytes each) for AES-128 encryption and decryption.
#key: List of 16 bytes (integers 0–255)
# Returns: List of 11 round keys, each a 4x4 matrix of bytes.

def key_expansion(key): 
    w = [list(key[i:i+4]) for i in range(0,16,4)]           # Step 1: Divide the original key into four 4-byte words
    for i in range(4,44):                                   # Step 2: Generate 40 more words to form all 44 words (AES-128)
        temp = w[i-1][:]                                    # Copy previous word
        
        
        if i%4==0:
            temp = sub_word(rotate(temp))                       # Rotate and apply S-box
            temp[0] ^= r_con[i//4 - 1]                          # XOR first byte with round constant
        w.append([w[i-4][j]^temp[j] for j in range(4)])         # XOR with the word 4 positions earlier to create new word
    round_keys = [w[i:i+4] for i in range(0,44,4)]              # Step 3: Group every 4 words into one round key (total 11 round keys)
    return round_keys

# Hamming Distance (for Avalanche Test) -  Calculates the Hamming distance between two byte arrays (i.e., the number of differing bits).
def hamming_distance(b1,b2):
    return sum(bin(x^y).count('1') for x,y in zip(b1,b2))
