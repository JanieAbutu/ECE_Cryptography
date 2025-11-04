# ----------------------
# AES Utility Functions
# ----------------------

from aes_core import s_box

# Round constants
r_con = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# Key Expansion
def rotate(word): return word[1:] + word[:1]
def sub_word(word): return [s_box[b] for b in word]

def key_expansion(key):
    w = [list(key[i:i+4]) for i in range(0,16,4)]
    for i in range(4,44):
        temp = w[i-1][:]
        if i%4==0:
            temp = sub_word(rotate(temp))
            temp[0] ^= r_con[i//4 - 1]
        w.append([w[i-4][j]^temp[j] for j in range(4)])
    round_keys = [w[i:i+4] for i in range(0,44,4)]
    return round_keys

# Hamming Distance (for Avalanche Test)
def hamming_distance(b1,b2):
    return sum(bin(x^y).count('1') for x,y in zip(b1,b2))
