# ----------------------
# AES Encryption and Decryption Core Functions
# ----------------------

# Import AES core transformations
from aes_core import sub_bytes, shift_rows, mix_columns, add_round_key, inv_sub_bytes, inv_shift_rows, inv_mix_columns

# ----------------------
# AES Encryption (Single 128-bit Block)
# ----------------------
#Encrypts a single 16-byte (128-bit) block of plaintext using AES-128.
#plaintext: List of 16 bytes (integers 0–255)
#round_keys: List of 11 round keys (each a 4x4 byte matrix)
#Returns:  List of 16 encrypted bytes (ciphertext)

# Convert plaintext (1D list) into a 4x4 state matrix (column-major order)
def aes_encrypt_block(plaintext, round_keys):
    state = [[plaintext[r + 4*c] for c in range(4)] for r in range(4)]

    # Initial round — AddRoundKey
    state = add_round_key(state, round_keys[0])

     # Main 9 rounds
    for rnd in range(1,10):
        state = sub_bytes(state) # Step 1: Substitute bytes using S-box
        state = shift_rows(state) # Step 2: Shift each row by offset
        state = mix_columns(state)  # Step 3: Mix data within columns
        state = add_round_key(state, round_keys[rnd]) # Step 4: XOR with round key

    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    # Flatten 4x4 state matrix back to 16-byte ciphertext
    return [state[r][c] for c in range(4) for r in range(4)]

# ----------------------
# AES Decryption (Single 128-bit Block)
# ----------------------
#Decrypts a single 16-byte (128-bit) block of ciphertext using AES-128.
#ciphertext: List of 16 bytes (integers 0–255)
#round_keys: List of 11 round keys (each a 4x4 byte matrix)

#Returns List of 16 decrypted bytes (original plaintext)

def aes_decrypt_block(ciphertext, round_keys):
    # Convert ciphertext (1D list) into a 4x4 state matrix (column-major order)
    state = [[ciphertext[r + 4*c] for c in range(4)] for r in range(4)]

    # Initial round — start with last round key
    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state) # Step 1: Undo row shifts
    state = inv_sub_bytes(state)  # Step 2: Undo byte substitution

    # Main 9 rounds (reverse order)
    for rnd in range(9,0,-1):
        state = add_round_key(state, round_keys[rnd]) # Step 3: XOR with round key
        state = inv_mix_columns(state) # Step 4: Undo column mixing
        state = inv_shift_rows(state) #Undo row shifts
        state = inv_sub_bytes(state) # Step 6: Undo byte substitution

    # Final round — AddRoundKey using initial key
    state = add_round_key(state, round_keys[0])
    return [state[r][c] for c in range(4) for r in range(4)]
