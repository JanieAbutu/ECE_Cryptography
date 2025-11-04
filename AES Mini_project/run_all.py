import sys
import os
import hashlib

sys.path.append(os.path.dirname(__file__))

from aes_utils import key_expansion, hamming_distance
from aes_encrypt_dcrypt import aes_encrypt_block, aes_decrypt_block

# ------------------------------
# Helper functions
# ------------------------------

def pkcs7_pad(block):
    """Pad a byte array to 16 bytes using PKCS#7 style padding"""
    pad_len = 16 - len(block) % 16
    return block + [pad_len] * pad_len

def pkcs7_unpad(block):
    """Remove PKCS#7 padding"""
    pad_len = block[-1]
    return block[:-pad_len]

def text_to_bytes(text):
    """Convert string to list of byte values"""
    return [b for b in text.encode('utf-8')]

def password_to_aes_key(password):
    """Derive 16-byte AES key from any-length password"""
    hash_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    return list(hash_bytes[:16])

def parse_input(user_input):
    """
    Determine if input is numeric (space-separated 0-255) or text.
    Returns list of bytes.
    """
    try:
        # Attempt to parse as integers
        nums = [int(x) for x in user_input.strip().split()]
        if all(0 <= n <= 255 for n in nums):
            return nums
    except ValueError:
        pass
    # If not numeric, treat as text
    return text_to_bytes(user_input)

# ------------------------------
# Main
# ------------------------------

if __name__ == "__main__":
    print("=== AES Mini-Project ===")

    # User input
    plaintext_input = input("Enter plaintext (text or 16-bit numbers 0-255, space-separated): ")
    password_input = input("Enter key/password (text or numbers 0-255, space-separated): ")

    # Convert to bytes
    plaintext_bytes = parse_input(plaintext_input)
    padded_plaintext = pkcs7_pad(plaintext_bytes)

    key_bytes = parse_input(password_input)
    # Ensure key_bytes is exactly 16 bytes for AES-128
    if len(key_bytes) != 16:
        key_bytes = password_to_aes_key(password_input)

    # Generate round keys
    round_keys = key_expansion(key_bytes)

    # Encrypt all blocks
    ciphertext = []
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        ciphertext.extend(aes_encrypt_block(block, round_keys))

    # Decrypt all blocks
    decrypted_bytes = []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_bytes.extend(aes_decrypt_block(block, round_keys))

    # Remove padding
    decrypted_bytes = pkcs7_unpad(decrypted_bytes)
    try:
        decrypted_text = bytes(decrypted_bytes).decode('utf-8')
    except UnicodeDecodeError:
        decrypted_text = str(decrypted_bytes)  # fallback to byte list

    # Display results
    print("\nOriginal Plaintext: ", plaintext_input)
    print("Ciphertext (bytes): ", ciphertext)
    print("Decrypted Text:     ", decrypted_text)

        # ------------------------------
    # Avalanche test per block (detailed)
    # ------------------------------
    print("\n=== Detailed Avalanche Test per 16-byte block ===")
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        modified_block = block[:15] + [block[15] ^ 0x01]  # flip last bit of last byte
        
        cipher_original = aes_encrypt_block(block, round_keys)
        cipher_modified = aes_encrypt_block(modified_block, round_keys)
        
        distance = hamming_distance(cipher_original, cipher_modified)
        
        print(f"\nBlock {i//16 + 1}:")
        print(" Original Block:       ", block)
        print(" Modified Block:       ", modified_block)
        print(" Ciphertext Original:  ", cipher_original)
        print(" Ciphertext Modified:  ", cipher_modified)
        print(" Hamming Distance:     ", distance)
   
