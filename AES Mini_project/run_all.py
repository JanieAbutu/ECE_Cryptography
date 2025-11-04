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

def bytes_to_hex(byte_list):
    """Convert list of bytes to hex string"""
    return ''.join(f"{b:02x}" for b in byte_list)

# ------------------------------
# Main
# ------------------------------

if __name__ == "__main__":
    print("=== AES Mini-Project that Encrpts, Decrypts, and Avalanche Test when a bit is yesmodified ===")

    # User input
    plaintext_input = input("Enter plaintext (text or 16-bit numbers 0-255, space-separated): ")
    password_input = input("Enter key/password (text or numbers 0-255, space-separated): ")

    print("\nStarting Encryption...")
    print("Converting to bytes...")

    # Convert to bytes
    plaintext_bytes = parse_input(plaintext_input)
    padded_plaintext = pkcs7_pad(plaintext_bytes)

    key_bytes = parse_input(password_input)
    # Ensure key_bytes is exactly 16 bytes for AES-128
    if len(key_bytes) != 16:
        key_bytes = password_to_aes_key(password_input)

    # Generate round keys
    print("Generating round keys...")
    round_keys = key_expansion(key_bytes)

    print("Encrypting all blocks...")

    #Encrypt block by block
    ciphertext_blocks = []
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        enc_block = aes_encrypt_block(block, round_keys)
        ciphertext_blocks.append(enc_block)

    # Encrypt all blocks at once
    ciphertext = []
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        ciphertext.extend(aes_encrypt_block(block, round_keys))

    print("--- Encrypting completed ---")

    # Display Encryption output
    print("\nENCRYPTION OUTPUT:")

    # Display ciphertext per block
    print("\nCiphertext Blocks:")
    for i, blk in enumerate(ciphertext_blocks, 1):
        print(f"   Block {i} (bytes): {blk}")
        print(f"   Block {i} (hex)  : {bytes_to_hex(blk)}\n")

    #print("Original Plaintext: ", plaintext_input)
    print("    Ciphertext (bytes): ", ciphertext)
    print("    Ciphertext (hex):   ", bytes_to_hex(ciphertext))

    
    # Pause before decryption
    input("\nPress Enter to start decryption...")

    print("Starting Decryption...")

    # ------------------------------
    # Decrypt block by block
    # ------------------------------
    #decrypted_bytes = []
    #for blk in ciphertext_blocks:
      #  decrypted_bytes.extend(aes_decrypt_block(blk, round_keys))

    # Remove padding
    #decrypted_bytes = pkcs7_unpad(decrypted_bytes)
    #try:
     #   decrypted_text = bytes(decrypted_bytes).decode('utf-8')
    #except UnicodeDecodeError:
     #   decrypted_text = str(decrypted_bytes)

    #print("\nDecrypted Text: ", decrypted_text)


    # Decrypt all blocks at once
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

    
    print("\n--- Decryption Completed ---")
    print("\nDECRYPTION OUTPUT:")
    print("    Decrypted Text:     ", decrypted_text)

    print("    Original Plaintext for comparison: ", plaintext_input)

        # ------------------------------
    # Avalanche test per block (detailed)
    # ------------------------------
    input("\nPress Enter to start avalanche test...")
    print("STARTING AVALANCHE TEST...")
    print("\n=== Detailed Avalanche Test per 16-byte block ===")
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        modified_block = block[:15] + [block[15] ^ 0x01]  # flip last bit of last byte
        
        cipher_original = aes_encrypt_block(block, round_keys)
        cipher_modified = aes_encrypt_block(modified_block, round_keys)
        
        distance = hamming_distance(cipher_original, cipher_modified)
        
        print(f"Block {i//16 + 1}:")
        print("  Original Block:       ", block)
        print("  Modified Block:       ", modified_block)
        print("  Ciphertext Original:  ", cipher_original)
        print("  Ciphertext Original (hex):", bytes_to_hex(cipher_original))
        print("  Ciphertext Modified:  ", cipher_modified)
        print("  Ciphertext Modified (hex):", bytes_to_hex(cipher_modified))
        print("  Hamming Distance:     ", distance)

    
    # ------------------------------
    # Key sensitivity test
    # ------------------------------
    input("\nPress Enter to start key sensitivity test...")

    print("\n=== KEY SENSITIVITY TEST ===")

    # Flip one bit in the key (e.g., last byte)
    modified_key = key_bytes.copy()
    modified_key[-1] ^= 0x01  # flip last bit of the last key byte

    # Generate round keys for modified key
    round_keys_modified = key_expansion(modified_key)

    # Encrypt the same plaintext block with both keys
    original_cipher = aes_encrypt_block(padded_plaintext[:16], round_keys)
    modified_cipher = aes_encrypt_block(padded_plaintext[:16], round_keys_modified)

    distance_key = hamming_distance(original_cipher, modified_cipher)

    print("Original Key:       ", key_bytes)
    print("Modified Key:       ", modified_key)
    print("Ciphertext Original:", original_cipher)
    print("Ciphertext Modified:", modified_cipher)
    print("Hamming Distance (key change):", distance_key)

    
