import sys
import os
sys.path.append(os.path.dirname(__file__))

from aes_utils import key_expansion, hamming_distance
from aes import aes_encrypt_block, aes_decrypt_block

if __name__ == "__main__":
    print("=== AES Mini-Project ===")

    # Dynamic user input for plaintext and key
    try:
        plaintext = [int(x) for x in input("Enter 16-byte plaintext (0-255, space separated): ").split()]
        key = [int(x) for x in input("Enter 16-byte key (0-255, space separated): ").split()]
    except ValueError:
        print("Error: Please enter only integers between 0 and 255.")
        exit(1)

    if len(plaintext) != 16 or len(key) != 16:
        print("Error: Plaintext and key must be exactly 16 bytes each.")
        exit(1)

    # Key expansion
    round_keys = key_expansion(key)

    # Encrypt and decrypt
    ciphertext = aes_encrypt_block(plaintext, round_keys)
    decrypted = aes_decrypt_block(ciphertext, round_keys)

    # Display results
    print("\nOriginal Plaintext: ", plaintext)
    print("Ciphertext:         ", ciphertext)
    print("Decrypted Text:     ", decrypted)

    # Avalanche Test: flip 1 bit in plaintext
    modified_plain = plaintext[:15] + [plaintext[15] ^ 0x01]
    cipher_mod_plain = aes_encrypt_block(modified_plain, round_keys)
    print("\nHamming distance (1 bit flipped in plaintext):",
          hamming_distance(ciphertext, cipher_mod_plain))

    # Avalanche Test: flip 1 bit in key
    modified_key = key[:15] + [key[15] ^ 0x01]
    round_keys_mod = key_expansion(modified_key)
    cipher_mod_key = aes_encrypt_block(plaintext, round_keys_mod)
    print("Hamming distance (1 bit flipped in key):      ",
          hamming_distance(ciphertext, cipher_mod_key))
