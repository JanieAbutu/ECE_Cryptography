# main.py
from ecc_encoder import ec_add, ec_scalar_mul, ec_neg, encode_sentence
from ecc_encryptor import encrypt_message
from ecc_decryptor import decrypt_message

def main():
    print("\n=== ECC ElGamal Full Demo ===")

    # ---------- Curve parameters ----------
    p = int(input("Enter prime p: "))
    a = int(input("Enter curve coefficient a: "))
    b = int(input("Enter curve coefficient b: "))

    # ---------- Base point ----------
    R_x = int(input("Enter base point R.x: ")) 
    R_y = int(input("Enter base point R.y: "))
    R = (R_x, R_y)

    # ---------- Bob's public key ----------
    eB_x = int(input("Enter Bob's public key eB.x: "))
    eB_y = int(input("Enter Bob's public key eB.y: "))
    eB = (eB_x, eB_y)

    # ---------- Sender ephemeral key ----------
    k = int(input("Enter sender ephemeral key k: "))

    # ---------- Message ----------
    message = input("Enter sentence to encrypt: ")

    # ---------- Encrypt ----------
    cipher, r = encrypt_message(message, a, b, p, R, eB, k)

    # Print all ciphertext points on one line with brackets
    cipher_str = " ".join(
        f"({C2}, {offset})" if offset is not None else f"({C2}, None)"
        for C2, offset in cipher
    )
    print("\n--- Encrypted Ciphertext ---")
    print()
    print(cipher_str)
    print("r =", r)



    # ---------- Decrypt ----------
    dB = int(input("\nEnter Bob's private key dB for decryption: "))
    decrypted_message = decrypt_message(cipher, r, a, p, dB)

    print("\n--- Decrypted Message ---")
    print()
    print(decrypted_message)
    print()

if __name__ == "__main__":
    main()
