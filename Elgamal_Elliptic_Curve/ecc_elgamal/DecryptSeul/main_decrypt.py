import re
from ecc_decryptor import decrypt_message

def parse_point(text):
    """Parse a point like (154,155) or 154,155 or [154 155]."""
    nums = re.findall(r"\d+", text)
    if len(nums) != 2:
        raise ValueError("Invalid point format for r. Expected something like (154,155)")
    return (int(nums[0]), int(nums[1]))

def parse_cipher(cipher_input):
    """Parse ciphertext entries like ((x,y), offset)."""
    pattern = r"\((\d+),\s*(\d+)\)\s*,\s*(\d+)"
    matches = re.findall(pattern, cipher_input)

    if not matches:
        raise ValueError("Invalid ciphertext format. Expected entries like ((x,y), offset)")

    cipher = []
    for x_str, y_str, offset_str in matches:
        cipher.append(((int(x_str), int(y_str)), int(offset_str)))

    return cipher


def main():
    print("\n=== ECC ElGamal Decryption Only ===\n")

    # ----- Curve parameters -----
    p = int(input("Enter prime p: "))
    a = int(input("Enter curve coefficient a: "))
    b = int(input("Enter curve coefficient b: "))

    # ----- Base point -----
    R_x = int(input("Enter base point R.x: "))
    R_y = int(input("Enter base point R.y: "))
    R = (R_x, R_y)

    # ----- Private key -----
    dB = int(input("Enter private key dA: "))

    # ----- Ciphertext -----
    cipher_input = input("\nEnter ciphertext: ")
    r_input = input("Enter r (point): ")

    cipher = parse_cipher(cipher_input)
    r_point = parse_point(r_input)

    # ----- Decrypt -----
    decrypted_message = decrypt_message(cipher, r_point, a, p, dB)

    print("\n--- Decrypted Message ---\n")
    print(decrypted_message)
    print()


if __name__ == "__main__":
    main()
