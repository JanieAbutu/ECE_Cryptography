# main_decrypt.py

from decrypt_message import decrypt_message


def parse_ciphertext(raw):
    """
    Convert user input of the form:
    ((27,105),0) ((97,171),1) ...
    into a Python list: [((27,105),0), ((97,171),1), ...]
    """
    cleaned = raw.replace(";", "").replace("),", ") ,")
    parts = cleaned.split()

    cipher_list = []
    for part in parts:
        if part.strip() == "":
            continue

        # Expect format ((x,y),offset)
        if part.startswith("(") and part.endswith(")"):
            # Remove outer parentheses
            inner = part[1:-1]

            # Split into "(x,y)" and "offset"
            c2_str, offset_str = inner.split("),")
            c2_str = c2_str + ")"  # restore
            offset = int(offset_str.strip())

            # parse point (x,y)
            c2_str = c2_str.strip()[1:-1]  # remove ()
            x_str, y_str = c2_str.split(",")
            C2 = (int(x_str), int(y_str))

            cipher_list.append((C2, offset))

    return cipher_list


def main():
    print("\n=== ECC ElGamal Decryption Only ===\n")

    # Fixed parameters from the question
    p = 191
    a = 11
    b = 22
    R = (117, 94)

    print("Using fixed curve parameters:")
    print(f"  p={p}, a={a}, b={b}, R={R}\n")

    dB = int(input("Enter private key (dA or dB): "))

    print("\nEnter ciphertext in this exact format:")
    print("((27,105),0) ((97,171),1) ((170,56),0) ((33,154),0) ((37,64),1)\n")

    raw_cipher = input("Ciphertext: ").strip()
    cipher = parse_ciphertext(raw_cipher)

    # Parse r = (x,y)
    r_raw = input("Enter r as (x,y): ").strip()
    r_raw = r_raw.replace("(", "").replace(")", "")
    r_x, r_y = r_raw.split(",")
    r_point = (int(r_x), int(r_y))

    # ---- Decrypt ----
    decrypted = decrypt_message(cipher, r_point, a, p, dB)

    print("\n--- Decrypted Message ---\n")
    print(decrypted)
    print()


if __name__ == "__main__":
    main()
