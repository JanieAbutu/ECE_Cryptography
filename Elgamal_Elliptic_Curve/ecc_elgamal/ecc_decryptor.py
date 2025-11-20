# decryption.py
from ecc_encoder import ec_add, ec_neg, ec_scalar_mul

def decrypt_message(cipher, r, a, p, dB):
    def decode_point_with_offset(x, offset):
        num = (x - offset) % p
        return chr((num % 26) + 65)

    S = ec_scalar_mul(dB, r, a, p)
    decrypted_message = ""

    print("\n--- Points after subtracting S (before decoding) ---")

    for item in cipher:
        C2, offset = item
        if offset is not None:
            Pm = ec_add(C2, ec_neg(S, p), a, p)
            print(f"Point: {Pm}, Offset: {offset}")
            letter = decode_point_with_offset(Pm[0], offset)
            decrypted_message += letter
        else:
            print(f"Non-alpha character: {C2}")
            decrypted_message += C2  # preserve punctuation/spaces
            
    return decrypted_message
