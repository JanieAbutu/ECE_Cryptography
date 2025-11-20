# encryption.py
from ecc_encoder import encode_sentence, ec_add, ec_scalar_mul

def encrypt_message(message, a, b, p, R, eB, k):
    encoded = encode_sentence(message, a, b, p)
    r = ec_scalar_mul(k, R, a, p)
    kQ = ec_scalar_mul(k, eB, a, p)

    cipher = []
    for item in encoded:
        Pm, offset = item
        if offset is not None:
            C2 = ec_add(Pm, kQ, a, p)
            cipher.append((C2, offset))
        else:
            cipher.append((Pm, None))
    
    return cipher, r
