# tests/test_elgamal.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.elgamal import ElGamalECC

# --- Use a larger prime field to fit ASCII messages ---
curve = EllipticCurve(
    p=257,    # prime field
    a=1, b=1,
    Gx=3, Gy=10,
    n=251     # generator order close to prime
)

def test_encrypt_decrypt():
    # Generate keys
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()

    # Encrypt and decrypt message
    e = ElGamalECC(curve)
    C1, C2 = e.encrypt(Q, "hi")
    pt = e.decrypt(d, (C1, C2))

    # Assert decrypted message matches original
    assert pt == "hi"
