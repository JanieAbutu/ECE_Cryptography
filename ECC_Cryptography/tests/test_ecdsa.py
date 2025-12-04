# tests/test_ecdsa.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA

# --- Use a large curve for reliable tests (secp256k1-like) ---
curve = EllipticCurve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,  # secp256k1 prime
    a=0,
    b=7,
    Gx=55066263022277343669578718895168534326250603453777594175500187360389116729240,
    Gy=32670510020758816978083085130507043184471273380659243275938904335757337482424,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

def test_sign_and_verify_random():
    """Test ECDSA signing and verification with normal random k"""
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "hello"
    sig = ecdsa.sign(msg)  # normal random k
    assert ecdsa.verify(msg, sig, Q)

def test_sign_and_verify_deterministic():
    """Test ECDSA signing and verification with a fixed deterministic k"""
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "hello"
    fixed_k = 123456789  # deterministic k for testing
    sig = ecdsa.sign(msg, k=fixed_k)
    assert ecdsa.verify(msg, sig, Q)
