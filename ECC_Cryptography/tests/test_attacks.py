#tests/test_attacks.py

import hashlib
from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.attacks import demo_k_reuse_attack

curve = EllipticCurve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=55066263022277343669578718895168534326250603453777594175500187360389116729240,
    Gy=32670510020758816978083085130507043184471273380659243275938904335757337482424,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

kp = ECCKeyPair(curve)
d,Q = kp.generate_keys()

def h(m):
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), 'big')

def test_nonce_reuse_attack():
    res = demo_k_reuse_attack(curve, d, "A", "B", h)
    assert res["private_key_original"] == res["private_key_recovered"]
