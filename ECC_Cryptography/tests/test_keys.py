#tests/test_keys.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair

curve = EllipticCurve(
    p=23, a=1, b=1,
    Gx=3, Gy=10,
    n=7
)

def test_key_generation():
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    assert 1 <= d < curve.n
    assert Q is not None
