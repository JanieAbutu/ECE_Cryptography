#tests/test_encoder.py

from ecc.encoder import encode_point, decode_point

def test_encode_decode_point():
    P = (123, 456)
    b = encode_point(P)
    P2 = decode_point(b)
    assert P == P2
