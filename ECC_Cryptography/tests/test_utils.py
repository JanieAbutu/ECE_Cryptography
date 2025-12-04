#tests/test_utils.py

from ecc.utils import sha256_int

def test_sha256_int():
    x = sha256_int("hello")
    assert isinstance(x, int)
