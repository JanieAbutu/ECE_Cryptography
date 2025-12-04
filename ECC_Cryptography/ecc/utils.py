# ecc/utils.py
import hashlib

def sha256_int(msg: str) -> int:
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big')

# small helper alias
def sha256_bytes(msg: str) -> bytes:
    return hashlib.sha256(msg.encode()).digest()
