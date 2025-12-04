#Use sign_with_forced_k() to simulate a broken signer that reuses or forces k.
#Use demo_k_reuse_attack() as a quick CLI/test for private key recovery.
#The module uses only curve and keys — it deliberately bypasses RFC6979 to simulate broken implementations.


# ecc/attacks.py
"""
Attack utilities for the ECC/ECDSA project.

Provides:
- sign_with_forced_k: produce ECDSA signatures using a forced nonce k (simulates broken RNG)
- recover_private_key_from_nonce_reuse: recover private key given two signatures that reuse k
- demo_k_reuse_attack: demo script for CLI usage (returns original and recovered keys)
"""

from .curve import Point, EllipticCurve
from typing import Tuple

# Helper: modular inverse already available in EllipticCurve.inverse_mod
# We'll operate directly with curve arithmetic to create signatures with a forced k.

def sign_with_forced_k(curve: EllipticCurve, private_key: int, message_hash_int: int, k: int) -> Tuple[int, int]:
    """
    Create ECDSA signature (r, s) using a forced nonce k.
    This simulates a vulnerable implementation that reuses k.
    message_hash_int: integer hash of the message (e.g., int.from_bytes(sha256(msg).digest(),'big'))
    """
    # R = k * G
    R = curve.scalar_mult(k, curve.G)
    r = R.x % curve.n
    if r == 0:
        raise ValueError("r == 0 for this k; pick different k")
    k_inv = curve.inverse_mod(k)
    s = (k_inv * (message_hash_int + r * private_key)) % curve.n
    if s == 0:
        raise ValueError("s == 0 for this k; pick different k")
    return (r, s)


def recover_private_key_from_nonce_reuse(curve: EllipticCurve,
                                         sig1: Tuple[int,int],
                                         sig2: Tuple[int,int],
                                         h1: int, h2: int) -> Tuple[int,int]:
    """
    Given two signatures sig1=(r,s1), sig2=(r,s2) that used the same nonce k (so same r),
    recover k and the private key d.
    Returns (k_recovered, d_recovered).
    Raises ValueError if r differs (no nonce reuse).
    """
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("Signatures do not share r -> nonce likely not reused")

    # compute k = (h1 - h2) * (s1 - s2)^-1 mod n
    n = curve.n
    s_diff = (s1 - s2) % n
    if s_diff == 0:
        raise ValueError("s1 == s2 mod n; can't recover k (degenerate)")

    k = ((h1 - h2) * pow(s_diff, -1, n)) % n
    # compute private key d = (s1 * k - h1) * r^-1 mod n
    d = ((s1 * k - h1) * pow(r1, -1, n)) % n
    return k, d


def demo_k_reuse_attack(curve: EllipticCurve, private_key: int,
                       message1: str, message2: str, hash_func) -> dict:
    """
    Demo helper: sign two messages with the SAME forced k, then recover the private key.
    hash_func: function that given string -> int (message hash integer)
    Returns dict with original d, recovered d, k used and recovered, signatures, hashes.
    """
    # pick a forced (bad) k
    import random
    bad_k = random.randrange(2, curve.n - 1)
    h1 = hash_func(message1)
    h2 = hash_func(message2)
    sig1 = sign_with_forced_k(curve, private_key, h1, bad_k)
    sig2 = sign_with_forced_k(curve, private_key, h2, bad_k)

    k_rec, d_rec = recover_private_key_from_nonce_reuse(curve, sig1, sig2, h1, h2)

    return {
        "private_key_original": private_key,
        "private_key_recovered": d_rec,
        "k_used": bad_k,
        "k_recovered": k_rec,
        "sig1": sig1,
        "sig2": sig2,
        "h1": h1,
        "h2": h2
    }


# If run standalone for quick test
if __name__ == "__main__":
    # minimal demo (requires curve.py and an existing key)
    from curve import EllipticCurve
    from keys import ECCKeyPair
    import hashlib

    # instantiate secp256k1 parameters
    curve = EllipticCurve(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0,
        b=7,
        Gx=55066263022277343669578718895168534326250603453777594175500187360389116729240,
        Gy=32670510020758816978083085130507043184471273380659243275938904335757337482424,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    )

    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()

    def hfunc(msg):
        return int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big')

    res = demo_k_reuse_attack(curve, d, "Alice->Bob:100", "Alice->Charlie:200", hfunc)
    print("Demo attack result:")
    for k,v in res.items():
        print(f"{k}: {v}")
