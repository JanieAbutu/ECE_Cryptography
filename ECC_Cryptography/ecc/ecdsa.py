# ecc/ecdsa.py
import hashlib
from random import randint
from typing import Tuple, Optional

class ECDSA:
    """
    Robust ECDSA implementation compatible with our EllipticCurve and Point.
    Works for both small toy curves and large curves like secp256k1.
    """

    def __init__(self, curve, private_key: Optional[int] = None, public_key=None):
        self.curve = curve
        self.private_key = private_key
        self.public_key = public_key

    def _hash_msg(self, msg: str) -> int:
        """Return SHA-256(msg) reduced modulo curve.n."""
        z = int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big')
        return z % self.curve.n

    def sign(self, msg: str, k: Optional[int] = None) -> Tuple[int, int]:
        """
        Produce an ECDSA signature (r, s) for the message `msg`.
        Optional deterministic k can be supplied for testing.
        """
        if self.private_key is None:
            raise ValueError("Private key not set for signing")

        n = self.curve.n
        G = self.curve.G
        d = self.private_key
        z = self._hash_msg(msg)

        while True:
            # Random or deterministic k
            if k is None:
                k = randint(1, n - 1)

            # Point multiplication mod p
            P = k * G
            if P is None or getattr(P, "x", None) is None:
                if k is not None:
                    raise ValueError(f"Invalid deterministic k={k}")
                continue

            r = P.x % n
            if r == 0:
                if k is not None:
                    raise ValueError(f"r=0 for deterministic k={k}")
                k = None
                continue

            k_inv = pow(k, -1, n)
            s = (k_inv * (z + r * d) % n) % n
            if s == 0:
                if k is not None:
                    raise ValueError(f"s=0 for deterministic k={k}")
                k = None
                continue

            return (r, s)

    def verify(self, msg: str, sig: Tuple[int, int], Q) -> bool:
        """
        Verify ECDSA signature.
        - sig: (r, s)
        - Q: public key point
        Returns True if valid, False otherwise.
        """
        r, s = sig
        n = self.curve.n

        # Check bounds
        if not (1 <= r < n and 1 <= s < n):
            return False

        z = self._hash_msg(msg)

        try:
            s_inv = pow(s, -1, n)
        except ValueError:
            return False

        u1 = (z * s_inv) % n
        u2 = (r * s_inv) % n

        X = u1 * self.curve.G + u2 * Q

        if X is None or getattr(X, "x", None) is None:
            return False

        return (X.x % n) == r
