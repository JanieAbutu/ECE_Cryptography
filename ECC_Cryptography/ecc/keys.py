#Flow of keys.py:
#ECCKeyPair(curve) → Initialize key pair object with a specific curve.
#generate_keys() →
#Randomly picks private key d ∈ [1, n-1]
#Computes public key Q = d*G using scalar multiplication from curve.py

# ecc/keys.py
import random
from .curve import EllipticCurve

class ECCKeyPair:
    """Generates and stores an ECC private and public key pair."""

    def __init__(self, curve: EllipticCurve):
        self.curve = curve
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """Generates private and public keys."""
        self.private_key = random.randrange(1, self.curve.n)
        self.public_key = self.curve.scalar_mult(self.private_key, self.curve.G)
        return self.private_key, self.public_key

    def load_private_key(self, private_key: int):
        """Set an existing private key and compute public key."""
        self.private_key = private_key
        self.public_key = self.curve.scalar_mult(self.private_key, self.curve.G)
        return self.public_key

    def load_public_key(self, public_key):
        """Set an existing public key (optional)."""
        self.public_key = public_key
