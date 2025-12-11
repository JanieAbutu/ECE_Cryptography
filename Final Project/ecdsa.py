# ecdsa.py
##############################################################
# ECDSA implementation
###############################################################
import secrets
from hashlib import sha256
from curve import G, n, add, multiply

class ECDSA:
    def __init__(self):
        # Key generation
        self.private_key = secrets.randbelow(n - 1) + 1
        self.public_key = multiply(self.private_key, G)

    def sign(self, message):
        z = int.from_bytes(sha256(message.encode()).digest(), "big")

        while True:
            k = secrets.randbelow(n - 1) + 1
            x, _ = multiply(k, G)
            r = x % n
            if r == 0:
                continue

            s = (pow(k, -1, n) * (z + r * self.private_key)) % n
            if s != 0:
                break

        return (r, s)

    def sign_verbose(self, message):
        print("\n=== ECDSA SIGNING STEPS ===")

        z = int.from_bytes(sha256(message.encode()).digest(), "big")
        print("1. Message hash (z):", z)

        k = secrets.randbelow(n - 1) + 1
        print("2. Nonce (k):", k)

        x, _ = multiply(k, G)
        r = x % n
        print("3. r = (k · G).x mod n:", r)

        s = (pow(k, -1, n) * (z + r * self.private_key)) % n
        print("4. s = k⁻¹(z + r·d) mod n:", s)

        return (r, s)

    def sign_with_nonce(self, message, forced_k):
        """
        INSECURE: Used ONLY for nonce‑reuse attack demonstration
        """
        z = int.from_bytes(sha256(message.encode()).digest(), "big")
        x, _ = multiply(forced_k, G)
        r = x % n
        s = (pow(forced_k, -1, n) * (z + r * self.private_key)) % n
        return (r, s), z

    def verify(self, message, signature, public_key):
        r, s = signature
        if not (1 <= r < n and 1 <= s < n):
            return False

        z = int.from_bytes(sha256(message.encode()).digest(), "big")
        w = pow(s, -1, n)
        u1 = (z * w) % n
        u2 = (r * w) % n

        x, _ = add(
            multiply(u1, G),
            multiply(u2, public_key)
        )

        return r == (x % n)
