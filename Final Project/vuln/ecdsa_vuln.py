# vuln/ecdsa_vuln.py

import random
import hashlib

# --------------------------------------------------
# Curve parameters (secp256k1-style)
# --------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Generator (simplified integer form for demo)
G = 55066263022277343669578718895168534326250603453777594175500187360389116729240

# Explicit export for other modules
CURVE_G = G
CURVE_N = N


# --------------------------------------------------
# ❌ VULNERABLE ECDSA
# --------------------------------------------------
class VulnerableECDSA:
    """
    ❌ Intentionally vulnerable ECDSA signer

    Vulnerabilities:
    - Allows fixed nonce reuse
    - No deterministic nonce protection
    - No domain separation
    - Simplified math (educational)
    """

    def __init__(self, fixed_k=None):
        self.fixed_k = fixed_k

    def sign(self, z, private_key):
        """
        Sign hash z using ECDSA (vulnerable version)
        """
        if self.fixed_k is not None:
            k = self.fixed_k          # ❌ nonce reuse
        else:
            k = random.randint(1, N - 1)

        r = (k * G) % N
        s = (pow(k, -1, N) * (z + r * private_key)) % N
        return r, s


# --------------------------------------------------
# ✅ HELPER: Public key derivation
# --------------------------------------------------
def derive_public_key(private_key):
    """
    Q = d · G
    """
    return (private_key * G) % N


# --------------------------------------------------
# ✅ SECURE VERSION (for comparison in slides)
# --------------------------------------------------
class SecureECDSA:
    """
    ✅ Secure ECDSA signer (deterministic nonce)
    Demonstrates the FIX for nonce reuse
    """

    def sign(self, z, private_key):
        k = self._deterministic_k(z, private_key)

        r = (k * G) % N
        s = (pow(k, -1, N) * (z + r * private_key)) % N
        return r, s

    def _deterministic_k(self, z, d):
        h = hashlib.sha256(f"{z}{d}".encode()).hexdigest()
        return int(h, 16) % N
