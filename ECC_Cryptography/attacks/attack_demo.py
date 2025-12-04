# attack_demo.py
"""
ECDSA Vulnerability Demonstration:
----------------------------------
This script shows how reusing the SAME NONCE (k) in two signatures
allows an attacker to recover the private key and forge transactions.

Steps:
1. Bank signs two different transactions using SAME k (bad!).
2. Attacker observes both signatures.
3. Attacker recovers the bank's private key.
4. Attacker forges a new fraudulent transaction.
"""

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA

# Use a small curve so the attack is easy to see
curve = EllipticCurve(
    p=257,
    a=1,
    b=1,
    Gx=3,
    Gy=10,
    n=251
)

def recover_private_key(curve, sig1, sig2, h1, h2):
    """
    Recover private key using:
        s1 = k_inv * (h1 + d*r)
        s2 = k_inv * (h2 + d*r)
    Where k is reused.
    """

    r1, s1 = sig1
    r2, s2 = sig2

    if r1 != r2:
        raise ValueError("Nonces not reused, attack fails")

    n = curve.n

    # Step 1: Recover k
    #     s1 - s2 = k_inv (h1 - h2)
    # →   k = (h1 - h2) * (s1 - s2)^-1 mod n
    numerator = (h1 - h2) % n
    denominator = (s1 - s2) % n

    denom_inv = pow(denominator, -1, n)
    k = (numerator * denom_inv) % n

    # Step 2: Recover private key d
    #   s1 = k^-1 (h1 + d*r)
    # → d = (s1*k - h1) * r^-1 mod n
    k_inv = pow(k, -1, n)

    d = ((s1 * k - h1) * pow(r1, -1, n)) % n
    return d, k


def main():

    print("\n=== ECDSA Nonce-Reuse Attack Demonstration ===\n")

    # Generate legitimate bank keys
    kp = ECCKeyPair(curve)
    d_bank, Q_bank = kp.generate_keys()

    bank = ECDSA(curve, private_key=d_bank, public_key=Q_bank)

    print(f"Bank Private Key (SECRET): {d_bank}")
    print(f"Bank Public Key: {Q_bank}\n")

    # Bank signs two different transactions — but insecurely reuses SAME k
    msg1 = "Transfer 500 to Alice"
    msg2 = "Transfer 1000 to Bob"

    fixed_k = 42  # BAD SECURITY PRACTICE (for demo only)

    sig1 = bank.sign(msg1, k=fixed_k)
    sig2 = bank.sign(msg2, k=fixed_k)

    print("--- Legitimate Signatures ---")
    print(f"Message 1: {msg1}")
    print(f"Signature 1: {sig1}")
    print("")
    print(f"Message 2: {msg2}")
    print(f"Signature 2: {sig2}")
    print("\nAttacker intercepts both signatures...\n")

    # Hash values (publicly computable)
    h1 = bank._hash_msg(msg1)
    h2 = bank._hash_msg(msg2)

    # Attacker recovers the private key
    recovered_d, recovered_k = recover_private_key(curve, sig1, sig2, h1, h2)

    print("=== Attacker Recovers the Private Key ===")
    print(f"Recovered k: {recovered_k}")
    print(f"Recovered PRIVATE KEY: {recovered_d}\n")

    # Now attacker forges a fraudulent transaction
    attacker = ECDSA(curve, private_key=recovered_d)

    fake_msg = "Transfer 1,000,000 to Mallory"
    fake_sig = attacker.sign(fake_msg)

    print("=== Attacker Forges Transaction ===")
    print(f"Forged Message: {fake_msg}")
    print(f"Forged Signature: {fake_sig}\n")

    # Verify using the bank’s public key
    valid = bank.verify(fake_msg, fake_sig, Q_bank)

    print("=== Verification Result ===")
    print("Forgery Accepted by Bank System? ->", valid)
    print("\n--- END OF DEMO ---\n")


if __name__ == "__main__":
    main()
