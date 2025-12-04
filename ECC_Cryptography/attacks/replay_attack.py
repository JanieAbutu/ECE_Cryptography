# attacks/attack_replay.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA

# Medium teaching curve
curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9739
)

def main():
    print("\n=== REPLAY ATTACK DEMO ===")

    # Bank user generates keys
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    # Original legitimate transaction
    msg1 = "Transfer 50 USD to Wallet_X"
    sig1 = ecdsa.sign(msg1)

    print("\n[Legitimate Transaction Signed]")
    print("Message:", msg1)
    print("Signature:", sig1)

    # Attacker replays SAME signature for a NEW transaction
    msg2 = "Transfer 5000 USD to Attacker"
    print("\n[Attacker Replays Signature]")
    print("New Message:", msg2)
    print("Reused Signature:", sig1)

    # Verification SHOULD FAIL (message different)
    valid = ecdsa.verify(msg2, sig1, Q)

    print("\nReplay Attack Successful?" , valid)
    print("Expected: False (signature bound to original message)\n")

if __name__ == "__main__":
    main()
