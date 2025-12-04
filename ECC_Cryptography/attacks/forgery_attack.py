# attacks/attack_forgery.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from random import randint

# Medium teaching curve
curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9739
)

def main():
    print("\n=== SIGNATURE FORGERY ATTEMPT ===")

    # Honest user
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    # Attacker attempts forgery
    msg = "Transfer 5000 USD to Attacker"

    print("\nAttacker tries random (r, s) pairs...")

    for _ in range(20):
        r = randint(1, curve.n - 1)
        s = randint(1, curve.n - 1)
        if ecdsa.verify(msg, (r, s), Q):
            print("\nForged Signature:", (r, s))
            print("Attack Succeeded — (this should not happen!)")
            break
    else:
        print("\nForgery Failed (correct behavior).")

if __name__ == "__main__":
    main()
