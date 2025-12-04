# attacks/attack_mitm.py

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
    print("\n=== MAN-IN-THE-MIDDLE (MITM) ATTACK ===")

    # Victim
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "Pay 100 USD to Alice"
    sig = ecdsa.sign(msg)

    print("\n[Original Signed Message]")
    print(msg)
    print(sig)

    # MITM modifies the message
    tampered = "Pay 100 USD to Mallory"

    print("\n[TAMPERED MESSAGE]")
    print(tampered)

    valid = ecdsa.verify(tampered, sig, Q)

    print("\nMITM Successful?" , valid)
    print("Expected: False")

if __name__ == "__main__":
    main()
