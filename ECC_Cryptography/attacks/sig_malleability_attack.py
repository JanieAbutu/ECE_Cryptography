# attacks/attack_malleability.py

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
    print("\n=== SIGNATURE MALLEABILITY ===")

    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "Authorize debit 120 USD"
    r, s = ecdsa.sign(msg)

    print("\nOriginal Signature:", (r, s))

    # Malleability transformation: (r, n - s)
    s_malleable = (curve.n - s) % curve.n
    forged_sig = (r, s_malleable)

    print("Malleable Signature:", forged_sig)

    valid_original = ecdsa.verify(msg, (r, s), Q)
    valid_malleable = ecdsa.verify(msg, forged_sig, Q)

    print("\nOriginal Valid?: ", valid_original)
    print("Malleable Valid?:", valid_malleable)

if __name__ == "__main__":
    main()
