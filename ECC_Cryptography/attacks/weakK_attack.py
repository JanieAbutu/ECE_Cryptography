# attacks/attack_weak_k.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
#from ecc_library_path import ECDSA

# Medium teaching curve
curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9739
)

def run_weak_k_attack(log):
    log("Attacker forces weak k = 1...")
    log("Private key becomes recoverable because signature leaks d.")
    # insert your previous weak‑k demo logic here
    return "Weak k attack completed."

from logging_config import logger
logger.info("Starting weak-k attack…")


def main():
    print("\n=== WEAK k ATTACK (Nonce Reuse) ===")

    # Victim
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    # Attacker forces SAME k for both signatures
    k = 1337

    msg1 = "Pay 40 USD"
    msg2 = "Pay 60 USD"

    r1, s1 = ecdsa.sign(msg1, k=k)
    r2, s2 = ecdsa.sign(msg2, k=k)

    print("\nVictim reused k =", k)
    print("Signature 1:", (r1, s1))
    print("Signature 2:", (r2, s2))

    # Weak k attack formula:
    #   d = ( (s1*z2 - s2*z1) * inverse(r*(s2 - s1)) ) mod n
    z1 = ecdsa._hash_msg(msg1)
    z2 = ecdsa._hash_msg(msg2)

    n = curve.n
    numerator = (s1 * z2 - s2 * z1) % n
    denominator = (r1 * (s2 - s1)) % n
    denom_inv = pow(denominator, -1, n)

    recovered_d = (numerator * denom_inv) % n

    print("\nRecovered Private Key:", recovered_d)
    print("Real Private Key:     ", d)
    print("\nAttack Successful?" , recovered_d == d)

if __name__ == "__main__":
    main()
