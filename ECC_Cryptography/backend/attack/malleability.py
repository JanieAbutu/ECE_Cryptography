# malleability_attack.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from logging_config import logger

logger.info("Starting Signature Malleability Simulation…")


curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9929
)

def run_malleability_attack(log):
    log("=== SIGNATURE MALLEABILITY ATTACK ===")

    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()

    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "Release 2000 USD"
    r, s = ecdsa.sign(msg)

    log(f"Original signature: (r={r}, s={s})")

    # Malleability: attacker computes s' = n - s
    s_prime = (curve.n - s) % curve.n
    forged_sig = (r, s_prime)

    log(f"Forged malleable signature: (r={r}, s'={s_prime})")

    valid = ecdsa.verify(msg, forged_sig, Q)

    if valid:
        log("Malleability attack SUCCEEDED — alternative signature also valid!")
        return "Malleability SUCCESS (ECDSA is malleable by design)."

    log("Malleability attack FAILED (unexpected).")
    return "Malleability FAILED."


if __name__ == "__main__":
    def cli_log(msg): print(msg)
    print(run_malleability_attack(cli_log))
