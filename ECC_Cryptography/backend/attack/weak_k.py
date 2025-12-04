# weak_k_attack.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from logging_config import logger

logger.info("Starting Weak‑k Attack Simulation…")


curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9929
)


def run_weak_k_attack(log):
    """
    If k is too small or predictable, private key can be recovered.
    We simulate attacker forcing k = 1.
    """
    log("=== WEAK k ATTACK ===")
    log("Attacker forces weak k = 1...")

    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()

    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "Authorize payment of 1000 USD"
    r, s = ecdsa.sign(msg, k=1)

    log(f"Signature with weak k: r={r}, s={s}")

    log("Mathematical fact: with k=1, attacker computes:")
    recovered_d = ((s * 1) - ecdsa.hash_message(msg)) * pow(r, -1, curve.n)
    recovered_d %= curve.n

    log(f"Recovered private key = {recovered_d}")
    log(f"Actual private key    = {d}")

    if recovered_d == d:
        log("Weak‑k attack SUCCEEDED — private key fully recovered!")
        return "Weak‑k Attack SUCCESS (system vulnerable!)"

    log("Weak‑k attack FAILED (unexpected).")
    return "Weak‑k Attack FAILED."


if __name__ == "__main__":
    def cli_log(msg): print(msg)
    print(run_weak_k_attack(cli_log))
