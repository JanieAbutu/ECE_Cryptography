# forgery.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from random import randint
from logging_config import logger


logger.info("Starting signature forgery attack simulation…")


curve = EllipticCurve(
    p=9739,
    a=497,
    b=1768,
    Gx=1804,
    Gy=5368,
    n=9929
)


def run_forgery_attack(log):
    log("=== SIGNATURE FORGERY ATTEMPT ===")
    log("Attacker tries random (r, s) pairs...")

    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()
    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    msg = "Transfer 5000 USD to Attacker"

    for _ in range(50):
        r = randint(1, curve.n - 1)
        s = randint(1, curve.n - 1)
        if ecdsa.verify(msg, (r, s), Q):
            forged = f"(r={r}, s={s})"
            log(f"FORGERY SUCCEEDED — {forged}")
            return f"Forgery SUCCESS: {forged}"

    log("Forgery FAILED — attacker could NOT generate a valid signature.")
    return "Forgery FAILED (correct behavior)."


if __name__ == "__main__":
    def cli_log(msg): print(msg)
    print(run_forgery_attack(cli_log))
