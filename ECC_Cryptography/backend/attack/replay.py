# replay_attack.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from logging_config import logger

logger.info("Starting Replay Attack Simulation…")


# Teaching curve
curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9929
)


def run_replay_attack(log):
    """
    Attacker reuses a previously valid signature on a new transaction.
    """
    log("=== REPLAY ATTACK ===")

    # Honest user generates keys
    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()

    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    # Original payment
    msg1 = "Pay 200 USD to Vendor A"
    r1, s1 = ecdsa.sign(msg1)

    log(f"Original transaction signed: {msg1}")
    log(f"Signature = (r={r1}, s={s1})")

    # Attacker replays same signature
    msg2 = "Pay 200 USD to Attacker"

    log("Attacker attempts to reuse signature on new message!")
    valid = ecdsa.verify(msg2, (r1, s1), Q)

    if valid:
        log("Replay attack SUCCEEDED — signature wrongly verified!")
        return "Replay Attack SUCCESS (system vulnerable!)"

    log("Replay attack FAILED — signature bound to original message.")
    return "Replay Attack FAILED (correct behavior)."


if __name__ == "__main__":
    def cli_log(msg): print(msg)
    print(run_replay_attack(cli_log))
