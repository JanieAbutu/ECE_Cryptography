# mitm_tampering.py

from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from logging_config import logger

logger.info("Starting MITM Tampering Simulation…")

curve = EllipticCurve(
    p=9739, a=497, b=1768,
    Gx=1804, Gy=5368,
    n=9929
)

def run_mitm_tampering(log):
    log("=== MITM TAMPERING ATTACK ===")

    kp = ECCKeyPair(curve)
    d, Q = kp.generate_keys()

    ecdsa = ECDSA(curve, private_key=d, public_key=Q)

    original_msg = "Pay 300 USD to Alice"
    tampered_msg = "Pay 300 USD to Mallory"

    sig = ecdsa.sign(original_msg)

    log(f"Original message: {original_msg}")
    log(f"Tampered message: {tampered_msg}")
    log(f"Signature: {sig}")

    log("MITM sends the tampered message with original signature...")

    verified = ecdsa.verify(tampered_msg, sig, Q)

    if verified:
        log("MITM attack SUCCEEDED — tampered message accepted!")
        return "MITM Attack SUCCESS (system vulnerable!)"

    log("MITM attack FAILED — signature did NOT match tampered message.")
    return "MITM Attack FAILED (correct behavior)."


if __name__ == "__main__":
    def cli_log(msg): print(msg)
    print(run_mitm_tampering(cli_log))
