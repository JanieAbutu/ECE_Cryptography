from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from ecc.curve import EllipticCurve
from datetime import datetime
import json
import hashlib

# Realistic curve (small to compute fast)
curve = EllipticCurve(
    p=257, a=1, b=1,
    Gx=3, Gy=10,
    n=251
)

class BankingApp:
    def __init__(self):
        self.kp = ECCKeyPair(curve)
        self.private_key, self.public_key = self.kp.generate_keys()
        self.ecdsa = ECDSA(curve, self.private_key, self.public_key)
        self.balance = 100000  # ₦100,000 starting balance

    def create_transaction(self, amount, recipient):
        if amount > self.balance:
            return None, "INSUFFICIENT FUNDS"

        tx = {
            "sender": "USER123",
            "recipient": recipient,
            "amount": amount,
            "timestamp": datetime.now().isoformat()
        }

        message = json.dumps(tx)
        signature = self.ecdsa.sign(message)

        return (tx, signature)

    def verify_transaction(self, tx, signature):
        message = json.dumps(tx)
        return self.ecdsa.verify(message, signature, self.public_key)

    def deduct_funds(self, amount):
        self.balance -= amount
