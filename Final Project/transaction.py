# transaction.py
###########################################################################################
# Core transaction logic of the banking system. It handles:
# Creating accounts
# Generating per-user key pairs
# Signing transactions
# Verifying signatures
# Transfer of funds
# Updating account balances
# Logging transactions in the ledger
########################################################################################

from keys import UserKeyPair
from ecdsa import ECDSA

class TransactionSystem:
    def __init__(self, ledger):
        self.ledger = ledger
        self.accounts = {}
        self.keys = {}

    def create_account(self, name, balance):
        self.accounts[name] = balance
        self.keys[name] = UserKeyPair()
        print(f"✅ Account '{name}' created with ${balance}")
        print(f"🔑 Public key: {self.keys[name].public_key}")

    def show_accounts(self):
        for u, b in self.accounts.items():
            print(f"{u}: ${b}")

    def transfer(self, sender, receiver, amount):
        if self.accounts[sender] < amount:
            print("❌ Insufficient funds.")
            return

        message = f"{sender} pays {receiver} ${amount}"
        signature = self.keys[sender].sign(message)

        print("\n=== SIGNING DETAILS ===")
        print("Sender    :", sender)
        print("Message   :", message)
        print("Signature :", signature)
        print("PublicKey :", self.keys[sender].public_key)

        verifier = ECDSA()
        valid = verifier.verify(
            message,
            signature,
            self.keys[sender].public_key
        )

        print("Verification:", "✅ VALID" if valid else "❌ INVALID")

        self.accounts[sender] -= amount
        self.accounts[receiver] += amount

        self.ledger.add(
            sender, receiver, message, signature, self.keys[sender].public_key
        )

    def verify_ledger(self, index):
        entry = self.ledger.get(index)
        if not entry:
            print("Invalid index.")
            return

        verifier = ECDSA()
        valid = verifier.verify(
            entry["message"],
            entry["signature"],
            entry["public_key"]
        )

        print("\n=== LEDGER VERIFICATION ===")
        print("Message   :", entry["message"])
        print("Signature :", entry["signature"])
        print("PublicKey :", entry["public_key"])
        print("Result    :", "✅ VALID" if valid else "INVALID")
