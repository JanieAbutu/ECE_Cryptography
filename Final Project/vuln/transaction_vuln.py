# vuln/transaction_vuln.py
#########################################################################
# Simulated payment system where:
# Accounts have balances and cryptographic keys
# Transactions are “signed”
# Security checks are intentionally skipped
# An attacker can observe transactions in real time
#
# Shows how attacks succeed when basic rules are broken.
##########################################################################

import hashlib

class VulnerableTransactionSystem:
  

    def __init__(self, attacker=None):
        self.accounts = {}
        self.ledger = []
        self.attacker = attacker
        self.frozen_accounts = set()

    def create_account(self, name, balance, keypair, signer=None):
        self.accounts[name] = {
            "balance": balance,
            "keypair": keypair,
            "signer": signer
        }
        print(f"[Result] Account created: {name}")

    def freeze_account(self, name):
        self.frozen_accounts.add(name)
        print(f"[Info] Account {name} frozen")

    def transfer(self, sender, receiver, amount, allow_mitm=False, allow_forgery=False):
        """
        Performs a transfer. Parameters allow_mitm and allow_forgery are
        used by demo code to simulate MITM/forgery scenarios.
        """
        if sender in self.frozen_accounts:
            print(f"[Warning] Account {sender} is frozen; transfer rejected")
            return

        if sender not in self.accounts or receiver not in self.accounts:
            print("[Warning] Invalid account")
            return

        if self.accounts[sender]["balance"] < amount:
            print("[Warning] Insufficient funds")
            return

        msg = f"{sender} pays {receiver} ${amount}"
        z = int(hashlib.sha256(msg.encode()).hexdigest(), 16)

        signer = self.accounts[sender]["signer"]
        keypair = self.accounts[sender]["keypair"]

        # If allow_forgery is set by a demo, simulate a forged signature (attacker supplied)
        if allow_forgery:
            # Create a dummy forged signature for demo
            r, s = 1, 1
        elif signer:
            r, s = signer.sign(z, keypair.private_key)
        else:
            r, s = None, None

        print("[Warning] Signature verification intentionally skipped in vulnerable demo")

        tx = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "message": msg,
            "hash": z,
            "r": r,
            "s": s,
            "public_key": getattr(keypair, "public_key", None),
            "forged": bool(allow_forgery),
            "mitm_modified": bool(allow_mitm),
        }

        self.ledger.append(tx)

        # --- Attacker observes LIVE ---
        if self.attacker:
            try:
                self.attacker.observe(tx)
            except Exception as e:
                # Keep demo resilient: print a small note, don't crash
                print(f"[Warning] Attacker observation raised an error: {e}")

        # Apply transfer
        self.accounts[sender]["balance"] -= amount
        self.accounts[receiver]["balance"] += amount

        print("[Result] Vulnerable transaction committed\n")

    def show_accounts(self):
        print("\n--- ACCOUNTS ---")
        for name, acc in self.accounts.items():
            print(f"{name}: ${acc['balance']}")

    def show_ledger(self):
        print("\n--- LEDGER ---")
        for i, tx in enumerate(self.ledger):
            print(f"{i}: {tx}")
