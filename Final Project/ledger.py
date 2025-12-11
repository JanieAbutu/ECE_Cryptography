# ledger.py
###############################################################################
# Defines a TransactionLedger class, which acts as a simple transaction log
# Adds timestamps to transactions
################################################################################
import time
import copy


# Defines an immutable append only ledger
# Stores used signatures which can serve as replay prevention technique
# Adds a new ledger entry
# Prints the ledger
# Retrieves transaction entry

class TransactionLedger:
    def __init__(self):
        self.entries = []
        self.seen_signatures = set()  # stores used signatures serving as replay protection

    def add(self, sender, receiver, message, signature, public_key):
        sig_id = (signature[0], signature[1])

        if sig_id in self.seen_signatures:
            print("REPLAY ATTACK DETECTED – signature already used.")
            return False

        self.seen_signatures.add(sig_id)

        self.entries.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "signature": signature,
            "public_key": public_key
        })

        print("✅ Ledger entry added.")
        return True

    def show(self):
        print("\n=== TRANSACTION LEDGER ===")
        for i, e in enumerate(self.entries):
            print(f"\n[{i+1}] {e['timestamp']}")
            print(f"From      : {e['sender']}")
            print(f"To        : {e['receiver']}")
            print(f"Message   : {e['message']}")
            print(f"Signature : {e['signature']}")
            print(f"PublicKey : {e['public_key']}")

    def get(self, index):
        if index < 0 or index >= len(self.entries):
            return None
        return copy.deepcopy(self.entries[index])
