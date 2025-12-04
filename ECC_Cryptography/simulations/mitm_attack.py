def mitm_attack(bank_app, tx, signature):
    print("\n[ATTACK] MITM modifying amount...")

    tampered_tx = tx.copy()
    tampered_tx["amount"] = tx["amount"] + 50000  # attacker modifies amount

    if bank_app.verify_transaction(tampered_tx, signature):
        print("[WARNING] MITM SUCCEEDED! Verification accepted tampered TX.")
    else:
        print("[SAFE] MITM FAILED — signature mismatch prevented tampering.")
