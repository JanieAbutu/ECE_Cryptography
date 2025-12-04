def malleability_attack(bank_app, tx, signature):
    print("\n[ATTACK] Signature Malleability Attempt...")

    r, s = signature
    n = bank_app.ecdsa.n

    # alternate valid signature if ECDSA malleable
    s2 = (-s) % n
    new_sig = (r, s2)

    print(f"Trying alternate signature: {new_sig}")

    if bank_app.verify_transaction(tx, new_sig):
        print("[WARNING] Malleability allowed signature variant!")
    else:
        print("[SAFE] Malleability blocked — strong ECDSA implementation.")
