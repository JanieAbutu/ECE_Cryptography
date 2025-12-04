def replay_attack(bank_app, tx, signature):
    print("\n[ATTACK] Replaying previous transaction...")
    message = json.dumps(tx)

    if bank_app.ecdsa.verify(message, signature, bank_app.public_key):
        print("[SUCCESS] Bank ACCEPTED the replayed transaction!")
        return True
    else:
        print("[FAIL] Replay failed.")
        return False
