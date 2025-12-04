def forgery_attack(bank_app):
    print("\n[ATTACK] Attempting signature forgery...")

    fake_tx = {
        "sender": "USER123",
        "recipient": "ATTACKER001",
        "amount": 9999999,
        "timestamp": "FORGED"
    }

    fake_sig = (123, 123)  # attacker guesses

    if bank_app.verify_transaction(fake_tx, fake_sig):
        print("[WARNING] Forgery SUCCESS — system broken!")
        return True
    else:
        print("[SAFE] Forgery FAILED — private key required.")
        return False
