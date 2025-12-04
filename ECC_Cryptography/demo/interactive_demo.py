from simulations.banking_app import BankingApp
from simulations.replay_attack import replay_attack
from simulations.forgery_attack import forgery_attack
from simulations.mitm_attack import mitm_attack
from simulations.malleability_attack import malleability_attack
from simulations.weak_k_attack import weak_k_attack

import json

bank = BankingApp()
last_tx = None
last_signature = None

def menu():
    print("\n==== DIGITAL BANKING SECURITY DEMO ====")
    print("Balance:", bank.balance)
    print("1. Make Transaction")
    print("2. Verify Last Transaction")
    print("3. Attack: Replay Transaction")
    print("4. Attack: Signature Forgery")
    print("5. Attack: MITM Tampering")
    print("6. Attack: Signature Malleability")
    print("7. Attack: Weak-k Exploit Explanation")
    print("0. Exit")
    return input("Choose: ")

while True:
    choice = menu()

    if choice == "1":
        amt = int(input("Amount to send: "))
        recip = input("Recipient ID: ")

        tx, sig = bank.create_transaction(amt, recip)
        if tx is None:
            print("❌ ERROR:", sig)
        else:
            last_tx, last_signature = tx, sig
            print("\n✔ Transaction Signed")
            print(json.dumps(tx, indent=4))
            print("Signature:", sig)

    elif choice == "2":
        if not last_tx:
            print("No transaction yet.")
        else:
            result = bank.verify_transaction(last_tx, last_signature)
            print("✔ VALID Signature" if result else "❌ INVALID Signature")

    elif choice == "3":
        replay_attack(bank, last_tx, last_signature)

    elif choice == "4":
        forgery_attack(bank)

    elif choice == "5":
        mitm_attack(bank, last_tx, last_signature)

    elif choice == "6":
        malleability_attack(bank, last_tx, last_signature)

    elif choice == "7":
        weak_k_attack()

    elif choice == "0":
        break

    else:
        print("Invalid option.")
