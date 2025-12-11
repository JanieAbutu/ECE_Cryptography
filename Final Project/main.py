# main.py
# ################################################################################
# CLI based Bank simulator
# Ties together the transaction system, ledger, ECDSA signing
################################################################################

from ledger import TransactionLedger
from transaction import TransactionSystem



ledger = TransactionLedger()
bank = TransactionSystem(ledger)

while True:
    print("\n1. Create account")
    print("2. Show accounts")
    print("3. Transfer money")
    print("4. Show ledger")
    print("5. Verify ledger transaction")
    

    print("0. Exit")

    c = input("Choice: ")

    if c == "1":
        name = input("Name: ")
        bal = int(input("Balance: "))
        bank.create_account(name, bal)

    elif c == "2":
        bank.show_accounts()

    elif c == "3":
        s = input("Sender: ")
        r = input("Receiver: ")
        a = int(input("Amount: "))
        bank.transfer(s, r, a)

    elif c == "4":
        ledger.show()

    elif c == "5":
        i = int(input("Transaction #: ")) - 1
        bank.verify_ledger(i)

    elif c == "6":
        nonce_reuse_attack()


    elif c == "0":
        print("THANK YOU FOR BANKING WITH US!\n")
        break
