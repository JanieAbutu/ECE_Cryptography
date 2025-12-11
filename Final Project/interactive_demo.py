# interactive_demo.py

#!/usr/bin/env python3
#########################################################
# Ties together the vulnerable transaction system and breakable ECDSA signing
# Demonstrates attacker mindset and real attack classes
# Purposefully breaks ECDSA
# Prove private key recovery mathematically
##########################################################

import time
import hashlib
import secrets

from vuln.transaction_vuln import VulnerableTransactionSystem
from vuln.ecdsa_vuln import VulnerableECDSA, derive_public_key, CURVE_G, CURVE_N
from vuln.nonce_attacker import NonceReuseAttacker
from keys import UserKeyPair


# ----- configuration -----
LINE_WIDTH = 80
SEPARATOR = "=" * LINE_WIDTH
PAUSE_PROMPT = "Press Enter to continue (type 'a' + Enter to auto-play): "

# ----- helpers -----
def pause(auto_mode):
    if auto_mode:
        time.sleep(0.6)
        return True
    s = input(PAUSE_PROMPT).strip().lower()
    return (s == "a")

def print_header(title):
    print("\n" + SEPARATOR)
    print(title.center(LINE_WIDTH))
    print(SEPARATOR + "\n")

def compute_hash(msg: str) -> int:
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)

def modinv(a: int, n: int) -> int:
    return pow(a % n, -1, n)


# ----- demo 1: nonce reuse -----
def demo_nonce_reuse(auto_mode=False):
    print_header("Demo 1: Nonce-reuse attack — explicit math and proof")

    attacker = NonceReuseAttacker()
    bank = VulnerableTransactionSystem(attacker=attacker)

    alice = UserKeyPair()
    bob = UserKeyPair()

    # vulnerable signer with fixed nonce to force reuse
    FIXED_K = 777
    signer = VulnerableECDSA(fixed_k=FIXED_K)

    bank.create_account("alice", 1000, alice, signer=signer)
    bank.create_account("bob", 500, bob, signer=None)

    # Proof: reveal initial secret state (demo only)
    print("[Proof] Initial keys and balances (demo only):")
    print(f"  Alice private key : {alice.private_key}")
    print(f"  Alice public key  : {alice.public_key}")
    print(f"  Alice balance     : {bank.accounts['alice']['balance']}")
    print(f"  Bob   balance     : {bank.accounts['bob']['balance']}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    # Tx1
    msg1 = "alice pays bob $100"
    z1 = compute_hash(msg1)
    print("\n[Tx] Transaction 1 (to be signed):")
    print(f"  message: {msg1}")
    print(f"  hash(z1): {z1}")
    print(f"  signer.fixed_k: {signer.fixed_k}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    r1, s1 = signer.sign(z1, alice.private_key)
    print("\n[Tx] Signature 1 (from signer.sign):")
    print(f"  r1 = {r1}")
    print(f"  s1 = {s1}")
    print(f"  nonce k used = {signer.fixed_k}")
    print(f"  check r1 == (k * G) % n: {((signer.fixed_k * CURVE_G) % CURVE_N) == r1}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Info] Committing transaction 1 to vulnerable ledger (verification skipped).")
    bank.transfer("alice", "bob", 100)
    print("[Result] Ledger entry appended (last entry shown):")
    print(f"  {bank.ledger[-1]}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    # Tx2 (different message, same nonce)
    msg2 = "alice pays bob $200"
    z2 = compute_hash(msg2)
    print("\n[Tx] Transaction 2 (to be signed):")
    print(f"  message: {msg2}")
    print(f"  hash(z2): {z2}")
    print(f"  signer.fixed_k: {signer.fixed_k}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    r2, s2 = signer.sign(z2, alice.private_key)
    print("\n[Tx] Signature 2 (from signer.sign):")
    print(f"  r2 = {r2}")
    print(f"  s2 = {s2}")
    print(f"  nonce k used = {signer.fixed_k}")
    print(f"  r1 == r2 ? {r1 == r2}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Info] Committing transaction 2 to vulnerable ledger (verification skipped).")
    bank.transfer("alice", "bob", 200)
    print("[Result] Ledger entry appended (last entry shown):")
    print(f"  {bank.ledger[-1]}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    # Attacker recovery (either live via attacker.observe or manual)
    recovered = getattr(attacker, "recovered_private_key", None)
    print("\n[Info] Attacker recovered private key (observer):", recovered)

    if recovered is None:
        print("\n[Info] Demonstrating explicit recovery math using two ledger entries with same r.")
        entries = [tx for tx in bank.ledger if tx.get("r") is not None]
        pair = None
        for i in range(len(entries)):
            for j in range(i+1, len(entries)):
                if entries[i]["r"] == entries[j]["r"] and entries[i]["s"] != entries[j]["s"]:
                    pair = (entries[i], entries[j])
                    break
            if pair:
                break
        if pair is None:
            print("[Alert] No suitable pair found in ledger to perform recovery.")
            return
        e1, e2 = pair
        r = e1["r"]
        s1 = e1["s"]
        s2 = e2["s"]
        z1 = e1["hash"]
        z2 = e2["hash"]

        # Print math in symbolic form, then substitute numbers
        print("\n[Proof] ECDSA equations (symbolic):")
        print("  s1 = k^{-1} (z1 + r*d)  (mod n)")
        print("  s2 = k^{-1} (z2 + r*d)  (mod n)")
        print("Subtract: s1 - s2 = k^{-1} (z1 - z2)")
        print("Solve for k: k = (z1 - z2) * (s1 - s2)^{-1} (mod n)")
        print("Recover d: d = (s1*k - z1) * r^{-1} (mod n)")

        print("\n[Proof] Substituting numeric values:")
        print(f"  r  = {r}")
        print(f"  s1 = {s1}")
        print(f"  s2 = {s2}")
        print(f"  z1 = {z1}")
        print(f"  z2 = {z2}")

        denom = (s1 - s2) % CURVE_N
        k_recovered = ((z1 - z2) * modinv(denom, CURVE_N)) % CURVE_N
        d_recovered = ((s1 * k_recovered - z1) * modinv(r, CURVE_N)) % CURVE_N

        print("\n[Result] Computed values:")
        print(f"  k_recovered = {k_recovered}")
        print(f"  d_recovered = {d_recovered}")
        recovered = d_recovered

    # Compare recovered key with real
    real_d = bank.accounts["alice"]["keypair"].private_key
    print("\n[Result] Compare recovered key with real private key:")
    print(f"  real private key : {real_d}")
    print(f"  recovered key    : {recovered}")
    print(f"  match            : {recovered == real_d}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    # If recovered, show takeover flow
    if recovered == real_d:
        print("\n[Info] Demonstrating account takeover using recovered key (impersonation).")
        bank.accounts["alice"]["keypair"].private_key = recovered
        bank.accounts["alice"]["keypair"].public_key = derive_public_key(recovered)

        print("\n[Proof] Balances before forged transaction:")
        bank.show_accounts()
        if not auto_mode:
            auto_mode = pause(auto_mode)

        print("\n[Tx] Attacker submits forged transaction as Alice: alice -> bob $400")
        bank.transfer("alice", "bob", 400)

        print("\n[Proof] Balances after forged transaction:")
        bank.show_accounts()
        if not auto_mode:
            auto_mode = pause(auto_mode)

        print("\n[Info] Freezing compromised account")
        bank.freeze_account("alice")

        print("\n[Tx] Attempt transaction from frozen account (should be rejected):")
        bank.transfer("alice", "bob", 50)

        print("\n[Result] Final ledger:")
        bank.show_ledger()
    else:
        print("\n[Alert] Key recovery failed. No takeover performed.")

    print("\n" + SEPARATOR + "\n")


# ----- demo 2: MITM -----
def demo_mitm(auto_mode=False):
    print_header("Demo 2: Man-in-the-middle — integrity violation (balance proof)")

    bank = VulnerableTransactionSystem()
    alice = UserKeyPair()
    bob = UserKeyPair()
    signer = VulnerableECDSA()

    bank.create_account("alice", 1000, alice, signer=signer)
    bank.create_account("bob", 500, bob, signer=None)

    print("[Proof] Balances before MITM:")
    bank.show_accounts()
    if not auto_mode:
        auto_mode = pause(auto_mode)

    original_msg = "alice pays bob $100"
    z = compute_hash(original_msg)
    r, s = signer.sign(z, alice.private_key)

    print("\n[Tx] Original signed intent (before network):")
    print(f"  message: {original_msg}")
    print(f"  hash: {z}")
    print(f"  signature (r,s): ({r}, {s})")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Alert] MITM modifies the message in transit (example: increase amount).")
    modified_msg = "alice pays bob $1000"
    modified_hash = compute_hash(modified_msg)
    print(f"  delivered message: {modified_msg}")
    print(f"  delivered hash   : {modified_hash}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Info] Bank processes delivered (modified) message — vulnerable to tampering.")
    bank.transfer("alice", "bob", 1000, allow_mitm=True)

    print("\n[Proof] Balances after MITM:")
    bank.show_accounts()

    print("\n[Result] Ledger (note: signature corresponds to original message):")
    bank.show_ledger()
    print("\n" + SEPARATOR + "\n")


# ----- demo 3: forgery -----
def demo_forgery(auto_mode=False):
    print_header("Demo 3: Signature forgery — accepted when verification skipped")

    bank = VulnerableTransactionSystem()
    alice = UserKeyPair()
    bob = UserKeyPair()
    signer = VulnerableECDSA()

    bank.create_account("alice", 1000, alice, signer=signer)
    bank.create_account("bob", 500, bob, signer=None)

    print("[Proof] Alice private key (demo):", alice.private_key)
    if not auto_mode:
        auto_mode = pause(auto_mode)

    fake_r = secrets.randbelow(1 << 256)
    fake_s = secrets.randbelow(1 << 256)
    print("\n[Attack] Attacker crafts forged signature (r,s):")
    print(f"  r = {fake_r}")
    print(f"  s = {fake_s}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Info] Submitting forged transaction to vulnerable bank.")
    bank.transfer("alice", "bob", 999, allow_forgery=True)

    print("\n[Proof] Ledger and balances after forged transaction:")
    bank.show_ledger()
    bank.show_accounts()
    print("\n" + SEPARATOR + "\n")


# ----- demo 4: replay -----
def demo_replay(auto_mode=False):
    print_header("Demo 4: Replay attack — capture and resubmit signed tx")

    bank = VulnerableTransactionSystem()
    alice = UserKeyPair()
    bob = UserKeyPair()
    signer = VulnerableECDSA()

    bank.create_account("alice", 1000, alice, signer=signer)
    bank.create_account("bob", 500, bob, signer=None)

    print("[Proof] Alice private key (demo):", alice.private_key)
    print("[Proof] Balances before any tx:")
    bank.show_accounts()
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Step] Alice sends a legitimate transaction: alice -> bob $150")
    bank.transfer("alice", "bob", 150)
    tx_captured = bank.ledger[-1]
    print("\n[Captured] Exact ledger entry attacker obtains:")
    print(f"  {tx_captured}")
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Attack] Attacker replays the captured transaction (resubmits identical signed tx).")
    tx_replay = tx_captured.copy()
    tx_replay["replayed"] = True
    bank.ledger.append(tx_replay)
    bank.accounts[tx_replay["sender"]]["balance"] -= tx_replay["amount"]
    bank.accounts[tx_replay["receiver"]]["balance"] += tx_replay["amount"]

    print("\n[Proof] Balances after replay (vulnerable bank accepted replay):")
    bank.show_accounts()
    if not auto_mode:
        auto_mode = pause(auto_mode)

    print("\n[Mitigation] Simple detection by tracking seen (sender,hash,r,s) tuples.")
    seen = set()
    duplicate_found = False
    for tx in bank.ledger:
        key = (tx.get("sender"), tx.get("receiver"), tx.get("hash"), tx.get("r"), tx.get("s"))
        if key in seen:
            print("[Alert] Detected duplicate/replay in ledger:")
            print(f"  {tx}")
            duplicate_found = True
            print("[Info] Freezing offending account:", tx["sender"])
            bank.freeze_account(tx["sender"])
            break
        seen.add(key)

    if duplicate_found:
        print("\n[Proof] Attempt transaction from frozen account (should be rejected):")
        bank.transfer("alice", "bob", 10)
        print("\n[Proof] Balances after attempted tx post-freeze:")
        bank.show_accounts()
    else:
        print("\n[Result] No duplicates detected by naive checker (unexpected).")
    print("\n" + SEPARATOR + "\n")


# ----- main menu -----
def main_menu():
    while True:
        print("\n" + SEPARATOR)
        print("Interactive explicit attacks demo".center(LINE_WIDTH))
        print(SEPARATOR)
        print("[Info] Choose a demo:")
        print("  1) Nonce-reuse attack (math + takeover)")
        print("  2) Man-in-the-middle (MITM) attack")
        print("  3) Signature forgery")
        print("  4) Replay attack")
        print("  5) Auto-play all demos (fast)")
        print("  0) Exit")
        choice = input("\nChoice: ").strip()

        if choice == "1":
            demo_nonce_reuse(auto_mode=False)
        elif choice == "2":
            demo_mitm(auto_mode=False)
        elif choice == "3":
            demo_forgery(auto_mode=False)
        elif choice == "4":
            demo_replay(auto_mode=False)
        elif choice == "5":
            demo_nonce_reuse(auto_mode=True)
            time.sleep(0.6)
            demo_mitm(auto_mode=True)
            time.sleep(0.6)
            demo_forgery(auto_mode=True)
            time.sleep(0.6)
            demo_replay(auto_mode=True)
        elif choice == "0":
            print("[Info] Exiting.")
            break
        else:
            print("[Alert] Invalid choice. Enter 0-5.")

if __name__ == "__main__":
    main_menu()
