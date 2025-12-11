
### Project: Securing Banking Transactions Using ECDSA

This project was developed for an advanced cryptography course to see, understand, and interactively experience how real-world ECDSA vulnerabilities can completely compromise digital signing systems.

**The demos show:**
- How ECDSA signatures work 
- How insecure implementations introduce attacks
- How attackers extract private keys, forge transactions, and modify messages
- How replay attacks bypass naive verifiers
- Differences between secure and insecure ECDSA

**Project Structure:**
Final Project/
|--- curve.py                 # Elliptic curve operations (add, multiply, G, n)
|--- ecdsa.py                 # ECDSA implementation
|--- transaction.py           # Banking system
|--- keys.py                  # Creates ECDSA keypair (private and public per user)
|--- ledger.py                # Logs transactions
|--- utils.py                 # Shows nonce reuse vulnerability
|--- main.py                  # Interactive CLI to run the transaction logic
|
|--vuln/
│   |--- ecdsa_vuln.py          # Intentionally vulnerable ECDSA for nonce-reuse attack
|   |--- nonce_attack.py         # Standalone demo showing nonce reuse vulnerability (how it works)
|   |--- nonce_attacker.py       # Nonce attack module two that monitors system transactions and automatically performs key recovery when nonce reuse happens.
|   |--- transaction_vuln.py     # Intentional Vulnerable Banking system
|
|
|
|--- interactive_demo.py         # Interactive CLI menu to run the attack simulation logic
|--- README.md                   # Documentation


### Features
**- Fully Interactive CLI**
Users can:
1. Create accounts
2. View balances
3. Make signed transfers
4. Show ledger
5. Verify ledger signatures

**- Attack Simulation**
**A. Nonce-Reuse Attack (Private Key Extraction)**
- Uses same k in two signatures
- Recover private key using
- Prints:
1. original private key
2. recovered private key
3. verification that both match
4. forged transaction using recovered key

**B.  MITM Attack (Message Tampering)**
- User signs legitimate message (e.g., Alice pays Bob $100)
- Attacker modifies message in transit (e.g., to $1000)
- Signature verification is skipped in the vulnerable version
- Updated balances printed to show impact

**C. Forgery Attack (Signature Skipping)**
- Attacker sends unsigned transaction
- Vulnerable verifier accepts it
- Balance changes without any signature

**D. Replay Attack**
- Attacker resends old signed message
- Bank processes it again
- Balance decreases twice
- Demonstrates the need for:
   + nonces
   + sequence numbers
   + live session tokens

##Installation
**Requirements**
- Python 3.10 or newer
- No external dependencies required
- Run the project:
**python main.py**                   # For transaction simulation
**Example Output**                   # You will see an interactive menu.
   1. Create account
   2. Show accounts
   3. Transfer money
   4. Show ledger
   5. Verify ledger transaction
   0. Exit

   Name: alice       # Enter name
   Balance: 800      # Enter balance
   Account 'alice' created.
   Public key: (...)

**python interactive_demo.py**      # For attack simulation demo
**Each attack prints:**
   - Private and public keys
   - Message hash z
   - Nonce k
   - Signature (r, s)
   - Verification result
   - Attack process
   - Post-attack balances

 
### Lessons Learnt:
- How ECDSA signing mathematically works
- Why nonce reuse instantly reveals private keys
- Why signature verification must always be enforced
- Why message hashing prevents tampering
- Why freshness markers prevent replay attacks
- Differences between correct and incorrect implementations

