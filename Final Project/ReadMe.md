
# Project: Securing Banking Transactions Using ECDSA

The project focuses on hands‑on exploitation, showing how incorrect integration of cryptography — not weak algorithms — leads to severe security breaches. The work emphasizes why cryptographic correctness alone is insufficient without proper protocol enforcement.

## 1. Objective and Motivation
The objective of this project was to study, demonstrate, and analyze real‑world cryptographic failures in ECDSA‑based transaction systems by building both secure and intentionally vulnerable implementations of a digital banking and ledger environment.

Rather than treating cryptographic attacks purely theoretically, the project focuses on hands‑on exploitation, showing how incorrect integration of cryptography — not weak algorithms - leads to severe security breaches. The work emphasizes why cryptographic correctness alone is insufficient without proper protocol enforcement.

## 2. System Architecture
The project is composed of two parallel systems:
**2.1 Secure Transaction System**
- Implements correct ECDSA signing and verification
- Enforces message integrity, authentication, and replay protection
- Uses per‑user key pairs and a verified transaction ledger

**2.2 Vulnerable Transaction System**
- Intentionally omits or weakens security checks
- Enables controlled demonstrations of cryptographic attacks
- Allows observation of real attack consequences in a deterministic environment
This dual‑system design allows for direct comparison between correct and incorrect cryptographic usage.

## 3. Project Structure:
**Final Project/**
- |--- curve.py                    # Elliptic curve operations (add, multiply, G, n)
- |--- ecdsa.py                    # ECDSA implementation
- |--- transaction.py              # Banking system
- |--- keys.py                     # Creates ECDSA keypair (private and public per user)
- |--- ledger.py                   # Logs transactions
- |--- utils.py                    # Shows nonce reuse vulnerability
- |--- main.py                     # Interactive CLI to run the transaction logic
- |
- |--vuln/
- │   |--- ecdsa_vuln.py          # Intentionally vulnerable ECDSA for nonce-reuse attack
- |   |--- nonce_attack.py         # Standalone demo showing nonce reuse vulnerability (how it works)
- |   |--- nonce_attacker.py       # Nonce attack module two that monitors system transactions and automatically performs key recovery when nonce reuse happens.
- |   |--- transaction_vuln.py     # Intentional Vulnerable Banking system
- |
- |
- |
- |--- interactive_demo.py         # Interactive CLI menu to run the attack simulation logic
- |--- README.md                   # Documentation

## 4. Cryptographic Foundations
3.1 ECDSA Implementation
- Elliptic Curve Digital Signature Algorithm (ECDSA) is used for transaction authorization.
- Each user possesses:
- 1. A private signing key
- 2. A corresponding public verification key
- Transactions are signed over a SHA‑256 message hash.
Two ECDSA variants are implemented:
- 1. Secure ECDSA: Uses proper nonce generation and verification
- 2.  Vulnerable ECDSA: Allows fixed or reused nonces and skips protections
This separation enables controlled exploitation without compromising core logic clarity.

## 5. Key Management and Identity
Each user is assigned a unique cryptographic identity encapsulated in a UserKeyPair abstraction:
- Private keys remain local to the user
- Public keys are shared and used for verification
- Signing and verification operations are cleanly abstracted
- This mirrors real‑world public‑key infrastructure concepts while remaining educational and transparent.

## 6. Transaction Processing Workflow
A transaction follows this logical flow:
1. The sender constructs a transaction message describing intent.
2. The message is hashed using SHA‑256.
3. The sender signs the hash using ECDSA.
4. The system verifies the signature against the sender’s public key.
5. Upon successful verification, balances are updated and the transaction is recorded.

In the vulnerable system, specific steps are intentionally skipped or weakened to demonstrate attack feasibility.

**Features**
- Fully Interactive CLI**
- Users can:
- - 1. Create accounts
- - 2. View balances
- - 3. Make signed transfers
- - 4. Show ledger
- - 5. Verify ledger signatures

## 7. Implemented Attacks and Demonstrations
### 7.1 Nonce‑Reuse Attack
**- Why:**
- - ECDSA security critically depends on generating a fresh random nonce (k) for each signature.

**- How:**
- - A vulnerable signer is configured to reuse a fixed nonce.
- - Two distinct messages are signed using the same nonce.
- - Identical r values reveal nonce reuse.
- - The attacker uses known ECDSA equations to recover:
- - - The nonce k
- - - The private key d
**- Result:**
Complete private key compromise, enabling account takeover and transaction forgery.
**- Attack Simulation**
**A. Nonce-Reuse Attack (Private Key Extraction)**

### 7.2 Man‑in‑the‑Middle (MITM) Message Tampering
**- Why:**
Digital signatures bind the message contents to the signer. Skipping verification breaks this guarantee.

**- How:**
- - A legitimate transaction is signed.
- - An attacker modifies the message (e.g., increases transfer amount).
- - The vulnerable system processes the modified message without verifying the signature.
**-Result:**
Unauthorized balance modifications while preserving a valid‑looking signature record.

### 7.3 Signature Forgery**
**- Why:**
A system that does not validate signatures cannot distinguish legitimate users from attackers.
**- How:**
- - The attacker submits random (r, s) values as a forged signature.
- - The vulnerable system accepts the transaction due to skipped verification.
**- Result:**
Full authentication bypass with arbitrary fund transfers.

###  7.4 Replay Attack**
**- Why:**
Signed transactions remain valid unless uniqueness or freshness is enforced.
**- How:**
- - A valid signed transaction is captured from the ledger.
- - The same transaction is resubmitted verbatim.
- - The vulnerable system processes it again as new.
**- Result:**
Double‑spending and repeated balance manipulation.

**Summary**
The attack demos show:
- How ECDSA signatures work 
- How insecure implementations introduce attacks
- How attackers extract private keys, forge transactions, and modify messages
- How replay attacks bypass naive verifiers
- Differences between secure and insecure ECDSA 

## 8. Security Mitigations Demonstrated
*- The project also illustrates practical defenses, including:**
- - Mandatory signature verification
- - Replay detection via signature tracking
- - Account freezing upon anomaly detection
- - Clear separation between data, control, and cryptographic layers
- - Transaction logging for visiibility and traceability
These mitigations reinforce industry best practices.


## 9. Installation
**Requirements**
- - Python 3.10 or newer
- - No external dependencies required
- - Run the project:

# For transaction simulation, run:

**python main.py** 

**-You will see an interactive menu.**           
*- Example Output*               
- 1. Create account
- 2. Show accounts
- 3. Transfer money
- 4. Show ledger
- 5. Verify ledger transaction
- 0. Exit
                 
- - Name: alice       # Enter name
- - Balance: 800      # Enter balance
- - Account 'alice' created.
- - Public key: (...)

## For attack simulation demo, run: 

**python interactive_demo.py**  

**-You will see an interactive menu.** 
*- Choose a demo:*
- 1) Nonce-reuse attack (math + takeover)
- 2) Man-in-the-middle (MITM) attack
- 3) Signature forgery
- 4) Replay attack
- 5) Auto-play all demos (fast)
- 0) Exit

**Each attack prints:**
- - Private and public keys
- - Message hash z
- - Nonce k
- - Signature (r, s)
- - Verification result
- - Attack process
- - Post-attack balances

 
## 10. Key Insights and Lessons Learned
- How ECDSA signing mathematically works
- Cryptographic algorithms are only secure when used correctly
- ECDSA nonce misuse leads to immediate key compromise
- Skipping verification is equivalent to having no cryptography at all
- Replay attacks highlight the importance of transaction uniqueness
- Defense‑in‑depth is essential in financial and distributed systems

#*Future Implementation:*
1. Deterministic nonces (RFC 6979)
2. Other relevant updates

## 11. Conclusion

This project demonstrates that most real‑world cryptographic failures arise from implementation and protocol errors, not algorithmic weaknesses. By constructing vulnerable systems alongside secure counterparts, the work provides a practical and educational exploration of how cryptography fails — and how it must be correctly applied to succeed.

The resulting framework serves both as:
- A learning platform for applied cryptography
- A cautionary example of insecure system design