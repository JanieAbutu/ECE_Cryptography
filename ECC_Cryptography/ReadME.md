# ECC Banking Simulation & Attack Lab

This project provides a realistic, interactive demonstration of Elliptic Curve Cryptography (ECC) used in digital banking systems. It includes:

* A simulated banking app using ECC keys and ECDSA signatures
* Multiple attack scenarios: replay, forgery, MITM, malleability, weak-k
* Interactive hybrid CLI demo
* Security diagrams and architectural flow
* Logging / audit trail system
* Web UI version

## Folder Structure

```
project_root/
│
├── ecc/                   # ECC core implementation
├── simulations/           # Banking app + attacks
├── demo/                  # Interactive CLI demo
├── webui/                 # Web interface version
├── logs/                  # Audit logs generated at runtime
└── README.md
```

## Features

### ✔ Banking Transactions

* User can initiate transfers
* System signs transactions using ECDSA
* Verification ensures authenticity and integrity

### ✔ Attack Simulations

1. Replay attack
2. Signature forgery attempt
3. MITM tampering
4. Signature malleability
5. Weak random-k exploit explanation

### ✔ Web UI

* Clean interactive interface using Flask + HTML + Tailwind
* Users can perform transactions and simulate attacks visually

### ✔ Audit Logs

Every action is recorded for security traceability:

* Transactions
* Attacks
* Key generation
* Verifications

Logs stored in `logs/audit.log`

## Running the CLI Demo

```
python demo/interactive_demo.py
```

## Running the Web App

```
python webui/app.py
```

Open browser:

```
http://127.0.0.1:5000
```
