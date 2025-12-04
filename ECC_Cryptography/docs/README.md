# ECC Project — ECDSA & ElGamal Demo

This repository contains an educational, object-oriented ECC framework with:
- ECDSA (RFC6979 deterministic nonce)
- EC ElGamal demo encrypt/decrypt
- Attack demos (nonce reuse)
- Flask web UI to simulate signing/encrypting/attacks
- Tests and CI

## Quick start

1. Create a virtualenv and install:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

2. Run tests:

pytest -q


3. Run web app:

python app/app.py
# open http://127.0.0.1:5000

Notes

ElGamal encoder is demo-only (not RFC hash-to-curve).

Never use demo secrets in production.


---

# How to integrate and run (step-by-step)

1. Create the folder structure exactly as shown and save each file with the contents above.

2. Create a Python virtual environment and install requirements:
```bash
#python -m venv .venv
#source .venv/bin/activate    # or .venv\Scripts\activate on Windows
#pip install -r requirements.txt


3.Run tests:

pytest -q


Run the Flask app for demos:

python app/app.py
# then open http://127.0.0.1:5000

