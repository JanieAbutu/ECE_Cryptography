# app/app.py
"""
Flask web application for ECC/ECDSA demonstration.

Provides:
 - key generation
 - ElGamal encrypt / decrypt (demo encoder)
 - ECDSA sign / verify (RFC6979 deterministic k)
 - Attack demo: k-reuse private key recovery
"""

from flask import Flask, render_template, request, redirect, url_for, flash
import hashlib

# import ECC framework modules (adjust imports depending on your package layout)
# If ecc is a package (folder named ecc with __init__.py), use:
from ecc.curve import EllipticCurve, Point
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA
from ecc.elgamal import ElGamalECC
from ecc.attacks import demo_k_reuse_attack

app = Flask(__name__)
app.secret_key = "dev-secret-key-for-demo"  # use secure secret in production

# Initialize curve and components (secp256k1)
curve = EllipticCurve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=55066263022277343669578718895168534326250603453777594175500187360389116729240,
    Gy=32670510020758816978083085130507043184471273337482424,  # NOTE: fix below in template if needed
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

# The previous Gx/Gy in earlier code used large integers; ensure you copy correct Gy value
# Use the standard values below for secp256k1 if the above is wrong:
curve.G = Point(
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)

# Keypair for demo (server-side single identity)
keypair = ECCKeyPair(curve)
private_key, public_key = keypair.generate_keys()

ecdsa = ECDSA(curve, private_key=private_key, public_key=public_key)
elgamal = ElGamalECC(curve)

def hash_message_str(msg: str) -> int:
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big')

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html",
                           public_key=public_key,
                           result=None)

@app.route("/sign", methods=["POST"])
def sign():
    message = request.form.get("message", "")
    if not message:
        flash("Please enter a message to sign.")
        return redirect(url_for('index'))

    sig = ecdsa.sign(message)
    return render_template("index.html",
                           public_key=public_key,
                           result={
                               "action": "sign",
                               "message": message,
                               "signature": sig
                           })

@app.route("/verify", methods=["POST"])
def verify():
    message = request.form.get("message", "")
    r = request.form.get("r", "")
    s = request.form.get("s", "")
    try:
        r_int = int(r)
        s_int = int(s)
    except:
        flash("Invalid r or s (must be integers).")
        return redirect(url_for('index'))

    valid = ecdsa.verify(message, (r_int, s_int), public_key)
    return render_template("index.html",
                           public_key=public_key,
                           result={
                               "action": "verify",
                               "message": message,
                               "signature": (r_int, s_int),
                               "valid": valid
                           })

@app.route("/encrypt", methods=["POST"])
def encrypt():
    message = request.form.get("message_encrypt", "")
    if not message:
        flash("Please enter a message to encrypt.")
        return redirect(url_for('index'))

    C1, C2 = elgamal.encrypt(public_key, message)
    # provide compact serializable strings for display; not secure serialization
    c1 = (C1.x, C1.y)
    c2 = (C2.x, C2.y)
    return render_template("index.html",
                           public_key=public_key,
                           result={
                               "action": "encrypt",
                               "message": message,
                               "ciphertext": (c1, c2)
                           })

@app.route("/decrypt", methods=["POST"])
def decrypt():
    # Expect coordinates posted as ints
    try:
        c1x = int(request.form.get("c1x"))
        c1y = int(request.form.get("c1y"))
        c2x = int(request.form.get("c2x"))
        c2y = int(request.form.get("c2y"))
    except:
        flash("Invalid ciphertext coordinates.")
        return redirect(url_for('index'))

    C1 = Point(c1x, c1y)
    C2 = Point(c2x, c2y)
    try:
        pt = elgamal.decrypt(private_key, (C1, C2))
    except Exception as e:
        flash(f"Decryption error: {e}")
        return redirect(url_for('index'))

    return render_template("index.html",
                           public_key=public_key,
                           result={
                               "action": "decrypt",
                               "plaintext": pt
                           })

@app.route("/attack", methods=["POST"])
def attack():
    # Run demo attack: two messages -> forced-nonce signing -> recover private key
    m1 = request.form.get("attack_m1", "Alice->Bob:100")
    m2 = request.form.get("attack_m2", "Alice->Charlie:200")
    res = demo_k_reuse_attack(curve, private_key, m1, m2, hash_message_str)
    return render_template("index.html",
                           public_key=public_key,
                           result={
                               "action": "attack",
                               "attack_result": res
                           })

if __name__ == "__main__":
    app.run(debug=True)
