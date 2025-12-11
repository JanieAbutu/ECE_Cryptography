# utils.py
# Shows nonce reuse vulnerability
from curve import G, secp256k1, n

def demo_nonce_vulnerability(priv_key):
    print("\n=== Nonce Vulnerability Demo ===")
    message = "Transfer $1000 to Alice"
    k = 123456  # Fixed nonce (BAD PRACTICE)
    z = int.from_bytes(message.encode(), 'big')
    R = secp256k1.scalar_mult(k, G)
    r = R[0] % n
    k_inv = pow(k, -1, n)
    s = (k_inv * (z + r * priv_key)) % n
    print(f"Message: {message}")
    print(f"Signature with fixed nonce: (r={r}, s={s})")
    print("Warning: Fixed or repeated k can reveal the private key!")
