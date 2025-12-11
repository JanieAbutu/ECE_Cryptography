# nonce_attack.py - just to show how nonce reuse work
########################################################################################
# Demonstrates ECDSA Vulnerability (Reusing the same nonce k when signing different messages)
# Private key recovery
#######################################################################################
from ecdsa import ECDSA
from curve import n

def nonce_reuse_attack():
    print("\n=== NONCE REUSE ATTACK DEMO ===")

    ecdsa = ECDSA()
    d = ecdsa.private_key

    k = 123456789  # reused nonce (INSECURE)

    m1 = "Alice pays Bob $100"
    m2 = "Alice pays Charlie $200"

    (r, s1), z1 = ecdsa.sign_with_nonce(m1, k)
    (_, s2), z2 = ecdsa.sign_with_nonce(m2, k)

    print("\nSame nonce k used!")
    print(f"Signature 1: r={r}, s1={s1}")
    print(f"Signature 2: r={r}, s2={s2}")

    recovered_k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
    recovered_d = ((s1 * recovered_k - z1) * pow(r, -1, n)) % n

    print("\n=== RECOVERY ===")
    print("Original private key :", d)
    print("Recovered private key:", recovered_d)

    print("\nAttack successful ✅" if d == recovered_d else "Attack failed ❌")
