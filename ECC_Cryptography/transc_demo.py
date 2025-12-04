from ecc.curve import EllipticCurve
from ecc.keys import ECCKeyPair
from ecc.ecdsa import ECDSA

# Setup curve (use same curve you used in the tests)
curve = EllipticCurve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=55066263022277343669578718895168534326250603453777594175500187360389116729240,
    Gy=32670510020758816978083085130507043184471273380659243275938904335757337482424,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

print("\n=== BANKING TRANSACTION DEMO ===")

# 1. Customer generates keys
customer_keys = ECCKeyPair(curve)
private_key, public_key = customer_keys.generate_keys()

ecdsa = ECDSA(curve, private_key=private_key, public_key=public_key)

# 2. Customer creates a transaction message
transaction = "TRANSFER: ₦2500000 FROM 023XXXX TO 112XXXX"

# 3. Customer signs it
signature = ecdsa.sign(transaction)

print("\nTransaction:", transaction)
print("Signature:", signature)

# 4. Bank receives: (message, signature, public_key)
verified = ecdsa.verify(transaction, signature, public_key)
print("\nVerification result:", verified)

# 5. ATTACK TEST — attacker modifies the message
tampered = "TRANSFER: ₦9500000 FROM 023XXXX TO 112XXXX"   # attacker increases amount

print("\nTampered transaction:", tampered)
verified_tampered = ecdsa.verify(tampered, signature, public_key)
print("Verification on tampered message:", verified_tampered)
