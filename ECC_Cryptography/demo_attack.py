from ecdsa_core import generate_keys, sign_message, inverse_mod

def recover_private_key(r, s1, s2, z1, z2):
    k = ((z1 - z2) * inverse_mod(s1 - s2, N)) % N
    private_key = ((s1 * k - z1) * inverse_mod(r, N)) % N
    return private_key

# Simulate nonce reuse attack
private_key, public_key = generate_keys()
message1 = "Alice -> Bob: $100"
message2 = "Alice -> Charlie: $200"

(sig1, k) = sign_message(private_key, message1)
(sig2, _) = sign_message(private_key, message2)  # Reuse same k for demo

r1, s1 = sig1
r2, s2 = sig2
z1 = int.from_bytes(message1.encode(), 'big')
z2 = int.from_bytes(message2.encode(), 'big')

# Recover private key
recovered_key = recover_private_key(r1, s1, s2, z1, z2)
print("\nOriginal private key:", private_key)
print("Recovered private key (nonce reuse):", recovered_key)
