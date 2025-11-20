# =====================================
#  RSA UTILITY FUNCTIONS (MODULAR)
# =====================================

def egcd(a, b):
    """
    Extended Euclidean Algorithm.
    Returns gcd and Bézout coefficients.
    Used to compute modular inverse.
    """
    if b == 0:
        return a, 1, 0

    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    """
    Compute modular inverse of a modulo m.
    Solves: a * d ≡ 1 (mod m)
    """
    g, x, _ = egcd(a, m)

    if g != 1:
        raise Exception("No modular inverse exists.")

    return x % m


def generate_private_key(p, q, e):
    """
    Generate RSA values:
        n = p * q
        phi = (p-1)(q-1)
        d = modular inverse of e mod phi
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)

    return n, phi, d


def rsa_encrypt(message, e, n):
    """
    Encrypt using:
        ciphertext = message^e mod n
    """
    return pow(message, e, n)


def rsa_sign(value, d, n):
    """
    Sign using:
        signature = value^d mod n
    """
    return pow(value, d, n)


def rsa_verify(signature, e, n):
    """
    Verify signature:
        verified_value = signature^e mod n
    Returns value that should match original signed value.
    """
    return pow(signature, e, n)
