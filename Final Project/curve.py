# curve.py
# secp256k1 parameters 

# Curve: y^2 = x^3 + ax + b over finite field p
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7

# Generator point
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)

# Order of the generator
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

O = None  # point at infinity

# --- Elliptic Curve Operations ---
def inv_mod(x, p):
    return pow(x, -1, p)

def add(P, Q):
    """Add two points P and Q on the curve."""
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 != y2:
        return None

    if P == Q:
        # Point doubling
        l = (3 * x1 * x1 + a) * inv_mod(2 * y1, p) % p
    else:
        # Point addition
        l = (y2 - y1) * inv_mod(x2 - x1, p) % p

    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p

    return (x3, y3)

def multiply(k, P):
    """Multiply point P by scalar k."""
    R = None
    N = P

    while k > 0:
        if k & 1:
            R = add(R, N)
        N = add(N, N)
        k >>= 1
    return R
