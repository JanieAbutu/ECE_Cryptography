# =======================================
# Encoding Module
# =======================================

# Curve parameters will be passed from outside for flexibility

def sqrt_mod(a, p):
    for x in range(p):
        if (x*x) % p == a:
            return x
    return None

def inv_mod(k, p):
    return pow(k, p-2, p)

# ECC Operations
def ec_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == (-y2 % p):
        return None
    if P != Q:
        m = ((y2 - y1) * inv_mod(x2 - x1, p)) % p
    else:
        m = ((3*x1*x1 + a) * inv_mod(2*y1, p)) % p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p
    return (x3, y3)

def ec_scalar_mul(k, P, a, p):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = ec_add(R, Q, a, p)
        Q = ec_add(Q, Q, a, p)
        k >>= 1
    return R

def ec_neg(P, p):
    x, y = P
    return (x, (-y) % p)

# Encoding
def encode_letter(ch, a, b, p):
    m = ord(ch.upper()) - 65
    offset = 0
    while offset < 200:
        x = (m + offset) % p
        rhs = (x*x*x + a*x + b) % p
        y = sqrt_mod(rhs, p)
        if y is not None:
            if offset == 0:
                print(f"{ch}: maps to {m}, found ({x},{y}), offset={offset}")
            else:
                skipped = ", ".join(str(m + i) for i in range(offset))
                print(f"{ch}: maps to {m}, no points for x={skipped}, first valid ({x},{y}), offset={offset}")
            return (x, y), offset
        offset += 1
    raise ValueError("Encoding failed")

def encode_sentence(sentence, a, b, p):
    encoded = []
    for ch in sentence:
        if ch.isalpha():
            Pm, off = encode_letter(ch, a, b, p)
            encoded.append((Pm, off))
        else:
            encoded.append((ch, None))
    return encoded
