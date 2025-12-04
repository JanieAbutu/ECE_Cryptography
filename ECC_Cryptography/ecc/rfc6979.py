#Flow of Data
#Hash the message using SHA-256 (done in ECDSA module)
#RFC 6979 HMAC procedure generates deterministic k
#k is used in signature (r, s) generation


# ecc/rfc6979.py
import hmac
import hashlib


def int2octets(x, rlen):
    """Convert integer x to rlen-length octet string."""
    return x.to_bytes(rlen, byteorder='big')


def bits2octets(b, qlen, q):
    """Convert hash to integer -> then to octets modulo q."""
    z1 = int.from_bytes(b, 'big')
    z2 = z1 if qlen >= len(b) * 8 else z1 >> (len(b)*8 - qlen)
    return int2octets(z2 % q, (qlen + 7) // 8)


def rfc6979_generate_k(msg_hash, private_key, q):
    """
    Deterministic k generation per RFC 6979.
    msg_hash: bytes
    private_key: int
    q: curve order
    """
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8

    x = private_key
    h1 = msg_hash

    # Step: Convert x and h1 to octets
    bx = int2octets(x, rlen)
    bh = bits2octets(h1, qlen, q)

    # Step: Initialize V and K
    V = b'\x01' * 32
    K = b'\x00' * 32

    # Step: K = HMAC_K(V || 0x00 || bx || bh)
    K = hmac.new(K, V + b'\x00' + bx + bh, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Step: K = HMAC_K(V || 0x01 || bx || bh)
    K = hmac.new(K, V + b'\x01' + bx + bh, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Loop
    while True:
        T = b''
        while len(T) < rlen:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V

        k = int.from_bytes(T[:rlen], 'big')
        if 1 <= k < q:
            return k  # Valid RFC 6979 nonce

        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()
