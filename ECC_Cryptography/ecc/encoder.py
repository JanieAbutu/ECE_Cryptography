# ecc/encoder.py

def encode_point(point):
    """
    Encode a point (tuple or Point object) into bytes.
    Format: [2 bytes length | x bytes | y bytes]
    """
    if point is None:
        return b"INF"

    # Accept tuple or Point object
    if isinstance(point, tuple):
        x, y = point
    else:
        x, y = point.x, point.y

    xb = x.to_bytes((x.bit_length() + 7) // 8, 'big')
    yb = y.to_bytes((y.bit_length() + 7) // 8, 'big')

    return len(xb).to_bytes(2, 'big') + xb + yb


def decode_point(encoded: bytes):
    """
    Decode the bytes back to (x, y).
    This matches the encode_point() format.
    """
    if encoded == b"INF":
        return None

    L = int.from_bytes(encoded[:2], "big")
    xb = encoded[2:2+L]
    yb = encoded[2+L:]

    x = int.from_bytes(xb, "big")
    y = int.from_bytes(yb, "big")
    return (x, y)
