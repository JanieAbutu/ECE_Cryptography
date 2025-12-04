# ecc/curve.py

class Point:
    """Represents a point on an elliptic curve."""
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve  # <-- CRITICAL

    def __eq__(self, other):
        return (
            isinstance(other, Point) and
            self.x == other.x and self.y == other.y
        )

    def __repr__(self):
        if self.x is None and self.y is None:
            return "Point(infinity)"
        return f"Point({self.x}, {self.y})"

    # ----------- Point ADDITION -----------
    def __add__(self, Q):
        curve = self.curve
        p, a = curve.p, curve.a

        # Point at infinity rules
        if self.x is None:
            return Q
        if Q.x is None:
            return self

        # If P == -Q → infinity
        if self.x == Q.x and (self.y + Q.y) % p == 0:
            return curve.O

        # Slope m
        if self == Q:
            # Doubling
            m = (3 * self.x * self.x + a) * pow(2 * self.y, -1, p)
            m %= p
        else:
            # Addition
            m = (Q.y - self.y) * pow(Q.x - self.x, -1, p)
            m %= p

        # Result coordinates
        xr = (m * m - self.x - Q.x) % p
        yr = (m * (self.x - xr) - self.y) % p

        return Point(xr, yr, curve)

    # ----------- Scalar multiplication (double-and-add) -----------
    def __rmul__(self, k):
        return self.__mul__(k)

    def __mul__(self, k):
        result = self.curve.O
        addend = self

        while k > 0:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1

        return result


class EllipticCurve:
    """Elliptic curve over finite field: y^2 = x^3 + ax + b (mod p)."""
    def __init__(self, p, a, b, Gx, Gy, n):
        self.p = p
        self.a = a
        self.b = b
        self.n = n

        # generator and infinity point
        self.G = Point(Gx, Gy, self)
        self.O = Point(None, None, self)

    # ----------- Modular inverse helper -----------
    def inverse_mod(self, k):
        """Modular inverse of k modulo p."""
        if k == 0:
            raise ZeroDivisionError("Cannot invert 0 in modular arithmetic.")
        return pow(k, -1, self.p)

    # ----------- Point addition helper -----------
    def point_add(self, P, Q):
        """Add two points P and Q on the curve."""
        return P + Q

    # ----------- Scalar multiplication helper -----------
    def scalar_mult(self, k, P):
        """Multiply point P by scalar k using double-and-add."""
        return k * P
