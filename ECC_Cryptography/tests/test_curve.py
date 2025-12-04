#tests/test_curve.py


import pytest 
from ecc.curve import EllipticCurve, Point

curve = EllipticCurve(
    p=23, a=1, b=1,
    Gx=3, Gy=10,
    n=7
)

def test_point_addition():
    P = Point(3, 10, curve)
    Q = Point(3, 13, curve)
    R = curve.point_add(P, Q)
    assert isinstance(R, Point)

def test_scalar_mult():
    P = Point(3, 10, curve)
    R = curve.scalar_mult(2, P)
    assert isinstance(R, Point)
