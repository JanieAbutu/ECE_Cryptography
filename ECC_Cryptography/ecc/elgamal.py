from random import randint

class ElGamalECC:
    def __init__(self, curve):
        self.curve = curve

    # encode each character to a number modulo the field prime
    def _encode(self, msg: str):
        return [ord(c) % self.curve.p for c in msg]

    # decode list of numbers back to string
    def _decode(self, m_list):
        return "".join(chr(m) for m in m_list)

    def encrypt(self, Q, msg: str):
        p = self.curve.p
        G = self.curve.G
        n = self.curve.n
        m_list = self._encode(msg)

        C1_list = []
        C2_list = []

        for m in m_list:
            k = randint(1, n - 1)
            C1 = k * G
            S = k * Q
            C2 = (m + S.x) % p
            C1_list.append(C1)
            C2_list.append(C2)

        return C1_list, C2_list

    def decrypt(self, d, cipher):
        C1_list, C2_list = cipher
        m_list = []

        for C1, C2 in zip(C1_list, C2_list):
            S = d * C1
            m = (C2 - S.x) % self.curve.p
            m_list.append(m)

        return self._decode(m_list)
