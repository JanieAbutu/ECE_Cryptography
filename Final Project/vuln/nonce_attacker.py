# vuln/nonce_attacker.py

#################################################################################################
# Implements an ECDSA nonce-reuse attack detector and private-key recovery engine.
# Detect when two ECDSA signatures reuse the SAME nonce
# Recover the private key automatically
# Store the recovered private key for later use
################################################################################################

from math import gcd
from vuln.ecdsa_vuln import CURVE_N
from math import inf

class NonceReuseAttacker:
    def __init__(self):
        # keep map of observed signatures by r
        self.observed = {}
        self.recovered_private_key = None

    def observe(self, tx):
        """
        Observe a transaction (tx is a dict containing 'r', 's', 'hash', 'sender', ...).
        If two signatures using the same r are observed for the same sender, attempt recovery.
        """
        r = tx.get("r")
        s = tx.get("s")
        z = tx.get("hash")
        sender = tx.get("sender")

        if r is None or s is None:
            return

        key = (sender, r)
        if key in self.observed:
            # found nonce reuse for same sender and r
            prev = self.observed[key]
            print("[Alert] Nonce reuse detected for sender:", sender)
            print(f"  previous s: {prev['s']}, new s: {s}")
            print(f"  previous hash: {prev['hash']}, new hash: {z}")
            # attempt recovery
            try:
                self._recover_from_pair(prev['s'], s, prev['hash'], z, r)
            except Exception as e:
                print(f"[Warning] Recovery attempt failed: {e}")
        else:
            self.observed[key] = {"s": s, "hash": z}

    def _recover_from_pair(self, s1, s2, z1, z2, r):
        """
        Recover k and private key d from two signatures s1,s2 with same r:
        k = (z1 - z2) / (s1 - s2) mod n
        d = (s1*k - z1) / r mod n
        """
        print("[Info] Attempting math-based recovery of nonce and private key")
        n = CURVE_N
        denom = (s1 - s2) % n
        if denom == 0:
            raise ValueError("s1 - s2 == 0 (cannot invert); recovery aborted")

        k = ((z1 - z2) * pow(denom, -1, n)) % n
        d = ((s1 * k - z1) * pow(r, -1, n)) % n

        self.recovered_private_key = d
        print("[Result] Private key recovery successful")
        print(f"  Recovered k : {k}")
        print(f"  Recovered d : {d}")
