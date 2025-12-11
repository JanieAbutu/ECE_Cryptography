# keys.py per user
#######################################################################################
# keys.py defines a UserKeyPair class that represents one user’s ECDSA keypair (private key + public key) 
# Exposes sign and verify functions for that user.
###########################################################################################
from ecdsa import ECDSA

# Create ECDSA keypair for each user
class UserKeyPair:
    def __init__(self):
        self.ecdsa = ECDSA()
        self.private_key = self.ecdsa.private_key
        self.public_key = self.ecdsa.public_key

# User signs with their private key
    def sign(self, message):
        return self.ecdsa.sign(message)

# Checks signature match and validity using public key
    def verify(self, message, signature):
        return self.ecdsa.verify(message, signature, self.public_key)
