# ==============================
# MAIN MODULE – FULLY CONFIGURABLE
# ==============================

from config import (
    ALT_p, ALT_q, ALT_e,
    BHA_p, BHA_q, BHA_e,
    MESSAGE_X,
    SIG_A_VALUE,
    SIG_B_EXPECTED,
    RECEIVED_SIG_YAB
)

from rsa_utils import (
    generate_private_key,
    rsa_encrypt,
    rsa_sign,
    rsa_verify
)

def rsa_decrypt_int(value, d, n):
    """
    Decrypt an integer value using private key (RSA)
    """
    return pow(value, d, n)

def main():
    print("===== RSA DEBUG TRACE =====")

    # --------------------------------------------------------
    # 1. Generate private keys
    # --------------------------------------------------------
    print("\nGenerating Altair's private key...")
    print(f"Inputs: p={ALT_p}, q={ALT_q}, e={ALT_e}")
    nA, phiA, dA = generate_private_key(ALT_p, ALT_q, ALT_e)
    print(f"Output: nA={nA}, phiA={phiA}, dA={dA}")

    print("\nGenerating Bharani's private key...")
    print(f"Inputs: p={BHA_p}, q={BHA_q}, e={BHA_e}")
    nB, phiB, dB = generate_private_key(BHA_p, BHA_q, BHA_e)
    print(f"Output: nB={nB}, phiB={phiB}, dB={dB}")

    # --------------------------------------------------------
    # 2. Altair encrypts MESSAGE_X for Bharani
    # --------------------------------------------------------
    print("\nEncrypting message for Bharani...")
    print(f"Inputs: message={MESSAGE_X}, e={BHA_e}, n={nB}")
    encrypted_msg = rsa_encrypt(MESSAGE_X, BHA_e, nB)
    print(f"Output (ciphertext) = {encrypted_msg}")

    # --------------------------------------------------------
    # 3. Altair signs SIG_A_VALUE
    # --------------------------------------------------------
    print("\nSigning value for Altair...")
    print(f"Inputs: value={SIG_A_VALUE}, d={dA}, n={nA}")
    altair_signature = rsa_sign(SIG_A_VALUE, dA, nA)
    print(f"Output (signature) = {altair_signature}")

    # --------------------------------------------------------
    # 4. Verify Bharani’s signature (Step 1)
    # --------------------------------------------------------
    print("\nStep 1: Verify Bharani’s signature using public key...")
    print(f"Inputs: signature={RECEIVED_SIG_YAB}, e={BHA_e}, n={nB}")
    s_b = rsa_verify(RECEIVED_SIG_YAB, BHA_e, nB)
    print(f"Output after public key verification (s_b) = {s_b}")
  
