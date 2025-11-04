from aes_core import sub_bytes, shift_rows, mix_columns, add_round_key, inv_sub_bytes, inv_shift_rows, inv_mix_columns

def aes_encrypt_block(plaintext, round_keys):
    state = [[plaintext[r + 4*c] for c in range(4)] for r in range(4)]
    state = add_round_key(state, round_keys[0])
    for rnd in range(1,10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return [state[r][c] for c in range(4) for r in range(4)]

def aes_decrypt_block(ciphertext, round_keys):
    state = [[ciphertext[r + 4*c] for c in range(4)] for r in range(4)]
    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for rnd in range(9,0,-1):
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return [state[r][c] for c in range(4) for r in range(4)]
