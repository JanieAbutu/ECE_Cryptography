def weak_k_attack():
    print("\n[ATTACK] Weak k attack demonstration...")

    print("This attack only demonstrates how repeated 'k' leaks the private key.")
    print("If two signatures reuse the same k:")
    print("- r stays the same")
    print("- private key becomes solvable through linear equations")
