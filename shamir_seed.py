#!/usr/bin/env python3
"""
SLIP-39 Shamir's Secret Sharing for BIP-39 Seed Phrases
Uses Trezor's python-shamir-mnemonic library (local copy)

WARNING: Run this ONLY on an air-gapped, offline machine!
"""

from shamir_mnemonic import generate_mnemonics, combine_mnemonics, MnemonicError

# ============== CONFIGURATION ==============
M = 3  # Minimum shares needed to reconstruct
N = 5  # Total shares to generate
BIP39_WORDLIST_FILE = "bip39_words.txt"
# ===========================================


def load_wordlist(path):
    with open(path, 'r') as f:
        return [w.strip() for w in f.readlines()]


def bip39_to_entropy(words, wordlist):
    """Convert BIP-39 mnemonic words to entropy bytes."""
    indices = [wordlist.index(w) for w in words]
    # Each word is 11 bits
    bit_string = ''.join(format(i, '011b') for i in indices)

    # For 24 words: 264 bits = 256 bits entropy + 8 bits checksum
    # For 12 words: 132 bits = 128 bits entropy + 4 bits checksum
    word_count = len(words)
    if word_count == 24:
        entropy_bits = 256
    elif word_count == 12:
        entropy_bits = 128
    elif word_count == 18:
        entropy_bits = 192
    elif word_count == 15:
        entropy_bits = 160
    else:
        raise ValueError(f"Invalid word count: {word_count}")

    # Extract entropy (without checksum)
    entropy_bit_string = bit_string[:entropy_bits]
    return bytes(int(entropy_bit_string[i:i+8], 2) for i in range(0, entropy_bits, 8))


def entropy_to_bip39(entropy, wordlist):
    """Convert entropy bytes back to BIP-39 mnemonic words."""
    import hashlib

    # Calculate checksum
    h = hashlib.sha256(entropy).digest()

    # Checksum length depends on entropy length
    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32

    # Build bit string: entropy + checksum
    bit_string = ''.join(format(b, '08b') for b in entropy)
    checksum = format(h[0], '08b')[:checksum_bits]
    bit_string += checksum

    # Split into 11-bit groups
    words = []
    for i in range(0, len(bit_string), 11):
        idx = int(bit_string[i:i+11], 2)
        words.append(wordlist[idx])

    return words


def main():
    print("=" * 60)
    print("SLIP-39 Shamir's Secret Sharing for Seed Phrases")
    print(f"Configuration: {M}-of-{N} (need {M} shares to recover)")
    print("=" * 60)
    print()
    print("This tool uses the SLIP-39 standard, compatible with:")
    print("  - Trezor Model T")
    print("  - Other SLIP-39 compatible wallets")
    print()

    wordlist = load_wordlist(BIP39_WORDLIST_FILE)

    print("Choose mode:")
    print("1. Split BIP-39 seed phrase into SLIP-39 shares")
    print("2. Reconstruct BIP-39 seed phrase from SLIP-39 shares")
    print()
    mode = input("Enter 1 or 2: ").strip()

    if mode == "1":
        print()
        print("Enter your seed words (space-separated):")
        print()

        line = input().strip().lower()
        words = line.split()

        word_count = len(words)
        if word_count not in (12, 15, 18, 24):
            print(f"ERROR: Got {word_count} words. BIP-39 requires 12, 15, 18, or 24 words.")
            return

        print(f"Got {word_count} words.")

        # Validate words
        invalid = [w for w in words if w not in wordlist]
        if invalid:
            print(f"WARNING: These words are not in the BIP-39 wordlist: {invalid}")

        # Convert BIP-39 to entropy
        try:
            entropy = bip39_to_entropy(words, wordlist)
        except Exception as e:
            print(f"Error converting seed phrase: {e}")
            return

        # Generate SLIP-39 shares
        # groups is a list of (threshold, count) tuples
        # For simple M-of-N, we use one group with M threshold and N shares
        try:
            mnemonics = generate_mnemonics(
                group_threshold=1,           # Only 1 group needed
                groups=[(M, N)],             # 1 group: M-of-N
                master_secret=entropy,
                passphrase=b"",              # No passphrase (can be added for extra security)
                iteration_exponent=0,        # Faster, less KDF iterations
                extendable=False,            # Better compatibility with older tools
            )
        except Exception as e:
            print(f"Error generating shares: {e}")
            return

        print()
        print("=" * 60)
        print(f"Generated {N} SLIP-39 shares (any {M} can reconstruct):")
        print("=" * 60)
        print()

        for i, mnemonic in enumerate(mnemonics[0], 1):
            print(f"Share {i}:")
            print(f"  {mnemonic}")
            print()

        print("=" * 60)
        print("IMPORTANT: Store these shares in separate secure locations!")
        print("Each share is a 20-word SLIP-39 mnemonic.")
        print("=" * 60)

    elif mode == "2":
        print()
        print(f"Enter {M} SLIP-39 share mnemonics to reconstruct:")
        print("(Each share is typically 20 words)")
        print()

        mnemonics = []
        for i in range(M):
            print(f"Share {i+1}:")
            mnemonic = input("  Enter all words (space-separated): ").strip().lower()
            mnemonics.append(mnemonic)
            print()

        # Recover entropy from SLIP-39 shares
        try:
            entropy = combine_mnemonics(mnemonics, passphrase=b"")
        except MnemonicError as e:
            print(f"Error recovering secret: {e}")
            return

        # Convert entropy back to BIP-39 words
        words = entropy_to_bip39(entropy, wordlist)

        print()
        print("=" * 60)
        print("Reconstructed BIP-39 seed phrase:")
        print("=" * 60)
        print()
        for i, word in enumerate(words, 1):
            print(f"Word {i}: {word}")

        print()
        print("Full phrase:")
        print(" ".join(words))

    else:
        print("Invalid mode")


if __name__ == "__main__":
    main()
