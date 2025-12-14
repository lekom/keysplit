#!/usr/bin/env python3
"""Test that any 3 of 5 SLIP-39 shares can reconstruct the seed phrase."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from itertools import combinations
from shamir_mnemonic import generate_mnemonics, combine_mnemonics

EXPECTED_PHRASE = """
motor wrestle amateur want snap minor today cup grunt smoke twelve toast loop crouch veteran company typical ahead enhance clown parade banner legal stumble
"""


def load_wordlist(path):
    with open(path, 'r') as f:
        return [w.strip() for w in f.readlines()]


def bip39_to_entropy(words, wordlist):
    """Convert BIP-39 mnemonic words to entropy bytes."""
    indices = [wordlist.index(w) for w in words]
    bit_string = ''.join(format(i, '011b') for i in indices)
    word_count = len(words)
    if word_count == 24:
        entropy_bits = 256
    elif word_count == 12:
        entropy_bits = 128
    else:
        raise ValueError(f"Invalid word count: {word_count}")
    entropy_bit_string = bit_string[:entropy_bits]
    return bytes(int(entropy_bit_string[i:i+8], 2) for i in range(0, entropy_bits, 8))


def entropy_to_bip39(entropy, wordlist):
    """Convert entropy bytes back to BIP-39 mnemonic words."""
    import hashlib
    h = hashlib.sha256(entropy).digest()
    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32
    bit_string = ''.join(format(b, '08b') for b in entropy)
    checksum = format(h[0], '08b')[:checksum_bits]
    bit_string += checksum
    words = []
    for i in range(0, len(bit_string), 11):
        idx = int(bit_string[i:i+11], 2)
        words.append(wordlist[idx])
    return words


def main():
    wordlist_path = Path(__file__).parent.parent / "bip39_words.txt"
    wordlist = load_wordlist(wordlist_path)
    expected_words = EXPECTED_PHRASE.lower().split()
    word_count = len(expected_words)

    print(f"Expected BIP-39 seed phrase ({word_count} words):")
    print(" ".join(expected_words))
    print()

    # Convert BIP-39 to entropy
    entropy = bip39_to_entropy(expected_words, wordlist)
    print(f"Master secret: 0x{entropy.hex()}")
    print(f"Length: {len(entropy)} bytes ({len(entropy)*8} bits)")
    print()

    # Generate 5 SLIP-39 shares with threshold 3
    print("Generating SLIP-39 shares (3-of-5)...")
    mnemonics = generate_mnemonics(
        group_threshold=1,
        groups=[(3, 5)],  # 3-of-5
        master_secret=entropy,
        passphrase=b"",
        iteration_exponent=0,
    )

    share_list = mnemonics[0]  # First (and only) group

    print()
    print("Generated SLIP-39 shares:")
    for i, mnemonic in enumerate(share_list, 1):
        print(f"  Share {i}: {mnemonic[:50]}...")
    print()

    print("=" * 60)
    print("Testing all combinations of 3 shares from 5...")
    print("=" * 60)

    all_passed = True

    # Test all combinations of 3 shares from 5
    for combo in combinations(range(5), 3):
        test_mnemonics = [share_list[i] for i in combo]
        indices = tuple(i + 1 for i in combo)

        try:
            recovered_entropy = combine_mnemonics(test_mnemonics, passphrase=b"")
            recovered_words = entropy_to_bip39(recovered_entropy, wordlist)

            if recovered_words == expected_words:
                print(f"Shares {indices}: PASS")
            else:
                all_passed = False
                print(f"Shares {indices}: FAIL")
                print(f"  Expected: {expected_words[:5]}...")
                print(f"  Got:      {recovered_words[:5]}...")
        except Exception as e:
            all_passed = False
            print(f"Shares {indices}: ERROR: {e}")

    print()
    print("=" * 60)
    if all_passed:
        print("ALL TESTS PASSED - Any 3 SLIP-39 shares successfully reconstruct the seed!")
    else:
        print("SOME TESTS FAILED")


if __name__ == "__main__":
    main()
