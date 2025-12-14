#!/usr/bin/env python3
"""Tests for shamir_seed.py functions.

Test vectors from official BIP-39 specification:
https://github.com/trezor/python-mnemonic/blob/master/vectors.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from itertools import combinations
from shamir_mnemonic import generate_mnemonics, combine_mnemonics
from shamir_seed import load_wordlist, bip39_to_entropy, entropy_to_bip39, M, N

WORDLIST_PATH = Path(__file__).parent.parent / "bip39_words.txt"

# BIP-39 test vectors: (entropy_hex, mnemonic)
# Generated using proper entropy byte lengths for each word count
TEST_VECTORS = {
    12: [
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        ),
    ],
    15: [
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage wise"
        ),
        (
            "8080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor accident"
        ),
    ],
    18: [
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"
        ),
    ],
    24: [
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
        ),
    ],
}


def test_load_wordlist():
    """Test that wordlist loads correctly."""
    wordlist = load_wordlist(WORDLIST_PATH)
    assert len(wordlist) == 2048, f"Expected 2048 words, got {len(wordlist)}"
    assert wordlist[0] == "abandon", f"First word should be 'abandon', got '{wordlist[0]}'"
    assert wordlist[-1] == "zoo", f"Last word should be 'zoo', got '{wordlist[-1]}'"
    print("test_load_wordlist: PASS")


def test_bip39_entropy_conversion():
    """Test entropy extraction and conversion for all word lengths."""
    wordlist = load_wordlist(WORDLIST_PATH)

    expected_entropy_bytes = {12: 16, 15: 20, 18: 24, 24: 32}

    for word_count, vectors in TEST_VECTORS.items():
        for entropy_hex, mnemonic in vectors:
            words = mnemonic.split()
            assert len(words) == word_count, f"Expected {word_count} words, got {len(words)}"

            # Test entropy extraction
            entropy = bip39_to_entropy(words, wordlist)
            expected_len = expected_entropy_bytes[word_count]
            assert len(entropy) == expected_len, \
                f"Expected {expected_len} bytes for {word_count} words, got {len(entropy)}"

            # Verify entropy matches expected
            expected_entropy = bytes.fromhex(entropy_hex)
            assert entropy == expected_entropy, \
                f"Entropy mismatch for {word_count}-word phrase:\n  Expected: {entropy_hex}\n  Got: {entropy.hex()}"

    print("test_bip39_entropy_conversion: PASS (all word lengths)")


def test_entropy_to_bip39_roundtrip():
    """Test that entropy -> BIP-39 -> entropy roundtrips correctly for all lengths."""
    wordlist = load_wordlist(WORDLIST_PATH)

    for word_count, vectors in TEST_VECTORS.items():
        for entropy_hex, mnemonic in vectors:
            words = mnemonic.split()
            entropy = bip39_to_entropy(words, wordlist)
            recovered_words = entropy_to_bip39(entropy, wordlist)
            assert recovered_words == words, \
                f"Roundtrip failed for {word_count}-word phrase:\n  Original: {words}\n  Recovered: {recovered_words}"

    print("test_entropy_to_bip39_roundtrip: PASS (all word lengths)")


def test_full_split_recover_flow():
    """Test complete split and recovery flow for all word lengths."""
    wordlist = load_wordlist(WORDLIST_PATH)

    for word_count, vectors in TEST_VECTORS.items():
        entropy_hex, mnemonic = vectors[0]  # Use first vector for each length
        original_words = mnemonic.split()

        # Convert to entropy
        entropy = bip39_to_entropy(original_words, wordlist)

        # Generate SLIP-39 shares
        mnemonics = generate_mnemonics(
            group_threshold=1,
            groups=[(M, N)],
            master_secret=entropy,
            passphrase=b"",
            iteration_exponent=0,
            extendable=False,
        )

        share_list = mnemonics[0]
        assert len(share_list) == N, f"Expected {N} shares, got {len(share_list)}"

        # Test all M-of-N combinations
        for combo in combinations(range(N), M):
            test_shares = [share_list[i] for i in combo]
            recovered_entropy = combine_mnemonics(test_shares, passphrase=b"")
            recovered_words = entropy_to_bip39(recovered_entropy, wordlist)

            assert recovered_words == original_words, \
                f"Recovery failed for {word_count}-word phrase with shares {combo}"

        print(f"  {word_count}-word phrase: all {M}-of-{N} combinations work")

    print("test_full_split_recover_flow: PASS")


def test_invalid_word_count():
    """Test that invalid word counts raise errors."""
    wordlist = load_wordlist(WORDLIST_PATH)

    for invalid_count in [11, 13, 14, 16, 17, 19, 20, 21, 22, 23, 25]:
        words = ["abandon"] * invalid_count
        try:
            bip39_to_entropy(words, wordlist)
            assert False, f"Should have raised error for {invalid_count} words"
        except ValueError as e:
            assert "Invalid word count" in str(e)

    print("test_invalid_word_count: PASS")


def test_invalid_words():
    """Test that invalid words are detected."""
    wordlist = load_wordlist(WORDLIST_PATH)

    # Word not in wordlist
    invalid_words = ["notaword"] + ["abandon"] * 11
    try:
        bip39_to_entropy(invalid_words, wordlist)
        assert False, "Should have raised error for invalid word"
    except ValueError:
        pass  # Expected

    print("test_invalid_words: PASS")


def main():
    print("=" * 60)
    print("Testing shamir_seed.py functions")
    print("=" * 60)
    print()

    test_load_wordlist()
    test_bip39_entropy_conversion()
    test_entropy_to_bip39_roundtrip()
    print()
    test_full_split_recover_flow()
    print()
    test_invalid_word_count()
    test_invalid_words()

    print()
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
