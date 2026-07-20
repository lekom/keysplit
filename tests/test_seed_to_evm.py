#!/usr/bin/env python3
"""Tests for BIP-39 to EVM wallet derivation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seed_to_evm import derivation_path, derive_private_key, evm_keys, keccak256, validate_mnemonic


TEST_MNEMONIC = 'test test test test test test test test test test test junk'


class TestSeedToEvm(unittest.TestCase):
    def test_keccak_256_empty_string(self):
        self.assertEqual(
            keccak256(b'').hex(),
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
        )

    def test_known_hardhat_wallet_zero(self):
        keys = evm_keys(derive_private_key(TEST_MNEMONIC, wallet_index=0))
        self.assertEqual(
            keys['private_key'],
            '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
        )
        self.assertEqual(keys['address'], '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')

    def test_known_hardhat_wallet_one(self):
        keys = evm_keys(derive_private_key(TEST_MNEMONIC, wallet_index=1))
        self.assertEqual(
            keys['private_key'],
            '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
        )
        self.assertEqual(keys['address'], '0x70997970C51812dc3A010C7d01b50e0d17dc79C8')

    def test_path_uses_address_index(self):
        self.assertEqual(derivation_path(7), "m/44'/60'/0'/0/7")

    def test_invalid_checksum_is_rejected(self):
        invalid = 'test test test test test test test test test test test test'
        with self.assertRaisesRegex(ValueError, 'checksum'):
            validate_mnemonic(invalid)

    def test_negative_index_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Wallet index'):
            derive_private_key(TEST_MNEMONIC, wallet_index=-1)


if __name__ == '__main__':
    unittest.main()
