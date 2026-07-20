#!/usr/bin/env python3
"""
BIP-39 Seed Phrase → EVM Private Key / Public Key / Address
Derives at m/44'/60'/0'/0/index (standard Ethereum wallet accounts)

WARNING: Run ONLY on an air-gapped, offline machine!
Pure Python stdlib — no external dependencies.
"""

import hashlib
import hmac
import struct
import unicodedata
from getpass import getpass
from pathlib import Path

# ── secp256k1 curve parameters ─────────────────────────────────────────────
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _padd(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2:
        if y1 != y2: return None
        lam = 3 * x1 * x1 * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P

def _pmul(k):
    R, Q = None, (_Gx, _Gy)
    while k:
        if k & 1: R = _padd(R, Q)
        Q = _padd(Q, Q)
        k >>= 1
    return R

# ── Keccak-256 (pure Python, NOT standard SHA3) ────────────────────────────
_M64 = (1 << 64) - 1
_RC  = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
# Rotation offsets stored as five y-values for each x: _ROT[y + 5*x]
_ROT = [0, 36, 3, 41, 18, 1, 44, 10, 45, 2, 62, 6, 43, 15, 61, 28, 55, 25, 21, 56, 27, 20, 39, 8, 14]

def _r64(x, n): return ((x << n) | (x >> (64 - n))) & _M64

def _keccak_f(A):
    A = list(A)
    for rc in _RC:
        C = [A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20] for x in range(5)]
        D = [C[(x-1) % 5] ^ _r64(C[(x+1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5): A[x + 5*y] ^= D[x]
        B = [0] * 25
        for y in range(5):
            for x in range(5):
                B[y + 5*((2*x + 3*y) % 5)] = _r64(A[x + 5*y], _ROT[y + 5*x])
        for y in range(5):
            for x in range(5):
                A[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1) % 5 + 5*y] & _M64) & B[(x+2) % 5 + 5*y])
        A[0] ^= rc
    return A

def keccak256(data: bytes) -> bytes:
    rate, msg = 136, bytearray(data)
    pad = rate - len(msg) % rate
    msg += b'\x81' if pad == 1 else (b'\x01' + b'\x00' * (pad - 2) + b'\x80')
    state = [0] * 25
    for i in range(0, len(msg), rate):
        blk = msg[i:i + rate]
        for j in range(17): state[j] ^= int.from_bytes(blk[j*8:j*8+8], 'little')
        state = _keccak_f(state)
    return b''.join(state[i].to_bytes(8, 'little') for i in range(4))

# ── BIP-39 → seed ──────────────────────────────────────────────────────────
def _normalized(value: str) -> str:
    return unicodedata.normalize('NFKD', value)


def validate_mnemonic(mnemonic: str) -> str:
    """Validate an English BIP-39 mnemonic and return its normalized form."""
    normalized = ' '.join(_normalized(mnemonic).strip().lower().split())
    words = normalized.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError('Seed phrase must contain 12, 15, 18, 21, or 24 words.')

    wordlist_path = Path(__file__).with_name('bip39_words.txt')
    try:
        wordlist = wordlist_path.read_text(encoding='utf-8').splitlines()
    except OSError as exc:
        raise ValueError(f'Unable to read BIP-39 wordlist: {wordlist_path}') from exc
    if len(wordlist) != 2048:
        raise ValueError('BIP-39 wordlist must contain exactly 2048 words.')

    positions = {word: index for index, word in enumerate(wordlist)}
    unknown = [word for word in words if word not in positions]
    if unknown:
        raise ValueError(f"Unknown BIP-39 word: {unknown[0]}")

    bits = ''.join(f'{positions[word]:011b}' for word in words)
    checksum_length = len(bits) // 33
    entropy_bits = bits[:-checksum_length]
    checksum_bits = bits[-checksum_length:]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, 'big')
    expected = f'{hashlib.sha256(entropy).digest()[0]:08b}'[:checksum_length]
    if checksum_bits != expected:
        raise ValueError('Seed phrase has an invalid BIP-39 checksum.')
    return normalized


def mnemonic_to_seed(mnemonic: str, passphrase: str = '') -> bytes:
    return hashlib.pbkdf2_hmac(
        'sha512',
        _normalized(mnemonic).encode('utf-8'),
        _normalized('mnemonic' + passphrase).encode('utf-8'),
        2048,
    )

# ── BIP-32 key derivation ──────────────────────────────────────────────────
def _master_key(seed: bytes):
    h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    master = int.from_bytes(h[:32], 'big')
    if master == 0 or master >= _N:
        raise ValueError('BIP-32 produced an invalid master key.')
    return h[:32], h[32:]

def _child_key(key: bytes, chain: bytes, index: int):
    if index >= 0x80000000:  # hardened
        data = b'\x00' + key + struct.pack('>I', index)
    else:
        x, y = _pmul(int.from_bytes(key, 'big'))
        pub = (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
        data = pub + struct.pack('>I', index)
    h = hmac.new(chain, data, hashlib.sha512).digest()
    left = int.from_bytes(h[:32], 'big')
    if left >= _N:
        raise ValueError(f'BIP-32 produced an invalid child key at index {index}.')
    child = (left + int.from_bytes(key, 'big')) % _N
    if child == 0:
        raise ValueError(f'BIP-32 produced a zero child key at index {index}.')
    return child.to_bytes(32, 'big'), h[32:]

def derivation_path(wallet_index: int = 0) -> str:
    if not 0 <= wallet_index < 0x80000000:
        raise ValueError('Wallet index must be between 0 and 2147483647.')
    return f"m/44'/60'/0'/0/{wallet_index}"


def derive_private_key(mnemonic: str, passphrase: str = '', wallet_index: int = 0) -> int:
    """Derive an EVM key at m/44'/60'/0'/0/wallet_index."""
    normalized_mnemonic = validate_mnemonic(mnemonic)
    derivation_path(wallet_index)
    path = (0x80000000 + 44, 0x80000000 + 60, 0x80000000, 0, wallet_index)
    key, chain = _master_key(mnemonic_to_seed(normalized_mnemonic, passphrase))
    for idx in path:
        key, chain = _child_key(key, chain, idx)
    return int.from_bytes(key, 'big')

# ── EVM key formatting ─────────────────────────────────────────────────────
def evm_keys(priv: int) -> dict:
    x, y = _pmul(priv)
    pub_comp   = ((b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')).hex()
    pub_uncomp = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    # Ethereum address: keccak256(uncompressed pubkey without 04 prefix), last 20 bytes
    addr_raw = keccak256(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))[12:]
    hex_addr = addr_raw.hex()
    cksum    = keccak256(hex_addr.encode('ascii')).hex()
    address  = '0x' + ''.join(c.upper() if int(cksum[i], 16) >= 8 else c for i, c in enumerate(hex_addr))

    return {
        'private_key':            f'0x{priv:064x}',
        'public_key_compressed':  pub_comp,
        'public_key_uncompressed': pub_uncomp,
        'address':                address,
    }

# ── CLI ────────────────────────────────────────────────────────────────────
def main():
    print('=' * 64)
    print('BIP-39 Seed Phrase → EVM Wallet Keys')
    print("Derivation: m/44'/60'/0'/0/index  (standard Ethereum accounts)")
    print('=' * 64)
    print()

    mnemonic = getpass('Seed phrase: ')
    # BIP-39 passphrases are exact strings; leading/trailing spaces are significant.
    passphrase = getpass('BIP-39 passphrase (Enter to skip): ')

    try:
        index_str = input('Wallet index (Enter for 0): ').strip()
        wallet_index = int(index_str) if index_str else 0
        derivation_path(wallet_index)
    except ValueError:
        print('Invalid wallet index; it must be a non-negative integer.')
        return

    print('\nDeriving...')
    try:
        priv = derive_private_key(mnemonic, passphrase, wallet_index)
    except ValueError as exc:
        print(f'Error: {exc}')
        return
    k    = evm_keys(priv)

    print()
    print('=' * 64)
    print(f'Derivation path:         {derivation_path(wallet_index)}')
    print(f"Private key:             {k['private_key']}")
    print(f"Public key (compressed): {k['public_key_compressed']}")
    print(f"Public key (full):       {k['public_key_uncompressed']}")
    print(f"EVM address:             {k['address']}")
    print('=' * 64)
    print()
    print('Verify this address matches your wallet before use.')


if __name__ == '__main__':
    main()
