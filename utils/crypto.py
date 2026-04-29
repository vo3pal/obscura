"""
Obscura Crypto Utilities
=============================
XOR encryption, Base64, MBA expression generation, and key utilities.
"""

import base64
import random
from typing import List, Tuple


def xor_encrypt(data: bytes, key: int) -> bytes:
    """XOR each byte with a single-byte key."""
    return bytes(b ^ key for b in data)


def xor_encrypt_rotating(data: bytes, key_bytes: List[int]) -> bytes:
    """XOR with a rotating multi-byte key."""
    klen = len(key_bytes)
    return bytes(b ^ key_bytes[i % klen] for i, b in enumerate(data))


def b64_encode(data: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(data).decode('ascii')


def b64_decode(data: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(data)


def encrypt_string(s: str, rng: random.Random) -> Tuple[str, int]:
    """
    Encrypt a string with per-string random XOR key + Base64.
    Returns (base64_encrypted, key).
    """
    key = rng.randint(1, 255)
    raw = s.encode('utf-8')
    xored = xor_encrypt(raw, key)
    encoded = b64_encode(xored)
    return encoded, key


def encrypt_string_double(s: str, rng: random.Random) -> Tuple[str, int, int]:
    """
    Double encryption: XOR with key1, then XOR result with key2, then Base64.
    Returns (base64_encrypted, key1, key2).
    """
    key1 = rng.randint(1, 255)
    key2 = rng.randint(1, 255)
    raw = s.encode('utf-8')
    pass1 = xor_encrypt(raw, key1)
    pass2 = xor_encrypt(pass1, key2)
    encoded = b64_encode(pass2)
    return encoded, key1, key2


def generate_mba(n: int, depth: int, rng: random.Random) -> str:
    """
    Generate a Mixed Boolean Arithmetic expression that evaluates to n.
    Depth controls nesting level (1-3).
    """
    if depth <= 0 or (n == 0 and rng.random() < 0.5):
        return str(n)

    strategies = []

    # Strategy 1: addition/subtraction
    r = rng.randint(1, 200)
    strategies.append(f"({generate_mba(n + r, depth - 1, rng)} - {r})")

    # Strategy 2: XOR identity
    k = rng.randint(1, 0xFF)
    strategies.append(f"bit32.bxor(bit32.bxor({generate_mba(n, depth - 1, rng)}, {k}), {k})")

    # Strategy 3: multiplication/division (only if cleanly divisible)
    if n != 0 and abs(n) > 1:
        factor = rng.choice([2, 3, 5])
        strategies.append(f"(({generate_mba(n * factor, depth - 1, rng)}) / {factor})")

    # Strategy 4: nested add
    a = rng.randint(1, 100)
    b = n - a
    if depth >= 2:
        strategies.append(f"({generate_mba(a, depth - 1, rng)} + {generate_mba(b, depth - 1, rng)})")

    return rng.choice(strategies)


def generate_rotating_key(length: int, rng: random.Random) -> List[int]:
    """Generate a multi-byte rotating XOR key."""
    return [rng.randint(1, 255) for _ in range(length)]
